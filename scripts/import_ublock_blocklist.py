#!/usr/bin/env python3
"""Import hostname rules from a uBlock filter list into the app SQLite database."""

from __future__ import annotations
import argparse
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

DEFAULT_URL = "https://ublockorigin.github.io/uAssets/filters/filters.min.txt"
HOST_RULE = re.compile(r"^\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^", re.IGNORECASE)
VALID_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


def default_database_path() -> Path:
    """Return the default Tauri app-data database path for the current OS."""
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "com.vital.ip-firewall" / "ip-firewall.sqlite3"


def fetch_filter_list(url: str, timeout: int) -> str:
    request = Request(url, headers={"User-Agent": "IP-Firewall uBlock importer/1.0"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def extract_domains(contents: str) -> list[str]:
    domains: set[str] = set()
    for line in contents.splitlines():
        match = HOST_RULE.match(line.strip().lower())
        if match:
            domain = match.group(1).rstrip(".")
            if VALID_HOST.fullmatch(domain):
                domains.add(domain)
    return sorted(domains)


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            added_at TEXT NOT NULL,
            is_default INTEGER NOT NULL DEFAULT 0,
            category TEXT NOT NULL DEFAULT 'advertising',
            source TEXT NOT NULL DEFAULT 'manual',
            enabled INTEGER NOT NULL DEFAULT 1,
            redirect TEXT NOT NULL DEFAULT '0.0.0.0',
            notes TEXT NOT NULL DEFAULT ''
        )
        """)
    for name, definition in (
        ("category", "TEXT NOT NULL DEFAULT 'advertising'"),
        ("source", "TEXT NOT NULL DEFAULT 'legacy'"),
        ("enabled", "INTEGER NOT NULL DEFAULT 1"),
        ("redirect", "TEXT NOT NULL DEFAULT '0.0.0.0'"),
        ("notes", "TEXT NOT NULL DEFAULT ''"),
    ):
        try:
            connection.execute(f"ALTER TABLE blocked_domains ADD COLUMN {name} {definition}")
        except sqlite3.OperationalError as error:
            if "duplicate column name" not in str(error).lower():
                raise


def import_domains(
    database: Path, domains: list[str], dry_run: bool
) -> tuple[int, int]:
    if not database.exists():
        raise FileNotFoundError(
            f"Database not found: {database}. Start IP Firewall once or pass --database."
        )

    connection = sqlite3.connect(database)
    try:
        ensure_schema(connection)
        existing = {
            row[0].lower()
            for row in connection.execute("SELECT domain FROM blocked_domains")
        }
        new_domains = [domain for domain in domains if domain not in existing]

        if not dry_run:
            timestamp = str(int(time.time()))
            connection.executemany(
                """
                INSERT OR IGNORE INTO blocked_domains
                (domain, added_at, is_default, category, source, enabled, redirect, notes)
                VALUES (?, ?, 0, 'advertising', 'uBlock import', 1, '0.0.0.0', '')
                """,
                [(domain, timestamp) for domain in new_domains],
            )
            connection.commit()
        return len(new_domains), len(existing)
    finally:
        connection.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import uBlock hostname rules into the IP Firewall blocklist."
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=default_database_path(),
        help="SQLite database path (default: the current OS Tauri app-data path)",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help="uBlock filter list URL")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Download timeout in seconds"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download and count new domains without modifying SQLite",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        contents = fetch_filter_list(args.url, args.timeout)
        domains = extract_domains(contents)
        added, existing = import_domains(args.database, domains, args.dry_run)
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1

    action = "would be added" if args.dry_run else "added"
    print(f"Parsed {len(domains)} valid hostname rules from the filter list.")
    print(f"{added} new domains {action}; {existing} existing domains preserved.")
    if args.dry_run:
        print("Dry run: the database was not modified.")
    else:
        print(f"Database updated: {args.database}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
