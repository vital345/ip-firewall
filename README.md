# IP Firewall

Device-wide advertisement filtering. IP Firewall maintains a clearly marked block in the system hosts file and maps known advertising domains to `0.0.0.0`, so those domains are stopped before they reach applications, including Edge when it uses the operating system resolver.

## Run

```bash
npm install
npm run tauri dev
```

Run the desktop app as administrator before enabling protection. The app only edits the block between `# IP-FIREWALL:START` and `# IP-FIREWALL:END`, leaving the rest of the hosts file untouched.

This is DNS-level device filtering, not arbitrary packet inspection. Edge's Secure DNS setting can bypass the hosts file by resolving through an encrypted provider; turn off Secure DNS in Edge if you want it to use this device-wide blocklist. Full packet-level dropping on Windows requires a Windows Filtering Platform driver.

## Data and activity

The app stores its local SQLite database as `ip-firewall.sqlite3` in the Tauri application data directory. Overview, Activity, and Blocklist are live views backed by the database and refresh every two seconds. Protection enable/disable operations are recorded immediately.

The hosts-file mode cannot observe individual packets or DNS matches after they leave the operating system resolver. Activity records configuration changes and does not fabricate blocked or unfiltered DNS events. Real-time blocked and allowed-domain telemetry requires a local DNS proxy or a platform-specific DNS monitoring backend.

## Import uBlock domains

The repository includes a dependency-free importer for uBlock hostname rules. Start IP Firewall once so its SQLite database exists, close the app, then preview the import:

```bash
python scripts/import_ublock_blocklist.py --dry-run
```

Apply the import with:

```bash
npm run import:ublock
```

The importer extracts network rules in the form `||hostname^`, ignores cosmetic and script-only filters, preserves existing domains, and inserts imported domains as admin-managed entries. To target another database, pass `--database path/to/ip-firewall.sqlite3`.

# Tauri + React + Typescript

This template should help get you started developing with Tauri, React and Typescript in Vite.

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
