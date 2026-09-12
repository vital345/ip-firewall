use rusqlite::{params, Connection};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager};

use crate::sinkhole::AD_DOMAINS;

pub fn database_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Unable to locate the application data directory: {error}"))?;
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Unable to create the application data directory: {error}"))?;
    Ok(directory.join("ip-firewall.sqlite3"))
}

pub fn open_database(app: &AppHandle) -> Result<(Connection, PathBuf), String> {
    let path = database_path(app)?;
    let connection = Connection::open(&path)
        .map_err(|error| format!("Unable to open the activity database: {error}"))?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS blocked_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                added_at TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS activity_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                domain TEXT,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_activity_created_at
                ON activity_events(created_at DESC);",
        )
        .map_err(|error| format!("Unable to initialize the activity database: {error}"))?;
    Ok((connection, path))
}

pub fn now_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

pub fn record_event(
    app: &AppHandle,
    kind: &str,
    action: &str,
    detail: &str,
    domain: Option<&str>,
) -> Result<(), String> {
    let (connection, _) = open_database(app)?;
    connection
        .execute(
            "INSERT INTO activity_events (created_at, kind, domain, action, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now_string(), kind, domain, action, detail],
        )
        .map_err(|error| format!("Unable to record activity: {error}"))?;
    Ok(())
}

pub fn load_events(connection: &Connection) -> Result<Vec<crate::models::ActivityEvent>, String> {
    let mut statement = connection
        .prepare(
            "SELECT id, created_at, kind, domain, action, detail
             FROM activity_events ORDER BY id DESC LIMIT 100",
        )
        .map_err(|error| format!("Unable to query activity: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok(crate::models::ActivityEvent {
                id: row.get(0)?,
                created_at: row.get(1)?,
                kind: row.get(2)?,
                domain: row.get(3)?,
                action: row.get(4)?,
                detail: row.get(5)?,
            })
        })
        .map_err(|error| format!("Unable to read activity: {error}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Unable to decode activity: {error}"))
}

pub fn ensure_blocklist(connection: &Connection) -> Result<Vec<String>, String> {
    let count: usize = connection
        .query_row("SELECT COUNT(*) FROM blocked_domains", [], |row| row.get(0))
        .map_err(|error| format!("Unable to load blocklist count: {error}"))?;

    if count == 0 {
        let timestamp = now_string();
        for domain in AD_DOMAINS {
            connection
                .execute(
                    "INSERT OR IGNORE INTO blocked_domains (domain, added_at, is_default) VALUES (?1, ?2, 1)",
                    params![*domain, timestamp],
                )
                .map_err(|error| format!("Unable to seed the default blocklist: {error}"))?;
        }
    }

    let mut statement = connection
        .prepare("SELECT domain FROM blocked_domains ORDER BY domain ASC")
        .map_err(|error| format!("Unable to load the blocklist: {error}"))?;

    let rows = statement
        .query_map([], |row| row.get(0))
        .map_err(|error| format!("Unable to read the blocklist: {error}"))?;

    rows.collect::<Result<Vec<String>, _>>()
        .map_err(|error| format!("Unable to decode the blocklist: {error}"))
}
