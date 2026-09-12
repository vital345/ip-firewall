use std::collections::HashSet;
use std::sync::Mutex;

use tauri::{AppHandle, State};

use crate::database::{ensure_blocklist, load_events, now_string, open_database, record_event};
use crate::dns_proxy::DnsProxyHandle;
use crate::models::{DashboardData, BLOCK_START};
use crate::sinkhole::{
    blocker_state, can_write_hosts_file, normalize_domain, read_hosts, write_blocker,
};

fn refresh_active_sinkhole(app: &AppHandle) -> Result<(), String> {
    if read_hosts()?.contains(BLOCK_START) {
        write_blocker(app, true)?;
    }
    Ok(())
}

fn record_admin_change(
    app: &AppHandle,
    action: &str,
    detail: &str,
    domain: &str,
) -> Result<(), String> {
    record_event(app, "admin", action, detail, Some(domain))
}

#[tauri::command]
pub fn get_dashboard(app: AppHandle) -> Result<DashboardData, String> {
    let hosts = read_hosts()?;
    let (connection, path) = open_database(&app)?;
    let blocklist = ensure_blocklist(&connection)?;
    let blocked_requests = connection
        .query_row(
            "SELECT COUNT(*) FROM activity_events WHERE kind = 'blocked'",
            [],
            |row| row.get::<_, u64>(0),
        )
        .map_err(|error| format!("Unable to count observed blocked requests: {error}"))?;

    Ok(DashboardData {
        state: blocker_state(&hosts, blocked_requests, blocklist.len()),
        events: load_events(&connection)?,
        blocklist,
        database_path: path.display().to_string(),
    })
}

#[tauri::command]
pub fn set_blocker_enabled(
    app: AppHandle,
    enabled: bool,
    dns_proxy: State<'_, Mutex<DnsProxyHandle>>,
) -> Result<DashboardData, String> {
    if !can_write_hosts_file() {
        return Err(
            "This environment cannot modify the system hosts file. Run as administrator or use a supported hosts-editing environment.".to_string(),
        );
    }

    let mut proxy = dns_proxy
        .lock()
        .map_err(|_| "Unable to access the DNS proxy state.".to_string())?;
    if enabled {
        proxy.start(app.clone())?;
        if let Err(error) = write_blocker(&app, true) {
            proxy.stop();
            return Err(error);
        }
    } else {
        write_blocker(&app, false)?;
        proxy.stop();
    }
    record_event(
        &app,
        "system",
        if enabled { "enabled" } else { "disabled" },
        if enabled {
            "Advertisement filter enabled"
        } else {
            "Advertisement filter disabled"
        },
        None,
    )?;
    get_dashboard(app)
}

#[tauri::command]
pub fn add_domain(
    app: AppHandle,
    domain: String,
    category: String,
    source: String,
    notes: String,
) -> Result<DashboardData, String> {
    let normalized = normalize_domain(domain)?;
    let (connection, _) = open_database(&app)?;
    let rows = connection
        .execute(
            "INSERT OR IGNORE INTO blocked_domains
             (domain, added_at, is_default, category, source, enabled, redirect, notes)
             VALUES (?1, ?2, 0, ?3, ?4, 1, '0.0.0.0', ?5)",
            rusqlite::params![normalized, now_string(), category, source, notes],
        )
        .map_err(|error| format!("Unable to add the domain to the blocklist: {error}"))?;

    if rows == 0 {
        return Err("This domain is already in the blocklist.".to_string());
    }

    refresh_active_sinkhole(&app)?;
    record_admin_change(&app, "added", "Domain added to control list", &normalized)?;
    get_dashboard(app)
}

#[tauri::command]
pub fn import_domains(app: AppHandle, domains: Vec<String>) -> Result<DashboardData, String> {
    let (mut connection, _) = open_database(&app)?;
    ensure_blocklist(&connection)?;

    let mut normalized_domains = HashSet::new();
    for domain in domains {
        if let Ok(normalized) = normalize_domain(domain) {
            normalized_domains.insert(normalized);
        }
    }

    if normalized_domains.is_empty() {
        return Err("The selected file contained no valid domains.".to_string());
    }

    let transaction = connection
        .transaction()
        .map_err(|error| format!("Unable to begin blocklist import: {error}"))?;
    for domain in &normalized_domains {
        transaction
            .execute(
                "INSERT OR IGNORE INTO blocked_domains
                 (domain, added_at, is_default, category, source, enabled, redirect, notes)
                 VALUES (?1, ?2, 0, 'advertising', 'import', 1, '0.0.0.0', '')",
                rusqlite::params![domain, now_string()],
            )
            .map_err(|error| format!("Unable to import the blocklist: {error}"))?;
    }
    transaction
        .commit()
        .map_err(|error| format!("Unable to commit the blocklist import: {error}"))?;

    refresh_active_sinkhole(&app)?;
    record_event(
        &app,
        "admin",
        "imported",
        "Domains imported into control list",
        None,
    )?;
    get_dashboard(app)
}

#[tauri::command]
pub fn save_export(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents)
        .map_err(|error| format!("Unable to save the export to {path}: {error}"))
}

#[tauri::command]
pub fn remove_domain(app: AppHandle, domain: String) -> Result<DashboardData, String> {
    let normalized = normalize_domain(domain)?;
    let (connection, _) = open_database(&app)?;
    let rows = connection
        .execute(
            "DELETE FROM blocked_domains WHERE lower(domain) = lower(?1)",
            rusqlite::params![normalized],
        )
        .map_err(|error| format!("Unable to remove the domain from the blocklist: {error}"))?;

    if rows == 0 {
        return Err("That domain is not in the blocklist.".to_string());
    }

    refresh_active_sinkhole(&app)?;
    record_admin_change(
        &app,
        "removed",
        "Domain removed from control list",
        &normalized,
    )?;
    get_dashboard(app)
}

#[tauri::command]
pub fn clear_activity(app: AppHandle) -> Result<DashboardData, String> {
    let (connection, _) = open_database(&app)?;
    connection
        .execute("DELETE FROM activity_events", [])
        .map_err(|error| format!("Unable to clear activity: {error}"))?;
    get_dashboard(app)
}
