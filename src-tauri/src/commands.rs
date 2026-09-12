use std::collections::HashSet;
use std::sync::Mutex;

use tauri::{AppHandle, State};

use crate::database::{ensure_blocklist, load_events, now_string, open_database, record_event};
use crate::dns_proxy::DnsProxyHandle;
use crate::models::{DashboardData, BLOCK_START};
use crate::packet_filter::PacketFilterHandle;
use crate::sinkhole::{
    blocker_state, can_write_hosts_file, normalize_domain, read_hosts, write_blocker,
};
use crate::system_dns::{configure_local_dns, restore_dns};

fn refresh_active_sinkhole(
    app: &AppHandle,
    dns_proxy: &State<'_, Mutex<DnsProxyHandle>>,
) -> Result<(), String> {
    let proxy = dns_proxy
        .lock()
        .map_err(|_| "Unable to access the DNS proxy state.".to_string())?;
    if proxy.is_running() {
        let _ = write_blocker(app, false);
        return Ok(());
    }
    if read_hosts()?.contains(BLOCK_START) {
        write_blocker(app, true)?;
    }
    Ok(())
}

fn refresh_packet_filter(
    app: &AppHandle,
    packet_filter: &Mutex<PacketFilterHandle>,
) -> Result<(), String> {
    let (connection, _) = open_database(app)?;
    let domains = ensure_blocklist(&connection)?
        .into_iter()
        .filter(|entry| entry.enabled)
        .map(|entry| entry.domain)
        .collect::<Vec<_>>();
    let mut filter = packet_filter
        .lock()
        .map_err(|_| "Unable to access the packet filter state.".to_string())?;
    if filter.is_running() {
        filter.apply_blocklist(&domains)?;
    }
    Ok(())
}

fn dashboard_data(
    app: AppHandle,
    packet_filter: &Mutex<PacketFilterHandle>,
) -> Result<DashboardData, String> {
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
    let status = packet_filter
        .lock()
        .map_err(|_| "Unable to access the packet filter state.".to_string())?
        .status();

    Ok(DashboardData {
        state: blocker_state(
            &hosts,
            blocked_requests,
            blocklist.len(),
            status.backend,
            status.enabled,
            status.note,
        ),
        events: load_events(&connection)?,
        blocklist,
        database_path: path.display().to_string(),
    })
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
pub fn get_dashboard(
    app: AppHandle,
    packet_filter: State<'_, Mutex<PacketFilterHandle>>,
) -> Result<DashboardData, String> {
    dashboard_data(app, packet_filter.inner())
}

#[tauri::command]
pub fn set_blocker_enabled(
    app: AppHandle,
    enabled: bool,
    dns_proxy: State<'_, Mutex<DnsProxyHandle>>,
    packet_filter_state: State<'_, Mutex<PacketFilterHandle>>,
) -> Result<DashboardData, String> {
    let mut proxy = dns_proxy
        .lock()
        .map_err(|_| "Unable to access the DNS proxy state.".to_string())?;
    let mut packet_filter = packet_filter_state
        .lock()
        .map_err(|_| "Unable to access the packet filter state.".to_string())?;
    let mut detail = if enabled {
        String::from("Advertisement filter enabled")
    } else {
        String::from("Advertisement filter disabled")
    };
    if enabled {
        let packet_ready = match packet_filter.start() {
            Ok(()) => true,
            Err(error) => {
                eprintln!("Packet filter not available: {error}");
                false
            }
        };
        let dns_configured = if can_write_hosts_file() {
            match configure_local_dns(&app) {
                Ok(()) => true,
                Err(error) => {
                    eprintln!("System DNS unavailable, using hosts-file fallback: {error}");
                    let _ = restore_dns(&app);
                    false
                }
            }
        } else {
            false
        };
        if dns_configured {
            if let Err(error) = proxy.start(app.clone()) {
                let _ = restore_dns(&app);
                detail = String::from("Hosts-file protection enabled; local DNS proxy unavailable");
                eprintln!("Local DNS proxy unavailable, using hosts-file fallback: {error}");
            } else {
                detail = String::from("Advertisement filter enabled; DNS proxy active");
                let _ = write_blocker(&app, false);
            }
        } else {
            detail = String::from("Hosts-file protection enabled; system DNS unavailable");
            if let Err(error) = write_blocker(&app, true) {
                proxy.stop();
                let _ = restore_dns(&app);
                return Err(error);
            }
        }
        if !proxy.is_running() {
            if !can_write_hosts_file() && !packet_ready {
                return Err("No usable enforcement backend is available. Enable administrator privileges or install the native packet-filter backend.".to_string());
            }
            if can_write_hosts_file() && !packet_ready {
                if let Err(error) = write_blocker(&app, true) {
                    proxy.stop();
                    let _ = restore_dns(&app);
                    return Err(error);
                }
            }
        }
        if packet_ready {
            detail = format!(
                "{detail}; packet filter backend {} active",
                packet_filter.backend().name()
            );
        }
        let domains = ensure_blocklist(&open_database(&app)?.0)?
            .into_iter()
            .filter(|entry| entry.enabled)
            .map(|entry| entry.domain)
            .collect::<Vec<_>>();
        if packet_ready {
            packet_filter.apply_blocklist(&domains)?;
        }
    } else {
        packet_filter.stop()?;
        write_blocker(&app, false)?;
        proxy.stop();
        restore_dns(&app)?;
    }
    record_event(
        &app,
        "system",
        if enabled { "enabled" } else { "disabled" },
        detail.as_str(),
        None,
    )?;
    drop(packet_filter);
    dashboard_data(app, packet_filter_state.inner())
}

#[tauri::command]
pub fn add_domain(
    app: AppHandle,
    domain: String,
    category: String,
    source: String,
    notes: String,
    dns_proxy: State<'_, Mutex<DnsProxyHandle>>,
    packet_filter: State<'_, Mutex<PacketFilterHandle>>,
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

    refresh_active_sinkhole(&app, &dns_proxy)?;
    record_admin_change(&app, "added", "Domain added to control list", &normalized)?;
    refresh_packet_filter(&app, packet_filter.inner())?;
    dashboard_data(app, packet_filter.inner())
}

#[tauri::command]
pub fn import_domains(
    app: AppHandle,
    domains: Vec<String>,
    dns_proxy: State<'_, Mutex<DnsProxyHandle>>,
    packet_filter: State<'_, Mutex<PacketFilterHandle>>,
) -> Result<DashboardData, String> {
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

    refresh_active_sinkhole(&app, &dns_proxy)?;
    record_event(
        &app,
        "admin",
        "imported",
        "Domains imported into control list",
        None,
    )?;
    refresh_packet_filter(&app, packet_filter.inner())?;
    dashboard_data(app, packet_filter.inner())
}

#[tauri::command]
pub fn save_export(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents)
        .map_err(|error| format!("Unable to save the export to {path}: {error}"))
}

#[tauri::command]
pub fn remove_domain(
    app: AppHandle,
    domain: String,
    dns_proxy: State<'_, Mutex<DnsProxyHandle>>,
    packet_filter: State<'_, Mutex<PacketFilterHandle>>,
) -> Result<DashboardData, String> {
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

    refresh_active_sinkhole(&app, &dns_proxy)?;
    record_admin_change(
        &app,
        "removed",
        "Domain removed from control list",
        &normalized,
    )?;
    refresh_packet_filter(&app, packet_filter.inner())?;
    dashboard_data(app, packet_filter.inner())
}

#[tauri::command]
pub fn clear_activity(
    app: AppHandle,
    packet_filter: State<'_, Mutex<PacketFilterHandle>>,
) -> Result<DashboardData, String> {
    let (connection, _) = open_database(&app)?;
    connection
        .execute("DELETE FROM activity_events", [])
        .map_err(|error| format!("Unable to clear activity: {error}"))?;
    dashboard_data(app, packet_filter.inner())
}
