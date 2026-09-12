use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const BACKUP_FILE: &str = "dns-settings-backup.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdapterDnsState {
    alias: String,
    family: u16,
    servers: Vec<String>,
}

#[cfg(target_os = "windows")]
pub fn configure_local_dns(app: &AppHandle) -> Result<(), String> {
    if !cfg!(target_os = "windows") {
        return Ok(());
    }

    let backup_path = backup_path(app)?;
    let states = if backup_path.exists() {
        read_backup(&backup_path)?
    } else {
        let states = active_dns_states()?;
        write_backup(&backup_path, &states)?;
        states
    };

    for state in &states {
        let servers = if state.family == 4 {
            vec!["127.0.0.1".to_string()]
        } else {
            vec!["::1".to_string()]
        };
        if let Err(error) = set_servers(&state.alias, state.family, &servers) {
            let _ = restore_dns(app);
            return Err(error);
        }
    }
    flush_dns_cache();
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn restore_dns(app: &AppHandle) -> Result<(), String> {
    if !cfg!(target_os = "windows") {
        return Ok(());
    }

    let path = backup_path(app)?;
    if !path.exists() {
        return Ok(());
    }

    let states = read_backup(&path)?;
    let mut first_error = None;
    for state in &states {
        let result = if state.servers.is_empty() {
            run_powershell(&format!(
                "Reset-DnsClientServerAddress -InterfaceAlias {} -AddressFamily {}",
                quote_ps(&state.alias),
                family_name(state.family)
            ))
            .map(|_| ())
        } else {
            set_servers(&state.alias, state.family, &state.servers)
        };
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    flush_dns_cache();
    if let Some(error) = first_error {
        return Err(error);
    }
    fs::remove_file(path)
        .map_err(|error| format!("Unable to remove DNS settings backup: {error}"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn active_dns_states() -> Result<Vec<AdapterDnsState>, String> {
    let script = r#"
$items = Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
  $adapter = $_
    foreach ($family in @('IPv4', 'IPv6')) {
    $servers = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses)
        [PSCustomObject]@{ alias = $adapter.InterfaceAlias; family = $(if ($family -eq 'IPv4') { 4 } else { 6 }); servers = $servers }
  }
}
$items | ConvertTo-Json -Compress
"#;
    let output = run_powershell(script)?;
    if output.trim().is_empty() {
        return Err("No active Windows network adapters were found.".to_string());
    }
    let value: serde_json::Value = serde_json::from_str(&output)
        .map_err(|error| format!("Unable to read Windows DNS settings: {error}"))?;
    let values = match value {
        serde_json::Value::Array(values) => values,
        value => vec![value],
    };
    values
        .into_iter()
        .map(|value| {
            let alias = value
                .get("alias")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    "Windows DNS settings did not include an adapter alias.".to_string()
                })?
                .to_string();
            let family = value
                .get("family")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    "Windows DNS settings did not include an address family.".to_string()
                })? as u16;
            let servers = match value.get("servers") {
                Some(serde_json::Value::Array(values)) => values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect(),
                Some(serde_json::Value::String(value)) if !value.is_empty() => {
                    vec![value.to_string()]
                }
                _ => Vec::new(),
            };
            Ok(AdapterDnsState {
                alias,
                family,
                servers,
            })
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn set_servers(alias: &str, family: u16, servers: &[String]) -> Result<(), String> {
    let addresses = servers
        .iter()
        .map(|server| quote_ps(server))
        .collect::<Vec<_>>()
        .join(", ");
    run_powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceAlias {} -AddressFamily {} -ServerAddresses @({addresses})",
        quote_ps(alias), family_name(family)
    ))
    .map(|_| ())
}

fn backup_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Unable to locate application data directory: {error}"))?;
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Unable to create application data directory: {error}"))?;
    Ok(directory.join(BACKUP_FILE))
}

fn read_backup(path: &PathBuf) -> Result<Vec<AdapterDnsState>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("Unable to read DNS settings backup: {error}"))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("Unable to decode DNS settings backup: {error}"))
}

fn write_backup(path: &PathBuf, states: &[AdapterDnsState]) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(states)
        .map_err(|error| format!("Unable to encode DNS settings backup: {error}"))?;
    fs::write(path, contents)
        .map_err(|error| format!("Unable to save DNS settings backup: {error}"))
}

#[cfg(target_os = "windows")]
fn quote_ps(value: &str) -> String {
    format!("'{}'", value.replace("'", "''"))
}

#[cfg(target_os = "windows")]
fn family_name(family: u16) -> &'static str {
    if family == 6 {
        "IPv6"
    } else {
        "IPv4"
    }
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> Result<String, String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|error| format!("Unable to run PowerShell for DNS settings: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "windows")]
fn flush_dns_cache() {
    let _ = Command::new("ipconfig").arg("/flushdns").output();
}

#[cfg(target_os = "linux")]
pub fn configure_local_dns(app: &AppHandle) -> Result<(), String> {
    let path = backup_path(app)?;
    let states = if path.exists() {
        read_backup(&path)?
    } else {
        let states = linux_dns_states()?;
        write_backup(&path, &states)?;
        states
    };
    for state in &states {
        linux_set_servers(&state.alias, &["127.0.0.1", "::1"])?;
    }
    let _ = run_command("resolvectl", &["flush-caches"]);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn restore_dns(app: &AppHandle) -> Result<(), String> {
    let path = backup_path(app)?;
    if !path.exists() {
        return Ok(());
    }
    let states = read_backup(&path)?;
    let mut first_error = None;
    for state in &states {
        let result = if state.servers.is_empty() {
            run_command("resolvectl", &["revert", &state.alias]).map(|_| ())
        } else {
            let servers = state.servers.iter().map(String::as_str).collect::<Vec<_>>();
            linux_set_servers(&state.alias, &servers)
        };
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    let _ = run_command("resolvectl", &["flush-caches"]);
    if let Some(error) = first_error {
        return Err(error);
    }
    fs::remove_file(path)
        .map_err(|error| format!("Unable to remove DNS settings backup: {error}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_dns_states() -> Result<Vec<AdapterDnsState>, String> {
    let output = run_command("resolvectl", &["dns"])?;
    let mut states = Vec::new();
    let mut current: Option<AdapterDnsState> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Link ") {
            if let Some(state) = current.take() {
                states.push(state);
            }
            let alias = trimmed
                .split_once('(')
                .and_then(|(_, value)| {
                    value
                        .trim_end_matches(':')
                        .strip_suffix(')')
                        .or(Some(value))
                })
                .unwrap_or("")
                .to_string();
            if !alias.is_empty() {
                current = Some(AdapterDnsState {
                    alias,
                    family: 0,
                    servers: Vec::new(),
                });
            }
        } else if let Some(state) = current.as_mut() {
            for token in trimmed
                .strip_prefix("DNS Servers:")
                .unwrap_or("")
                .split_whitespace()
            {
                if token.parse::<IpAddr>().is_ok() {
                    state.servers.push(token.to_string());
                }
            }
        }
    }
    if let Some(state) = current {
        states.push(state);
    }
    if states.is_empty() {
        return Err("No resolvectl-managed network interfaces were found.".to_string());
    }
    Ok(states)
}

#[cfg(target_os = "linux")]
fn linux_set_servers(alias: &str, servers: &[&str]) -> Result<(), String> {
    let mut args = vec!["dns", alias];
    args.extend_from_slice(servers);
    run_command("resolvectl", &args).map(|_| ())
}

#[cfg(target_os = "macos")]
pub fn configure_local_dns(app: &AppHandle) -> Result<(), String> {
    let path = backup_path(app)?;
    let states = if path.exists() {
        read_backup(&path)?
    } else {
        let states = mac_dns_states()?;
        write_backup(&path, &states)?;
        states
    };
    for state in &states {
        mac_set_servers(&state.alias, &["127.0.0.1", "::1"])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn restore_dns(app: &AppHandle) -> Result<(), String> {
    let path = backup_path(app)?;
    if !path.exists() {
        return Ok(());
    }
    let states = read_backup(&path)?;
    let mut first_error = None;
    for state in &states {
        let servers = state.servers.iter().map(String::as_str).collect::<Vec<_>>();
        let result = mac_set_servers(&state.alias, &servers);
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    fs::remove_file(path)
        .map_err(|error| format!("Unable to remove DNS settings backup: {error}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn mac_dns_states() -> Result<Vec<AdapterDnsState>, String> {
    let services = run_command("networksetup", &["-listallnetworkservices"])?;
    let mut states = Vec::new();
    for service in services.lines().skip(1) {
        let service = service.trim().trim_start_matches('*').trim();
        if service.is_empty() {
            continue;
        }
        let info = run_command("networksetup", &["-getinfo", service]).unwrap_or_default();
        if info.contains("IP address: none") || !info.contains("IP address:") {
            continue;
        }
        let dns = run_command("networksetup", &["-getdnsservers", service]).unwrap_or_default();
        let servers = dns
            .lines()
            .filter_map(|line| line.trim().parse::<IpAddr>().ok())
            .map(|address| address.to_string())
            .collect();
        states.push(AdapterDnsState {
            alias: service.to_string(),
            family: 0,
            servers,
        });
    }
    if states.is_empty() {
        return Err("No active macOS network services were found.".to_string());
    }
    Ok(states)
}

#[cfg(target_os = "macos")]
fn mac_set_servers(service: &str, servers: &[&str]) -> Result<(), String> {
    if servers.is_empty() {
        return run_command("networksetup", &["-setdnsservers", service, "empty"]).map(|_| ());
    }
    let mut args = vec!["-setdnsservers", service];
    args.extend_from_slice(servers);
    run_command("networksetup", &args).map(|_| ())
}

#[cfg(target_os = "android")]
pub fn configure_local_dns(_app: &AppHandle) -> Result<(), String> {
    Err("Android requires a VpnService backend for system-wide DNS filtering.".to_string())
}

#[cfg(target_os = "android")]
pub fn restore_dns(_app: &AppHandle) -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "android"
)))]
pub fn configure_local_dns(_app: &AppHandle) -> Result<(), String> {
    Err("This operating system has no supported DNS configuration backend.".to_string())
}

#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "android"
)))]
pub fn restore_dns(_app: &AppHandle) -> Result<(), String> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("Unable to run {program}: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
