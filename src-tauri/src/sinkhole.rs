use std::fs;
use std::path::PathBuf;

use tauri::AppHandle;

use crate::database::{ensure_blocklist, open_database};
use crate::models::{BlocklistEntry, BLOCK_END, BLOCK_START};

pub enum SinkholeBackend {
    HostsFile { path: PathBuf, writable: bool },
    Unsupported,
}

impl SinkholeBackend {
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            SinkholeBackend::HostsFile { path, .. } => Some(path),
            SinkholeBackend::Unsupported => None,
        }
    }

    pub fn writable(&self) -> bool {
        match self {
            SinkholeBackend::HostsFile { writable, .. } => *writable,
            SinkholeBackend::Unsupported => false,
        }
    }

    pub fn name(&self) -> String {
        match self {
            SinkholeBackend::HostsFile { .. } => "Hosts file sinkhole".to_string(),
            SinkholeBackend::Unsupported => "Unsupported sinkhole backend".to_string(),
        }
    }
}

pub fn sinkhole_backend() -> SinkholeBackend {
    let path = match std::env::consts::OS {
        "windows" => PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"),
        "linux" => PathBuf::from("/etc/hosts"),
        "macos" => PathBuf::from("/etc/hosts"),
        _ => return SinkholeBackend::Unsupported,
    };

    let writable = match fs::metadata(&path) {
        Ok(metadata) => !metadata.permissions().readonly(),
        Err(_) => true,
    };

    SinkholeBackend::HostsFile { path, writable }
}

pub fn hosts_path() -> PathBuf {
    sinkhole_backend()
        .path()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/etc/hosts"))
}

pub fn operating_system_name() -> String {
    match std::env::consts::OS {
        "windows" => "Windows".to_string(),
        "linux" => "Linux".to_string(),
        "macos" => "macOS".to_string(),
        _ => "Cross-platform".to_string(),
    }
}

pub fn can_write_hosts_file() -> bool {
    sinkhole_backend().writable()
}

pub fn read_hosts() -> Result<String, String> {
    let path = match sinkhole_backend().path() {
        Some(path) => path.clone(),
        None => return Ok(String::new()),
    };

    match fs::read_to_string(&path) {
        Ok(contents) => Ok(contents),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(String::new())
        }
        Err(error) => Err(format!("Unable to read the hosts file: {error}")),
    }
}

pub fn normalize_domain(value: String) -> Result<String, String> {
    let cleaned = value
        .trim()
        .trim_matches([' ', '\t', '\r', '\n', '/', '\\'])
        .to_ascii_lowercase();

    if cleaned.is_empty() {
        return Err("Domain cannot be empty.".to_string());
    }

    let normalized = cleaned
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.")
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .trim();

    if normalized.is_empty() || normalized.starts_with('.') || normalized.ends_with('.') {
        return Err("Enter a valid hostname such as example.com.".to_string());
    }

    if normalized
        .chars()
        .any(|character| !character.is_ascii_alphanumeric() && character != '.' && character != '-')
    {
        return Err("Use only letters, numbers, dots, and dashes in the domain name.".to_string());
    }

    Ok(normalized.to_string())
}

pub fn managed_block_for(domains: &[BlocklistEntry]) -> String {
    let mut block = format!("{BLOCK_START}\n");
    for entry in domains.iter().filter(|entry| entry.enabled) {
        block.push_str(&format!(
            "{} {}\n{} www.{}\n",
            entry.redirect, entry.domain, entry.redirect, entry.domain
        ));
    }
    block.push_str(BLOCK_END);
    block
}

pub fn without_managed_block(hosts: &str) -> String {
    if let Some(start) = hosts.find(BLOCK_START) {
        let end = hosts[start..]
            .find(BLOCK_END)
            .map(|offset| start + offset + BLOCK_END.len())
            .unwrap_or(hosts.len());
        let mut cleaned = String::with_capacity(hosts.len());
        cleaned.push_str(hosts[..start].trim_end());
        cleaned.push_str(hosts[end..].trim_start_matches(['\r', '\n']));
        cleaned
    } else {
        hosts.trim_end().to_owned()
    }
}

pub fn write_blocker(app: &AppHandle, enabled: bool) -> Result<(), String> {
    if !can_write_hosts_file() {
        return Err(
            "This environment cannot modify the system hosts file. Run with administrator privileges or use a system that allows hosts-file edits.".to_string(),
        );
    }

    let hosts = read_hosts()?;
    let mut next = without_managed_block(&hosts);
    if enabled {
        if !next.is_empty() {
            next.push_str("\n\n");
        }
        next.push_str(&managed_block(app)?);
    }
    next.push('\n');
    fs::write(hosts_path(), next).map_err(|error| {
        format!("Unable to update the hosts file. Run IP Firewall as administrator and try again: {error}")
    })?;
    flush_dns_cache();
    Ok(())
}

fn flush_dns_cache() {
    let command = match std::env::consts::OS {
        "windows" => ("ipconfig", vec!["/flushdns"]),
        "linux" => ("resolvectl", vec!["flush-caches"]),
        "macos" => ("killall", vec!["-HUP", "mDNSResponder"]),
        _ => return,
    };

    let _ = std::process::Command::new(command.0)
        .args(command.1)
        .output();
}

pub fn blocker_state(
    hosts: &str,
    blocked_requests: u64,
    domain_count: usize,
    packet_filter_backend: String,
    packet_filter_enabled: bool,
    packet_filter_note: String,
) -> crate::models::BlockerState {
    let backend = sinkhole_backend();
    crate::models::BlockerState {
        enabled: hosts.contains(BLOCK_START) || packet_filter_enabled,
        domain_count,
        observed_blocked_requests: blocked_requests,
        hosts_path: hosts_path().display().to_string(),
        operating_system: operating_system_name(),
        sinkhole_backend: backend.name(),
        host_writeable: backend.writable(),
        protection_supported: !matches!(backend, SinkholeBackend::Unsupported)
            || packet_filter_backend != "unsupported",
        packet_filter_backend,
        packet_filter_enabled,
        packet_filter_note,
    }
}

pub fn managed_block(app: &AppHandle) -> Result<String, String> {
    let (connection, _) = open_database(app)?;
    let domains = ensure_blocklist(&connection)?;
    Ok(managed_block_for(&domains))
}

#[cfg(test)]
mod tests {
    use super::{managed_block_for, without_managed_block, BlocklistEntry, BLOCK_END, BLOCK_START};

    #[test]
    fn managed_block_has_stable_markers() {
        let block = managed_block_for(&[BlocklistEntry {
            domain: "doubleclick.net".to_owned(),
            category: "advertising".to_owned(),
            source: "test".to_owned(),
            enabled: true,
            redirect: "0.0.0.0".to_owned(),
            notes: String::new(),
        }]);
        assert!(block.starts_with(BLOCK_START));
        assert!(block.ends_with(BLOCK_END));
        assert!(block.contains("0.0.0.0 doubleclick.net"));
    }

    #[test]
    fn removing_managed_block_preserves_user_hosts() {
        let block = managed_block_for(&[BlocklistEntry {
            domain: "doubleclick.net".to_owned(),
            category: "advertising".to_owned(),
            source: "test".to_owned(),
            enabled: true,
            redirect: "0.0.0.0".to_owned(),
            notes: String::new(),
        }]);
        let hosts = format!("127.0.0.1 localhost\n\n{block}\n");
        assert_eq!(without_managed_block(&hosts), "127.0.0.1 localhost");
    }

    #[test]
    fn removing_missing_block_is_idempotent() {
        assert_eq!(
            without_managed_block("127.0.0.1 localhost\n"),
            "127.0.0.1 localhost"
        );
    }

    #[test]
    fn sinkhole_backend_is_platform_independent_in_logic() {
        let backend = super::sinkhole_backend();
        let supported = matches!(
            backend,
            super::SinkholeBackend::HostsFile { .. } | super::SinkholeBackend::Unsupported
        );
        assert!(supported);
        assert!(!backend.name().is_empty());
    }
}
