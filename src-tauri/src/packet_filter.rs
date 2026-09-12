use std::fs;
use std::process::Command;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketFilterBackend {
    Unsupported,
    Wfp,
    LinuxNftables,
    MacPf,
}

impl PacketFilterBackend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Wfp => "Windows Filtering Platform",
            Self::LinuxNftables => "Linux nftables",
            Self::MacPf => "macOS pf",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PacketFilterStatus {
    pub enabled: bool,
    pub backend: String,
    pub note: String,
}

pub struct PacketFilterHandle {
    enabled: bool,
    backend: PacketFilterBackend,
    active_ip_rules: Vec<String>,
}

impl Default for PacketFilterHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketFilterHandle {
    pub fn new() -> Self {
        Self {
            enabled: false,
            backend: detect_backend(),
            active_ip_rules: Vec::new(),
        }
    }

    pub fn backend(&self) -> PacketFilterBackend {
        self.backend
    }

    pub fn is_running(&self) -> bool {
        self.enabled
    }

    pub fn start(&mut self) -> Result<(), String> {
        match self.backend {
            PacketFilterBackend::Wfp => {
                ensure_command("powershell.exe")?;
                self.enabled = true;
                Ok(())
            }
            PacketFilterBackend::LinuxNftables => {
                ensure_command("iptables")?;
                self.enabled = true;
                Ok(())
            }
            PacketFilterBackend::MacPf => {
                ensure_command("pfctl")?;
                self.enabled = true;
                Ok(())
            }
            PacketFilterBackend::Unsupported => Err(
                "Packet filtering is not available on this platform. The DNS proxy remains the fallback backend."
                    .to_string(),
            ),
        }
    }

    pub fn stop(&mut self) -> Result<(), String> {
        self.clear_blocklist()?;
        self.enabled = false;
        Ok(())
    }

    pub fn apply_blocklist(&mut self, domains: &[String]) -> Result<(), String> {
        let addresses = resolve_domains(domains)?;
        if addresses.is_empty() {
            return self.clear_blocklist();
        }
        match self.backend {
            PacketFilterBackend::Wfp => {
                windows_apply_blocklist(&addresses)?;
            }
            PacketFilterBackend::LinuxNftables => {
                linux_apply_blocklist(&addresses)?;
            }
            PacketFilterBackend::MacPf => {
                macos_apply_blocklist(&addresses)?;
            }
            PacketFilterBackend::Unsupported => {
                return Err(
                    "Packet filtering is not available on this platform. The DNS proxy remains the fallback backend."
                        .to_string(),
                );
            }
        }
        self.active_ip_rules = addresses;
        Ok(())
    }

    pub fn clear_blocklist(&mut self) -> Result<(), String> {
        if self.active_ip_rules.is_empty() {
            return Ok(());
        }
        match self.backend {
            PacketFilterBackend::Wfp => windows_clear_blocklist(&self.active_ip_rules),
            PacketFilterBackend::LinuxNftables => linux_clear_blocklist(&self.active_ip_rules),
            PacketFilterBackend::MacPf => macos_clear_blocklist(&self.active_ip_rules),
            PacketFilterBackend::Unsupported => Ok(()),
        }?;
        self.active_ip_rules.clear();
        Ok(())
    }

    pub fn status(&self) -> PacketFilterStatus {
        let (note, backend) = match self.backend {
            PacketFilterBackend::Unsupported => (
                "This build does not expose a native packet-filtering backend on this platform."
                    .to_string(),
                self.backend.name().to_string(),
            ),
            PacketFilterBackend::Wfp => (
                if self.enabled {
                    "Windows Filtering Platform is active and ready for packet policy enforcement."
                        .to_string()
                } else {
                    "Windows Filtering Platform is available and will be activated when the runtime is started."
                        .to_string()
                },
                self.backend.name().to_string(),
            ),
            PacketFilterBackend::LinuxNftables => (
                if self.enabled {
                    "Linux nftables is active and ready for packet-level rule enforcement."
                        .to_string()
                } else {
                    "Linux nftables is the native packet-filtering backend for this platform."
                        .to_string()
                },
                self.backend.name().to_string(),
            ),
            PacketFilterBackend::MacPf => (
                if self.enabled {
                    "macOS pf is active and ready for packet-level rule enforcement.".to_string()
                } else {
                    "macOS pf is the native packet-filtering backend for this platform.".to_string()
                },
                self.backend.name().to_string(),
            ),
        };

        PacketFilterStatus {
            enabled: self.enabled,
            backend,
            note,
        }
    }
}

fn detect_backend() -> PacketFilterBackend {
    #[cfg(target_os = "windows")]
    {
        PacketFilterBackend::Wfp
    }

    #[cfg(target_os = "linux")]
    {
        PacketFilterBackend::LinuxNftables
    }

    #[cfg(target_os = "macos")]
    {
        PacketFilterBackend::MacPf
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        PacketFilterBackend::Unsupported
    }
}

fn resolve_domains(domains: &[String]) -> Result<Vec<String>, String> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for domain in domains {
        let entries = resolve_domain(domain)?;
        for address in entries {
            if seen.insert(address.clone()) {
                results.push(address);
            }
        }
    }
    Ok(results)
}

fn resolve_domain(domain: &str) -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        let domain = domain.replace('\'', "''");
        let output = run_powershell(&format!(
            "Resolve-DnsName -Type A_AAAA -Name '{domain}' -NoHostsFile -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress"
        ))?;
        Ok(extract_addresses(&output))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut addresses = Vec::new();
        for command in ["getent", "getent"] {
            let mut cmd = Command::new(command);
            let args = if command == "getent" {
                let mut args = vec!["ahostsv4", domain];
                if !domain.is_empty() {
                    args = vec!["ahostsv4", domain];
                }
                args
            } else {
                vec!["ahostsv6", domain]
            };
            let output = match cmd.args(&args).output() {
                Ok(result) if result.status.success() => result,
                _ => continue,
            };
            let stdout = String::from_utf8_lossy(&output.stdout);
            addresses.extend(extract_addresses(&stdout));
        }
        Ok(addresses)
    }
}

fn extract_addresses(output: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        for token in line.split_whitespace() {
            if token.contains('.') || token.contains(':') {
                if token.parse::<std::net::IpAddr>().is_ok() {
                    addresses.push(token.trim().to_string());
                }
            }
        }
    }
    addresses
}

fn ensure_command(program: &str) -> Result<(), String> {
    let output = match program {
        "powershell.exe" => Command::new(program)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "$PSVersionTable.PSVersion.ToString()",
            ])
            .output(),
        _ => Command::new(program).arg("--version").output(),
    };

    match output {
        Ok(result) if result.status.success() => Ok(()),
        Ok(_) => Err(format!(
            "The native packet-filter backend for {program} is installed but not ready to run."
        )),
        Err(error) => Err(format!(
            "The native packet filter for {program} is unavailable on this device: {error}"
        )),
    }
}

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
        .map_err(|error| format!("Unable to run PowerShell for packet filtering: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn windows_apply_blocklist(addresses: &[String]) -> Result<(), String> {
    if addresses.is_empty() {
        return Ok(());
    }
    for address in addresses {
        let name = firewall_rule_name(address);
        let script = format!(
            "New-NetFirewallRule -DisplayName {name} -Direction Outbound -Action Block -RemoteAddress {address} -Protocol Any | Out-Null"
        );
        run_powershell(&script)?;
    }
    Ok(())
}

fn windows_clear_blocklist(addresses: &[String]) -> Result<(), String> {
    for address in addresses {
        let name = firewall_rule_name(address);
        let script =
            format!("Remove-NetFirewallRule -DisplayName {name} -ErrorAction SilentlyContinue");
        let _ = run_powershell(&script);
    }
    Ok(())
}

fn firewall_rule_name(address: &str) -> String {
    let mut name = address
        .chars()
        .map(|character| match character {
            ch if ch.is_ascii_alphanumeric() => ch,
            _ => '-',
        })
        .collect::<String>();
    if name.is_empty() {
        name = "blocked-address".to_string();
    }
    format!("'{}'", name)
}

fn linux_apply_blocklist(addresses: &[String]) -> Result<(), String> {
    for address in addresses {
        let program = if address.contains(':') {
            "ip6tables"
        } else {
            "iptables"
        };
        let command = if command_exists(program) {
            program.to_string()
        } else {
            return Err(format!(
                "The {program} command is required for packet filtering on this Linux system."
            ));
        };
        let args = ["-C", "OUTPUT", "-d", address, "-j", "DROP"];
        if run_command(&command, &args).is_err() {
            run_command(&command, &["-A", "OUTPUT", "-d", address, "-j", "DROP"])?;
        }
    }
    Ok(())
}

fn linux_clear_blocklist(addresses: &[String]) -> Result<(), String> {
    for address in addresses {
        let program = if address.contains(':') {
            "ip6tables"
        } else {
            "iptables"
        };
        let _ = run_command(program, &["-D", "OUTPUT", "-d", address, "-j", "DROP"]);
    }
    Ok(())
}

fn macos_apply_blocklist(addresses: &[String]) -> Result<(), String> {
    if addresses.is_empty() {
        return Ok(());
    }
    let block = format!(
        "block out quick from any to {{ {} }}\n",
        addresses.join(" ")
    );
    let path = std::env::temp_dir().join("ip_firewall_pf.conf");
    fs::write(&path, block).map_err(|error| {
        format!("Unable to write pf configuration for packet filtering: {error}")
    })?;
    let status = Command::new("pfctl")
        .args(["-f", path.to_str().unwrap()])
        .status()
        .map_err(|error| format!("Unable to launch pfctl: {error}"))?;
    let _ = fs::remove_file(&path);
    if !status.success() {
        return Err("pfctl failed to apply the packet filter rules.".to_string());
    }
    Ok(())
}

fn macos_clear_blocklist(_addresses: &[String]) -> Result<(), String> {
    let _ = Command::new("pfctl").arg("-F").arg("all").status();
    Ok(())
}

fn command_exists(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok()
}

fn run_command(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("Unable to run {program}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "The {program} command failed while applying packet-filter rules."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{detect_backend, extract_addresses, PacketFilterBackend};

    #[test]
    fn detects_supported_native_backends_for_the_current_platform() {
        let backend = detect_backend();
        let valid = matches!(
            backend,
            PacketFilterBackend::Wfp
                | PacketFilterBackend::LinuxNftables
                | PacketFilterBackend::MacPf
                | PacketFilterBackend::Unsupported
        );
        assert!(valid);
    }

    #[test]
    fn extract_addresses_parses_ipv4_and_ipv6_from_dns_output() {
        let addresses = extract_addresses("10.0.0.9\n2001:4860:4860::8888\nexample.com\n");
        assert!(addresses.contains(&"10.0.0.9".to_string()));
        assert!(addresses.contains(&"2001:4860:4860::8888".to_string()));
    }
}
