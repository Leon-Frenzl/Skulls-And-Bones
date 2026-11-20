use std::net::IpAddr;
use std::process::Command;

pub struct OsIntegration;

fn validate_dns_namespace(ns: &str) -> Result<String, String> {
    let trimmed = ns.trim().trim_start_matches('.');
    if trimmed.is_empty()
        || trimmed.len() > 253
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!("Ungültiger DNS-Namespace '{ns}'"));
    }
    Ok(format!(".{trimmed}"))
}

impl OsIntegration {
    /// Install OS split-DNS routing for `.sbm` namespace.
    pub fn install_split_dns(dns_server_ip: &str) -> Result<String, String> {
        Self::install_split_dns_for_domains(dns_server_ip, &[".sbm"])
    }

    /// Install OS split-DNS routing for one or more sovereign namespaces (e.g. `[".sbm", ".corp.eu"]`).
    // [SECURITY-HYPOTHESIS] CWE-78: Unvalidated IP or domain suffix interpolated into PowerShell/resolvectl command.
    // [SECURITY-VERIFIED] Parses `dns_server_ip` strictly as `IpAddr` and validates each namespace to `[a-zA-Z0-9.-]`.
    pub fn install_split_dns_for_domains(
        dns_server_ip: &str,
        namespaces: &[&str],
    ) -> Result<String, String> {
        let parsed_ip: IpAddr = dns_server_ip
            .trim()
            .parse()
            .map_err(|_| format!("Ungültige DNS-Server-IP '{dns_server_ip}'"))?;
        let mut clean_ns = Vec::with_capacity(namespaces.len());
        for ns in namespaces {
            clean_ns.push(validate_dns_namespace(ns)?);
        }
        if clean_ns.is_empty() {
            clean_ns.push(".sbm".to_string());
        }

        #[cfg(target_os = "windows")]
        {
            let ns_array = clean_ns
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(",");
            let script = format!(
                "Get-DnsClientNrptRule | Where-Object {{ $_.DisplayName -eq 'Sovereign-SBM' -or $_.DisplayName -eq 'Sovereign-Domain' }} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; Add-DnsClientNrptRule -Namespace @({ns_array}) -NameServers '{parsed_ip}' -DisplayName 'Sovereign-Domain' -Comment 'Skulls and Bones Sovereign Split-DNS' -ErrorAction Stop"
            );

            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    &script,
                ])
                .output()
                .map_err(|e| format!("Failed to execute powershell: {e}"))?;

            if output.status.success() {
                Ok(format!(
                    "Windows NRPT rule active: [{}] -> {}",
                    clean_ns.join(", "),
                    parsed_ip
                ))
            } else {
                let err = String::from_utf8_lossy(&output.stderr);
                Err(format!(
                    "NRPT configuration failed (Elevated prompt may be required): {}",
                    err.trim()
                ))
            }
        }

        #[cfg(target_os = "linux")]
        {
            let domains_arg = clean_ns
                .iter()
                .map(|n| format!("~{}", n.trim_start_matches('.')))
                .collect::<Vec<_>>()
                .join(" ");
            let output = Command::new("resolvectl").args(["status"]).output();

            if let Ok(out) = output {
                if out.status.success() {
                    return Ok(format!(
                        "systemd-resolved detected. Configure split-DNS: sudo resolvectl domain <interface> {domains_arg}; sudo resolvectl dns <interface> {parsed_ip}"
                    ));
                }
            }
            Ok(format!(
                "Linux: Add 'nameserver {parsed_ip}' to /etc/resolv.conf or configure systemd-resolved ({domains_arg})."
            ))
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Ok(format!(
                "Configure system DNS to {parsed_ip} for [{}]",
                clean_ns.join(", ")
            ))
        }
    }

    /// Uninstall OS split-DNS routing (`.sbm` and domain rules).
    pub fn uninstall_split_dns() -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let script = "Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq 'Sovereign-SBM' -or $_.DisplayName -eq 'Sovereign-Domain' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue";

            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ])
                .output()
                .map_err(|e| format!("Failed to execute powershell: {e}"))?;

            if output.status.success() {
                Ok("Windows NRPT rules ('Sovereign-SBM', 'Sovereign-Domain') removed successfully.".into())
            } else {
                let err = String::from_utf8_lossy(&output.stderr);
                Err(format!("Failed to remove NRPT rule: {}", err.trim()))
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok("Remove custom DNS settings from /etc/resolv.conf or resolvectl".into())
        }
    }

    /// Check if OS split-DNS rule is currently registered.
    pub fn is_split_dns_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            let script = "$rule = Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq 'Sovereign-SBM' -or $_.DisplayName -eq 'Sovereign-Domain' }; if ($rule) { exit 0 } else { exit 1 }";
            if let Ok(out) = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ])
                .output()
            {
                return out.status.success();
            }
            false
        }

        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_dns_validation_rejects_injection() {
        assert_eq!(validate_dns_namespace("corp.eu").unwrap(), ".corp.eu");
        assert!(validate_dns_namespace("corp.eu; rm -rf /").is_err());
        assert!(OsIntegration::install_split_dns_for_domains("not-an-ip", &[".sbm"]).is_err());
    }
}
