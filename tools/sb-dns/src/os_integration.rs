use std::process::Command;

pub struct OsIntegration;

impl OsIntegration {
    /// Install OS split-DNS routing for .sbm namespace
    pub fn install_split_dns(dns_server_ip: &str) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            // Use Windows PowerShell NRPT (Name Resolution Policy Table)
            // Add-DnsClientNrptRule routes ONLY queries matching the namespace to the specified nameserver
            let script = format!(
                "Add-DnsClientNrptRule -Namespace '.sbm' -NameServers '{}' -DisplayName 'Sovereign-SBM' -Comment 'Skulls and Bones Sovereign Mesh DNS' -ErrorAction Stop",
                dns_server_ip
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
                .map_err(|e| format!("Failed to execute powershell: {}", e))?;

            if output.status.success() {
                Ok(format!(
                    "Windows NRPT rule active: '.sbm' routed to {}",
                    dns_server_ip
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
            // Try systemd-resolved split-domain routing: resolvectl domain <link> ~sbm
            let output = Command::new("resolvectl").args(["status"]).output();

            if let Ok(out) = output {
                if out.status.success() {
                    return Ok("systemd-resolved detected. Run: sudo resolvectl domain <interface> ~sbm; sudo resolvectl dns <interface> 127.0.0.1".into());
                }
            }
            Ok("Linux: Add 'nameserver 127.0.0.1' to /etc/resolv.conf or configure systemd-resolved.".into())
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Ok("Configure system DNS to 127.0.0.1".into())
        }
    }

    /// Uninstall OS split-DNS routing
    pub fn uninstall_split_dns() -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let script = "Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq 'Sovereign-SBM' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue";

            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ])
                .output()
                .map_err(|e| format!("Failed to execute powershell: {}", e))?;

            if output.status.success() {
                Ok("Windows NRPT rule 'Sovereign-SBM' removed successfully.".into())
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

    /// Check if OS split-DNS rule is currently registered
    pub fn is_split_dns_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            let script = "$rule = Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq 'Sovereign-SBM' }; if ($rule) { exit 0 } else { exit 1 }";
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
