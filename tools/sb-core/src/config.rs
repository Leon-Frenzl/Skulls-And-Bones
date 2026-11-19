//! S&B Suite — Central User-Configurable Settings (~/.sb/config.toml)
//! Eliminates hardcoded ports, endpoints, and thresholds across all tools.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::paths::sb_home;
use crate::ports::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SuiteConfig {
    #[serde(default)]
    pub ports: PortsConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortsConfig {
    pub mesh_udp: u16,
    pub proxy_ipc: u16,
    pub proxy_http: u16,
    pub proxy_https: u16,
    pub tunnel_hub: u16,
    pub mesh_ipc: u16,
    pub stealth_ssh: u16,
    pub default_dev_target: u16,
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            mesh_udp: DEFAULT_MESH_UDP_PORT,
            proxy_ipc: DEFAULT_PROXY_IPC_PORT,
            proxy_http: DEFAULT_HTTP_PORT,
            proxy_https: DEFAULT_HTTPS_PORT,
            tunnel_hub: DEFAULT_TUNNEL_HUB_PORT,
            mesh_ipc: DEFAULT_MESH_IPC_PORT,
            stealth_ssh: DEFAULT_STEALTH_SSH_PORT,
            default_dev_target: DEFAULT_DEV_TARGET_PORT,
        }
    }
}

use colored::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    pub default_server: Option<String>,
    pub server_pubkey: Option<String>,
    pub expected_node_ip: Option<String>,
    pub connect_timeout_ms: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            default_server: None,
            server_pubkey: None,
            expected_node_ip: None,
            connect_timeout_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    pub airgap_default: bool,
    pub lease_duration_secs: u64,
    pub secret_engine: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            airgap_default: false,
            lease_duration_secs: 28800, // 8 hours
            secret_engine: "vault".to_string(),
        }
    }
}

impl SuiteConfig {
    pub fn config_path() -> PathBuf {
        sb_home().join("config.toml")
    }

    /// Loads the suite config from ~/.sb/config.toml, or returns default if not present.
    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cfg) = toml::from_str::<SuiteConfig>(&content) {
                    return cfg;
                }
            }
        }
        Self::default()
    }

    /// Checks if ~/.sb/config.toml exists. If not, and stdin is an interactive terminal,
    /// queries the user for basic initial setup preferences, saves ~/.sb/config.toml,
    /// and returns the configuration.
    pub fn prompt_first_run() -> Self {
        let path = Self::config_path();
        if path.exists() {
            return Self::load();
        }

        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            let cfg = Self::default();
            let _ = cfg.save();
            return cfg;
        }

        println!(
            "\n{}",
            "💀 SKULLS & BONES — ERSTMALIGE EINRICHTUNG (FIRST-RUN SETUP)"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "──────────────────────────────────────────────────────────────────────────"
                .bright_black()
        );
        println!(
            "  Keine Konfigurationsdatei unter {} gefunden.",
            path.display().to_string().yellow()
        );
        println!("  Möchtest du Standardeinstellungen konfigurieren oder Standalone (rein lokal) starten?\n");

        use std::io::{self, Write};
        let mut cfg = Self::default();

        print!(
            "  [1] Flotten-Server Endpunkt (Host:Port) [Leer lassen für Standalone / 127.0.0.1]: "
        );
        let _ = io::stdout().flush();
        let mut server_input = String::new();
        if io::stdin().read_line(&mut server_input).is_ok() {
            let trimmed = server_input.trim();
            if !trimmed.is_empty() {
                cfg.network.default_server = Some(trimmed.to_string());
            }
        }

        print!(
            "  [2] Öffentliche Node-IP für Egress & Reverse-Proxy [Leer lassen falls rein lokal]: "
        );
        let _ = io::stdout().flush();
        let mut ip_input = String::new();
        if io::stdin().read_line(&mut ip_input).is_ok() {
            let trimmed = ip_input.trim();
            if !trimmed.is_empty() {
                cfg.network.expected_node_ip = Some(trimmed.to_string());
            }
        }

        if let Err(e) = cfg.save() {
            let err_str = e.to_string();
            crate::logfmt::warn(
                "ERR_CONFIG_SAVE",
                "core.config",
                "Failed to save suite configuration",
                &[("error", &err_str)],
            );
        } else {
            println!(
                "  {} Konfiguration gespeichert in: {}\n",
                "✓".green(),
                path.display().to_string().bright_black()
            );
        }

        cfg
    }

    /// Saves the configuration to ~/.sb/config.toml
    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        fs::write(&path, content)
            .map_err(|e| format!("Failed to write config file '{}': {}", path.display(), e))
    }

    /// Gets a value by dot-notation key (e.g. "ports.mesh_udp")
    pub fn get_value(&self, key: &str) -> Option<String> {
        match key {
            "ports.mesh_udp" => Some(self.ports.mesh_udp.to_string()),
            "ports.proxy_ipc" => Some(self.ports.proxy_ipc.to_string()),
            "ports.proxy_http" => Some(self.ports.proxy_http.to_string()),
            "ports.proxy_https" => Some(self.ports.proxy_https.to_string()),
            "ports.tunnel_hub" => Some(self.ports.tunnel_hub.to_string()),
            "ports.mesh_ipc" => Some(self.ports.mesh_ipc.to_string()),
            "ports.stealth_ssh" => Some(self.ports.stealth_ssh.to_string()),
            "ports.default_dev_target" => Some(self.ports.default_dev_target.to_string()),
            "network.default_server" => self.network.default_server.clone(),
            "network.server_pubkey" => self.network.server_pubkey.clone(),
            "network.expected_node_ip" => self.network.expected_node_ip.clone(),
            "network.connect_timeout_ms" => Some(self.network.connect_timeout_ms.to_string()),
            "security.airgap_default" => Some(self.security.airgap_default.to_string()),
            "security.lease_duration_secs" => Some(self.security.lease_duration_secs.to_string()),
            "security.secret_engine" => Some(self.security.secret_engine.clone()),
            _ => None,
        }
    }

    /// Sets a value by dot-notation key (e.g. "ports.mesh_udp", "59000")
    pub fn set_value(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "ports.mesh_udp" => {
                self.ports.mesh_udp = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "ports.proxy_ipc" => {
                self.ports.proxy_ipc = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "ports.proxy_http" => {
                self.ports.proxy_http = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "ports.proxy_https" => {
                self.ports.proxy_https = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "ports.tunnel_hub" => {
                self.ports.tunnel_hub = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "ports.mesh_ipc" => {
                self.ports.mesh_ipc = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "ports.stealth_ssh" => {
                self.ports.stealth_ssh = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "ports.default_dev_target" => {
                self.ports.default_dev_target = value.parse().map_err(|_| "Ungültiger Port")?
            }
            "network.default_server" => self.network.default_server = Some(value.to_string()),
            "network.server_pubkey" => self.network.server_pubkey = Some(value.to_string()),
            "network.expected_node_ip" => self.network.expected_node_ip = Some(value.to_string()),
            "network.connect_timeout_ms" => {
                self.network.connect_timeout_ms = value.parse().map_err(|_| "Ungültige Zahl")?
            }
            "security.airgap_default" => {
                self.security.airgap_default = value.parse().map_err(|_| "Erwartet true/false")?
            }
            "security.lease_duration_secs" => {
                self.security.lease_duration_secs =
                    value.parse().map_err(|_| "Ungültige Sekunden")?
            }
            "security.secret_engine" => self.security.secret_engine = value.to_string(),
            _ => return Err(format!("Unbekannter Konfigurations-Schlüssel '{}'", key)),
        }
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_config_defaults() {
        let cfg = SuiteConfig::default();
        assert_eq!(cfg.ports.mesh_udp, 58888);
        assert_eq!(cfg.ports.proxy_ipc, 58900);
        assert_eq!(cfg.ports.stealth_ssh, 58822);
        assert_eq!(cfg.ports.default_dev_target, 3000);
        assert_eq!(cfg.security.lease_duration_secs, 28800);
    }

    #[test]
    fn test_get_and_set_value() {
        let mut cfg = SuiteConfig::default();
        assert_eq!(cfg.get_value("ports.mesh_udp"), Some("58888".into()));

        // Update in memory without saving to disk
        cfg.ports.mesh_udp = 59999;
        assert_eq!(cfg.get_value("ports.mesh_udp"), Some("59999".into()));
    }
}
