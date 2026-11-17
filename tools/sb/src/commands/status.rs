use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::context;
use crate::meta::{
    available_tools, check_binary_version, get_sb_dir, print_banner, SovereignIdentity,
};
use crate::process_ledger;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportLevel {
    Optimal,
    Active,
    Ready,
    Warning,
    Error,
    Muted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEntry {
    pub label: String,
    pub status: String,
    pub detail: Option<String>,
    pub level: ReportLevel,
}

impl TelemetryEntry {
    pub fn new(
        label: impl Into<String>,
        status: impl Into<String>,
        detail: Option<String>,
        level: ReportLevel,
    ) -> Self {
        Self {
            label: label.into(),
            status: status.into(),
            detail,
            level,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolStatusItem {
    pub id: String,
    pub binary: String,
    pub title: String,
    pub package_name: String,
    pub category: String,
    pub maturity: String,
    pub installed_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveContextSummary {
    pub name: String,
    pub env: String,
    pub target_server: Option<String>,
    pub workspace_root: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StatusReport {
    pub context: Option<ActiveContextSummary>,
    pub tools: Vec<ToolStatusItem>,
    pub telemetry: Vec<TelemetryEntry>,
}

impl StatusReport {
    pub fn render_terminal(&self) {
        print_banner();
        println!(
            "  {} {}\n",
            "► SYSTEM AUDIT & WERKZEUG-STATUS".bold(),
            "[LIVE]".bright_green()
        );

        if let Some(ctx) = &self.context {
            let env_styled = match ctx.env.to_lowercase().as_str() {
                "prod" | "production" => ctx.env.bright_red().bold(),
                "staging" | "stage" => ctx.env.bright_yellow().bold(),
                _ => ctx.env.bright_green(),
            };
            println!(
                "  {} Aktiver Kontext: {} [{}]",
                "★".bright_yellow().bold(),
                ctx.name.bright_white().bold(),
                env_styled
            );
            if let Some(srv) = &ctx.target_server {
                println!("    └─ Default Server:  {}", srv.cyan());
            }
            if let Some(ws) = &ctx.workspace_root {
                println!("    └─ Workspace Root:  {}", ws.bright_black());
            }
            println!();
        }

        // Tools Table
        println!(
            "  {:<12} {:<36} {:<18} {:<38} {:<16}",
            "BINARY", "NAME & ROLLE", "BEREICH", "REIFEGRAD", "STATUS"
        );
        println!("  {}", "─".repeat(124).bright_black());

        let mut uninstalled_count = 0;
        for tool in &self.tools {
            let status_str = match &tool.installed_version {
                Some(v) => format!("✓ v{}", v).bright_green(),
                None => {
                    uninstalled_count += 1;
                    format!("○ sb install {}", tool.id).bright_black()
                }
            };
            let desc = format!("{} ({})", tool.title, tool.package_name);
            println!(
                "  {:<12} {:<36} {:<18} {:<38} {:<16}",
                tool.binary.bold(),
                desc,
                tool.category.bright_black(),
                tool.maturity.bright_yellow(),
                status_str
            );
        }
        println!("  {}", "─".repeat(124).bright_black());

        if uninstalled_count > 0 {
            println!(
                "  {} {} Werkzeug(e) nicht installiert. Installieren mit: {}",
                "i".bright_cyan(),
                uninstalled_count,
                "sb install <id>".bright_yellow()
            );
        }

        // Telemetry Section
        println!(
            "\n  {} {}\n",
            "► DAEMON & SERVICE TELEMETRIE".bold(),
            "[SOCKET-PROBE]".bright_cyan()
        );

        for probe in &self.telemetry {
            let status_display = match probe.level {
                ReportLevel::Optimal => probe.status.bright_green().bold(),
                ReportLevel::Active => probe.status.bright_green().bold(),
                ReportLevel::Ready => probe.status.bright_cyan().bold(),
                ReportLevel::Warning => probe.status.bright_yellow().bold(),
                ReportLevel::Error => probe.status.bright_red().bold(),
                ReportLevel::Muted => probe.status.bright_black(),
            };

            let formatted = if let Some(detail) = &probe.detail {
                format!("{} ({})", status_display, detail)
            } else {
                status_display.to_string()
            };

            println!("  {:<26}{}", probe.label, formatted);
        }

        // Footer
        println!(
            "\n  {} Schnellauswahl: {} · {} · {} · {}",
            "i".bright_black(),
            "sb ps".bold(),
            "sb stop".bold(),
            "sb install <id>".bold(),
            "sb status".bold()
        );
    }
}

pub struct ReportBuilder {
    report: StatusReport,
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            report: StatusReport::default(),
        }
    }

    pub fn collect_active_context(mut self) -> Self {
        let (active_ctx, _detected) = context::ContextStore::new().active_or_detected();
        self.report.context = Some(ActiveContextSummary {
            name: active_ctx.name,
            env: active_ctx.env,
            target_server: active_ctx.target_server,
            workspace_root: active_ctx.workspace_root.map(|p| p.display().to_string()),
        });
        self
    }

    pub fn collect_tools(mut self) -> Self {
        self.report.tools = available_tools()
            .iter()
            .map(|t| {
                let bin = t.binary_name.as_deref().unwrap_or_default();
                ToolStatusItem {
                    id: t.id.to_string(),
                    binary: bin.to_string(),
                    title: t.title.to_string(),
                    package_name: t.package_name.to_string(),
                    category: t.category.to_string(),
                    maturity: t.maturity.label().to_string(),
                    installed_version: check_binary_version(bin),
                }
            })
            .collect();
        self
    }

    pub fn collect_telemetry(mut self) -> Self {
        self.report.telemetry = vec![
            probe_mesh_ipc(),
            probe_tunnel_manager(),
            probe_shared_identity(),
            probe_root_key(),
            probe_ram_lease(),
            probe_edge_gateway(),
            probe_developer_ca(),
            probe_process_ledger(),
        ];
        self
    }

    pub fn build(self) -> StatusReport {
        self.report
    }
}

pub fn handle_status() {
    let report = ReportBuilder::new()
        .collect_active_context()
        .collect_tools()
        .collect_telemetry()
        .build();

    report.render_terminal();
}

pub fn handle_status_json() {
    let report = ReportBuilder::new()
        .collect_active_context()
        .collect_tools()
        .collect_telemetry()
        .build();

    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

fn probe_mesh_ipc() -> TelemetryEntry {
    let label = "S&B Mesh Daemon IPC:".to_string();
    let mesh_ipc_port = sb_core::config::SuiteConfig::load().ports.mesh_ipc;
    let mesh_ipc_addr = format!("127.0.0.1:{}", mesh_ipc_port);
    if let Ok(addr) = mesh_ipc_addr.parse::<std::net::SocketAddr>() {
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            let _ = stream.write_all(br#"{"action":"GetStatus"}"#);
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&buf[..n]) {
                    let peer_cnt = val
                        .get("data")
                        .and_then(|d| d.get("peer_count"))
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0);
                    return TelemetryEntry::new(
                        label,
                        "ONLINE",
                        Some(format!("{} aktive Peers", peer_cnt)),
                        ReportLevel::Optimal,
                    );
                }
            }
            return TelemetryEntry::new(
                label,
                "ONLINE",
                Some(format!("Port {} erreichbar", mesh_ipc_port)),
                ReportLevel::Optimal,
            );
        }
    }
    TelemetryEntry::new(
        label,
        "OFFLINE",
        Some("Daemon nicht gestartet".to_string()),
        ReportLevel::Muted,
    )
}

fn probe_tunnel_manager() -> TelemetryEntry {
    let label = "S&B Tunnel Manager:".to_string();
    let tunnel_path = sb_core::paths::tunnels_config_path();
    if tunnel_path.exists() {
        if let Ok(data) = fs::read_to_string(&tunnel_path) {
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&data) {
                return TelemetryEntry::new(
                    label,
                    format!("{} Profile", arr.len()),
                    Some("konfiguriert".to_string()),
                    ReportLevel::Ready,
                );
            }
        }
    }
    TelemetryEntry::new(
        label,
        "0 Profile",
        Some("Bereit".to_string()),
        ReportLevel::Muted,
    )
}

fn probe_shared_identity() -> TelemetryEntry {
    let label = "Gemeinsame Identität:".to_string();
    let sb_dir = get_sb_dir();
    let id_file = sb_dir.join("identity.json");
    if id_file.exists() {
        if let Ok(data) = fs::read_to_string(&id_file) {
            if let Ok(id) = serde_json::from_str::<SovereignIdentity>(&data) {
                return TelemetryEntry::new(
                    label,
                    id.callsign,
                    Some(id.node_fingerprint),
                    ReportLevel::Active,
                );
            }
        }
        return TelemetryEntry::new(label, "Initialisiert", None, ReportLevel::Active);
    }
    TelemetryEntry::new(
        label,
        "Nicht erzeugt",
        Some("Führe 'sb identity' aus".to_string()),
        ReportLevel::Warning,
    )
}

fn probe_root_key() -> TelemetryEntry {
    let label = "Sovereign Root Key:".to_string();
    let root_key_file = get_sb_dir().join("identity.sbkey");
    if root_key_file.exists() {
        TelemetryEntry::new(
            label,
            "VORHANDEN",
            Some("~/.sb/identity.sbkey".to_string()),
            ReportLevel::Optimal,
        )
    } else {
        TelemetryEntry::new(
            label,
            "NICHT INITIALISIERT",
            Some("'sb key init'".to_string()),
            ReportLevel::Warning,
        )
    }
}

fn probe_ram_lease() -> TelemetryEntry {
    let label = "Ephemeral RAM Lease:".to_string();
    let lease_file = get_sb_dir().join("lease.json");
    if lease_file.exists() {
        if let Ok(data) = fs::read_to_string(&lease_file) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(exp_str) = v.get("expires_at").and_then(|e| e.as_str()) {
                    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(exp_str)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                    {
                        let now = chrono::Utc::now();
                        if exp > now {
                            let rem = exp - now;
                            let total_secs = rem.num_seconds();
                            let h = total_secs / 3600;
                            let m = (total_secs % 3600) / 60;
                            let s = total_secs % 60;
                            let callsign = v
                                .get("callsign")
                                .and_then(|c| c.as_str())
                                .unwrap_or("Operator");
                            return TelemetryEntry::new(
                                label,
                                "AKTIV",
                                Some(format!(
                                    "Aktiv für {}, {:02}h {:02}m {:02}s verbleibend",
                                    callsign, h, m, s
                                )),
                                ReportLevel::Active,
                            );
                        } else {
                            return TelemetryEntry::new(
                                label,
                                "ABGELAUFEN",
                                Some("'sb lease' zum Erneuern".to_string()),
                                ReportLevel::Error,
                            );
                        }
                    }
                }
                return TelemetryEntry::new(
                    label,
                    "UNBEKANNTES FORMAT",
                    None,
                    ReportLevel::Warning,
                );
            }
            return TelemetryEntry::new(label, "UNGÜLTIG", None, ReportLevel::Warning);
        }
        return TelemetryEntry::new(label, "NICHT LESBAR", None, ReportLevel::Warning);
    }
    TelemetryEntry::new(
        label,
        "INAKTIV / GESPERRT",
        Some("'sb lease' zum Entsperren".to_string()),
        ReportLevel::Muted,
    )
}

fn probe_edge_gateway() -> TelemetryEntry {
    let label = "Edge Gateway (sb-proxy):".to_string();
    let proxy_exists = which::which("sb-proxy").is_ok()
        || std::path::Path::new("tools/sb-proxy").exists()
        || std::path::Path::new("../sb-proxy").exists();

    if let Ok(addr) = "127.0.0.1:58900".parse::<std::net::SocketAddr>() {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok() {
            return TelemetryEntry::new(
                label,
                "ONLINE",
                Some("127.0.0.1:58900 / IPC Telemetrie aktiv".to_string()),
                ReportLevel::Optimal,
            );
        } else if proxy_exists {
            return TelemetryEntry::new(
                label,
                "BEREIT",
                Some("Gestoppt - Start mit 'sb proxy start'".to_string()),
                ReportLevel::Muted,
            );
        }
    }
    TelemetryEntry::new(
        label,
        "NICHT INSTALLIERT",
        Some("'sb install proxy'".to_string()),
        ReportLevel::Warning,
    )
}

/// Probes the unified `sb-ca` PKI status (X.509 Root CA, OpenSSH CA, and OS Trust Store anchoring).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Inaccurate telemetry reporting untrusted Root CA on Linux/macOS due to platform-specific stub.
/// - CVE / CWE Mapping: CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Queries `sb_ca::status()` and `sb_ca::is_root_ca_installed()` across all host operating systems.
/// - Standards Compliance: Conforms to IETF RFC 5280 (X.509) and IETF RFC 4251 (OpenSSH).
fn probe_developer_ca() -> TelemetryEntry {
    let label = "Developer CA (sb ca):".to_string();
    if let Ok(ca_status) = sb_ca::status() {
        if ca_status.x509.initialized || ca_status.ssh.initialized {
            let is_trusted = sb_ca::is_root_ca_installed();
            let trust_str = if is_trusted {
                "OS-Trust: AKTIV"
            } else {
                "OS-Trust: INAKTIV ('sb-ca install-root')"
            };
            let ssh_str = if ca_status.ssh.initialized {
                "SSH-CA: AKTIV"
            } else {
                "SSH-CA: INAKTIV"
            };
            let level = if is_trusted && ca_status.ssh.initialized {
                ReportLevel::Optimal
            } else {
                ReportLevel::Active
            };
            return TelemetryEntry::new(
                label,
                "INITIALISIERT",
                Some(format!(
                    "{} Zertifikate, {}, {}",
                    ca_status.x509.issued_certs_count, ssh_str, trust_str
                )),
                level,
            );
        }
    }
    TelemetryEntry::new(
        label,
        "NICHT INITIALISIERT",
        Some("'sb-ca init'".to_string()),
        ReportLevel::Warning,
    )
}

fn probe_process_ledger() -> TelemetryEntry {
    let label = "Hintergrund-Dienste:".to_string();
    let mut ledger = process_ledger::load_ledger();
    let _ = process_ledger::prune_dead(&mut ledger);
    if ledger.processes.is_empty() {
        TelemetryEntry::new(
            label,
            "0 aktiv",
            Some("On-Demand Auto-Spawn".to_string()),
            ReportLevel::Muted,
        )
    } else {
        TelemetryEntry::new(
            label,
            format!("{} aktiv", ledger.processes.len()),
            Some("'sb ps' für Details, 'sb stop' zum Beenden".to_string()),
            ReportLevel::Active,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_report_builder_pipeline() {
        let report = ReportBuilder::new()
            .collect_active_context()
            .collect_tools()
            .collect_telemetry()
            .build();

        assert!(!report.tools.is_empty(), "Tools list should not be empty");
        assert_eq!(
            report.telemetry.len(),
            8,
            "Expected exactly 8 telemetry probes"
        );

        let json_val = serde_json::to_value(&report).unwrap();
        assert!(json_val.get("tools").is_some());
        assert!(json_val.get("telemetry").is_some());
        assert!(json_val.get("context").is_some());
    }
}
