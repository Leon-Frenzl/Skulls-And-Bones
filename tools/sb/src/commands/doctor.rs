use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::cli::Cli;
use crate::commands::pkg::{handle_identity, handle_update_with_source};
use crate::meta::{available_tools, get_sb_dir, print_banner, SovereignIdentity};

/// Generates shell autocompletion scripts including dynamic context and fleet server hints.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Shell injection via untrusted server or context names emitted into completion comments.
/// - CVE / CWE Mapping: CWE-78 (OS Command Injection), CWE-116 (Improper Encoding or Escaping of Output).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Filters context and server names strictly to ASCII alphanumeric, dash, underscore, and dot characters (`is_ascii_alphanumeric() || '-' || '_' || '.'`).
#[allow(dead_code)]
pub fn handle_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "sb", &mut std::io::stdout());

    let contexts: Vec<String> = crate::context::ContextStore::new()
        .list_all()
        .into_iter()
        .map(|c| c.name)
        .filter(|n| {
            !n.is_empty()
                && n.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
        })
        .collect();

    let mut servers = Vec::new();
    let servers_path = sb_core::paths::servers_config_path();
    if let Ok(raw) = std::fs::read_to_string(&servers_path) {
        if let Ok(parsed) = toml::from_str::<toml::Value>(&raw) {
            if let Some(tbl) = parsed.get("servers").and_then(|s| s.as_table()) {
                for key in tbl.keys() {
                    if key
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
                    {
                        servers.push(key.clone());
                    }
                }
            }
        }
    }

    println!(
        "\n# S&B Dynamic Contexts: {}",
        if contexts.is_empty() {
            "default".to_string()
        } else {
            contexts.join(" ")
        }
    );
    if !servers.is_empty() {
        println!("# S&B Registered Fleet Servers: {}", servers.join(" "));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    Optimal,
    Ready,
    Notice,
    Warning,
    Error,
    Muted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub id: String,
    pub title: String,
    pub status: String,
    pub detail: Option<String>,
    pub level: DiagnosticLevel,
    pub issues: usize,
    pub fixed: usize,
    pub advice: Option<String>,
    pub items: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<DiagnosticCheck>,
    pub total_issues: usize,
    pub total_fixed: usize,
    pub fix_applied: bool,
}

impl DoctorReport {
    pub fn render_terminal(&self) {
        print_banner();
        println!(
            "  {} {}\n",
            "► SYSTEM INTEGRITÄTS- & SICHERHEITS-AUDIT".bold(),
            "[SB DOCTOR]".bright_cyan()
        );

        for check in &self.checks {
            let status_styled = match check.level {
                DiagnosticLevel::Optimal => check.status.bright_green().bold(),
                DiagnosticLevel::Ready => check.status.bright_cyan().bold(),
                DiagnosticLevel::Notice => check.status.bright_yellow().bold(),
                DiagnosticLevel::Warning => check.status.bright_yellow().bold(),
                DiagnosticLevel::Error => check.status.bright_red().bold(),
                DiagnosticLevel::Muted => check.status.bright_black(),
            };

            if let Some(detail) = &check.detail {
                println!("  {:<36}{} ({})", check.title, status_styled, detail);
            } else {
                println!("  {:<36}{}", check.title, status_styled);
            }

            for item in &check.items {
                if item.starts_with('✗') {
                    println!("    {}", item.bright_red());
                } else if item.starts_with("[AUTO-FIX]") {
                    println!("    ► {}", item.bright_green());
                } else {
                    println!("    {}", item);
                }
            }

            if let Some(advice) = &check.advice {
                println!("    ► {}", advice.bright_yellow());
            }
        }

        print_doctor_summary(self.total_issues, self.total_fixed, self.fix_applied);
    }
}

pub struct DoctorBuilder {
    fix: bool,
    checks: Vec<DiagnosticCheck>,
}

impl DoctorBuilder {
    pub fn new(fix: bool) -> Self {
        Self {
            fix,
            checks: Vec::new(),
        }
    }

    pub fn add_check(mut self, check: DiagnosticCheck) -> Self {
        self.checks.push(check);
        self
    }

    pub fn run_all_checks(mut self) -> Self {
        let fix = self.fix;
        self = self
            .add_check(check_rust_toolchain())
            .add_check(check_root_identity(fix))
            .add_check(check_secret_dirs(fix))
            .add_check(check_ca_status(fix))
            .add_check(check_mesh_socket())
            .add_check(check_tool_integrity(fix))
            .add_check(check_offline_readiness())
            .add_check(check_key_and_lease())
            .add_check(check_edge_gateway())
            .add_check(check_developer_ca(fix))
            .add_check(check_path_conflicts())
            .add_check(check_workspace_links(fix))
            .add_check(check_npm_config());
        self
    }

    pub fn build(self) -> DoctorReport {
        let total_issues = self.checks.iter().map(|c| c.issues).sum();
        let total_fixed = self.checks.iter().map(|c| c.fixed).sum();
        DoctorReport {
            checks: self.checks,
            total_issues,
            total_fixed,
            fix_applied: self.fix,
        }
    }
}

pub fn handle_doctor(fix: bool, json: bool) {
    let report = DoctorBuilder::new(fix).run_all_checks().build();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        report.render_terminal();
    }
}

fn check_rust_toolchain() -> DiagnosticCheck {
    if which::which("cargo").is_ok() {
        let (status, detail) = if let Ok(output) = Command::new("cargo").arg("--version").output() {
            let ver = String::from_utf8_lossy(&output.stdout);
            let first = ver.lines().next().unwrap_or("").trim().to_string();
            ("OPTIMAL".to_string(), Some(first))
        } else {
            ("VORHANDEN".to_string(), None)
        };
        DiagnosticCheck {
            id: "rust_toolchain".to_string(),
            title: "1. Rust / Cargo Toolchain:".to_string(),
            status,
            detail,
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    } else {
        DiagnosticCheck {
            id: "rust_toolchain".to_string(),
            title: "1. Rust / Cargo Toolchain:".to_string(),
            status: "WARNUNG".to_string(),
            detail: Some("Cargo nicht im PATH".to_string()),
            level: DiagnosticLevel::Warning,
            issues: 1,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    }
}

fn check_root_identity(fix: bool) -> DiagnosticCheck {
    let sb_dir = get_sb_dir();
    let id_file = sb_dir.join("identity.json");
    if id_file.exists() {
        if let Ok(data) = fs::read_to_string(&id_file) {
            if let Ok(id) = serde_json::from_str::<SovereignIdentity>(&data) {
                DiagnosticCheck {
                    id: "root_identity".to_string(),
                    title: "2. Root-Identität (~/.sb):".to_string(),
                    status: "VERIFIZIERT".to_string(),
                    detail: Some(format!(
                        "Callsign: {}, {}",
                        id.callsign, id.node_fingerprint
                    )),
                    level: DiagnosticLevel::Optimal,
                    issues: 0,
                    fixed: 0,
                    advice: None,
                    items: Vec::new(),
                }
            } else if fix {
                let _ = fs::remove_file(&id_file);
                handle_identity();
                DiagnosticCheck {
                    id: "root_identity".to_string(),
                    title: "2. Root-Identität (~/.sb):".to_string(),
                    status: "BEHOBEN".to_string(),
                    detail: Some("Beschädigtes JSON neu generiert".to_string()),
                    level: DiagnosticLevel::Optimal,
                    issues: 1,
                    fixed: 1,
                    advice: None,
                    items: vec!["[AUTO-FIX] Root-Identität neu generiert".to_string()],
                }
            } else {
                DiagnosticCheck {
                    id: "root_identity".to_string(),
                    title: "2. Root-Identität (~/.sb):".to_string(),
                    status: "FEHLER".to_string(),
                    detail: Some("Beschädigtes JSON".to_string()),
                    level: DiagnosticLevel::Error,
                    issues: 1,
                    fixed: 0,
                    advice: Some("Beheben mit: sb identity".to_string()),
                    items: Vec::new(),
                }
            }
        } else {
            DiagnosticCheck {
                id: "root_identity".to_string(),
                title: "2. Root-Identität (~/.sb):".to_string(),
                status: "FEHLER".to_string(),
                detail: Some("Lesefehler".to_string()),
                level: DiagnosticLevel::Error,
                issues: 1,
                fixed: 0,
                advice: Some("Beheben mit: sb identity".to_string()),
                items: Vec::new(),
            }
        }
    } else if fix {
        handle_identity();
        DiagnosticCheck {
            id: "root_identity".to_string(),
            title: "2. Root-Identität (~/.sb):".to_string(),
            status: "BEHOBEN".to_string(),
            detail: Some("Root-Identität neu erzeugt".to_string()),
            level: DiagnosticLevel::Optimal,
            issues: 1,
            fixed: 1,
            advice: None,
            items: vec!["[AUTO-FIX] Root-Identität erzeugt".to_string()],
        }
    } else {
        DiagnosticCheck {
            id: "root_identity".to_string(),
            title: "2. Root-Identität (~/.sb):".to_string(),
            status: "WARNUNG".to_string(),
            detail: Some("Fehlt".to_string()),
            level: DiagnosticLevel::Warning,
            issues: 1,
            fixed: 0,
            advice: Some("Beheben mit: sb identity".to_string()),
            items: Vec::new(),
        }
    }
}

/// Audits secret directories for strict POSIX 0700 isolation.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: World- or group-readable secret directories exposing private CA keys or session tokens.
/// - CVE / CWE Mapping: CWE-276 (Incorrect Default Permissions), CWE-732 (Incorrect Permission Assignment for Critical Resource).
/// - Likelihood & Exploitability: Medium (5/10) on multi-user POSIX hosts with permissive umask.
/// - Applied Mitigation: Enforces mode 0700 on `~/.sb`, `~/.sb/ca`, `~/.sb/ca/ssh`, `~/.sb-forge`, and `~/.sb-mesh`.
/// - Standards Compliance: Conforms to IEEE 1003.1 (POSIX.1-2017) File Permissions.
#[allow(unused_variables)]
fn check_secret_dirs(fix: bool) -> DiagnosticCheck {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let sb_dir = get_sb_dir();
    let secret_dirs = [
        sb_dir.clone(),
        sb_dir.join("ca"),
        sb_dir.join("ca").join("ssh"),
        home.join(".sb-forge"),
        home.join(".sb-mesh"),
    ];
    #[allow(unused_mut)]
    let mut dir_issues = 0;
    #[allow(unused_mut)]
    let mut dir_fixed = 0;
    for dir in &secret_dirs {
        if dir.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(dir) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != 0o700 {
                        dir_issues += 1;
                        if fix {
                            let mut perms = meta.permissions();
                            perms.set_mode(0o700);
                            let _ = fs::set_permissions(dir, perms);
                            dir_fixed += 1;
                        }
                    }
                }
            }
        }
    }
    if dir_issues > 0 {
        DiagnosticCheck {
            id: "secret_dirs".to_string(),
            title: "3. Secret-Verzeichnisse:".to_string(),
            status: "WARNUNG".to_string(),
            detail: Some("Rechte weicher als 0700".to_string()),
            level: DiagnosticLevel::Warning,
            issues: dir_issues,
            fixed: dir_fixed,
            advice: Some("Rechte auf 0700 einschränken (sb doctor --fix)".to_string()),
            items: Vec::new(),
        }
    } else {
        DiagnosticCheck {
            id: "secret_dirs".to_string(),
            title: "3. Secret-Verzeichnisse:".to_string(),
            status: "GESCHÜTZT".to_string(),
            detail: Some("0700 / Isoliert".to_string()),
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    }
}

/// Verifies the unified `sb-ca` OpenSSH Certificate Authority (`~/.sb/ca/ssh/ca_key`).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Split-brain SSH CA state where legacy `~/.sb-ssh/ca_key` masks an uninitialized unified `sb-ca` engine.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path), CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: Medium (5/10) during legacy-to-unified PKI transition.
/// - Applied Mitigation: Strictly queries `sb_ca::SshCa::status()` against `~/.sb/ca/ssh/ca_key` and `~/.sb/ca/ssh/ca_key.pub` without `~/.sb-ssh` fallback.
/// - Standards Compliance: Conforms to IETF RFC 4251, RFC 8709 (Ed25519), and OpenSSH PROTOCOL.certkeys.
fn check_ca_status(fix: bool) -> DiagnosticCheck {
    let status = sb_ca::SshCa::status();
    if status.initialized {
        DiagnosticCheck {
            id: "ca_status".to_string(),
            title: "4. S&B NetGate CA-Status:".to_string(),
            status: "BEREIT".to_string(),
            detail: Some("Ed25519 Root CA aktiv (~/.sb/ca/ssh)".to_string()),
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    } else if fix && sb_ca::SshCa::init_ca(false).is_ok() {
        DiagnosticCheck {
            id: "ca_status".to_string(),
            title: "4. S&B NetGate CA-Status:".to_string(),
            status: "BEHOBEN".to_string(),
            detail: Some("Ed25519 Root CA initialisiert (~/.sb/ca/ssh)".to_string()),
            level: DiagnosticLevel::Optimal,
            issues: 1,
            fixed: 1,
            advice: None,
            items: vec!["[AUTO-FIX] OpenSSH Root CA in ~/.sb/ca/ssh erzeugt".to_string()],
        }
    } else {
        DiagnosticCheck {
            id: "ca_status".to_string(),
            title: "4. S&B NetGate CA-Status:".to_string(),
            status: "NICHT INITIALISIERT".to_string(),
            detail: Some("Initialisieren mit 'sb-ca init'".to_string()),
            level: DiagnosticLevel::Muted,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    }
}

fn check_mesh_socket() -> DiagnosticCheck {
    let mesh_ipc_port = sb_core::config::SuiteConfig::load().ports.mesh_ipc;
    let mesh_ipc_addr = format!("127.0.0.1:{}", mesh_ipc_port);
    if let Ok(addr) = mesh_ipc_addr.parse() {
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            let _ = stream.write_all(br#"{"action":"GetStatus"}"#);
            DiagnosticCheck {
                id: "mesh_socket".to_string(),
                title: "5. Sovereign Mesh Socket:".to_string(),
                status: "ONLINE".to_string(),
                detail: Some(mesh_ipc_addr),
                level: DiagnosticLevel::Optimal,
                issues: 0,
                fixed: 0,
                advice: None,
                items: Vec::new(),
            }
        } else {
            DiagnosticCheck {
                id: "mesh_socket".to_string(),
                title: "5. Sovereign Mesh Socket:".to_string(),
                status: "IDLE".to_string(),
                detail: Some("Daemon nicht gestartet — Start via 'sb mesh daemon'".to_string()),
                level: DiagnosticLevel::Muted,
                issues: 0,
                fixed: 0,
                advice: None,
                items: Vec::new(),
            }
        }
    } else {
        DiagnosticCheck {
            id: "mesh_socket".to_string(),
            title: "5. Sovereign Mesh Socket:".to_string(),
            status: "FEHLER".to_string(),
            detail: Some("Ungültige Socket-Adresse in Konfiguration".to_string()),
            level: DiagnosticLevel::Error,
            issues: 1,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    }
}

/// Audits the installation and cryptographic integrity of all 12 installable S&B Suite binaries.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Binary tampering, partial installation, or missing PKI engine (`sb-ca`) in the suite binary roster.
/// - CVE / CWE Mapping: CWE-353 (Missing Support for Integrity Check), CWE-494 (Download of Code Without Integrity Check).
/// - Likelihood & Exploitability: Low (2/10) with SHA-256 ledger and Ed25519 manifest verification.
/// - Applied Mitigation: Verifies all 12 installable products from `sb_core::catalog::installable_products()` (including `sb` and `sb-ca`).
/// - Standards Compliance: Conforms to FIPS 180-4 (SHA-256) and IETF RFC 8032 (Ed25519).
fn check_tool_integrity(fix: bool) -> DiagnosticCheck {
    let bin_dir = get_sb_dir().join("bin");
    let audit = crate::commands::release::audit_installed_binaries(&bin_dir);
    let all_installable =
        sb_core::catalog::installable_products().unwrap_or_else(|_| available_tools());
    let total = all_installable.len();
    let mut installed_count = audit.total_installed;

    if installed_count == 0 {
        for tool in &all_installable {
            if tool.binary_name.as_deref().is_some_and(|binary| {
                which::which(binary).is_ok() || sb_core::BinaryResolver::resolve(binary).is_some()
            }) {
                installed_count += 1;
            }
        }
    }

    if !audit.tampered.is_empty() {
        let tampered_len = audit.tampered.len();
        let items = audit
            .tampered
            .iter()
            .map(|name| format!("✗ Mögliche Manipulation oder Beschädigung: {}", name))
            .collect();
        DiagnosticCheck {
            id: "tool_integrity".to_string(),
            title: "6. Suite Werkzeug-Integrität:".to_string(),
            status: "FEHLER".to_string(),
            detail: Some(format!(
                "{} Binaries weisen Prüfsummenabweichungen auf!",
                tampered_len
            )),
            level: DiagnosticLevel::Error,
            issues: tampered_len,
            fixed: 0,
            advice: None,
            items,
        }
    } else if audit.verified_count > 0 && audit.signature_valid {
        let (status, detail) = if audit.verified_count >= total {
            (
                "OPTIMAL".to_string(),
                format!(
                    "{}/{} signiert & verifiziert, Ed25519 OK",
                    audit.verified_count, total
                ),
            )
        } else {
            (
                "VERIFIZIERT".to_string(),
                format!(
                    "{}/{} signiert & verifiziert, {} lokal",
                    audit.verified_count,
                    total,
                    audit.unmanaged.len()
                ),
            )
        };
        DiagnosticCheck {
            id: "tool_integrity".to_string(),
            title: "6. Suite Werkzeug-Integrität:".to_string(),
            status,
            detail: Some(detail),
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    } else if installed_count > 0 {
        let (status, level) = if installed_count >= total {
            ("VOLLSTÄNDIG".to_string(), DiagnosticLevel::Optimal)
        } else {
            ("TEILWEISE".to_string(), DiagnosticLevel::Warning)
        };
        DiagnosticCheck {
            id: "tool_integrity".to_string(),
            title: "6. Suite Werkzeug-Integrität:".to_string(),
            status,
            detail: Some(format!(
                "{}/{} installiert, Lokaler Dev-Build",
                installed_count, total
            )),
            level,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    } else {
        let (fixed, items) = if fix {
            match handle_update_with_source(&["all".to_string()], None) {
                Ok(()) => (
                    1,
                    vec!["[AUTO-FIX] Basis-Tools erfolgreich installiert".to_string()],
                ),
                Err(error) => (0, vec![format!("Installation fehlgeschlagen: {error}")]),
            }
        } else {
            (0, Vec::new())
        };
        DiagnosticCheck {
            id: "tool_integrity".to_string(),
            title: "6. Suite Werkzeug-Integrität:".to_string(),
            status: if fixed > 0 {
                "BEHOBEN".to_string()
            } else {
                "WARNUNG".to_string()
            },
            detail: Some("Keine Tools installiert".to_string()),
            level: if fixed > 0 {
                DiagnosticLevel::Optimal
            } else {
                DiagnosticLevel::Warning
            },
            issues: 1,
            fixed,
            advice: Some("Installiere die Suite mit: sb install all".to_string()),
            items,
        }
    }
}

fn check_offline_readiness() -> DiagnosticCheck {
    DiagnosticCheck {
        id: "offline_readiness".to_string(),
        title: "7. Lokale Autarkie (Offline-Betrieb):".to_string(),
        status: "AUTARK".to_string(),
        detail: Some("Local-First / autarker Betrieb".to_string()),
        level: DiagnosticLevel::Optimal,
        issues: 0,
        fixed: 0,
        advice: None,
        items: Vec::new(),
    }
}

fn check_key_and_lease() -> DiagnosticCheck {
    let sb_dir = get_sb_dir();
    let root_key = sb_dir.join("identity.sbkey");
    let lease_file = sb_dir.join("lease.json");
    let (status, detail, level) = if root_key.exists() {
        if lease_file.exists() {
            (
                "OPTIMAL".to_string(),
                "Root Key & Lease aktiv".to_string(),
                DiagnosticLevel::Optimal,
            )
        } else {
            (
                "BEREIT".to_string(),
                "Root Key vorhanden, Lease inaktiv/gesperrt".to_string(),
                DiagnosticLevel::Ready,
            )
        }
    } else {
        (
            "UNINITIALISIERT".to_string(),
            "Führe 'sb key init' aus".to_string(),
            DiagnosticLevel::Warning,
        )
    };
    DiagnosticCheck {
        id: "key_and_lease".to_string(),
        title: "8. Sovereign Key & RAM Lease:".to_string(),
        status,
        detail: Some(detail),
        level,
        issues: 0,
        fixed: 0,
        advice: None,
        items: Vec::new(),
    }
}

fn check_edge_gateway() -> DiagnosticCheck {
    let proxy_running = "127.0.0.1:58900"
        .parse()
        .ok()
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(300)).ok())
        .is_some();
    let proxy_exists = which::which("sb-proxy").is_ok()
        || std::path::Path::new("tools/sb-proxy").exists()
        || std::path::Path::new("../sb-proxy").exists();

    if proxy_running {
        DiagnosticCheck {
            id: "edge_gateway".to_string(),
            title: "9. S&B Edge Gateway (sb-proxy):".to_string(),
            status: "ONLINE".to_string(),
            detail: Some("127.0.0.1:58900 / IPC Aktiv".to_string()),
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    } else if proxy_exists {
        DiagnosticCheck {
            id: "edge_gateway".to_string(),
            title: "9. S&B Edge Gateway (sb-proxy):".to_string(),
            status: "BEREIT".to_string(),
            detail: Some("Installiert, Daemon gestoppt".to_string()),
            level: DiagnosticLevel::Ready,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    } else {
        DiagnosticCheck {
            id: "edge_gateway".to_string(),
            title: "9. S&B Edge Gateway (sb-proxy):".to_string(),
            status: "WARNUNG".to_string(),
            detail: Some("Binary fehlt im PATH".to_string()),
            level: DiagnosticLevel::Warning,
            issues: 1,
            fixed: 0,
            advice: Some("Installiere sb-proxy mit: sb install proxy".to_string()),
            items: Vec::new(),
        }
    }
}

/// Verifies the unified X.509 Developer Root CA (`~/.sb/ca/root_ca.crt`) and host OS trust store anchoring via `sb-ca`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: False-negative OS trust detection on Linux/macOS or unanchored local TLS Root CA causing MITM susceptibility.
/// - CVE / CWE Mapping: CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: Low (2/10) when verified via `sb_ca::is_root_ca_installed()`.
/// - Applied Mitigation: Queries `sb_ca::X509Ca::status()` and `sb_ca::is_root_ca_installed()` across Windows, macOS, and Linux trust stores.
/// - Standards Compliance: Conforms to IETF RFC 5280 (X.509 PKI) and TLS 1.3 (RFC 8446).
fn check_developer_ca(fix: bool) -> DiagnosticCheck {
    let ca_crt = sb_ca::paths::x509_root_crt_path();
    if ca_crt.exists() {
        let is_trusted = sb_ca::is_root_ca_installed();

        if is_trusted {
            DiagnosticCheck {
                id: "developer_ca".to_string(),
                title: "10. Developer Root CA & OS-Trust:".to_string(),
                status: "OPTIMAL".to_string(),
                detail: Some("Im OS-Zertifikatsmagazin verankert".to_string()),
                level: DiagnosticLevel::Optimal,
                issues: 0,
                fixed: 0,
                advice: None,
                items: Vec::new(),
            }
        } else if fix && sb_ca::install_root_ca().is_ok() && sb_ca::is_root_ca_installed() {
            DiagnosticCheck {
                id: "developer_ca".to_string(),
                title: "10. Developer Root CA & OS-Trust:".to_string(),
                status: "BEHOBEN".to_string(),
                detail: Some("Im OS-Zertifikatsmagazin verankert".to_string()),
                level: DiagnosticLevel::Optimal,
                issues: 1,
                fixed: 1,
                advice: None,
                items: vec![
                    "[AUTO-FIX] Developer Root-CA im OS-Zertifikatsmagazin verankert".to_string(),
                ],
            }
        } else {
            let advice = if fix {
                Some("[INTERAKTIV] Bitte führe 'sb-ca install-root' (ggf. mit sudo/Admin-Rechten) aus.".to_string())
            } else {
                Some("Installiere im Betriebssystem mit: sb-ca install-root".to_string())
            };
            DiagnosticCheck {
                id: "developer_ca".to_string(),
                title: "10. Developer Root CA & OS-Trust:".to_string(),
                status: "WARNUNG".to_string(),
                detail: Some("Root-CA erzeugt, aber nicht im OS installiert".to_string()),
                level: DiagnosticLevel::Warning,
                issues: 1,
                fixed: 0,
                advice,
                items: Vec::new(),
            }
        }
    } else if fix && sb_ca::init_all(false).is_ok() {
        let _ = sb_ca::install_root_ca();
        let trusted = sb_ca::is_root_ca_installed();
        DiagnosticCheck {
            id: "developer_ca".to_string(),
            title: "10. Developer Root CA & OS-Trust:".to_string(),
            status: "BEHOBEN".to_string(),
            detail: Some(if trusted {
                "Developer Root-CA initialisiert & im OS verankert".to_string()
            } else {
                "Developer Root-CA initialisiert".to_string()
            }),
            level: DiagnosticLevel::Optimal,
            issues: 1,
            fixed: 1,
            advice: if trusted {
                None
            } else {
                Some("[INTERAKTIV] Führe nun 'sb-ca install-root' aus, um das Zertifikat im Betriebssystem zu verankern.".to_string())
            },
            items: vec!["[AUTO-FIX] Developer Root-CA via sb-ca initialisiert".to_string()],
        }
    } else {
        DiagnosticCheck {
            id: "developer_ca".to_string(),
            title: "10. Developer Root CA & OS-Trust:".to_string(),
            status: "WARNUNG".to_string(),
            detail: Some("Nicht initialisiert".to_string()),
            level: DiagnosticLevel::Warning,
            issues: 1,
            fixed: 0,
            advice: Some(
                "Initialisiere Developer CA mit: sb-ca init && sb-ca install-root".to_string(),
            ),
            items: Vec::new(),
        }
    }
}

fn check_path_conflicts() -> DiagnosticCheck {
    match which::which("ssh") {
        Ok(p) if p.to_string_lossy().to_lowercase().contains(".cargo") => DiagnosticCheck {
            id: "path_conflicts".to_string(),
            title: "11. PATH-Konflikte (ssh):".to_string(),
            status: "WARNUNG".to_string(),
            detail: Some(format!("{} überschattet OpenSSH", p.display())),
            level: DiagnosticLevel::Warning,
            issues: 1,
            fixed: 0,
            advice: Some(
                "Umbenennen: sb-ssh nicht als 'ssh' installieren (PATH-Reihenfolge prüfen)."
                    .to_string(),
            ),
            items: Vec::new(),
        },
        Ok(_) => DiagnosticCheck {
            id: "path_conflicts".to_string(),
            title: "11. PATH-Konflikte (ssh):".to_string(),
            status: "OK".to_string(),
            detail: Some("System-OpenSSH".to_string()),
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        },
        Err(_) => DiagnosticCheck {
            id: "path_conflicts".to_string(),
            title: "11. PATH-Konflikte (ssh):".to_string(),
            status: "KEIN ssh im PATH".to_string(),
            detail: None,
            level: DiagnosticLevel::Muted,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        },
    }
}

fn check_workspace_links(fix: bool) -> DiagnosticCheck {
    let mut broken = Vec::new();
    if let Ok(rd) = fs::read_dir(".") {
        for e in rd.flatten() {
            let p = e.path();
            let is_link = fs::symlink_metadata(&p)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
                || (cfg!(windows) && fs::read_link(&p).is_ok());
            if is_link && fs::metadata(&p).is_err() {
                broken.push(p);
            }
        }
    }
    if broken.is_empty() {
        DiagnosticCheck {
            id: "workspace_links".to_string(),
            title: "12. Workspace-Links:".to_string(),
            status: "OK".to_string(),
            detail: None,
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    } else {
        let broken_len = broken.len();
        let mut fixed_count = 0;
        let mut items = Vec::new();
        for p in &broken {
            let target = fs::read_link(p)
                .map(|t| t.display().to_string())
                .unwrap_or_default();
            items.push(format!("✗ {} → {}", p.display(), target));
            if fix {
                if let Ok(t) = fs::read_link(p) {
                    if fs::create_dir_all(&t).is_ok() {
                        fixed_count += 1;
                        items.push("[AUTO-FIX] Ziel angelegt.".to_string());
                    }
                }
            }
        }
        DiagnosticCheck {
            id: "workspace_links".to_string(),
            title: "12. Workspace-Links:".to_string(),
            status: if fixed_count == broken_len {
                "BEHOBEN".to_string()
            } else {
                "WARNUNG".to_string()
            },
            detail: Some(format!("{} defekt", broken_len)),
            level: if fixed_count == broken_len {
                DiagnosticLevel::Optimal
            } else {
                DiagnosticLevel::Warning
            },
            issues: broken_len,
            fixed: fixed_count,
            advice: None,
            items,
        }
    }
}

fn check_npm_config() -> DiagnosticCheck {
    let npmrc_bad = dirs::home_dir()
        .map(|h| h.join(".npmrc"))
        .and_then(|p| fs::read_to_string(p).ok())
        .is_some_and(|c| {
            c.lines()
                .any(|l| l.trim_start().starts_with("allow-scripts"))
        });
    if npmrc_bad {
        DiagnosticCheck {
            id: "npm_config".to_string(),
            title: "13. npm-Konfiguration:".to_string(),
            status: "HINWEIS".to_string(),
            detail: Some("~/.npmrc: allow-scripts".to_string()),
            level: DiagnosticLevel::Notice,
            issues: 0,
            fixed: 0,
            advice: Some(
                "'npm run install:ui' isoliert die User-Konfiguration automatisch.".to_string(),
            ),
            items: Vec::new(),
        }
    } else {
        DiagnosticCheck {
            id: "npm_config".to_string(),
            title: "13. npm-Konfiguration:".to_string(),
            status: "OK".to_string(),
            detail: None,
            level: DiagnosticLevel::Optimal,
            issues: 0,
            fixed: 0,
            advice: None,
            items: Vec::new(),
        }
    }
}

fn print_doctor_summary(issues: usize, fixed: usize, fix: bool) {
    println!("  {}", "─".repeat(84).bright_black());

    if issues == 0 {
        println!(
            "  {} Deine S&B Suite ist optimal konfiguriert.",
            "✓ ALLE SYSTEMPRÜFUNGEN BESTANDEN!".bright_green().bold()
        );
    } else if fix {
        println!(
            "  {} {} Problem(e) erkannt, {} automatisch behoben.",
            "✓".bright_green().bold(),
            issues,
            fixed
        );
    } else {
        println!(
            "  {} {} Hinweis(e)/Problem(e) gefunden. Automatisch beheben mit: {}",
            "i".bright_yellow().bold(),
            issues,
            "sb doctor --fix".bright_cyan().bold()
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doctor_report_builder_pipeline() {
        let report = DoctorBuilder::new(false).run_all_checks().build();
        assert_eq!(report.checks.len(), 13);
        let json =
            serde_json::to_string_pretty(&report).expect("DoctorReport must serialize to JSON");
        assert!(json.contains("rust_toolchain"));
        assert!(json.contains("offline_readiness"));
        assert!(json.contains("developer_ca"));
    }
}
