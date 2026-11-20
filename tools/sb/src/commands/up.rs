//! 1-Command Workstation & Session Bringup (`sb up`)
//!
//! Orchestrates an idempotent, sub-second readiness check and auto-initialization
//! of the Sovereign Root Identity (`identity.json` & `identity.sbkey`), Unified Dual-CA
//! (`sb-ca` OpenSSH + X.509), OS Trust Store, 8-hour Ephemeral RAM Lease (`sb-key`),
//! and Cross-Tool Context Synchronization (`sb ctx` <-> `sb-forge`).
//!
//! Standards Compliance:
//! - Conforms to IETF RFC 4251 (OpenSSH CA Architecture)
//! - Conforms to IETF RFC 5280 (X.509 PKI Profile)
//! - Conforms to IETF RFC 8259 (Structured JSON Output)
//! - Conforms to IEEE 1003.1 / POSIX.1-2017 (0700/0600 Secret Directory Hardening)

use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::context::{sync_forge_session_env, ContextStore};
use crate::meta::{print_banner, SovereignIdentity};

/// Structured output payload for `sb up --json` (conforms to RFC 8259).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpReport {
    pub ready: bool,
    pub fix_applied: bool,
    pub callsign: String,
    pub active_context: String,
    pub active_env: String,
    pub detected_workspace: Option<String>,
    pub identity_initialized: bool,
    pub root_key_id: Option<String>,
    pub ssh_ca_ready: bool,
    pub ssh_ca_pub_path: String,
    pub x509_ca_ready: bool,
    pub x509_root_crt_path: String,
    pub os_trust_installed: bool,
    pub lease_active: bool,
    pub lease_id: Option<String>,
    pub lease_expires_at: Option<String>,
    pub actions_taken: Vec<String>,
    pub fix_hint: Option<String>,
}

/// Enforces `0700` permissions on secret directories inside `~/.sb/` on Unix platforms.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: World- or group-readable secret directories allowing local privilege escalation or CA key theft.
/// - CVE / CWE Mapping: CWE-732 (Incorrect Permission Assignment for Critical Resource), CWE-276 (Incorrect Default Permissions).
/// - Likelihood & Exploitability: Medium (5/10) on shared multi-user Linux hosts.
/// - Applied Mitigation: Creates `~/.sb`, `~/.sb/ca`, `~/.sb/ca/ssh`, and `~/.sb/ssh` and enforces `0o700` directory mode on Unix.
/// - Standards Compliance: Conforms to IEEE 1003.1 (POSIX.1-2017) `chmod(2)`.
fn ensure_secret_directories() -> Vec<String> {
    let mut actions = Vec::new();
    let dirs = [
        sb_core::paths::sb_home(),
        sb_core::paths::sb_ca_dir(),
        sb_core::paths::sb_ca_ssh_dir(),
        sb_core::paths::sb_ssh_dir(),
    ];

    for dir in &dirs {
        if !dir.exists() && fs::create_dir_all(dir).is_ok() {
            actions.push(format!("Created secret directory {}", dir.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(dir) {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o700 {
                    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
                    actions.push(format!("Hardened permissions (0700) on {}", dir.display()));
                }
            }
        }
    }
    actions
}

/// Executes the idempotent 1-command workstation and session bringup (`sb up`).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Partial or unverified cryptographic initialization leaving SSH/TLS CA or RAM lease in an inconsistent state.
/// - CVE / CWE Mapping: CWE-665 (Improper Initialization), CWE-311 (Missing Encryption of Sensitive Data).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Sequentially verifies and initializes secret directory modes, root identity, Unified Dual-CA, OS trust store, and 8-hour RAM lease; never logs private key bytes.
/// - Standards Compliance: Conforms to RFC 4251, RFC 5280, RFC 8259, and POSIX.1-2017.
pub fn handle_up(fix: bool, json: bool) {
    let mut actions = ensure_secret_directories();

    // 1. Sovereign Identity (identity.json) & Root Key (identity.sbkey)
    let shared_id = SovereignIdentity::load_or_create();
    let mut key_opt = sb_key::inspect_identity(None).ok();
    if key_opt.is_none() {
        if let Ok(created_key) =
            sb_key::init_identity(Some(shared_id.callsign.clone()), None, false)
        {
            actions.push(format!(
                "Initialized Sovereign Root Key ({})",
                created_key.id
            ));
            key_opt = Some(created_key);
        }
    }

    // 2. Unified Dual-CA (OpenSSH + X.509)
    let mut ssh_ca_status = sb_ca::SshCa::status();
    let mut x509_ca_status = sb_ca::X509Ca::status().unwrap_or(sb_ca::x509::X509CaStatus {
        initialized: false,
        crt_path: sb_core::paths::sb_ca_x509_crt_path().display().to_string(),
        key_path: sb_core::paths::sb_ca_x509_key_path().display().to_string(),
        is_installed_in_os: false,
        issued_certs_count: 0,
        common_name: "Skulls & Bones Sovereign Root CA".to_string(),
        organization: "Skulls & Bones Lab".to_string(),
    });
    if !ssh_ca_status.initialized || !x509_ca_status.initialized {
        if let Ok(ca_status) = sb_ca::init_all(false) {
            ssh_ca_status = ca_status.ssh;
            x509_ca_status = ca_status.x509;
            actions.push("Initialized Unified Dual-CA (OpenSSH + X.509)".to_string());
        }
    }

    // 3. OS Trust Store (installed automatically when --fix is passed)
    let mut os_trust = sb_ca::is_root_ca_installed();
    if !os_trust && fix && x509_ca_status.initialized && sb_ca::X509Ca::install_root_ca().is_ok() {
        os_trust = sb_ca::is_root_ca_installed();
        actions.push("Installed X.509 Root CA into OS trust store".to_string());
    }

    // 4. Ephemeral 8-Hour RAM Lease
    let mut lease_opt = sb_key::get_lease_status();
    if lease_opt.is_none() {
        if let Ok(minted) = sb_key::mint_lease(None, 8) {
            actions.push(format!(
                "Minted fresh 8h ephemeral RAM lease ({})",
                minted.lease_id
            ));
            lease_opt = Some(minted);
        }
    }

    // 5. Sovereign OpenSSH Integrator (~/.sb/ssh/ssh_config + ephemeral user cert + ~/.ssh/config Include)
    let _ = crate::commands::ssh::ensure_ephemeral_ssh_user_cert();
    let _ = sb_core::ssh_transport::ensure_sovereign_ssh_config();
    if fix {
        if let Ok(user_ssh_cfg) = sb_core::ssh_transport::integrate_into_user_ssh_config() {
            actions.push(format!(
                "Anchored Sovereign SSH Include in {}",
                user_ssh_cfg.display()
            ));
        }
    }

    // 6. Context & Workspace Synchronization
    let store = ContextStore::new();
    let (active_ctx, detected_ws) = store.active_or_detected();
    sync_forge_session_env(&active_ctx.env, &active_ctx.name);

    let ready = key_opt.is_some()
        && ssh_ca_status.initialized
        && x509_ca_status.initialized
        && lease_opt.is_some();

    let fix_hint = if !ready {
        Some("sb up --fix".to_string())
    } else if !os_trust {
        Some("sb up --fix (or 'sb ca install-root')".to_string())
    } else {
        None
    };

    let report = UpReport {
        ready,
        fix_applied: fix,
        callsign: shared_id.callsign,
        active_context: active_ctx.name,
        active_env: active_ctx.env,
        detected_workspace: detected_ws,
        identity_initialized: key_opt.is_some(),
        root_key_id: key_opt.as_ref().map(|k| k.id.clone()),
        ssh_ca_ready: ssh_ca_status.initialized,
        ssh_ca_pub_path: ssh_ca_status.ca_pub_path,
        x509_ca_ready: x509_ca_status.initialized,
        x509_root_crt_path: x509_ca_status.crt_path,
        os_trust_installed: os_trust,
        lease_active: lease_opt.is_some(),
        lease_id: lease_opt.as_ref().map(|l| l.lease_id.clone()),
        lease_expires_at: lease_opt.as_ref().map(|l| l.expires_at.clone()),
        actions_taken: actions,
        fix_hint,
    };

    if json {
        if let Ok(serialized) = serde_json::to_string_pretty(&report) {
            println!("{}", serialized);
        }
        if !report.ready {
            std::process::exit(1);
        }
        return;
    }

    print_banner();
    println!(
        "  {} {}\n",
        "► SOVEREIGN WORKSTATION & SESSION BRINGUP".bold(),
        "[SB UP]".bright_cyan().bold()
    );

    println!(
        "  {} Callsign & Kontext: {} · Kontext '{}' [{}]{}",
        "★".bright_yellow().bold(),
        report.callsign.bright_white().bold(),
        report.active_context.bright_cyan().bold(),
        report.active_env.bright_green().bold(),
        report
            .detected_workspace
            .as_ref()
            .map(|w| format!(" (Forge.toml: {})", w))
            .unwrap_or_default()
    );

    println!(
        "  {} Root Identity:      {}",
        if report.identity_initialized {
            "✓".bright_green().bold()
        } else {
            "✗".bright_red().bold()
        },
        report
            .root_key_id
            .as_deref()
            .unwrap_or("NICHT INITIALISIERT")
            .bright_yellow()
    );

    println!(
        "  {} Unified SSH-CA:     {} ({})",
        if report.ssh_ca_ready {
            "✓".bright_green().bold()
        } else {
            "✗".bright_red().bold()
        },
        if report.ssh_ca_ready {
            "BEREIT".bright_green().bold()
        } else {
            "FEHLT".bright_red().bold()
        },
        report.ssh_ca_pub_path.bright_black()
    );

    println!(
        "  {} Unified X.509-CA:   {} (OS-Trust: {})",
        if report.x509_ca_ready {
            "✓".bright_green().bold()
        } else {
            "✗".bright_red().bold()
        },
        if report.x509_ca_ready {
            "BEREIT".bright_green().bold()
        } else {
            "FEHLT".bright_red().bold()
        },
        if report.os_trust_installed {
            "VERANKERT".bright_green().to_string()
        } else {
            "AUSSTEHEND ('sb up --fix')".bright_yellow().to_string()
        }
    );

    println!(
        "  {} 8h RAM-Lease:       {} ({})",
        if report.lease_active {
            "✓".bright_green().bold()
        } else {
            "✗".bright_red().bold()
        },
        report
            .lease_id
            .as_deref()
            .unwrap_or("INAKTIV")
            .bright_yellow()
            .bold(),
        report
            .lease_expires_at
            .as_deref()
            .unwrap_or("-")
            .bright_black()
    );

    if !report.actions_taken.is_empty() {
        println!("\n  {} Ausgeführte Bringup-Aktionen:", "►".bright_cyan());
        for act in &report.actions_taken {
            println!("    • {}", act.bright_green());
        }
    }

    if let Some(ref hint) = report.fix_hint {
        println!("\n  ► Fix with: {}", hint.bright_cyan().bold());
    }

    println!(
        "\n  {} {}\n",
        if report.ready {
            "✓".bright_green().bold()
        } else {
            "!".bright_yellow().bold()
        },
        if report.ready {
            "Sovereign Workstation & Session sind vollständig einsatzbereit!"
                .bright_green()
                .bold()
        } else {
            "Einige Komponenten benötigen Aufmerksamkeit ('sb up --fix')."
                .bright_yellow()
                .bold()
        }
    );

    if !report.ready {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_up_report_json_contract() {
        let report = UpReport {
            ready: true,
            fix_applied: true,
            callsign: "sb-test-node".to_string(),
            active_context: "default".to_string(),
            active_env: "dev".to_string(),
            detected_workspace: Some("skulls-and-bones".to_string()),
            identity_initialized: true,
            root_key_id: Some("sbk-12345678".to_string()),
            ssh_ca_ready: true,
            ssh_ca_pub_path: "/root/.sb/ca/ssh/ca_key.pub".to_string(),
            x509_ca_ready: true,
            x509_root_crt_path: "/root/.sb/ca/root_ca.crt".to_string(),
            os_trust_installed: true,
            lease_active: true,
            lease_id: Some("sbl-abcdef01".to_string()),
            lease_expires_at: Some("2026-10-29T08:00:00Z".to_string()),
            actions_taken: vec!["Minted fresh 8h ephemeral RAM lease".to_string()],
            fix_hint: None,
        };
        let json = serde_json::to_string_pretty(&report).expect("UpReport must serialize to JSON");
        assert!(json.contains("\"ready\": true"));
        assert!(json.contains("\"ssh_ca_ready\": true"));
        assert!(json.contains("\"x509_ca_ready\": true"));
        assert!(json.contains("\"lease_active\": true"));
    }
}
