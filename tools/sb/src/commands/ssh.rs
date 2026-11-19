//! Sovereign OpenSSH Integrator CLI (`sb ssh`)
//!
//! Replaces the legacy prototype `sb-ssh` binary with a native command module inside `sb`
//! that combines:
//! - Short-lived OpenSSH user certificates signed by `sb-ca` (`~/.sb/ssh/id_ed25519-cert.pub`)
//! - `@cert-authority` host pinning (`~/.sb/ssh/known_hosts_ca`)
//! - Auto-generated `~/.sb/ssh/ssh_config` with `~/.ssh/config` `Include` anchoring
//! - Zero-overhead delegation to the authentic system OpenSSH (`ssh` & `scp`)
//!
//! Standards Compliance:
//! - Conforms to IETF RFC 4251 / RFC 4252 / RFC 4254 (SSH Protocol & Connection Architecture)
//! - Conforms to OpenSSH PROTOCOL.certkeys (Ed25519 User & Host Certificates)
//! - Conforms to IEEE 1003.1 / POSIX.1-2017 (`0700` / `0600` file permissions)

use colored::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::meta::{print_banner, SovereignIdentity};

/// Ensures the operator's Ed25519 SSH keypair exists in `~/.sb/ssh/id_ed25519` (or mirrors `~/.ssh/id_ed25519.pub`)
/// and issues a fresh 8-hour OpenSSH user certificate (`~/.sb/ssh/id_ed25519-cert.pub`) via `sb_ca::SshCa`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Long-lived static SSH public keys remaining authorized indefinitely on fleet servers.
/// - CVE / CWE Mapping: CWE-613 (Insufficient Session Expiration), CWE-732 (Incorrect Permission Assignment).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Issues short-lived (8h / 28800s) OpenSSH user certificates bound to the operator's callsign and `root`/`sbadmin` principals.
/// - Standards Compliance: Conforms to OpenSSH PROTOCOL.certkeys and IETF RFC 4251.
pub fn ensure_ephemeral_ssh_user_cert() -> Option<PathBuf> {
    let ssh_dir = sb_core::paths::sb_ssh_dir();
    let _ = fs::create_dir_all(&ssh_dir);

    let sb_priv = ssh_dir.join("id_ed25519");
    let sb_pub = ssh_dir.join("id_ed25519.pub");
    let sb_cert = ssh_dir.join("id_ed25519-cert.pub");

    // Check if ~/.ssh/id_ed25519 exists and copy/link if ~/.sb/ssh/id_ed25519 does not exist yet
    if !sb_pub.is_file() {
        if let Some(home) = dirs::home_dir() {
            let user_priv = home.join(".ssh").join("id_ed25519");
            let user_pub = home.join(".ssh").join("id_ed25519.pub");
            if user_priv.is_file() && user_pub.is_file() {
                let _ = fs::copy(&user_priv, &sb_priv);
                let _ = fs::copy(&user_pub, &sb_pub);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&sb_priv, fs::Permissions::from_mode(0o600));
                }
            }
        }
    }

    if !sb_pub.is_file() {
        let _ = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                "",
                "-q",
                "-f",
                &sb_priv.to_string_lossy(),
            ])
            .status();
    }

    if !sb_pub.is_file() {
        return None;
    }

    let pubkey_str = fs::read_to_string(&sb_pub).ok()?;

    let cert_str = if sb_ca::SshCa::status().initialized {
        let identity = SovereignIdentity::load_or_create();
        let principals = vec![
            "root".to_string(),
            "sbadmin".to_string(),
            identity.callsign.clone(),
        ];
        sb_ca::SshCa::issue_user_certificate(
            pubkey_str.trim(),
            &format!("sb-operator-{}", identity.callsign),
            &principals,
            28_800,
            None,
        )
        .ok()?
    } else {
        request_remote_ssh_user_cert(pubkey_str.trim())?
    };

    if fs::write(&sb_cert, cert_str.as_bytes()).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&sb_cert, fs::Permissions::from_mode(0o600));
        }
        let _ = sb_core::ssh_transport::ensure_sovereign_ssh_config();
        return Some(sb_cert);
    }

    None
}

/// Fetches a short-lived OpenSSH user certificate from the Domain Controller (`POST /v1/me/ssh-cert`)
/// using the persisted DC session (`~/.sb/domain/session.json`).
fn request_remote_ssh_user_cert(pubkey: &str) -> Option<String> {
    let sess_path = sb_core::domain::local_domain_dir().join("session.json");
    let raw = fs::read_to_string(sess_path).ok()?;
    let sess: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let dc_url = sess.get("dc_url")?.as_str()?.trim_end_matches('/');
    let token = sess.get("access_token")?.as_str()?;

    let endpoint = format!("{dc_url}/v1/me/ssh-cert");
    let payload = serde_json::json!({
        "ssh_public_key": pubkey,
        "ttl_seconds": 28_800u64,
    })
    .to_string();
    let resp = ureq::post(&endpoint)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {token}"))
        .send_string(&payload)
        .ok()?;
    let body: serde_json::Value = serde_json::from_reader(resp.into_reader()).ok()?;
    body.get("certificate_openssh")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Primary handler for `sb ssh <args...>`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Binary stream corruption on `stdout` during non-interactive command execution (`sb ssh exec` or piped commands) or argument injection via leading dashes.
/// - CVE / CWE Mapping: CWE-88 (Argument Injection), CWE-116 (Improper Output Neutralization).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Suppresses all decorative banners during `exec`, `push`, `pull`, and remote command invocations; delegates transport to `sb_core::ssh_transport`.
pub fn handle_ssh(args: &[String]) {
    let _ = ensure_ephemeral_ssh_user_cert();
    let cfg_path = match sb_core::ssh_transport::ensure_sovereign_ssh_config() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  {} {}", "✗".bright_red().bold(), e);
            std::process::exit(1);
        }
    };

    match args.first().map(|s| s.as_str()) {
        None | Some("status") | Some("--help") | Some("-h") => {
            render_ssh_status(&cfg_path, false);
        }
        Some("config") | Some("integrate") => {
            render_ssh_status(&cfg_path, true);
        }
        Some("push") => {
            if args.len() < 3 {
                eprintln!("Usage: sb ssh push <server> <local_path> [remote_path]");
                std::process::exit(1);
            }
            let server = &args[1];
            let local_path = &args[2];
            let remote_path = args.get(3).map(|s| s.as_str());
            match sb_core::ssh_transport::build_scp_push_args(server, local_path, remote_path) {
                Ok((scp_bin, scp_args)) => {
                    let status = Command::new(&scp_bin)
                        .args(&scp_args)
                        .status()
                        .unwrap_or_else(|e| {
                            eprintln!("Fehler beim Starten von scp: {}", e);
                            std::process::exit(1);
                        });
                    std::process::exit(status.code().unwrap_or(1));
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".bright_red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        Some("pull") => {
            if args.len() < 3 {
                eprintln!("Usage: sb ssh pull <server> <remote_path> [local_path]");
                std::process::exit(1);
            }
            let server = &args[1];
            let remote_path = &args[2];
            let local_path = args.get(3).map(|s| s.as_str());
            match sb_core::ssh_transport::build_scp_pull_args(server, remote_path, local_path) {
                Ok((scp_bin, scp_args)) => {
                    let status = Command::new(&scp_bin)
                        .args(&scp_args)
                        .status()
                        .unwrap_or_else(|e| {
                            eprintln!("Fehler beim Starten von scp: {}", e);
                            std::process::exit(1);
                        });
                    std::process::exit(status.code().unwrap_or(1));
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".bright_red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        Some("exec") => {
            if args.len() < 3 {
                eprintln!("Usage: sb ssh exec <server> <command...>");
                std::process::exit(1);
            }
            let server = &args[1];
            let remote_cmd = args[2..].join(" ");
            match sb_core::ssh_transport::build_ssh_exec_args(server, &remote_cmd) {
                Ok((ssh_bin, ssh_args)) => {
                    let status = Command::new(&ssh_bin)
                        .args(&ssh_args)
                        .status()
                        .unwrap_or_else(|e| {
                            eprintln!("Fehler beim Starten von ssh: {}", e);
                            std::process::exit(1);
                        });
                    std::process::exit(status.code().unwrap_or(1));
                }
                Err(e) => {
                    eprintln!("  {} {}", "✗".bright_red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        Some(target) => {
            let ssh_bin = match sb_core::ssh_transport::resolve_system_ssh() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("  {} {}", "✗".bright_red().bold(), e);
                    std::process::exit(1);
                }
            };

            let mut ssh_args = vec!["-F".to_string(), cfg_path.to_string_lossy().to_string()];

            if !target.starts_with('-') {
                if let Some(resolved) = sb_core::TargetResolver::resolve(target) {
                    ssh_args.push("-p".to_string());
                    ssh_args.push(resolved.port.to_string());
                    ssh_args.push(resolved.ssh_destination());
                    ssh_args.extend_from_slice(&args[1..]);
                } else {
                    ssh_args.extend_from_slice(args);
                }
            } else {
                ssh_args.extend_from_slice(args);
            }

            let status = Command::new(&ssh_bin)
                .args(&ssh_args)
                .status()
                .unwrap_or_else(|e| {
                    eprintln!("Fehler beim Starten von System-OpenSSH: {}", e);
                    std::process::exit(1);
                });
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

fn render_ssh_status(cfg_path: &std::path::Path, install_include: bool) {
    print_banner();
    println!(
        "  {} {}\n",
        "► SOVEREIGN OPENSSH INTEGRATOR".bold(),
        "[SB SSH + SB-CA]".bright_cyan().bold()
    );

    if install_include {
        if let Ok(user_cfg) = sb_core::ssh_transport::integrate_into_user_ssh_config() {
            println!(
                "  {} Include-Direktive verankert in: {}",
                "✓".bright_green().bold(),
                user_cfg.display().to_string().bright_cyan()
            );
        }
    }

    match sb_core::ssh_transport::resolve_system_ssh() {
        Ok(ssh_bin) => println!(
            "  {} System-OpenSSH:    {}",
            "✓".bright_green().bold(),
            ssh_bin.display().to_string().bright_green()
        ),
        Err(e) => println!("  {} System-OpenSSH:    {}", "✗".bright_red().bold(), e),
    }

    println!(
        "  {} S&B SSH-Config:    {}",
        "✓".bright_green().bold(),
        cfg_path.display().to_string().bright_cyan()
    );

    let kh_ca = sb_core::ssh_transport::sb_known_hosts_ca_path();
    println!(
        "  {} Host-CA Pinning:   {}",
        if kh_ca.is_file() {
            "✓".bright_green().bold()
        } else {
            "○".bright_yellow().bold()
        },
        if kh_ca.is_file() {
            format!("AKTIV ({})", kh_ca.display())
                .bright_green()
                .to_string()
        } else {
            "INAKTIV ('sb up --fix')".bright_yellow().to_string()
        }
    );

    let cert_path = sb_core::paths::sb_ssh_dir().join("id_ed25519-cert.pub");
    println!(
        "  {} 8h User-Zertifikat:{}",
        if cert_path.is_file() {
            "✓".bright_green().bold()
        } else {
            "○".bright_black()
        },
        if cert_path.is_file() {
            format!(" {}", cert_path.display())
                .bright_green()
                .to_string()
        } else {
            " Standard-Key (kein lokaler ~/.ssh/id_ed25519.pub zum Signieren)"
                .bright_black()
                .to_string()
        }
    );

    let servers = sb_core::TargetResolver::load_servers();
    println!(
        "\n  {} Konfigurierte Flotten-Ziele ({}):",
        "►".bright_cyan(),
        servers.len()
    );
    if servers.is_empty() {
        println!(
            "    • default-node -> root@<expected_node_ip>:22 (konfiguriere ~/.sb/config.toml)"
        );
    } else {
        for s in &servers {
            println!(
                "    • {:<20} -> {}@{}:{}",
                s.name.bright_white().bold(),
                s.user,
                s.host.cyan(),
                s.port
            );
        }
    }

    println!("\n  {} Befehle:", "i".bright_cyan());
    println!(
        "    • Interaktive Shell:  {}",
        "sb ssh <server>".bright_yellow().bold()
    );
    println!(
        "    • Remote-Befehl:      {}",
        "sb ssh exec <server> <cmd>".bright_yellow()
    );
    println!(
        "    • Datei-Upload (SCP): {}",
        "sb ssh push <server> <local> [remote]".bright_yellow()
    );
    println!(
        "    • Datei-Download:     {}",
        "sb ssh pull <server> <remote> [local]".bright_yellow()
    );
    println!(
        "    • ~/.ssh/config Hook: {}\n",
        "sb ssh config".bright_yellow()
    );
}
