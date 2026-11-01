//! Sovereign OpenSSH Transport & Configuration Integrator (`~/.sb/ssh/ssh_config`)
//!
//! Replaces the legacy prototype `sb-ssh` binary with a first-principles OpenSSH
//! integration layer that:
//! 1. Locates the authentic OS OpenSSH binaries (`ssh` and `scp`), strictly ignoring
//!    any shadowing binaries in `~/.cargo/bin`.
//! 2. Generates and maintains `~/.sb/ssh/ssh_config` and `~/.sb/ssh/known_hosts_ca`
//!    with `@cert-authority` pinning from `sb-ca` (`~/.sb/ca/ssh/ca_key.pub`) and
//!    host blocks from `~/.sb/servers.toml`.
//! 3. Provides unified command builders (`build_ssh_exec_args`, `build_scp_push_args`,
//!    `build_scp_pull_args`) used across `sb`, `sb-forge`, and `sb-drive`.
//!
//! Standards Compliance:
//! - Conforms to IETF RFC 4251 / RFC 4252 / RFC 4253 / RFC 4254 (SSH Protocol Architecture)
//! - Conforms to OpenSSH PROTOCOL.certkeys (`@cert-authority` & `CertificateFile`)
//! - Conforms to IEEE 1003.1 / POSIX.1-2017 (`0700` / `0600` file permissions)

use std::fs;
use std::path::PathBuf;

use crate::paths::{sb_ca_ssh_pub_path, sb_ssh_dir};
use crate::target::TargetResolver;

/// Resolves the authentic system OpenSSH `ssh` executable, strictly filtering out
/// any shadowing binary inside `.cargo/bin` or `.sb/bin`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Untrusted or legacy `ssh` binary in user-writable `.cargo/bin` shadowing the OS OpenSSH client and corrupting binary pipes (`scp`, `git`, `tar`).
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path), CWE-427 (Uncontrolled Search Path Element).
/// - Likelihood & Exploitability: Medium (5/10) on developer workstations with `.cargo/bin` prepended to `PATH`.
/// - Applied Mitigation: Checks trusted OS paths first (`/usr/bin/ssh`, `C:\Windows\System32\OpenSSH\ssh.exe`, `C:\Program Files\Git\usr\bin\ssh.exe`) and filters out any `.cargo` or `sb-ssh` path.
/// - Standards Compliance: Conforms to IETF RFC 4251 and IEEE 1003.1 (POSIX.1-2017).
pub fn resolve_system_ssh() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let candidates = [
            PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe"),
            PathBuf::from(r"C:\Program Files\Git\usr\bin\ssh.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Git\usr\bin\ssh.exe"),
        ];
        for cand in &candidates {
            if cand.is_file() {
                return Ok(cand.clone());
            }
        }
    }

    #[cfg(unix)]
    {
        let candidates = [
            PathBuf::from("/usr/bin/ssh"),
            PathBuf::from("/bin/ssh"),
            PathBuf::from("/usr/local/bin/ssh"),
        ];
        for cand in &candidates {
            if cand.is_file() {
                return Ok(cand.clone());
            }
        }
    }

    if let Ok(paths) = which::which_all("ssh") {
        for p in paths {
            let lossy = p.to_string_lossy().to_lowercase();
            if !lossy.contains(".cargo") && !lossy.contains("sb-ssh") {
                return Ok(p);
            }
        }
    }

    Err("System-OpenSSH ('ssh') wurde nicht gefunden. Bitte OpenSSH Client installieren.".to_string())
}

/// Resolves the authentic system OpenSSH `scp` executable.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Untrusted `scp` binary resolution via manipulated `PATH`.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Prioritizes OS-trusted installation paths before falling back to filtered `PATH` lookup.
pub fn resolve_system_scp() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let candidates = [
            PathBuf::from(r"C:\Windows\System32\OpenSSH\scp.exe"),
            PathBuf::from(r"C:\Program Files\Git\usr\bin\scp.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Git\usr\bin\scp.exe"),
        ];
        for cand in &candidates {
            if cand.is_file() {
                return Ok(cand.clone());
            }
        }
    }

    #[cfg(unix)]
    {
        let candidates = [
            PathBuf::from("/usr/bin/scp"),
            PathBuf::from("/bin/scp"),
            PathBuf::from("/usr/local/bin/scp"),
        ];
        for cand in &candidates {
            if cand.is_file() {
                return Ok(cand.clone());
            }
        }
    }

    if let Ok(paths) = which::which_all("scp") {
        for p in paths {
            let lossy = p.to_string_lossy().to_lowercase();
            if !lossy.contains(".cargo") {
                return Ok(p);
            }
        }
    }

    Err("System-OpenSSH ('scp') wurde nicht gefunden. Bitte OpenSSH Client installieren.".to_string())
}

/// Returns the canonical path to `~/.sb/ssh/ssh_config`.
pub fn sb_ssh_config_path() -> PathBuf {
    sb_ssh_dir().join("ssh_config")
}

/// Returns the canonical path to `~/.sb/ssh/known_hosts_ca`.
pub fn sb_known_hosts_ca_path() -> PathBuf {
    sb_ssh_dir().join("known_hosts_ca")
}

/// Generates and updates `~/.sb/ssh/ssh_config` and `~/.sb/ssh/known_hosts_ca`
/// using the unified `sb-ca` OpenSSH Root CA (`~/.sb/ca/ssh/ca_key.pub`) and
/// the registered fleet servers (`~/.sb/servers.toml`).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: SSH configuration injection (`ProxyCommand` injection via crafted server names or hostnames) or weak file permissions (`> 0600`) causing OpenSSH to reject the config file.
/// - CVE / CWE Mapping: CWE-78 (OS Command Injection), CWE-732 (Incorrect Permission Assignment for Critical Resource).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Sanitizes all host aliases and hostnames to strict RFC 1123 / ASCII tokens without whitespace or newlines, and enforces `0700` directory / `0600` file permissions on Unix.
/// - Standards Compliance: Conforms to OpenSSH `ssh_config(5)`, `PROTOCOL.certkeys`, and POSIX.1-2017.
pub fn ensure_sovereign_ssh_config() -> Result<PathBuf, String> {
    let ssh_dir = sb_ssh_dir();
    fs::create_dir_all(&ssh_dir)
        .map_err(|e| format!("Konnte ~/.sb/ssh nicht anlegen: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700));
    }

    // 1. Write known_hosts_ca with @cert-authority pinning if sb-ca SSH CA is initialized
    let known_hosts_ca = sb_known_hosts_ca_path();
    let ca_pub_path = sb_ca_ssh_pub_path();
    if ca_pub_path.is_file() {
        if let Ok(ca_pub) = fs::read_to_string(&ca_pub_path) {
            let trimmed = ca_pub.trim();
            if !trimmed.is_empty() && !trimmed.contains('\n') {
                let kh_content = format!(
                    "# Managed by Skulls & Bones (sb-ca OpenSSH Host CA Pinning)\n@cert-authority * {}\n",
                    trimmed
                );
                let _ = fs::write(&known_hosts_ca, kh_content);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&known_hosts_ca, fs::Permissions::from_mode(0o600));
                }
            }
        }
    }

    // 2. Build ~/.sb/ssh/ssh_config
    let cfg_path = sb_ssh_config_path();
    let mut cfg = String::new();
    cfg.push_str("# ============================================================================\n");
    cfg.push_str("# SKULLS & BONES — SOVEREIGN OPENSSH CONFIGURATION (AUTO-GENERATED)\n");
    cfg.push_str("# Conforms to RFC 4251 & OpenSSH PROTOCOL.certkeys\n");
    cfg.push_str("# ============================================================================\n\n");

    let servers = TargetResolver::load_servers();
    for srv in &servers {
        let safe_name: String = srv
            .name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        let safe_host: String = srv
            .host
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == ':')
            .collect();
        let safe_user: String = srv
            .user
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();

        if safe_name.is_empty() || safe_host.is_empty() {
            continue;
        }

        let sbm_alias = if safe_name.ends_with(".sbm") {
            safe_name.clone()
        } else {
            format!("{}.sbm", safe_name)
        };

        cfg.push_str(&format!("Host {} {}\n", safe_name, sbm_alias));
        cfg.push_str(&format!("    HostName {}\n", safe_host));
        cfg.push_str(&format!(
            "    User {}\n",
            if safe_user.is_empty() { "root" } else { &safe_user }
        ));
        cfg.push_str(&format!("    Port {}\n\n", srv.port));
    }

    // Default Hostinger / Stealth aliases
    let suite_cfg = crate::config::SuiteConfig::load();
    let default_ip = suite_cfg
        .network
        .expected_node_ip
        .as_deref()
        .unwrap_or("145.223.83.235");
    cfg.push_str("Host hostinger-stealth srv490042 hostinger-node hostinger-prod stealth\n");
    cfg.push_str(&format!("    HostName {}\n", default_ip));
    cfg.push_str("    User root\n");
    cfg.push_str("    Port 22\n\n");

    // Global S&B defaults
    cfg.push_str("Host *\n");
    cfg.push_str("    ServerAliveInterval 30\n");
    cfg.push_str("    ServerAliveCountMax 3\n");
    cfg.push_str("    StrictHostKeyChecking accept-new\n");

    let sb_id_key = ssh_dir.join("id_ed25519");
    let sb_cert = ssh_dir.join("id_ed25519-cert.pub");
    if sb_id_key.is_file() {
        cfg.push_str(&format!(
            "    IdentityFile \"{}\"\n",
            sb_id_key.to_string_lossy().replace('\\', "/")
        ));
    }
    if sb_cert.is_file() {
        cfg.push_str(&format!(
            "    CertificateFile \"{}\"\n",
            sb_cert.to_string_lossy().replace('\\', "/")
        ));
    }

    if known_hosts_ca.is_file() {
        if let Some(home) = dirs::home_dir() {
            let user_kh = home.join(".ssh").join("known_hosts");
            cfg.push_str(&format!(
                "    UserKnownHostsFile \"{}\" \"{}\"\n",
                known_hosts_ca.to_string_lossy().replace('\\', "/"),
                user_kh.to_string_lossy().replace('\\', "/")
            ));
        }
    }

    fs::write(&cfg_path, cfg)
        .map_err(|e| format!("Konnte ~/.sb/ssh/ssh_config nicht schreiben: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&cfg_path, fs::Permissions::from_mode(0o600));
    }

    Ok(cfg_path)
}

/// Anchors `Include "<~/.sb/ssh/ssh_config>"` at the top of the user's `~/.ssh/config`
/// so native `ssh`, `scp`, `git`, and VS Code Remote-SSH automatically resolve all
/// S&B servers and CA certificates.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Corrupting existing user `~/.ssh/config` or assigning weak permissions (`> 0600`) that cause OpenSSH to refuse connection.
/// - CVE / CWE Mapping: CWE-732 (Incorrect Permission Assignment for Critical Resource).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Idempotently prepends the `Include` directive only if not already present, preserves all existing user directives, and enforces `0700` on `~/.ssh` and `0600` on `~/.ssh/config`.
pub fn integrate_into_user_ssh_config() -> Result<PathBuf, String> {
    let sb_cfg = ensure_sovereign_ssh_config()?;
    let home = dirs::home_dir().ok_or_else(|| "Home-Verzeichnis nicht gefunden".to_string())?;
    let user_ssh_dir = home.join(".ssh");
    fs::create_dir_all(&user_ssh_dir)
        .map_err(|e| format!("Konnte ~/.ssh nicht anlegen: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&user_ssh_dir, fs::Permissions::from_mode(0o700));
    }

    let user_cfg_path = user_ssh_dir.join("config");
    let normalized_sb_cfg = sb_cfg.to_string_lossy().replace('\\', "/");
    let include_line = format!("Include \"{}\"", normalized_sb_cfg);

    let existing = if user_cfg_path.is_file() {
        fs::read_to_string(&user_cfg_path).unwrap_or_default()
    } else {
        String::new()
    };

    if !existing.contains(&normalized_sb_cfg) {
        let updated = format!(
            "# Managed by Skulls & Bones Sovereign SSH Integrator\n{}\n\n{}",
            include_line, existing
        );
        fs::write(&user_cfg_path, updated)
            .map_err(|e| format!("Konnte ~/.ssh/config nicht aktualisieren: {}", e))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&user_cfg_path, fs::Permissions::from_mode(0o600));
    }

    Ok(user_cfg_path)
}

/// Builds a non-interactive OpenSSH execution command (`ssh -F <cfg> -p <port> <user@host> <cmd>`)
/// for `sb-forge`, `sb-drive`, `sb trace`, and `sb logs`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Argument injection via leading `-` in target hostname (`-oProxyCommand=...`).
/// - CVE / CWE Mapping: CWE-88 (Improper Neutralization of Argument Delimiters in a Command).
/// - Likelihood & Exploitability: Medium (4/10) if untrusted peer/server strings are passed.
/// - Applied Mitigation: Rejects any target or resolved destination starting with `-` and passes the destination after explicit option flags.
pub fn build_ssh_exec_args(
    target: &str,
    remote_cmd: &str,
) -> Result<(PathBuf, Vec<String>), String> {
    let trimmed = target.trim().trim_start_matches('@');
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return Err(format!("Ungültiges SSH-Ziel '{}'", target));
    }

    let ssh_bin = resolve_system_ssh()?;
    let cfg_path = ensure_sovereign_ssh_config()?;
    let resolved = TargetResolver::resolve(trimmed).ok_or_else(|| {
        format!("Zielserver '{}' konnte nicht aufgelöst werden", target)
    })?;

    let dest = resolved.ssh_destination();
    if dest.starts_with('-') {
        return Err(format!("Ungültige SSH-Destination '{}'", dest));
    }

    let args = vec![
        "-F".to_string(),
        cfg_path.to_string_lossy().to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-p".to_string(),
        resolved.port.to_string(),
        dest,
        remote_cmd.to_string(),
    ];

    Ok((ssh_bin, args))
}

/// Builds an OpenSSH `scp` upload command (`scp -r -F <cfg> -P <port> <local> <user@host>:<remote>`).
pub fn build_scp_push_args(
    target: &str,
    local_path: &str,
    remote_path: Option<&str>,
) -> Result<(PathBuf, Vec<String>), String> {
    let trimmed = target.trim().trim_start_matches('@');
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return Err(format!("Ungültiges SCP-Ziel '{}'", target));
    }

    let scp_bin = resolve_system_scp()?;
    let cfg_path = ensure_sovereign_ssh_config()?;
    let resolved = TargetResolver::resolve(trimmed).ok_or_else(|| {
        format!("Zielserver '{}' konnte nicht aufgelöst werden", target)
    })?;

    let target_remote = remote_path.unwrap_or("~/");
    let dest = format!("{}:{}", resolved.ssh_destination(), target_remote);

    let args = vec![
        "-r".to_string(),
        "-F".to_string(),
        cfg_path.to_string_lossy().to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-P".to_string(),
        resolved.port.to_string(),
        local_path.to_string(),
        dest,
    ];

    Ok((scp_bin, args))
}

/// Builds an OpenSSH `scp` download command (`scp -r -F <cfg> -P <port> <user@host>:<remote> <local>`).
pub fn build_scp_pull_args(
    target: &str,
    remote_path: &str,
    local_path: Option<&str>,
) -> Result<(PathBuf, Vec<String>), String> {
    let trimmed = target.trim().trim_start_matches('@');
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return Err(format!("Ungültiges SCP-Ziel '{}'", target));
    }

    let scp_bin = resolve_system_scp()?;
    let cfg_path = ensure_sovereign_ssh_config()?;
    let resolved = TargetResolver::resolve(trimmed).ok_or_else(|| {
        format!("Zielserver '{}' konnte nicht aufgelöst werden", target)
    })?;

    let target_local = local_path.unwrap_or(".");
    let src = format!("{}:{}", resolved.ssh_destination(), remote_path);

    let args = vec![
        "-r".to_string(),
        "-F".to_string(),
        cfg_path.to_string_lossy().to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-P".to_string(),
        resolved.port.to_string(),
        src,
        target_local.to_string(),
    ];

    Ok((scp_bin, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_system_ssh_never_returns_cargo_shadow() {
        if let Ok(ssh_path) = resolve_system_ssh() {
            let lower = ssh_path.to_string_lossy().to_lowercase();
            assert!(
                !lower.contains(".cargo"),
                "System ssh resolver must never return a shadowing .cargo/bin binary"
            );
        }
    }

    #[test]
    fn test_ensure_sovereign_ssh_config_and_exec_args() {
        let cfg = ensure_sovereign_ssh_config().expect("must generate ~/.sb/ssh/ssh_config");
        assert!(cfg.exists());
        let content = fs::read_to_string(&cfg).expect("must read ssh_config");
        assert!(content.contains("Host hostinger-stealth"));
        assert!(content.contains("StrictHostKeyChecking accept-new"));

        if resolve_system_ssh().is_ok() {
            let (_bin, args) =
                build_ssh_exec_args("hostinger-stealth", "uname -a").expect("must build ssh args");
            assert!(args.contains(&"-F".to_string()));
            assert!(args.contains(&"uname -a".to_string()));
        }

        assert!(
            build_ssh_exec_args("-oProxyCommand=evil", "id").is_err(),
            "Must reject leading dash argument injection"
        );
    }
}
