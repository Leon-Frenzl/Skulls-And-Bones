//! Mesh-authorized Web SSH session manager for the Sovereign Control Console.
//!
//! Enforces domain membership, revocation status, RBAC/capability rules, issues
//! short-lived OpenSSH user certificates via `IdentityDirectory::issue_user_ssh_cert`,
//! and executes commands over SSH using ephemeral per-session Ed25519 keys.

use chrono::{DateTime, Duration, Utc};
use sb_auth::claims::SovereignClaims;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct WebSshSession {
    pub session_id: String,
    pub owner: String,
    pub machine_id: String,
    pub fqdn: String,
    pub mesh_ip: IpAddr,
    pub ssh_user: String,
    pub principals: Vec<String>,
    pub key_dir: PathBuf,
    pub priv_key_path: PathBuf,
    pub cert_path: PathBuf,
    pub known_hosts_path: PathBuf,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WebSshSessionInfo {
    pub session_id: String,
    pub machine_id: String,
    pub fqdn: String,
    pub mesh_ip: String,
    pub ssh_user: String,
    pub principals: Vec<String>,
    pub expires_at: String,
    pub cli_fallback: String,
}

#[derive(Debug, Serialize)]
pub struct WebSshExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

static SESSIONS: OnceLock<Arc<RwLock<HashMap<String, WebSshSession>>>> = OnceLock::new();

fn session_store() -> &'static Arc<RwLock<HashMap<String, WebSshSession>>> {
    SESSIONS.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// Validates an SSH target username (`1..=32` safe ASCII characters).
pub fn validate_ssh_user(user: &str) -> Result<String, String> {
    let trimmed = user.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err("SSH user must be 1..=32 characters".into());
    }
    let first = trimmed.as_bytes()[0];
    if !first.is_ascii_alphanumeric() && first != b'_' {
        return Err("SSH user must start with ASCII letter, digit, or '_'".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("SSH user contains invalid characters".into());
    }
    Ok(trimmed.to_string())
}

/// Checks Mesh/Domain authorization and opens a short-lived Web SSH session for `machine_id`.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unauthorized lateral SSH movement to revoked machines,
///   cross-user session hijacking, or SSH option/command injection.
/// - **CVE / CWE Mapping:** CWE-284 (Improper Access Control), CWE-78 (OS Command Injection),
///   CWE-295 (Improper Certificate Validation).
/// - **Likelihood & Exploitability:** High (8/10) on browser-accessible SSH bridges.
/// - **Applied Mitigation:** Verifies `user.enabled`, enforces `domain:admin`/`ssh:connect` or
///   active JIT elevation, rejects revoked machines, validates `mesh_ip` as `IpAddr`, issues a
///   1-hour OpenSSH user certificate bound to `claims.subject`, and isolates ephemeral keys per
///   session directory (`0o600`).
// Conforms to OpenSSH PROTOCOL.certkeys and NIST SP 800-53 AC-3 (Access Enforcement).
pub async fn open_web_ssh_session(
    claims: &SovereignClaims,
    machine_id: &str,
    requested_ssh_user: Option<&str>,
    base_dir: &Path,
) -> Result<WebSshSessionInfo, (u16, String)> {
    let users_path = base_dir.join("users.json");
    let dir = crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
        .map_err(|e| (500, e))?;
    let user = dir
        .users
        .get(&claims.subject)
        .ok_or_else(|| (404, format!("User '{}' not found", claims.subject)))?;
    if !user.enabled {
        return Err((403, "User account is disabled".into()));
    }

    let rbac_path = base_dir.join("rbac.json");
    let mut rbac_store = crate::rbac::RbacStore::load(&rbac_path).unwrap_or_default();
    let has_jit = rbac_store
        .active_elevations_for(&claims.subject)
        .iter()
        .any(|e| {
            e.granted_capabilities
                .iter()
                .any(|c| c == "ssh:connect" || c == "domain:admin")
        });
    let authorized = claims.has_role("admin")
        || claims.has_capability("domain:admin")
        || claims.has_capability("ssh:connect")
        || has_jit;
    if !authorized {
        return Err((
            403,
            "Token lacks 'ssh:connect', 'domain:admin', or active SSH elevation".into(),
        ));
    }

    let reg_path = base_dir.join("machines.json");
    let registry = crate::domain_join::DomainRegistry::load_from_path(&reg_path, &dir.domain)
        .map_err(|e| (500, e))?;
    let machine = registry
        .machines
        .iter()
        .find(|m| m.machine_id == machine_id)
        .ok_or_else(|| (404, format!("Machine '{machine_id}' not found")))?;
    if machine.revoked {
        return Err((
            403,
            format!(
                "Machine '{}' is revoked and blocked by Mesh policy",
                machine.fqdn
            ),
        ));
    }

    let mesh_ip: IpAddr = machine.mesh_ip.trim().parse().map_err(|e| {
        (
            500,
            format!("Invalid machine mesh_ip '{}': {e}", machine.mesh_ip),
        )
    })?;

    let ssh_user = match requested_ssh_user {
        Some(u) if !u.trim().is_empty() => {
            if !claims.has_role("admin")
                && !claims.has_capability("domain:admin")
                && u.trim() != claims.subject
            {
                return Err((
                    403,
                    "Only admins may specify a different SSH target user".into(),
                ));
            }
            validate_ssh_user(u).map_err(|e| (400, e))?
        }
        _ => validate_ssh_user(&claims.subject).map_err(|e| (400, e))?,
    };

    let sid = format!("wssh_{:016x}", rand::random::<u64>());
    let key_dir = base_dir.join("web_ssh").join(&sid);
    fs::create_dir_all(&key_dir).map_err(|e| (500, format!("Failed creating key dir: {e}")))?;
    let priv_key_path = key_dir.join("id_ed25519");
    let pub_key_path = key_dir.join("id_ed25519.pub");
    let cert_path = key_dir.join("id_ed25519-cert.pub");
    let known_hosts_path = key_dir.join("known_hosts");

    let keygen_out = tokio::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-q",
            "-f",
            &priv_key_path.to_string_lossy(),
        ])
        .output()
        .await
        .map_err(|e| (500, format!("ssh-keygen failed: {e}")))?;
    if !keygen_out.status.success() {
        let _ = fs::remove_dir_all(&key_dir);
        return Err((
            500,
            format!(
                "ssh-keygen error: {}",
                String::from_utf8_lossy(&keygen_out.stderr)
            ),
        ));
    }

    let pubkey = fs::read_to_string(&pub_key_path)
        .map_err(|e| (500, format!("Failed reading generated pubkey: {e}")))?;
    let cert_resp = dir
        .issue_user_ssh_cert(&claims.subject, Some(pubkey.trim()), 3600)
        .map_err(|e| (500, format!("OpenSSH CA cert issuance failed: {e}")))?;
    fs::write(&cert_path, cert_resp.certificate_openssh.as_bytes())
        .map_err(|e| (500, format!("Failed writing SSH cert: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&priv_key_path, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o600));
    }

    let expires_at = Utc::now() + Duration::hours(1);
    let info = WebSshSessionInfo {
        session_id: sid.clone(),
        machine_id: machine.machine_id.clone(),
        fqdn: machine.fqdn.clone(),
        mesh_ip: mesh_ip.to_string(),
        ssh_user: ssh_user.clone(),
        principals: cert_resp.principals.clone(),
        expires_at: expires_at.to_rfc3339(),
        cli_fallback: format!("sb ssh {ssh_user}@{}", machine.fqdn),
    };

    let session = WebSshSession {
        session_id: sid.clone(),
        owner: claims.subject.clone(),
        machine_id: machine.machine_id.clone(),
        fqdn: machine.fqdn.clone(),
        mesh_ip,
        ssh_user,
        principals: cert_resp.principals,
        key_dir,
        priv_key_path,
        cert_path,
        known_hosts_path,
        expires_at,
    };

    let mut guard = session_store().write().await;
    // Prune expired sessions and cap active sessions to prevent resource exhaustion
    let now = Utc::now();
    let expired_keys: Vec<String> = guard
        .iter()
        .filter(|(_, s)| s.expires_at <= now)
        .map(|(k, _)| k.clone())
        .collect();
    for k in expired_keys {
        if let Some(old) = guard.remove(&k) {
            let _ = fs::remove_dir_all(&old.key_dir);
        }
    }
    if guard.len() >= 32 {
        return Err((429, "Too many active Web SSH sessions (max 32)".into()));
    }
    guard.insert(sid, session);

    Ok(info)
}

/// Executes a single command inside an authorized Web SSH session.
pub async fn exec_web_ssh_command(
    claims: &SovereignClaims,
    session_id: &str,
    command: &str,
) -> Result<WebSshExecResult, (u16, String)> {
    let trimmed = command.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 || trimmed.contains('\0') {
        return Err((400, "Command must be 1..=4096 NUL-free characters".into()));
    }

    let session = {
        let guard = session_store().read().await;
        let s = guard
            .get(session_id)
            .ok_or_else(|| (404, "Web SSH session not found or expired".to_string()))?;
        if s.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "Session belongs to another user".into()));
        }
        if s.expires_at <= Utc::now() {
            return Err((401, "Web SSH session expired".into()));
        }
        s.clone()
    };

    let target = format!("{}@{}", session.ssh_user, session.mesh_ip);
    let cert_opt = format!("CertificateFile={}", session.cert_path.display());
    let kh_opt = format!("UserKnownHostsFile={}", session.known_hosts_path.display());

    let mut cmd = tokio::process::Command::new("ssh");
    cmd.args([
        "-i",
        &session.priv_key_path.to_string_lossy(),
        "-o",
        &cert_opt,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        &kh_opt,
        &target,
        "--",
        trimmed,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let out = tokio::time::timeout(std::time::Duration::from_secs(15), cmd.output())
        .await
        .map_err(|_| (504, "SSH command timed out after 15s".to_string()))?
        .map_err(|e| (502, format!("Failed to invoke ssh client: {e}")))?;

    Ok(WebSshExecResult {
        exit_code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

/// Closes a Web SSH session and deletes its ephemeral keypair/certificate directory.
pub async fn close_web_ssh_session(
    claims: &SovereignClaims,
    session_id: &str,
) -> Result<bool, (u16, String)> {
    let mut guard = session_store().write().await;
    if let Some(s) = guard.get(session_id) {
        if s.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "Session belongs to another user".into()));
        }
    } else {
        return Ok(false);
    }
    if let Some(removed) = guard.remove(session_id) {
        let _ = fs::remove_dir_all(&removed.key_dir);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_user_validation_blocks_injection() {
        assert!(validate_ssh_user("leon.admin").is_ok());
        assert!(validate_ssh_user("root").is_ok());
        assert!(validate_ssh_user("bad;rm").is_err());
        assert!(validate_ssh_user("-oProxyCommand=evil").is_err());
        assert!(validate_ssh_user("").is_err());
    }
}
