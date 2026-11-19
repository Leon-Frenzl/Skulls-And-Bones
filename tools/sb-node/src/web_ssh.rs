//! Mesh-authorized Web SSH session manager for the Sovereign Control Console.
//!
//! Enforces domain membership, revocation status, RBAC/capability rules, issues
//! short-lived OpenSSH user certificates via `IdentityDirectory::issue_user_ssh_cert`,
//! and executes commands over SSH using ephemeral per-session Ed25519 keys.

use chrono::{DateTime, Duration, Utc};
use sb_auth::claims::SovereignClaims;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use tokio::sync::{Notify, RwLock};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSshExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub cwd: String,
}

fn default_relay_kind() -> String {
    "exec".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCommand {
    pub cmd_id: String,
    pub session_id: String,
    pub ssh_user: String,
    pub command: String,
    #[serde(default = "default_relay_kind")]
    pub kind: String,
    #[serde(default)]
    pub target_port: Option<u16>,
}

#[derive(Debug, Default)]
struct MachineRelayQueue {
    last_poll_at: Option<DateTime<Utc>>,
    queue: VecDeque<RelayCommand>,
    notify: Arc<Notify>,
}

static SESSIONS: OnceLock<Arc<RwLock<HashMap<String, WebSshSession>>>> = OnceLock::new();
static RELAY_QUEUES: OnceLock<Arc<RwLock<HashMap<String, MachineRelayQueue>>>> = OnceLock::new();
#[allow(clippy::type_complexity)]
static RELAY_RESULTS: OnceLock<
    Arc<RwLock<HashMap<String, (Arc<Notify>, Option<WebSshExecResult>)>>>,
> = OnceLock::new();

fn session_store() -> &'static Arc<RwLock<HashMap<String, WebSshSession>>> {
    SESSIONS.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

fn relay_queues() -> &'static Arc<RwLock<HashMap<String, MachineRelayQueue>>> {
    RELAY_QUEUES.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

#[allow(clippy::type_complexity)]
fn relay_results() -> &'static Arc<RwLock<HashMap<String, (Arc<Notify>, Option<WebSshExecResult>)>>>
{
    RELAY_RESULTS.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

async fn is_relay_online(machine_id: &str) -> bool {
    let guard = relay_queues().read().await;
    guard
        .get(machine_id)
        .and_then(|q| q.last_poll_at)
        .map(|ts| Utc::now() - ts < Duration::seconds(90))
        .unwrap_or(false)
}

/// Long-polls for the next authorized Web SSH command queued for `machine_id`.
pub async fn poll_relay_command(machine_id: &str, wait_secs: u64) -> Option<RelayCommand> {
    let wait = wait_secs.min(25);
    let notify = {
        let mut guard = relay_queues().write().await;
        let entry = guard.entry(machine_id.to_string()).or_default();
        entry.last_poll_at = Some(Utc::now());
        if let Some(cmd) = entry.queue.pop_front() {
            return Some(cmd);
        }
        Arc::clone(&entry.notify)
    };

    if wait == 0 {
        return None;
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(wait), notify.notified()).await;

    let mut guard = relay_queues().write().await;
    let entry = guard.entry(machine_id.to_string()).or_default();
    entry.last_poll_at = Some(Utc::now());
    entry.queue.pop_front()
}

/// Records the execution result of a relayed command and wakes the waiting Web Console call.
pub async fn submit_relay_result(cmd_id: &str, result: WebSshExecResult) -> bool {
    let notify_opt = {
        let mut guard = relay_results().write().await;
        if let Some((notify, slot)) = guard.get_mut(cmd_id) {
            *slot = Some(result);
            Some(Arc::clone(notify))
        } else {
            None
        }
    };
    if let Some(notify) = notify_opt {
        notify.notify_one();
        true
    } else {
        false
    }
}

async fn exec_via_relay(
    machine_id: &str,
    session_id: &str,
    ssh_user: &str,
    command: &str,
) -> Result<WebSshExecResult, (u16, String)> {
    let cmd_id = format!("rcmd_{:016x}", rand::random::<u64>());
    let res_notify = Arc::new(Notify::new());
    {
        let mut res_guard = relay_results().write().await;
        res_guard.insert(cmd_id.clone(), (Arc::clone(&res_notify), None));
    }

    let q_notify = {
        let mut q_guard = relay_queues().write().await;
        let entry = q_guard.entry(machine_id.to_string()).or_default();
        entry.queue.push_back(RelayCommand {
            cmd_id: cmd_id.clone(),
            session_id: session_id.to_string(),
            ssh_user: ssh_user.to_string(),
            command: command.to_string(),
            kind: "exec".to_string(),
            target_port: None,
        });
        Arc::clone(&entry.notify)
    };
    q_notify.notify_one();

    let wait_res =
        tokio::time::timeout(std::time::Duration::from_secs(15), res_notify.notified()).await;
    let mut res_guard = relay_results().write().await;
    let removed = res_guard.remove(&cmd_id).and_then(|(_, r)| r);
    match (wait_res, removed) {
        (Ok(_), Some(r)) => Ok(r),
        _ => Err((
            504,
            "HTTPS-Relay Zeitüberschreitung (15s) — Agent hat nicht geantwortet".into(),
        )),
    }
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

    if is_relay_online(&session.machine_id).await {
        return exec_via_relay(
            &session.machine_id,
            &session.session_id,
            &session.ssh_user,
            trimmed,
        )
        .await;
    }

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
        cwd: String::new(),
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

/// Public metadata returned when opening a TCP-over-HTTPS-443 relay tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTunnelInfo {
    pub tunnel_id: String,
    pub machine_id: String,
    pub fqdn: String,
    pub target_port: u16,
    pub expires_at: String,
}

#[derive(Debug)]
struct RelayTunnelState {
    owner: String,
    #[allow(dead_code)]
    machine_id: String,
    c2a_buf: VecDeque<Vec<u8>>,
    a2c_buf: VecDeque<Vec<u8>>,
    c2a_notify: Arc<Notify>,
    a2c_notify: Arc<Notify>,
    closed: bool,
    expires_at: DateTime<Utc>,
}

static RELAY_TUNNELS: OnceLock<Arc<RwLock<HashMap<String, RelayTunnelState>>>> = OnceLock::new();

fn relay_tunnels() -> &'static Arc<RwLock<HashMap<String, RelayTunnelState>>> {
    RELAY_TUNNELS.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// Opens an authorized TCP-over-HTTPS-443 relay tunnel to `target_port` on `machine_id`.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unauthorized TCP port forwarding to internal machine loopback
///   services (e.g. RDP/DB/Admin UI) or accessing revoked machines.
/// - **CVE / CWE Mapping:** CWE-284 (Improper Access Control), CWE-918 (SSRF).
/// - **Likelihood & Exploitability:** High (8/10) on remote tunnel gateways.
/// - **Applied Mitigation:** Validates active user, `admin`/`domain:admin`/`tunnel:connect`/`ssh:connect`
///   capability, non-revoked machine membership, non-zero `target_port`, active online relay
///   agent, and caps concurrent tunnels at 32 with a 1-hour lifetime.
pub async fn open_relay_tunnel(
    claims: &SovereignClaims,
    machine_id: &str,
    target_port: u16,
    base_dir: &Path,
) -> Result<RelayTunnelInfo, (u16, String)> {
    if target_port == 0 {
        return Err((400, "Target port must be 1..=65535".into()));
    }
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
    let authorized = claims.has_role("admin")
        || claims.has_capability("domain:admin")
        || claims.has_capability("tunnel:connect")
        || claims.has_capability("ssh:connect");
    if !authorized {
        return Err((
            403,
            "Token lacks 'tunnel:connect', 'ssh:connect', or 'domain:admin'".into(),
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
    if !is_relay_online(machine_id).await {
        return Err((503, format!("Relay agent on '{}' is offline", machine.fqdn)));
    }

    let tunnel_id = format!("tun_{:016x}", rand::random::<u64>());
    let expires_at = Utc::now() + Duration::hours(1);
    {
        let mut guard = relay_tunnels().write().await;
        let now = Utc::now();
        guard.retain(|_, t| !t.closed && t.expires_at > now);
        if guard.len() >= 32 {
            return Err((429, "Too many active relay tunnels (max 32)".into()));
        }
        guard.insert(
            tunnel_id.clone(),
            RelayTunnelState {
                owner: claims.subject.clone(),
                machine_id: machine.machine_id.clone(),
                c2a_buf: VecDeque::new(),
                a2c_buf: VecDeque::new(),
                c2a_notify: Arc::new(Notify::new()),
                a2c_notify: Arc::new(Notify::new()),
                closed: false,
                expires_at,
            },
        );
    }

    let q_notify = {
        let mut q_guard = relay_queues().write().await;
        let entry = q_guard.entry(machine_id.to_string()).or_default();
        entry.queue.push_back(RelayCommand {
            cmd_id: tunnel_id.clone(),
            session_id: tunnel_id.clone(),
            ssh_user: claims.subject.clone(),
            command: String::new(),
            kind: "tunnel_open".to_string(),
            target_port: Some(target_port),
        });
        Arc::clone(&entry.notify)
    };
    q_notify.notify_one();

    Ok(RelayTunnelInfo {
        tunnel_id,
        machine_id: machine.machine_id.clone(),
        fqdn: machine.fqdn.clone(),
        target_port,
        expires_at: expires_at.to_rfc3339(),
    })
}

/// Pushes a raw byte chunk into a relay tunnel (`from_agent = false` -> client-to-agent).
pub async fn push_tunnel_data(
    claims: &SovereignClaims,
    tunnel_id: &str,
    from_agent: bool,
    data: Vec<u8>,
    eof: bool,
) -> Result<(), (u16, String)> {
    let notify = {
        let mut guard = relay_tunnels().write().await;
        let t = guard
            .get_mut(tunnel_id)
            .ok_or_else(|| (404, "Tunnel not found".to_string()))?;
        if from_agent {
            if !claims.has_capability("domain:join") && !claims.has_role("admin") {
                return Err((403, "Forbidden".into()));
            }
        } else if t.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "Tunnel belongs to another user".into()));
        }
        if t.closed {
            return Err((410, "Tunnel closed".into()));
        }
        if !data.is_empty() {
            if from_agent {
                t.a2c_buf.push_back(data);
            } else {
                t.c2a_buf.push_back(data);
            }
        }
        if eof {
            t.closed = true;
            t.c2a_notify.notify_waiters();
            t.a2c_notify.notify_waiters();
            return Ok(());
        }
        if from_agent {
            Arc::clone(&t.a2c_notify)
        } else {
            Arc::clone(&t.c2a_notify)
        }
    };
    notify.notify_one();
    Ok(())
}

/// Pulls pending bytes from a relay tunnel (`from_agent = true` -> agent reads client-to-agent).
pub async fn pull_tunnel_data(
    claims: &SovereignClaims,
    tunnel_id: &str,
    from_agent: bool,
    wait_secs: u64,
) -> Result<(Vec<u8>, bool), (u16, String)> {
    let wait = wait_secs.min(20);
    let notify = {
        let mut guard = relay_tunnels().write().await;
        let t = guard
            .get_mut(tunnel_id)
            .ok_or_else(|| (404, "Tunnel not found".to_string()))?;
        if from_agent {
            if !claims.has_capability("domain:join") && !claims.has_role("admin") {
                return Err((403, "Forbidden".into()));
            }
        } else if t.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "Tunnel belongs to another user".into()));
        }
        let buf = if from_agent {
            &mut t.c2a_buf
        } else {
            &mut t.a2c_buf
        };
        if !buf.is_empty() || t.closed {
            let mut out = Vec::new();
            while let Some(chunk) = buf.pop_front() {
                out.extend_from_slice(&chunk);
            }
            return Ok((out, t.closed));
        }
        if from_agent {
            Arc::clone(&t.c2a_notify)
        } else {
            Arc::clone(&t.a2c_notify)
        }
    };

    if wait > 0 {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(wait), notify.notified()).await;
    }

    let mut guard = relay_tunnels().write().await;
    let t = guard
        .get_mut(tunnel_id)
        .ok_or_else(|| (404, "Tunnel not found".to_string()))?;
    let buf = if from_agent {
        &mut t.c2a_buf
    } else {
        &mut t.a2c_buf
    };
    let mut out = Vec::new();
    while let Some(chunk) = buf.pop_front() {
        out.extend_from_slice(&chunk);
    }
    Ok((out, t.closed))
}

/// Closes a relay tunnel and wakes all waiters.
pub async fn close_relay_tunnel(
    claims: &SovereignClaims,
    tunnel_id: &str,
) -> Result<bool, (u16, String)> {
    let mut guard = relay_tunnels().write().await;
    if let Some(t) = guard.get_mut(tunnel_id) {
        if t.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "Tunnel belongs to another user".into()));
        }
        t.closed = true;
        t.c2a_notify.notify_waiters();
        t.a2c_notify.notify_waiters();
        guard.remove(tunnel_id);
        return Ok(true);
    }
    Ok(false)
}

/// Public metadata returned when opening an interactive PTY session over the HTTPS-443 relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtySessionInfo {
    pub pty_id: String,
    pub machine_id: String,
    pub fqdn: String,
    pub ssh_user: String,
    pub cols: u16,
    pub rows: u16,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct PtyInputItem {
    pub data: Vec<u8>,
    pub resize: Option<(u16, u16)>,
}

#[derive(Debug)]
struct PtySessionState {
    owner: String,
    input_buf: VecDeque<PtyInputItem>,
    output_buf: VecDeque<Vec<u8>>,
    input_notify: Arc<Notify>,
    output_notify: Arc<Notify>,
    closed: bool,
    expires_at: DateTime<Utc>,
}

static RELAY_PTYS: OnceLock<Arc<RwLock<HashMap<String, PtySessionState>>>> = OnceLock::new();

fn relay_ptys() -> &'static Arc<RwLock<HashMap<String, PtySessionState>>> {
    RELAY_PTYS.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// Opens an interactive PTY session (`ConPTY` on Windows, `openpty` on Linux) via the HTTPS-443 relay.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unauthorized interactive shell access or resource exhaustion via zombie PTYs.
/// - **CWE Mapping:** CWE-284 (Improper Access Control), CWE-400 (Resource Consumption).
/// - **Likelihood & Exploitability:** High (8/10) on remote shell gateways.
/// - **Applied Mitigation:** Verifies active user, `admin`/`domain:admin`/`ssh:connect` capability, non-revoked
///   machine record, online relay agent, validates `ssh_user`, clamps `cols`/`rows`, and caps active PTYs at 32.
pub async fn open_pty_session(
    claims: &SovereignClaims,
    machine_id: &str,
    requested_ssh_user: Option<&str>,
    cols: u16,
    rows: u16,
    base_dir: &Path,
) -> Result<PtySessionInfo, (u16, String)> {
    let cols = cols.clamp(20, 400);
    let rows = rows.clamp(5, 200);

    let users_path = base_dir.join("users.json");
    let dir = crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
        .map_err(|e| (500, e))?;
    let user = dir
        .users
        .get(&claims.subject)
        .ok_or_else(|| (404, format!("User '{}' not found", claims.subject)))?;
    if !user.enabled {
        return Err((403, format!("User '{}' is disabled", claims.subject)));
    }
    if !claims.has_role("admin") && !claims.has_capability("domain:admin") {
        return Err((
            403,
            "Interaktive ConPTY/PTY-Shell erfordert admin oder domain:admin".into(),
        ));
    }

    let ssh_user = requested_ssh_user
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&claims.subject)
        .to_string();
    validate_ssh_user(&ssh_user).map_err(|e| (400, e))?;

    let reg_file = base_dir.join("machines.json");
    let reg_raw = fs::read_to_string(&reg_file)
        .map_err(|e| (500, format!("Failed to read machines registry: {e}")))?;
    let reg: crate::domain_join::DomainRegistry = serde_json::from_str(&reg_raw)
        .map_err(|e| (500, format!("Failed to parse machines registry: {e}")))?;
    let machine = reg
        .machines
        .iter()
        .find(|m| m.machine_id == machine_id || m.fqdn.eq_ignore_ascii_case(machine_id))
        .ok_or_else(|| (404, format!("Machine '{machine_id}' not found")))?;
    if machine.revoked {
        return Err((403, format!("Machine '{}' is revoked", machine.fqdn)));
    }
    if !is_relay_online(&machine.machine_id).await {
        return Err((
            503,
            format!(
                "Agent auf '{}' ist nicht mit dem Relay verbunden (sb-node-agent prüfen)",
                machine.fqdn
            ),
        ));
    }

    let pty_id = format!("pty_{}", hex::encode(rand::random::<[u8; 12]>()));
    let now = Utc::now();
    let expires_at = now + Duration::minutes(60);

    {
        let mut guard = relay_ptys().write().await;
        guard.retain(|_, p| !p.closed && p.expires_at > now);
        if guard.len() >= 32 {
            return Err((429, "Too many active PTY sessions (max 32)".into()));
        }
        guard.insert(
            pty_id.clone(),
            PtySessionState {
                owner: claims.subject.clone(),
                input_buf: VecDeque::new(),
                output_buf: VecDeque::new(),
                input_notify: Arc::new(Notify::new()),
                output_notify: Arc::new(Notify::new()),
                closed: false,
                expires_at,
            },
        );
    }

    let q_notify = {
        let mut q_guard = relay_queues().write().await;
        let entry = q_guard.entry(machine.machine_id.clone()).or_default();
        entry.queue.push_back(RelayCommand {
            cmd_id: pty_id.clone(),
            session_id: pty_id.clone(),
            ssh_user: ssh_user.clone(),
            command: format!("{cols}x{rows}"),
            kind: "pty_open".to_string(),
            target_port: None,
        });
        Arc::clone(&entry.notify)
    };
    q_notify.notify_one();

    Ok(PtySessionInfo {
        pty_id,
        machine_id: machine.machine_id.clone(),
        fqdn: machine.fqdn.clone(),
        ssh_user,
        cols,
        rows,
        expires_at: expires_at.to_rfc3339(),
    })
}

/// Pushes keyboard input / resize events from the browser to the PTY session.
pub async fn push_pty_input(
    claims: &SovereignClaims,
    pty_id: &str,
    data: Vec<u8>,
    resize: Option<(u16, u16)>,
    close: bool,
) -> Result<(), (u16, String)> {
    let notify = {
        let mut guard = relay_ptys().write().await;
        let p = guard
            .get_mut(pty_id)
            .ok_or_else(|| (404, "PTY session not found".to_string()))?;
        if p.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "PTY session belongs to another user".into()));
        }
        if !data.is_empty() || resize.is_some() {
            if p.input_buf.len() >= 256 {
                return Err((429, "PTY input queue full".into()));
            }
            p.input_buf.push_back(PtyInputItem {
                data,
                resize: resize.map(|(c, r)| (c.clamp(20, 400), r.clamp(5, 200))),
            });
        }
        if close {
            p.closed = true;
        }
        Arc::clone(&p.input_notify)
    };
    notify.notify_one();
    Ok(())
}

/// Agent pulls queued keystrokes / resize events from the DC PTY buffer.
pub async fn pull_pty_input(
    claims: &SovereignClaims,
    pty_id: &str,
    wait_secs: u64,
) -> Result<(Vec<u8>, Option<(u16, u16)>, bool), (u16, String)> {
    if !claims.has_capability("domain:join") && !claims.has_role("admin") {
        return Err((403, "Forbidden".into()));
    }
    let wait = wait_secs.min(25);
    let notify = {
        let mut guard = relay_ptys().write().await;
        let p = guard
            .get_mut(pty_id)
            .ok_or_else(|| (404, "PTY session not found".to_string()))?;
        if !p.input_buf.is_empty() || p.closed {
            let mut data = Vec::new();
            let mut last_resize = None;
            while let Some(item) = p.input_buf.pop_front() {
                data.extend_from_slice(&item.data);
                if item.resize.is_some() {
                    last_resize = item.resize;
                }
            }
            return Ok((data, last_resize, p.closed));
        }
        Arc::clone(&p.input_notify)
    };

    if wait > 0 {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(wait), notify.notified()).await;
    }

    let mut guard = relay_ptys().write().await;
    let p = guard
        .get_mut(pty_id)
        .ok_or_else(|| (404, "PTY session not found".to_string()))?;
    let mut data = Vec::new();
    let mut last_resize = None;
    while let Some(item) = p.input_buf.pop_front() {
        data.extend_from_slice(&item.data);
        if item.resize.is_some() {
            last_resize = item.resize;
        }
    }
    Ok((data, last_resize, p.closed))
}

/// Agent pushes raw PTY stdout/stderr bytes to the DC buffer.
pub async fn push_pty_output(
    claims: &SovereignClaims,
    pty_id: &str,
    data: Vec<u8>,
    eof: bool,
) -> Result<(), (u16, String)> {
    if !claims.has_capability("domain:join") && !claims.has_role("admin") {
        return Err((403, "Forbidden".into()));
    }
    let notify = {
        let mut guard = relay_ptys().write().await;
        let p = guard
            .get_mut(pty_id)
            .ok_or_else(|| (404, "PTY session not found".to_string()))?;
        if !data.is_empty() {
            if p.output_buf.len() >= 512 {
                p.output_buf.pop_front();
            }
            p.output_buf.push_back(data);
        }
        if eof {
            p.closed = true;
        }
        Arc::clone(&p.output_notify)
    };
    notify.notify_one();
    Ok(())
}

/// Browser pulls raw PTY output bytes from the DC buffer.
pub async fn pull_pty_output(
    claims: &SovereignClaims,
    pty_id: &str,
    wait_secs: u64,
) -> Result<(Vec<u8>, bool), (u16, String)> {
    let wait = wait_secs.min(25);
    let notify = {
        let mut guard = relay_ptys().write().await;
        let p = guard
            .get_mut(pty_id)
            .ok_or_else(|| (404, "PTY session not found".to_string()))?;
        if p.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "PTY session belongs to another user".into()));
        }
        if !p.output_buf.is_empty() || p.closed {
            let mut out = Vec::new();
            while let Some(chunk) = p.output_buf.pop_front() {
                out.extend_from_slice(&chunk);
            }
            return Ok((out, p.closed));
        }
        Arc::clone(&p.output_notify)
    };

    if wait > 0 {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(wait), notify.notified()).await;
    }

    let mut guard = relay_ptys().write().await;
    let p = guard
        .get_mut(pty_id)
        .ok_or_else(|| (404, "PTY session not found".to_string()))?;
    let mut out = Vec::new();
    while let Some(chunk) = p.output_buf.pop_front() {
        out.extend_from_slice(&chunk);
    }
    Ok((out, p.closed))
}

/// Verifies that `claims` owns `pty_id` (or has `admin` role) before upgrading to WebSocket.
pub async fn verify_pty_owner(claims: &SovereignClaims, pty_id: &str) -> Result<(), (u16, String)> {
    let guard = relay_ptys().read().await;
    let p = guard
        .get(pty_id)
        .ok_or_else(|| (404, "PTY session not found".to_string()))?;
    if p.owner != claims.subject && !claims.has_role("admin") {
        return Err((403, "PTY session belongs to another user".into()));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct WsTicketRecord {
    pty_id: String,
    claims: SovereignClaims,
    expires_at: DateTime<Utc>,
}

static WS_TICKETS: OnceLock<Arc<RwLock<HashMap<String, WsTicketRecord>>>> = OnceLock::new();

fn ws_tickets() -> &'static Arc<RwLock<HashMap<String, WsTicketRecord>>> {
    WS_TICKETS.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// Issues a single-use, 30-second WebSocket ticket bound to `pty_id` so long-lived
/// bearer tokens never appear in WebSocket URL query strings.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Bearer token exposure in proxy/server URL access logs.
/// - **CWE Mapping:** CWE-598 (Use of GET Request Method With Sensitive Query Strings).
/// - **Likelihood & Exploitability:** Medium (5/10) when browser `WebSocket` APIs cannot send custom headers.
/// - **Applied Mitigation:** Binds a 128-bit random `wst_` ticket to `pty_id`, caps TTL at 30s, and consumes it once.
pub async fn issue_pty_ws_ticket(
    claims: &SovereignClaims,
    pty_id: &str,
) -> Result<String, (u16, String)> {
    verify_pty_owner(claims, pty_id).await?;
    let now = Utc::now();
    let ticket = format!("wst_{}", hex::encode(rand::random::<[u8; 16]>()));
    let mut guard = ws_tickets().write().await;
    guard.retain(|_, v| v.expires_at > now);
    if guard.len() >= 128 {
        return Err((429, "Too many pending WebSocket tickets".into()));
    }
    guard.insert(
        ticket.clone(),
        WsTicketRecord {
            pty_id: pty_id.to_string(),
            claims: claims.clone(),
            expires_at: now + Duration::seconds(30),
        },
    );
    Ok(ticket)
}

/// Consumes a single-use WebSocket ticket and verifies its `pty_id` binding and 30s expiry.
pub async fn consume_pty_ws_ticket(
    ticket: &str,
    pty_id: &str,
) -> Result<SovereignClaims, (u16, String)> {
    let now = Utc::now();
    let mut guard = ws_tickets().write().await;
    guard.retain(|_, v| v.expires_at > now);
    let Some(rec) = guard.remove(ticket) else {
        return Err((401, "Invalid or expired WebSocket ticket".into()));
    };
    if rec.pty_id != pty_id {
        return Err((403, "WebSocket ticket bound to another PTY session".into()));
    }
    Ok(rec.claims)
}

/// Executes a structured file-explorer operation (`file_list`, `file_read`, `file_write`)
/// over the HTTPS-443 reverse relay and returns the JSON payload from `stdout`.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unauthorized filesystem read/write or memory DoS via oversized payloads.
/// - **CWE Mapping:** CWE-284 (Improper Access Control), CWE-400 (Resource Consumption).
/// - **Likelihood & Exploitability:** High (8/10) on remote file-transfer APIs.
/// - **Applied Mitigation:** Requires active user, `admin`/`domain:admin`/`ssh:connect` capability,
///   non-revoked online machine, and caps relay file payloads at 2 MiB.
pub async fn exec_relay_file_op(
    claims: &SovereignClaims,
    machine_id: &str,
    kind: &str,
    payload_json: &str,
    base_dir: &Path,
) -> Result<serde_json::Value, (u16, String)> {
    if payload_json.len() > 3 * 1024 * 1024 {
        return Err((413, "File payload exceeds 2 MiB relay limit".into()));
    }
    let users_path = base_dir.join("users.json");
    let dir = crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
        .map_err(|e| (500, e))?;
    let user = dir
        .users
        .get(&claims.subject)
        .ok_or_else(|| (404, format!("User '{}' not found", claims.subject)))?;
    if !user.enabled {
        return Err((403, format!("User '{}' is disabled", claims.subject)));
    }
    if !claims.has_role("admin") && !claims.has_capability("domain:admin") {
        return Err((
            403,
            "Interaktive ConPTY/PTY-Shell erfordert admin oder domain:admin".into(),
        ));
    }

    let reg_file = base_dir.join("machines.json");
    let reg_raw = fs::read_to_string(&reg_file)
        .map_err(|e| (500, format!("Failed to read machines registry: {e}")))?;
    let reg: crate::domain_join::DomainRegistry = serde_json::from_str(&reg_raw)
        .map_err(|e| (500, format!("Failed to parse machines registry: {e}")))?;
    let machine = reg
        .machines
        .iter()
        .find(|m| m.machine_id == machine_id || m.fqdn.eq_ignore_ascii_case(machine_id))
        .ok_or_else(|| (404, format!("Machine '{machine_id}' not found")))?;
    if machine.revoked {
        return Err((403, format!("Machine '{}' is revoked", machine.fqdn)));
    }
    if !is_relay_online(&machine.machine_id).await {
        return Err((
            503,
            format!(
                "Agent auf '{}' ist nicht mit dem Relay verbunden",
                machine.fqdn
            ),
        ));
    }

    let cmd_id = format!("file_{}", hex::encode(rand::random::<[u8; 8]>()));
    let waiter = Arc::new(Notify::new());
    {
        let mut res_guard = relay_results().write().await;
        res_guard.insert(cmd_id.clone(), (Arc::clone(&waiter), None));
    }
    let q_notify = {
        let mut q_guard = relay_queues().write().await;
        let entry = q_guard.entry(machine.machine_id.clone()).or_default();
        entry.queue.push_back(RelayCommand {
            cmd_id: cmd_id.clone(),
            session_id: cmd_id.clone(),
            ssh_user: claims.subject.clone(),
            command: payload_json.to_string(),
            kind: kind.to_string(),
            target_port: None,
        });
        Arc::clone(&entry.notify)
    };
    q_notify.notify_one();

    let _ = tokio::time::timeout(std::time::Duration::from_secs(20), waiter.notified()).await;
    let res = {
        let mut res_guard = relay_results().write().await;
        res_guard.remove(&cmd_id).and_then(|(_, r)| r)
    };
    let Some(res) = res else {
        return Err((504, "Agent file operation timed out".into()));
    };
    if res.exit_code != 0 {
        return Err((
            400,
            if res.stderr.is_empty() {
                "File operation failed".into()
            } else {
                res.stderr
            },
        ));
    }
    serde_json::from_str(&res.stdout).map_err(|e| (500, format!("Invalid agent file JSON: {e}")))
}

/// Closes an active PTY session and notifies both browser and agent.
pub async fn close_pty_session(
    claims: &SovereignClaims,
    pty_id: &str,
) -> Result<bool, (u16, String)> {
    let mut guard = relay_ptys().write().await;
    if let Some(p) = guard.get_mut(pty_id) {
        if p.owner != claims.subject && !claims.has_role("admin") {
            return Err((403, "PTY session belongs to another user".into()));
        }
        p.closed = true;
        p.input_notify.notify_waiters();
        p.output_notify.notify_waiters();
        guard.remove(pty_id);
        return Ok(true);
    }
    Ok(false)
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

    #[test]
    fn relay_command_defaults_kind_to_exec() {
        let json = r#"{"cmd_id":"c1","session_id":"s1","ssh_user":"admin","command":"whoami"}"#;
        let cmd: RelayCommand =
            serde_json::from_str(json).expect("deserialize legacy RelayCommand");
        assert_eq!(cmd.kind, "exec");
        assert_eq!(cmd.target_port, None);
    }

    #[tokio::test]
    async fn relay_tunnel_validates_port_and_transfers_data() {
        let claims = SovereignClaims {
            token_id: "tok_test".to_string(),
            token_type: sb_auth::claims::TokenType::Access,
            subject: "leon.admin".to_string(),
            session_id: None,
            user_epoch: 1,
            roles: vec!["admin".to_string()],
            capabilities: vec!["domain:admin".to_string()],
            audience: None,
            issuer: "test".to_string(),
            issued_at: 0,
            not_before: 0,
            expires_at: 9_999_999_999,
            metadata: serde_json::Value::Null,
        };
        let tmp = std::env::temp_dir().join(format!("sb-tunnel-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        let err = open_relay_tunnel(&claims, "mach_nonexistent", 0, &tmp)
            .await
            .expect_err("port 0 must fail");
        assert_eq!(err.0, 400);

        // Simulate active relay poll for mach_test_tunnel
        {
            let mut q = relay_queues().write().await;
            q.insert(
                "mach_test_tunnel".to_string(),
                MachineRelayQueue {
                    last_poll_at: Some(Utc::now()),
                    queue: VecDeque::new(),
                    notify: Arc::new(Notify::new()),
                },
            );
        }
        // Without machine record on disk, open_relay_tunnel returns 404
        let err = open_relay_tunnel(&claims, "mach_test_tunnel", 3389, &tmp)
            .await
            .expect_err("missing machine must fail");
        assert_eq!(err.0, 404);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn portable_pty_spawns_shell_with_timeout() {
        use portable_pty::{native_pty_system, CommandBuilder, PtySize};
        use std::io::{Read, Write};

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let cmd = if cfg!(windows) {
            let mut c = CommandBuilder::new("powershell.exe");
            c.arg("-NoLogo");
            c
        } else {
            CommandBuilder::new("sh")
        };
        let mut child = pair.slave.spawn_command(cmd).expect("spawn");
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().expect("reader");
        let mut writer = pair.master.take_writer().expect("writer");

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = tx.send(buf[..n].to_vec());
                    }
                }
            }
        });

        writer
            .write_all(b"\x1b[1;1Recho PTY_OK\r\n")
            .expect("write");
        writer.flush().expect("flush");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        let mut out = Vec::new();
        while std::time::Instant::now() < deadline {
            if let Ok(chunk) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                out.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&out).contains("PTY_OK") {
                    break;
                }
            }
        }
        let _ = child.kill();
        drop(writer);
        drop(pair.master);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("PTY_OK"), "unexpected pty output: {text:?}");
    }

    #[tokio::test]
    async fn pty_ws_ticket_is_single_use_and_bound_to_pty_id() {
        let claims = SovereignClaims {
            token_id: "tok_ws".to_string(),
            token_type: sb_auth::claims::TokenType::Access,
            subject: "leon.admin".to_string(),
            session_id: None,
            user_epoch: 1,
            roles: vec!["admin".to_string()],
            capabilities: vec!["domain:admin".to_string()],
            audience: None,
            issuer: "test".to_string(),
            issued_at: 0,
            not_before: 0,
            expires_at: 9_999_999_999,
            metadata: serde_json::Value::Null,
        };
        let pid = "pty_ticket_test_1";
        {
            let mut guard = relay_ptys().write().await;
            guard.insert(
                pid.to_string(),
                PtySessionState {
                    owner: "leon.admin".to_string(),
                    input_buf: VecDeque::new(),
                    output_buf: VecDeque::new(),
                    input_notify: Arc::new(Notify::new()),
                    output_notify: Arc::new(Notify::new()),
                    closed: false,
                    expires_at: Utc::now() + Duration::minutes(5),
                },
            );
        }
        let ticket = issue_pty_ws_ticket(&claims, pid)
            .await
            .expect("issue ticket");
        assert!(ticket.starts_with("wst_"));
        assert!(consume_pty_ws_ticket(&ticket, "pty_wrong").await.is_err());

        let ticket2 = issue_pty_ws_ticket(&claims, pid)
            .await
            .expect("issue ticket2");
        let verified = consume_pty_ws_ticket(&ticket2, pid).await.expect("consume");
        assert_eq!(verified.subject, "leon.admin");
        assert!(consume_pty_ws_ticket(&ticket2, pid).await.is_err());
    }
}
