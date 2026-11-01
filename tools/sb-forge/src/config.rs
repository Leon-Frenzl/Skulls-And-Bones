//! Forge configuration paths and unified S&B PKI / NetGate session integration
//!
//! Standards Compliance:
//! - Conforms to IEEE 1003.1 (POSIX.1-2017) directory resolution
//! - Conforms to IETF RFC 4251 (OpenSSH CA hierarchy) and IETF RFC 8259 (JSON)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Returns the Forge state directory (`~/.sb-forge/`).
pub fn get_forge_dir() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sb-forge");
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
    }
    dir
}

/// Returns the canonical Sovereign SSH directory (`~/.sb/ssh/`) via `sb_core::paths`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Legacy `~/.sb-ssh` path resolution loading stale or unverified session/CA state.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Strictly delegates to `sb_core::paths::sb_ssh_dir()` (`~/.sb/ssh`) without `~/.sb-ssh` fallback.
/// - Standards Compliance: Conforms to IEEE 1003.1 (POSIX.1-2017).
pub fn get_sb_ssh_dir() -> PathBuf {
    sb_core::paths::sb_ssh_dir()
}

/// Returns the canonical unified OpenSSH CA directory (`~/.sb/ca/ssh/`) via `sb_core::paths`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Split-brain CA resolution between Forge deployments and `sb-ca`.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path), CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Strictly resolves `~/.sb/ca/ssh` via `sb_core::paths::sb_ca_ssh_dir()`.
/// - Standards Compliance: Conforms to IETF RFC 4251 and OpenSSH PROTOCOL.certkeys.
pub fn get_sb_ca_ssh_dir() -> PathBuf {
    sb_core::paths::sb_ca_ssh_dir()
}

/// Checks whether the unified `sb-ca` OpenSSH CA keypair is initialized in `~/.sb/ca/ssh/`.
pub fn is_ssh_ca_initialized() -> bool {
    sb_core::paths::sb_ca_ssh_key_path().exists() && sb_core::paths::sb_ca_ssh_pub_path().exists()
}

// ── S&B NETGATE (sb-ssh) & UNIFIED IDENTITY INTEGRATION ─────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbSshSession {
    pub username: String,
    pub email: Option<String>,
    pub provider: String,
    pub access_token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl SbSshSession {
    pub fn is_valid(&self) -> bool {
        chrono::Utc::now() < self.expires_at
    }
}

pub fn load_sb_ssh_session() -> Option<SbSshSession> {
    let session_path = get_sb_ssh_dir().join("session.json");
    if session_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&session_path) {
            if let Ok(sess) = serde_json::from_str::<SbSshSession>(&content) {
                if sess.is_valid() {
                    return Some(sess);
                }
            }
        }
    }
    None
}

/// Resolves the active operator identity from unified `~/.sb/ssh/session.json`, `~/.sb/identity.json`, or OS environment.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Unattributed secret mutations or pipeline runs in audit logs.
/// - CVE / CWE Mapping: CWE-778 (Insufficient Logging).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Queries validated session token first, then canonical `~/.sb/identity.json` callsign, then OS user.
/// - Standards Compliance: Conforms to IETF RFC 8259 (JSON).
pub fn get_current_identity() -> String {
    if let Some(session) = load_sb_ssh_session() {
        return format!("{} ({})", session.username, session.provider);
    }
    let id_file = sb_core::paths::sb_home().join("identity.json");
    if id_file.exists() {
        if let Ok(raw) = std::fs::read_to_string(&id_file) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(callsign) = val.get("callsign").and_then(|v| v.as_str()) {
                    if !callsign.trim().is_empty() {
                        return callsign.trim().to_string();
                    }
                }
            }
        }
    }
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "operator".to_string())
}

// ── FORGE SESSION (AKTIVES ENVIRONMENT) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeSession {
    pub active_env: String,
    pub activated_at: chrono::DateTime<chrono::Utc>,
    pub activated_by: String,
}

pub fn load_forge_session() -> Option<ForgeSession> {
    let session_path = get_forge_dir().join("session.toml");
    if session_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&session_path) {
            return toml::from_str::<ForgeSession>(&content).ok();
        }
    }
    None
}

pub fn save_forge_session(session: &ForgeSession) -> std::io::Result<()> {
    let session_path = get_forge_dir().join("session.toml");
    let content = toml::to_string_pretty(session).unwrap_or_default();
    std::fs::write(session_path, content)
}

pub fn get_active_env() -> String {
    load_forge_session()
        .map(|s| s.active_env)
        .unwrap_or_else(|| "dev".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_unified_ssh_and_ca_paths() {
        let ssh_dir = get_sb_ssh_dir();
        let ca_ssh_dir = get_sb_ca_ssh_dir();
        assert!(
            !ssh_dir.to_string_lossy().contains(".sb-ssh"),
            "Must not fall back to legacy ~/.sb-ssh"
        );
        assert!(ssh_dir.ends_with("ssh"));
        assert!(ca_ssh_dir.ends_with("ssh"));
        assert!(ca_ssh_dir.to_string_lossy().contains("ca"));
    }
}
