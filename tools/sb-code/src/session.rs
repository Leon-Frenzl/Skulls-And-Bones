use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerRole {
    Host,
    Collaborator,
    Observer,
}

impl std::fmt::Display for PeerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerRole::Host => write!(f, "Host / Driver"),
            PeerRole::Collaborator => write!(f, "Collaborator"),
            PeerRole::Observer => write!(f, "Observer (Read-Only)"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub callsign: String,
    pub node_id: String,
    pub role: PeerRole,
    pub active_scope: Option<String>,
    pub ping_ms: u32,
    pub is_self: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeSession {
    pub session_id: String,
    pub session_name: String,
    pub host_callsign: String,
    pub is_host: bool,
    pub self_callsign: String,
    pub peers: Vec<PeerInfo>,
    pub active_lease_ttl_secs: i64,
}

impl CodeSession {
    pub fn new_host(session_name: &str, self_callsign: &str) -> Self {
        let session_id = uuid::Uuid::new_v4().to_string();
        let host_peer = PeerInfo {
            callsign: self_callsign.to_string(),
            node_id: format!("node-{}", &session_id[..8]),
            role: PeerRole::Host,
            active_scope: Some("src/main.rs::main".to_string()),
            ping_ms: 0,
            is_self: true,
        };

        Self {
            session_id,
            session_name: session_name.to_string(),
            host_callsign: self_callsign.to_string(),
            is_host: true,
            self_callsign: self_callsign.to_string(),
            peers: vec![host_peer],
            active_lease_ttl_secs: get_active_lease_ttl().unwrap_or(28800),
        }
    }

    pub fn join(session_name: &str, self_callsign: &str, host_callsign: &str) -> Self {
        let session_id = uuid::Uuid::new_v4().to_string();

        let host_peer = PeerInfo {
            callsign: host_callsign.to_string(),
            node_id: "node-host".to_string(),
            role: PeerRole::Host,
            active_scope: Some("src/main.rs::main".to_string()),
            ping_ms: 12,
            is_self: false,
        };

        let self_peer = PeerInfo {
            callsign: self_callsign.to_string(),
            node_id: format!("node-{}", &session_id[..8]),
            role: PeerRole::Collaborator,
            active_scope: Some("src/main.rs::main".to_string()),
            ping_ms: 0,
            is_self: true,
        };

        Self {
            session_id,
            session_name: session_name.to_string(),
            host_callsign: host_callsign.to_string(),
            is_host: false,
            self_callsign: self_callsign.to_string(),
            peers: vec![host_peer, self_peer],
            active_lease_ttl_secs: get_active_lease_ttl().unwrap_or(28800),
        }
    }

    pub fn update_scope(&mut self, callsign: &str, scope_id: &str) {
        if let Some(peer) = self.peers.iter_mut().find(|p| p.callsign == callsign) {
            peer.active_scope = Some(scope_id.to_string());
        }
    }

    pub fn formatted_lease_ttl(&self) -> String {
        let hours = self.active_lease_ttl_secs / 3600;
        let mins = (self.active_lease_ttl_secs % 3600) / 60;
        format!("{:02}h {:02}m", hours, mins)
    }
}

pub fn get_active_lease_ttl() -> Option<i64> {
    let lease_path = dirs::home_dir()?.join(".sb").join("lease.json");
    if !lease_path.exists() {
        return None;
    }
    let content = fs::read_to_string(lease_path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&content).ok()?;
    let expires_at_str = val.get("expires_at")?.as_str()?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at_str).ok()?;
    let now = chrono::Utc::now();
    let diff = expires_at.signed_duration_since(now).num_seconds();
    Some(diff.max(0))
}

pub fn get_active_callsign() -> String {
    if let Ok(val) = std::env::var("SB_CALLSIGN").or_else(|_| std::env::var("SB_AUTHOR")) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(home) = dirs::home_dir() {
        let id_path = home.join(".sb").join("identity.json");
        if id_path.exists() {
            if let Ok(c) = fs::read_to_string(id_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&c) {
                    if let Some(callsign) = v.get("callsign").and_then(|cs| cs.as_str()) {
                        let trimmed = callsign.trim();
                        if !trimmed.is_empty() {
                            return trimmed.to_string();
                        }
                    }
                }
            }
        }
    }
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "sentinel-prime".to_string())
}

/// Ermittelt den kryptographischen Ed25519-Signierschlüssel für den lokalen Benutzer.
/// Prioritätsreihenfolge:
/// 1. Umgebungsvariable `SB_SIGNING_KEY` (32 Bytes Hex oder Pfad zu Key-Datei)
/// 2. `~/.sb/identity.sbkey` (Wurzelanker von sb-key; deterministisch abgeleiteter VCS-Subkey)
/// 3. `~/.sb/code_signer.key` (dedizierter lokaler Ed25519-Seed für sb-code)
/// 4. Neu erzeugter persistenter Schlüssel in `~/.sb/code_signer.key`
pub fn get_active_signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    use base64::Engine;

    // 1. Umgebungsvariable SB_SIGNING_KEY
    if let Ok(env_key) = std::env::var("SB_SIGNING_KEY") {
        let trimmed = env_key.trim();
        if trimmed.len() == 64 {
            if let Ok(bytes) = hex::decode(trimmed) {
                if bytes.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&bytes);
                    return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
                }
            }
        }
        let p = std::path::PathBuf::from(trimmed);
        if p.exists() {
            if let Ok(content) = fs::read(&p) {
                if content.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&content);
                    return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
                } else if content.len() == 64 {
                    if let Ok(decoded) = hex::decode(&content) {
                        if decoded.len() == 32 {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&decoded);
                            return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
                        }
                    }
                }
            }
        }
    }

    let home =
        dirs::home_dir().ok_or_else(|| "Konnte Home-Verzeichnis nicht ermitteln".to_string())?;
    let sb_dir = home.join(".sb");

    // 2. ~/.sb/identity.sbkey (aus sb-key)
    let sbkey_path = sb_dir.join("identity.sbkey");
    if sbkey_path.exists() {
        if let Ok(content) = fs::read_to_string(&sbkey_path) {
            for line in content.lines() {
                if let Some(payload) = line.strip_prefix("Payload:") {
                    if let Ok(raw_seed) =
                        base64::engine::general_purpose::STANDARD.decode(payload.trim())
                    {
                        if raw_seed.len() == 32 {
                            let mut hasher =
                                blake3::Hasher::new_keyed(b"sb-code-commit-signer-v1________");
                            hasher.update(&raw_seed);
                            let subkey = hasher.finalize();
                            return Ok(ed25519_dalek::SigningKey::from_bytes(subkey.as_bytes()));
                        }
                    }
                }
            }
        }
    }

    // 3. ~/.sb/code_signer.key
    let signer_key_path = sb_dir.join("code_signer.key");
    if signer_key_path.exists() {
        if let Ok(bytes) = fs::read(&signer_key_path) {
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
            } else if bytes.len() == 64 {
                if let Ok(decoded) = hex::decode(&bytes) {
                    if decoded.len() == 32 {
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&decoded);
                        return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
                    }
                }
            }
        }
    }

    // 4. Neu generieren und in ~/.sb/code_signer.key sichern
    let _ = fs::create_dir_all(&sb_dir);
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut seed);
    let _ = fs::write(&signer_key_path, &seed);
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_resolution_and_env_override() {
        let test_seed = [42u8; 32];
        let hex_seed = hex::encode(test_seed);
        std::env::set_var("SB_SIGNING_KEY", &hex_seed);

        let key = get_active_signing_key().expect("Should resolve from env");
        assert_eq!(key.to_bytes(), test_seed);

        std::env::remove_var("SB_SIGNING_KEY");
    }
}
