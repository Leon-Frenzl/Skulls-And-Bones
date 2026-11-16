use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use crate::directory::{AuthorityTrust, DirectorySnapshot};
use std::io::Read;

pub const MAX_DIRECTORY_SNAPSHOT_FILE_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub listen_ip: String,
    pub listen_port: u16,
    pub sovereign_suffixes: Vec<String>,
    pub enable_upstream_forwarding: bool,
    pub upstream_servers: Vec<SocketAddr>,
    pub cache_size: usize,
    pub default_ttl: u32,
    #[serde(default)]
    pub authority_trust: Vec<AuthorityTrustConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityTrustConfig {
    pub mesh_id: String,
    pub pinned_keys: HashMap<String, String>,
}

impl AuthorityTrustConfig {
    pub fn into_authority_trust(self) -> Result<AuthorityTrust, String> {
        let pinned_keys = self
            .pinned_keys
            .into_iter()
            .map(|(key_id, encoded)| {
                let public_key = decode_public_key(&encoded)
                    .map_err(|error| format!("Authority key '{key_id}': {error}"))?;
                Ok((key_id, public_key))
            })
            .collect::<Result<HashMap<_, _>, String>>()?;

        AuthorityTrust::new(self.mesh_id.clone(), pinned_keys).map_err(|error| {
            format!(
                "Invalid authority trust configuration for mesh '{}': {error}",
                self.mesh_id
            )
        })
    }
}

fn decode_public_key(encoded: &str) -> Result<[u8; 32], String> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err("Ed25519 public keys must be exactly 64 hexadecimal characters".to_string());
    }
    let mut public_key = [0u8; 32];
    for (index, byte) in public_key.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&encoded[start..start + 2], 16)
            .map_err(|_| "Ed25519 public key contains a non-hexadecimal character".to_string())?;
    }
    Ok(public_key)
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen_ip: "127.0.0.1".to_string(),
            listen_port: 58853,
            sovereign_suffixes: vec![".sbm".to_string(), ".sb".to_string(), ".mesh".to_string()],
            enable_upstream_forwarding: true,
            upstream_servers: vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()],
            cache_size: 1024,
            default_ttl: 300,
            authority_trust: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrvRecordConfig {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordsConfig {
    #[serde(default)]
    pub a: HashMap<String, Ipv4Addr>,
    #[serde(default)]
    pub aaaa: HashMap<String, Ipv6Addr>,
    #[serde(default)]
    pub cname: HashMap<String, String>,
    #[serde(default)]
    pub txt: HashMap<String, String>,
    #[serde(default)]
    pub srv: HashMap<String, Vec<SrvRecordConfig>>,
}

pub struct ConfigManager;

impl ConfigManager {
    pub fn config_path() -> PathBuf {
        let dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".sb")
            .join("dns");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("config.json")
    }

    pub fn records_path() -> PathBuf {
        let dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".sb")
            .join("dns");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("records.json")
    }

    pub fn directory_snapshots_path() -> PathBuf {
        Self::config_path().with_file_name("directory-snapshots.json")
    }

    pub fn load_config() -> DnsConfig {
        let p = Self::config_path();
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(&p) {
                if let Ok(cfg) = serde_json::from_str(&content) {
                    return cfg;
                }
            }
        }
        let cfg = DnsConfig::default();
        if let Ok(content) = serde_json::to_string_pretty(&cfg) {
            let _ = std::fs::write(&p, content);
        }
        cfg
    }

    pub fn load_config_checked() -> Result<DnsConfig, String> {
        let path = Self::config_path();
        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content)
                .map_err(|error| format!("Invalid DNS configuration at {path:?}: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let config = DnsConfig::default();
                let content = serde_json::to_string_pretty(&config).map_err(|error| {
                    format!("Failed to serialize default DNS configuration: {error}")
                })?;
                std::fs::write(&path, content).map_err(|error| {
                    format!("Failed to create DNS configuration at {path:?}: {error}")
                })?;
                Ok(config)
            }
            Err(error) => Err(format!(
                "Failed to read DNS configuration at {path:?}: {error}"
            )),
        }
    }

    pub fn load_directory_snapshots_checked() -> Result<Vec<DirectorySnapshot>, String> {
        let path = Self::directory_snapshots_path();
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(format!(
                    "Failed to open directory snapshots at {path:?}: {error}"
                ))
            }
        };
        let mut content = Vec::new();
        file.by_ref()
            .take(MAX_DIRECTORY_SNAPSHOT_FILE_SIZE + 1)
            .read_to_end(&mut content)
            .map_err(|error| format!("Failed to read directory snapshots at {path:?}: {error}"))?;
        parse_directory_snapshots(&path, &content)
    }

    pub fn load_records() -> RecordsConfig {
        let p = Self::records_path();
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(&p) {
                if let Ok(rec) = serde_json::from_str(&content) {
                    return rec;
                }
            }
        }
        let mut rec = RecordsConfig::default();
        rec.a
            .insert("gateway.sbm".to_string(), Ipv4Addr::new(10, 240, 0, 1));
        rec.a
            .insert("mesh.sbm".to_string(), Ipv4Addr::new(127, 0, 0, 1));
        let _ = Self::save_records(&rec);
        rec
    }

    pub fn save_records(records: &RecordsConfig) -> Result<(), String> {
        let p = Self::records_path();
        let content = serde_json::to_string_pretty(records)
            .map_err(|e| format!("Fehler beim Serialisieren der DNS-Records: {}", e))?;
        std::fs::write(&p, content).map_err(|e| format!("Fehler beim Schreiben von {:?}: {}", p, e))
    }

    pub fn add_a_record(domain: &str, ip: Ipv4Addr) -> Result<(), String> {
        let mut records = Self::load_records();
        let clean = domain.to_lowercase().trim_end_matches('.').to_string();
        records.a.insert(clean, ip);
        Self::save_records(&records)
    }

    /// Registers or updates an RFC 2782 SRV record (e.g. `_dc._tcp.corp.eu -> 10 0 8443 dc.corp.eu`).
    pub fn add_srv_record(
        domain: &str,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
    ) -> Result<(), String> {
        let mut records = Self::load_records();
        let clean = domain.to_lowercase().trim_end_matches('.').to_string();
        let clean_target = target.to_lowercase().trim_end_matches('.').to_string();
        let entry = SrvRecordConfig {
            priority,
            weight,
            port,
            target: clean_target.clone(),
        };
        let list = records.srv.entry(clean).or_default();
        list.retain(|existing| !(existing.target == clean_target && existing.port == port));
        list.push(entry);
        Self::save_records(&records)
    }

    pub fn add_cname_record(domain: &str, target: &str) -> Result<(), String> {
        let mut records = Self::load_records();
        let clean = domain.to_lowercase().trim_end_matches('.').to_string();
        let clean_target = target.to_lowercase().trim_end_matches('.').to_string();
        records.cname.insert(clean, clean_target);
        Self::save_records(&records)
    }

    pub fn add_txt_record(domain: &str, text: &str) -> Result<(), String> {
        if text.len() > 255 {
            return Err("TXT record value exceeds 255-byte single-string limit".to_string());
        }
        let mut records = Self::load_records();
        let clean = domain.to_lowercase().trim_end_matches('.').to_string();
        records.txt.insert(clean, text.to_string());
        Self::save_records(&records)
    }

    pub fn remove_record(domain: &str) -> Result<bool, String> {
        let mut records = Self::load_records();
        let clean = domain.to_lowercase().trim_end_matches('.').to_string();
        let mut removed = false;
        if records.a.remove(&clean).is_some() {
            removed = true;
        }
        if records.aaaa.remove(&clean).is_some() {
            removed = true;
        }
        if records.cname.remove(&clean).is_some() {
            removed = true;
        }
        if records.txt.remove(&clean).is_some() {
            removed = true;
        }
        if records.srv.remove(&clean).is_some() {
            removed = true;
        }
        if removed {
            Self::save_records(&records)?;
        }
        Ok(removed)
    }
}

fn parse_directory_snapshots(
    path: &std::path::Path,
    content: &[u8],
) -> Result<Vec<DirectorySnapshot>, String> {
    // CVE-Threat: Memory exhaustion from a hostile or corrupted snapshot file.
    // Analysis: JSON parsing allocates according to input size before signature checks run.
    // Hardening: Reject files above a fixed cap before deserializing any snapshot objects.
    if content.len() as u64 > MAX_DIRECTORY_SNAPSHOT_FILE_SIZE {
        return Err(format!(
            "Directory snapshot file at {path:?} exceeds the {}-byte limit",
            MAX_DIRECTORY_SNAPSHOT_FILE_SIZE
        ));
    }
    serde_json::from_slice(content)
        .map_err(|error| format!("Invalid directory snapshot file at {path:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pinned_ed25519_authority_keys_from_dns_config() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let public_key = signing_key
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let config: DnsConfig = serde_json::from_value(serde_json::json!({
            "authority_trust": [{
                "mesh_id": "mesh-dev-01",
                "pinned_keys": { "auth-1": public_key }
            }]
        }))
        .unwrap();
        let trust = config.authority_trust.into_iter().next().unwrap();
        let authority = trust.into_authority_trust().unwrap();
        assert_eq!(authority.mesh_id(), "mesh-dev-01");
    }

    #[test]
    fn rejects_malformed_authority_public_keys() {
        let config: DnsConfig = serde_json::from_value(serde_json::json!({
            "authority_trust": [{
                "mesh_id": "mesh-dev-01",
                "pinned_keys": { "auth-1": "not-a-public-key" }
            }]
        }))
        .unwrap();
        let error = config
            .authority_trust
            .into_iter()
            .next()
            .unwrap()
            .into_authority_trust()
            .unwrap_err();
        assert!(error.contains("64 hexadecimal characters"));
    }

    #[test]
    fn rejects_snapshot_files_larger_than_the_configured_limit() {
        let oversized = vec![b' '; MAX_DIRECTORY_SNAPSHOT_FILE_SIZE as usize + 1];
        let error = parse_directory_snapshots(std::path::Path::new("snapshots.json"), &oversized)
            .unwrap_err();
        assert!(error.contains("exceeds the"));
    }
}
