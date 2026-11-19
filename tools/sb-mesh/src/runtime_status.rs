use crate::peer::{PeerStatus, PeerTable};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RUNTIME_STATUS_SCHEMA_VERSION: u16 = 1;
pub const RUNTIME_STATUS_FILE: &str = "runtime-status.json";
pub const RUNTIME_STATUS_MAX_AGE_SECS: u64 = 5;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRuntimeNetwork {
    pub name: String,
    pub description: String,
    pub subnet: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRuntimePeer {
    pub node_id: String,
    pub callsign: String,
    pub overlay_ip: Option<String>,
    pub status: PeerStatus,
    pub ping_ms: Option<u32>,
    pub last_handshake_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRuntimeStatus {
    pub schema_version: u16,
    pub process_id: u32,
    pub started_at_unix: u64,
    pub heartbeat_unix: u64,
    pub mesh_name: String,
    pub description: String,
    pub overlay_subnet: String,
    pub swarm_topic: String,
    pub local_node_id: String,
    pub local_public_key: String,
    pub listen_port: u16,
    pub air_gap_killswitch: bool,
    pub protocol: String,
    pub peers: Vec<MeshRuntimePeer>,
    pub available_networks: Vec<MeshRuntimeNetwork>,
}

impl MeshRuntimeStatus {
    pub fn now_unix() -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|error| format!("System clock is before Unix epoch: {error}"))
    }

    pub fn is_fresh_at(&self, now_unix: u64) -> bool {
        self.schema_version == RUNTIME_STATUS_SCHEMA_VERSION
            && self.heartbeat_unix <= now_unix
            && now_unix - self.heartbeat_unix <= RUNTIME_STATUS_MAX_AGE_SECS
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_live_state(
        mesh_name: String,
        description: String,
        overlay_subnet: String,
        swarm_topic: String,
        local_node_id: String,
        local_public_key: String,
        listen_port: u16,
        air_gap_killswitch: bool,
        started_at_unix: u64,
        peers: &PeerTable,
        available_networks: Vec<MeshRuntimeNetwork>,
    ) -> Result<Self, String> {
        let now = Self::now_unix()?;
        let mut runtime_peers = peers
            .list()
            .into_iter()
            .map(|peer| MeshRuntimePeer {
                node_id: peer.config.node_id.clone(),
                callsign: peer.config.callsign.clone(),
                overlay_ip: peer.config.overlay_ip.clone(),
                status: peer.status,
                ping_ms: peer.rtt_ms.and_then(|rtt| {
                    (rtt.is_finite() && rtt >= 0.0 && rtt <= u32::MAX as f64)
                        .then_some(rtt.round() as u32)
                }),
                last_handshake_unix: peer
                    .last_handshake
                    .and_then(|timestamp| u64::try_from(timestamp.timestamp()).ok()),
            })
            .collect::<Vec<_>>();
        runtime_peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));

        Ok(Self {
            schema_version: RUNTIME_STATUS_SCHEMA_VERSION,
            process_id: std::process::id(),
            started_at_unix,
            heartbeat_unix: now,
            mesh_name,
            description,
            overlay_subnet,
            swarm_topic,
            local_node_id,
            local_public_key,
            listen_port,
            air_gap_killswitch,
            protocol: "sb-mesh-experimental-v2".into(),
            peers: runtime_peers,
            available_networks,
        })
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create runtime status directory {:?}: {error}",
                parent
            )
        })?;
        let serialized = serde_json::to_vec(self)
            .map_err(|error| format!("Failed to serialize mesh runtime status: {error}"))?;
        let temporary_path = temporary_path(path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| {
                format!(
                    "Failed to create temporary mesh runtime status {:?}: {error}",
                    temporary_path
                )
            })?;
        if let Err(error) = file.write_all(&serialized).and_then(|()| file.sync_all()) {
            drop(file);
            return Err(cleanup_temp(&temporary_path, error.to_string()));
        }
        drop(file);

        if let Err(error) = replace_file(&temporary_path, path) {
            return Err(cleanup_temp(
                &temporary_path,
                format!("Failed to replace mesh runtime status {:?}: {error}", path),
            ));
        }
        Ok(())
    }

    pub fn load_fresh(path: &Path) -> Result<Self, String> {
        let metadata = fs::metadata(path)
            .map_err(|error| format!("Mesh runtime status unavailable at {:?}: {error}", path))?;
        if metadata.len() > 1024 * 1024 {
            return Err("Mesh runtime status exceeds the 1 MiB limit".into());
        }
        let serialized = fs::read(path)
            .map_err(|error| format!("Failed to read mesh runtime status {:?}: {error}", path))?;
        let status: Self = serde_json::from_slice(&serialized)
            .map_err(|error| format!("Invalid mesh runtime status {:?}: {error}", path))?;
        status.validate()?;
        let now = Self::now_unix()?;
        if !status.is_fresh_at(now) {
            return Err("Mesh runtime status is stale".into());
        }
        Ok(status)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != RUNTIME_STATUS_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported mesh runtime status schema {}",
                self.schema_version
            ));
        }
        if self.process_id == 0 || self.started_at_unix == 0 || self.heartbeat_unix == 0 {
            return Err("Mesh runtime status contains invalid process timestamps".into());
        }
        if self.mesh_name.trim().is_empty()
            || self.local_node_id.trim().is_empty()
            || self.local_public_key.trim().is_empty()
            || self.listen_port == 0
        {
            return Err("Mesh runtime status is missing node or network identity".into());
        }
        if self.peers.iter().any(|peer| {
            peer.node_id.trim().is_empty()
                || peer.callsign.trim().is_empty()
                || peer.ping_ms.is_some_and(|ping| ping == u32::MAX)
        }) {
            return Err("Mesh runtime status contains invalid peer fields".into());
        }
        Ok(())
    }
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = path
        .file_name()
        .ok_or_else(|| format!("Runtime status path {:?} has no file name", path))?;
    Ok(parent.join(format!(
        ".{}.{}.{}.tmp",
        filename.to_string_lossy(),
        std::process::id(),
        TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )))
}

fn replace_file(temporary_path: &Path, destination: &Path) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(temporary_path, destination)
}

fn cleanup_temp(path: &Path, message: String) -> String {
    match fs::remove_file(path) {
        Ok(()) => message,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => message,
        Err(error) => format!(
            "{message}; failed to clean temporary file {:?}: {error}",
            path
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sb-mesh-runtime-status-{}-{nonce}.json",
            std::process::id()
        ))
    }

    fn runtime_status() -> MeshRuntimeStatus {
        let mut table = PeerTable::new();
        table.add_peer(PeerConfig {
            callsign: "replica".into(),
            node_id: "node-replica".into(),
            public_key_base64: "cHVibGljLWtleQ==".into(),
            endpoint: None,
            overlay_ip: Some("10.42.0.2".into()),
            created_at: chrono::Utc::now(),
        });
        MeshRuntimeStatus::from_live_state(
            "engineering".into(),
            "Engineering mesh".into(),
            "10.42.0.0/16".into(),
            "sbm-engineering".into(),
            "node-local".into(),
            "cHVibGljLWtleQ==".into(),
            58888,
            false,
            MeshRuntimeStatus::now_unix().unwrap(),
            &table,
            vec![MeshRuntimeNetwork {
                name: "engineering".into(),
                description: "Engineering mesh".into(),
                subnet: "10.42.0.0/16".into(),
                is_active: true,
            }],
        )
        .unwrap()
    }

    #[test]
    fn live_status_round_trips_with_real_peer_runtime_fields() {
        let path = test_path();
        let status = runtime_status();
        status.write_atomic(&path).unwrap();
        let loaded = MeshRuntimeStatus::load_fresh(&path).unwrap();
        assert_eq!(loaded, status);
        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0].status, PeerStatus::Disconnected);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn stale_or_wrong_schema_status_is_rejected() {
        let path = test_path();
        let mut status = runtime_status();
        status.heartbeat_unix = 1;
        status.write_atomic(&path).unwrap();
        assert!(MeshRuntimeStatus::load_fresh(&path)
            .unwrap_err()
            .contains("stale"));

        status.heartbeat_unix = MeshRuntimeStatus::now_unix().unwrap();
        status.schema_version += 1;
        assert!(status.write_atomic(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
