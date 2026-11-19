use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use crate::crypto::SessionKeys;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Connected,
    HandshakeInProgress,
    Standby,
    Disconnected,
}

impl PeerStatus {
    pub fn badge_text(&self) -> &'static str {
        match self {
            PeerStatus::Connected => "ONLINE",
            PeerStatus::HandshakeInProgress => "HANDSHAKE",
            PeerStatus::Standby => "STANDBY",
            PeerStatus::Disconnected => "OFFLINE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathType {
    DirectIPv4(SocketAddr),
    DirectIPv6(SocketAddr),
    Relay(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePath {
    pub path_type: PathType,
    pub rtt_ms: Option<f64>,
    pub last_success: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
    pub is_active: bool,
}

impl CandidatePath {
    pub fn new(path_type: PathType) -> Self {
        Self {
            path_type,
            rtt_ms: None,
            last_success: None,
            consecutive_failures: 0,
            is_active: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub callsign: String,
    pub node_id: String,
    pub public_key_base64: String,
    pub endpoint: Option<String>,
    pub overlay_ip: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl PeerConfig {
    pub fn new(callsign: &str, public_key_base64: &str, endpoint: &str) -> Self {
        Self {
            callsign: callsign.to_string(),
            node_id: format!(
                "sbm-{}",
                &public_key_base64[..8.min(public_key_base64.len())]
            ),
            public_key_base64: public_key_base64.to_string(),
            endpoint: Some(endpoint.to_string()),
            overlay_ip: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerState {
    pub config: PeerConfig,
    pub parsed_endpoint: Option<SocketAddr>,
    pub status: PeerStatus,
    pub rtt_ms: Option<f64>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub last_handshake: Option<DateTime<Utc>>,
    pub last_ping_sent: Option<DateTime<Utc>>,
    pub sequence_counter: u64,
    pub zk_attested: bool,
    pub zk_verified_at: Option<DateTime<Utc>>,
    pub roaming_events: u64,
    // Phase 14: In-Band Rekeying & PFS Ratchet
    pub session_keys: Option<SessionKeys>,
    pub session_epoch: u64,
    pub last_rekey: Option<DateTime<Utc>>,
    pub rekey_count: u64,
    pub pending_ephemeral_secret: Option<[u8; 32]>,
    // Phase 15: Multi-Path Fast Failover
    pub candidate_paths: Vec<CandidatePath>,
    // Phase 20: Adaptive Power-Saving Keepalive
    pub heartbeat_mode: HeartbeatMode,
    pub last_data_activity: Option<DateTime<Utc>>,
    // Anti-replay sliding window filter
    pub anti_replay: crate::anti_replay::AntiReplayWindow,
}

/// Sleep-Aware Adaptive Heartbeat Mode for Battery & Bandwidth Conservation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeartbeatMode {
    /// High-activity mode (<30s since last traffic): fast 2s keepalive
    Active,
    /// Moderate-idle mode (30s - 120s since last traffic): standard 25s keepalive
    Idle,
    /// Sleep-aware battery-saver mode (>120s since last traffic): 120s backoff keepalive
    PowerSave,
}

impl HeartbeatMode {
    pub fn interval(&self) -> std::time::Duration {
        match self {
            HeartbeatMode::Active => std::time::Duration::from_secs(2),
            HeartbeatMode::Idle => std::time::Duration::from_secs(25),
            HeartbeatMode::PowerSave => std::time::Duration::from_secs(120),
        }
    }
}

impl PeerState {
    pub fn new(config: PeerConfig) -> Self {
        let parsed_endpoint: Option<SocketAddr> =
            config.endpoint.as_deref().and_then(|ep| ep.parse().ok());
        let mut candidate_paths = Vec::new();
        if let Some(ep) = parsed_endpoint {
            let ptype = if ep.is_ipv6() {
                PathType::DirectIPv6(ep)
            } else {
                PathType::DirectIPv4(ep)
            };
            let mut cp = CandidatePath::new(ptype);
            cp.is_active = true;
            candidate_paths.push(cp);
        }

        Self {
            config,
            parsed_endpoint,
            status: PeerStatus::Disconnected,
            rtt_ms: None,
            bytes_sent: 0,
            bytes_recv: 0,
            last_handshake: None,
            last_ping_sent: None,
            sequence_counter: 0,
            zk_attested: false,
            zk_verified_at: None,
            roaming_events: 0,
            session_keys: None,
            session_epoch: 0,
            last_rekey: None,
            rekey_count: 0,
            pending_ephemeral_secret: None,
            candidate_paths,
            heartbeat_mode: HeartbeatMode::Idle,
            last_data_activity: None,
            anti_replay: crate::anti_replay::AntiReplayWindow::new(),
        }
    }

    /// Record packet/data activity, waking the peer and resetting heartbeat mode to Active
    pub fn record_data_activity(&mut self) {
        self.last_data_activity = Some(Utc::now());
        self.heartbeat_mode = HeartbeatMode::Active;
    }

    /// Evaluates current idle duration and updates heartbeat mode accordingly
    pub fn update_heartbeat_mode(&mut self, now: DateTime<Utc>) -> HeartbeatMode {
        if let Some(last_activity) = self.last_data_activity {
            let elapsed_secs = (now - last_activity).num_seconds();
            if elapsed_secs < 30 {
                self.heartbeat_mode = HeartbeatMode::Active;
            } else if elapsed_secs < 120 {
                self.heartbeat_mode = HeartbeatMode::Idle;
            } else {
                self.heartbeat_mode = HeartbeatMode::PowerSave;
            }
        } else {
            self.heartbeat_mode = HeartbeatMode::Idle;
        }
        self.heartbeat_mode
    }

    /// Checks if a heartbeat ping is due based on adaptive interval
    pub fn is_heartbeat_due(&mut self, now: DateTime<Utc>) -> bool {
        self.update_heartbeat_mode(now);
        let interval = chrono::Duration::from_std(self.heartbeat_mode.interval())
            .unwrap_or(chrono::Duration::seconds(25));
        if let Some(last_ping) = self.last_ping_sent {
            now - last_ping >= interval
        } else {
            true
        }
    }

    /// Add or update candidate network path
    pub fn add_or_update_path(&mut self, path_type: PathType) {
        if !self
            .candidate_paths
            .iter()
            .any(|p| p.path_type == path_type)
        {
            let mut cp = CandidatePath::new(path_type);
            if self.candidate_paths.is_empty() {
                cp.is_active = true;
            }
            self.candidate_paths.push(cp);
        }
    }

    /// Record success on a candidate path, updating RTT and resetting failures
    pub fn record_path_success(&mut self, path_type: &PathType, rtt: f64) {
        for path in &mut self.candidate_paths {
            if &path.path_type == path_type {
                path.rtt_ms = Some(rtt);
                path.last_success = Some(Utc::now());
                path.consecutive_failures = 0;
            }
        }
    }

    /// Record failure on a candidate path; triggers fast failover if threshold reached
    pub fn record_path_failure(&mut self, path_type: &PathType, failure_threshold: u32) -> bool {
        let mut failed_active = false;
        for path in &mut self.candidate_paths {
            if &path.path_type == path_type {
                path.consecutive_failures += 1;
                if path.is_active && path.consecutive_failures >= failure_threshold {
                    path.is_active = false;
                    failed_active = true;
                }
            }
        }
        if failed_active {
            self.failover_to_best_path();
            true
        } else {
            false
        }
    }

    /// Selects the best candidate path (lowest latency, fewest failures) as active
    pub fn failover_to_best_path(&mut self) -> Option<PathType> {
        for p in &mut self.candidate_paths {
            p.is_active = false;
        }

        if let Some(best) = self.candidate_paths.iter_mut().min_by(|a, b| {
            let score_a = a.consecutive_failures as f64 * 1000.0 + a.rtt_ms.unwrap_or(500.0);
            let score_b = b.consecutive_failures as f64 * 1000.0 + b.rtt_ms.unwrap_or(500.0);
            score_a
                .partial_cmp(&score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        }) {
            best.is_active = true;
            match &best.path_type {
                PathType::DirectIPv4(addr) | PathType::DirectIPv6(addr) => {
                    self.parsed_endpoint = Some(*addr);
                }
                PathType::Relay(_) => {}
            }
            Some(best.path_type.clone())
        } else {
            None
        }
    }

    pub fn active_path(&self) -> Option<&CandidatePath> {
        self.candidate_paths.iter().find(|p| p.is_active)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeersFile {
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

pub struct PeerTable {
    pub peers: HashMap<String, PeerState>,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let mut table = Self::new();
        if path.exists() {
            let content = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read peers file: {}", e))?;
            let file: PeersFile = toml::from_str(&content)
                .map_err(|e| format!("Failed to parse peers.toml: {}", e))?;

            for cfg in file.peers {
                let pubkey = cfg.public_key_base64.clone();
                table.peers.insert(pubkey, PeerState::new(cfg));
            }
        }
        Ok(table)
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let file = PeersFile {
            peers: self.peers.values().map(|p| p.config.clone()).collect(),
        };
        let content = toml::to_string_pretty(&file)
            .map_err(|e| format!("Failed to serialize peers.toml: {}", e))?;
        fs::write(path, content).map_err(|e| format!("Failed to write peers.toml: {}", e))?;
        Ok(())
    }

    pub fn add_peer(&mut self, config: PeerConfig) {
        let pubkey = config.public_key_base64.clone();
        self.peers.insert(pubkey, PeerState::new(config));
    }

    pub fn remove_peer(&mut self, pubkey_base64: &str) -> Option<PeerState> {
        self.peers.remove(pubkey_base64)
    }

    pub fn get_mut_by_pubkey(&mut self, pubkey_base64: &str) -> Option<&mut PeerState> {
        self.peers.get_mut(pubkey_base64)
    }

    pub fn get_by_pubkey(&self, pubkey_base64: &str) -> Option<&PeerState> {
        self.peers.get(pubkey_base64)
    }

    pub fn list(&self) -> Vec<&PeerState> {
        let mut list: Vec<&PeerState> = self.peers.values().collect();
        list.sort_by(|a, b| a.config.callsign.cmp(&b.config.callsign));
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_path_fast_failover() {
        let cfg = PeerConfig {
            callsign: "backup-node".to_string(),
            node_id: "sbm-0xbackup".to_string(),
            public_key_base64: "dGVzdF9rZXk=".to_string(),
            endpoint: Some("198.51.100.1:58888".to_string()),
            overlay_ip: None,
            created_at: Utc::now(),
        };

        let mut peer = PeerState::new(cfg);
        let ipv4_path = PathType::DirectIPv4("198.51.100.1:58888".parse().unwrap());
        let ipv6_path = PathType::DirectIPv6("[2001:db8::1]:58888".parse().unwrap());
        let relay_path = PathType::Relay("sbm-0xrelaynode".to_string());

        peer.add_or_update_path(ipv6_path.clone());
        peer.add_or_update_path(relay_path.clone());

        assert_eq!(peer.candidate_paths.len(), 3);
        assert_eq!(peer.active_path().unwrap().path_type, ipv4_path);

        // IPv4 fails twice (threshold = 2)
        assert!(!peer.record_path_failure(&ipv4_path, 2));
        assert!(peer.record_path_failure(&ipv4_path, 2)); // threshold met -> failover!

        // Active path should now failover to IPv6
        let active = peer.active_path().expect("Should have active path");
        assert_ne!(active.path_type, ipv4_path);
        assert_eq!(active.path_type, ipv6_path);
        assert_eq!(
            peer.parsed_endpoint,
            Some("[2001:db8::1]:58888".parse().unwrap())
        );

        // Now record IPv6 latency 25ms, Relay latency 10ms
        peer.record_path_success(&ipv6_path, 25.0);
        peer.record_path_success(&relay_path, 10.0);

        // Fast failover selects best path by latency
        let best = peer.failover_to_best_path().unwrap();
        assert_eq!(best, relay_path);
        assert_eq!(peer.active_path().unwrap().path_type, relay_path);
    }

    #[test]
    fn test_adaptive_heartbeat_backoff_and_wake() {
        let cfg = PeerConfig {
            callsign: "mobile-node".to_string(),
            node_id: "sbm-0xmobile".to_string(),
            public_key_base64: "bW9iaWxlX2tleQ==".to_string(),
            endpoint: Some("192.168.1.100:58888".to_string()),
            overlay_ip: None,
            created_at: Utc::now(),
        };

        let mut peer = PeerState::new(cfg);
        let t0 = Utc::now();

        // 1. Initially Idle (no activity recorded yet)
        assert_eq!(peer.update_heartbeat_mode(t0), HeartbeatMode::Idle);

        // 2. Data activity occurs -> immediately Active (2s interval)
        peer.record_data_activity();
        assert_eq!(peer.heartbeat_mode, HeartbeatMode::Active);
        assert_eq!(
            peer.update_heartbeat_mode(t0 + chrono::Duration::seconds(10)),
            HeartbeatMode::Active
        );
        assert_eq!(
            peer.heartbeat_mode.interval(),
            std::time::Duration::from_secs(2)
        );

        // 3. After 45s idle -> drops to Idle (25s interval)
        assert_eq!(
            peer.update_heartbeat_mode(t0 + chrono::Duration::seconds(45)),
            HeartbeatMode::Idle
        );
        assert_eq!(
            peer.heartbeat_mode.interval(),
            std::time::Duration::from_secs(25)
        );

        // 4. After 150s idle -> drops to PowerSave (120s backoff interval)
        assert_eq!(
            peer.update_heartbeat_mode(t0 + chrono::Duration::seconds(150)),
            HeartbeatMode::PowerSave
        );
        assert_eq!(
            peer.heartbeat_mode.interval(),
            std::time::Duration::from_secs(120)
        );

        // 5. Wake on packet / traffic -> immediately returns to Active
        peer.record_data_activity();
        assert_eq!(peer.heartbeat_mode, HeartbeatMode::Active);
    }
}
