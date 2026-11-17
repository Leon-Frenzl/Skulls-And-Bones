//! Unified IPC & Telemetry Data Transfer Objects (DTOs)

use serde::{Deserialize, Serialize};

/// Live telemetry of a remote fleet node gathered by `sb-node`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteTelemetry {
    pub node_name: String,
    pub swarm_domain: String,
    pub uptime_seconds: u64,
    pub cpu_usage_percent: f32,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub mem_used_percent: f32,
    pub stealth_ssh_active: bool,
    pub active_leaks_count: usize,
    #[serde(default)]
    pub cross_mesh_active: bool,
    #[serde(default)]
    pub cross_mesh_rules_count: usize,
}

/// Telemetry reported by S&B Edge Proxy over Loopback IPC (127.0.0.1:58900)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyTelemetryDto {
    pub status: String,
    pub pid: u32,
    pub uptime_secs: u64,
    pub total_requests: u64,
    #[serde(default)]
    pub requests_2xx: u64,
    #[serde(default)]
    pub requests_4xx: u64,
    #[serde(default)]
    pub requests_5xx: u64,
    pub rate_limited_count: u64,
    #[serde(default)]
    pub avg_latency_ms: f32,
    pub active_spaces_count: usize,
}

/// Unified representation of a cross-mesh bridging rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossMeshRuleItem {
    pub rule_id: String,
    pub source_mesh: String,
    pub target_mesh: String,
    pub ports: String,
    pub token: bool,
    pub desc: String,
}

// ==============================================================================
// SOVEREIGN MESH & PEER NETWORK DTOS
// ==============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshNetworkInfo {
    pub active_network: String,
    pub description: String,
    pub overlay_subnet: String,
    pub swarm_topic: String,
    pub local_node_id: String,
    pub local_pubkey: String,
    pub local_callsign: String,
    pub listen_port: u16,
    pub airgap_killswitch: bool,
    pub available_networks: Vec<NetworkSummaryItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSummaryItem {
    pub name: String,
    pub description: String,
    pub subnet: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshNodeInfo {
    pub node_id: String,
    pub callsign: String,
    pub mesh_ip: String,
    pub role: String,
    pub privilege: String,
    pub status: String,
    pub ping_ms: u32,
    pub gpu_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshUser {
    pub id: String,
    pub username: String,
    pub callsign: String,
    pub display_name: String,
    pub role: String,
    pub node_id: String,
    pub mesh_ip: String,
    pub avatar_color: String,
    pub last_active: String,
    pub key_fingerprint: String,
    pub is_current: bool,
}

// ==============================================================================
// SOVEREIGN DRIVE & GHOST FILESYSTEM DTOS
// ==============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteFileItem {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub permissions: String,
    pub modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerFileItem {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size_bytes: u64,
    pub permissions: String,
    pub modified: String,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerDirectoryResult {
    pub peer: String,
    pub os_type: String,
    pub current_path: String,
    pub parent_path: Option<String>,
    pub items: Vec<PeerFileItem>,
    pub total_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerFileContentResult {
    pub peer: String,
    pub path: String,
    pub name: String,
    pub size_bytes: u64,
    pub is_binary: bool,
    pub content: String,
    pub modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GhostLaunchResult {
    pub success: bool,
    pub message: String,
    pub local_cache_path: String,
    pub launched_app: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshDriveFile {
    pub id: String,
    pub name: String,
    pub peer: String,
    pub path: String,
    pub size_bytes: u64,
    pub file_type: String,
    pub modified_at: String,
    pub ntfs_acl: String,
    pub can_write: bool,
    pub can_execute: bool,
    pub fast_cdc_chunks: u32,
}

// ==============================================================================
// SECRETS, SERVERS & TUNNELS DTOS
// ==============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretItem {
    pub id: String,
    pub key: String,
    pub value: String,
    pub env: String,
    pub project: String,
    pub description: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerEntry {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub tags: Vec<String>,
    pub description: String,
    pub last_connected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelProfile {
    pub id: String,
    pub name: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub server_target: String,
    pub is_active: bool,
    pub created_at: String,
}
