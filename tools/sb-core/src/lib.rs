//! S&B Core — Unified Domain Types, IPC DTOs, Path Manager, Ports Topology & Vault Crypto

pub mod binary_resolver;
pub mod catalog;
pub mod config;
pub mod daemon_auth;
pub mod daemon_client;
pub mod domain;
pub mod dto;
pub mod ipam;
pub mod mesh_ipc;
pub mod paths;
pub mod policy;
pub mod ports;
pub mod process;
pub mod rpc;
pub mod service;
pub mod ssh_transport;
pub mod target;
pub mod vault;

pub use binary_resolver::BinaryResolver;
pub use catalog::{ProductKind, ProductMaturity, SuiteProduct};
pub use config::{NetworkConfig, PortsConfig, SecurityConfig, SuiteConfig};
pub use dto::{
    CrossMeshRuleItem, GhostLaunchResult, MeshDriveFile, MeshNetworkInfo, MeshNodeInfo, MeshUser,
    NetworkSummaryItem, PeerDirectoryResult, PeerFileContentResult, PeerFileItem,
    ProxyTelemetryDto, RemoteFileItem, RemoteTelemetry, SecretItem, ServerEntry, TunnelProfile,
};
pub use paths::{
    escape_spaces_path, history_path, sb_ca_dir, sb_home, sb_mesh_dir, sb_run_dir, sb_ssh_dir,
};
pub use ports::{
    DEFAULT_DAEMON_API_PORT, DEFAULT_DEV_TARGET_PORT, DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT,
    DEFAULT_MESH_IPC_PORT, DEFAULT_MESH_UDP_PORT, DEFAULT_PROXY_IPC_PORT, DEFAULT_STEALTH_SSH_PORT,
    DEFAULT_TUNNEL_HUB_PORT,
};
pub use process::{
    is_pid_alive, is_port_listening, ledger_path, load_ledger, modify_ledger, prune_dead,
    register_process, save_ledger, terminate_pid, unregister_process_by_pid, ProcessLedger,
    ServiceSupervisor, TrackedProcess,
};
pub use rpc::{RpcError, RpcRequest, RpcResponse};
pub use service::{
    InventoryProductCatalog, ProductCatalogService, ServiceError, ServiceResult,
    SERVICE_API_VERSION,
};
pub use target::{ServerConfig, TargetResolver};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dto_serialization() {
        let tele = RemoteTelemetry {
            node_name: "node-1".into(),
            swarm_domain: "node-1.sbm".into(),
            uptime_seconds: 3600,
            cpu_usage_percent: 15.5,
            mem_total_mb: 4096,
            mem_used_mb: 1024,
            mem_used_percent: 25.0,
            stealth_ssh_active: true,
            active_leaks_count: 0,
            cross_mesh_active: true,
            cross_mesh_rules_count: 2,
        };

        let json = serde_json::to_string(&tele).expect("serialization works");
        let decoded: RemoteTelemetry = serde_json::from_str(&json).expect("deserialization works");
        assert_eq!(tele, decoded);
    }

    #[test]
    fn test_ports_values() {
        assert_eq!(DEFAULT_MESH_UDP_PORT, 58888);
        assert_eq!(DEFAULT_PROXY_IPC_PORT, 58900);
        assert_eq!(DEFAULT_TUNNEL_HUB_PORT, 58910);
    }

    #[test]
    fn test_domain_dtos_serialization() {
        let node = MeshNodeInfo {
            node_id: "sbm-123".into(),
            callsign: "@test-node".into(),
            mesh_ip: "10.240.0.9".into(),
            role: "Operator".into(),
            privilege: "Admin".into(),
            status: "Online".into(),
            ping_ms: 12,
            gpu_info: Some("NVIDIA RTX 4090".into()),
        };
        let node_json = serde_json::to_string(&node).unwrap();
        let decoded_node: MeshNodeInfo = serde_json::from_str(&node_json).unwrap();
        assert_eq!(node, decoded_node);

        let file_item = PeerFileItem {
            name: "test.txt".into(),
            path: "/home/test.txt".into(),
            is_dir: false,
            is_symlink: false,
            size_bytes: 42,
            permissions: "-rw-r--r--".into(),
            modified: "2026-10-03".into(),
            file_type: "code".into(),
        };
        let file_json = serde_json::to_string(&file_item).unwrap();
        let decoded_file: PeerFileItem = serde_json::from_str(&file_json).unwrap();
        assert_eq!(file_item, decoded_file);
    }

    #[test]
    fn test_rpc_serialization() {
        let req = RpcRequest::new(
            1,
            "drive.list",
            serde_json::json!({ "peer": "hostinger", "path": "/root" }),
        );
        let req_json = serde_json::to_string(&req).unwrap();
        let decoded_req: RpcRequest = serde_json::from_str(&req_json).unwrap();
        assert_eq!(req, decoded_req);

        let resp = RpcResponse::success(serde_json::json!(1), serde_json::json!({ "ok": true }));
        let resp_json = serde_json::to_string(&resp).unwrap();
        let decoded_resp: RpcResponse = serde_json::from_str(&resp_json).unwrap();
        assert_eq!(resp, decoded_resp);
    }
}
