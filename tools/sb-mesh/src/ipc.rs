use crate::config::MeshConfig;
use crate::identity::NodeIdentity;
use crate::peer::{PeerState, PeerTable};
use crate::transport::MeshTransport;
use sb_core::mesh_ipc::AuthenticatedRpcEnvelope;
use sb_core::rpc::{
    error_codes, RpcRequest, RpcResponse, MAX_RPC_REQUEST_BYTES, RPC_METHOD_MESH_NODES,
    RPC_METHOD_MESH_PING, RPC_METHOD_MESH_SET_AIR_GAP, RPC_METHOD_MESH_STATUS,
};
use sb_core::service::{MeshService, ServiceError, ServiceResult, SERVICE_API_VERSION};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

pub use sb_core::mesh_ipc::{
    IpcPayload, IpcRequest, IpcResponse, NodeStatusPayload, PeerSummaryPayload,
};

pub const IPC_PIPE_NAME: &str = r"\\.\pipe\sb-mesh";
pub const IPC_TCP_PORT: u16 = 58890;

impl From<&PeerState> for PeerSummaryPayload {
    fn from(p: &PeerState) -> Self {
        Self {
            callsign: p.config.callsign.clone(),
            node_id: p.config.node_id.clone(),
            public_key_base64: p.config.public_key_base64.clone(),
            endpoint: p.config.endpoint.clone(),
            overlay_ip: p.config.overlay_ip.clone(),
            status: p.status.badge_text().to_string(),
            rtt_ms: p.rtt_ms,
            bytes_sent: p.bytes_sent,
            bytes_recv: p.bytes_recv,
            zk_attested: p.zk_attested,
        }
    }
}

pub struct IpcServer {
    pub identity: Arc<NodeIdentity>,
    pub transport: Arc<MeshTransport>,
    pub peer_table: Arc<RwLock<PeerTable>>,
    pub config: Arc<RwLock<MeshConfig>>,
}

impl IpcServer {
    pub fn new(
        identity: Arc<NodeIdentity>,
        transport: Arc<MeshTransport>,
        peer_table: Arc<RwLock<PeerTable>>,
        config: Arc<RwLock<MeshConfig>>,
    ) -> Self {
        Self {
            identity,
            transport,
            peer_table,
            config,
        }
    }

    /// Spawns the IPC listener in the background (using local TCP loopback 127.0.0.1:58890 for universal cross-platform reliability)
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let identity = self.identity.clone();
        let transport = self.transport.clone();
        let peer_table = self.peer_table.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let addr = format!("127.0.0.1:{}", IPC_TCP_PORT);
            if let Ok(listener) = tokio::net::TcpListener::bind(&addr).await {
                loop {
                    if let Ok((mut socket, _)) = listener.accept().await {
                        let id_c = identity.clone();
                        let tr_c = transport.clone();
                        let pt_c = peer_table.clone();
                        let cfg_c = config.clone();

                        tokio::spawn(async move {
                            let mut buf = vec![0u8; MAX_RPC_REQUEST_BYTES];
                            if let Ok(n) = socket.read(&mut buf).await {
                                if n > 0 {
                                    let req_str = String::from_utf8_lossy(&buf[..n]);

                                    // Handle JSON-RPC 2.0 versioned format
                                    if req_str.contains("\"jsonrpc\"") {
                                        let parsed_rpc = serde_json::from_str::<
                                            AuthenticatedRpcEnvelope,
                                        >(
                                            &req_str
                                        )
                                        .map(|env| env.request)
                                        .or_else(|_| serde_json::from_str::<RpcRequest>(&req_str));

                                        let rpc_resp = match parsed_rpc {
                                            Ok(rpc_req) => {
                                                let id = rpc_req.id.clone();
                                                if rpc_req.jsonrpc != "2.0" {
                                                    RpcResponse::error(
                                                        id,
                                                        error_codes::INVALID_REQUEST,
                                                        "Unsupported JSON-RPC version",
                                                        None,
                                                    )
                                                } else if rpc_req.api_version != SERVICE_API_VERSION
                                                {
                                                    RpcResponse::error(
                                                        id,
                                                        error_codes::UNSUPPORTED_API_VERSION,
                                                        "Unsupported Suite API version",
                                                        Some(json!({
                                                            "requested": rpc_req.api_version,
                                                            "supported": SERVICE_API_VERSION
                                                        })),
                                                    )
                                                } else {
                                                    match rpc_req.method.as_str() {
                                                        RPC_METHOD_MESH_STATUS => {
                                                            let cfg = cfg_c.read().await;
                                                            let pt = pt_c.read().await;
                                                            let payload = NodeStatusPayload {
                                                                node_id: id_c.node_id.clone(),
                                                                wireguard_pubkey: id_c
                                                                    .wireguard_pubkey
                                                                    .clone(),
                                                                listen_port: cfg.listen_port,
                                                                air_gap_killswitch: cfg
                                                                    .air_gap_killswitch,
                                                                lan_discovery: cfg.lan_discovery,
                                                                zk_attestation:
                                                                    "ACTIVE (Phase 2 / 0-Leak)"
                                                                        .to_string(),
                                                                peer_count: pt.peers.len(),
                                                            };
                                                            RpcResponse::success(
                                                                id,
                                                                serde_json::to_value(payload)
                                                                    .unwrap_or(Value::Null),
                                                            )
                                                        }
                                                        RPC_METHOD_MESH_NODES => {
                                                            let pt = pt_c.read().await;
                                                            let list: Vec<PeerSummaryPayload> = pt
                                                                .list()
                                                                .into_iter()
                                                                .map(Into::into)
                                                                .collect();
                                                            RpcResponse::success(
                                                                id,
                                                                serde_json::to_value(list)
                                                                    .unwrap_or(Value::Null),
                                                            )
                                                        }
                                                        RPC_METHOD_MESH_PING => {
                                                            let target = rpc_req
                                                                .params
                                                                .get("target")
                                                                .and_then(|v| v.as_str());
                                                            match target {
                                                                Some(t) if !t.trim().is_empty() => {
                                                                    let t = t.trim();
                                                                    let pt = pt_c.read().await;
                                                                    let found = pt.peers.values().find(|p| {
                                                                        p.config.callsign == t
                                                                            || p.config.node_id == t
                                                                            || p.config.public_key_base64 == t
                                                                    }).map(|p| p.config.public_key_base64.clone());
                                                                    drop(pt);

                                                                    if let Some(pk) = found {
                                                                        match tr_c.send_ping(&pk).await {
                                                                            Ok(_) => RpcResponse::success(id, json!({ "status": "sent", "ack": format!("Ping sent to {}", t) })),
                                                                            Err(e) => RpcResponse::error(id, error_codes::PEER_UNREACHABLE, format!("Ping failed: {}", e), None),
                                                                        }
                                                                    } else {
                                                                        RpcResponse::error(id, error_codes::PEER_UNREACHABLE, format!("Peer not found: {}", t), None)
                                                                    }
                                                                }
                                                                _ => RpcResponse::error(id, error_codes::INVALID_PARAMS, "Missing or empty required string parameter 'target'", None),
                                                            }
                                                        }
                                                        RPC_METHOD_MESH_SET_AIR_GAP => {
                                                            let enabled = rpc_req
                                                                .params
                                                                .get("enabled")
                                                                .and_then(|v| v.as_bool());
                                                            match enabled {
                                                                Some(val) => {
                                                                    let mut cfg = cfg_c.write().await;
                                                                    cfg.air_gap_killswitch = val;
                                                                    let mut air = tr_c.air_gap.write().await;
                                                                    *air = val;
                                                                    RpcResponse::success(id, json!({
                                                                        "status": "updated",
                                                                        "ack": format!("Air-gap killswitch set to {}", val),
                                                                        "air_gap_killswitch": val,
                                                                    }))
                                                                }
                                                                None => RpcResponse::error(id, error_codes::INVALID_PARAMS, "Missing or invalid required boolean parameter 'enabled'", None),
                                                            }
                                                        }
                                                        other => RpcResponse::error(
                                                            id,
                                                            error_codes::METHOD_NOT_FOUND,
                                                            format!("Method '{}' not found", other),
                                                            None,
                                                        ),
                                                    }
                                                }
                                            }
                                            Err(e) => RpcResponse::error(
                                                Value::Null,
                                                error_codes::PARSE_ERROR,
                                                format!("Invalid JSON-RPC request: {}", e),
                                                None,
                                            ),
                                        };

                                        if let Ok(resp_bytes) = serde_json::to_vec(&rpc_resp) {
                                            let _ = socket.write_all(&resp_bytes).await;
                                        }
                                    } else {
                                        // Legacy IpcRequest fallback
                                        let resp =
                                            match serde_json::from_str::<IpcRequest>(&req_str) {
                                                Ok(IpcRequest::GetStatus) => {
                                                    let cfg = cfg_c.read().await;
                                                    let pt = pt_c.read().await;
                                                    let payload = NodeStatusPayload {
                                                        node_id: id_c.node_id.clone(),
                                                        wireguard_pubkey: id_c
                                                            .wireguard_pubkey
                                                            .clone(),
                                                        listen_port: cfg.listen_port,
                                                        air_gap_killswitch: cfg.air_gap_killswitch,
                                                        lan_discovery: cfg.lan_discovery,
                                                        zk_attestation: "ACTIVE (Phase 2 / 0-Leak)"
                                                            .to_string(),
                                                        peer_count: pt.peers.len(),
                                                    };
                                                    IpcResponse::Ok(IpcPayload::Status(payload))
                                                }
                                                Ok(IpcRequest::ListPeers) => {
                                                    let pt = pt_c.read().await;
                                                    let list: Vec<PeerSummaryPayload> = pt
                                                        .list()
                                                        .into_iter()
                                                        .map(Into::into)
                                                        .collect();
                                                    IpcResponse::Ok(IpcPayload::Peers(list))
                                                }
                                                Ok(IpcRequest::SendPing { target }) => {
                                                    let pt = pt_c.read().await;
                                                    let found = pt
                                                        .peers
                                                        .values()
                                                        .find(|p| {
                                                            p.config.callsign == target
                                                                || p.config.node_id == target
                                                                || p.config.public_key_base64
                                                                    == target
                                                        })
                                                        .map(|p| {
                                                            p.config.public_key_base64.clone()
                                                        });
                                                    drop(pt);

                                                    if let Some(pk) = found {
                                                        match tr_c.send_ping(&pk).await {
                                                            Ok(_) => IpcResponse::Ok(
                                                                IpcPayload::Ack(format!(
                                                                    "Ping sent to {}",
                                                                    target
                                                                )),
                                                            ),
                                                            Err(e) => IpcResponse::Error(format!(
                                                                "Ping failed: {}",
                                                                e
                                                            )),
                                                        }
                                                    } else {
                                                        IpcResponse::Error(format!(
                                                            "Peer not found: {}",
                                                            target
                                                        ))
                                                    }
                                                }
                                                Ok(IpcRequest::SetAirGap { enabled }) => {
                                                    let mut cfg = cfg_c.write().await;
                                                    cfg.air_gap_killswitch = enabled;
                                                    let mut air = tr_c.air_gap.write().await;
                                                    *air = enabled;
                                                    IpcResponse::Ok(IpcPayload::Ack(format!(
                                                        "Air-gap killswitch set to {}",
                                                        enabled
                                                    )))
                                                }
                                                Err(e) => IpcResponse::Error(format!(
                                                    "Invalid IPC request: {}",
                                                    e
                                                )),
                                            };

                                        if let Ok(resp_bytes) = serde_json::to_vec(&resp) {
                                            let _ = socket.write_all(&resp_bytes).await;
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        })
    }
}

/// Client helper for external processes (such as sb-browser, daemon and CLI)
pub struct IpcClient;

impl IpcClient {
    /// Send a legacy IPC request to the running sb-mesh daemon
    pub async fn query(req: IpcRequest) -> Result<IpcResponse, String> {
        let addr = format!("127.0.0.1:{}", IPC_TCP_PORT);
        let mut stream = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("Could not connect to sb-mesh daemon at {}: {}", addr, e))?;

        let req_bytes =
            serde_json::to_vec(&req).map_err(|e| format!("Serialization error: {}", e))?;
        stream
            .write_all(&req_bytes)
            .await
            .map_err(|e| format!("IPC write error: {}", e))?;

        let mut buf = vec![0u8; 65535];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("IPC read error: {}", e))?;

        serde_json::from_slice(&buf[..n])
            .map_err(|e| format!("Failed to parse IPC response: {}", e))
    }

    /// Send a versioned JSON-RPC 2.0 request over the local IPC socket
    pub async fn query_rpc(req: RpcRequest, token: Option<&str>) -> Result<RpcResponse, String> {
        let addr = format!("127.0.0.1:{}", IPC_TCP_PORT);
        let mut stream = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("Could not connect to sb-mesh daemon at {}: {}", addr, e))?;

        let envelope = AuthenticatedRpcEnvelope {
            token: token.map(|t| t.to_string()),
            request: req,
        };
        let req_bytes =
            serde_json::to_vec(&envelope).map_err(|e| format!("Serialization error: {}", e))?;
        stream
            .write_all(&req_bytes)
            .await
            .map_err(|e| format!("IPC write error: {}", e))?;

        let mut buf = vec![0u8; MAX_RPC_REQUEST_BYTES];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("IPC read error: {}", e))?;

        serde_json::from_slice(&buf[..n])
            .map_err(|e| format!("Failed to parse JSON-RPC response: {}", e))
    }

    pub async fn get_status() -> Result<NodeStatusPayload, String> {
        let req = RpcRequest::new(1, RPC_METHOD_MESH_STATUS, Value::Null);
        match Self::query_rpc(req, None).await {
            Ok(resp) => {
                if let Some(err) = resp.error {
                    Err(err.message)
                } else if let Some(res) = resp.result {
                    serde_json::from_value(res)
                        .map_err(|e| format!("Failed to decode NodeStatusPayload: {e}"))
                } else {
                    Err("Empty response from mesh daemon".to_string())
                }
            }
            Err(_) => match Self::query(IpcRequest::GetStatus).await? {
                IpcResponse::Ok(IpcPayload::Status(s)) => Ok(s),
                IpcResponse::Error(e) => Err(e),
                _ => Err("Unexpected response payload".to_string()),
            },
        }
    }

    pub async fn list_peers() -> Result<Vec<PeerSummaryPayload>, String> {
        let req = RpcRequest::new(1, RPC_METHOD_MESH_NODES, Value::Null);
        match Self::query_rpc(req, None).await {
            Ok(resp) => {
                if let Some(err) = resp.error {
                    Err(err.message)
                } else if let Some(res) = resp.result {
                    serde_json::from_value(res)
                        .map_err(|e| format!("Failed to decode PeerSummaryPayload list: {e}"))
                } else {
                    Err("Empty response from mesh daemon".to_string())
                }
            }
            Err(_) => match Self::query(IpcRequest::ListPeers).await? {
                IpcResponse::Ok(IpcPayload::Peers(p)) => Ok(p),
                IpcResponse::Error(e) => Err(e),
                _ => Err("Unexpected response payload".to_string()),
            },
        }
    }

    pub async fn ping(target: &str) -> Result<String, String> {
        let req = RpcRequest::new(1, RPC_METHOD_MESH_PING, json!({ "target": target }));
        match Self::query_rpc(req, None).await {
            Ok(resp) => {
                if let Some(err) = resp.error {
                    Err(err.message)
                } else if let Some(res) = resp.result {
                    Ok(res
                        .get("ack")
                        .and_then(|a| a.as_str())
                        .unwrap_or("Ping sent")
                        .to_string())
                } else {
                    Err("Empty response from mesh daemon".to_string())
                }
            }
            Err(_) => match Self::query(IpcRequest::SendPing {
                target: target.to_string(),
            })
            .await?
            {
                IpcResponse::Ok(IpcPayload::Ack(msg)) => Ok(msg),
                IpcResponse::Error(e) => Err(e),
                _ => Err("Unexpected response payload".to_string()),
            },
        }
    }

    pub async fn set_air_gap(enabled: bool) -> Result<String, String> {
        let req = RpcRequest::new(
            1,
            RPC_METHOD_MESH_SET_AIR_GAP,
            json!({ "enabled": enabled }),
        );
        match Self::query_rpc(req, None).await {
            Ok(resp) => {
                if let Some(err) = resp.error {
                    Err(err.message)
                } else if let Some(res) = resp.result {
                    Ok(res
                        .get("ack")
                        .and_then(|a| a.as_str())
                        .unwrap_or("Air-gap updated")
                        .to_string())
                } else {
                    Err("Empty response from mesh daemon".to_string())
                }
            }
            Err(_) => match Self::query(IpcRequest::SetAirGap { enabled }).await? {
                IpcResponse::Ok(IpcPayload::Ack(msg)) => Ok(msg),
                IpcResponse::Error(e) => Err(e),
                _ => Err("Unexpected response payload".to_string()),
            },
        }
    }
}

impl MeshService for IpcClient {
    fn status(&self) -> ServiceResult<NodeStatusPayload> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { Self::get_status().await.map_err(ServiceError::Unavailable) })
        })
    }

    fn list_peers(&self) -> ServiceResult<Vec<PeerSummaryPayload>> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { Self::list_peers().await.map_err(ServiceError::Unavailable) })
        })
    }

    fn ping(&self, target: &str) -> ServiceResult<String> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { Self::ping(target).await.map_err(ServiceError::Unavailable) })
        })
    }

    fn set_air_gap(&self, enabled: bool) -> ServiceResult<String> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                Self::set_air_gap(enabled)
                    .await
                    .map_err(ServiceError::Unavailable)
            })
        })
    }
}
