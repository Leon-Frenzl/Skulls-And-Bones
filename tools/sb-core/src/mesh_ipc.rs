//! Shared data contract for the existing local `sb-mesh` IPC boundary.
//!
//! This preserves the current wire format; API versioning and authenticated
//! transport migration remain separate work.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", content = "params")]
pub enum IpcRequest {
    GetStatus,
    ListPeers,
    SendPing { target: String },
    SetAirGap { enabled: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", content = "data")]
pub enum IpcResponse {
    Ok(IpcPayload),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum IpcPayload {
    Status(NodeStatusPayload),
    Peers(Vec<PeerSummaryPayload>),
    Ack(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeStatusPayload {
    pub node_id: String,
    pub wireguard_pubkey: String,
    pub listen_port: u16,
    pub air_gap_killswitch: bool,
    pub lan_discovery: bool,
    pub zk_attestation: String,
    pub peer_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerSummaryPayload {
    pub callsign: String,
    pub node_id: String,
    pub public_key_base64: String,
    pub endpoint: Option<String>,
    pub overlay_ip: Option<String>,
    pub status: String,
    pub rtt_ms: Option<f64>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub zk_attested: bool,
}

impl IpcRequest {
    pub fn to_rpc_request(&self, id: impl Into<serde_json::Value>) -> crate::rpc::RpcRequest {
        match self {
            Self::GetStatus => crate::rpc::RpcRequest::new(
                id,
                crate::rpc::RPC_METHOD_MESH_STATUS,
                serde_json::Value::Null,
            ),
            Self::ListPeers => crate::rpc::RpcRequest::new(
                id,
                crate::rpc::RPC_METHOD_MESH_NODES,
                serde_json::Value::Null,
            ),
            Self::SendPing { target } => crate::rpc::RpcRequest::new(
                id,
                crate::rpc::RPC_METHOD_MESH_PING,
                serde_json::json!({ "target": target }),
            ),
            Self::SetAirGap { enabled } => crate::rpc::RpcRequest::new(
                id,
                crate::rpc::RPC_METHOD_MESH_SET_AIR_GAP,
                serde_json::json!({ "enabled": enabled }),
            ),
        }
    }

    pub fn from_rpc_request(
        req: &crate::rpc::RpcRequest,
    ) -> Result<Self, crate::service::ServiceError> {
        if req.api_version != crate::service::SERVICE_API_VERSION {
            return Err(crate::service::ServiceError::UnsupportedVersion {
                client: req.api_version,
                server: crate::service::SERVICE_API_VERSION,
            });
        }
        match req.method.as_str() {
            crate::rpc::RPC_METHOD_MESH_STATUS => Ok(Self::GetStatus),
            crate::rpc::RPC_METHOD_MESH_NODES => Ok(Self::ListPeers),
            crate::rpc::RPC_METHOD_MESH_PING => {
                let target = req
                    .params
                    .get("target")
                    .and_then(|t| t.as_str())
                    .ok_or_else(|| {
                        crate::service::ServiceError::InvalidRequest(
                            "Missing required 'target' parameter".into(),
                        )
                    })?;
                Ok(Self::SendPing {
                    target: target.to_string(),
                })
            }
            crate::rpc::RPC_METHOD_MESH_SET_AIR_GAP => {
                let enabled = req
                    .params
                    .get("enabled")
                    .and_then(|e| e.as_bool())
                    .ok_or_else(|| {
                        crate::service::ServiceError::InvalidRequest(
                            "Missing required 'enabled' boolean parameter".into(),
                        )
                    })?;
                Ok(Self::SetAirGap { enabled })
            }
            unknown => Err(crate::service::ServiceError::NotFound(format!(
                "Unknown mesh RPC method: {unknown}"
            ))),
        }
    }
}

impl IpcResponse {
    pub fn into_rpc_response(self, id: serde_json::Value) -> crate::rpc::RpcResponse {
        match self {
            Self::Ok(payload) => match serde_json::to_value(payload) {
                Ok(val) => crate::rpc::RpcResponse::success(id, val),
                Err(err) => crate::rpc::RpcResponse::error(
                    id,
                    crate::rpc::error_codes::INTERNAL_ERROR,
                    err.to_string(),
                    None,
                ),
            },
            Self::Error(err) => crate::rpc::RpcResponse::error(
                id,
                crate::rpc::error_codes::PEER_UNREACHABLE,
                err,
                None,
            ),
        }
    }
}

/// Versioned and authenticated envelope for transport-level JSON-RPC calls over local socket
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatedRpcEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(flatten)]
    pub request: crate::rpc::RpcRequest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn requests_keep_the_existing_mesh_ipc_wire_format() {
        let fixtures = [
            (IpcRequest::GetStatus, json!({"action": "GetStatus"})),
            (IpcRequest::ListPeers, json!({"action": "ListPeers"})),
            (
                IpcRequest::SendPing {
                    target: "node-1".into(),
                },
                json!({"action": "SendPing", "params": {"target": "node-1"}}),
            ),
            (
                IpcRequest::SetAirGap { enabled: true },
                json!({"action": "SetAirGap", "params": {"enabled": true}}),
            ),
        ];

        for (request, fixture) in fixtures {
            assert_eq!(serde_json::to_value(&request).unwrap(), fixture);
            assert_eq!(
                serde_json::from_value::<IpcRequest>(fixture).unwrap(),
                request
            );
        }
    }

    #[test]
    fn responses_keep_the_existing_mesh_ipc_wire_format() {
        let response = IpcResponse::Ok(IpcPayload::Status(NodeStatusPayload {
            node_id: "sbm-0x1234".into(),
            wireguard_pubkey: "public-key".into(),
            listen_port: 58888,
            air_gap_killswitch: false,
            lan_discovery: true,
            zk_attestation: "unavailable".into(),
            peer_count: 2,
        }));
        let fixture = json!({
            "status": "Ok",
            "data": {
                "node_id": "sbm-0x1234",
                "wireguard_pubkey": "public-key",
                "listen_port": 58888,
                "air_gap_killswitch": false,
                "lan_discovery": true,
                "zk_attestation": "unavailable",
                "peer_count": 2
            }
        });

        assert_eq!(serde_json::to_value(&response).unwrap(), fixture);
        assert_eq!(
            serde_json::from_value::<IpcResponse>(fixture).unwrap(),
            response
        );
    }

    #[test]
    fn rpc_and_ipc_request_roundtrip_and_version_enforcement() {
        let req = IpcRequest::SendPing {
            target: "peer-abc".into(),
        };
        let rpc = req.to_rpc_request(42);
        assert_eq!(rpc.jsonrpc, "2.0");
        assert_eq!(rpc.api_version, crate::service::SERVICE_API_VERSION);
        assert_eq!(rpc.method, crate::rpc::RPC_METHOD_MESH_PING);
        assert_eq!(rpc.params["target"], "peer-abc");

        let reconstructed = IpcRequest::from_rpc_request(&rpc).expect("must parse");
        assert_eq!(reconstructed, req);

        // Version mismatch
        let mut wrong_version = rpc.clone();
        wrong_version.api_version = 999;
        let err = IpcRequest::from_rpc_request(&wrong_version).unwrap_err();
        assert_eq!(
            err,
            crate::service::ServiceError::UnsupportedVersion {
                client: 999,
                server: crate::service::SERVICE_API_VERSION
            }
        );

        // Unknown method
        let mut unknown_method = rpc.clone();
        unknown_method.method = "nonexistent.method".into();
        assert!(IpcRequest::from_rpc_request(&unknown_method).is_err());
    }

    #[test]
    fn authenticated_envelope_roundtrip() {
        let rpc = IpcRequest::GetStatus.to_rpc_request(1);
        let env = AuthenticatedRpcEnvelope {
            token: Some("secret-token-123".into()),
            request: rpc,
        };
        let serialized = serde_json::to_string(&env).unwrap();
        let parsed: AuthenticatedRpcEnvelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.token, Some("secret-token-123".into()));
        assert_eq!(parsed.request.method, crate::rpc::RPC_METHOD_MESH_STATUS);
    }
}
