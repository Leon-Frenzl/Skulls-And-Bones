//! S&B Core — Sovereign JSON-RPC 2.0 Protocol & Method Definitions
//!
//! Provides the universal protocol contract for Headless Daemons (`sb daemon --api`),
//! GUI frontends (`sb-desktop`), CLI commands, TUIs, and third-party custom clients.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard JSON-RPC 2.0 version string
pub const JSONRPC_VERSION: &str = "2.0";
pub const RPC_API_VERSION: u16 = crate::service::SERVICE_API_VERSION;
pub const MAX_RPC_REQUEST_BYTES: usize = 60 * 1024;
pub const MAX_RPC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RPC_HTTP_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_RPC_HTTP_REQUEST_BYTES: usize = MAX_RPC_REQUEST_BYTES + MAX_RPC_HTTP_HEADER_BYTES;
pub const MAX_RPC_HTTP_RESPONSE_BYTES: usize =
    MAX_RPC_RESPONSE_BYTES + MAX_RPC_HTTP_HEADER_BYTES + 4;

/// Canonical RPC Method Names
pub const RPC_METHOD_SUITE_STATUS: &str = "suite.status";
pub const RPC_METHOD_SUITE_CATALOG: &str = "suite.catalog";
pub const RPC_METHOD_MESH_STATUS: &str = "mesh.status";
pub const RPC_METHOD_MESH_NODES: &str = "mesh.nodes";
pub const RPC_METHOD_MESH_PING: &str = "mesh.ping";
pub const RPC_METHOD_MESH_OBJECTS_LIST: &str = "mesh.objects.list";
pub const RPC_METHOD_MESH_OBJECTS_GET: &str = "mesh.objects.get";
pub const RPC_METHOD_MESH_OBJECTS_PREVIEW: &str = "mesh.objects.preview";
pub const RPC_METHOD_APPS_LIST: &str = "apps.list";
pub const RPC_METHOD_APPS_PREVIEW: &str = "apps.preview";
pub const RPC_METHOD_APPS_INSTALL: &str = "apps.install";
pub const RPC_METHOD_APPS_UNINSTALL: &str = "apps.uninstall";
pub const RPC_METHOD_APPS_ROLLBACK: &str = "apps.rollback";
pub const RPC_METHOD_APPS_LAUNCH: &str = "apps.launch";
pub const RPC_METHOD_FLEET_LIST: &str = "fleet.list";
pub const RPC_METHOD_TUNNELS_LIST: &str = "tunnels.list";
pub const RPC_METHOD_AUDIT_LIST: &str = "audit.list";
pub const RPC_METHOD_AUDIT_RECORDING: &str = "audit.recording";
pub const RPC_METHOD_MESH_SET_AIR_GAP: &str = "mesh.set_air_gap";
pub const RPC_METHOD_DRIVE_LIST: &str = "drive.list";
pub const RPC_METHOD_DRIVE_READ: &str = "drive.read";
pub const RPC_METHOD_DRIVE_WRITE: &str = "drive.write";
pub const RPC_METHOD_DRIVE_GET: &str = "drive.get";
pub const RPC_METHOD_SERVER_LIST: &str = "server.list";
pub const RPC_METHOD_VAULT_LIST: &str = "vault.list";
pub const RPC_METHOD_VAULT_STATUS: &str = "vault.status";
pub const RPC_METHOD_VAULT_INITIALIZE: &str = "vault.initialize";
pub const RPC_METHOD_VAULT_UNLOCK: &str = "vault.unlock";
pub const RPC_METHOD_VAULT_LOCK: &str = "vault.lock";
pub const RPC_METHOD_VAULT_GET: &str = "vault.get";
pub const RPC_METHOD_VAULT_SET: &str = "vault.set";
pub const RPC_METHOD_VAULT_DELETE: &str = "vault.delete";
pub const RPC_METHOD_VAULT_GET_ALL: &str = "vault.get_all";
pub const RPC_METHOD_VAULT_CHANGE_PASSWORD: &str = "vault.change_password";

/// Canonical JSON-RPC 2.0 Request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub api_version: u16,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl RpcRequest {
    pub fn new(id: impl Into<Value>, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            api_version: RPC_API_VERSION,
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

/// Canonical JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub api_version: u16,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            api_version: RPC_API_VERSION,
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            api_version: RPC_API_VERSION,
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

/// Canonical JSON-RPC 2.0 Error object
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const PEER_UNREACHABLE: i32 = -32001;
    pub const ACCESS_DENIED: i32 = -32002;
    pub const TIMEOUT: i32 = -32003;
    pub const UNSUPPORTED_API_VERSION: i32 = -32004;
    pub const RESOURCE_NOT_FOUND: i32 = -32005;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_contract_always_serializes_api_version() {
        let request = RpcRequest::new(1, RPC_METHOD_SUITE_CATALOG, Value::Null);
        let request_value = serde_json::to_value(request.clone()).unwrap();
        assert_eq!(request_value["api_version"], RPC_API_VERSION);

        let response = RpcResponse::success(1.into(), Value::Null);
        let response_value = serde_json::to_value(response.clone()).unwrap();
        assert_eq!(response_value["api_version"], RPC_API_VERSION);

        let mut request_without_version = request_value.clone();
        request_without_version
            .as_object_mut()
            .unwrap()
            .remove("api_version");
        assert!(serde_json::from_value::<RpcRequest>(request_without_version).is_err());

        let mut request_without_protocol = request_value;
        request_without_protocol
            .as_object_mut()
            .unwrap()
            .remove("jsonrpc");
        assert!(serde_json::from_value::<RpcRequest>(request_without_protocol).is_err());

        let mut response_without_version = response_value;
        response_without_version
            .as_object_mut()
            .unwrap()
            .remove("api_version");
        assert!(serde_json::from_value::<RpcResponse>(response_without_version).is_err());
    }

    #[test]
    fn service_errors_map_to_stable_rpc_error_codes() {
        use crate::service::ServiceError;
        assert_eq!(
            ServiceError::Unauthorized.rpc_error_code(),
            error_codes::ACCESS_DENIED
        );
        assert_eq!(
            ServiceError::PayloadTooLarge.rpc_error_code(),
            error_codes::INVALID_PARAMS
        );
        assert_eq!(
            ServiceError::UnsupportedVersion {
                client: 2,
                server: 1,
            }
            .rpc_error_code(),
            error_codes::UNSUPPORTED_API_VERSION
        );
    }
}
