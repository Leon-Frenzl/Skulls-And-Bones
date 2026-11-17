use crate::catalog::SuiteProduct;
use std::fmt;

pub const SERVICE_API_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    InvalidRequest(String),
    Unauthorized,
    NotFound(String),
    Unavailable(String),
    PayloadTooLarge,
    UnsupportedVersion { client: u16, server: u16 },
    Internal(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message)
            | Self::NotFound(message)
            | Self::Unavailable(message)
            | Self::Internal(message) => formatter.write_str(message),
            Self::Unauthorized => formatter.write_str("Authentication required"),
            Self::PayloadTooLarge => formatter.write_str("Request exceeds the local size limit"),
            Self::UnsupportedVersion { client, server } => {
                write!(
                    formatter,
                    "Unsupported API version {client}; daemon supports {server}"
                )
            }
        }
    }
}

impl std::error::Error for ServiceError {}

impl ServiceError {
    pub fn rpc_error_code(&self) -> i32 {
        use crate::rpc::error_codes;
        match self {
            Self::InvalidRequest(_) => error_codes::INVALID_PARAMS,
            Self::Unauthorized => error_codes::ACCESS_DENIED,
            Self::NotFound(_) => error_codes::RESOURCE_NOT_FOUND,
            Self::Unavailable(_) => error_codes::PEER_UNREACHABLE,
            Self::PayloadTooLarge => error_codes::INVALID_PARAMS,
            Self::UnsupportedVersion { .. } => error_codes::UNSUPPORTED_API_VERSION,
            Self::Internal(_) => error_codes::INTERNAL_ERROR,
        }
    }

    pub fn into_rpc_response(self, id: serde_json::Value) -> crate::rpc::RpcResponse {
        crate::rpc::RpcResponse::error(id, self.rpc_error_code(), self.to_string(), None)
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

pub trait ProductCatalogService {
    fn list_products(&self) -> ServiceResult<Vec<SuiteProduct>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct InventoryProductCatalog;

impl ProductCatalogService for InventoryProductCatalog {
    fn list_products(&self) -> ServiceResult<Vec<SuiteProduct>> {
        crate::catalog::products()
            .map(|products| products.to_vec())
            .map_err(ServiceError::Internal)
    }
}

pub trait MeshService {
    fn status(&self) -> ServiceResult<crate::mesh_ipc::NodeStatusPayload>;
    fn list_peers(&self) -> ServiceResult<Vec<crate::mesh_ipc::PeerSummaryPayload>>;
    fn ping(&self, target: &str) -> ServiceResult<String>;
    fn set_air_gap(&self, enabled: bool) -> ServiceResult<String>;
}
