//! X.509 Certificate Authority Engine module.
//!
//! Standards:
//! - Conforms to IETF RFC 5280
//! - Conforms to IETF RFC 8446 (TLS 1.3)

pub mod leaf;
pub mod root;
pub mod store;

pub use leaf::{
    domain_to_safe_filename, get_or_issue_on_demand, issue_leaf_certificate, validate_domain,
    DEFAULT_LEAF_CERT_TTL_DAYS,
};
pub use root::{
    get_ca_status, init_root_ca, X509CaStatus, CA_COMMON_NAME, CA_ORG, CA_OU, CA_VALIDITY_DAYS,
};
pub use store::{DevCertIndex, DevCertMetadata, IssuedCertPair};

use crate::error::CaError;

/// High-level X.509 Certificate Authority interface.
pub struct X509Ca;

impl X509Ca {
    /// Initializes the Sovereign Developer Root CA.
    pub fn init_root_ca(force: bool) -> Result<X509CaStatus, CaError> {
        init_root_ca(force)
    }

    /// Installs Root CA certificate into local OS trust store.
    pub fn install_root_ca() -> Result<String, CaError> {
        crate::trust::install_root_ca()
    }

    /// Removes Root CA certificate from local OS trust store.
    pub fn uninstall_root_ca() -> Result<String, CaError> {
        crate::trust::uninstall_root_ca()
    }

    /// Checks if Root CA is installed and trusted in local OS.
    pub fn is_installed() -> bool {
        crate::trust::is_root_ca_installed()
    }

    /// Issues a leaf certificate for specified domains.
    pub fn issue_leaf_certificate(
        domains: &[String],
        ttl_days: u32,
    ) -> Result<IssuedCertPair, CaError> {
        issue_leaf_certificate(domains, ttl_days)
    }

    /// Checks cache or dynamically generates certificate on-demand.
    pub fn get_or_issue_on_demand(domain: &str) -> Result<IssuedCertPair, CaError> {
        get_or_issue_on_demand(domain)
    }

    /// Returns Root CA status report.
    pub fn status() -> Result<X509CaStatus, CaError> {
        get_ca_status()
    }

    /// Returns list of all previously issued leaf certificates.
    pub fn list_certificates() -> Vec<DevCertMetadata> {
        DevCertIndex::load().certs
    }
}
