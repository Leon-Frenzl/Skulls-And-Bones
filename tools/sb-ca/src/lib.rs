//! `sb-ca` — Sovereign Unified PKI & Certificate Authority Engine
//!
//! Provides dual-mode cryptographic certificate issuance for the Skulls & Bones ecosystem:
//! 1. **OpenSSH CA Engine (`sb_ca::ssh`)**: Issues short-lived Ed25519 user certificates
//!    and host certificates conforming to OpenSSH `PROTOCOL.certkeys` and IETF RFC 4251 / RFC 8709.
//! 2. **X.509 CA Engine (`sb_ca::x509`)**: Issues ECDSA P-256 Root and leaf certificates
//!    with SAN extensions for mesh domains (`*.sbm`, `*.mesh`, localhost, 127.0.0.1) and mTLS
//!    Extended Key Usages conforming to IETF RFC 5280 and TLS 1.3 RFC 8446.
//!
//! # Standards Compliance:
//! - IETF RFC 4251 (The Secure Shell (SSH) Protocol Architecture)
//! - IETF RFC 8709 (Ed25519 and Ed448 public key algorithms for SSH)
//! - OpenSSH PROTOCOL.certkeys (OpenSSH Certificate Format)
//! - IETF RFC 5280 (X.509 Public Key Infrastructure Certificate and CRL Profile)
//! - IETF RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3)
//! - ISO 8601 (Representation of dates and times)

pub mod error;
pub mod paths;
pub mod ssh;
pub mod trust;
pub mod x509;

pub use error::CaError;
pub use ssh::{SshCa, SshCaStatus};
pub use trust::{install_root_ca, is_root_ca_installed, uninstall_root_ca};
pub use x509::{IssuedCertPair, X509Ca, X509CaStatus};

use serde::{Deserialize, Serialize};

/// Comprehensive status summary of both OpenSSH and X.509 CA engines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedCaStatus {
    pub ssh: SshCaStatus,
    pub x509: X509CaStatus,
}

/// Returns the status of both OpenSSH and X.509 Certificate Authorities.
pub fn status() -> Result<UnifiedCaStatus, CaError> {
    Ok(UnifiedCaStatus {
        ssh: SshCa::status(),
        x509: X509Ca::status()?,
    })
}

/// Initializes both OpenSSH CA and X.509 Root CA.
pub fn init_all(force: bool) -> Result<UnifiedCaStatus, CaError> {
    let ssh = SshCa::init_ca(force)?;
    let x509 = X509Ca::init_root_ca(force)?;
    Ok(UnifiedCaStatus { ssh, x509 })
}
