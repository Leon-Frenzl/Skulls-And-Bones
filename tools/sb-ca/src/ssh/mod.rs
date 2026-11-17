//! OpenSSH Certificate Authority Engine module.
//!
//! Standards:
//! - Conforms to OpenSSH PROTOCOL.certkeys
//! - Conforms to IETF RFC 4251
//! - Conforms to IETF RFC 8709

pub mod cert;
pub mod key;

pub use cert::{
    issue_host_certificate, issue_user_certificate, DEFAULT_HOST_CERT_TTL_SECONDS,
    DEFAULT_USER_CERT_TTL_SECONDS, MAX_HOST_CERT_TTL_SECONDS, MAX_USER_CERT_TTL_SECONDS,
};
pub use key::{ca_public_key_openssh, init_ssh_ca, load_ca_key, parse_public_key, SSH_CA_COMMENT};

use crate::error::CaError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCaStatus {
    pub initialized: bool,
    pub ca_key_path: String,
    pub ca_pub_path: String,
    pub public_key: Option<String>,
}

/// High-level OpenSSH Certificate Authority interface.
pub struct SshCa;

impl SshCa {
    /// Initializes the OpenSSH Root CA keypair.
    pub fn init_ca(force: bool) -> Result<SshCaStatus, CaError> {
        let pub_line = init_ssh_ca(force)?;
        Ok(SshCaStatus {
            initialized: true,
            ca_key_path: crate::paths::ssh_ca_key_path().display().to_string(),
            ca_pub_path: crate::paths::ssh_ca_pub_path().display().to_string(),
            public_key: Some(pub_line),
        })
    }

    /// Returns the public key in standard OpenSSH wire format for `TrustedUserCAKeys`.
    pub fn ca_public_key_openssh() -> Result<String, CaError> {
        ca_public_key_openssh()
    }

    /// Issues a short-lived user certificate for ssh authentication.
    pub fn issue_user_certificate(
        subject_pubkey_openssh: &str,
        key_id: &str,
        principals: &[String],
        ttl_seconds: u64,
        serial: Option<u64>,
    ) -> Result<String, CaError> {
        issue_user_certificate(subject_pubkey_openssh, key_id, principals, ttl_seconds, serial)
    }

    /// Issues a host certificate for host identification.
    pub fn issue_host_certificate(
        subject_pubkey_openssh: &str,
        hostname: &str,
        ttl_seconds: u64,
        serial: Option<u64>,
    ) -> Result<String, CaError> {
        issue_host_certificate(subject_pubkey_openssh, hostname, ttl_seconds, serial)
    }

    /// Returns status report for OpenSSH CA.
    pub fn status() -> SshCaStatus {
        let priv_path = crate::paths::ssh_ca_key_path();
        let pub_path = crate::paths::ssh_ca_pub_path();
        let initialized = priv_path.exists() && pub_path.exists();
        let public_key = ca_public_key_openssh().ok();

        SshCaStatus {
            initialized,
            ca_key_path: priv_path.display().to_string(),
            ca_pub_path: pub_path.display().to_string(),
            public_key,
        }
    }
}
