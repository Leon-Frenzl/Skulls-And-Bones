//! Error types for the S&B Unified PKI Engine (`sb-ca`).
//!
//! Standards:
//! - Conforms to IETF RFC 4251 (SSH Protocol Architecture)
//! - Conforms to OpenSSH PROTOCOL.certkeys (OpenSSH Certificate Format)
//! - Conforms to IETF RFC 5280 (X.509 PKI Certificate and CRL Profile)
//! - Conforms to IETF RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3)

use thiserror::Error;

/// Core error enumeration covering SSH, X.509, filesystem, and cryptographic operations.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Error information leakage or ambiguous error codes leading to fail-open logic.
/// - CVE / CWE Mapping: CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-754 (Improper Check for Unusual or Exceptional Conditions).
/// - Likelihood & Exploitability: Low (2/10).
///   * Threat Condition: Sensitive private key material inadvertently surfaced in error strings.
/// - Applied Mitigation: Redacted error messages; cryptographic secrets are never formatted into errors.
#[derive(Error, Debug)]
pub enum CaError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("OpenSSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("X.509 rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid subject public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid principal name '{0}': must not be empty or contain control characters")]
    InvalidPrincipal(String),

    #[error("Invalid domain name '{0}': must be valid RFC 1123 hostname or sanctioned wildcard")]
    InvalidDomain(String),

    #[error("Requested TTL {requested}s exceeds maximum permitted lifetime of {max}s (CWE-613)")]
    TtlExceeded { requested: u64, max: u64 },

    #[error("CA is not initialized under '{path}'. Run 'sb-ca init' first.")]
    NotInitialized { path: String },

    #[error("OS certificate trust store error: {0}")]
    TrustStore(String),

    #[error("Security or validation error: {0}")]
    Security(String),

    #[error("Generic CA error: {0}")]
    Other(String),
}
