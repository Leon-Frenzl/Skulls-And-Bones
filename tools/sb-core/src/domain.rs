use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Target operating system of a domain-joined machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsKind {
    Linux,
    Windows,
    MacOs,
}

impl OsKind {
    /// Detects the current host operating system at compile time.
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOs
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            Self::Linux
        }
    }
}

impl std::fmt::Display for OsKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Linux => write!(f, "linux"),
            Self::Windows => write!(f, "windows"),
            Self::MacOs => write!(f, "macos"),
        }
    }
}

/// Validates a single DNS host label (RFC 1123 §2.1).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Path traversal (`../`), shell metacharacters, or DNS label
///   injection when generating hostnames, certificate SANs, and local filesystem paths.
/// - **CVE / CWE Mapping:** CWE-20 (Improper Input Validation) / CWE-22 (Path Traversal).
/// - **Likelihood & Exploitability:** High (8/10) if untrusted hostnames reach CA SANs or file paths.
/// - **Applied Mitigation:** Enforces strict RFC 1123 ASCII alphanumeric + hyphen bounds (1..=63 chars,
///   no leading/trailing hyphen) and normalizes to lowercase.
// Conforms to RFC 1123 §2.1
pub fn validate_hostname(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 63 {
        return Err("Hostname must be between 1 and 63 characters".to_string());
    }
    if trimmed.starts_with('-') || trimmed.ends_with('-') {
        return Err("Hostname must not start or end with '-'".to_string());
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(
            "Hostname must contain only ASCII lowercase letters, digits, and '-'".to_string(),
        );
    }
    Ok(trimmed)
}

/// Validates a domain name (RFC 1035 / RFC 1123) for domain join and DNS registration.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Wildcard injection (`*.corp`), dotfile traversal (`..`), or
///   malformed DNS names used to hijack domain zones or X.509 SANs.
/// - **CVE / CWE Mapping:** CWE-20 (Improper Input Validation) / CWE-295 (Improper Certificate Validation).
/// - **Likelihood & Exploitability:** High (8/10) on domain join / CA issuance paths.
/// - **Applied Mitigation:** Validates total length (<= 253), splits into labels, and validates each
///   label against RFC 1123 rules; rejects empty labels, trailing dots after normalization, and wildcards.
// Conforms to RFC 1035 §2.3.4 / RFC 1123 §2.1
pub fn validate_domain_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err("Domain name must be between 1 and 253 characters".to_string());
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 2 {
        return Err("Domain name must have at least two labels (e.g. corp.sbm)".to_string());
    }
    for label in labels {
        validate_hostname(label)?;
    }
    Ok(trimmed)
}

/// Request sent by a machine (authorized by an `sb-auth` user token) to join a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainJoinRequest {
    pub hostname: String,
    pub domain: String,
    pub os: OsKind,
    /// URL-safe Base64 Ed25519 public key generated locally on the joining machine.
    pub machine_public_key_b64: String,
    /// Optional OpenSSH Ed25519 host public key (`ssh-ed25519 AAAA...`) for host cert signing.
    pub ssh_host_public_key: Option<String>,
    /// Optional requested mesh IPv4 address (assigned automatically if `None`).
    pub mesh_ip: Option<String>,
    /// `sbt.*` Sovereign Token of the user authorizing this machine join.
    pub join_token: String,
}

/// Response returned by the Domain Controller upon a successful, authorized join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainJoinResponse {
    pub machine_id: String,
    pub fqdn: String,
    pub domain: String,
    pub joined_by: String,
    pub mesh_ip: String,
    pub dns_server: String,
    pub device_cert_pem: String,
    pub root_ca_pem: String,
    pub ssh_host_cert: Option<String>,
    pub ssh_user_ca_pubkey: String,
    pub joined_at: String,
}

/// Record of a joined machine stored in the Domain Controller's registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineRecord {
    pub machine_id: String,
    pub hostname: String,
    pub domain: String,
    pub fqdn: String,
    pub os: OsKind,
    pub machine_public_key_b64: String,
    pub mesh_ip: String,
    pub joined_by: String,
    pub joined_at: String,
    pub revoked: bool,
    pub revoked_reason: Option<String>,
}

/// Local state persisted on a domain-joined machine under `~/.sb/domain/machine.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinedMachineState {
    pub machine_id: String,
    pub fqdn: String,
    pub domain: String,
    pub os: OsKind,
    pub joined_by: String,
    pub mesh_ip: String,
    pub dns_server: String,
    pub device_cert_pem: String,
    pub root_ca_pem: String,
    pub ssh_user_ca_pubkey: String,
    pub joined_at: String,
}

/// Returns the local domain state directory (`~/.sb/domain`).
pub fn local_domain_dir() -> PathBuf {
    crate::paths::sb_home().join("domain")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_and_domain_validation_rejects_traversal_and_wildcards() {
        assert_eq!(validate_hostname("Web-01").unwrap(), "web-01");
        assert!(validate_hostname("../etc").is_err());
        assert!(validate_hostname("-bad").is_err());
        assert!(validate_hostname("bad-").is_err());
        assert!(validate_hostname("").is_err());

        assert_eq!(validate_domain_name("Corp.SBM.").unwrap(), "corp.sbm");
        assert!(validate_domain_name("*.corp.sbm").is_err());
        assert!(validate_domain_name("singlelabel").is_err());
        assert!(validate_domain_name("corp..sbm").is_err());
    }
}
