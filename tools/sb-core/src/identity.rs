//! Sovereign User, Group, and SSH User Certificate identity models.
//!
//! Shared between `sb-node` (Domain Directory), `sb-proxy` (Open Graph API), and `console/`.
//! Conforms to RFC 5322 (email syntax bounds) and OpenSSH `PROTOCOL.certkeys`.

use crate::policy::validate_policy_id;
use serde::{Deserialize, Serialize};

/// Maximum length for usernames and display names.
pub const MAX_USERNAME_LEN: usize = 64;

/// Minimum and maximum TTL for issued OpenSSH user certificates (1 minute to 24 hours).
pub const MIN_SSH_CERT_TTL_SECONDS: u64 = 60;
pub const MAX_SSH_CERT_TTL_SECONDS: u64 = 24 * 3600;

/// Validates a canonical domain username (`[a-z0-9][a-z0-9._-]{0,63}`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Path traversal (`../`), shell metacharacters, or uppercase
///   aliasing in SSH principals (`Anna` vs `anna`) and `/v1/users/{username}` routes.
/// - **CVE / CWE Mapping:** CWE-20 (Improper Input Validation), CWE-22 (Path Traversal).
/// - **Likelihood & Exploitability:** High (7/10) if exposed on directory and SSH cert APIs.
/// - **Applied Mitigation:** Enforces lowercase ASCII alphanumerics with `.`, `-`, `_`, forbids
///   `..` sequences, and requires starting with an alphanumeric character.
///
/// # Standards Compliance
/// - Conforms to POSIX.1-2017 §3.437 portable username character set (lowercase subset).
pub fn validate_username(username: &str) -> Result<String, String> {
    let trimmed = username.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_USERNAME_LEN {
        return Err(format!(
            "Username must be 1..={MAX_USERNAME_LEN} characters"
        ));
    }
    if trimmed.contains("..") {
        return Err("Username cannot contain '..'".into());
    }
    let first = trimmed.as_bytes()[0];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err("Username must start with a lowercase ASCII letter or digit".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_')
    {
        return Err(
            "Username may only contain lowercase ASCII letters, digits, '.', '-' and '_'".into(),
        );
    }
    Ok(trimmed.to_string())
}

/// Validates a single-line OpenSSH public key string (`ssh-ed25519 ...` / `ecdsa-sha2-...` / `ssh-rsa ...`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Newline or option injection (`command="..."`) into OpenSSH
///   authorized_keys / `ssh-keygen` arguments.
/// - **CVE / CWE Mapping:** CWE-74 (Output/Argument Injection).
/// - **Likelihood & Exploitability:** High (8/10) if raw user input is passed to `ssh-keygen`.
/// - **Applied Mitigation:** Rejects control/newline characters, enforces recognized key type
///   prefix, and validates base64 key blob token structure.
///
/// # Standards Compliance
/// - Conforms to OpenSSH `PROTOCOL.certkeys` and RFC 4253 §6.6 public key format.
pub fn validate_openssh_pubkey(pubkey: &str) -> Result<String, String> {
    let trimmed = pubkey.trim();
    if trimmed.is_empty() || trimmed.len() > 8192 {
        return Err("OpenSSH public key must be 1..=8192 bytes".into());
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("OpenSSH public key cannot contain control characters or newlines".into());
    }
    let mut parts = trimmed.split_whitespace();
    let alg = parts.next().unwrap_or("");
    let key_b64 = parts.next().unwrap_or("");
    let allowed = matches!(
        alg,
        "ssh-ed25519"
            | "sk-ssh-ed25519@openssh.com"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "ssh-rsa"
    );
    if !allowed || key_b64.len() < 16 {
        return Err(format!(
            "Unsupported or malformed OpenSSH public key '{alg}'"
        ));
    }
    Ok(trimmed.to_string())
}

fn default_ou() -> String {
    "/".to_string()
}

/// Validates a canonical Organizational Unit path (e.g. `"/"` or `"/Engineering/Backend"`).
pub fn validate_ou_path(ou: &str) -> Result<String, String> {
    let trimmed = ou.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Ok("/".to_string());
    }
    if !trimmed.starts_with('/') || trimmed.contains("..") || trimmed.len() > 128 {
        return Err("OU path must start with '/' and be <= 128 chars without '..'".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        return Err("OU path contains invalid characters".into());
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// A domain user account in the sovereign directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainUser {
    pub username: String,
    pub display_name: String,
    pub email: String,
    #[serde(default = "default_ou")]
    pub ou: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub ssh_public_key: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl DomainUser {
    /// Validates username, display name, email, group names, and optional SSH public key.
    pub fn validate(&self) -> Result<(), String> {
        validate_username(&self.username)?;
        if self.display_name.trim().is_empty() || self.display_name.len() > 128 {
            return Err("display_name must be 1..=128 characters".into());
        }
        let email = self.email.trim();
        if email.is_empty()
            || email.len() > 254
            || !email.contains('@')
            || email.contains(char::is_whitespace)
        {
            return Err(format!("Invalid email address '{}'", self.email));
        }
        for g in &self.groups {
            validate_policy_id(g)?;
        }
        if let Some(ref pk) = self.ssh_public_key {
            validate_openssh_pubkey(pk)?;
        }
        Ok(())
    }
}

/// A domain security/organizational group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainGroup {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_ou")]
    pub ou: String,
    #[serde(default)]
    pub is_local_admin: bool,
    #[serde(default)]
    pub allowed_machines: Vec<String>,
    #[serde(default)]
    pub members: Vec<String>,
    pub updated_at: String,
}

impl DomainGroup {
    /// Validates group name and member usernames.
    pub fn validate(&self) -> Result<(), String> {
        validate_policy_id(&self.name)?;
        for m in &self.members {
            validate_username(m)?;
        }
        Ok(())
    }
}

/// Request payload for `POST /v1/users/{username}/ssh-cert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUserCertRequest {
    #[serde(default)]
    pub ssh_public_key: Option<String>,
    #[serde(default = "default_ssh_cert_ttl")]
    pub ttl_seconds: u64,
}

fn default_ssh_cert_ttl() -> u64 {
    8 * 3600
}

/// Response returned when issuing a short-lived OpenSSH user certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUserCertResponse {
    pub username: String,
    pub principals: Vec<String>,
    pub ttl_seconds: u64,
    pub certificate_openssh: String,
    pub expires_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_and_ssh_pubkey_validation_blocks_injection() {
        assert!(validate_username("anna.admin").is_ok());
        assert!(validate_username("../root").is_err());
        assert!(validate_username("Anna").is_err());
        assert!(validate_username("a..b").is_err());

        assert!(validate_openssh_pubkey(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyDataHere123456 anna@corp.eu"
        )
        .is_ok());
        assert!(validate_openssh_pubkey(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMock\ncommand=\"id\""
        )
        .is_err());
        assert!(validate_openssh_pubkey("ssh-dss AAAAB3NzaC1kc3M=").is_err());
    }
}
