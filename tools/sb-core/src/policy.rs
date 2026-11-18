//! Cross-platform, signed Group Policy Object (GPO) models and canonical validation.
//!
//! Designed to be shared between `sb-node` (DC & machine agent), `sb-proxy` (Open Graph API
//! gateway), and developer SDKs. Conforms to RFC 8259 (JSON) and RFC 3339 (timestamps).

use crate::domain::{validate_domain_name, OsKind};
use serde::{Deserialize, Serialize};

/// Maximum allowed length for a policy identifier.
pub const MAX_POLICY_ID_LEN: usize = 64;

/// Maximum allowed rules per policy document to prevent resource exhaustion.
pub const MAX_RULES_PER_POLICY: usize = 128;

/// Validates a developer-friendly policy identifier (`[a-z0-9][a-z0-9_-]{0,63}`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Path traversal (`../`), control characters, or oversized IDs
///   injected into `/v1/policies/{id}` or local policy filenames.
/// - **CVE / CWE Mapping:** CWE-22 (Path Traversal), CWE-20 (Improper Input Validation).
/// - **Likelihood & Exploitability:** Medium (6/10) if exposed over the remote policy API.
/// - **Applied Mitigation:** Strict allowlist of lowercase ASCII alphanumerics, `-`, and `_`,
///   starting with an alphanumeric character and bounded to 64 bytes.
///
/// # Standards Compliance
/// - Conforms to RFC 3986 §2.3 unreserved URL path segment characters.
pub fn validate_policy_id(id: &str) -> Result<String, String> {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_POLICY_ID_LEN {
        return Err(format!(
            "Policy ID must be 1..={MAX_POLICY_ID_LEN} characters"
        ));
    }
    let bytes = trimmed.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err("Policy ID must start with a lowercase ASCII letter or digit".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(
            "Policy ID may only contain lowercase ASCII letters, digits, '-' and '_'".into(),
        );
    }
    Ok(trimmed.to_string())
}

/// Validates a sysctl key (`[a-zA-Z0-9._-]+`) and single-line value to prevent config injection.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Newline or directive injection into `/etc/sysctl.d/*.conf`.
/// - **CVE / CWE Mapping:** CWE-74 (Improper Neutralization of Special Elements in Output).
/// - **Likelihood & Exploitability:** High (7/10) if untrusted policy values reach OS config files.
/// - **Applied Mitigation:** Strict character allowlist on keys and rejection of CR/LF/NUL/`;`
///   characters in values.
pub fn validate_sysctl_pair(key: &str, value: &str) -> Result<(), String> {
    let k = key.trim();
    let v = value.trim();
    if k.is_empty()
        || k.len() > 128
        || !k
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(format!("Invalid sysctl key: '{key}'"));
    }
    if v.is_empty()
        || v.len() > 128
        || v.chars()
            .any(|c| c == '\n' || c == '\r' || c == '\0' || c == ';')
    {
        return Err(format!("Invalid sysctl value for '{key}'"));
    }
    Ok(())
}

/// Scope at which a policy applies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "target", rename_all = "snake_case")]
pub enum PolicyScope {
    Domain,
    Ou(String),
    Machine(String),
}

/// Declarative, cross-platform policy rule (no arbitrary shell commands).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyRule {
    /// Enforces modern OpenSSH daemon hardening (certificate/key auth only).
    SshHardening {
        password_auth: bool,
        permit_root_login: bool,
        trusted_user_ca_keys: bool,
    },
    /// Configures host firewall baseline (default-deny inbound + explicit allow ports).
    FirewallBaseline {
        default_deny_inbound: bool,
        allow_ports: Vec<u16>,
    },
    /// Configures split-DNS resolution for sovereign domain suffixes over the mesh.
    DnsSplitZone {
        domains: Vec<String>,
        nameservers: Vec<String>,
    },
    /// Enforces a kernel/OS sysctl parameter (Linux/macOS).
    SysctlSetting { key: String, value: String },
    /// Enforces screen-lock / idle-session timeout across desktop/workstation OSes.
    ScreenLock {
        idle_timeout_seconds: u32,
        require_password: bool,
    },
}

impl PolicyRule {
    /// Validates all fields of a declarative policy rule before persistence or signing.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** Malformed domain names, invalid port 0, or newline injection
    ///   in generated OS configuration files (`sshd_config`, `resolved.conf`, `sysctl.conf`).
    /// - **CVE / CWE Mapping:** CWE-20 (Improper Input Validation), CWE-74 (Output Injection).
    /// - **Likelihood & Exploitability:** High (7/10) without pre-sign validation.
    /// - **Applied Mitigation:** Exhaustive variant validation before signing or rendering.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            PolicyRule::SshHardening { .. } => Ok(()),
            PolicyRule::FirewallBaseline { allow_ports, .. } => {
                if allow_ports.contains(&0) {
                    return Err("Firewall allow_ports cannot contain port 0".into());
                }
                Ok(())
            }
            PolicyRule::DnsSplitZone {
                domains,
                nameservers,
            } => {
                if domains.is_empty() || nameservers.is_empty() {
                    return Err("DnsSplitZone requires at least one domain and nameserver".into());
                }
                for d in domains {
                    validate_domain_name(d)?;
                }
                for ns in nameservers {
                    if ns.parse::<std::net::IpAddr>().is_err() {
                        return Err(format!("Invalid nameserver IP '{ns}'"));
                    }
                }
                Ok(())
            }
            PolicyRule::SysctlSetting { key, value } => validate_sysctl_pair(key, value),
            PolicyRule::ScreenLock {
                idle_timeout_seconds,
                ..
            } => {
                if *idle_timeout_seconds == 0 || *idle_timeout_seconds > 86_400 {
                    return Err("idle_timeout_seconds must be within 1..=86400".into());
                }
                Ok(())
            }
        }
    }
}

/// A single versioned Group Policy Object (GPO) document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDocument {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub version: u64,
    pub scope: PolicyScope,
    /// Empty means all OSes (`Linux`, `Windows`, `MacOs`).
    #[serde(default)]
    pub target_os: Vec<OsKind>,
    pub rules: Vec<PolicyRule>,
    pub updated_at: String,
    pub updated_by: String,
}

impl PolicyDocument {
    /// Validates the policy document ID, rules count, and every contained rule.
    pub fn validate(&self) -> Result<(), String> {
        validate_policy_id(&self.id)?;
        if self.name.trim().is_empty() || self.name.len() > 128 {
            return Err("Policy name must be 1..=128 characters".into());
        }
        if self.rules.len() > MAX_RULES_PER_POLICY {
            return Err(format!("Policy cannot exceed {MAX_RULES_PER_POLICY} rules"));
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }

    /// Returns `true` if this policy applies to the given operating system.
    pub fn applies_to_os(&self, os: OsKind) -> bool {
        self.target_os.is_empty() || self.target_os.contains(&os)
    }

    /// Returns `true` if this policy's scope matches the target machine/OU.
    pub fn applies_to_scope(&self, machine_id: &str, fqdn: Option<&str>, ou: Option<&str>) -> bool {
        match &self.scope {
            PolicyScope::Domain => true,
            PolicyScope::Ou(target_ou) => {
                ou.is_some_and(|m_ou| m_ou.eq_ignore_ascii_case(target_ou))
            }
            PolicyScope::Machine(target_machine) => {
                target_machine.eq_ignore_ascii_case(machine_id)
                    || fqdn.is_some_and(|f| f.eq_ignore_ascii_case(target_machine))
            }
        }
    }
}

/// Canonical unsigned payload used for Ed25519 signing and verification.
#[derive(Debug, Serialize)]
pub struct PolicyBundlePayload<'a> {
    pub domain: &'a str,
    pub revision: u64,
    pub issued_at: &'a str,
    pub expires_at: &'a str,
    pub policies: &'a [PolicyDocument],
}

/// Ed25519-signed policy bundle distributed to domain-joined machines (online & offline).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPolicyBundle {
    pub domain: String,
    pub revision: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub policies: Vec<PolicyDocument>,
    pub authority_pubkey_b64: String,
    pub signature_b64: String,
}

impl SignedPolicyBundle {
    /// Produces the deterministic canonical JSON byte representation covered by `signature_b64`.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** Signature malleability or canonicalization mismatch between
    ///   signer and verifier.
    /// - **CVE / CWE Mapping:** CWE-347 (Improper Verification of Cryptographic Signature).
    /// - **Likelihood & Exploitability:** Medium (5/10) if signer/verifier serialize differently.
    /// - **Applied Mitigation:** Single shared serialization helper (`PolicyBundlePayload`) used
    ///   by both signing and verification paths.
    ///
    /// # Standards Compliance
    /// - Conforms to RFC 8259 (JSON) deterministic field ordering via struct layout.
    pub fn canonical_payload_bytes(
        domain: &str,
        revision: u64,
        issued_at: &str,
        expires_at: &str,
        policies: &[PolicyDocument],
    ) -> Result<Vec<u8>, String> {
        let payload = PolicyBundlePayload {
            domain,
            revision,
            issued_at,
            expires_at,
            policies,
        };
        serde_json::to_vec(&payload).map_err(|e| format!("Failed to serialize policy payload: {e}"))
    }
}

/// Outcome of a single policy rule application or dry-run evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRuleResult {
    pub policy_id: String,
    pub rule_kind: String,
    pub action: String,
    pub target_path: Option<String>,
}

/// Structured report returned by `POST /v1/policies/apply` and `sb-node policy apply`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyApplyReport {
    pub machine_id: String,
    pub os: OsKind,
    pub bundle_revision: u64,
    pub dry_run: bool,
    pub applied: Vec<PolicyRuleResult>,
    pub skipped: Vec<PolicyRuleResult>,
    pub applied_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_id_and_rule_validation_rejects_traversal_and_injection() {
        assert!(validate_policy_id("baseline-ssh").is_ok());
        assert!(validate_policy_id("../evil").is_err());
        assert!(validate_policy_id("UpperCase").is_err());
        assert!(validate_policy_id("-leading-dash").is_err());

        let bad_sysctl = PolicyRule::SysctlSetting {
            key: "net.ipv4.ip_forward".into(),
            value: "1\nkernel.evil=1".into(),
        };
        assert!(bad_sysctl.validate().is_err());

        let bad_dns = PolicyRule::DnsSplitZone {
            domains: vec!["corp.eu".into()],
            nameservers: vec!["not-an-ip".into()],
        };
        assert!(bad_dns.validate().is_err());

        let good_dns = PolicyRule::DnsSplitZone {
            domains: vec!["corp.eu".into()],
            nameservers: vec!["10.42.0.1".into()],
        };
        assert!(good_dns.validate().is_ok());
    }
}
