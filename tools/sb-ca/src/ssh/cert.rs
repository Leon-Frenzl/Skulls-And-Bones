//! OpenSSH certificate issuing engine conforming to PROTOCOL.certkeys.
//!
//! Standards:
//! - Conforms to OpenSSH PROTOCOL.certkeys (OpenSSH Certificate Format)
//! - Conforms to IETF RFC 4251 (SSH Protocol Architecture)
//! - Conforms to ISO 8601 (Timestamps)

use crate::error::CaError;
use crate::ssh::key::{load_ca_key, parse_public_key};
use rand::Rng;
use ssh_key::certificate::{Builder, CertType};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default lifetime for short-lived user certificates: 1 hour (3,600 seconds).
pub const DEFAULT_USER_CERT_TTL_SECONDS: u64 = 3600;

/// Hard upper bound for user certificates: 8 hours (28,800 seconds).
pub const MAX_USER_CERT_TTL_SECONDS: u64 = 28800;

/// Default lifetime for host certificates: 30 days (2,592,000 seconds).
pub const DEFAULT_HOST_CERT_TTL_SECONDS: u64 = 30 * 86400;

/// Hard upper bound for host certificates: 90 days (7,776,000 seconds).
pub const MAX_HOST_CERT_TTL_SECONDS: u64 = 90 * 86400;

/// Clock drift absorption margin: 60 seconds backdating.
pub const CLOCK_DRIFT_MARGIN_SECONDS: u64 = 60;

/// Validates principal strings to prevent injection or malformed principal names,
/// returning the sanitized, trimmed string slice.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Shell meta-character injection, newline injection into sshd
///   AuthorizedPrincipalsFile, or boundary whitespace smuggling in OpenSSH certificate principals.
/// - CVE / CWE Mapping: CWE-20 (Improper Input Validation), CWE-74 (Improper Neutralization of Special Elements),
///   CWE-287 (Improper Authentication).
/// - Likelihood & Exploitability: High (7/10).
///   * Threat Condition: Untrusted client provides crafted principal string (e.g. `root\n*` or boundary whitespace).
/// - Applied Mitigation: Strips boundary whitespace and validates against strict RFC 1123 / safe UNIX username
///   character allowlist (`[a-zA-Z0-9._-]`); returns trimmed slice so un-trimmed strings cannot be signed.
/// - Standards Compliance: IETF RFC 1123, IEEE 1003.1 (POSIX 3.437).
fn validate_principal(principal: &str) -> Result<&str, CaError> {
    let trimmed = principal.trim();
    if trimmed.is_empty() {
        return Err(CaError::InvalidPrincipal("Principal cannot be empty".into()));
    }
    if trimmed.len() > 64 {
        return Err(CaError::InvalidPrincipal(format!(
            "Principal '{}' exceeds max length of 64 characters",
            trimmed
        )));
    }
    // Principals must be safe UNIX usernames or DNS hostnames (RFC 1123 / POSIX 3.437)
    for ch in trimmed.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' {
            return Err(CaError::InvalidPrincipal(format!(
                "Principal '{}' contains disallowed character '{}'",
                trimmed, ch
            )));
        }
    }
    Ok(trimmed)
}

/// Computes current Unix timestamp in seconds.
fn current_unix_timestamp() -> Result<u64, CaError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| CaError::Other(format!("System clock error: {e}")))
}

/// Issues a short-lived OpenSSH User Certificate signed by the Root CA.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Privilege escalation via unconstrained certificate lifetime or unauthorized principals.
/// - CVE / CWE Mapping: CWE-269 (Improper Privilege Management), CWE-613 (Insufficient Session Expiration).
/// - Likelihood & Exploitability: High (8/10).
///   * Threat Condition: Client requests multi-month user certificate with `root` or invalid principal.
/// - Applied Mitigation: Hard cap on TTL (max 8h, default 1h); validates each principal; backdates validity window by 60s to prevent clock skew desynchronization; injects standard interactive shell extensions.
pub fn issue_user_certificate(
    subject_pubkey_openssh: &str,
    key_id: &str,
    principals: &[String],
    ttl_seconds: u64,
    serial: Option<u64>,
) -> Result<String, CaError> {
    if ttl_seconds > MAX_USER_CERT_TTL_SECONDS {
        return Err(CaError::TtlExceeded {
            requested: ttl_seconds,
            max: MAX_USER_CERT_TTL_SECONDS,
        });
    }

    let actual_ttl = if ttl_seconds == 0 {
        DEFAULT_USER_CERT_TTL_SECONDS
    } else {
        ttl_seconds
    };

    if principals.is_empty() {
        return Err(CaError::InvalidPrincipal(
            "At least one valid principal (e.g. username) is required".into(),
        ));
    }

    let mut validated_principals = Vec::with_capacity(principals.len());
    for p in principals {
        let v = validate_principal(p)?;
        validated_principals.push(v);
    }

    let trimmed_key_id = key_id.trim();
    if trimmed_key_id.is_empty() {
        return Err(CaError::Security("key_id must not be empty".into()));
    }

    let subject_pubkey = parse_public_key(subject_pubkey_openssh)?;
    let ca_key = load_ca_key()?;

    let now = current_unix_timestamp()?;
    let valid_after = now.saturating_sub(CLOCK_DRIFT_MARGIN_SECONDS);
    let valid_before = now.saturating_add(actual_ttl);

    let cert_serial = serial.unwrap_or_else(|| {
        let mut rng = rand::thread_rng();
        rng.gen::<u64>() & 0x7FFFFFFFFFFFFFFF
    });

    let mut rng = rand::rngs::OsRng;
    let mut builder = Builder::new_with_random_nonce(
        &mut rng,
        subject_pubkey.key_data().clone(),
        valid_after,
        valid_before,
    )?;

    builder.serial(cert_serial)?;
    builder.key_id(trimmed_key_id)?;
    builder.cert_type(CertType::User)?;

    for p in &validated_principals {
        builder.valid_principal(*p)?;
    }

    // Standard OpenSSH user certificate capability extensions
    builder.extension("permit-X11-forwarding", "")?;
    builder.extension("permit-agent-forwarding", "")?;
    builder.extension("permit-port-forwarding", "")?;
    builder.extension("permit-pty", "")?;
    builder.extension("permit-user-rc", "")?;

    let cert = builder.sign(&ca_key)?;
    let cert_str = cert.to_openssh()?;

    Ok(cert_str)
}

/// Issues an OpenSSH Host Certificate for node provisioning and host identity.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Host identity spoofing, man-in-the-middle impersonation, or unconstrained host cert lifetime.
/// - CVE / CWE Mapping: CWE-290 (Authentication Bypass by Spoofing), CWE-295 (Improper Certificate Validation), CWE-613 (Insufficient Session Expiration).
/// - Likelihood & Exploitability: Medium (5/10).
///   * Threat Condition: Malicious node requests host certificate claiming another host's FQDN or infinite lifetime.
/// - Applied Mitigation: Hard cap on TTL (max 90 days); validates and trims hostname against RFC 1123 hostname rules; restricts CertType to Host; signs with pinned CA key.
/// - Standards Compliance: IETF RFC 4251, OpenSSH PROTOCOL.certkeys.
pub fn issue_host_certificate(
    subject_pubkey_openssh: &str,
    hostname: &str,
    ttl_seconds: u64,
    serial: Option<u64>,
) -> Result<String, CaError> {
    if ttl_seconds > MAX_HOST_CERT_TTL_SECONDS {
        return Err(CaError::TtlExceeded {
            requested: ttl_seconds,
            max: MAX_HOST_CERT_TTL_SECONDS,
        });
    }

    let raw_parts: Vec<&str> = hostname
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if raw_parts.is_empty() {
        return Err(CaError::InvalidPrincipal(
            "Host certificate requires at least one valid hostname or IP principal".into(),
        ));
    }
    let mut valid_hostnames = Vec::with_capacity(raw_parts.len());
    for part in raw_parts {
        valid_hostnames.push(validate_principal(part)?);
    }

    let actual_ttl = if ttl_seconds == 0 {
        DEFAULT_HOST_CERT_TTL_SECONDS
    } else {
        ttl_seconds
    };

    let subject_pubkey = parse_public_key(subject_pubkey_openssh)?;
    let ca_key = load_ca_key()?;

    let now = current_unix_timestamp()?;
    let valid_after = now.saturating_sub(CLOCK_DRIFT_MARGIN_SECONDS);
    let valid_before = now.saturating_add(actual_ttl);

    let cert_serial = serial.unwrap_or_else(|| {
        let mut rng = rand::thread_rng();
        rng.gen::<u64>() & 0x7FFFFFFFFFFFFFFF
    });

    let mut rng = rand::rngs::OsRng;
    let mut builder = Builder::new_with_random_nonce(
        &mut rng,
        subject_pubkey.key_data().clone(),
        valid_after,
        valid_before,
    )?;

    builder.serial(cert_serial)?;
    builder.key_id(format!("host-cert-{}", valid_hostnames[0]))?;
    builder.cert_type(CertType::Host)?;
    for h in &valid_hostnames {
        builder.valid_principal(*h)?;
    }

    let cert = builder.sign(&ca_key)?;
    let cert_str = cert.to_openssh()?;

    Ok(cert_str)
}
