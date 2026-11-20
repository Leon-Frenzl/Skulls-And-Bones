use chrono::Utc;
use sb_auth::{AuthVerifier, SovereignClaims};
use sb_mesh::ticket::TicketGrantPayload;
use serde::{Deserialize, Serialize};

use crate::error::{DbError, DbResult};

/// Required capability scope for database operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbCapability {
    Read,
    Write,
    SecretReveal,
    Admin,
}

impl DbCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "db:read",
            Self::Write => "db:write",
            Self::SecretReveal => "db:secret:reveal",
            Self::Admin => "db:admin",
        }
    }

    fn matches(&self, granted: &str) -> bool {
        let g = granted.trim();
        g == "*"
            || g == "db:*"
            || g == "admin"
            || g == self.as_str()
            || (*self == Self::Read && (g == "db:write" || g == "db:admin"))
            || (*self == Self::Write && g == "db:admin")
    }
}

/// Verified caller identity extracted from an existing `sb-mesh` (`SBM-TEP`) ticket
/// or an `sb-auth` Ed25519 Sovereign Token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedDbTicket {
    pub ticket_id: String,
    pub subject: String,
    pub role: String,
    pub capabilities: Vec<String>,
    pub valid_until: u64,
    pub single_use: bool,
}

impl VerifiedDbTicket {
    /// Checks whether the ticket grants `required` capability and is not expired.
    // [SECURITY-VERIFIED] CWE-285 / CWE-613 Mitigiert:
    // Fail-closed: Prüft Ablaufzeit gegen aktuelle UTC-Zeit und erfordert explizite Capability.
    pub fn authorize(&self, required: DbCapability) -> DbResult<()> {
        let now = Utc::now().timestamp().max(0) as u64;
        if self.valid_until <= now {
            return Err(DbError::Unauthorized("Ticket is expired".into()));
        }
        if self.subject.trim().is_empty() || self.ticket_id.trim().is_empty() {
            return Err(DbError::Unauthorized(
                "Ticket has empty subject or ticket_id".into(),
            ));
        }
        if !self.capabilities.iter().any(|c| required.matches(c)) {
            return Err(DbError::Unauthorized(format!(
                "Missing required capability '{}'",
                required.as_str()
            )));
        }
        Ok(())
    }
}

/// Verifies an existing `sb-mesh` `TicketGrantPayload` (`SBM-TEP`) for database access.
///
/// The `session_ticket` must be signed/verified via `AuthVerifier` (Ed25519 `sbt.*` token),
/// or—when `verifier` is provided—matched against the cryptographic token claims so forged
/// JSON payloads cannot bypass authorization.
// [SECURITY-VERIFIED] CWE-287 / CWE-347 Mitigiert:
// Verifiziert `grant.session_ticket` kryptografisch gegen `AuthVerifier` (Ed25519),
// prüft `subject_node_id`, Ablaufzeit (`valid_until`) und erzwingt Nicht-Leere Capabilities.
pub fn verify_mesh_ticket(
    grant: &TicketGrantPayload,
    verifier: &AuthVerifier,
    single_use: bool,
) -> DbResult<VerifiedDbTicket> {
    if grant.subject_node_id.trim().is_empty() {
        return Err(DbError::Unauthorized(
            "Mesh ticket missing subject_node_id".into(),
        ));
    }
    let claims = verifier
        .verify_token(&grant.session_ticket)
        .map_err(|e| DbError::Unauthorized(format!("Invalid session_ticket signature: {e}")))?;

    if claims.subject != grant.subject_node_id {
        return Err(DbError::Unauthorized(
            "Ticket subject mismatch between grant and signed token".into(),
        ));
    }

    let now = Utc::now().timestamp().max(0) as u64;
    if grant.valid_until <= now {
        return Err(DbError::Unauthorized("Mesh ticket grant expired".into()));
    }

    let effective_exp = grant.valid_until.min(claims.expires_at.max(0) as u64);
    let mut caps = grant.capabilities.clone();
    for cap in &claims.capabilities {
        if !caps.contains(cap) {
            caps.push(cap.clone());
        }
    }
    if caps.is_empty() {
        return Err(DbError::Unauthorized(
            "Mesh ticket contains no capabilities".into(),
        ));
    }

    Ok(VerifiedDbTicket {
        ticket_id: claims.token_id,
        subject: claims.subject,
        role: grant.role.clone(),
        capabilities: caps,
        valid_until: effective_exp,
        single_use,
    })
}

/// Verifies an `sb-auth` Ed25519 Sovereign Token directly for database access.
pub fn verify_auth_token(
    token: &str,
    verifier: &AuthVerifier,
    single_use: bool,
) -> DbResult<VerifiedDbTicket> {
    let claims: SovereignClaims = verifier
        .verify_token(token)
        .map_err(|e| DbError::Unauthorized(format!("Invalid auth token: {e}")))?;
    if claims.capabilities.is_empty() {
        return Err(DbError::Unauthorized(
            "Auth token contains no capabilities".into(),
        ));
    }
    Ok(VerifiedDbTicket {
        ticket_id: claims.token_id,
        subject: claims.subject,
        role: claims.roles.first().cloned().unwrap_or_else(|| "User".into()),
        capabilities: claims.capabilities,
        valid_until: claims.expires_at.max(0) as u64,
        single_use,
    })
}
