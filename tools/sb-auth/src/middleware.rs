use crate::claims::SovereignClaims;
use crate::engine::{AuthEngine, AuthVerifier};
use crate::error::AuthError;

/// Extrahiert einen Bearer-Token aus einem HTTP Authorization Header (z. B. "Bearer sbt....")
pub fn extract_bearer_token(header_value: &str) -> Result<&str, AuthError> {
    let trimmed = header_value.trim();
    if let Some(token) = trimmed.strip_prefix("Bearer ") {
        let t = token.trim();
        if t.is_empty() {
            Err(AuthError::InvalidToken("Leerer Bearer-Token".to_string()))
        } else {
            Ok(t)
        }
    } else if let Some(token) = trimmed.strip_prefix("bearer ") {
        let t = token.trim();
        if t.is_empty() {
            Err(AuthError::InvalidToken("Leerer Bearer-Token".to_string()))
        } else {
            Ok(t)
        }
    } else {
        Err(AuthError::InvalidToken(
            "Authorization Header muss das Format 'Bearer <token>' haben".to_string(),
        ))
    }
}

/// Extrahiert und verifiziert einen Token aus einem Authorization-Header
pub fn authenticate_header(
    engine: &AuthEngine,
    header_value: &str,
) -> Result<SovereignClaims, AuthError> {
    let token = extract_bearer_token(header_value)?;
    engine.verify_token(token)
}

/// Extrahiert, verifiziert und autorisiert einen Token gegen geforderte Rollen oder Capabilities
pub fn authorize_header(
    engine: &AuthEngine,
    header_value: &str,
    required_role: Option<&str>,
    required_capability: Option<&str>,
) -> Result<SovereignClaims, AuthError> {
    let token = extract_bearer_token(header_value)?;
    engine.authorize(token, required_role, required_capability)
}

/// Extrahiert, verifiziert und autorisiert einen Token mittels eines Public-Key-Only `AuthVerifier`
pub fn authorize_header_with_verifier(
    verifier: &AuthVerifier,
    header_value: &str,
    required_role: Option<&str>,
    required_capability: Option<&str>,
) -> Result<SovereignClaims, AuthError> {
    let token = extract_bearer_token(header_value)?;
    verifier.authorize(token, required_role, required_capability)
}
