use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::claims::SovereignClaims;
use crate::crypto::{verify_signature, Keypair};
use crate::error::AuthError;

pub const TOKEN_PREFIX: &str = "sbt";
pub const CURRENT_VERSION: &str = "1";
pub const ALGORITHM_ED25519: &str = "Ed25519";

/// Header eines Sovereign Tokens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenHeader {
    /// Protokollversion (aktuell "1")
    pub ver: String,
    /// Asymmetrischer Signaturalgorithmus (stets "Ed25519")
    pub alg: String,
    /// Eindeutige Kennung des Schlüssels (KID)
    pub kid: String,
}

impl TokenHeader {
    pub fn new(key_id: impl Into<String>) -> Self {
        Self {
            ver: CURRENT_VERSION.to_string(),
            alg: ALGORITHM_ED25519.to_string(),
            kid: key_id.into(),
        }
    }
}

/// Encoder für Sovereign Tokens
pub struct TokenEncoder;

impl TokenEncoder {
    /// Kodiert und signiert SovereignClaims mit einem Ed25519-Schlüsselpaar
    pub fn encode(claims: &SovereignClaims, keypair: &Keypair) -> Result<String, AuthError> {
        let header = TokenHeader::new(&keypair.key_id);
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| AuthError::SerializationError(e.to_string()))?;
        let claims_json =
            serde_json::to_vec(claims).map_err(|e| AuthError::SerializationError(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        let signed_payload = format!("{}.{}", header_b64, claims_b64);
        let signature_bytes = keypair.sign(signed_payload.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature_bytes);

        Ok(format!(
            "{}.{}.{}",
            TOKEN_PREFIX, signed_payload, signature_b64
        ))
    }
}

/// Decoder & Verifier für Sovereign Tokens
pub struct TokenDecoder;

impl TokenDecoder {
    /// Parst und verifiziert die kryptografische Signatur eines Tokens
    pub fn decode_and_verify(
        token_str: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<(TokenHeader, SovereignClaims), AuthError> {
        let (header, claims, signed_payload, signature_bytes) = Self::parse_segments(token_str)?;

        // Signaturprüfung
        verify_signature(verifying_key, signed_payload.as_bytes(), &signature_bytes)?;

        Ok((header, claims))
    }

    /// Parst einen Token nur informativ ohne Signaturprüfung (z. B. für Token-Inspektion im CLI)
    pub fn inspect(token_str: &str) -> Result<(TokenHeader, SovereignClaims), AuthError> {
        let (header, claims, _, _) = Self::parse_segments(token_str)?;
        Ok((header, claims))
    }

    fn parse_segments(
        token_str: &str,
    ) -> Result<(TokenHeader, SovereignClaims, String, Vec<u8>), AuthError> {
        let parts: Vec<&str> = token_str.trim().split('.').collect();
        if parts.len() != 4 {
            return Err(AuthError::InvalidToken(format!(
                "Token muss 4 Segmente haben: sbt.<header>.<payload>.<sig> (erhalten: {})",
                parts.len()
            )));
        }

        if parts[0] != TOKEN_PREFIX {
            return Err(AuthError::InvalidToken(format!(
                "Ungültiges Token-Präfix: erwartet '{}', erhalten '{}'",
                TOKEN_PREFIX, parts[0]
            )));
        }

        let header_json = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| AuthError::InvalidToken(format!("Header Base64 fehlerhaft: {e}")))?;
        let header: TokenHeader = serde_json::from_slice(&header_json)
            .map_err(|e| AuthError::InvalidToken(format!("Header JSON fehlerhaft: {e}")))?;

        if header.ver != CURRENT_VERSION {
            return Err(AuthError::InvalidToken(format!(
                "Nicht unterstützte Protokollversion: '{}'",
                header.ver
            )));
        }

        if header.alg != ALGORITHM_ED25519 {
            return Err(AuthError::InvalidToken(format!(
                "Nicht unterstützter Algorithmus: '{}' (nur {} erlaubt)",
                header.alg, ALGORITHM_ED25519
            )));
        }

        let claims_json = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| AuthError::InvalidToken(format!("Payload Base64 fehlerhaft: {e}")))?;
        let claims: SovereignClaims = serde_json::from_slice(&claims_json)
            .map_err(|e| AuthError::InvalidToken(format!("Payload JSON fehlerhaft: {e}")))?;

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[3])
            .map_err(|e| AuthError::InvalidToken(format!("Signatur Base64 fehlerhaft: {e}")))?;

        let signed_payload = format!("{}.{}", parts[1], parts[2]);

        Ok((header, claims, signed_payload, signature_bytes))
    }
}
