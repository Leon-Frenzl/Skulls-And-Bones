use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crc32fast::Hasher;
use rand::RngCore;

use crate::error::AuthError;

pub const API_KEY_PREFIX: &str = "sba";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyEnv {
    Live,
    Test,
    Dev,
}

impl ApiKeyEnv {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Test => "test",
            Self::Dev => "dev",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "live" => Some(Self::Live),
            "test" => Some(Self::Test),
            "dev" => Some(Self::Dev),
            _ => None,
        }
    }
}

/// Strukturierter, prüfsummen-geschützter Sovereign API-Key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKey {
    pub env: ApiKeyEnv,
    pub entropy_b64: String,
    pub checksum: u32,
    pub raw: String,
}

impl ApiKey {
    /// Generiert einen neuen kryptografischen API-Key mit 24 Bytes Entropie und integrierter CRC32-Prüfsumme
    pub fn generate(env: ApiKeyEnv) -> Self {
        let mut entropy = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let entropy_b64 = URL_SAFE_NO_PAD.encode(entropy);

        let checksum_input = format!("{}_{}_{}", API_KEY_PREFIX, env.as_str(), entropy_b64);
        let mut hasher = Hasher::new();
        hasher.update(checksum_input.as_bytes());
        let checksum = hasher.finalize();

        let raw = format!("{}_{:08x}", checksum_input, checksum);

        Self {
            env,
            entropy_b64,
            checksum,
            raw,
        }
    }

    /// Parst und validiert die Integrität eines API-Keys (Tippfehler & Vertauschungen werden sofort erkannt)
    pub fn parse(key_str: &str) -> Result<Self, AuthError> {
        let key_str = key_str.trim();
        // CVE-Threat: A delimiter inside the encoded credential can cause valid keys to be rejected.
        // Analysis: Base64url includes "_", which is also used between fields in the textual key.
        // Hardening: Split from the checksum at the end and validate the decoded entropy length.
        let (key_body, checksum_text) = key_str.rsplit_once('_').ok_or(AuthError::InvalidApiKey)?;
        let mut parts = key_body.splitn(3, '_');
        if parts.next() != Some(API_KEY_PREFIX) {
            return Err(AuthError::InvalidApiKey);
        }

        let env = ApiKeyEnv::from_str(parts.next().ok_or(AuthError::InvalidApiKey)?)
            .ok_or(AuthError::InvalidApiKey)?;
        let entropy_b64 = parts.next().ok_or(AuthError::InvalidApiKey)?.to_string();
        let entropy = URL_SAFE_NO_PAD
            .decode(&entropy_b64)
            .map_err(|_| AuthError::InvalidApiKey)?;
        if entropy.len() != 24 {
            return Err(AuthError::InvalidApiKey);
        }
        let checksum =
            u32::from_str_radix(checksum_text, 16).map_err(|_| AuthError::InvalidApiKey)?;

        // Prüfsumme verifizieren
        let checksum_input = format!("{}_{}_{}", API_KEY_PREFIX, env.as_str(), entropy_b64);
        let mut hasher = Hasher::new();
        hasher.update(checksum_input.as_bytes());
        let expected_checksum = hasher.finalize();

        if checksum != expected_checksum {
            return Err(AuthError::InvalidApiKey);
        }

        Ok(Self {
            env,
            entropy_b64,
            checksum,
            raw: key_str.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_with_entropy(entropy: &[u8]) -> String {
        let entropy_b64 = URL_SAFE_NO_PAD.encode(entropy);
        let checksum_input = format!(
            "{}_{}_{}",
            API_KEY_PREFIX,
            ApiKeyEnv::Live.as_str(),
            entropy_b64
        );
        let mut hasher = Hasher::new();
        hasher.update(checksum_input.as_bytes());
        format!("{}_{:08x}", checksum_input, hasher.finalize())
    }

    #[test]
    fn parses_valid_entropy_containing_field_delimiters() {
        let raw = key_with_entropy(&[u8::MAX; 24]);
        let entropy_b64 = URL_SAFE_NO_PAD.encode([u8::MAX; 24]);
        assert!(entropy_b64.contains('_'));

        let parsed = ApiKey::parse(&raw).expect("Base64url underscores must be parsed as payload");
        assert_eq!(parsed.entropy_b64, entropy_b64);
    }

    #[test]
    fn rejects_entropy_with_invalid_length_even_with_valid_checksum() {
        let raw = key_with_entropy(&[0; 23]);
        assert!(matches!(ApiKey::parse(&raw), Err(AuthError::InvalidApiKey)));
    }
}
