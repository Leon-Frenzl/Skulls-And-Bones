use serde::{Deserialize, Serialize};

use crate::error::AuthError;

/// Typ des Sovereign Tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Kurzlebiger Access Token für API-Aufrufe
    Access,
    /// Langlebiger Refresh Token zur Session-Verlängerung
    Refresh,
    /// Statischer API-Key für Service-to-Service Aufrufe
    ApiKey,
    /// Delegierter Token mit eingeschränkten Rechten
    Delegated,
}

/// Strukturierte Nutzdaten (Claims) eines Sovereign Tokens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignClaims {
    /// Eindeutige Kennung dieses Tokens (jti)
    pub token_id: String,

    /// Art des Tokens
    pub token_type: TokenType,

    /// Subjekt / Benutzerkennung (sub)
    pub subject: String,

    /// Zugehörige Sitzungs-ID (für session-basierten Logout)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<String>,

    /// Epoch-Zähler des Benutzers (Inkrementiert bei "Überall abmelden")
    #[serde(default)]
    pub user_epoch: u64,

    /// Zugewiesene Rollen (z. B. ["admin", "developer"])
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,

    /// Feingranulare Berechtigungen / Scopes (z. B. ["code:write", "mesh:connect"])
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Zielgruppe (aud)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub audience: Option<String>,

    /// Aussteller des Tokens (iss)
    pub issuer: String,

    /// Ausstellungszeitpunkt (iat) in Sekunden seit Unix-Epoche
    pub issued_at: i64,

    /// Gültig ab (nbf)
    pub not_before: i64,

    /// Ablaufzeitpunkt (exp)
    pub expires_at: i64,

    /// Beliebige anwendungsspezifische Metadaten
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

impl SovereignClaims {
    /// Prüft die zeitliche Gültigkeit des Tokens
    pub fn validate_time(&self, now: i64, clock_skew_seconds: i64) -> Result<(), AuthError> {
        if now < self.not_before - clock_skew_seconds {
            return Err(AuthError::TokenNotYetValid {
                not_before: self.not_before,
                now,
            });
        }
        if now > self.expires_at + clock_skew_seconds {
            return Err(AuthError::ExpiredToken {
                expired_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }

    /// Prüft, ob der Token eine bestimmte Rolle besitzt
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Prüft, ob der Token eine bestimmte Berechtigung (Capability) besitzt
    /// Unterstützt Wildcard-Matching (z. B. "code:*" matcht "code:write")
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|cap| {
            if cap == "*" || cap == capability {
                return true;
            }
            if let Some(prefix) = cap.strip_suffix(":*") {
                if let Some(req_prefix) = capability.split(':').next() {
                    return prefix == req_prefix;
                }
            }
            false
        })
    }

    /// Validiert die Audience, falls vorgegeben
    pub fn validate_audience(&self, expected_aud: Option<&str>) -> Result<(), AuthError> {
        if let Some(expected) = expected_aud {
            match &self.audience {
                Some(actual) if actual == expected => Ok(()),
                Some(actual) => Err(AuthError::AudienceMismatch {
                    expected: expected.to_string(),
                    actual: actual.clone(),
                }),
                None => Err(AuthError::AudienceMismatch {
                    expected: expected.to_string(),
                    actual: "<keine>".to_string(),
                }),
            }
        } else {
            Ok(())
        }
    }
}
