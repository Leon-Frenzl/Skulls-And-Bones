use chrono::Utc;
use std::sync::Arc;

use crate::claims::{SovereignClaims, TokenType};
use crate::crypto::Keypair;
use crate::error::AuthError;
use crate::revocation::RevocationManager;
use crate::storage::RevocationStore;
use crate::token::{TokenDecoder, TokenEncoder};

/// Sovereign Authentication Engine — Die zentrale Schnittstelle für Entwickler
pub struct AuthEngine {
    keypair: Keypair,
    revocation: RevocationManager,
    issuer: String,
    access_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
}

impl AuthEngine {
    /// Initialisiert eine neue AuthEngine mit einem Schlüsselpaar und einem Revocation-Store
    pub fn new(keypair: Keypair, store: Arc<dyn RevocationStore>) -> Self {
        Self {
            keypair,
            revocation: RevocationManager::new(store),
            issuer: "sb-auth".to_string(),
            access_token_ttl_seconds: 900,      // 15 Minuten
            refresh_token_ttl_seconds: 604_800, // 7 Tage
        }
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    pub fn with_access_token_ttl(mut self, ttl_seconds: i64) -> Self {
        self.access_token_ttl_seconds = ttl_seconds;
        self
    }

    pub fn with_refresh_token_ttl(mut self, ttl_seconds: i64) -> Self {
        self.refresh_token_ttl_seconds = ttl_seconds;
        self
    }

    pub fn public_key_base64(&self) -> String {
        self.keypair.to_public_base64()
    }

    pub fn key_id(&self) -> &str {
        &self.keypair.key_id
    }

    pub fn revocation_manager(&self) -> &RevocationManager {
        &self.revocation
    }

    /// Erzeugt ein neues Access- und Refresh-Token-Paar für eine neue Benutzersitzung
    pub fn issue_session(
        &self,
        subject: &str,
        roles: Vec<String>,
        capabilities: Vec<String>,
        metadata: serde_json::Value,
    ) -> Result<SessionTokens, AuthError> {
        let now = Utc::now().timestamp();
        let session_id = format!("sbs_{}_{:08x}", now, rand::random::<u32>());
        let user_epoch = self.revocation.get_user_epoch(subject)?;

        // 1. Access Token
        let access_token_id = format!("sbt_acc_{}_{:08x}", now, rand::random::<u32>());
        let access_claims = SovereignClaims {
            token_id: access_token_id.clone(),
            token_type: TokenType::Access,
            subject: subject.to_string(),
            session_id: Some(session_id.clone()),
            user_epoch,
            roles: roles.clone(),
            capabilities: capabilities.clone(),
            audience: None,
            issuer: self.issuer.clone(),
            issued_at: now,
            not_before: now,
            expires_at: now + self.access_token_ttl_seconds,
            metadata: metadata.clone(),
        };
        let access_token = TokenEncoder::encode(&access_claims, &self.keypair)?;

        // 2. Refresh Token
        let refresh_token_id = format!("sbt_ref_{}_{:08x}", now, rand::random::<u32>());
        let refresh_claims = SovereignClaims {
            token_id: refresh_token_id.clone(),
            token_type: TokenType::Refresh,
            subject: subject.to_string(),
            session_id: Some(session_id.clone()),
            user_epoch,
            roles,
            capabilities,
            audience: None,
            issuer: self.issuer.clone(),
            issued_at: now,
            not_before: now,
            expires_at: now + self.refresh_token_ttl_seconds,
            metadata,
        };
        let refresh_token = TokenEncoder::encode(&refresh_claims, &self.keypair)?;

        Ok(SessionTokens {
            access_token,
            access_token_id,
            refresh_token,
            refresh_token_id,
            session_id,
            expires_at: now + self.access_token_ttl_seconds,
        })
    }

    /// Verifiziert einen Token vollständig:
    /// 1. Signaturprüfung mit Ed25519
    /// 2. Zeitliche Gültigkeit (Ablauf & Not-Before)
    /// 3. Multi-Tier Revocation-Prüfung (Token, Session, User-Epoch)
    pub fn verify_token(&self, token_str: &str) -> Result<SovereignClaims, AuthError> {
        let (_header, claims) =
            TokenDecoder::decode_and_verify(token_str, &self.keypair.verifying_key)?;
        let now = Utc::now().timestamp();
        self.revocation.validate(&claims, now)?;
        Ok(claims)
    }

    /// Verifiziert einen Token und autorisiert erforderliche Rollen oder Capabilities
    pub fn authorize(
        &self,
        token_str: &str,
        required_role: Option<&str>,
        required_capability: Option<&str>,
    ) -> Result<SovereignClaims, AuthError> {
        let claims = self.verify_token(token_str)?;

        if let Some(role) = required_role {
            if !claims.has_role(role) {
                return Err(AuthError::MissingRole(role.to_string()));
            }
        }

        if let Some(cap) = required_capability {
            if !claims.has_capability(cap) {
                return Err(AuthError::MissingCapability(cap.to_string()));
            }
        }

        Ok(claims)
    }

    /// Erneuert eine Session mittels rotierendem Refresh-Token
    /// (Der alte Refresh-Token wird sofort widerrufen, um Replay-Angriffe zu verhindern)
    pub fn refresh_session(&self, refresh_token_str: &str) -> Result<SessionTokens, AuthError> {
        let old_claims = self.verify_token(refresh_token_str)?;
        if old_claims.token_type != TokenType::Refresh {
            return Err(AuthError::InvalidToken(
                "Zur Erneuerung muss ein Refresh-Token übergeben werden".to_string(),
            ));
        }

        // Alten Refresh-Token sofort widerrufen (Single-Use Rotation)
        self.revocation.revoke_token(
            &old_claims.token_id,
            old_claims.expires_at,
            "Rotated via refresh",
        )?;

        // Neue Tokens ausstellen
        let now = Utc::now().timestamp();
        let session_id = old_claims
            .session_id
            .unwrap_or_else(|| format!("sbs_{}_{:08x}", now, rand::random::<u32>()));

        let access_token_id = format!("sbt_acc_{}_{:08x}", now, rand::random::<u32>());
        let access_claims = SovereignClaims {
            token_id: access_token_id.clone(),
            token_type: TokenType::Access,
            subject: old_claims.subject.clone(),
            session_id: Some(session_id.clone()),
            user_epoch: old_claims.user_epoch,
            roles: old_claims.roles.clone(),
            capabilities: old_claims.capabilities.clone(),
            audience: old_claims.audience.clone(),
            issuer: self.issuer.clone(),
            issued_at: now,
            not_before: now,
            expires_at: now + self.access_token_ttl_seconds,
            metadata: old_claims.metadata.clone(),
        };
        let access_token = TokenEncoder::encode(&access_claims, &self.keypair)?;

        let new_refresh_token_id = format!("sbt_ref_{}_{:08x}", now, rand::random::<u32>());
        let new_refresh_claims = SovereignClaims {
            token_id: new_refresh_token_id.clone(),
            token_type: TokenType::Refresh,
            subject: old_claims.subject,
            session_id: Some(session_id.clone()),
            user_epoch: old_claims.user_epoch,
            roles: old_claims.roles,
            capabilities: old_claims.capabilities,
            audience: old_claims.audience,
            issuer: self.issuer.clone(),
            issued_at: now,
            not_before: now,
            expires_at: now + self.refresh_token_ttl_seconds,
            metadata: old_claims.metadata,
        };
        let new_refresh_token = TokenEncoder::encode(&new_refresh_claims, &self.keypair)?;

        Ok(SessionTokens {
            access_token,
            access_token_id,
            refresh_token: new_refresh_token,
            refresh_token_id: new_refresh_token_id,
            session_id,
            expires_at: now + self.access_token_ttl_seconds,
        })
    }

    /// Widerruft einen einzelnen Token
    pub fn revoke_token(
        &self,
        token_id: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(), AuthError> {
        self.revocation.revoke_token(token_id, expires_at, reason)
    }

    /// Widerruft eine Session
    pub fn revoke_session(
        &self,
        session_id: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(), AuthError> {
        self.revocation
            .revoke_session(session_id, expires_at, reason)
    }

    /// Widerruft schlagartig alle Sessions eines Benutzers
    pub fn revoke_all_user_sessions(&self, user_id: &str) -> Result<u64, AuthError> {
        self.revocation.revoke_all_user_sessions(user_id)
    }
}

/// Rückgabe von ausgestellten Sitzungs-Tokens
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTokens {
    pub access_token: String,
    pub access_token_id: String,
    pub refresh_token: String,
    pub refresh_token_id: String,
    pub session_id: String,
    pub expires_at: i64,
}
