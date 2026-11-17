use std::sync::Arc;

use crate::claims::SovereignClaims;
use crate::error::AuthError;
use crate::storage::RevocationStore;

/// Validiert und verwaltet mehrstufige Token- und Session-Widerrufe (Multi-Tier Revocation)
pub struct RevocationManager {
    store: Arc<dyn RevocationStore>,
    clock_skew_seconds: i64,
}

impl RevocationManager {
    pub fn new(store: Arc<dyn RevocationStore>) -> Self {
        Self {
            store,
            clock_skew_seconds: 5,
        }
    }

    pub fn with_clock_skew(mut self, skew_seconds: i64) -> Self {
        self.clock_skew_seconds = skew_seconds;
        self
    }

    /// Führt die vollständige mehrstufige Revocation-Prüfung durch
    pub fn validate(&self, claims: &SovereignClaims, now: i64) -> Result<(), AuthError> {
        // 1. Zeitliche Validierung
        claims.validate_time(now, self.clock_skew_seconds)?;

        // 2. Token-Level Revocation
        if let Some(reason) = self.store.is_token_revoked(&claims.token_id)? {
            return Err(AuthError::RevokedToken {
                token_id: claims.token_id.clone(),
                reason,
            });
        }

        // 3. Session-Level Revocation
        if let Some(session_id) = &claims.session_id {
            if let Some(reason) = self.store.is_session_revoked(session_id)? {
                return Err(AuthError::RevokedSession {
                    session_id: session_id.clone(),
                    reason,
                });
            }
        }

        // 4. User-Level Epoch (Globaler Logout aller Geräte)
        let current_epoch = self.store.get_user_epoch(&claims.subject)?;
        if claims.user_epoch < current_epoch {
            return Err(AuthError::RevokedUserEpoch {
                user_id: claims.subject.clone(),
                token_epoch: claims.user_epoch,
                current_epoch,
            });
        }

        Ok(())
    }

    /// Gibt die aktuelle Epoch-Nummer eines Benutzers zurück
    pub fn get_user_epoch(&self, user_id: &str) -> Result<u64, AuthError> {
        self.store.get_user_epoch(user_id)
    }

    /// Widerruft einen einzelnen Token
    pub fn revoke_token(
        &self,
        token_id: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(), AuthError> {
        self.store.revoke_token(token_id, expires_at, reason)
    }

    /// Widerruft eine gesamte Session
    pub fn revoke_session(
        &self,
        session_id: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(), AuthError> {
        self.store.revoke_session(session_id, expires_at, reason)
    }

    /// Widerruft schlagartig alle Sessions eines Benutzers durch Inkrementieren der Epoche
    pub fn revoke_all_user_sessions(&self, user_id: &str) -> Result<u64, AuthError> {
        self.store.bump_user_epoch(user_id)
    }

    /// Bereinigt abgelaufene Einträge aus dem Speicher
    pub fn prune_expired(&self, now: i64) -> Result<usize, AuthError> {
        self.store.prune_expired(now)
    }
}
