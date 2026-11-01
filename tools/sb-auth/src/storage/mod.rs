pub mod file;
pub mod memory;

use crate::error::AuthError;

/// Abstraktion für die Speicherung von Revocation-Listen und Benutzer-Epochen
pub trait RevocationStore: Send + Sync {
    /// Prüft, ob ein bestimmter Token explizit widerrufen wurde.
    /// Gibt `Some(grund)` zurück, falls widerrufen.
    fn is_token_revoked(&self, token_id: &str) -> Result<Option<String>, AuthError>;

    /// Prüft, ob eine Session explizit widerrufen wurde.
    /// Gibt `Some(grund)` zurück, falls widerrufen.
    fn is_session_revoked(&self, session_id: &str) -> Result<Option<String>, AuthError>;

    /// Gibt die aktuelle Epoch-Nummer eines Benutzers zurück (Standard: 0)
    fn get_user_epoch(&self, user_id: &str) -> Result<u64, AuthError>;

    /// Widerruft einen einzelnen Token bis zu seinem regulären Ablaufzeitpunkt
    fn revoke_token(&self, token_id: &str, expires_at: i64, reason: &str) -> Result<(), AuthError>;

    /// Widerruft eine gesamte Session
    fn revoke_session(
        &self,
        session_id: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(), AuthError>;

    /// Inkrementiert die Epoch eines Benutzers (macht alle bisherigen Tokens sofort ungültig)
    fn bump_user_epoch(&self, user_id: &str) -> Result<u64, AuthError>;

    /// Bereinigt abgelaufene Revocation-Einträge zur Speicheroptimierung
    fn prune_expired(&self, now: i64) -> Result<usize, AuthError>;
}
