use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("Ungültiger oder fehlerhaft formatierter Token: {0}")]
    InvalidToken(String),

    #[error("Token ist abgelaufen (abgelaufen um {expired_at}, aktuelle Zeit {now})")]
    ExpiredToken { expired_at: i64, now: i64 },

    #[error("Token ist noch nicht gültig (gültig ab {not_before}, aktuelle Zeit {now})")]
    TokenNotYetValid { not_before: i64, now: i64 },

    #[error("Token wurde widerrufen: ID '{token_id}' (Grund: {reason})")]
    RevokedToken { token_id: String, reason: String },

    #[error("Sitzung wurde widerrufen: ID '{session_id}' (Grund: {reason})")]
    RevokedSession { session_id: String, reason: String },

    #[error("Benutzer-Sitzungen ungültig: Epoch {token_epoch} < aktuelle Epoch {current_epoch} für '{user_id}'")]
    RevokedUserEpoch {
        user_id: String,
        token_epoch: u64,
        current_epoch: u64,
    },

    #[error("Kryptografische Signaturprüfung fehlgeschlagen")]
    InvalidSignature,

    #[error("Schlüsselfehler: {0}")]
    InvalidKey(String),

    #[error("Ungültiges Passwort")]
    InvalidPassword,

    #[error("Passwort-Hashing-Fehler: {0}")]
    PasswordHashError(String),

    #[error("Ungültiger TOTP-Code")]
    InvalidTotp,

    #[error("TOTP-Code wurde in diesem Zeitfenster bereits verwendet (Replay erkannt)")]
    TotpReplay,

    #[error("Fehlende Berechtigung (Capability): '{0}' erforderlich")]
    MissingCapability(String),

    #[error("Fehlende Rolle: '{0}' erforderlich")]
    MissingRole(String),

    #[error("Fehlende Zielgruppe (Audience): erwartet '{expected}', gefunden '{actual}'")]
    AudienceMismatch { expected: String, actual: String },

    #[error("Speicherfehler im Auth-Tresor: {0}")]
    StorageError(String),

    #[error("Serialisierungsfehler: {0}")]
    SerializationError(String),

    #[error("API-Key ist ungültig oder Prüfsumme stimmt nicht")]
    InvalidApiKey,
}
