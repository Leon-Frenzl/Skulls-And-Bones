use thiserror::Error;

/// Typed error enumeration for `sb-db` persistence, cryptography, and ticket authorization.
#[derive(Error, Debug)]
pub enum DbError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("Ticket authorization denied: {0}")]
    Unauthorized(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Entry not found: {0}")]
    NotFound(String),

    #[error("Resource exhausted: {0}")]
    Exhausted(String),
}

impl From<rusqlite::Error> for DbError {
    fn from(err: rusqlite::Error) -> Self {
        // Avoid leaking full filesystem paths or SQL internals to callers.
        Self::Storage(err.to_string())
    }
}

pub type DbResult<T> = Result<T, DbError>;
