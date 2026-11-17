use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::AuthError;
use crate::storage::RevocationStore;

#[derive(Debug, Clone)]
struct RevocationEntry {
    pub expires_at: i64,
    pub reason: String,
}

/// Schneller In-Memory Revocation Store mit RwLock
pub struct MemoryRevocationStore {
    tokens: RwLock<HashMap<String, RevocationEntry>>,
    sessions: RwLock<HashMap<String, RevocationEntry>>,
    user_epochs: RwLock<HashMap<String, u64>>,
}

impl Default for MemoryRevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryRevocationStore {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            user_epochs: RwLock::new(HashMap::new()),
        }
    }
}

impl RevocationStore for MemoryRevocationStore {
    fn is_token_revoked(&self, token_id: &str) -> Result<Option<String>, AuthError> {
        let guard = self
            .tokens
            .read()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        Ok(guard.get(token_id).map(|e| e.reason.clone()))
    }

    fn is_session_revoked(&self, session_id: &str) -> Result<Option<String>, AuthError> {
        let guard = self
            .sessions
            .read()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        Ok(guard.get(session_id).map(|e| e.reason.clone()))
    }

    fn get_user_epoch(&self, user_id: &str) -> Result<u64, AuthError> {
        let guard = self
            .user_epochs
            .read()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        Ok(guard.get(user_id).copied().unwrap_or(0))
    }

    fn revoke_token(&self, token_id: &str, expires_at: i64, reason: &str) -> Result<(), AuthError> {
        let mut guard = self
            .tokens
            .write()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        guard.insert(
            token_id.to_string(),
            RevocationEntry {
                expires_at,
                reason: reason.to_string(),
            },
        );
        Ok(())
    }

    fn revoke_session(
        &self,
        session_id: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(), AuthError> {
        let mut guard = self
            .sessions
            .write()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        guard.insert(
            session_id.to_string(),
            RevocationEntry {
                expires_at,
                reason: reason.to_string(),
            },
        );
        Ok(())
    }

    fn bump_user_epoch(&self, user_id: &str) -> Result<u64, AuthError> {
        let mut guard = self
            .user_epochs
            .write()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        let epoch = guard.entry(user_id.to_string()).or_insert(0);
        *epoch += 1;
        Ok(*epoch)
    }

    fn prune_expired(&self, now: i64) -> Result<usize, AuthError> {
        let mut pruned = 0;
        {
            let mut tokens = self
                .tokens
                .write()
                .map_err(|e| AuthError::StorageError(e.to_string()))?;
            let before = tokens.len();
            tokens.retain(|_, entry| entry.expires_at > now);
            pruned += before - tokens.len();
        }
        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| AuthError::StorageError(e.to_string()))?;
            let before = sessions.len();
            sessions.retain(|_, entry| entry.expires_at > now);
            pruned += before - sessions.len();
        }
        Ok(pruned)
    }
}
