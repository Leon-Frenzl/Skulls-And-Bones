use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::error::AuthError;
use crate::storage::RevocationStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevocationEntry {
    pub expires_at: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StorageData {
    pub tokens: HashMap<String, RevocationEntry>,
    pub sessions: HashMap<String, RevocationEntry>,
    pub user_epochs: HashMap<String, u64>,
}

/// Dateibasierter Revocation Store mit atomarem JSON-Schreiben
pub struct FileRevocationStore {
    path: PathBuf,
    data: RwLock<StorageData>,
}

impl FileRevocationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            let content = fs::read_to_string(&path).map_err(|e| {
                AuthError::StorageError(format!("Datei konnte nicht gelesen werden: {e}"))
            })?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            StorageData::default()
        };

        Ok(Self {
            path,
            data: RwLock::new(data),
        })
    }

    fn persist(&self, data: &StorageData) -> Result<(), AuthError> {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| AuthError::SerializationError(e.to_string()))?;
        fs::write(&self.path, json)
            .map_err(|e| AuthError::StorageError(format!("Schreiben fehlgeschlagen: {e}")))?;
        Ok(())
    }
}

impl RevocationStore for FileRevocationStore {
    fn is_token_revoked(&self, token_id: &str) -> Result<Option<String>, AuthError> {
        let guard = self
            .data
            .read()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        Ok(guard.tokens.get(token_id).map(|e| e.reason.clone()))
    }

    fn is_session_revoked(&self, session_id: &str) -> Result<Option<String>, AuthError> {
        let guard = self
            .data
            .read()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        Ok(guard.sessions.get(session_id).map(|e| e.reason.clone()))
    }

    fn get_user_epoch(&self, user_id: &str) -> Result<u64, AuthError> {
        let guard = self
            .data
            .read()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        Ok(guard.user_epochs.get(user_id).copied().unwrap_or(0))
    }

    fn revoke_token(&self, token_id: &str, expires_at: i64, reason: &str) -> Result<(), AuthError> {
        let mut guard = self
            .data
            .write()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        guard.tokens.insert(
            token_id.to_string(),
            RevocationEntry {
                expires_at,
                reason: reason.to_string(),
            },
        );
        self.persist(&guard)?;
        Ok(())
    }

    fn revoke_session(
        &self,
        session_id: &str,
        expires_at: i64,
        reason: &str,
    ) -> Result<(), AuthError> {
        let mut guard = self
            .data
            .write()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        guard.sessions.insert(
            session_id.to_string(),
            RevocationEntry {
                expires_at,
                reason: reason.to_string(),
            },
        );
        self.persist(&guard)?;
        Ok(())
    }

    fn bump_user_epoch(&self, user_id: &str) -> Result<u64, AuthError> {
        let mut guard = self
            .data
            .write()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        let epoch = guard.user_epochs.entry(user_id.to_string()).or_insert(0);
        *epoch += 1;
        let new_val = *epoch;
        self.persist(&guard)?;
        Ok(new_val)
    }

    fn prune_expired(&self, now: i64) -> Result<usize, AuthError> {
        let mut guard = self
            .data
            .write()
            .map_err(|e| AuthError::StorageError(e.to_string()))?;
        let t_before = guard.tokens.len();
        guard.tokens.retain(|_, e| e.expires_at > now);
        let s_before = guard.sessions.len();
        guard.sessions.retain(|_, e| e.expires_at > now);
        let pruned = (t_before - guard.tokens.len()) + (s_before - guard.sessions.len());
        if pruned > 0 {
            self.persist(&guard)?;
        }
        Ok(pruned)
    }
}
