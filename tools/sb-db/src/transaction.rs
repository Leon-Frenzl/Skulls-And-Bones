use crate::entry::Entry;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub tx_id: u64,
    pub operations: Vec<Entry>,
}

impl Transaction {
    pub fn new(tx_id: u64) -> Self {
        Self {
            tx_id,
            operations: Vec::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        self.operations
            .push(Entry::new_set(self.tx_id, now, 0, key.into(), value));
    }

    pub fn set_with_ttl(
        &mut self,
        key: impl Into<String>,
        value: serde_json::Value,
        ttl: Duration,
    ) {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let expires_at = now + ttl.as_millis() as u64;
        self.operations.push(Entry::new_set(
            self.tx_id,
            now,
            expires_at,
            key.into(),
            value,
        ));
    }

    pub fn delete(&mut self, key: impl Into<String>) {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        self.operations
            .push(Entry::new_delete(self.tx_id, now, key.into()));
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}
