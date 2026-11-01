use crate::entry::{Entry, EntryKind};
use crate::event::{DbEvent, EventBus, EventKind};
use crate::index::{resolve_json_path, set_json_path, SecondaryIndexManager, ValueRecord};
use crate::storage::StorageEngine;
use crate::transaction::Transaction;
use crate::ttl::TtlManager;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub path: PathBuf,
    pub key_count: usize,
    pub index_count: usize,
    pub file_size_bytes: u64,
    pub last_tx_id: u64,
}

struct DbInner {
    storage: StorageEngine,
    primary: BTreeMap<String, ValueRecord>,
    secondary: SecondaryIndexManager,
    current_tx_id: u64,
    event_bus: EventBus,
}

#[derive(Clone)]
pub struct Database {
    inner: Arc<RwLock<DbInner>>,
}

impl Database {
    /// Open or create a Sovereign `.sbdb` database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut storage = StorageEngine::open(path)?;
        let (primary, secondary, max_tx_id) = storage.recover()?;
        let event_bus = EventBus::new(1024);

        let inner = DbInner {
            storage,
            primary,
            secondary,
            current_tx_id: max_tx_id,
            event_bus,
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    /// Read a JSON value by key
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        let guard = self.inner.read().ok()?;
        let record = guard.primary.get(key)?;
        let now = TtlManager::now_millis();
        if record.is_expired(now) {
            None
        } else {
            Some(record.value.clone())
        }
    }

    /// Read and deserialize value into type T
    pub fn get_typed<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, String> {
        match self.get(key) {
            Some(val) => serde_json::from_value(val)
                .map(Some)
                .map_err(|e| e.to_string()),
            None => Ok(None),
        }
    }

    /// Read a nested field inside a document using dot notation (e.g. "profile.address.city")
    pub fn get_path(&self, key: &str, path: &str) -> Option<serde_json::Value> {
        let doc = self.get(key)?;
        resolve_json_path(&doc, path).cloned()
    }

    /// Store a serializable value at key
    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<(), String> {
        let json_val = serde_json::to_value(value).map_err(|e| e.to_string())?;
        self.set_raw(key, json_val, 0)
    }

    /// Store a value with a Time-To-Live duration
    pub fn set_with_ttl<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<(), String> {
        let json_val = serde_json::to_value(value).map_err(|e| e.to_string())?;
        let now = TtlManager::now_millis();
        let expires_at = now + ttl.as_millis() as u64;
        self.set_raw(key, json_val, expires_at)
    }

    fn set_raw(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl_expires_at: u64,
    ) -> Result<(), String> {
        let mut guard = self.inner.write().map_err(|e| e.to_string())?;
        guard.current_tx_id += 1;
        let tx_id = guard.current_tx_id;
        let now = TtlManager::now_millis();

        let entry = Entry::new_set(tx_id, now, ttl_expires_at, key.to_string(), value.clone());
        guard.storage.append(&entry)?;

        let old_doc = guard.primary.get(key).map(|r| r.value.clone());
        guard.secondary.on_set(key, &value, old_doc.as_ref());

        guard.primary.insert(
            key.to_string(),
            ValueRecord {
                value: value.clone(),
                expires_at: ttl_expires_at,
                revision: tx_id,
                updated_at: now,
            },
        );

        guard.event_bus.publish(DbEvent {
            kind: EventKind::Set,
            key: key.to_string(),
            old_value: old_doc,
            new_value: Some(value),
            timestamp: now,
        });

        Ok(())
    }

    /// Mutate a specific nested path inside an existing JSON document
    pub fn set_path(
        &self,
        key: &str,
        path: &str,
        new_value: serde_json::Value,
    ) -> Result<(), String> {
        let mut current_doc = self
            .get(key)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        set_json_path(&mut current_doc, path, new_value)?;
        self.set(key, &current_doc)
    }

    /// Delete a key
    pub fn delete(&self, key: &str) -> Result<bool, String> {
        let mut guard = self.inner.write().map_err(|e| e.to_string())?;
        if let Some(old_record) = guard.primary.remove(key) {
            guard.current_tx_id += 1;
            let tx_id = guard.current_tx_id;
            let now = TtlManager::now_millis();

            let entry = Entry::new_delete(tx_id, now, key.to_string());
            guard.storage.append(&entry)?;
            guard.secondary.on_delete(key, &old_record.value);

            guard.event_bus.publish(DbEvent {
                kind: EventKind::Delete,
                key: key.to_string(),
                old_value: Some(old_record.value),
                new_value: None,
                timestamp: now,
            });

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Scan all keys starting with prefix
    pub fn scan(&self, prefix: &str) -> Vec<(String, serde_json::Value)> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        let now = TtlManager::now_millis();
        let mut results = Vec::new();

        for (k, v) in guard.primary.range(prefix.to_string()..) {
            if !k.starts_with(prefix) {
                break;
            }
            if !v.is_expired(now) {
                results.push((k.clone(), v.value.clone()));
            }
        }

        results
    }

    /// Register a secondary index on a collection prefix and field
    pub fn create_index(&self, prefix: &str, field: &str) -> Result<(), String> {
        let mut guard = self.inner.write().map_err(|e| e.to_string())?;
        guard.current_tx_id += 1;
        let tx_id = guard.current_tx_id;
        let now = TtlManager::now_millis();

        let entry = Entry {
            kind: EntryKind::CreateIndex,
            tx_id,
            timestamp: now,
            ttl_expires_at: 0,
            key: prefix.to_string(),
            value: serde_json::Value::String(field.to_string()),
        };
        guard.storage.append(&entry)?;

        guard
            .secondary
            .register_index(prefix.to_string(), field.to_string());

        // Backfill existing keys
        let matching: Vec<(String, serde_json::Value)> = guard
            .primary
            .iter()
            .filter(|(k, v)| k.starts_with(prefix) && !v.is_expired(now))
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect();

        for (k, v) in matching {
            guard.secondary.on_set(&k, &v, None);
        }

        Ok(())
    }

    /// Drop a secondary index
    pub fn drop_index(&self, prefix: &str, field: &str) -> Result<bool, String> {
        let mut guard = self.inner.write().map_err(|e| e.to_string())?;
        guard.current_tx_id += 1;
        let tx_id = guard.current_tx_id;
        let now = TtlManager::now_millis();

        let entry = Entry {
            kind: EntryKind::DropIndex,
            tx_id,
            timestamp: now,
            ttl_expires_at: 0,
            key: prefix.to_string(),
            value: serde_json::Value::String(field.to_string()),
        };
        guard.storage.append(&entry)?;

        Ok(guard.secondary.drop_index(prefix, field))
    }

    /// Find documents matching an indexed field value in O(1)
    pub fn find(
        &self,
        prefix: &str,
        field: &str,
        value: &serde_json::Value,
    ) -> Vec<(String, serde_json::Value)> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        let matched_keys = guard.secondary.find_keys(prefix, field, value);
        let now = TtlManager::now_millis();
        let mut results = Vec::new();

        for key in matched_keys {
            if let Some(record) = guard.primary.get(&key) {
                if !record.is_expired(now) {
                    results.push((key, record.value.clone()));
                }
            }
        }

        results
    }

    /// Start a transaction
    pub fn transaction(&self) -> Result<Transaction, String> {
        let guard = self.inner.read().map_err(|e| e.to_string())?;
        Ok(Transaction::new(guard.current_tx_id + 1))
    }

    /// Commit a batch of transaction operations atomically
    pub fn commit(&self, tx: Transaction) -> Result<(), String> {
        if tx.is_empty() {
            return Ok(());
        }

        let mut guard = self.inner.write().map_err(|e| e.to_string())?;
        guard.current_tx_id += 1;
        let tx_id = guard.current_tx_id;
        let now = TtlManager::now_millis();

        let mut batch = Vec::with_capacity(tx.operations.len() + 2);
        batch.push(Entry {
            kind: EntryKind::TxBegin,
            tx_id,
            timestamp: now,
            ttl_expires_at: 0,
            key: String::new(),
            value: serde_json::Value::Null,
        });

        for mut op in tx.operations {
            op.tx_id = tx_id;
            batch.push(op);
        }

        batch.push(Entry {
            kind: EntryKind::TxCommit,
            tx_id,
            timestamp: now,
            ttl_expires_at: 0,
            key: String::new(),
            value: serde_json::Value::Null,
        });

        guard.storage.append_batch(&batch)?;

        // Apply mutations to in-memory index
        for entry in &batch {
            match entry.kind {
                EntryKind::Set => {
                    let old_doc = guard.primary.get(&entry.key).map(|r| r.value.clone());
                    guard
                        .secondary
                        .on_set(&entry.key, &entry.value, old_doc.as_ref());

                    guard.primary.insert(
                        entry.key.clone(),
                        ValueRecord {
                            value: entry.value.clone(),
                            expires_at: entry.ttl_expires_at,
                            revision: tx_id,
                            updated_at: entry.timestamp,
                        },
                    );

                    guard.event_bus.publish(DbEvent {
                        kind: EventKind::Set,
                        key: entry.key.clone(),
                        old_value: old_doc,
                        new_value: Some(entry.value.clone()),
                        timestamp: entry.timestamp,
                    });
                }
                EntryKind::Delete => {
                    if let Some(old_record) = guard.primary.remove(&entry.key) {
                        guard.secondary.on_delete(&entry.key, &old_record.value);
                        guard.event_bus.publish(DbEvent {
                            kind: EventKind::Delete,
                            key: entry.key.clone(),
                            old_value: Some(old_record.value),
                            new_value: None,
                            timestamp: entry.timestamp,
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Subscribe to live reactive events (Change Data Capture)
    pub fn watch(&self) -> broadcast::Receiver<DbEvent> {
        let guard = self.inner.read().unwrap();
        guard.event_bus.subscribe()
    }

    /// Compact database file by purging dead & expired records
    pub fn compact(&self) -> Result<u64, String> {
        let mut guard = self.inner.write().map_err(|e| e.to_string())?;
        let inner = &mut *guard;
        // First sweep memory of expired keys
        TtlManager::sweep(&mut inner.primary, &mut inner.secondary);

        let indexes = inner.secondary.list_indexes();
        inner.storage.compact(&inner.primary, &indexes)
    }

    /// Database statistics
    pub fn stats(&self) -> Result<DbStats, String> {
        let guard = self.inner.read().map_err(|e| e.to_string())?;
        let file_size_bytes = guard.storage.file.metadata().map(|m| m.len()).unwrap_or(0);
        let index_count = guard.secondary.list_indexes().len();

        Ok(DbStats {
            path: guard.storage.path.clone(),
            key_count: guard.primary.len(),
            index_count,
            file_size_bytes,
            last_tx_id: guard.current_tx_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_crud_and_json_path() {
        let dir = std::env::temp_dir().join(format!("sbdb_test_{}", rand::random::<u32>()));
        let db_path = dir.join("test.sbdb");

        let db = Database::open(&db_path).unwrap();

        // 1. Set simple
        db.set(
            "user:1",
            &serde_json::json!({"name": "Alice", "role": "admin"}),
        )
        .unwrap();
        let doc = db.get("user:1").unwrap();
        assert_eq!(doc["name"], "Alice");

        // 2. Read path
        assert_eq!(db.get_path("user:1", "role").unwrap(), "admin");

        // 3. Mutate path
        db.set_path("user:1", "role", serde_json::json!("superuser"))
            .unwrap();
        assert_eq!(db.get_path("user:1", "role").unwrap(), "superuser");

        // 4. Scan
        db.set("user:2", &serde_json::json!({"name": "Bob"}))
            .unwrap();
        let users = db.scan("user:");
        assert_eq!(users.len(), 2);

        // 5. Delete
        assert!(db.delete("user:1").unwrap());
        assert!(db.get("user:1").is_none());

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_db_transactions() {
        let dir = std::env::temp_dir().join(format!("sbdb_tx_{}", rand::random::<u32>()));
        let db_path = dir.join("test_tx.sbdb");

        let db = Database::open(&db_path).unwrap();

        let mut tx = db.transaction().unwrap();
        tx.set("k1", serde_json::json!("v1"));
        tx.set("k2", serde_json::json!("v2"));
        tx.set("k3", serde_json::json!("v3"));
        db.commit(tx).unwrap();

        assert_eq!(db.get("k1").unwrap(), "v1");
        assert_eq!(db.get("k2").unwrap(), "v2");
        assert_eq!(db.get("k3").unwrap(), "v3");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
