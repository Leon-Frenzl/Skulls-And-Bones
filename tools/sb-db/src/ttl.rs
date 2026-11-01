use crate::index::{SecondaryIndexManager, ValueRecord};
use std::collections::BTreeMap;

pub struct TtlManager;

impl TtlManager {
    /// Return current time in epoch milliseconds
    pub fn now_millis() -> u64 {
        chrono::Utc::now().timestamp_millis() as u64
    }

    /// Check if a given expiration timestamp is in the past
    pub fn is_expired(expires_at: u64, now: u64) -> bool {
        expires_at > 0 && now >= expires_at
    }

    /// Sweep and remove all expired keys from primary and secondary indexes
    pub fn sweep(
        primary: &mut BTreeMap<String, ValueRecord>,
        secondary: &mut SecondaryIndexManager,
    ) -> Vec<String> {
        let now = Self::now_millis();
        let mut expired_keys = Vec::new();

        for (k, v) in primary.iter() {
            if v.is_expired(now) {
                expired_keys.push(k.clone());
            }
        }

        for k in &expired_keys {
            if let Some(record) = primary.remove(k) {
                secondary.on_delete(k, &record.value);
            }
        }

        expired_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_sweep() {
        let mut primary = BTreeMap::new();
        let mut secondary = SecondaryIndexManager::new();

        let now = TtlManager::now_millis();

        // Expired record
        primary.insert(
            "temp:expired".to_string(),
            ValueRecord {
                value: serde_json::json!({"test": 1}),
                expires_at: now - 1000,
                revision: 1,
                updated_at: now - 2000,
            },
        );

        // Valid record
        primary.insert(
            "temp:valid".to_string(),
            ValueRecord {
                value: serde_json::json!({"test": 2}),
                expires_at: now + 50000,
                revision: 2,
                updated_at: now,
            },
        );

        let swept = TtlManager::sweep(&mut primary, &mut secondary);
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0], "temp:expired");
        assert!(primary.contains_key("temp:valid"));
        assert!(!primary.contains_key("temp:expired"));
    }
}
