use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    Set,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbEvent {
    pub kind: EventKind,
    pub key: String,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub timestamp: u64,
}

impl DbEvent {
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        matches_pattern(&self.key, pattern)
    }
}

pub struct EventBus {
    sender: broadcast::Sender<DbEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: DbEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DbEvent> {
        self.sender.subscribe()
    }
}

/// Helper function to match simple glob/prefix patterns (e.g. "users:*" or "config/*")
pub fn matches_pattern(key: &str, pattern: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        key.starts_with(prefix)
    } else {
        key == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("users:alice", "users:*"));
        assert!(matches_pattern("users:bob", "users:*"));
        assert!(!matches_pattern("orders:123", "users:*"));
        assert!(matches_pattern("anything", "*"));
        assert!(matches_pattern("exact:key", "exact:key"));
        assert!(!matches_pattern("exact:other", "exact:key"));
    }
}
