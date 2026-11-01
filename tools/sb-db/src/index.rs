use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValueRecord {
    pub value: serde_json::Value,
    pub expires_at: u64,
    pub revision: u64,
    pub updated_at: u64,
}

impl ValueRecord {
    pub fn is_expired(&self, now_millis: u64) -> bool {
        self.expires_at > 0 && now_millis >= self.expires_at
    }
}

/// Secondary Index Definition
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexDef {
    pub prefix: String, // e.g. "users:"
    pub field: String,  // e.g. "role" or "profile.age"
}

/// Secondary Index Map: (prefix + field) -> (serialized_field_value -> Set of primary keys)
#[derive(Debug, Clone, Default)]
pub struct SecondaryIndexManager {
    indexes: HashMap<IndexDef, BTreeMap<String, BTreeSet<String>>>,
}

impl SecondaryIndexManager {
    pub fn new() -> Self {
        Self {
            indexes: HashMap::new(),
        }
    }

    pub fn register_index(&mut self, prefix: String, field: String) {
        let def = IndexDef { prefix, field };
        self.indexes.entry(def).or_default();
    }

    pub fn drop_index(&mut self, prefix: &str, field: &str) -> bool {
        let def = IndexDef {
            prefix: prefix.to_string(),
            field: field.to_string(),
        };
        self.indexes.remove(&def).is_some()
    }

    pub fn list_indexes(&self) -> Vec<IndexDef> {
        self.indexes.keys().cloned().collect()
    }

    /// Index a document on write/update
    pub fn on_set(
        &mut self,
        key: &str,
        new_doc: &serde_json::Value,
        old_doc: Option<&serde_json::Value>,
    ) {
        for (def, value_map) in self.indexes.iter_mut() {
            if key.starts_with(&def.prefix) {
                // If there was an old value, remove key from old index bucket
                if let Some(old) = old_doc {
                    if let Some(old_val) = resolve_json_path(old, &def.field) {
                        let old_key = serialize_field_key(old_val);
                        if let Some(set) = value_map.get_mut(&old_key) {
                            set.remove(key);
                        }
                    }
                }

                // Add to new index bucket
                if let Some(new_val) = resolve_json_path(new_doc, &def.field) {
                    let new_key = serialize_field_key(new_val);
                    value_map
                        .entry(new_key)
                        .or_default()
                        .insert(key.to_string());
                }
            }
        }
    }

    /// Remove a document from all secondary indexes on delete
    pub fn on_delete(&mut self, key: &str, old_doc: &serde_json::Value) {
        for (def, value_map) in self.indexes.iter_mut() {
            if key.starts_with(&def.prefix) {
                if let Some(val) = resolve_json_path(old_doc, &def.field) {
                    let field_key = serialize_field_key(val);
                    if let Some(set) = value_map.get_mut(&field_key) {
                        set.remove(key);
                    }
                }
            }
        }
    }

    /// Find primary keys matching an indexed field value
    pub fn find_keys(&self, prefix: &str, field: &str, value: &serde_json::Value) -> Vec<String> {
        let def = IndexDef {
            prefix: prefix.to_string(),
            field: field.to_string(),
        };

        if let Some(value_map) = self.indexes.get(&def) {
            let field_key = serialize_field_key(value);
            if let Some(set) = value_map.get(&field_key) {
                return set.iter().cloned().collect();
            }
        }

        Vec::new()
    }
}

/// Convert field value to deterministic index string
fn serialize_field_key(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Traverse a nested JSON value using dot notation (e.g. "profile.address.city" or "items.0.name")
pub fn resolve_json_path<'a>(
    root: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(root);
    }

    let mut current = root;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment)?;
            }
            serde_json::Value::Array(arr) => {
                let idx = segment.parse::<usize>().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Mutate a nested JSON value at path
pub fn set_json_path(
    root: &mut serde_json::Value,
    path: &str,
    new_value: serde_json::Value,
) -> Result<(), String> {
    if path.is_empty() {
        *root = new_value;
        return Ok(());
    }

    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, &segment) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;

        if is_last {
            match current {
                serde_json::Value::Object(map) => {
                    map.insert(segment.to_string(), new_value);
                    return Ok(());
                }
                serde_json::Value::Array(arr) => {
                    let idx = segment
                        .parse::<usize>()
                        .map_err(|_| "Array index must be numeric")?;
                    if idx < arr.len() {
                        arr[idx] = new_value;
                        return Ok(());
                    } else if idx == arr.len() {
                        arr.push(new_value);
                        return Ok(());
                    } else {
                        return Err(format!("Index {} out of bounds (len: {})", idx, arr.len()));
                    }
                }
                _ => return Err("Cannot set property on non-object/array".into()),
            }
        } else {
            // Need object or array
            if !current.is_object() && !current.is_array() {
                *current = serde_json::Value::Object(serde_json::Map::new());
            }

            match current {
                serde_json::Value::Object(map) => {
                    if !map.contains_key(segment) {
                        map.insert(
                            segment.to_string(),
                            serde_json::Value::Object(serde_json::Map::new()),
                        );
                    }
                    current = map.get_mut(segment).unwrap();
                }
                _ => return Err("Nested array path creation not supported".into()),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_json_path() {
        let doc = serde_json::json!({
            "name": "Bob",
            "profile": {
                "age": 30,
                "address": {
                    "city": "Berlin"
                }
            },
            "tags": ["rust", "sovereign"]
        });

        assert_eq!(resolve_json_path(&doc, "name").unwrap(), "Bob");
        assert_eq!(resolve_json_path(&doc, "profile.age").unwrap(), 30);
        assert_eq!(
            resolve_json_path(&doc, "profile.address.city").unwrap(),
            "Berlin"
        );
        assert_eq!(resolve_json_path(&doc, "tags.0").unwrap(), "rust");
        assert!(resolve_json_path(&doc, "profile.nonexistent").is_none());
    }

    #[test]
    fn test_set_json_path() {
        let mut doc = serde_json::json!({
            "name": "Alice"
        });

        set_json_path(&mut doc, "role", serde_json::json!("admin")).unwrap();
        assert_eq!(doc["role"], "admin");

        set_json_path(&mut doc, "meta.verified", serde_json::json!(true)).unwrap();
        assert_eq!(doc["meta"]["verified"], true);
    }

    #[test]
    fn test_secondary_index() {
        let mut manager = SecondaryIndexManager::new();
        manager.register_index("users:".to_string(), "role".to_string());

        let user1 = serde_json::json!({"name": "Alice", "role": "admin"});
        let user2 = serde_json::json!({"name": "Bob", "role": "developer"});
        let user3 = serde_json::json!({"name": "Charlie", "role": "admin"});

        manager.on_set("users:alice", &user1, None);
        manager.on_set("users:bob", &user2, None);
        manager.on_set("users:charlie", &user3, None);

        let admins = manager.find_keys("users:", "role", &serde_json::json!("admin"));
        assert_eq!(admins.len(), 2);
        assert!(admins.contains(&"users:alice".to_string()));
        assert!(admins.contains(&"users:charlie".to_string()));

        // Update Alice's role to developer
        let user1_updated = serde_json::json!({"name": "Alice", "role": "developer"});
        manager.on_set("users:alice", &user1_updated, Some(&user1));

        let admins_after = manager.find_keys("users:", "role", &serde_json::json!("admin"));
        assert_eq!(admins_after.len(), 1);
        assert_eq!(admins_after[0], "users:charlie");

        let devs = manager.find_keys("users:", "role", &serde_json::json!("developer"));
        assert_eq!(devs.len(), 2);
    }
}
