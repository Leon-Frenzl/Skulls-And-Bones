use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Legacy prototype commit; `signature_ed25519` is a placeholder, not a signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleCommit {
    pub commit_id: String,
    pub parent_id: Option<String>,
    pub author_callsign: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub root_tree_hash: String,
    pub signature_ed25519: String,
}

/// Local commit store managing the repository history.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CommitStore {
    pub head_commit_id: Option<String>,
    pub commits: Vec<MerkleCommit>,
}

impl CommitStore {
    pub fn load_or_init(workspace_root: &Path) -> Self {
        let store_path = workspace_root.join(".sb").join("code").join("history.json");
        if store_path.exists() {
            if let Ok(content) = fs::read_to_string(&store_path) {
                if let Ok(store) = serde_json::from_str::<CommitStore>(&content) {
                    return store;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self, workspace_root: &Path) -> std::io::Result<()> {
        let dir = workspace_root.join(".sb").join("code");
        fs::create_dir_all(&dir)?;
        let store_path = dir.join("history.json");
        let content = serde_json::to_string_pretty(self)?;
        fs::write(store_path, content)?;
        Ok(())
    }

    pub fn create_commit(
        &mut self,
        message: &str,
        root_tree_hash: &str,
        author_callsign: &str,
    ) -> MerkleCommit {
        let timestamp = Utc::now();
        let parent_id = self.head_commit_id.clone();

        // Calculate BLAKE3 commit ID
        let mut hasher = blake3::Hasher::new();
        if let Some(ref p) = parent_id {
            hasher.update(p.as_bytes());
        }
        hasher.update(author_callsign.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(message.as_bytes());
        hasher.update(root_tree_hash.as_bytes());
        let commit_id = hasher.finalize().to_hex().to_string();

        // Retained only for legacy prototype output; this is not cryptographic signing.
        let signature_ed25519 = format!("ed25519_sig_{}", &commit_id[..16]);

        let commit = MerkleCommit {
            commit_id: commit_id.clone(),
            parent_id,
            author_callsign: author_callsign.to_string(),
            timestamp,
            message: message.to_string(),
            root_tree_hash: root_tree_hash.to_string(),
            signature_ed25519,
        };

        self.head_commit_id = Some(commit_id);
        self.commits.push(commit.clone());

        commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_chain() {
        let mut store = CommitStore::default();
        assert!(store.head_commit_id.is_none());

        let c1 = store.create_commit("Initial commit", "blake3_root_1", "sentinel-prime");
        assert_eq!(store.head_commit_id, Some(c1.commit_id.clone()));
        assert!(c1.parent_id.is_none());

        let c2 = store.create_commit("Add auth module", "blake3_root_2", "sentinel-prime");
        assert_eq!(c2.parent_id, Some(c1.commit_id));
        assert_eq!(store.commits.len(), 2);
    }
}
