use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::vcs::VcsEngine;

pub const DEV_WORKSPACE_PREFIX: &str = "dev/";

/// Validates that a workspace identifier matches canonical format:
/// Must start with "dev/", followed by sub-namespace (e.g. "tools/sb-core"),
/// only contain alphanumeric characters, '-', '_', and '/'. No empty segments, no '..' or '.'.
pub fn validate_workspace_id(id: &str) -> Result<(), String> {
    if !id.starts_with(DEV_WORKSPACE_PREFIX) {
        return Err(format!(
            "Dev workspace ID must start with '{}' (got '{}')",
            DEV_WORKSPACE_PREFIX, id
        ));
    }
    let sub = &id[DEV_WORKSPACE_PREFIX.len()..];
    if sub.is_empty() {
        return Err("Dev workspace ID cannot have an empty name after prefix".into());
    }
    for segment in sub.split('/') {
        if segment.is_empty() {
            return Err("Dev workspace ID cannot contain empty path segments '//'".into());
        }
        if segment == "." || segment == ".." {
            return Err(
                "Dev workspace ID cannot contain relative path elements ('.' or '..')".into(),
            );
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "Invalid characters in workspace segment '{}'; only alphanumeric, '-', and '_' are allowed",
                segment
            ));
        }
    }
    Ok(())
}

/// Access and replication policy for a specific Dev-Mesh workspace.
/// Enforces single authoritative writer and explicit replica list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevWorkspacePolicy {
    pub workspace_id: String,
    pub project_name: String,
    /// Node ID of the sole authoritative writer for this tool workspace
    pub authoritative_writer: String,
    /// List of node IDs allowed to replicate (read/pull) this workspace
    pub allowed_replicas: Vec<String>,
    pub policy_version: u32,
    /// Require that all pushes are strict fast-forwards (no history overwrites)
    pub require_fast_forward: bool,
    /// Optional Ed25519 signature of the policy canonical payload
    #[serde(default)]
    pub signature: Option<String>,
}

impl DevWorkspacePolicy {
    pub fn new(
        workspace_id: impl Into<String>,
        project_name: impl Into<String>,
        authoritative_writer: impl Into<String>,
        allowed_replicas: Vec<String>,
    ) -> Result<Self, String> {
        let wid = workspace_id.into();
        validate_workspace_id(&wid)?;
        Ok(Self {
            workspace_id: wid,
            project_name: project_name.into(),
            authoritative_writer: authoritative_writer.into(),
            allowed_replicas,
            policy_version: 1,
            require_fast_forward: true,
            signature: None,
        })
    }

    /// Canonical payload for Ed25519 policy signing
    pub fn signing_digest(&self) -> Vec<u8> {
        let mut sorted_replicas = self.allowed_replicas.clone();
        sorted_replicas.sort();
        let payload = format!(
            "SB_DEV_WORKSPACE_V1|{}|{}|{}|{}|{}|{}",
            self.workspace_id,
            self.project_name,
            self.authoritative_writer,
            sorted_replicas.join(","),
            self.policy_version,
            self.require_fast_forward
        );
        blake3::hash(payload.as_bytes()).as_bytes().to_vec()
    }

    pub fn sign(&mut self, key_bytes: &[u8; 32]) {
        let signing_key = SigningKey::from_bytes(key_bytes);
        let digest = self.signing_digest();
        let sig = signing_key.sign(&digest);
        let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        self.signature = Some(format!("ed25519:{pub_hex}:{sig_hex}"));
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        let sig_str = self
            .signature
            .as_deref()
            .ok_or_else(|| "Workspace policy has no signature".to_string())?;
        let parts: Vec<&str> = sig_str.split(':').collect();
        if parts.len() != 3 || parts[0] != "ed25519" {
            return Err("Invalid policy signature format".into());
        }
        let pub_bytes =
            hex::decode(parts[1]).map_err(|e| format!("Invalid signer public key hex: {e}"))?;
        let sig_bytes = hex::decode(parts[2]).map_err(|e| format!("Invalid signature hex: {e}"))?;
        let pub_arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| "Signer public key must be 32 bytes".to_string())?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "Signature must be 64 bytes".to_string())?;

        let verifying_key = VerifyingKey::from_bytes(&pub_arr)
            .map_err(|e| format!("Invalid Ed25519 verifying key: {e}"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let digest = self.signing_digest();

        verifying_key
            .verify(&digest, &signature)
            .map_err(|e| format!("Workspace policy signature verification failed: {e}"))
    }

    /// Authorizes a push (write) request.
    /// Fails closed if caller is not the authoritative writer or if capability token is invalid.
    pub fn authorize_write(
        &self,
        caller_node_id: &str,
        token: Option<&sb_mesh::acl::CapabilityToken>,
    ) -> Result<(), String> {
        if caller_node_id.trim().is_empty() {
            return Err("Caller node ID is required for workspace write authorization".into());
        }
        if caller_node_id != self.authoritative_writer {
            return Err(format!(
                "Access Denied: Node '{}' is not the authoritative writer for workspace '{}' (writer is '{}')",
                caller_node_id, self.workspace_id, self.authoritative_writer
            ));
        }

        // If capability token is provided, verify it strictly
        if let Some(tok) = token {
            let now = Utc::now().timestamp() as u64;
            tok.verify(now).map_err(|e| {
                format!("Capability token verification failed for workspace write: {e}")
            })?;
            if tok.subject_node_id != caller_node_id {
                return Err(format!(
                    "Capability token subject mismatch: Token is for '{}', caller is '{}'",
                    tok.subject_node_id, caller_node_id
                ));
            }
            if !tok
                .allowed_ports
                .contains(&crate::mesh_sync::CODE_SYNC_PORT)
            {
                return Err(format!(
                    "Capability token does not permit access to code-sync port {}",
                    crate::mesh_sync::CODE_SYNC_PORT
                ));
            }
        }

        Ok(())
    }

    /// Authorizes a pull (read/replicate) request.
    /// Fails closed if caller is neither writer nor in allowed_replicas list.
    pub fn authorize_read(
        &self,
        caller_node_id: &str,
        token: Option<&sb_mesh::acl::CapabilityToken>,
    ) -> Result<(), String> {
        if caller_node_id.trim().is_empty() {
            return Err("Caller node ID is required for workspace read authorization".into());
        }

        let is_writer = caller_node_id == self.authoritative_writer;
        let is_replica = self
            .allowed_replicas
            .iter()
            .any(|r| r == caller_node_id || r == "*");

        if !is_writer && !is_replica {
            return Err(format!(
                "Access Denied: Node '{}' is not authorized to read/replicate workspace '{}'",
                caller_node_id, self.workspace_id
            ));
        }

        if let Some(tok) = token {
            let now = Utc::now().timestamp() as u64;
            tok.verify(now).map_err(|e| {
                format!("Capability token verification failed for workspace read: {e}")
            })?;
            if tok.subject_node_id != caller_node_id {
                return Err(format!(
                    "Capability token subject mismatch: Token is for '{}', caller is '{}'",
                    tok.subject_node_id, caller_node_id
                ));
            }
            if !tok
                .allowed_ports
                .contains(&crate::mesh_sync::CODE_SYNC_PORT)
            {
                return Err(format!(
                    "Capability token does not permit access to code-sync port {}",
                    crate::mesh_sync::CODE_SYNC_PORT
                ));
            }
        }

        Ok(())
    }
}

/// Represents a registered Dev-Mesh workspace directory and its replication policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevWorkspaceEntry {
    pub workspace_id: String,
    pub repo_path: PathBuf,
    pub policy: DevWorkspacePolicy,
}

/// Registry mapping logical Dev-Mesh workspace IDs to isolated local repositories and policies.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DevWorkspaceRegistry {
    pub workspaces: HashMap<String, DevWorkspaceEntry>,
}

impl DevWorkspaceRegistry {
    pub fn new() -> Self {
        Self {
            workspaces: HashMap::new(),
        }
    }

    pub fn register(&mut self, entry: DevWorkspaceEntry) -> Result<(), String> {
        validate_workspace_id(&entry.workspace_id)?;
        if entry.workspace_id != entry.policy.workspace_id {
            return Err("Entry workspace_id must match policy workspace_id".into());
        }
        self.workspaces.insert(entry.workspace_id.clone(), entry);
        Ok(())
    }

    pub fn get(&self, workspace_id: &str) -> Option<&DevWorkspaceEntry> {
        self.workspaces.get(workspace_id)
    }

    pub fn get_engine(&self, workspace_id: &str) -> Result<VcsEngine, String> {
        let entry = self
            .get(workspace_id)
            .ok_or_else(|| format!("Unknown Dev-Mesh workspace: '{}'", workspace_id))?;
        VcsEngine::open(&entry.repo_path).map_err(|e| {
            format!(
                "Failed to open workspace repository for '{}': {}",
                workspace_id, e
            )
        })
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "Failed to read workspace registry from '{}': {}",
                path.display(),
                e
            )
        })?;
        serde_json::from_str(&content).map_err(|e| {
            format!(
                "Invalid workspace registry JSON at '{}': {}",
                path.display(),
                e
            )
        })
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let serialized = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize workspace registry: {e}"))?;
        std::fs::write(path, serialized).map_err(|e| {
            format!(
                "Failed to write workspace registry to '{}': {}",
                path.display(),
                e
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use sb_mesh::curve25519_dalek::scalar::Scalar;

    #[test]
    fn workspace_id_validation_rules() {
        assert!(validate_workspace_id("dev/tools/sb-core").is_ok());
        assert!(validate_workspace_id("dev/tools/sb-mesh").is_ok());
        assert!(validate_workspace_id("dev/my-project_v1").is_ok());

        // Invalid: missing dev/ prefix
        assert!(validate_workspace_id("tools/sb-core").is_err());
        assert!(validate_workspace_id("sb-core").is_err());
        assert!(validate_workspace_id("dev/").is_err());
        assert!(validate_workspace_id("dev//sb-core").is_err());
        assert!(validate_workspace_id("dev/tools/../escaped").is_err());
        assert!(validate_workspace_id("dev/tools/./escaped").is_err());
        assert!(validate_workspace_id("dev/tools/invalid$char").is_err());
    }

    #[test]
    fn policy_authorizes_writer_and_rejects_unauthorized_node() {
        let policy = DevWorkspacePolicy::new(
            "dev/tools/sb-core",
            "sb-core",
            "writer-node-1",
            vec!["replica-node-2".to_string()],
        )
        .unwrap();

        // Writer can write
        assert!(policy.authorize_write("writer-node-1", None).is_ok());

        // Replica CANNOT write
        let err = policy.authorize_write("replica-node-2", None).unwrap_err();
        assert!(err.contains("Access Denied"));
        assert!(err.contains("not the authoritative writer"));

        // Unknown node CANNOT write
        assert!(policy.authorize_write("attacker-node", None).is_err());

        // Empty node ID rejected
        assert!(policy.authorize_write("", None).is_err());
    }

    #[test]
    fn policy_authorizes_replicas_and_writer_for_read() {
        let policy = DevWorkspacePolicy::new(
            "dev/tools/sb-core",
            "sb-core",
            "writer-node-1",
            vec!["replica-node-2".to_string(), "replica-node-3".to_string()],
        )
        .unwrap();

        // Writer can read
        assert!(policy.authorize_read("writer-node-1", None).is_ok());
        // Replicas can read
        assert!(policy.authorize_read("replica-node-2", None).is_ok());
        assert!(policy.authorize_read("replica-node-3", None).is_ok());

        // Unknown node cannot read
        let err = policy
            .authorize_read("unauthorized-peer", None)
            .unwrap_err();
        assert!(err.contains("Access Denied"));
        assert!(err.contains("not authorized to read/replicate"));
    }

    #[test]
    fn capability_token_validation_and_subject_isolation() {
        let policy = DevWorkspacePolicy::new(
            "dev/tools/sb-core",
            "sb-core",
            "writer-node-1",
            vec!["replica-node-2".to_string()],
        )
        .unwrap();

        let authority_secret = Scalar::random(&mut OsRng);

        // 1. Valid token for writer-node-1 with correct port
        let valid_writer_token = sb_mesh::acl::CapabilityToken::issue(
            "authority-node",
            "writer-node-1",
            vec![crate::mesh_sync::CODE_SYNC_PORT],
            Utc::now().timestamp() as u64 + 3600,
            &authority_secret,
        );
        assert!(policy
            .authorize_write("writer-node-1", Some(&valid_writer_token))
            .is_ok());

        // 2. Token subject mismatch: Token is for replica-node-2, caller tries to push as writer-node-1
        let mismatch_token = sb_mesh::acl::CapabilityToken::issue(
            "authority-node",
            "replica-node-2",
            vec![crate::mesh_sync::CODE_SYNC_PORT],
            Utc::now().timestamp() as u64 + 3600,
            &authority_secret,
        );
        let err = policy
            .authorize_write("writer-node-1", Some(&mismatch_token))
            .unwrap_err();
        assert!(err.contains("subject mismatch"));

        // 3. Token for wrong port (e.g. 80 instead of 58832)
        let wrong_port_token = sb_mesh::acl::CapabilityToken::issue(
            "authority-node",
            "writer-node-1",
            vec![80],
            Utc::now().timestamp() as u64 + 3600,
            &authority_secret,
        );
        let err = policy
            .authorize_write("writer-node-1", Some(&wrong_port_token))
            .unwrap_err();
        assert!(err.contains("does not permit access to code-sync port"));

        // 4. Expired token
        let expired_token = sb_mesh::acl::CapabilityToken::issue(
            "authority-node",
            "writer-node-1",
            vec![crate::mesh_sync::CODE_SYNC_PORT],
            Utc::now().timestamp() as u64 - 10,
            &authority_secret,
        );
        let err = policy
            .authorize_write("writer-node-1", Some(&expired_token))
            .unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn policy_signing_and_tamper_detection() {
        let mut policy = DevWorkspacePolicy::new(
            "dev/tools/sb-core",
            "sb-core",
            "writer-node-1",
            vec!["replica-node-2".to_string()],
        )
        .unwrap();

        let seed = [42u8; 32];
        policy.sign(&seed);
        assert!(policy.verify_signature().is_ok());

        // Tamper with authoritative_writer
        let mut tampered = policy.clone();
        tampered.authoritative_writer = "attacker".to_string();
        assert!(tampered.verify_signature().is_err());

        // Tamper with allowed_replicas
        let mut tampered2 = policy.clone();
        tampered2.allowed_replicas.push("attacker".to_string());
        assert!(tampered2.verify_signature().is_err());
    }

    #[test]
    fn registry_save_load_and_lookup() {
        let temp_dir = std::env::temp_dir().join(format!("sb_dev_reg_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let repo1 = temp_dir.join("sb-core");
        let repo2 = temp_dir.join("sb-mesh");
        std::fs::create_dir_all(&repo1).unwrap();
        std::fs::create_dir_all(&repo2).unwrap();

        let mut reg = DevWorkspaceRegistry::new();
        let policy1 = DevWorkspacePolicy::new(
            "dev/tools/sb-core",
            "sb-core",
            "writer-core",
            vec!["replica-1".into()],
        )
        .unwrap();
        let policy2 = DevWorkspacePolicy::new(
            "dev/tools/sb-mesh",
            "sb-mesh",
            "writer-mesh",
            vec!["replica-2".into()],
        )
        .unwrap();

        reg.register(DevWorkspaceEntry {
            workspace_id: "dev/tools/sb-core".into(),
            repo_path: repo1.clone(),
            policy: policy1,
        })
        .unwrap();

        reg.register(DevWorkspaceEntry {
            workspace_id: "dev/tools/sb-mesh".into(),
            repo_path: repo2.clone(),
            policy: policy2,
        })
        .unwrap();

        let file = temp_dir.join("workspaces.json");
        reg.save_to_file(&file).unwrap();

        let loaded = DevWorkspaceRegistry::load_from_file(&file).unwrap();
        assert_eq!(loaded.workspaces.len(), 2);
        assert_eq!(
            loaded
                .get("dev/tools/sb-core")
                .unwrap()
                .policy
                .authoritative_writer,
            "writer-core"
        );
        assert_eq!(
            loaded
                .get("dev/tools/sb-mesh")
                .unwrap()
                .policy
                .authoritative_writer,
            "writer-mesh"
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
