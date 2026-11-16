//! Sovereign Per-User & Group-Scoped Team Password Manager (`sb-node::vault_manager`).
//!
//! Reuses `sb_core::vault` (Argon2id + AES-256-GCM + `ZeroizeOnDrop`) to provide encrypted
//! personal vaults (`/v1/me/vault`) and RBAC-enforced team vaults (`/v1/vault/team`).

use sb_core::identity::validate_username;
use sb_core::policy::validate_policy_id;
use sb_core::vault::{VaultFile, VaultSecretEntry, VaultSession, VaultStore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Metadata for a vault entry (safe to return without decrypting or knowing the passphrase).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntryMeta {
    pub key: String,
    pub label: String,
    pub updated_at: String,
    pub updated_by: String,
    pub version: u32,
}

/// Returns the default root directory for domain user & team vaults (`~/.sb/domain/vaults`).
pub fn default_vaults_root() -> PathBuf {
    sb_core::domain::local_domain_dir().join("vaults")
}

fn personal_store(vaults_root: &Path) -> VaultStore {
    VaultStore::new(vaults_root.join("users"))
}

fn team_store(vaults_root: &Path) -> VaultStore {
    VaultStore::new(vaults_root.join("teams"))
}

/// Validates a secret key name (`[a-z0-9][a-z0-9_-]{0,63}`) to prevent path/TOML key injection.
pub fn validate_secret_key(key: &str) -> Result<String, String> {
    validate_policy_id(key)
}

fn list_entries(store: &VaultStore, env_name: &str) -> Result<Vec<VaultEntryMeta>, String> {
    let file = store.load(env_name)?;
    let mut out: Vec<VaultEntryMeta> = file
        .secrets
        .into_iter()
        .map(|(k, v)| VaultEntryMeta {
            key: k,
            label: v.project,
            updated_at: v.updated_at,
            updated_by: v.updated_by,
            version: v.version,
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

/// Encrypts and stores a secret in a `VaultFile`, initializing the verifier on first use.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Weak/unauthenticated vault files accepting arbitrary wrong
///   passphrases when empty, or plaintext secret leakage to disk.
/// - **CVE / CWE Mapping:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-287
///   (Improper Authentication).
/// - **Likelihood & Exploitability:** High (8/10) for credential storage.
/// - **Applied Mitigation:** Reuses `sb_core::vault::VaultSession` (Argon2id key derivation +
///   AES-256-GCM AEAD + `ZeroizeOnDrop`) and verifies the vault passphrase against the stored
///   authenticated verifier before writing or decrypting.
///
/// # Standards Compliance
/// - Conforms to RFC 9106 (Argon2id) and NIST SP 800-38D (AES-GCM).
fn put_encrypted_secret(
    store: &VaultStore,
    env_name: &str,
    key: &str,
    label: &str,
    secret_value: &str,
    passphrase: &str,
    actor: &str,
) -> Result<VaultEntryMeta, String> {
    let clean_key = validate_secret_key(key)?;
    if passphrase.is_empty() {
        return Err("Vault passphrase cannot be empty".into());
    }
    if secret_value.is_empty() || secret_value.len() > 32 * 1024 {
        return Err("Secret value must be 1..=32768 bytes".into());
    }
    let clean_label = label.trim();
    let project = if clean_label.is_empty() {
        "general".to_string()
    } else {
        clean_label.chars().take(128).collect()
    };

    let session = VaultSession::new(passphrase);
    let mut vault: VaultFile = store.load(env_name)?;
    if vault.verifier.is_none() {
        session.initialize(&mut vault)?;
    } else {
        session.verify_vault(&vault)?;
    }

    let (ciphertext, nonce, salt) = session.encrypt(secret_value)?;
    let next_ver = vault
        .secrets
        .get(&clean_key)
        .map(|e| e.version.saturating_add(1))
        .unwrap_or(1);
    let now = chrono::Utc::now().to_rfc3339();
    let entry = VaultSecretEntry {
        ciphertext,
        nonce,
        salt,
        updated_at: now.clone(),
        updated_by: actor.to_string(),
        version: next_ver,
        project: project.clone(),
    };
    vault.secrets.insert(clean_key.clone(), entry);
    store.save(env_name, &vault)?;

    Ok(VaultEntryMeta {
        key: clean_key,
        label: project,
        updated_at: now,
        updated_by: actor.to_string(),
        version: next_ver,
    })
}

fn reveal_encrypted_secret(
    store: &VaultStore,
    env_name: &str,
    key: &str,
    passphrase: &str,
) -> Result<String, String> {
    let clean_key = validate_secret_key(key)?;
    if passphrase.is_empty() {
        return Err("Vault passphrase cannot be empty".into());
    }
    let session = VaultSession::new(passphrase);
    let vault = store.load(env_name)?;
    session.verify_vault(&vault)?;
    let entry = vault
        .secrets
        .get(&clean_key)
        .ok_or_else(|| format!("Secret '{clean_key}' not found"))?;
    session.decrypt(entry)
}

fn delete_encrypted_secret(store: &VaultStore, env_name: &str, key: &str) -> Result<bool, String> {
    let clean_key = validate_secret_key(key)?;
    let mut vault = store.load(env_name)?;
    let existed = vault.secrets.remove(&clean_key).is_some();
    if existed {
        store.save(env_name, &vault)?;
    }
    Ok(existed)
}

/// Lists metadata for a user's personal encrypted vault.
pub fn list_personal_vault(
    username: &str,
    vaults_root: &Path,
) -> Result<Vec<VaultEntryMeta>, String> {
    let clean_user = validate_username(username)?;
    list_entries(&personal_store(vaults_root), &clean_user)
}

/// Stores an encrypted secret in a user's personal vault.
pub fn put_personal_secret(
    username: &str,
    key: &str,
    label: &str,
    secret_value: &str,
    passphrase: &str,
    vaults_root: &Path,
) -> Result<VaultEntryMeta, String> {
    let clean_user = validate_username(username)?;
    put_encrypted_secret(
        &personal_store(vaults_root),
        &clean_user,
        key,
        label,
        secret_value,
        passphrase,
        &clean_user,
    )
}

/// Decrypts a secret from a user's personal vault.
pub fn reveal_personal_secret(
    username: &str,
    key: &str,
    passphrase: &str,
    vaults_root: &Path,
) -> Result<String, String> {
    let clean_user = validate_username(username)?;
    reveal_encrypted_secret(&personal_store(vaults_root), &clean_user, key, passphrase)
}

/// Deletes a secret from a user's personal vault.
pub fn delete_personal_secret(
    username: &str,
    key: &str,
    vaults_root: &Path,
) -> Result<bool, String> {
    let clean_user = validate_username(username)?;
    delete_encrypted_secret(&personal_store(vaults_root), &clean_user, key)
}

/// Lists metadata for a group-scoped team vault.
pub fn list_team_vault(group: &str, vaults_root: &Path) -> Result<Vec<VaultEntryMeta>, String> {
    let clean_group = validate_policy_id(group)?;
    list_entries(&team_store(vaults_root), &clean_group)
}

/// Stores an encrypted secret in a group-scoped team vault.
pub fn put_team_secret(
    group: &str,
    key: &str,
    label: &str,
    secret_value: &str,
    passphrase: &str,
    actor: &str,
    vaults_root: &Path,
) -> Result<VaultEntryMeta, String> {
    let clean_group = validate_policy_id(group)?;
    put_encrypted_secret(
        &team_store(vaults_root),
        &clean_group,
        key,
        label,
        secret_value,
        passphrase,
        actor,
    )
}

/// Decrypts a secret from a group-scoped team vault.
pub fn reveal_team_secret(
    group: &str,
    key: &str,
    passphrase: &str,
    vaults_root: &Path,
) -> Result<String, String> {
    let clean_group = validate_policy_id(group)?;
    reveal_encrypted_secret(&team_store(vaults_root), &clean_group, key, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_and_team_vaults_encrypt_and_enforce_passphrase() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_vault_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        put_personal_secret(
            "anna.admin",
            "github-pat",
            "https://github.com",
            "ghp_super_secret_123",
            "correct-horse-battery-staple",
            &temp,
        )
        .unwrap();

        let metas = list_personal_vault("anna.admin", &temp).unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].key, "github-pat");

        // Wrong passphrase must fail
        assert!(reveal_personal_secret("anna.admin", "github-pat", "wrong-pass", &temp).is_err());

        // Correct passphrase decrypts
        let plain = reveal_personal_secret(
            "anna.admin",
            "github-pat",
            "correct-horse-battery-staple",
            &temp,
        )
        .unwrap();
        assert_eq!(plain, "ghp_super_secret_123");

        // Team vault
        put_team_secret(
            "engineering",
            "prod-db-root",
            "Postgres Primary",
            "pg_pass_xyz",
            "team-master-key-99",
            "anna.admin",
            &temp,
        )
        .unwrap();
        assert_eq!(
            reveal_team_secret("engineering", "prod-db-root", "team-master-key-99", &temp).unwrap(),
            "pg_pass_xyz"
        );

        let _ = std::fs::remove_dir_all(&temp);
    }
}
