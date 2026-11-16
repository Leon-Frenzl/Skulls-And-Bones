//! Linux Local Administrator Password Solution (LAPS) for `sb-node`.
//!
//! Generates per-machine emergency local admin passwords using `OsRng`, stores them
//! encrypted via `sb_core::vault` (Argon2id + AES-256-GCM), optionally applies the password
//! locally on Linux via `chpasswd`, and flags `rotate_pending` after every admin reveal.

use chrono::{Duration, Utc};
use rand::RngCore;
use sb_core::policy::validate_policy_id;
use sb_core::vault::{VaultFile, VaultSecretEntry, VaultSession, VaultStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Metadata for a machine's LAPS emergency password (safe to return without passphrase).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LapsMetadata {
    pub machine_id: String,
    pub local_account: String,
    pub rotated_at: String,
    pub expires_at: String,
    pub rotate_pending: bool,
    pub version: u32,
}

/// Persistent LAPS metadata index (`~/.sb/domain/laps_meta.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LapsMetaStore {
    pub entries: BTreeMap<String, LapsMetadata>,
}

/// Generates a strong 24-character password using OS CSPRNG (`OsRng`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Predictable or shared emergency admin passwords across
///   domain-joined Linux hosts.
/// - **CVE / CWE Mapping:** CWE-330 (Use of Insufficiently Random Values), CWE-798
///   (Use of Hard-coded Credentials).
/// - **Likelihood & Exploitability:** High (8/10) if static or weak rescue passwords are used.
/// - **Applied Mitigation:** Uses 24 rejection-free random selections from a 64-char alphabet
///   (`64^24 = 2^144` bits of entropy) backed by `OsRng`.
pub fn generate_laps_password() -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&";
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[(b & 63) as usize] as char)
        .collect()
}

/// Validates a Linux local rescue account name (`[a-z_][a-z0-9_-]{0,31}`).
pub fn validate_linux_account(account: &str) -> Result<String, String> {
    let trimmed = account.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err("Linux account name must be 1..=32 characters".into());
    }
    let first = trimmed.as_bytes()[0];
    if !first.is_ascii_lowercase() && first != b'_' {
        return Err("Linux account must start with lowercase letter or '_'".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("Linux account contains invalid characters".into());
    }
    Ok(trimmed.to_string())
}

pub fn default_laps_meta_path() -> PathBuf {
    sb_core::domain::local_domain_dir().join("laps_meta.json")
}

pub fn default_laps_vault_dir() -> PathBuf {
    sb_core::domain::local_domain_dir()
        .join("vaults")
        .join("laps")
}

impl LapsMetaStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read LAPS metadata {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid LAPS metadata JSON {}: {e}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create LAPS dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize LAPS metadata: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp LAPS metadata: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit LAPS metadata: {e}"))?;
        Ok(())
    }
}

/// Encrypts and stores a rotated LAPS password for `machine_id`, updating metadata.
pub fn store_laps_password(
    machine_id: &str,
    local_account: &str,
    password: &str,
    passphrase: &str,
    ttl_days: i64,
    vault_dir: &Path,
    meta_path: &Path,
) -> Result<LapsMetadata, String> {
    let clean_id = validate_policy_id(machine_id)?;
    let clean_acct = validate_linux_account(local_account)?;
    if passphrase.is_empty() || password.len() < 12 {
        return Err("LAPS passphrase cannot be empty and password must be >= 12 chars".into());
    }

    let store = VaultStore::new(vault_dir);
    let session = VaultSession::new(passphrase);
    let mut vault: VaultFile = store.load("laps")?;
    if vault.verifier.is_none() {
        session.initialize(&mut vault)?;
    } else {
        session.verify_vault(&vault)?;
    }

    let (ciphertext, nonce, salt) = session.encrypt(password)?;
    let mut meta_store = LapsMetaStore::load(meta_path)?;
    let next_ver = meta_store
        .entries
        .get(&clean_id)
        .map(|m| m.version.saturating_add(1))
        .unwrap_or(1);

    let now = Utc::now();
    let clamped_days = ttl_days.clamp(1, 90);
    let rotated_at = now.to_rfc3339();
    let expires_at = (now + Duration::days(clamped_days)).to_rfc3339();

    vault.secrets.insert(
        clean_id.clone(),
        VaultSecretEntry {
            ciphertext,
            nonce,
            salt,
            updated_at: rotated_at.clone(),
            updated_by: clean_acct.clone(),
            version: next_ver,
            project: "laps".into(),
        },
    );
    store.save("laps", &vault)?;

    let meta = LapsMetadata {
        machine_id: clean_id.clone(),
        local_account: clean_acct,
        rotated_at,
        expires_at,
        rotate_pending: false,
        version: next_ver,
    };
    meta_store.entries.insert(clean_id, meta.clone());
    meta_store.save(meta_path)?;
    Ok(meta)
}

/// Decrypts a machine's LAPS password and marks `rotate_pending = true` so it rotates next.
pub fn reveal_laps_password(
    machine_id: &str,
    passphrase: &str,
    vault_dir: &Path,
    meta_path: &Path,
) -> Result<(String, LapsMetadata), String> {
    let clean_id = validate_policy_id(machine_id)?;
    if passphrase.is_empty() {
        return Err("LAPS passphrase cannot be empty".into());
    }
    let store = VaultStore::new(vault_dir);
    let session = VaultSession::new(passphrase);
    let vault = store.load("laps")?;
    session.verify_vault(&vault)?;
    let entry = vault
        .secrets
        .get(&clean_id)
        .ok_or_else(|| format!("No LAPS password stored for machine '{clean_id}'"))?;
    let password = session.decrypt(entry)?;

    let mut meta_store = LapsMetaStore::load(meta_path)?;
    let meta = meta_store
        .entries
        .get_mut(&clean_id)
        .ok_or_else(|| format!("Missing LAPS metadata for '{clean_id}'"))?;
    meta.rotate_pending = true;
    let updated_meta = meta.clone();
    meta_store.save(meta_path)?;
    Ok((password, updated_meta))
}

/// Applies the LAPS password locally on Linux via `chpasswd` (unless `dry_run` is true).
#[cfg(target_os = "linux")]
pub fn apply_linux_chpasswd(account: &str, password: &str, dry_run: bool) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let clean_acct = validate_linux_account(account)?;
    if password.contains('\n') || password.contains('\r') || password.contains(':') {
        return Err("Password contains forbidden chpasswd delimiter".into());
    }
    if dry_run {
        return Ok(());
    }
    let mut child = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn chpasswd: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{clean_acct}:{password}")
            .map_err(|e| format!("Failed writing to chpasswd stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("chpasswd wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chpasswd exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_linux_chpasswd(account: &str, _password: &str, dry_run: bool) -> Result<(), String> {
    let _ = validate_linux_account(account)?;
    if dry_run {
        return Ok(());
    }
    Err("apply_linux_chpasswd requires a Linux host (use --dry-run on non-Linux)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laps_rotates_encrypts_and_marks_rotate_pending_on_reveal() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_laps_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&temp);
        let vault_dir = temp.join("vault");
        let meta_path = temp.join("laps_meta.json");

        let pw = generate_laps_password();
        assert_eq!(pw.len(), 24);
        assert!(validate_linux_account("sb-rescue").is_ok());
        assert!(validate_linux_account("Root").is_err());

        let meta = store_laps_password(
            "m-app-01",
            "sb-rescue",
            &pw,
            "laps-master-secret",
            30,
            &vault_dir,
            &meta_path,
        )
        .unwrap();
        assert!(!meta.rotate_pending);
        assert_eq!(meta.version, 1);

        // Wrong passphrase must fail
        assert!(reveal_laps_password("m-app-01", "wrong", &vault_dir, &meta_path).is_err());

        // Correct passphrase decrypts and sets rotate_pending = true
        let (revealed, updated_meta) =
            reveal_laps_password("m-app-01", "laps-master-secret", &vault_dir, &meta_path).unwrap();
        assert_eq!(revealed, pw);
        assert!(updated_meta.rotate_pending);

        let _ = fs::remove_dir_all(&temp);
    }
}
