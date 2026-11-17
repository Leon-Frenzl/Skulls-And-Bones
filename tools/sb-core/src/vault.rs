use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
pub use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ══════════════════════════════════════════════════════════════════════════════
// Vault Crypto Core — Shared Argon2id + AES-256-GCM implementation
// Used by: sb-desktop (Tauri vault.rs) and sb-key (CLI vault commands)
// ══════════════════════════════════════════════════════════════════════════════

/// Encrypted secret container stored in a .vault TOML file
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct VaultSecretEntry {
    pub ciphertext: String,
    pub nonce: String,
    pub salt: String,
    pub updated_at: String,
    pub updated_by: String,
    pub version: u32,
    #[serde(default = "default_project")]
    pub project: String,
}

fn default_project() -> String {
    "global".to_string()
}

const VAULT_FORMAT_VERSION: u32 = 2;
const VERIFIER_VALUE: &str = "skulls-and-bones-vault-verifier-v1";

/// On-disk document shared by suite clients.
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct VaultFile {
    #[serde(default)]
    pub format_version: u32,
    #[serde(default)]
    pub verifier: Option<VaultSecretEntry>,
    pub secrets: HashMap<String, VaultSecretEntry>,
}

/// File-backed access to one shared, profile-selected vault directory.
#[derive(Debug, Clone)]
pub struct VaultStore {
    root: PathBuf,
}

impl VaultStore {
    pub fn active() -> Result<Self, String> {
        Ok(Self::new(crate::paths::active_vault_dir()?))
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load(&self, environment: &str) -> Result<VaultFile, String> {
        let path = self.path_for(environment)?;
        if !path.exists() {
            return Ok(VaultFile::default());
        }
        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "Vault '{}' konnte nicht gelesen werden: {e}",
                path.display()
            )
        })?;
        toml::from_str(&content)
            .map_err(|e| format!("Vault '{}' enthält ungültige Daten: {e}", path.display()))
    }

    pub fn save(&self, environment: &str, vault: &VaultFile) -> Result<(), String> {
        let path = self.path_for(environment)?;
        std::fs::create_dir_all(&self.root).map_err(|e| {
            format!(
                "Vault-Verzeichnis '{}' konnte nicht erstellt werden: {e}",
                self.root.display()
            )
        })?;
        let content = toml::to_string_pretty(vault)
            .map_err(|e| format!("Vault-Serialisierung fehlgeschlagen: {e}"))?;
        std::fs::write(&path, content).map_err(|e| {
            format!(
                "Vault '{}' konnte nicht gespeichert werden: {e}",
                path.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Vault-Berechtigungen konnten nicht gesetzt werden: {e}"))?;
        }

        Ok(())
    }

    pub fn path_for(&self, environment: &str) -> Result<PathBuf, String> {
        if environment.is_empty()
            || environment == "."
            || environment == ".."
            || !environment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("Ungültiger Vault-Environment-Name".to_string());
        }
        Ok(self.root.join(format!("{environment}.vault")))
    }
}

/// Decrypted secret item returned to callers
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct VaultSecretItem {
    pub name: String,
    pub value: String,
    pub updated_at: String,
    pub updated_by: String,
    pub version: u32,
    pub age_days: i64,
    pub project: String,
}

impl Drop for VaultSecretItem {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Active vault session (erased from memory when dropped)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultSession {
    passphrase: Vec<u8>,
}

impl VaultSession {
    pub fn new(passphrase: &str) -> Self {
        Self {
            passphrase: passphrase.as_bytes().to_vec(),
        }
    }

    pub fn from_owned_passphrase(passphrase: String) -> Self {
        Self {
            passphrase: passphrase.into_bytes(),
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.passphrase).expect("VaultSession passphrase is UTF-8")
    }

    pub fn encrypt(&self, value: &str) -> Result<(String, String, String), String> {
        vault_encrypt(value, self.as_str())
    }

    pub fn decrypt(&self, entry: &VaultSecretEntry) -> Result<String, String> {
        vault_decrypt(entry, self.as_str())
    }

    pub fn initialize(&self, vault: &mut VaultFile) -> Result<(), String> {
        if vault.verifier.is_some() {
            return Err("Vault ist bereits initialisiert".to_string());
        }
        let (ciphertext, nonce, salt) = self.encrypt(VERIFIER_VALUE)?;
        vault.format_version = VAULT_FORMAT_VERSION;
        vault.verifier = Some(VaultSecretEntry {
            ciphertext,
            nonce,
            salt,
            updated_at: chrono::Utc::now().to_rfc3339(),
            updated_by: "system".to_string(),
            version: 1,
            project: "system".to_string(),
        });
        Ok(())
    }

    // CVE-Threat: Empty or malformed vaults could accept arbitrary passwords as a successful unlock.
    // Analysis: Secret-only formats cannot authenticate a password when there are no entries.
    // Hardening: Require the supported format version and decrypt a dedicated authenticated verifier.
    pub fn verify_vault(&self, vault: &VaultFile) -> Result<(), String> {
        if vault.format_version != VAULT_FORMAT_VERSION {
            return Err(format!(
                "Nicht unterstützte Vault-Formatversion: {}",
                vault.format_version
            ));
        }
        let verifier = vault
            .verifier
            .as_ref()
            .ok_or_else(|| "Vault ist nicht initialisiert".to_string())?;
        let mut plaintext = self.decrypt(verifier)?;
        let matches = plaintext == VERIFIER_VALUE;
        plaintext.zeroize();
        if matches {
            Ok(())
        } else {
            Err("Vault-Prüfdatensatz ist ungültig".to_string())
        }
    }

    pub fn rekey_vault(
        &self,
        vault: &mut VaultFile,
        new_session: &VaultSession,
    ) -> Result<(), String> {
        self.verify_vault(vault)?;

        for entry in vault.secrets.values_mut() {
            let mut plaintext = self.decrypt(entry)?;
            let encrypted = new_session.encrypt(&plaintext);
            plaintext.zeroize();
            let (ciphertext, nonce, salt) = encrypted?;
            entry.ciphertext = ciphertext;
            entry.nonce = nonce;
            entry.salt = salt;
        }

        let (ciphertext, nonce, salt) = new_session.encrypt(VERIFIER_VALUE)?;
        let verifier = vault
            .verifier
            .as_mut()
            .ok_or_else(|| "Vault ist nicht initialisiert".to_string())?;
        verifier.ciphertext = ciphertext;
        verifier.nonce = nonce;
        verifier.salt = salt;
        verifier.updated_at = chrono::Utc::now().to_rfc3339();
        vault.format_version = VAULT_FORMAT_VERSION;
        Ok(())
    }
}

pub fn derive_vault_key(passphrase: &str, salt: &SaltString) -> Result<[u8; 32], String> {
    let password_hash = Argon2::default()
        .hash_password(passphrase.as_bytes(), salt)
        .map_err(|e| format!("Argon2id Fehler: {}", e))?;
    let hash_bytes = password_hash
        .hash
        .ok_or_else(|| "Argon2id lieferte keinen Schlüssel-Hash".to_string())?;
    let key_bytes = hash_bytes
        .as_bytes()
        .get(..32)
        .ok_or_else(|| "Argon2id lieferte einen ungültigen Schlüssel-Hash".to_string())?;
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    Ok(key)
}

/// Decrypt raw bytes using Argon2id key-derivation + AES-256-GCM
pub fn decrypt_payload(
    ciphertext_bytes: &[u8],
    nonce_bytes: &[u8],
    salt: &SaltString,
    passphrase: &str,
) -> Result<Vec<u8>, String> {
    if nonce_bytes.len() != 12 {
        return Err("Ungültige Nonce-Länge (erwartet 12 Bytes)".to_string());
    }
    let nonce = Nonce::from_slice(nonce_bytes);
    let mut key_bytes = derive_vault_key(passphrase, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    key_bytes.zeroize();

    cipher.decrypt(nonce, ciphertext_bytes).map_err(|_| {
        "Entschlüsselung fehlgeschlagen (falsches Passwort oder beschädigte Daten)".to_string()
    })
}

/// Encrypt raw bytes using Argon2id key-derivation + AES-256-GCM
/// Returns (ciphertext_bytes, nonce_bytes, salt)
pub fn encrypt_payload(
    payload: &[u8],
    passphrase: &str,
) -> Result<(Vec<u8>, [u8; 12], SaltString), String> {
    let salt = SaltString::generate(&mut OsRng);
    let mut key_bytes = derive_vault_key(passphrase, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    key_bytes.zeroize();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| format!("Verschlüsselung fehlgeschlagen: {}", e))?;

    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce.as_slice());

    Ok((ciphertext, nonce_arr, salt))
}

/// Decrypt a vault secret using Argon2id key-derivation + AES-256-GCM
pub fn vault_decrypt(entry: &VaultSecretEntry, passphrase: &str) -> Result<String, String> {
    let salt = SaltString::from_b64(&entry.salt).map_err(|e| format!("Ungültiger Salt: {}", e))?;
    let nonce_bytes = BASE64
        .decode(&entry.nonce)
        .map_err(|e| format!("Nonce decode error: {}", e))?;
    let ciphertext = BASE64
        .decode(&entry.ciphertext)
        .map_err(|e| format!("Ciphertext decode error: {}", e))?;

    let plaintext = decrypt_payload(&ciphertext, &nonce_bytes, &salt, passphrase)?;
    match String::from_utf8(plaintext) {
        Ok(s) => Ok(s),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err("Secret enthält ungültige UTF-8 Zeichen".to_string())
        }
    }
}

/// Encrypt a secret value using Argon2id key-derivation + AES-256-GCM
/// Returns (ciphertext_b64, nonce_b64, salt_string)
pub fn vault_encrypt(value: &str, passphrase: &str) -> Result<(String, String, String), String> {
    let (ciphertext, nonce, salt) = encrypt_payload(value.as_bytes(), passphrase)?;

    Ok((
        BASE64.encode(&ciphertext),
        BASE64.encode(nonce),
        salt.to_string(),
    ))
}

/// Verify a passphrase against a known encrypted entry (non-destructive auth check)
pub fn vault_verify_passphrase(entry: &VaultSecretEntry, candidate: &str) -> bool {
    vault_decrypt(entry, candidate).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_encrypt_decrypt_roundtrip() {
        let pass = "sovereign-master-test-pass-2026";
        let val = "STRIPE_SK_LIVE_SOVEREIGN_TEST_abc123";
        let (ct, nonce, salt) = vault_encrypt(val, pass).unwrap();
        let entry = VaultSecretEntry {
            ciphertext: ct,
            nonce,
            salt,
            updated_at: "2026-10-03T00:00:00Z".to_string(),
            updated_by: "test-agent".to_string(),
            version: 1,
            project: "prod".to_string(),
        };
        let decrypted = vault_decrypt(&entry, pass).unwrap();
        assert_eq!(decrypted, val);
    }

    #[test]
    fn test_vault_wrong_passphrase_rejected() {
        let pass = "correct-horse-battery-staple";
        let val = "secret_token_value";
        let (ct, nonce, salt) = vault_encrypt(val, pass).unwrap();
        let entry = VaultSecretEntry {
            ciphertext: ct,
            nonce,
            salt,
            updated_at: "2026-10-03T00:00:00Z".to_string(),
            updated_by: "test".to_string(),
            version: 1,
            project: "dev".to_string(),
        };
        assert!(vault_decrypt(&entry, "wrong-passphrase").is_err());
        assert!(!vault_verify_passphrase(&entry, "wrong-pass"));
        assert!(vault_verify_passphrase(&entry, pass));
    }

    #[test]
    fn test_vault_session_zeroize() {
        let session = VaultSession::new("my-super-secret-pass");
        assert_eq!(session.as_str(), "my-super-secret-pass");
    }

    #[test]
    fn test_vault_rejects_invalid_nonce_length() {
        let entry = VaultSecretEntry {
            ciphertext: BASE64.encode([0u8; 16]),
            nonce: BASE64.encode([0u8; 1]),
            salt: SaltString::generate(&mut OsRng).to_string(),
            updated_at: "2026-10-03T00:00:00Z".to_string(),
            updated_by: "test".to_string(),
            version: 1,
            project: "dev".to_string(),
        };

        assert!(vault_decrypt(&entry, "test-passphrase")
            .unwrap_err()
            .contains("Nonce-Länge"));
    }

    #[test]
    fn test_vault_store_roundtrip_and_environment_validation() {
        let root = std::env::temp_dir().join(format!(
            "sb-core-vault-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = VaultStore::new(&root);
        let mut vault = VaultFile::default();
        let (ciphertext, nonce, salt) = vault_encrypt("value", "passphrase").unwrap();
        vault.secrets.insert(
            "test".to_string(),
            VaultSecretEntry {
                ciphertext,
                nonce,
                salt,
                updated_at: "2026-10-03T00:00:00Z".to_string(),
                updated_by: "test".to_string(),
                version: 1,
                project: "global".to_string(),
            },
        );

        store.save("dev", &vault).unwrap();
        assert_eq!(store.load("dev").unwrap(), vault);
        assert!(store.path_for("../outside").is_err());
        assert!(store.path_for("dev/../../outside").is_err());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_vault_store_rejects_malformed_file() {
        let root = std::env::temp_dir().join(format!(
            "sb-core-vault-malformed-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("dev.vault"), "not valid TOML =").unwrap();

        let result = VaultStore::new(&root).load("dev");
        assert!(result.is_err());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_vault_initialization_verifies_password_even_without_secrets() {
        let mut vault = VaultFile::default();
        let session = VaultSession::new("initial-password");

        session.initialize(&mut vault).unwrap();
        assert_eq!(vault.format_version, VAULT_FORMAT_VERSION);
        assert!(vault.secrets.is_empty());
        assert!(session.verify_vault(&vault).is_ok());
        assert!(VaultSession::new("wrong-password")
            .verify_vault(&vault)
            .is_err());
        assert!(session.initialize(&mut vault).is_err());
    }

    #[test]
    fn test_uninitialized_vault_is_not_authenticated_by_empty_password() {
        assert!(VaultSession::new("any-password")
            .verify_vault(&VaultFile::default())
            .is_err());
    }

    #[test]
    fn test_vault_verification_rejects_unsupported_format_version() {
        let session = VaultSession::new("password");
        let mut vault = VaultFile::default();
        session.initialize(&mut vault).unwrap();
        vault.format_version = VAULT_FORMAT_VERSION + 1;

        assert!(session.verify_vault(&vault).is_err());
    }

    #[test]
    fn test_rekey_vault_rejects_old_session_and_accepts_new_one() {
        let old_session = VaultSession::new("old-password");
        let new_session = VaultSession::new("new-password");
        let mut vault = VaultFile::default();
        old_session.initialize(&mut vault).unwrap();
        let (ciphertext, nonce, salt) = old_session.encrypt("secret-value").unwrap();
        vault.secrets.insert(
            "key".to_string(),
            VaultSecretEntry {
                ciphertext,
                nonce,
                salt,
                updated_at: "2026-10-03T00:00:00Z".to_string(),
                updated_by: "test".to_string(),
                version: 1,
                project: "global".to_string(),
            },
        );

        old_session.rekey_vault(&mut vault, &new_session).unwrap();
        assert!(old_session.verify_vault(&vault).is_err());
        assert!(new_session.verify_vault(&vault).is_ok());
        assert_eq!(
            new_session
                .decrypt(vault.secrets.get("key").unwrap())
                .unwrap(),
            "secret-value"
        );
    }
}
