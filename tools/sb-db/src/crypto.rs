use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{DbError, DbResult};

const AT_REST_VERSION: u8 = 1;
const E2EE_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// 256-bit symmetric key for database encryption-at-rest.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; KEY_LEN],
}

impl MasterKey {
    /// Generates a fresh 256-bit key using the OS CSPRNG (`OsRng`).
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Creates a `MasterKey` from raw 32-byte key material.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Derives a 256-bit `MasterKey` from a passphrase and 16+ byte salt using Argon2id (RFC 9106).
    // [SECURITY-VERIFIED] CWE-916 Mitigiert:
    // Erzwingt mindestens 16-Byte-Salt und nicht-leere Passphrase vor Argon2id-Ableitung.
    pub fn derive_from_passphrase(passphrase: &str, salt: &[u8]) -> DbResult<Self> {
        if passphrase.is_empty() {
            return Err(DbError::Validation("Passphrase cannot be empty".into()));
        }
        if salt.len() < 16 {
            return Err(DbError::Validation(
                "Argon2id salt must be at least 16 bytes".into(),
            ));
        }
        let mut out = [0u8; KEY_LEN];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| DbError::Crypto(format!("Argon2id key derivation failed: {e}")))?;
        Ok(Self { bytes: out })
    }

    /// Loads an existing hex-encoded 32-byte key from `path`, or generates and persists one (`0o600`).
    // [SECURITY-VERIFIED] CWE-312 / CWE-732 Mitigiert:
    // Setzt unter Unix restriktive Dateiberechtigungen (0o600) und schreibt atomar über Temp-Datei.
    pub fn load_or_create_file(path: &Path) -> DbResult<Self> {
        if path.exists() {
            let raw = fs::read_to_string(path)
                .map_err(|e| DbError::Storage(format!("Failed to read DB master key: {e}")))?;
            let decoded = hex::decode(raw.trim())
                .map_err(|_| DbError::Crypto("Invalid hex encoding in DB master key".into()))?;
            let bytes: [u8; KEY_LEN] = decoded
                .try_into()
                .map_err(|_| DbError::Crypto("DB master key must be exactly 32 bytes".into()))?;
            return Ok(Self { bytes });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| DbError::Storage(format!("Failed to create key dir: {e}")))?;
        }
        let key = Self::generate();
        let encoded = Zeroizing::new(hex::encode(key.bytes));
        let tmp = path.with_extension("key.tmp");
        fs::write(&tmp, encoded.as_bytes())
            .map_err(|e| DbError::Storage(format!("Failed to write temp master key: {e}")))?;
        sb_core::paths::ensure_private_permissions(&tmp)
            .map_err(|e| DbError::Storage(format!("Failed to set key permissions: {e}")))?;
        fs::rename(&tmp, path)
            .map_err(|e| DbError::Storage(format!("Failed to persist DB master key: {e}")))?;
        Ok(key)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

/// Authenticated ciphertext container for encryption-at-rest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedBlob {
    pub v: u8,
    pub nonce: String,
    pub ct: String,
}

/// Encrypts `plaintext` with AES-256-GCM bound to `aad` (e.g., `table:id:version`).
// [SECURITY-VERIFIED] CWE-327 / CWE-345 Mitigiert:
// Nutzt zufällige 96-Bit-OsRng-Nonces und AAD-Bindung gegen Ciphertext-Swapping zwischen Zeilen.
pub fn encrypt_at_rest(key: &MasterKey, aad: &[u8], plaintext: &[u8]) -> DbResult<EncryptedBlob> {
    let cipher = Aes256Gcm::new_from_slice(&key.bytes)
        .map_err(|e| DbError::Crypto(format!("AES-256-GCM init failed: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| DbError::Crypto("AES-256-GCM encryption failed".into()))?;
    Ok(EncryptedBlob {
        v: AT_REST_VERSION,
        nonce: B64.encode(nonce_bytes),
        ct: B64.encode(ct),
    })
}

/// Decrypts an `EncryptedBlob` and verifies its AAD tag.
pub fn decrypt_at_rest(
    key: &MasterKey,
    aad: &[u8],
    blob: &EncryptedBlob,
) -> DbResult<Zeroizing<Vec<u8>>> {
    if blob.v != AT_REST_VERSION {
        return Err(DbError::Crypto(format!(
            "Unsupported at-rest blob version: {}",
            blob.v
        )));
    }
    let nonce_vec = B64
        .decode(blob.nonce.trim())
        .map_err(|_| DbError::Crypto("Invalid base64 nonce".into()))?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| DbError::Crypto("Nonce must be 12 bytes".into()))?;
    let ct = B64
        .decode(blob.ct.trim())
        .map_err(|_| DbError::Crypto("Invalid base64 ciphertext".into()))?;

    let cipher = Aes256Gcm::new_from_slice(&key.bytes)
        .map_err(|e| DbError::Crypto(format!("AES-256-GCM init failed: {e}")))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &ct, aad })
        .map_err(|_| DbError::Crypto("AES-256-GCM authentication failed".into()))?;
    Ok(Zeroizing::new(pt))
}

/// End-to-end encrypted envelope using Ephemeral-Static X25519 + HKDF-SHA256 + AES-256-GCM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eeEnvelope {
    pub v: u8,
    /// Base64-encoded 32-byte ephemeral X25519 public key.
    pub eph_pub: String,
    /// Base64-encoded 12-byte AES-GCM nonce.
    pub nonce: String,
    /// Base64-encoded AES-GCM ciphertext + 16-byte tag.
    pub ct: String,
}

fn derive_e2ee_key(
    shared_secret: &[u8; 32],
    eph_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> DbResult<Zeroizing<[u8; KEY_LEN]>> {
    // Reject all-zero shared secret (low-order / invalid X25519 point per RFC 7748).
    if shared_secret.iter().all(|b| *b == 0) {
        return Err(DbError::Crypto(
            "X25519 key agreement produced all-zero shared secret".into(),
        ));
    }
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(b"sb-db-e2ee-envelope-v1", okm.as_mut())
        .map_err(|_| DbError::Crypto("HKDF expansion failed".into()))?;
    Ok(okm)
}

/// Seals `plaintext` for `recipient_x25519_pub` using ephemeral-static X25519 + AES-256-GCM.
/// The database server never learns the plaintext without `recipient_x25519_secret`.
// [SECURITY-VERIFIED] CWE-312 / CWE-327 Mitigiert:
// Ephemeraler X25519-Schlüssel pro Envelope, RFC-7748 Zero-Secret-Check, HKDF-SHA256 und AAD-Bindung.
pub fn seal_e2ee(
    recipient_x25519_pub: &[u8; 32],
    context_aad: &[u8],
    plaintext: &[u8],
) -> DbResult<E2eeEnvelope> {
    let recipient_pub = PublicKey::from(*recipient_x25519_pub);
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient_pub);
    let key = derive_e2ee_key(
        shared.as_bytes(),
        eph_pub.as_bytes(),
        recipient_pub.as_bytes(),
    )?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| DbError::Crypto(format!("AES-256-GCM init failed: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: context_aad,
            },
        )
        .map_err(|_| DbError::Crypto("E2EE AES-256-GCM encryption failed".into()))?;

    Ok(E2eeEnvelope {
        v: E2EE_VERSION,
        eph_pub: B64.encode(eph_pub.as_bytes()),
        nonce: B64.encode(nonce_bytes),
        ct: B64.encode(ct),
    })
}

/// Opens an `E2eeEnvelope` using the recipient's static X25519 secret key.
pub fn open_e2ee(
    recipient_x25519_secret: &StaticSecret,
    context_aad: &[u8],
    envelope: &E2eeEnvelope,
) -> DbResult<Zeroizing<Vec<u8>>> {
    if envelope.v != E2EE_VERSION {
        return Err(DbError::Crypto(format!(
            "Unsupported E2EE envelope version: {}",
            envelope.v
        )));
    }
    let eph_vec = B64
        .decode(envelope.eph_pub.trim())
        .map_err(|_| DbError::Crypto("Invalid base64 ephemeral public key".into()))?;
    let eph_bytes: [u8; 32] = eph_vec
        .try_into()
        .map_err(|_| DbError::Crypto("Ephemeral public key must be 32 bytes".into()))?;
    let nonce_vec = B64
        .decode(envelope.nonce.trim())
        .map_err(|_| DbError::Crypto("Invalid base64 nonce".into()))?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| DbError::Crypto("Nonce must be 12 bytes".into()))?;
    let ct = B64
        .decode(envelope.ct.trim())
        .map_err(|_| DbError::Crypto("Invalid base64 ciphertext".into()))?;

    let eph_pub = PublicKey::from(eph_bytes);
    let recipient_pub = PublicKey::from(recipient_x25519_secret);
    let shared = recipient_x25519_secret.diffie_hellman(&eph_pub);
    let key = derive_e2ee_key(shared.as_bytes(), &eph_bytes, recipient_pub.as_bytes())?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| DbError::Crypto(format!("AES-256-GCM init failed: {e}")))?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ct,
                aad: context_aad,
            },
        )
        .map_err(|_| DbError::Crypto("E2EE decryption or tag verification failed".into()))?;
    Ok(Zeroizing::new(pt))
}
