use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::AuthError;

pub type HmacSha256 = Hmac<Sha256>;

/// Ed25519 Keypair Container für Sovereign Token Signierung & Verifikation
#[derive(Clone)]
pub struct Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub key_id: String,
}

impl Keypair {
    /// Generiert ein frisches kryptografisches Ed25519-Schlüsselpaar
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let key_id = derive_key_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            key_id,
        }
    }

    /// Lädt ein Schlüsselpaar aus rohen 32-Byte Secret Key Bytes
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        let key_id = derive_key_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            key_id,
        }
    }

    /// Lädt ein Schlüsselpaar aus einem URL-Safe Base64 String
    pub fn from_secret_base64(b64: &str) -> Result<Self, AuthError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| AuthError::InvalidKey(format!("Ungültiges Base64 für Secret Key: {e}")))?;
        if bytes.len() != 32 {
            return Err(AuthError::InvalidKey(format!(
                "Secret Key muss 32 Bytes lang sein (erhalten: {})",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_secret_bytes(&arr))
    }

    /// Exportiert den Secret Key als URL-Safe Base64
    pub fn to_secret_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes())
    }

    /// Exportiert den Public Key als URL-Safe Base64
    pub fn to_public_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.verifying_key.to_bytes())
    }

    /// Signiert eine Nachricht
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    /// Verifiziert eine Signatur
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), AuthError> {
        verify_signature(&self.verifying_key, message, signature_bytes)
    }
}

/// Erzeugt eine eindeutige Key-ID (KID) aus dem Public Key Hash
pub fn derive_key_id(verifying_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sb-auth-kid-v1:");
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    format!("sbk_{}", hex::encode(&hash[..8]))
}

/// Parst einen Public Key aus URL-Safe Base64
pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, AuthError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| AuthError::InvalidKey(format!("Ungültiges Base64 für Public Key: {e}")))?;
    if bytes.len() != 32 {
        return Err(AuthError::InvalidKey(format!(
            "Public Key muss 32 Bytes lang sein (erhalten: {})",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| AuthError::InvalidKey(format!("Ed25519 Public Key ungültig: {e}")))
}

/// Verifiziert eine Ed25519 Signatur
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AuthError> {
    if signature_bytes.len() != 64 {
        return Err(AuthError::InvalidSignature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| AuthError::InvalidSignature)
}

// ─────────────────────────────────────────────────────────────────────────────
// Argon2id Password Hashing
// ─────────────────────────────────────────────────────────────────────────────

/// Hasht ein Passwort mit Argon2id (OWASP/BSI konform)
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::PasswordHashError(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verifiziert ein Passwort gegen einen Argon2id Hash in konstanter Zeit
pub fn verify_password(password: &str, password_hash: &str) -> Result<(), AuthError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| AuthError::PasswordHashError(format!("Ungültiges Hash-Format: {e}")))?;
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::InvalidPassword)
}

// ─────────────────────────────────────────────────────────────────────────────
// TOTP (Time-based One-Time Password / RFC 6238)
// ─────────────────────────────────────────────────────────────────────────────

/// Berechnet einen 6-stelligen TOTP-Code für ein Secret zu einem gegebenen Unix-Timestamp (in Sekunden)
pub fn generate_totp_code(
    secret: &[u8],
    timestamp: i64,
    step_seconds: u64,
) -> Result<String, AuthError> {
    if step_seconds == 0 {
        return Err(AuthError::InvalidTotp);
    }
    let counter = (timestamp / step_seconds as i64) as u64;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| AuthError::InvalidKey(format!("Ungültiger HMAC-Schlüssel: {e}")))?;
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamische Trunkierung nach RFC 4226 / RFC 6238
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let binary = ((result[offset] & 0x7f) as u32) << 24
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let code = binary % 1_000_000;
    Ok(format!("{:06}", code))
}

/// Verifiziert einen TOTP-Code mit Zeittoleranz (Drift-Fenster: -1, 0, +1 Steps)
/// Gibt bei Erfolg den akzeptierten Step-Index zurück (für Replay-Schutz).
pub fn verify_totp_code(
    secret: &[u8],
    code: &str,
    timestamp: i64,
    step_seconds: u64,
    allowed_drift_steps: i64,
) -> Result<i64, AuthError> {
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(AuthError::InvalidTotp);
    }

    let current_step = timestamp / step_seconds as i64;
    for drift in -allowed_drift_steps..=allowed_drift_steps {
        let step = current_step + drift;
        let step_time = step * step_seconds as i64;
        if let Ok(expected_code) = generate_totp_code(secret, step_time, step_seconds) {
            if subtle::ConstantTimeEq::ct_eq(code.as_bytes(), expected_code.as_bytes()).into() {
                return Ok(step);
            }
        }
    }

    Err(AuthError::InvalidTotp)
}

/// Generiert ein zufälliges kryptografisches TOTP-Secret (32 Bytes Base64)
pub fn generate_totp_secret() -> String {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    let b64 = URL_SAFE_NO_PAD.encode(secret);
    secret.zeroize();
    b64
}
