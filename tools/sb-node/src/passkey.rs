//! W3C WebAuthn / FIDO2 Passkey MFA for the Sovereign Domain Controller.
//!
//! Implements Passkey registration and cryptographic assertion verification
//! (`ES256` P-256 ECDSA and `EdDSA` Ed25519) with single-use challenge replay
//! protection, RP-ID hash binding, origin validation, and `signCount` anti-cloning.
//!
//! Standards Compliance:
//! - W3C WebAuthn Level 2/3 (§7.1 Registering, §7.2 Verifying an Authentication Assertion)
//! - RFC 8152 / COSE Algorithms (`-7` ES256, `-8` EdDSA)

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// COSE algorithm identifier for ECDSA w/ SHA-256 (P-256).
pub const COSE_ALG_ES256: i32 = -7;
/// COSE algorithm identifier for EdDSA (Ed25519).
pub const COSE_ALG_EDDSA: i32 = -8;
/// Challenge lifetime in seconds (5 minutes).
const CHALLENGE_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Register,
    Authenticate,
}

/// Pending single-use WebAuthn challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge {
    pub challenge_b64: String,
    pub username: String,
    pub rp_id: String,
    pub kind: ChallengeKind,
    pub expires_at: String,
}

/// Registered FIDO2/WebAuthn Passkey credential bound to a domain user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id_b64: String,
    pub username: String,
    pub label: String,
    pub rp_id: String,
    pub alg: i32,
    /// Raw public key bytes encoded in base64url:
    /// - ES256: 65-byte uncompressed SEC1 point (`0x04 || x || y`)
    /// - EdDSA: 32-byte Ed25519 public key
    pub public_key_b64: String,
    pub sign_count: u32,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Persistent Passkey credential & challenge store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasskeyStore {
    pub credentials: BTreeMap<String, PasskeyCredential>,
    #[serde(default)]
    pub challenges: BTreeMap<String, PasskeyChallenge>,
}

pub fn default_passkeys_path() -> PathBuf {
    sb_core::domain::local_domain_dir().join("passkeys.json")
}

#[derive(Debug, Deserialize)]
struct ClientDataJson {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

impl PasskeyStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read passkeys {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid passkeys JSON {}: {e}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create passkeys dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize passkeys: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp passkeys: {e}"))?;
        let _ = sb_core::paths::ensure_private_permissions(&tmp);
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit passkeys: {e}"))?;
        Ok(())
    }

    pub fn load_from_db(
        db: &sb_db::SovereignDb,
        ticket: &sb_db::VerifiedDbTicket,
    ) -> Result<Self, String> {
        db.get_encrypted_json::<Self>(ticket, "passkey", "store")
            .map(|opt| opt.unwrap_or_default())
            .map_err(|e| e.to_string())
    }

    pub fn save_to_db(
        &self,
        db: &sb_db::SovereignDb,
        ticket: &sb_db::VerifiedDbTicket,
    ) -> Result<(), String> {
        db.put_encrypted_json(ticket, "passkey", "store", self)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Returns true if `username` has at least one registered passkey.
    pub fn user_has_passkey(&self, username: &str) -> bool {
        self.credentials.values().any(|c| c.username == username)
    }

    /// Lists credentials registered for `username`.
    pub fn list_for_user(&self, username: &str) -> Vec<PasskeyCredential> {
        self.credentials
            .values()
            .filter(|c| c.username == username)
            .cloned()
            .collect()
    }

    /// Removes a passkey owned by `username` (or any if `is_admin`).
    pub fn remove_credential(
        &mut self,
        credential_id_b64: &str,
        username: &str,
        is_admin: bool,
    ) -> Result<(), String> {
        let Some(cred) = self.credentials.get(credential_id_b64) else {
            return Err("Passkey credential not found".into());
        };
        if !is_admin && cred.username != username {
            return Err("Cannot delete another user's passkey".into());
        }
        self.credentials.remove(credential_id_b64);
        Ok(())
    }

    /// Starts Passkey registration (`navigator.credentials.create` options).
    pub fn start_registration(
        &mut self,
        username: &str,
        rp_id: &str,
        rp_name: &str,
    ) -> Result<serde_json::Value, String> {
        let clean = sb_core::identity::validate_username(username)?;
        let challenge = self.issue_challenge(&clean, rp_id, ChallengeKind::Register);
        let exclude: Vec<serde_json::Value> = self
            .list_for_user(&clean)
            .into_iter()
            .map(|c| serde_json::json!({ "type": "public-key", "id": c.credential_id_b64 }))
            .collect();

        Ok(serde_json::json!({
            "rp": { "id": rp_id, "name": rp_name },
            "user": {
                "id": URL_SAFE_NO_PAD.encode(clean.as_bytes()),
                "name": clean,
                "displayName": clean,
            },
            "challenge": challenge,
            "pubKeyCredParams": [
                { "type": "public-key", "alg": COSE_ALG_ES256 },
                { "type": "public-key", "alg": COSE_ALG_EDDSA },
            ],
            "timeout": 60000,
            "attestation": "none",
            "excludeCredentials": exclude,
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "required",
            },
        }))
    }

    /// Completes Passkey registration after validating `clientDataJSON`, `authData`, and public key.
    // [SECURITY-HYPOTHESIS] CWE-294 / CWE-345: Replay of registration challenge or forged RP ID / origin.
    // [SECURITY-VERIFIED] Challenge is single-use, `type` must be `webauthn.create`, origin and SHA-256(rpId) are verified.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_registration(
        &mut self,
        credential_id_b64: &str,
        client_data_json_b64: &str,
        auth_data_b64: &str,
        public_key_b64: &str,
        alg: i32,
        label: &str,
        expected_origin: Option<&str>,
    ) -> Result<PasskeyCredential, String> {
        if credential_id_b64.trim().is_empty() || credential_id_b64.len() > 512 {
            return Err("Invalid credential_id".into());
        }
        let client_bytes = decode_b64(client_data_json_b64, "clientDataJSON")?;
        let client: ClientDataJson = serde_json::from_slice(&client_bytes)
            .map_err(|e| format!("Invalid clientDataJSON: {e}"))?;
        if client.kind != "webauthn.create" {
            return Err(format!("Unexpected WebAuthn type '{}'", client.kind));
        }

        let ch = self.consume_challenge(&client.challenge, ChallengeKind::Register)?;
        verify_origin(&client.origin, &ch.rp_id, expected_origin)?;

        let auth_data = decode_b64(auth_data_b64, "authData")?;
        let (_flags, sign_count) = verify_auth_data(&auth_data, &ch.rp_id)?;

        let raw_pk = decode_b64(public_key_b64, "public_key")?;
        let normalized_pk = normalize_public_key(alg, &raw_pk)?;

        let clean_label = if label.trim().is_empty() {
            "Passkey".to_string()
        } else {
            label.trim().chars().take(64).collect()
        };

        let cred = PasskeyCredential {
            credential_id_b64: credential_id_b64.trim().to_string(),
            username: ch.username,
            label: clean_label,
            rp_id: ch.rp_id,
            alg,
            public_key_b64: URL_SAFE_NO_PAD.encode(normalized_pk),
            sign_count,
            created_at: Utc::now().to_rfc3339(),
            last_used_at: None,
        };
        self.credentials
            .insert(cred.credential_id_b64.clone(), cred.clone());
        Ok(cred)
    }

    /// Starts Passkey authentication (`navigator.credentials.get` options).
    pub fn start_authentication(
        &mut self,
        username: &str,
        rp_id: &str,
    ) -> Result<serde_json::Value, String> {
        let clean = sb_core::identity::validate_username(username)?;
        let creds = self.list_for_user(&clean);
        if creds.is_empty() {
            return Err(format!("No passkey registered for user '{clean}'"));
        }
        let challenge = self.issue_challenge(&clean, rp_id, ChallengeKind::Authenticate);
        let allow: Vec<serde_json::Value> = creds
            .into_iter()
            .map(|c| serde_json::json!({ "type": "public-key", "id": c.credential_id_b64 }))
            .collect();

        Ok(serde_json::json!({
            "challenge": challenge,
            "rpId": rp_id,
            "timeout": 60000,
            "userVerification": "required",
            "allowCredentials": allow,
        }))
    }

    /// Verifies a WebAuthn assertion (`navigator.credentials.get` response) and returns the authenticated username.
    // [SECURITY-HYPOTHESIS] CWE-287 / CWE-294: Forged signature, challenge replay, or cloned authenticator (`signCount` rollback).
    // [SECURITY-VERIFIED] Consumes single-use challenge, checks RP-ID hash, `signCount` monotonicity, and verifies ES256/EdDSA signature over `authData || sha256(clientDataJSON)`.
    pub fn finish_authentication(
        &mut self,
        credential_id_b64: &str,
        client_data_json_b64: &str,
        authenticator_data_b64: &str,
        signature_b64: &str,
        expected_origin: Option<&str>,
    ) -> Result<String, String> {
        let client_bytes = decode_b64(client_data_json_b64, "clientDataJSON")?;
        let client: ClientDataJson = serde_json::from_slice(&client_bytes)
            .map_err(|e| format!("Invalid clientDataJSON: {e}"))?;
        if client.kind != "webauthn.get" {
            return Err(format!("Unexpected WebAuthn type '{}'", client.kind));
        }

        let ch = self.consume_challenge(&client.challenge, ChallengeKind::Authenticate)?;
        verify_origin(&client.origin, &ch.rp_id, expected_origin)?;

        let cred = self
            .credentials
            .get(credential_id_b64.trim())
            .ok_or_else(|| "Unknown passkey credential".to_string())?
            .clone();
        if cred.username != ch.username || cred.rp_id != ch.rp_id {
            return Err("Passkey credential does not match challenge user or RP ID".into());
        }

        let auth_data = decode_b64(authenticator_data_b64, "authenticatorData")?;
        let (_flags, new_count) = verify_auth_data(&auth_data, &cred.rp_id)?;

        if (cred.sign_count > 0 || new_count > 0) && new_count <= cred.sign_count {
            return Err("Passkey signCount rollback detected (possible cloned authenticator)".into());
        }

        let sig_bytes = decode_b64(signature_b64, "signature")?;
        let pk_bytes = decode_b64(&cred.public_key_b64, "stored_public_key")?;

        let client_hash = Sha256::digest(&client_bytes);
        let mut signed_msg = Vec::with_capacity(auth_data.len() + 32);
        signed_msg.extend_from_slice(&auth_data);
        signed_msg.extend_from_slice(&client_hash);

        let alg: &'static dyn signature::VerificationAlgorithm = match cred.alg {
            COSE_ALG_ES256 => &signature::ECDSA_P256_SHA256_ASN1,
            COSE_ALG_EDDSA => &signature::ED25519,
            other => return Err(format!("Unsupported COSE algorithm {other}")),
        };
        UnparsedPublicKey::new(alg, &pk_bytes)
            .verify(&signed_msg, &sig_bytes)
            .map_err(|_| "Passkey signature verification failed".to_string())?;

        if let Some(entry) = self.credentials.get_mut(&cred.credential_id_b64) {
            entry.sign_count = new_count;
            entry.last_used_at = Some(Utc::now().to_rfc3339());
        }
        Ok(cred.username)
    }

    fn issue_challenge(&mut self, username: &str, rp_id: &str, kind: ChallengeKind) -> String {
        self.prune_expired(Utc::now());
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let challenge_b64 = URL_SAFE_NO_PAD.encode(raw);
        self.challenges.insert(
            challenge_b64.clone(),
            PasskeyChallenge {
                challenge_b64: challenge_b64.clone(),
                username: username.to_string(),
                rp_id: rp_id.to_string(),
                kind,
                expires_at: (Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS)).to_rfc3339(),
            },
        );
        challenge_b64
    }

    fn consume_challenge(
        &mut self,
        challenge_b64: &str,
        expected_kind: ChallengeKind,
    ) -> Result<PasskeyChallenge, String> {
        self.prune_expired(Utc::now());
        let entry = self
            .challenges
            .remove(challenge_b64.trim())
            .ok_or_else(|| "Invalid or expired passkey challenge".to_string())?;
        if entry.kind != expected_kind {
            return Err("Passkey challenge kind mismatch".into());
        }
        Ok(entry)
    }

    fn prune_expired(&mut self, now: DateTime<Utc>) {
        self.challenges.retain(|_, v| {
            DateTime::parse_from_rfc3339(&v.expires_at)
                .map(|dt| dt.with_timezone(&Utc) > now)
                .unwrap_or(false)
        });
    }
}

fn decode_b64(input: &str, field: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
        .map_err(|e| format!("Invalid base64 for {field}: {e}"))
}

fn verify_origin(origin: &str, rp_id: &str, expected_origin: Option<&str>) -> Result<(), String> {
    if let Some(exp) = expected_origin {
        if origin.trim_end_matches('/') != exp.trim_end_matches('/') {
            return Err(format!("Origin mismatch: got '{origin}', expected '{exp}'"));
        }
        return Ok(());
    }
    let host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://localhost"))
        .ok_or_else(|| format!("Insecure or invalid WebAuthn origin '{origin}'"))?;
    let host_only = host.split([':', '/']).next().unwrap_or("");
    if origin.starts_with("http://localhost") && (rp_id == "localhost" || rp_id == "127.0.0.1") {
        return Ok(());
    }
    if host_only == rp_id || host_only.ends_with(&format!(".{rp_id}")) {
        Ok(())
    } else {
        Err(format!("Origin '{origin}' does not match RP ID '{rp_id}'"))
    }
}

fn verify_auth_data(auth_data: &[u8], rp_id: &str) -> Result<(u8, u32), String> {
    if auth_data.len() < 37 {
        return Err("authenticatorData must be at least 37 bytes".into());
    }
    let expected_rp_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[..32] != expected_rp_hash[..] {
        return Err("RP ID hash mismatch in authenticatorData".into());
    }
    let flags = auth_data[32];
    if (flags & 0x01) == 0 {
        return Err("User Presence (UP) flag is not set".into());
    }
    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    Ok((flags, sign_count))
}

/// Normalizes SPKI DER or raw public key bytes into raw SEC1 (ES256) or 32-byte Ed25519.
fn normalize_public_key(alg: i32, key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        COSE_ALG_ES256 => {
            if key_bytes.len() == 65 && key_bytes[0] == 0x04 {
                return Ok(key_bytes.to_vec());
            }
            // SubjectPublicKeyInfo (SPKI) P-256 ends with 65-byte uncompressed point (0x04 || x || y).
            if key_bytes.len() > 65 && key_bytes[key_bytes.len() - 65] == 0x04 {
                return Ok(key_bytes[key_bytes.len() - 65..].to_vec());
            }
            Err("ES256 public key must be 65-byte uncompressed P-256 point or SPKI".into())
        }
        COSE_ALG_EDDSA => {
            if key_bytes.len() == 32 {
                return Ok(key_bytes.to_vec());
            }
            if key_bytes.len() > 32 {
                return Ok(key_bytes[key_bytes.len() - 32..].to_vec());
            }
            Err("EdDSA public key must be 32-byte Ed25519 key or SPKI".into())
        }
        other => Err(format!("Unsupported Passkey algorithm {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair};

    fn make_auth_data(rp_id: &str, sign_count: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        out.push(0x05); // UP + UV
        out.extend_from_slice(&sign_count.to_be_bytes());
        out
    }

    #[test]
    fn passkey_registration_and_assertion_verify_and_block_replay_and_cloning() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pub_b64 = URL_SAFE_NO_PAD.encode(kp.public_key().as_ref());

        let mut store = PasskeyStore::default();
        let reg_opts = store
            .start_registration("leon.admin", "console.skulls-and-bones.org", "S&B")
            .unwrap();
        let reg_ch = reg_opts["challenge"].as_str().unwrap().to_string();
        let reg_client = serde_json::json!({
            "type": "webauthn.create",
            "challenge": reg_ch,
            "origin": "https://console.skulls-and-bones.org"
        });
        let reg_client_b64 = URL_SAFE_NO_PAD.encode(reg_client.to_string().as_bytes());
        let reg_auth_b64 =
            URL_SAFE_NO_PAD.encode(make_auth_data("console.skulls-and-bones.org", 1));

        let cred = store
            .finish_registration(
                "cred-1",
                &reg_client_b64,
                &reg_auth_b64,
                &pub_b64,
                COSE_ALG_ES256,
                "YubiKey",
                None,
            )
            .unwrap();
        assert_eq!(cred.username, "leon.admin");
        assert!(store.user_has_passkey("leon.admin"));

        // Authenticate with sign_count = 2 (> 1)
        let auth_opts = store
            .start_authentication("leon.admin", "console.skulls-and-bones.org")
            .unwrap();
        let auth_ch = auth_opts["challenge"].as_str().unwrap().to_string();
        let auth_client = serde_json::json!({
            "type": "webauthn.get",
            "challenge": auth_ch,
            "origin": "https://console.skulls-and-bones.org"
        });
        let auth_client_bytes = auth_client.to_string().into_bytes();
        let auth_client_b64 = URL_SAFE_NO_PAD.encode(&auth_client_bytes);
        let auth_data = make_auth_data("console.skulls-and-bones.org", 2);
        let auth_data_b64 = URL_SAFE_NO_PAD.encode(&auth_data);

        let mut msg = Vec::new();
        msg.extend_from_slice(&auth_data);
        msg.extend_from_slice(&Sha256::digest(&auth_client_bytes));
        let sig = kp.sign(&rng, &msg).unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let verified_user = store
            .finish_authentication(
                "cred-1",
                &auth_client_b64,
                &auth_data_b64,
                &sig_b64,
                None,
            )
            .unwrap();
        assert_eq!(verified_user, "leon.admin");

        // Replay of the same assertion must fail
        assert!(store
            .finish_authentication(
                "cred-1",
                &auth_client_b64,
                &auth_data_b64,
                &sig_b64,
                None,
            )
            .is_err());

        // SignCount rollback (<= 2) must fail
        let auth_opts2 = store
            .start_authentication("leon.admin", "console.skulls-and-bones.org")
            .unwrap();
        let auth_ch2 = auth_opts2["challenge"].as_str().unwrap().to_string();
        let auth_client2 = serde_json::json!({
            "type": "webauthn.get",
            "challenge": auth_ch2,
            "origin": "https://console.skulls-and-bones.org"
        })
        .to_string()
        .into_bytes();
        let auth_data2 = make_auth_data("console.skulls-and-bones.org", 2);
        let mut msg2 = Vec::new();
        msg2.extend_from_slice(&auth_data2);
        msg2.extend_from_slice(&Sha256::digest(&auth_client2));
        let sig2 = kp.sign(&rng, &msg2).unwrap();
        assert!(store
            .finish_authentication(
                "cred-1",
                &URL_SAFE_NO_PAD.encode(&auth_client2),
                &URL_SAFE_NO_PAD.encode(&auth_data2),
                &URL_SAFE_NO_PAD.encode(sig2.as_ref()),
                None,
            )
            .is_err());
    }
}
