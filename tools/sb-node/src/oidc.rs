//! OpenID Connect (OIDC) Discovery, Ed25519 JWKS, and Single-Use Browser Login Code Exchange.
//!
//! Enables passwordless browser login for `console/` and standard OIDC discovery for
//! third-party EU/self-hosted apps (Grafana, GitLab, Gitea, Nextcloud).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sb_auth::AuthEngine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Single-use login code entry (stored as SHA-256 digest, never plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCodeEntry {
    pub code_hash_hex: String,
    pub username: String,
    pub capabilities: Vec<String>,
    pub expires_at: String,
}

/// Persistent single-use login code store (`~/.sb/domain/login_codes.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginCodeStore {
    pub codes: BTreeMap<String, LoginCodeEntry>,
}

/// Returns the default path for pending login codes.
pub fn default_login_codes_path() -> PathBuf {
    sb_core::domain::local_domain_dir().join("login_codes.json")
}

impl LoginCodeStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read login codes {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid login codes JSON {}: {e}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create login codes dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize login codes: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp login codes: {e}"))?;
        let _ = sb_core::paths::ensure_private_permissions(&tmp);
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit login codes: {e}"))?;
        Ok(())
    }

    /// Loads pending login codes from encrypted `SovereignDb` (`namespace = "oidc"`).
    pub fn load_from_db(
        db: &sb_db::SovereignDb,
        ticket: &sb_db::VerifiedDbTicket,
    ) -> Result<Self, String> {
        db.get_encrypted_json::<Self>(ticket, "oidc", "login_codes")
            .map(|opt| opt.unwrap_or_default())
            .map_err(|e| e.to_string())
    }

    /// Persists pending login codes into encrypted `SovereignDb` (`namespace = "oidc"`).
    pub fn save_to_db(
        &self,
        db: &sb_db::SovereignDb,
        ticket: &sb_db::VerifiedDbTicket,
    ) -> Result<(), String> {
        db.put_encrypted_json(ticket, "oidc", "login_codes", self)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Generates a 128-bit single-use login code (`sbc_...`) valid for `ttl_seconds`.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** Replay of login codes or plaintext code exposure if disk is read.
    /// - **CVE / CWE Mapping:** CWE-294 (Authentication Bypass by Capture-replay), CWE-312
    ///   (Cleartext Storage of Sensitive Information).
    /// - **Likelihood & Exploitability:** High (7/10) on browser login endpoints.
    /// - **Applied Mitigation:** Generates 16 random bytes from `OsRng`, stores only the SHA-256
    ///   digest on disk, clamps TTL to `60..=900` seconds, and consumes the code on first use.
    pub fn issue_code(
        &mut self,
        username: &str,
        capabilities: Vec<String>,
        ttl_seconds: i64,
    ) -> String {
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let code = format!("sbc_{}", URL_SAFE_NO_PAD.encode(raw));
        let digest = sha256_hex(&code);
        let clamped_ttl = ttl_seconds.clamp(60, 900);
        self.prune_expired(Utc::now());
        self.codes.insert(
            digest.clone(),
            LoginCodeEntry {
                code_hash_hex: digest,
                username: username.to_string(),
                capabilities,
                expires_at: (Utc::now() + Duration::seconds(clamped_ttl)).to_rfc3339(),
            },
        );
        code
    }

    /// Consumes a single-use login code and returns its `(username, capabilities)` if valid.
    pub fn consume_code(&mut self, code: &str) -> Result<(String, Vec<String>), String> {
        let now = Utc::now();
        self.prune_expired(now);
        let digest = sha256_hex(code.trim());
        let entry = self
            .codes
            .remove(&digest)
            .ok_or_else(|| "Invalid or expired login code".to_string())?;
        Ok((entry.username, entry.capabilities))
    }

    fn prune_expired(&mut self, now: DateTime<Utc>) {
        self.codes.retain(|_, v| {
            DateTime::parse_from_rfc3339(&v.expires_at)
                .map(|dt| dt.with_timezone(&Utc) > now)
                .unwrap_or(false)
        });
    }
}

fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

/// Builds an RFC 8414 / OpenID Connect Discovery 1.0 metadata document.
///
/// # Standards Compliance
/// - Conforms to OpenID Connect Discovery 1.0 & RFC 8414 §2.
pub fn openid_configuration(issuer: &str) -> serde_json::Value {
    let base = issuer.trim_end_matches('/');
    serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/enroll"),
        "token_endpoint": format!("{base}/v1/auth/exchange"),
        "userinfo_endpoint": format!("{base}/v1/auth/userinfo"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "response_types_supported": ["code", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
    })
}

/// Builds an RFC 7517 / RFC 8037 Ed25519 OKP JWKS document from `sb-auth`'s public key.
///
/// # Standards Compliance
/// - Conforms to RFC 7517 (JWK) and RFC 8037 §2 (CFRG Elliptic Curve `OKP` / `Ed25519`).
pub fn jwks_document(auth_pub_b64: &str) -> Result<serde_json::Value, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(auth_pub_b64.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(auth_pub_b64.trim()))
        .map_err(|e| format!("Invalid sb-auth public key encoding: {e}"))?;
    if raw.len() != 32 {
        return Err("Ed25519 public key must be 32 bytes".into());
    }
    let x = URL_SAFE_NO_PAD.encode(&raw);
    let mut h = Sha256::new();
    h.update(&raw);
    let kid = hex::encode(&h.finalize()[..8]);
    Ok(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": kid,
            "x": x,
        }]
    }))
}

/// Exchanges a single-use login code for an `sb-auth` `SessionTokens` bundle.
pub fn exchange_login_code_for_session(
    code: &str,
    store: &mut LoginCodeStore,
    engine: &AuthEngine,
    roles: Vec<String>,
) -> Result<sb_auth::SessionTokens, String> {
    let (username, capabilities) = store.consume_code(code)?;
    engine
        .issue_session(&username, roles, capabilities, serde_json::json!({}))
        .map_err(|e| format!("Failed to issue session tokens: {e}"))
}

/// Builds a standard OpenID Connect Discovery document (`/.well-known/openid-configuration`).
pub fn discovery_document(issuer: &str) -> serde_json::Value {
    let base = issuer.trim_end_matches('/');
    serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth2/authorize"),
        "token_endpoint": format!("{base}/oauth2/token"),
        "userinfo_endpoint": format!("{base}/oauth2/userinfo"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
    })
}

/// Persistent Argon2id password credential store (`~/.sb/domain/credentials.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialStore {
    pub hashes: BTreeMap<String, String>,
}

pub fn default_credentials_path() -> PathBuf {
    sb_core::domain::local_domain_dir().join("credentials.json")
}

impl CredentialStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read credentials {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid credentials JSON {}: {e}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create credentials dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize credentials: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp credentials: {e}"))?;
        let _ = sb_core::paths::ensure_private_permissions(&tmp);
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit credentials: {e}"))?;
        Ok(())
    }

    /// Loads Argon2id credentials from encrypted `SovereignDb` (`namespace = "oidc"`).
    pub fn load_from_db(
        db: &sb_db::SovereignDb,
        ticket: &sb_db::VerifiedDbTicket,
    ) -> Result<Self, String> {
        db.get_encrypted_json::<Self>(ticket, "oidc", "credentials")
            .map(|opt| opt.unwrap_or_default())
            .map_err(|e| e.to_string())
    }

    /// Persists Argon2id credentials into encrypted `SovereignDb` (`namespace = "oidc"`).
    pub fn save_to_db(
        &self,
        db: &sb_db::SovereignDb,
        ticket: &sb_db::VerifiedDbTicket,
    ) -> Result<(), String> {
        db.put_encrypted_json(ticket, "oidc", "credentials", self)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Sets an Argon2id password hash for `username` (min 8 chars).
    pub fn set_password(&mut self, username: &str, password: &str) -> Result<(), String> {
        let clean = sb_core::identity::validate_username(username)?;
        if password.len() < 8 || password.len() > 256 {
            return Err("Password must be 8..=256 characters".into());
        }
        let hash = sb_auth::crypto::hash_password(password)
            .map_err(|e| format!("Password hashing failed: {e}"))?;
        self.hashes.insert(clean, hash);
        Ok(())
    }

    /// Verifies `password` against the stored Argon2id hash for `username`.
    pub fn verify(&self, username: &str, password: &str) -> bool {
        let Ok(clean) = sb_core::identity::validate_username(username) else {
            return false;
        };
        let Some(hash) = self.hashes.get(&clean) else {
            return false;
        };
        sb_auth::crypto::verify_password(password, hash).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_auth::crypto::Keypair;
    use sb_auth::MemoryRevocationStore;
    use std::sync::Arc;

    #[test]
    fn login_code_is_single_use_and_jwks_exports_ed25519_okp() {
        let keypair = Keypair::generate();
        let rev = Arc::new(MemoryRevocationStore::new());
        let engine = AuthEngine::new(keypair, rev);

        let jwks = jwks_document(&engine.public_key_base64()).unwrap();
        assert_eq!(jwks["keys"][0]["kty"], "OKP");
        assert_eq!(jwks["keys"][0]["crv"], "Ed25519");

        let disc = discovery_document("https://dc.corp.sb/");
        assert_eq!(disc["issuer"], "https://dc.corp.sb");
        assert_eq!(disc["jwks_uri"], "https://dc.corp.sb/.well-known/jwks.json");
        assert_eq!(
            disc["userinfo_endpoint"],
            "https://dc.corp.sb/oauth2/userinfo"
        );

        let mut store = LoginCodeStore::default();
        let code = store.issue_code("anna.admin", vec!["domain:admin".into()], 300);
        assert!(code.starts_with("sbc_"));

        let tokens =
            exchange_login_code_for_session(&code, &mut store, &engine, vec!["admin".into()])
                .unwrap();
        assert!(tokens.access_token.starts_with("sbt."));

        // Replay of the same code must fail
        assert!(
            exchange_login_code_for_session(&code, &mut store, &engine, vec!["admin".into()])
                .is_err()
        );

        // Argon2id CredentialStore verification
        let mut creds = CredentialStore::default();
        creds.set_password("leon.admin", "StrongPass!2026").unwrap();
        assert!(creds.verify("leon.admin", "StrongPass!2026"));
        assert!(!creds.verify("leon.admin", "wrong"));
    }

    #[test]
    fn login_code_and_credentials_persist_in_sovereign_db() {
        let db = sb_db::SovereignDb::open_in_memory(sb_db::MasterKey::generate()).unwrap();
        let ticket = sb_db::VerifiedDbTicket {
            ticket_id: "tkt-oidc-1".into(),
            subject: "dc-1".into(),
            role: "Admin".into(),
            capabilities: vec!["db:read".into(), "db:write".into()],
            valid_until: (Utc::now().timestamp() + 3600) as u64,
            single_use: false,
        };

        let mut codes = LoginCodeStore::default();
        let code = codes.issue_code("anna.admin", vec!["domain:admin".into()], 300);
        codes.save_to_db(&db, &ticket).unwrap();

        let mut loaded_codes = LoginCodeStore::load_from_db(&db, &ticket).unwrap();
        let (user, caps) = loaded_codes.consume_code(&code).unwrap();
        assert_eq!(user, "anna.admin");
        assert_eq!(caps, vec!["domain:admin"]);
        loaded_codes.save_to_db(&db, &ticket).unwrap();

        let reloaded = LoginCodeStore::load_from_db(&db, &ticket).unwrap();
        assert!(reloaded.codes.is_empty());

        let mut creds = CredentialStore::default();
        creds.set_password("leon.admin", "StrongPass!2026").unwrap();
        creds.save_to_db(&db, &ticket).unwrap();

        let loaded_creds = CredentialStore::load_from_db(&db, &ticket).unwrap();
        assert!(loaded_creds.verify("leon.admin", "StrongPass!2026"));
        assert!(!loaded_creds.verify("leon.admin", "wrong"));
    }
}
