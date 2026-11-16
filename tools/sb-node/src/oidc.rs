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
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit login codes: {e}"))?;
        Ok(())
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
    }
}
