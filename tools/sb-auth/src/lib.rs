//! # S&B Auth — Sovereign Authentication & Revocation Kit
//!
//! Ein hochgradig taktisches, modulares und manipulationssicheres Authentifizierungs-Kit
//! für souveräne Entwickler, Microservices und Desktop-Clients in Rust.
//!
//! ## Kernfunktionen
//! - **Sovereign Tokens (`sbt.*`)**: Ed25519-signierte, zustandslose Tokens ohne JWT-Schwachstellen.
//! - **Multi-Tier Revocation**:
//!   1. Token-Level (`token_id` / jti)
//!   2. Session-Level (`session_id`)
//!   3. User-Level (`user_epoch` für weltweiten Logout aller aktiven Geräte)
//! - **Rotierende Refresh-Tokens**: Single-use Revocation bei jedem Refresh.
//! - **Prüfsummen-geschützte API-Keys (`sba_*`)**: CRC32-integrierte Keys zur Soforterkennung von Tippfehlern.
//! - **Argon2id Hashing**: Speicherharter Passwortschutz nach BSI/OWASP-Empfehlung.
//! - **TOTP (RFC 6238)**: 6-stellige Codes mit Zeittoleranz und Schutz vor Replay-Angriffen.

pub mod api_key;
pub mod claims;
pub mod crypto;
pub mod engine;
pub mod error;
pub mod middleware;
pub mod revocation;
pub mod storage;
pub mod token;
pub mod ui;

pub mod prelude {
    pub use crate::api_key::{ApiKey, ApiKeyEnv};
    pub use crate::claims::{SovereignClaims, TokenType};
    pub use crate::crypto::{
        generate_totp_code, generate_totp_secret, hash_password, verify_password, verify_totp_code,
        Keypair,
    };
    pub use crate::engine::{AuthEngine, AuthVerifier, SessionTokens};
    pub use crate::error::AuthError;
    pub use crate::middleware::{authenticate_header, authorize_header, extract_bearer_token};
    pub use crate::revocation::RevocationManager;
    pub use crate::storage::file::FileRevocationStore;
    pub use crate::storage::memory::MemoryRevocationStore;
    pub use crate::storage::RevocationStore;
    pub use crate::token::{TokenDecoder, TokenEncoder};
    pub use crate::ui::{render_login_page, serve_preview, UiConfig};
    pub use crate::{inspect_node_trust_status, AuthNodeTrustStatus};
}

pub use prelude::*;

/// Summary of the node's unified identity, revocation ledger, and `sb-ca` PKI trust state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AuthNodeTrustStatus {
    pub sb_home: String,
    pub identity_callsign: Option<String>,
    pub node_fingerprint: Option<String>,
    pub ssh_ca_active: bool,
    pub ssh_ca_pub_path: String,
    pub x509_ca_active: bool,
    pub x509_root_crt_path: String,
    pub revocation_db_path: String,
    pub revocation_db_exists: bool,
}

/// Inspects the local node's sovereign identity (`~/.sb/identity.json`), revocation database,
/// and unified `sb-ca` trust roots (`~/.sb/ca/ssh/ca_key.pub`, `~/.sb/ca/root_ca.crt`).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Disconnected identity/revocation state where `sb-auth` resolves paths outside `SB_HOME` or ignores `sb-ca` PKI status.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path), CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: Low (2/10) when anchored to `sb_core::paths`.
/// - Applied Mitigation: Strictly resolves all identity, revocation, and CA paths via `sb_core::paths` (`~/.sb/` and `~/.sb/ca/`).
/// - Standards Compliance: Conforms to IETF RFC 4251 (OpenSSH), IETF RFC 5280 (X.509), and IETF RFC 8259 (JSON).
pub fn inspect_node_trust_status() -> AuthNodeTrustStatus {
    let sb_home = sb_core::paths::sb_home();
    let id_path = sb_home.join("identity.json");
    let mut identity_callsign = None;
    let mut node_fingerprint = None;

    if id_path.exists() {
        if let Ok(raw) = std::fs::read_to_string(&id_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                identity_callsign = val
                    .get("callsign")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                node_fingerprint = val
                    .get("node_fingerprint")
                    .and_then(|v| v.as_str())
                    .map(String::from);
            }
        }
    }

    let ssh_ca_key = sb_core::paths::sb_ca_ssh_key_path();
    let ssh_ca_pub = sb_core::paths::sb_ca_ssh_pub_path();
    let x509_crt = sb_core::paths::sb_ca_x509_crt_path();
    let rev_db = sb_home.join("auth_revocations.json");

    AuthNodeTrustStatus {
        sb_home: sb_home.to_string_lossy().to_string(),
        identity_callsign,
        node_fingerprint,
        ssh_ca_active: ssh_ca_key.exists() && ssh_ca_pub.exists(),
        ssh_ca_pub_path: ssh_ca_pub.to_string_lossy().to_string(),
        x509_ca_active: x509_crt.exists(),
        x509_root_crt_path: x509_crt.to_string_lossy().to_string(),
        revocation_db_exists: rev_db.exists(),
        revocation_db_path: rev_db.to_string_lossy().to_string(),
    }
}

#[cfg(test)]
mod pki_coupling_tests {
    use super::*;

    #[test]
    fn test_inspect_node_trust_status_uses_canonical_sb_paths() {
        let status = inspect_node_trust_status();
        assert!(status.ssh_ca_pub_path.ends_with("ca_key.pub"));
        assert!(!status.ssh_ca_pub_path.contains(".sb-ssh"));
        assert!(status.x509_root_crt_path.ends_with("root_ca.crt"));
        assert!(status.revocation_db_path.ends_with("auth_revocations.json"));
    }
}
