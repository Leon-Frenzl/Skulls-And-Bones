use chrono::Utc;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

pub const ACL_DOMAIN_SEPARATOR: &[u8] = b"SBM_CAPABILITY_TOKEN_V2";
pub const CAPABILITY_TOKEN_VERSION: u16 = 2;
const MAX_TOKEN_PORTS: usize = 256;

/// Decentralized Capability Token granting specific port permissions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    #[serde(default = "default_capability_token_version")]
    pub version: u16,
    pub issuer_node_id: String,
    pub subject_node_id: String,
    pub allowed_ports: Vec<u16>,
    pub valid_until: u64,
    pub authority_pubkey: [u8; 32],
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],
}

fn default_capability_token_version() -> u16 {
    CAPABILITY_TOKEN_VERSION
}

impl CapabilityToken {
    pub fn digest(&self) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(ACL_DOMAIN_SEPARATOR);
        hasher.update(self.version.to_be_bytes());
        hash_field(&mut hasher, self.issuer_node_id.as_bytes());
        hash_field(&mut hasher, self.subject_node_id.as_bytes());
        hasher.update((self.allowed_ports.len() as u64).to_be_bytes());
        for &port in &self.allowed_ports {
            hasher.update(port.to_be_bytes());
        }
        hasher.update(self.valid_until.to_be_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&result);
        out
    }

    /// Issues and signs a new CapabilityToken using the issuer's private scalar key
    pub fn issue(
        issuer_node_id: &str,
        subject_node_id: &str,
        allowed_ports: Vec<u16>,
        valid_until: u64,
        authority_secret: &Scalar,
    ) -> Self {
        let authority_pub = (authority_secret * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        let mut dummy = Self {
            version: CAPABILITY_TOKEN_VERSION,
            issuer_node_id: issuer_node_id.to_string(),
            subject_node_id: subject_node_id.to_string(),
            allowed_ports,
            valid_until,
            authority_pubkey: authority_pub,
            signature_r: [0u8; 32],
            signature_s: [0u8; 32],
        };

        let digest = dummy.digest();

        // Schnorr signature
        let k = Scalar::random(&mut OsRng);
        let commitment_r = (k * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();

        let mut chal_hasher = Sha512::new();
        chal_hasher.update(ACL_DOMAIN_SEPARATOR);
        chal_hasher.update(commitment_r);
        chal_hasher.update(authority_pub);
        chal_hasher.update(digest);
        let chal_hash: [u8; 64] = chal_hasher.finalize().into();
        let challenge = Scalar::from_bytes_mod_order_wide(&chal_hash);

        let response_s = k + challenge * authority_secret;

        dummy.signature_r = commitment_r;
        dummy.signature_s = response_s.to_bytes();
        dummy
    }

    /// Verifies the cryptographic Schnorr signature and validity epoch of the token
    pub fn verify(&self, current_epoch: u64) -> Result<(), String> {
        if self.version != CAPABILITY_TOKEN_VERSION {
            return Err("Unsupported capability token version".to_string());
        }
        if self.issuer_node_id.is_empty() || self.subject_node_id.is_empty() {
            return Err("Capability token identities must not be empty".to_string());
        }
        if self.allowed_ports.is_empty() || self.allowed_ports.len() > MAX_TOKEN_PORTS {
            return Err("Capability token must contain 1-256 explicit ports".to_string());
        }
        if current_epoch >= self.valid_until {
            return Err("Capability token expired".to_string());
        }

        let compressed_x = CompressedRistretto(self.authority_pubkey);
        let x_point = compressed_x
            .decompress()
            .ok_or_else(|| "Invalid authority public key point".to_string())?;

        let compressed_r = CompressedRistretto(self.signature_r);
        let r_point = compressed_r
            .decompress()
            .ok_or_else(|| "Invalid commitment R point".to_string())?;

        let s_scalar: Option<Scalar> = Scalar::from_canonical_bytes(self.signature_s).into();
        let s_scalar = match s_scalar {
            Some(s) => s,
            None => return Err("Invalid scalar S".to_string()),
        };

        let digest = self.digest();

        let mut chal_hasher = Sha512::new();
        chal_hasher.update(ACL_DOMAIN_SEPARATOR);
        chal_hasher.update(self.signature_r);
        chal_hasher.update(self.authority_pubkey);
        chal_hasher.update(digest);
        let chal_hash: [u8; 64] = chal_hasher.finalize().into();
        let challenge = Scalar::from_bytes_mod_order_wide(&chal_hash);

        let lhs = s_scalar * RISTRETTO_BASEPOINT_POINT;
        let rhs = r_point + challenge * x_point;

        if lhs == rhs {
            Ok(())
        } else {
            Err("Signature verification failed".to_string())
        }
    }
}

fn hash_field(hasher: &mut Sha512, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// Capability-based Access Control Engine (Default-Deny)
#[derive(Debug, Clone)]
pub struct AclEngine {
    // Subject Node ID -> List of CapabilityTokens
    tokens: HashMap<String, Vec<CapabilityToken>>,
    trusted_authorities: HashMap<String, [u8; 32]>,
}

impl Default for AclEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AclEngine {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
            trusted_authorities: HashMap::new(),
        }
    }

    pub fn trust_authority(
        &mut self,
        issuer_node_id: &str,
        authority_pubkey: [u8; 32],
    ) -> Result<(), String> {
        if issuer_node_id.trim().is_empty()
            || CompressedRistretto(authority_pubkey).decompress().is_none()
        {
            return Err("Invalid capability authority identity or public key".to_string());
        }
        self.trusted_authorities
            .insert(issuer_node_id.trim().to_string(), authority_pubkey);
        Ok(())
    }

    /// Grants and stores a verified capability token
    pub fn grant(&mut self, token: CapabilityToken) -> Result<(), String> {
        let now = Utc::now().timestamp() as u64;
        token.verify(now)?;
        // CVE-Threat: Attacker-created self-signed capability grants.
        // Analysis: Signature validity alone proves key possession, not issuer authority.
        // Hardening: Require an explicit issuer-node/public-key trust pin before storing.
        if self.trusted_authorities.get(&token.issuer_node_id) != Some(&token.authority_pubkey) {
            return Err("Capability token issuer is not trusted".to_string());
        }
        self.tokens
            .entry(token.subject_node_id.clone())
            .or_default()
            .push(token);
        Ok(())
    }

    /// Checks whether subject node has permission to access the target port
    pub fn is_port_allowed(&self, subject_node_id: &str, port: u16, current_epoch: u64) -> bool {
        if let Some(token_list) = self.tokens.get(subject_node_id) {
            for token in token_list {
                if token.verify(current_epoch).is_ok() && token.allowed_ports.contains(&port) {
                    return true;
                }
            }
            false
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_token_signing_and_verification() {
        let authority_secret = Scalar::random(&mut OsRng);
        let now = Utc::now().timestamp() as u64;

        let token = CapabilityToken::issue(
            "sbm-0xissuer00",
            "sbm-0xsubject1",
            vec![22, 8080],
            now + 3600,
            &authority_secret,
        );

        assert!(token.verify(now).is_ok());

        // Tampering test: altered port
        let mut tampered = token.clone();
        tampered.allowed_ports.push(5432);
        assert!(tampered.verify(now).is_err());

        let mut identity_collision = token.clone();
        identity_collision.issuer_node_id = "issu".to_string();
        identity_collision.subject_node_id = "ertarget".to_string();
        assert_ne!(identity_collision.digest(), token.digest());

        let mut unsupported_version = token.clone();
        unsupported_version.version = 1;
        assert!(unsupported_version.verify(now).is_err());

        // Expiration test
        assert!(token.verify(now + 4000).is_err());
        assert!(token.verify(token.valid_until).is_err());
    }

    #[test]
    fn test_acl_engine_port_enforcement() {
        let authority_secret = Scalar::random(&mut OsRng);
        let now = Utc::now().timestamp() as u64;

        let token = CapabilityToken::issue(
            "sbm-0xvault",
            "sbm-0xclient",
            vec![22, 8080], // Only SSH and HTTP allowed
            now + 3600,
            &authority_secret,
        );

        let mut engine = AclEngine::new();
        engine
            .trust_authority("sbm-0xvault", token.authority_pubkey)
            .expect("Authority must be valid");
        engine.grant(token).expect("Grant failed");

        // Allowed ports
        assert!(engine.is_port_allowed("sbm-0xclient", 22, now));
        assert!(engine.is_port_allowed("sbm-0xclient", 8080, now));

        // Blocked database port
        assert!(!engine.is_port_allowed("sbm-0xclient", 5432, now));
        assert!(!engine.is_port_allowed("sbm-0xclient", 3306, now));

        // Unknown client blocked
        assert!(!engine.is_port_allowed("sbm-0xunknown", 22, now));
    }

    #[test]
    fn acl_rejects_untrusted_issuers_and_empty_port_scopes() {
        let secret = Scalar::random(&mut OsRng);
        let now = Utc::now().timestamp() as u64;
        let mut engine = AclEngine::new();

        let forged = CapabilityToken::issue("attacker", "client", vec![22], now + 3600, &secret);
        assert!(engine.grant(forged).is_err());
        assert!(!engine.is_port_allowed("unknown", 22, now));

        let empty_scope = CapabilityToken::issue("issuer", "client", vec![], now + 3600, &secret);
        assert!(empty_scope.verify(now).is_err());
    }
}
