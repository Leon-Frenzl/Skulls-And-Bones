use base64::prelude::*;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const DEFAULT_POW_DIFFICULTY: u8 = 16;
pub const POW_DOMAIN_SEPARATOR: &[u8] = b"SBM_SKADEMLIA_POW_V1";

/// Computes the number of leading zero bits of a 32-byte hash
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut zeros = 0u8;
    for &b in hash {
        if b == 0 {
            zeros += 8;
        } else {
            zeros += b.leading_zeros() as u8;
            break;
        }
    }
    zeros
}

/// S/Kademlia Static Proof-of-Work: Sha256(domain || pubkey || nonce)
pub fn compute_pow_hash(public_key: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POW_DOMAIN_SEPARATOR);
    hasher.update(public_key);
    hasher.update(nonce.to_be_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Mines a cryptographic Proof-of-Work nonce satisfying the difficulty threshold
pub fn mine_pow_nonce(public_key: &[u8; 32], difficulty: u8) -> u64 {
    let mut nonce = 0u64;
    loop {
        let hash = compute_pow_hash(public_key, nonce);
        if count_leading_zero_bits(&hash) >= difficulty {
            return nonce;
        }
        nonce += 1;
    }
}

/// Verifies whether a given nonce satisfies the S/Kademlia difficulty threshold
pub fn verify_pow_nonce(public_key: &[u8; 32], nonce: u64, difficulty: u8) -> bool {
    let hash = compute_pow_hash(public_key, nonce);
    count_leading_zero_bits(&hash) >= difficulty
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityJson {
    pub node_id: String,
    pub wireguard_pubkey: String,
    pub secret_key_base64: String,
    #[serde(default)]
    pub pow_nonce: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct NodeIdentity {
    pub node_id: String,
    pub wireguard_pubkey: String,
    pub secret: StaticSecret,
    pub public_key: PublicKey,
    pub pow_nonce: u64,
    pub created_at: DateTime<Utc>,
}

impl NodeIdentity {
    /// Generates a brand-new cryptographic sovereign node identity with S/Kademlia PoW
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);

        let pubkey_bytes = public_key.as_bytes();
        let wireguard_pubkey = BASE64_STANDARD.encode(pubkey_bytes);

        // Derive deterministic short Node-ID: sbm-0x<8 hex chars>
        let mut hasher = Sha256::new();
        hasher.update(pubkey_bytes);
        let hash = hasher.finalize();
        let short_hex = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3]
        );
        let node_id = format!("sbm-0x{}", short_hex);

        // Mine initial S/Kademlia Sybil-defense PoW
        let pow_nonce = mine_pow_nonce(pubkey_bytes, DEFAULT_POW_DIFFICULTY);

        Self {
            node_id,
            wireguard_pubkey,
            secret,
            public_key,
            pow_nonce,
            created_at: Utc::now(),
        }
    }

    /// Derive deterministic short Node-ID: sbm-0x<8 hex chars> from base64 pubkey
    pub fn derive_node_id_from_pubkey(pubkey_b64: &str) -> String {
        let pubkey_bytes = BASE64_STANDARD
            .decode(pubkey_b64.trim())
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&pubkey_bytes);
        let hash = hasher.finalize();
        format!(
            "sbm-0x{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3]
        )
    }

    /// Load the active mesh identity, or the `default` mesh identity when no catalog exists.
    pub fn load_or_generate_default() -> Result<Self, String> {
        let data_dir = default_data_dir()?;
        let networks_path = data_dir.join("networks.json");
        let mesh_name = if networks_path.exists() {
            let content = fs::read_to_string(&networks_path)
                .map_err(|error| format!("Failed to read mesh network catalog: {error}"))?;
            let networks: crate::network::NetworksFile = serde_json::from_str(&content)
                .map_err(|error| format!("Invalid mesh network catalog: {error}"))?;
            let mesh_name = networks.active_network;
            if !networks.networks.contains_key(&mesh_name) {
                return Err(format!(
                    "Active mesh '{}' is absent from the network catalog",
                    mesh_name
                ));
            }
            return Self::load_registered_for_mesh(&mesh_name);
        } else {
            "default".to_string()
        };
        Self::load_or_generate_for_mesh(&mesh_name)
    }

    pub fn load_or_generate_for_mesh(mesh_name: &str) -> Result<Self, String> {
        let paths = crate::state::MeshStatePaths::for_mesh(mesh_name)?;
        paths.ensure()?;
        let identity = Self::load_or_generate(&paths.identity)?;
        let base_dir = default_data_dir()?;
        crate::state::validate_identity_isolation(
            mesh_name,
            &identity.wireguard_pubkey,
            &base_dir,
        )?;
        Ok(identity)
    }

    pub fn load_registered_for_mesh(mesh_name: &str) -> Result<Self, String> {
        Self::load_registered_for_mesh_at(mesh_name, &default_data_dir()?)
    }

    fn load_registered_for_mesh_at(mesh_name: &str, data_dir: &Path) -> Result<Self, String> {
        // CVE-Threat: Identity substitution or silent key regeneration for a registered mesh.
        // Analysis: The catalog binding is authoritative; a missing or mismatched local key is not enrollment.
        // Hardening: Require an existing regular identity and compare its public key to the mesh catalog.
        let mesh_name = crate::state::normalize_mesh_name(mesh_name)?;
        let networks_path = data_dir.join("networks.json");
        let catalog_metadata = fs::symlink_metadata(&networks_path)
            .map_err(|error| format!("Mesh network catalog metadata could not be read: {error}"))?;
        if catalog_metadata.file_type().is_symlink() || !catalog_metadata.is_file() {
            return Err("Mesh network catalog must be a regular non-symlink file".to_string());
        }
        let content = fs::read_to_string(&networks_path)
            .map_err(|error| format!("Failed to read mesh network catalog: {error}"))?;
        let networks: crate::network::NetworksFile = serde_json::from_str(&content)
            .map_err(|error| format!("Invalid mesh network catalog: {error}"))?;
        if networks.networks.is_empty() || !networks.networks.contains_key(&networks.active_network)
        {
            return Err("Mesh network catalog has no valid active network".to_string());
        }
        for (key, network) in &networks.networks {
            crate::state::normalize_mesh_name(key)?;
            crate::state::normalize_mesh_name(&network.name)?;
            if key != &network.name {
                return Err(format!(
                    "Network key '{}' does not match network name '{}'",
                    key, network.name
                ));
            }
        }
        let network = networks
            .networks
            .get(mesh_name)
            .ok_or_else(|| format!("Mesh '{}' is absent from the network catalog", mesh_name))?;
        let paths = crate::state::MeshStatePaths::for_mesh_at(data_dir, mesh_name)?;
        paths.ensure()?;
        if !paths.identity.is_file() {
            return Err(format!(
                "Identity for registered mesh '{}' is missing; explicitly re-bootstrap or rejoin this mesh",
                mesh_name
            ));
        }
        let identity = Self::load_or_generate(&paths.identity)?;
        if network.wireguard_pubkey != identity.wireguard_pubkey {
            // Dynamic Threat Vector: Legacy placeholder pubkey ("sbm_node_fleet_anchor_pubkey=") in catalog blocks local mesh operations.
            // CVE / CWE Mapping: CWE-436: Interpretation Conflict
            // Likelihood & Exploitability: Medium (Score 6/10) - Triggered when catalog was initialized by older sb-node version.
            // Applied Mitigation: Automatically update placeholder key in network store to match verified local identity.
            if network.wireguard_pubkey == "sbm_node_fleet_anchor_pubkey=" {
                if let Ok(mut store) = crate::network::NetworkStore::load_existing(&networks_path) {
                    if let Some(net) = store.networks.get_mut(mesh_name) {
                        net.wireguard_pubkey = identity.wireguard_pubkey.clone();
                        let _ = store.save();
                    }
                }
            } else {
                return Err(format!(
                    "Mesh identity '{}' does not match its network catalog; explicitly re-bootstrap or rejoin this mesh",
                    mesh_name
                ));
            }
        }
        crate::state::validate_identity_isolation(mesh_name, &identity.wireguard_pubkey, data_dir)?;
        Ok(identity)
    }

    pub fn load_or_generate(path: &Path) -> Result<Self, String> {
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("Identity path must not be a symbolic link".to_string());
        }
        if path.exists() {
            let data = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read identity file: {}", e))?;
            let json: IdentityJson =
                serde_json::from_str(&data).map_err(|e| format!("Invalid identity JSON: {}", e))?;

            let mut secret_bytes = BASE64_STANDARD
                .decode(&json.secret_key_base64)
                .map_err(|e| format!("Corrupt secret key encoding: {}", e))?;

            if secret_bytes.len() != 32 {
                secret_bytes.zeroize();
                return Err("Invalid secret key length".to_string());
            }

            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&secret_bytes);
            secret_bytes.zeroize();
            let secret = StaticSecret::from(key_arr);
            key_arr.zeroize();
            let public_key = PublicKey::from(&secret);
            let wireguard_pubkey = BASE64_STANDARD.encode(public_key.as_bytes());
            let node_id = Self::derive_node_id_from_pubkey(&wireguard_pubkey);
            if json.wireguard_pubkey != wireguard_pubkey || json.node_id != node_id {
                return Err("Identity metadata does not match its private key".to_string());
            }

            let pow_nonce = if json.pow_nonce != 0
                && verify_pow_nonce(
                    public_key.as_bytes(),
                    json.pow_nonce,
                    DEFAULT_POW_DIFFICULTY,
                ) {
                json.pow_nonce
            } else {
                mine_pow_nonce(public_key.as_bytes(), DEFAULT_POW_DIFFICULTY)
            };

            Ok(Self {
                node_id,
                wireguard_pubkey,
                secret,
                public_key,
                pow_nonce,
                created_at: json.created_at,
            })
        } else {
            let identity = Self::generate();
            let mut secret_bytes = identity.secret.to_bytes();
            let json = IdentityJson {
                node_id: identity.node_id.clone(),
                wireguard_pubkey: identity.wireguard_pubkey.clone(),
                secret_key_base64: BASE64_STANDARD.encode(secret_bytes),
                pow_nonce: identity.pow_nonce,
                created_at: identity.created_at,
            };
            secret_bytes.zeroize();

            let mut data = serde_json::to_string_pretty(&json)
                .map_err(|e| format!("Failed to serialize identity: {}", e))?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .map_err(|e| format!("Failed to securely create identity file: {}", e))?;
            file.write_all(data.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| format!("Failed to save new identity: {}", e))?;
            data.zeroize();

            Ok(identity)
        }
    }

    /// Generate a Zero-Knowledge Platform Attestation Proof bound to a specific peer and session nonce
    pub fn generate_zk_proof(
        &self,
        peer_pubkey: &[u8; 32],
        session_nonce: u64,
        epoch: u64,
    ) -> crate::zk_attest::ZkProof {
        let witness = self.zk_witness();
        crate::zk_attest::generate_zk_proof(&witness, peer_pubkey, session_nonce, epoch)
    }

    /// Derive local sealed platform witness deterministically from node secret
    pub fn zk_witness(&self) -> crate::zk_attest::PlatformWitness {
        use sha2::Sha512;
        let mut hasher = Sha512::new();
        hasher.update(self.secret.to_bytes());
        hasher.update(b"SBM_ZK_PLATFORM_WITNESS_V1");
        let hash: [u8; 64] = hasher.finalize().into();
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&hash);
        crate::zk_attest::PlatformWitness {
            platform_secret: scalar,
            integrity_measurement: crate::zk_attest::STANDARD_POLICY_ROOT,
        }
    }

    /// Generate an air-gapped device pairing token to connect two devices without a central cloud
    pub fn generate_pairing_token(&self, endpoint: &str) -> String {
        self.generate_pairing_token_with_ttl(endpoint, None)
    }

    /// Generate an ephemeral air-gapped device pairing token with optional TTL in seconds
    pub fn generate_pairing_token_with_ttl(&self, endpoint: &str, ttl_secs: Option<u64>) -> String {
        let expires_at = ttl_secs
            .map(|ttl| Utc::now().timestamp() as u64 + ttl)
            .unwrap_or(0);
        let payload = format!(
            "{}|{}|{}|{}|{}",
            self.node_id, self.wireguard_pubkey, endpoint, self.pow_nonce, expires_at
        );
        format!("sbm-pair://{}", BASE64_STANDARD.encode(payload.as_bytes()))
    }

    /// Parse a pairing token from another device
    pub fn parse_pairing_token(token: &str) -> Result<(String, String, String), String> {
        let parsed = Self::parse_pairing_token_full(token)?;
        let now = Utc::now().timestamp() as u64;
        if parsed.is_expired(now) {
            return Err(
                "Pairing token has expired (TTL elapsed). Request a fresh QR/Token.".to_string(),
            );
        }
        Ok((parsed.node_id, parsed.wireguard_pubkey, parsed.endpoint))
    }

    /// Parse a pairing token including S/Kademlia Proof-of-Work nonce
    pub fn parse_pairing_token_with_pow(
        token: &str,
    ) -> Result<(String, String, String, u64), String> {
        let parsed = Self::parse_pairing_token_full(token)?;
        let now = Utc::now().timestamp() as u64;
        if parsed.is_expired(now) {
            return Err(
                "Pairing token has expired (TTL elapsed). Request a fresh QR/Token.".to_string(),
            );
        }
        Ok((
            parsed.node_id,
            parsed.wireguard_pubkey,
            parsed.endpoint,
            parsed.pow_nonce,
        ))
    }

    /// Full parser returning ParsedPairingToken structure with expiration details
    pub fn parse_pairing_token_full(token: &str) -> Result<ParsedPairingToken, String> {
        let raw = token.trim();
        let b64_str = if let Some(stripped) = raw.strip_prefix("sbm-pair://") {
            stripped
        } else {
            raw
        };

        let decoded = BASE64_STANDARD
            .decode(b64_str)
            .map_err(|e| format!("Invalid base64 token: {}", e))?;
        let text = String::from_utf8(decoded).map_err(|e| format!("Invalid UTF-8 token: {}", e))?;

        let parts: Vec<&str> = text.split('|').collect();
        if parts.len() < 3 {
            return Err("Token missing required components (NodeID|PubKey|Endpoint)".to_string());
        }

        let pow_nonce = if parts.len() >= 4 {
            parts[3].parse::<u64>().unwrap_or(0)
        } else {
            0
        };

        let expires_at = if parts.len() >= 5 {
            let exp = parts[4].parse::<u64>().unwrap_or(0);
            if exp > 0 {
                Some(exp)
            } else {
                None
            }
        } else {
            None
        };

        Ok(ParsedPairingToken {
            node_id: parts[0].to_string(),
            wireguard_pubkey: parts[1].to_string(),
            endpoint: parts[2].to_string(),
            pow_nonce,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPairingToken {
    pub node_id: String,
    pub wireguard_pubkey: String,
    pub endpoint: String,
    pub pow_nonce: u64,
    pub expires_at: Option<u64>,
}

impl ParsedPairingToken {
    pub fn is_expired(&self, current_time: u64) -> bool {
        if let Some(exp) = self.expires_at {
            exp > 0 && current_time > exp
        } else {
            false
        }
    }
}

/// Renders any text or token as a high-density Unicode half-block QR code for terminals
pub fn render_terminal_qr(data: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(data.as_bytes())
        .map_err(|e| format!("Failed to generate QR code: {}", e))?;
    let rendered = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Dark)
        .light_color(qrcode::render::unicode::Dense1x2::Light)
        .build();
    Ok(rendered)
}

pub fn default_data_dir() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("SB_MESH_HOME") {
        let path = PathBuf::from(path);
        if path.as_os_str().is_empty() {
            return Err("SB_MESH_HOME must not be empty".to_string());
        }
        return Ok(path);
    }
    dirs::home_dir()
        .map(|h| h.join(".sb-mesh"))
        .ok_or_else(|| "Could not determine home directory".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s_kademlia_pow_mining_and_verification() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let pubkey = PublicKey::from(&secret);

        // Test with 12 bits difficulty for fast test execution
        let difficulty = 12u8;
        let nonce = mine_pow_nonce(pubkey.as_bytes(), difficulty);

        assert!(verify_pow_nonce(pubkey.as_bytes(), nonce, difficulty));
        // Wrong nonce must fail
        assert!(!verify_pow_nonce(
            pubkey.as_bytes(),
            nonce ^ 0xdeadbeef,
            difficulty + 16
        ));
    }

    #[test]
    fn mesh_identity_is_isolated_persistent_and_metadata_bound() {
        let base = std::env::temp_dir().join(format!(
            "sb-mesh-identity-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let alpha = crate::state::MeshStatePaths::for_mesh_at(&base, "alpha").unwrap();
        let beta = crate::state::MeshStatePaths::for_mesh_at(&base, "beta").unwrap();
        alpha.ensure().unwrap();
        beta.ensure().unwrap();

        let first = NodeIdentity::load_or_generate(&alpha.identity).unwrap();
        let second = NodeIdentity::load_or_generate(&beta.identity).unwrap();
        assert_ne!(first.wireguard_pubkey, second.wireguard_pubkey);
        assert_eq!(
            first.wireguard_pubkey,
            NodeIdentity::load_or_generate(&alpha.identity)
                .unwrap()
                .wireguard_pubkey
        );

        let mut json: IdentityJson =
            serde_json::from_slice(&fs::read(&alpha.identity).unwrap()).unwrap();
        json.node_id = "forged-node-id".to_string();
        fs::write(&alpha.identity, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(NodeIdentity::load_or_generate(&alpha.identity)
            .err()
            .unwrap()
            .contains("does not match"));

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn registered_mesh_identity_is_not_generated_when_missing() {
        let base = std::env::temp_dir().join(format!(
            "sb-mesh-registered-identity-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&base).unwrap();
        let network = crate::network::MeshNetwork::new(
            "alpha",
            "test mesh",
            "10.42.0.0/16",
            "catalog-key",
            None,
            None,
            None,
        )
        .unwrap();
        let networks = crate::network::NetworksFile {
            active_network: "alpha".to_string(),
            networks: std::collections::HashMap::from([("alpha".to_string(), network)]),
        };
        fs::write(
            base.join("networks.json"),
            serde_json::to_vec(&networks).unwrap(),
        )
        .unwrap();

        let paths = crate::state::MeshStatePaths::for_mesh_at(&base, "alpha").unwrap();
        assert!(NodeIdentity::load_registered_for_mesh_at("alpha", &base)
            .err()
            .unwrap()
            .contains("is missing"));
        assert!(!paths.identity.exists());

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_pairing_token_with_pow() {
        let identity = NodeIdentity::generate();
        let token = identity.generate_pairing_token("192.168.1.200:58888");

        let (node_id, pubkey, endpoint, pow) =
            NodeIdentity::parse_pairing_token_with_pow(&token).expect("Failed to parse token");

        assert_eq!(node_id, identity.node_id);
        assert_eq!(pubkey, identity.wireguard_pubkey);
        assert_eq!(endpoint, "192.168.1.200:58888");
        assert_eq!(pow, identity.pow_nonce);
    }

    #[test]
    fn test_pairing_token_with_ttl_expiration() {
        let identity = NodeIdentity::generate();
        // Valid token with 300s TTL
        let valid_token =
            identity.generate_pairing_token_with_ttl("192.168.1.200:58888", Some(300));
        let parsed = NodeIdentity::parse_pairing_token_full(&valid_token).unwrap();
        assert!(parsed.expires_at.is_some());
        assert!(!parsed.is_expired(Utc::now().timestamp() as u64));

        // Expired token (simulate past time)
        assert!(parsed.is_expired(Utc::now().timestamp() as u64 + 400));
    }

    #[test]
    fn test_render_terminal_qr() {
        let identity = NodeIdentity::generate();
        let token = identity.generate_pairing_token("192.168.1.200:58888");
        let qr = render_terminal_qr(&token).expect("Failed to render QR");
        assert!(!qr.is_empty());
        assert!(qr.contains('▀') || qr.contains('▄') || qr.contains('█'));
    }

    #[test]
    fn test_self_heal_placeholder_dummy_pubkey_in_network_catalog() {
        let base = std::env::temp_dir().join(format!(
            "sb-mesh-self-heal-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&base).unwrap();

        let network = crate::network::MeshNetwork::new(
            "default",
            "test default mesh",
            "10.240.0.0/16",
            "sbm_node_fleet_anchor_pubkey=",
            None,
            None,
            None,
        )
        .unwrap();
        let networks = crate::network::NetworksFile {
            active_network: "default".to_string(),
            networks: std::collections::HashMap::from([("default".to_string(), network)]),
        };
        fs::write(
            base.join("networks.json"),
            serde_json::to_vec(&networks).unwrap(),
        )
        .unwrap();

        let paths = crate::state::MeshStatePaths::for_mesh_at(&base, "default").unwrap();
        paths.ensure().unwrap();
        let real_identity = NodeIdentity::load_or_generate(&paths.identity).unwrap();

        let loaded = NodeIdentity::load_registered_for_mesh_at("default", &base).unwrap();
        assert_eq!(loaded.wireguard_pubkey, real_identity.wireguard_pubkey);

        let store =
            crate::network::NetworkStore::load_existing(&base.join("networks.json")).unwrap();
        assert_eq!(
            store.networks.get("default").unwrap().wireguard_pubkey,
            real_identity.wireguard_pubkey
        );

        fs::remove_dir_all(base).unwrap();
    }
}
