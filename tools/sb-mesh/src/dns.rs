use chrono::Utc;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::peer::PeerTable;

pub const SBM_TLD: &str = ".sbm";
pub const DNS_DOMAIN_SEPARATOR: &[u8] = b"SBM_ZONE_NAME_RECORD_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionLayer {
    /// Layer 0: Globally unique, self-authenticating cryptographic node identity
    Layer0Canonical,
    /// Layer 1: Cryptographically signed delegation within a swarm/zone
    Layer1SwarmZone,
    /// Layer 2: Local, subjective human-meaningful petname alias
    Layer2Petname,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDestination {
    pub domain: String,
    pub node_id: String,
    pub public_key_base64: Option<String>,
    pub endpoint: Option<SocketAddr>,
    pub overlay_ip: Option<String>,
    pub port: u16,
    pub layer: ResolutionLayer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    NonSovereignDomain(String),
    MalformedDomain(String),
    RecordNotFound(String),
    SignatureVerificationFailed,
    RecordExpired { epoch: u64, ttl: u64 },
    PeerNotFound(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::NonSovereignDomain(d) => write!(f, "Domain '{}' does not end with .sbm", d),
            DnsError::MalformedDomain(d) => write!(f, "Malformed .sbm domain: '{}'", d),
            DnsError::RecordNotFound(d) => write!(f, "Sovereign name record not found for '{}'", d),
            DnsError::SignatureVerificationFailed => {
                write!(f, "Cryptographic zone signature verification failed")
            }
            DnsError::RecordExpired { epoch, ttl } => {
                write!(f, "Zone record expired (epoch: {}, ttl: {})", epoch, ttl)
            }
            DnsError::PeerNotFound(id) => write!(f, "Mesh peer not found for node ID '{}'", id),
        }
    }
}

impl std::error::Error for DnsError {}

/// Layer 1: Cryptographically signed Swarm / Zone Name Record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub service: String,
    pub zone: String,
    pub target_node_id: String,
    pub target_endpoint: Option<String>,
    pub target_port: u16,
    pub epoch: u64,
    pub ttl_secs: u64,
    pub authority_pubkey: [u8; 32],
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],
}

impl NameRecord {
    /// Computes deterministic hash over the record's payload
    pub fn digest(&self) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(DNS_DOMAIN_SEPARATOR);
        hasher.update(self.service.as_bytes());
        hasher.update(self.zone.as_bytes());
        hasher.update(self.target_node_id.as_bytes());
        if let Some(ref ep) = self.target_endpoint {
            hasher.update(ep.as_bytes());
        }
        hasher.update(self.target_port.to_be_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.ttl_secs.to_be_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&result);
        out
    }

    /// Signs the name record using a Zone Authority's private scalar key
    #[allow(clippy::too_many_arguments)]
    pub fn sign_record(
        service: &str,
        zone: &str,
        target_node_id: &str,
        target_endpoint: Option<String>,
        target_port: u16,
        epoch: u64,
        ttl_secs: u64,
        authority_secret: &Scalar,
    ) -> Self {
        let authority_pub = (authority_secret * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        let mut dummy = Self {
            service: service.to_string(),
            zone: zone.to_string(),
            target_node_id: target_node_id.to_string(),
            target_endpoint,
            target_port,
            epoch,
            ttl_secs,
            authority_pubkey: authority_pub,
            signature_r: [0u8; 32],
            signature_s: [0u8; 32],
        };

        let digest = dummy.digest();

        // Schnorr signature: r, R = k * B, e = H(R || X || M), s = k + e * x
        let k = Scalar::random(&mut OsRng);
        let commitment_r = (k * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();

        let mut chal_hasher = Sha512::new();
        chal_hasher.update(DNS_DOMAIN_SEPARATOR);
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

    /// Mathematically verifies the Schnorr signature against the zone authority public key
    pub fn verify(&self, current_epoch: u64) -> Result<(), DnsError> {
        // Check TTL expiration
        if current_epoch > self.epoch.saturating_add(self.ttl_secs) {
            return Err(DnsError::RecordExpired {
                epoch: self.epoch,
                ttl: self.ttl_secs,
            });
        }

        let compressed_x = CompressedRistretto(self.authority_pubkey);
        let x_point = compressed_x
            .decompress()
            .ok_or(DnsError::SignatureVerificationFailed)?;

        let compressed_r = CompressedRistretto(self.signature_r);
        let r_point = compressed_r
            .decompress()
            .ok_or(DnsError::SignatureVerificationFailed)?;

        let s_scalar: Option<Scalar> = Scalar::from_canonical_bytes(self.signature_s).into();
        let s_scalar = match s_scalar {
            Some(s) => s,
            None => return Err(DnsError::SignatureVerificationFailed),
        };

        let digest = self.digest();

        let mut chal_hasher = Sha512::new();
        chal_hasher.update(DNS_DOMAIN_SEPARATOR);
        chal_hasher.update(self.signature_r);
        chal_hasher.update(self.authority_pubkey);
        chal_hasher.update(digest);
        let chal_hash: [u8; 64] = chal_hasher.finalize().into();
        let challenge = Scalar::from_bytes_mod_order_wide(&chal_hash);

        // Verification equation: s * B == R + e * X
        let lhs = s_scalar * RISTRETTO_BASEPOINT_POINT;
        let rhs = r_point + challenge * x_point;

        if lhs == rhs {
            Ok(())
        } else {
            Err(DnsError::SignatureVerificationFailed)
        }
    }
}

/// In-memory cache & store for Layer 1 Swarm Zone Records
#[derive(Debug, Clone, Default)]
pub struct ZoneStore {
    // Key: (zone, service) in lowercase -> NameRecord
    records: HashMap<(String, String), NameRecord>,
}

impl ZoneStore {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn insert(&mut self, record: NameRecord) {
        let key = (record.zone.to_lowercase(), record.service.to_lowercase());
        self.records.insert(key, record);
    }

    pub fn get(&self, zone: &str, service: &str) -> Option<&NameRecord> {
        let key = (zone.to_lowercase(), service.to_lowercase());
        self.records.get(&key)
    }
}

/// Layer 2: Local Petname Registry
#[derive(Debug, Clone, Default)]
pub struct PetnameRegistry {
    // Alias (e.g. "nas", "vault", "laptop") -> Target (e.g. "0x12d3ae3b", "api.team-0x9a4f")
    aliases: HashMap<String, String>,
}

impl PetnameRegistry {
    pub fn new() -> Self {
        Self {
            aliases: HashMap::new(),
        }
    }

    pub fn set_alias(&mut self, petname: &str, target: &str) {
        self.aliases
            .insert(petname.to_lowercase(), target.to_lowercase());
    }

    pub fn get_alias(&self, petname: &str) -> Option<&String> {
        self.aliases.get(&petname.to_lowercase())
    }
}

/// Sovereign Name System (SNS) Resolver
/// Resolves `.sbm` domains across the 3 layers of Zooko's Triangle
pub struct SovereignResolver {
    pub peer_table: Arc<RwLock<PeerTable>>,
    pub petnames: Arc<RwLock<PetnameRegistry>>,
    pub zone_store: Arc<RwLock<ZoneStore>>,
}

impl SovereignResolver {
    pub fn new(peer_table: Arc<RwLock<PeerTable>>) -> Self {
        Self {
            peer_table,
            petnames: Arc::new(RwLock::new(PetnameRegistry::new())),
            zone_store: Arc::new(RwLock::new(ZoneStore::new())),
        }
    }

    /// Resolves a domain string like "vault.sbm" or "0x12d3ae3b.sbm:8080"
    pub async fn resolve(&self, query: &str) -> Result<ResolvedDestination, DnsError> {
        let (raw_domain, default_port) = parse_domain_and_port(query);

        if !raw_domain.ends_with(SBM_TLD) {
            return Err(DnsError::NonSovereignDomain(raw_domain.to_string()));
        }

        let label = raw_domain.trim_end_matches(SBM_TLD);
        if label.is_empty() {
            return Err(DnsError::MalformedDomain(raw_domain.to_string()));
        }

        let current_epoch = Utc::now().timestamp() as u64;

        // ───────────────────────────────────────────────────────────────────
        // SCHICHT 2: Petname Layer (Lokaler Subjektiver Alias)
        // ───────────────────────────────────────────────────────────────────
        let petname_target = {
            let petnames = self.petnames.read().await;
            petnames.get_alias(label).cloned()
        };

        if let Some(target) = petname_target {
            // Recurse with petname target
            let target_domain = if target.ends_with(SBM_TLD) {
                target.clone()
            } else {
                format!("{}{}", target, SBM_TLD)
            };

            if let Ok(mut res) =
                Box::pin(self.resolve_internal(&target_domain, default_port, current_epoch)).await
            {
                res.domain = raw_domain.to_string();
                res.layer = ResolutionLayer::Layer2Petname;
                return Ok(res);
            }
        }

        // ───────────────────────────────────────────────────────────────────
        // SCHICHT 0 / SCHICHT 1: Direkte Auflösung
        // ───────────────────────────────────────────────────────────────────
        self.resolve_internal(raw_domain, default_port, current_epoch)
            .await
    }

    async fn resolve_internal(
        &self,
        domain: &str,
        port: u16,
        current_epoch: u64,
    ) -> Result<ResolvedDestination, DnsError> {
        let label = domain.trim_end_matches(SBM_TLD);

        // ───────────────────────────────────────────────────────────────────
        // SCHICHT 0: Canonical Cryptographic Layer (z. B. "0x12d3ae3b" oder "sbm-0x12d3ae3b")
        // ───────────────────────────────────────────────────────────────────
        let canonical_id = normalize_canonical_node_id(label);
        {
            let peers = self.peer_table.read().await;
            // First check if it matches a peer by node_id directly
            for peer in peers.list() {
                if peer.config.node_id == canonical_id
                    || peer.config.callsign.eq_ignore_ascii_case(label)
                    || peer
                        .config
                        .node_id
                        .trim_start_matches("sbm-")
                        .eq_ignore_ascii_case(label)
                {
                    return Ok(ResolvedDestination {
                        domain: domain.to_string(),
                        node_id: peer.config.node_id.clone(),
                        public_key_base64: Some(peer.config.public_key_base64.clone()),
                        endpoint: peer.parsed_endpoint,
                        overlay_ip: peer.config.overlay_ip.clone(),
                        port,
                        layer: ResolutionLayer::Layer0Canonical,
                    });
                }
            }
        }

        // ───────────────────────────────────────────────────────────────────
        // SCHICHT 1: Swarm / Zone Layer (z. B. "<service>.<zone>.sbm")
        // ───────────────────────────────────────────────────────────────────
        if let Some((service, zone)) = label.split_once('.') {
            let zone_store = self.zone_store.read().await;
            if let Some(record) = zone_store.get(zone, service) {
                // Verify cryptographic signature and TTL
                record.verify(current_epoch)?;

                let parsed_ep: Option<SocketAddr> = record
                    .target_endpoint
                    .as_deref()
                    .and_then(|ep| ep.parse().ok());

                let target_port = if port != 0 && port != 80 {
                    port
                } else {
                    record.target_port
                };

                return Ok(ResolvedDestination {
                    domain: domain.to_string(),
                    node_id: record.target_node_id.clone(),
                    public_key_base64: None,
                    endpoint: parsed_ep,
                    overlay_ip: None,
                    port: target_port,
                    layer: ResolutionLayer::Layer1SwarmZone,
                });
            }
        }

        Err(DnsError::RecordNotFound(domain.to_string()))
    }
}

/// Helper to normalize "0x12d3ae3b" to "sbm-0x12d3ae3b"
pub fn normalize_canonical_node_id(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.starts_with("sbm-") {
        lower
    } else if lower.starts_with("0x") {
        format!("sbm-{}", lower)
    } else {
        format!("sbm-0x{}", lower)
    }
}

/// Helper to extract domain and port from "domain:port"
pub fn parse_domain_and_port(query: &str) -> (&str, u16) {
    if let Some((domain, port_str)) = query.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (domain, port);
        }
    }
    (query, 80)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{PeerConfig, PeerTable};
    use chrono::Utc;

    #[tokio::test]
    async fn test_layer0_canonical_resolution() {
        let mut table = PeerTable::new();
        table.add_peer(PeerConfig {
            callsign: "workstation".to_string(),
            node_id: "sbm-0x12d3ae3b".to_string(),
            public_key_base64: "dGVzdF9wdWJrZXlfMTIz".to_string(),
            endpoint: Some("192.168.1.100:58888".to_string()),
            overlay_ip: Some("10.42.0.2".to_string()),
            created_at: Utc::now(),
        });

        let resolver = SovereignResolver::new(Arc::new(RwLock::new(table)));

        // 1. Direct hex resolution: 0x12d3ae3b.sbm:8080
        let res1 = resolver.resolve("0x12d3ae3b.sbm:8080").await.unwrap();
        assert_eq!(res1.node_id, "sbm-0x12d3ae3b");
        assert_eq!(res1.port, 8080);
        assert_eq!(res1.layer, ResolutionLayer::Layer0Canonical);
        assert_eq!(res1.overlay_ip, Some("10.42.0.2".to_string()));

        // 2. Full prefix: sbm-0x12d3ae3b.sbm
        let res2 = resolver.resolve("sbm-0x12d3ae3b.sbm").await.unwrap();
        assert_eq!(res2.node_id, "sbm-0x12d3ae3b");
        assert_eq!(res2.layer, ResolutionLayer::Layer0Canonical);

        // 3. Callsign as fallback in Layer 0
        let res3 = resolver.resolve("workstation.sbm:22").await.unwrap();
        assert_eq!(res3.node_id, "sbm-0x12d3ae3b");
        assert_eq!(res3.port, 22);
    }

    #[tokio::test]
    async fn test_layer2_petname_mapping() {
        let mut table = PeerTable::new();
        table.add_peer(PeerConfig {
            callsign: "backup-srv".to_string(),
            node_id: "sbm-0xfeedface".to_string(),
            public_key_base64: "dGVzdF9wdWJrZXlfNDU2".to_string(),
            endpoint: Some("10.0.0.5:58888".to_string()),
            overlay_ip: Some("10.42.0.5".to_string()),
            created_at: Utc::now(),
        });

        let resolver = SovereignResolver::new(Arc::new(RwLock::new(table)));

        // Set local petname: "vault" -> "0xfeedface"
        {
            let mut petnames = resolver.petnames.write().await;
            petnames.set_alias("vault", "0xfeedface");
        }

        let res = resolver.resolve("vault.sbm:443").await.unwrap();
        assert_eq!(res.domain, "vault.sbm");
        assert_eq!(res.node_id, "sbm-0xfeedface");
        assert_eq!(res.port, 443);
        assert_eq!(res.layer, ResolutionLayer::Layer2Petname);
    }

    #[tokio::test]
    async fn test_layer1_signed_zone_record_and_tamper_defense() {
        let authority_secret = Scalar::random(&mut OsRng);
        let epoch = Utc::now().timestamp() as u64;

        let record = NameRecord::sign_record(
            "api",
            "team-infra",
            "sbm-0xca75cafe",
            Some("198.51.100.25:9000".to_string()),
            9000,
            epoch,
            3600, // 1 hour TTL
            &authority_secret,
        );

        // 1. Valid signature verification
        assert!(record.verify(epoch).is_ok());

        // 2. Tampered port detection
        let mut tampered_port = record.clone();
        tampered_port.target_port = 9001;
        assert_eq!(
            tampered_port.verify(epoch),
            Err(DnsError::SignatureVerificationFailed)
        );

        // 3. Tampered target node ID detection
        let mut tampered_node = record.clone();
        tampered_node.target_node_id = "sbm-0xhacked".to_string();
        assert_eq!(
            tampered_node.verify(epoch),
            Err(DnsError::SignatureVerificationFailed)
        );

        // 4. Expired TTL detection
        assert!(record.verify(epoch + 4000).is_err());
    }

    #[tokio::test]
    async fn test_layer1_swarm_zone_resolution_end_to_end() {
        let authority_secret = Scalar::random(&mut OsRng);
        let epoch = Utc::now().timestamp() as u64;

        let record = NameRecord::sign_record(
            "git",
            "s&b-swarm",
            "sbm-0x88889999",
            Some("203.0.113.50:58888".to_string()),
            3000,
            epoch,
            3600,
            &authority_secret,
        );

        let resolver = SovereignResolver::new(Arc::new(RwLock::new(PeerTable::new())));
        {
            let mut store = resolver.zone_store.write().await;
            store.insert(record);
        }

        let res = resolver.resolve("git.s&b-swarm.sbm").await.unwrap();
        assert_eq!(res.node_id, "sbm-0x88889999");
        assert_eq!(res.port, 3000);
        assert_eq!(res.layer, ResolutionLayer::Layer1SwarmZone);
    }
}
