use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::peer::PeerTable;

/// Pending Join Request under 4-Eyes Quorum evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingJoin {
    pub request_id: String,
    pub candidate_name: String,
    pub candidate_node_id: String,
    pub candidate_pubkey: String,
    pub requested_role: String,
    pub sponsor_node: String,
    pub timestamp: u64,
    pub approvals: HashSet<String>,
}

/// Types of Gossip Payload Disseminated Across the Swarm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipKind {
    /// Certificate / Key Revocation List (CRL) update for compromised nodes
    RevokeNode {
        revoked_pubkey: String,
        reason: String,
        revoked_at: u64,
    },
    /// Swarm Zone Record synchronization across peers (CRDT state sync)
    ZoneRecordSync {
        domain: String,
        target_node_id: String,
        record_type: String,
        ttl: u64,
    },
    /// Join Request requiring 4-Eyes approval from swarm members
    JoinRequest {
        request_id: String,
        candidate_name: String,
        candidate_node_id: String,
        candidate_pubkey: String,
        requested_role: String,
        sponsor_node: String,
        timestamp: u64,
    },
    /// 4-Eyes Approval vote from an existing peer
    JoinApproval {
        request_id: String,
        approver_node: String,
        timestamp: u64,
    },
    /// Lightweight anti-entropy ping
    PingGossip { nonce: u64 },
}

/// Cryptographically Identified Epidemic Gossip Message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipMessage {
    pub id: [u8; 32],
    pub origin_node: String,
    pub epoch: u64,
    pub kind: GossipKind,
    pub signature: Vec<u8>,
}

impl GossipMessage {
    /// Computes unique content hash ID for deduplication and anti-entropy
    pub fn compute_id(origin_node: &str, epoch: u64, kind: &GossipKind) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SBM_GOSSIP_V1:");
        hasher.update(origin_node.as_bytes());
        hasher.update(&epoch.to_le_bytes());
        let kind_bytes = serde_json::to_vec(kind).unwrap_or_default();
        hasher.update(&kind_bytes);
        hasher.finalize().into()
    }

    pub fn new(origin_node: &str, epoch: u64, kind: GossipKind, signature: Vec<u8>) -> Self {
        let id = Self::compute_id(origin_node, epoch, &kind);
        Self {
            id,
            origin_node: origin_node.to_string(),
            epoch,
            kind,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    }
}

/// Outcome of processing an incoming epidemic gossip message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipAction {
    /// Forward message to neighboring peers (Epidemic fanout)
    Forward(GossipMessage),
    /// Message already observed in history (Deduplicated)
    IgnoredAlreadySeen,
    /// Message successfully processed locally without further propagation
    AppliedLocally(String),
    /// Malformed or rejected
    RejectedInvalid(String),
}

/// Decentralized P2P Gossip & Anti-Entropy Engine
#[derive(Debug, Clone, Default)]
pub struct GossipEngine {
    pub seen_messages: HashSet<[u8; 32]>,
    pub revocation_list: HashSet<String>,
    pub replicated_zones: HashMap<String, String>,
    pub pending_joins: HashMap<String, PendingJoin>,
}

impl GossipEngine {
    pub fn new() -> Self {
        Self {
            seen_messages: HashSet::new(),
            revocation_list: HashSet::new(),
            replicated_zones: HashMap::new(),
            pending_joins: HashMap::new(),
        }
    }

    /// Check if a given public key has been revoked by network consensus
    pub fn is_revoked(&self, pubkey_b64: &str) -> bool {
        self.revocation_list.contains(pubkey_b64)
    }

    /// Checks if a join request has reached the required 4-Eyes quorum
    pub fn is_join_approved(&self, request_id: &str, quorum: usize) -> bool {
        self.pending_joins
            .get(request_id)
            .map(|j| j.approvals.len() >= quorum)
            .unwrap_or(false)
    }

    /// Creates an authoritative node revocation announcement
    pub fn create_revocation(
        origin_node: &str,
        revoked_pubkey: &str,
        reason: &str,
        epoch: u64,
        dummy_sig: Vec<u8>,
    ) -> GossipMessage {
        let now = chrono::Utc::now().timestamp() as u64;
        let kind = GossipKind::RevokeNode {
            revoked_pubkey: revoked_pubkey.to_string(),
            reason: reason.to_string(),
            revoked_at: now,
        };
        GossipMessage::new(origin_node, epoch, kind, dummy_sig)
    }

    /// Creates a swarm zone record announcement
    pub fn create_zone_sync(
        origin_node: &str,
        domain: &str,
        target_node_id: &str,
        epoch: u64,
    ) -> GossipMessage {
        let kind = GossipKind::ZoneRecordSync {
            domain: domain.to_string(),
            target_node_id: target_node_id.to_string(),
            record_type: "A/OVERLAY".to_string(),
            ttl: 300,
        };
        GossipMessage::new(origin_node, epoch, kind, Vec::new())
    }

    /// Creates a 4-Eyes Join Request announcement
    pub fn create_join_request(
        origin_node: &str,
        request_id: &str,
        candidate_name: &str,
        candidate_node_id: &str,
        candidate_pubkey: &str,
        requested_role: &str,
        epoch: u64,
    ) -> GossipMessage {
        let now = chrono::Utc::now().timestamp() as u64;
        let kind = GossipKind::JoinRequest {
            request_id: request_id.to_string(),
            candidate_name: candidate_name.to_string(),
            candidate_node_id: candidate_node_id.to_string(),
            candidate_pubkey: candidate_pubkey.to_string(),
            requested_role: requested_role.to_string(),
            sponsor_node: origin_node.to_string(),
            timestamp: now,
        };
        GossipMessage::new(origin_node, epoch, kind, Vec::new())
    }

    /// Creates a 4-Eyes Approval announcement from a co-sponsor peer
    pub fn create_join_approval(origin_node: &str, request_id: &str, epoch: u64) -> GossipMessage {
        let now = chrono::Utc::now().timestamp() as u64;
        let kind = GossipKind::JoinApproval {
            request_id: request_id.to_string(),
            approver_node: origin_node.to_string(),
            timestamp: now,
        };
        GossipMessage::new(origin_node, epoch, kind, Vec::new())
    }

    /// Evaluates an incoming gossip message with anti-entropy deduplication
    pub fn process_incoming(
        &mut self,
        msg: GossipMessage,
        peer_table: Option<&mut PeerTable>,
    ) -> GossipAction {
        // 1. Anti-entropy deduplication
        if self.seen_messages.contains(&msg.id) {
            return GossipAction::IgnoredAlreadySeen;
        }

        // Verify ID integrity
        let expected_id = GossipMessage::compute_id(&msg.origin_node, msg.epoch, &msg.kind);
        if msg.id != expected_id {
            return GossipAction::RejectedInvalid("Tampered gossip message ID".to_string());
        }

        // Mark as seen
        self.seen_messages.insert(msg.id);

        // 2. Apply state effect
        match &msg.kind {
            GossipKind::RevokeNode {
                revoked_pubkey,
                reason,
                revoked_at: _,
            } => {
                self.revocation_list.insert(revoked_pubkey.clone());
                if let Some(table) = peer_table {
                    // Evict compromised peer immediately
                    table.remove_peer(revoked_pubkey);
                }
                println!(
                    "[GOSSIP CRL] Revoked key '{}' evicted (Reason: {})",
                    revoked_pubkey, reason
                );
            }
            GossipKind::ZoneRecordSync {
                domain,
                target_node_id,
                ..
            } => {
                self.replicated_zones
                    .insert(domain.clone(), target_node_id.clone());
            }
            GossipKind::JoinRequest {
                request_id,
                candidate_name,
                candidate_node_id,
                candidate_pubkey,
                requested_role,
                sponsor_node,
                timestamp,
            } => {
                let mut approvals = HashSet::new();
                approvals.insert(sponsor_node.clone());
                self.pending_joins.insert(
                    request_id.clone(),
                    PendingJoin {
                        request_id: request_id.clone(),
                        candidate_name: candidate_name.clone(),
                        candidate_node_id: candidate_node_id.clone(),
                        candidate_pubkey: candidate_pubkey.clone(),
                        requested_role: requested_role.clone(),
                        sponsor_node: sponsor_node.clone(),
                        timestamp: *timestamp,
                        approvals,
                    },
                );
            }
            GossipKind::JoinApproval {
                request_id,
                approver_node,
                timestamp: _,
            } => {
                if let Some(pending) = self.pending_joins.get_mut(request_id) {
                    pending.approvals.insert(approver_node.clone());
                }
            }
            GossipKind::PingGossip { .. } => {}
        }

        // 3. Return Forward action so node relays message to other peers
        GossipAction::Forward(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use chrono::Utc;

    #[test]
    fn test_gossip_deduplication_and_crl_eviction() {
        let mut engine = GossipEngine::new();
        let mut table = PeerTable::new();

        let evil_pubkey = "ZXhwbG9pdGVkX2tleV9mb3JfcmV2b2NhdGlvbg==";
        table.add_peer(PeerConfig {
            callsign: "compromised-node".to_string(),
            node_id: "sbm-0xevil".to_string(),
            public_key_base64: evil_pubkey.to_string(),
            endpoint: Some("192.168.1.150:58888".to_string()),
            overlay_ip: None,
            created_at: Utc::now(),
        });
        assert!(table.get_by_pubkey(evil_pubkey).is_some());

        // 1. Create Revocation
        let revocation_msg = GossipEngine::create_revocation(
            "sbm-0xauthority",
            evil_pubkey,
            "Device physically compromised",
            1,
            vec![1, 2, 3, 4],
        );

        // 2. Process first time -> Forward & Evict
        let action = engine.process_incoming(revocation_msg.clone(), Some(&mut table));
        match action {
            GossipAction::Forward(m) => assert_eq!(m.id, revocation_msg.id),
            other => panic!("Expected Forward action, got {:?}", other),
        }

        assert!(engine.is_revoked(evil_pubkey));
        assert!(
            table.get_by_pubkey(evil_pubkey).is_none(),
            "Compromised peer must be evicted from peer table"
        );

        // 3. Process second time -> IgnoredAlreadySeen
        let action2 = engine.process_incoming(revocation_msg, Some(&mut table));
        assert_eq!(action2, GossipAction::IgnoredAlreadySeen);
    }

    #[test]
    fn test_gossip_zone_record_sync() {
        let mut engine = GossipEngine::new();
        let zone_msg =
            GossipEngine::create_zone_sync("sbm-0xalpha", "vault.sbm", "sbm-0xvault_node", 1);

        let action = engine.process_incoming(zone_msg, None);
        assert!(matches!(action, GossipAction::Forward(_)));
        assert_eq!(
            engine.replicated_zones.get("vault.sbm").map(|s| s.as_str()),
            Some("sbm-0xvault_node")
        );
    }

    #[test]
    fn test_gossip_4eyes_join_request_and_quorum() {
        let mut engine = GossipEngine::new();

        // 1. Sponsor Alice broadcasts JoinRequest for Bob
        let req_msg = GossipEngine::create_join_request(
            "alice-node",
            "req-bob-1234",
            "bob",
            "sbm-bob-hardware-01",
            "bob_x25519_key_base64",
            "dev",
            1,
        );
        let action1 = engine.process_incoming(req_msg, None);
        assert!(matches!(action1, GossipAction::Forward(_)));

        // With 1 approval (Alice), quorum of 2 is NOT met yet
        assert!(!engine.is_join_approved("req-bob-1234", 2));
        // But quorum of 1 (single-sponsor) IS met
        assert!(engine.is_join_approved("req-bob-1234", 1));

        // 2. Co-sponsor Charlie approves the request
        let approval_msg = GossipEngine::create_join_approval("charlie-node", "req-bob-1234", 2);
        let action2 = engine.process_incoming(approval_msg, None);
        assert!(matches!(action2, GossipAction::Forward(_)));

        // Now with 2 approvals (Alice + Charlie), 4-Eyes quorum of 2 IS satisfied!
        assert!(engine.is_join_approved("req-bob-1234", 2));

        let pending = engine.pending_joins.get("req-bob-1234").unwrap();
        assert_eq!(pending.candidate_name, "bob");
        assert_eq!(pending.approvals.len(), 2);
        assert!(pending.approvals.contains("alice-node"));
        assert!(pending.approvals.contains("charlie-node"));
    }
}
