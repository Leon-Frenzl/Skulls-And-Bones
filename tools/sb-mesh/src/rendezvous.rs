use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub const KAD_MAGIC: [u8; 4] = *b"SBK1";
pub const KAD_BUCKET_SIZE: usize = 20;

/// 256-bit Kademlia XOR metric distance
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

/// Derives a deterministic 32-byte secret Rendezvous Topic for two paired peers
/// Only Alice and Bob can compute this topic. For all other nodes in the DHT, it's opaque noise.
pub fn derive_rendezvous_topic(
    pubkey_a: &[u8; 32],
    pubkey_b: &[u8; 32],
    epoch_day: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SBM_SOVEREIGN_KADEMLIA_TOPIC_V1");
    if pubkey_a < pubkey_b {
        hasher.update(pubkey_a);
        hasher.update(pubkey_b);
    } else {
        hasher.update(pubkey_b);
        hasher.update(pubkey_a);
    }
    hasher.update(epoch_day.to_be_bytes());
    let hash = hasher.finalize();

    let mut topic = [0u8; 32];
    topic.copy_from_slice(&hash);
    topic
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KadContact {
    pub node_id: [u8; 32],
    pub addr: SocketAddr,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KadMessage {
    Ping {
        sender_node_id: [u8; 32],
    },
    Pong {
        sender_node_id: [u8; 32],
        observed_addr: SocketAddr,
    },
    FindNode {
        sender_node_id: [u8; 32],
        target_id: [u8; 32],
    },
    NodesFound {
        nodes: Vec<KadContact>,
    },
    StoreRendezvous {
        topic: [u8; 32],
        encrypted_beacon: Vec<u8>,
        ttl_secs: u32,
    },
    FindRendezvous {
        topic: [u8; 32],
    },
    RendezvousFound {
        beacons: Vec<Vec<u8>>,
    },
}

impl KadMessage {
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&KAD_MAGIC);
        let payload =
            serde_json::to_vec(self).map_err(|e| format!("Serialization error: {}", e))?;
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 || bytes[0..4] != KAD_MAGIC {
            return Err("Invalid SBM Kademlia packet magic".to_string());
        }
        serde_json::from_slice(&bytes[4..]).map_err(|e| format!("Deserialization error: {}", e))
    }
}

/// In-memory S&B Kademlia Routing Table
pub struct KadRoutingTable {
    pub local_node_id: [u8; 32],
    pub contacts: Vec<KadContact>,
    #[allow(clippy::type_complexity)]
    pub rendezvous_store: HashMap<[u8; 32], Vec<(Vec<u8>, DateTime<Utc>)>>,
}

impl KadRoutingTable {
    pub fn new(local_node_id: [u8; 32]) -> Self {
        Self {
            local_node_id,
            contacts: Vec::new(),
            rendezvous_store: HashMap::new(),
        }
    }

    pub fn add_contact(&mut self, contact: KadContact) {
        if contact.node_id == self.local_node_id {
            return;
        }
        if let Some(pos) = self
            .contacts
            .iter()
            .position(|c| c.node_id == contact.node_id)
        {
            self.contacts[pos] = contact;
        } else {
            if self.contacts.len() < 256 {
                self.contacts.push(contact);
            }
        }
    }

    pub fn find_closest_nodes(&self, target_id: &[u8; 32], count: usize) -> Vec<KadContact> {
        let mut sorted = self.contacts.clone();
        sorted.sort_by(|a, b| {
            let dist_a = xor_distance(&a.node_id, target_id);
            let dist_b = xor_distance(&b.node_id, target_id);
            dist_a.cmp(&dist_b)
        });
        sorted.into_iter().take(count).collect()
    }

    pub fn store_rendezvous(&mut self, topic: [u8; 32], beacon: Vec<u8>, ttl_secs: u32) {
        let expires = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        let list = self.rendezvous_store.entry(topic).or_default();
        list.push((beacon, expires));
    }

    pub fn find_rendezvous(&mut self, topic: &[u8; 32]) -> Vec<Vec<u8>> {
        let now = Utc::now();
        if let Some(list) = self.rendezvous_store.get_mut(topic) {
            list.retain(|(_, exp)| *exp > now);
            list.iter().map(|(b, _)| b.clone()).collect()
        } else {
            Vec::new()
        }
    }
}

/// Pure S&B Sovereign Kademlia DHT Manager (100% Isolated from BitTorrent)
pub struct SbmKademliaManager {
    pub local_node_id: [u8; 32],
    pub table: Arc<RwLock<KadRoutingTable>>,
    pub socket: Arc<UdpSocket>,
}

impl SbmKademliaManager {
    pub async fn bind(local_node_id: [u8; 32], port: u16) -> Result<Self, String> {
        let addr = format!("0.0.0.0:{}", port);
        let socket = UdpSocket::bind(&addr)
            .await
            .map_err(|e| format!("Failed to bind S&B Kademlia socket on {}: {}", addr, e))?;

        let table = Arc::new(RwLock::new(KadRoutingTable::new(local_node_id)));
        let manager = Self {
            local_node_id,
            table,
            socket: Arc::new(socket),
        };

        // Start background receiver
        manager.start_receiver();

        Ok(manager)
    }

    fn start_receiver(&self) {
        let socket = self.socket.clone();
        let table = self.table.clone();
        let local_id = self.local_node_id;

        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                if let Ok((len, sender_addr)) = socket.recv_from(&mut buf).await {
                    if let Ok(msg) = KadMessage::deserialize(&buf[..len]) {
                        match msg {
                            KadMessage::Ping { sender_node_id } => {
                                let mut tbl = table.write().await;
                                tbl.add_contact(KadContact {
                                    node_id: sender_node_id,
                                    addr: sender_addr,
                                    last_seen: Utc::now(),
                                });
                                drop(tbl);

                                // Reply with Pong including sender's observed public IP
                                let pong = KadMessage::Pong {
                                    sender_node_id: local_id,
                                    observed_addr: sender_addr,
                                };
                                if let Ok(bytes) = pong.serialize() {
                                    let _ = socket.send_to(&bytes, sender_addr).await;
                                }
                            }
                            KadMessage::Pong { sender_node_id, .. } => {
                                let mut tbl = table.write().await;
                                tbl.add_contact(KadContact {
                                    node_id: sender_node_id,
                                    addr: sender_addr,
                                    last_seen: Utc::now(),
                                });
                            }
                            KadMessage::FindNode {
                                sender_node_id,
                                target_id,
                            } => {
                                let mut tbl = table.write().await;
                                tbl.add_contact(KadContact {
                                    node_id: sender_node_id,
                                    addr: sender_addr,
                                    last_seen: Utc::now(),
                                });
                                let closest = tbl.find_closest_nodes(&target_id, KAD_BUCKET_SIZE);
                                drop(tbl);

                                let reply = KadMessage::NodesFound { nodes: closest };
                                if let Ok(bytes) = reply.serialize() {
                                    let _ = socket.send_to(&bytes, sender_addr).await;
                                }
                            }
                            KadMessage::StoreRendezvous {
                                topic,
                                encrypted_beacon,
                                ttl_secs,
                            } => {
                                let mut tbl = table.write().await;
                                tbl.store_rendezvous(topic, encrypted_beacon, ttl_secs);
                            }
                            KadMessage::FindRendezvous { topic } => {
                                let mut tbl = table.write().await;
                                let beacons = tbl.find_rendezvous(&topic);
                                drop(tbl);

                                let reply = KadMessage::RendezvousFound { beacons };
                                if let Ok(bytes) = reply.serialize() {
                                    let _ = socket.send_to(&bytes, sender_addr).await;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
    }

    /// Performs Stateful UDP Hole Punching towards a remote peer's candidate endpoint
    pub async fn punch_hole(socket: &UdpSocket, target_endpoint: SocketAddr) -> Result<(), String> {
        let probe = b"SBM_NAT_HOLE_PUNCH_V1";
        for _ in 0..5 {
            let _ = socket.send_to(probe, target_endpoint).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kademlia_xor_distance() {
        let a = [0x00u8; 32];
        let b = [0xFFu8; 32];
        let dist = xor_distance(&a, &b);
        assert_eq!(dist, [0xFFu8; 32]);

        // Identity
        assert_eq!(xor_distance(&a, &a), [0x00u8; 32]);
    }

    #[test]
    fn test_sovereign_rendezvous_topic_derivation() {
        let alice_pk = [1u8; 32];
        let bob_pk = [2u8; 32];
        let epoch = 20260913;

        let topic1 = derive_rendezvous_topic(&alice_pk, &bob_pk, epoch);
        let topic2 = derive_rendezvous_topic(&bob_pk, &alice_pk, epoch);

        // Symmetric: regardless of parameter order, topic is identical
        assert_eq!(topic1, topic2);
        assert_eq!(topic1.len(), 32);

        // Different epoch yields different topic
        let topic_tomorrow = derive_rendezvous_topic(&alice_pk, &bob_pk, epoch + 1);
        assert_ne!(topic1, topic_tomorrow);
    }

    #[test]
    fn test_kademlia_packet_serialization() {
        let msg = KadMessage::Ping {
            sender_node_id: [42u8; 32],
        };
        let bytes = msg.serialize().expect("Serialization should work");
        assert_eq!(&bytes[0..4], &KAD_MAGIC);

        let decoded = KadMessage::deserialize(&bytes).expect("Deserialization should work");
        match decoded {
            KadMessage::Ping { sender_node_id } => assert_eq!(sender_node_id, [42u8; 32]),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_routing_table_rendezvous_store() {
        let local_id = [0u8; 32];
        let mut table = KadRoutingTable::new(local_id);

        let topic = [7u8; 32];
        let beacon = b"encrypted_endpoint_payload".to_vec();

        table.store_rendezvous(topic, beacon.clone(), 60);

        let found = table.find_rendezvous(&topic);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], beacon);
    }
}
