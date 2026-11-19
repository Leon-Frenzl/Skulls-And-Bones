use crate::peer::PeerTable;
use std::net::SocketAddr;

pub const RELAY_MAGIC: [u8; 4] = *b"SBMR";
pub const MAX_RELAY_HOPS: u8 = 8;

/// Zero-Knowledge Encrypted Multi-Hop Relay Packet
///
/// Transit nodes forward this packet without possessing the encryption keys of the inner payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPacket {
    pub target_node_id: String,
    pub source_node_id: String,
    pub hop_count: u8,
    pub inner_payload: Vec<u8>,
}

impl RelayPacket {
    pub fn new(target_node_id: &str, source_node_id: &str, payload: Vec<u8>) -> Self {
        Self {
            target_node_id: target_node_id.to_string(),
            source_node_id: source_node_id.to_string(),
            hop_count: 0,
            inner_payload: payload,
        }
    }

    /// Serializes the relay packet into wire format:
    /// [4 bytes: MAGIC] [1 byte: hop_count] [1 byte: target_len] [target_bytes] [1 byte: source_len] [source_bytes] [inner_payload]
    pub fn to_bytes(&self) -> Vec<u8> {
        let target_bytes = self.target_node_id.as_bytes();
        let source_bytes = self.source_node_id.as_bytes();

        let mut buf = Vec::with_capacity(
            7 + target_bytes.len() + source_bytes.len() + self.inner_payload.len(),
        );
        buf.extend_from_slice(&RELAY_MAGIC);
        buf.push(self.hop_count);

        buf.push(target_bytes.len() as u8);
        buf.extend_from_slice(target_bytes);

        buf.push(source_bytes.len() as u8);
        buf.extend_from_slice(source_bytes);

        buf.extend_from_slice(&self.inner_payload);
        buf
    }

    /// Deserializes raw wire buffer into a RelayPacket
    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 7 {
            return Err("Packet too short for relay header".to_string());
        }

        if raw[0..4] != RELAY_MAGIC {
            return Err("Invalid relay magic bytes".to_string());
        }

        let hop_count = raw[4];
        let target_len = raw[5] as usize;

        let mut offset = 6;
        if offset + target_len > raw.len() {
            return Err("Malformed relay packet: truncated target_node_id".to_string());
        }
        let target_node_id = String::from_utf8_lossy(&raw[offset..offset + target_len]).to_string();
        offset += target_len;

        if offset >= raw.len() {
            return Err("Malformed relay packet: missing source_node_id header".to_string());
        }
        let source_len = raw[offset] as usize;
        offset += 1;

        if offset + source_len > raw.len() {
            return Err("Malformed relay packet: truncated source_node_id".to_string());
        }
        let source_node_id = String::from_utf8_lossy(&raw[offset..offset + source_len]).to_string();
        offset += source_len;

        let inner_payload = raw[offset..].to_vec();

        Ok(Self {
            target_node_id,
            source_node_id,
            hop_count,
            inner_payload,
        })
    }
}

/// Routing decision resulting from processing a relay packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAction {
    /// Packet has reached its final destination node; unpack inner payload
    DeliverLocally(RelayPacket),
    /// Forward packet to next hop node endpoint
    Forward {
        next_hop: SocketAddr,
        packet: RelayPacket,
    },
    /// Drop packet (loop detected, max hops exceeded, or unknown target)
    Drop(String),
}

/// Zero-Knowledge Sovereign Relay Engine
pub struct RelayManager;

impl RelayManager {
    /// Evaluates an incoming relay packet using direct peers
    pub fn process_packet(
        packet: RelayPacket,
        local_node_id: &str,
        peer_table: &PeerTable,
    ) -> RelayAction {
        Self::process_packet_with_routing(packet, local_node_id, peer_table, None)
    }

    /// Evaluates an incoming relay packet using both direct peers and multi-hop routing table
    pub fn process_packet_with_routing(
        mut packet: RelayPacket,
        local_node_id: &str,
        peer_table: &PeerTable,
        routing_table: Option<&crate::routing::RoutingTable>,
    ) -> RelayAction {
        // 1. Loop protection / Max hops check
        if packet.hop_count >= MAX_RELAY_HOPS {
            return RelayAction::Drop(format!(
                "Max relay hops ({}) exceeded for source {}",
                MAX_RELAY_HOPS, packet.source_node_id
            ));
        }

        // 2. Deliver locally if target matches our node ID
        if packet.target_node_id.eq_ignore_ascii_case(local_node_id) {
            return RelayAction::DeliverLocally(packet);
        }

        // 3. Check direct peers first
        for peer in peer_table.list() {
            if peer
                .config
                .node_id
                .eq_ignore_ascii_case(&packet.target_node_id)
            {
                if let Some(endpoint) = peer.parsed_endpoint {
                    packet.hop_count += 1;
                    return RelayAction::Forward {
                        next_hop: endpoint,
                        packet,
                    };
                } else {
                    return RelayAction::Drop(format!(
                        "Target peer {} has no active endpoint",
                        packet.target_node_id
                    ));
                }
            }
        }

        // 4. Check multi-hop routing table if available
        if let Some(rt) = routing_table {
            if let Some(route) = rt.get_route(&packet.target_node_id) {
                packet.hop_count += 1;
                return RelayAction::Forward {
                    next_hop: route.next_hop_endpoint,
                    packet,
                };
            }
        }

        RelayAction::Drop(format!(
            "Target peer {} unknown in local peer table or routing table",
            packet.target_node_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{PeerConfig, PeerTable};
    use chrono::Utc;

    #[test]
    fn test_relay_packet_roundtrip() {
        let payload = b"INNER_CHACHA20_ENCRYPTED_WIREGUARD_DATA".to_vec();
        let original = RelayPacket::new("sbm-0x12d3ae3b", "sbm-0x88776655", payload);

        let bytes = original.to_bytes();
        assert_eq!(&bytes[0..4], &RELAY_MAGIC);

        let recovered = RelayPacket::from_bytes(&bytes).expect("Failed to parse relay packet");
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_relay_deliver_locally() {
        let payload = b"SECRET".to_vec();
        let packet = RelayPacket::new("sbm-0xlocalnode", "sbm-0xremote", payload);
        let table = PeerTable::new();

        let action = RelayManager::process_packet(packet.clone(), "sbm-0xlocalnode", &table);
        assert_eq!(action, RelayAction::DeliverLocally(packet));
    }

    #[test]
    fn test_relay_forwarding_to_peer() {
        let mut table = PeerTable::new();
        table.add_peer(PeerConfig {
            callsign: "remote-node".to_string(),
            node_id: "sbm-0xtarget99".to_string(),
            public_key_base64: "dGVzdF9rZXk=".to_string(),
            endpoint: Some("198.51.100.10:58888".to_string()),
            overlay_ip: None,
            created_at: Utc::now(),
        });

        let packet = RelayPacket::new("sbm-0xtarget99", "sbm-0xoriginator", b"HELLO".to_vec());

        let action = RelayManager::process_packet(packet, "sbm-0xrelaynode", &table);
        match action {
            RelayAction::Forward { next_hop, packet } => {
                assert_eq!(next_hop.to_string(), "198.51.100.10:58888");
                assert_eq!(packet.hop_count, 1);
                assert_eq!(packet.target_node_id, "sbm-0xtarget99");
            }
            other => panic!("Expected Forward action, got {:?}", other),
        }
    }

    #[test]
    fn test_relay_hop_limit_defense() {
        let mut packet = RelayPacket::new("sbm-0xtarget99", "sbm-0xoriginator", b"HELLO".to_vec());
        packet.hop_count = MAX_RELAY_HOPS; // Already at limit

        let table = PeerTable::new();
        let action = RelayManager::process_packet(packet, "sbm-0xrelaynode", &table);
        match action {
            RelayAction::Drop(msg) => {
                assert!(msg.contains("Max relay hops"));
            }
            other => panic!("Expected Drop action, got {:?}", other),
        }
    }

    #[test]
    fn test_relay_forwarding_via_routing_table() {
        use crate::routing::{RouteEntry, RoutingTable};
        let table = PeerTable::new();
        let mut routing_table = RoutingTable::new();
        let next_hop_ep: SocketAddr = "203.0.113.50:58888".parse().unwrap();

        routing_table.update_route(RouteEntry::new(
            "sbm-0xdistant_destination",
            "sbm-0xintermediate_hop",
            next_hop_ep,
            45,
            2,
            1,
        ));

        let packet = RelayPacket::new(
            "sbm-0xdistant_destination",
            "sbm-0xoriginator",
            b"HOP_DATA".to_vec(),
        );
        let action = RelayManager::process_packet_with_routing(
            packet,
            "sbm-0xlocal_relay",
            &table,
            Some(&routing_table),
        );

        match action {
            RelayAction::Forward { next_hop, packet } => {
                assert_eq!(next_hop, next_hop_ep);
                assert_eq!(packet.hop_count, 1);
                assert_eq!(packet.target_node_id, "sbm-0xdistant_destination");
            }
            other => panic!("Expected Forward via routing table, got {:?}", other),
        }
    }
}
