use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

pub const MAX_ROUTE_HOPS: u8 = 8;
pub const ROUTE_EXPIRATION_SECS: i64 = 180;

/// Autonomous Distance-Vector / Babel-style Metric Routing Entry
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination_node_id: String,
    pub next_hop_node_id: String,
    pub next_hop_endpoint: SocketAddr,
    pub metric: u32,
    pub hop_count: u8,
    pub seq_no: u64,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl RouteEntry {
    pub fn new(
        destination_node_id: &str,
        next_hop_node_id: &str,
        next_hop_endpoint: SocketAddr,
        metric: u32,
        hop_count: u8,
        seq_no: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            destination_node_id: destination_node_id.to_string(),
            next_hop_node_id: next_hop_node_id.to_string(),
            next_hop_endpoint,
            metric,
            hop_count,
            seq_no,
            updated_at: now,
            expires_at: now + Duration::seconds(ROUTE_EXPIRATION_SECS),
        }
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Compact wire advertisement exchanged between mesh peers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAdvertisement {
    pub destination_node_id: String,
    pub metric: u32,
    pub hop_count: u8,
    pub seq_no: u64,
}

/// Autonomous Multi-Hop Routing Table
#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    pub routes: HashMap<String, RouteEntry>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Calculates link metric: RouteCost = hop_rtt_ms + (hop_count * 20) + loss_penalty
    pub fn calculate_metric(hop_rtt_ms: f64, hop_count: u8, packet_loss_ratio: f64) -> u32 {
        let rtt_cost = hop_rtt_ms.round() as u32;
        let hop_cost = (hop_count as u32) * 20;
        let loss_cost = (packet_loss_ratio * 1000.0).round() as u32;
        rtt_cost + hop_cost + loss_cost
    }

    /// Register or refresh a direct neighbor as a 1-hop route
    pub fn add_direct_peer(
        &mut self,
        node_id: &str,
        endpoint: SocketAddr,
        rtt_ms: f64,
        seq_no: u64,
    ) {
        let metric = Self::calculate_metric(rtt_ms, 1, 0.0);
        let entry = RouteEntry::new(node_id, node_id, endpoint, metric, 1, seq_no);
        self.routes.insert(node_id.to_string(), entry);
    }

    /// Inserts or updates a multi-hop route if newer sequence number or better metric
    pub fn update_route(&mut self, entry: RouteEntry) -> bool {
        if entry.hop_count > MAX_ROUTE_HOPS {
            return false;
        }

        if let Some(existing) = self.routes.get_mut(&entry.destination_node_id) {
            // Feasibility Condition / Loop-defense:
            // 1. Strictly newer sequence number -> accept
            // 2. Same sequence number and strictly lower metric -> accept
            let should_update = entry.seq_no > existing.seq_no
                || (entry.seq_no == existing.seq_no && entry.metric < existing.metric);

            if should_update {
                *existing = entry;
                true
            } else {
                false
            }
        } else {
            self.routes.insert(entry.destination_node_id.clone(), entry);
            true
        }
    }

    /// Finds best next hop route to target node
    pub fn get_route(&self, destination_node_id: &str) -> Option<&RouteEntry> {
        self.routes.get(destination_node_id)
    }

    /// Removes a route when a link is broken
    pub fn remove_route(&mut self, destination_node_id: &str) -> Option<RouteEntry> {
        self.routes.remove(destination_node_id)
    }

    /// Prunes expired routes
    pub fn prune_expired(&mut self) -> usize {
        let now = Utc::now();
        let initial_len = self.routes.len();
        self.routes.retain(|_, route| !route.is_expired(now));
        initial_len - self.routes.len()
    }

    /// Processes an incoming route advertisement from an immediate neighbor
    pub fn process_advertisement(
        &mut self,
        sender_node_id: &str,
        sender_endpoint: SocketAddr,
        sender_rtt_ms: f64,
        adv: &RouteAdvertisement,
    ) -> bool {
        // Drop advertisements exceeding max hop limits
        if adv.hop_count >= MAX_ROUTE_HOPS {
            return false;
        }

        let link_cost = Self::calculate_metric(sender_rtt_ms, 1, 0.0);
        let total_metric = adv.metric + link_cost;
        let total_hops = adv.hop_count + 1;

        let entry = RouteEntry::new(
            &adv.destination_node_id,
            sender_node_id,
            sender_endpoint,
            total_metric,
            total_hops,
            adv.seq_no,
        );

        self.update_route(entry)
    }

    /// Exports routes as Distance-Vector advertisements for neighbor gossip
    pub fn export_advertisements(&self) -> Vec<RouteAdvertisement> {
        self.routes
            .values()
            .map(|r| RouteAdvertisement {
                destination_node_id: r.destination_node_id.clone(),
                metric: r.metric,
                hop_count: r.hop_count,
                seq_no: r.seq_no,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_table_metric_and_convergence() {
        let mut table = RoutingTable::new();
        let ep_b: SocketAddr = "192.168.1.10:58888".parse().unwrap();

        // 1. Direct peer B
        table.add_direct_peer("node-b", ep_b, 15.0, 1);
        assert!(table.get_route("node-b").is_some());
        assert_eq!(table.get_route("node-b").unwrap().hop_count, 1);

        // 2. Peer B advertises Node C (2 hops)
        let adv_c = RouteAdvertisement {
            destination_node_id: "node-c".to_string(),
            metric: 35,
            hop_count: 1,
            seq_no: 1,
        };
        let updated = table.process_advertisement("node-b", ep_b, 15.0, &adv_c);
        assert!(updated);

        let route_c = table.get_route("node-c").unwrap();
        assert_eq!(route_c.next_hop_node_id, "node-b");
        assert_eq!(route_c.next_hop_endpoint, ep_b);
        assert_eq!(route_c.hop_count, 2);

        // 3. Reject route advertisement exceeding MAX_ROUTE_HOPS
        let adv_too_far = RouteAdvertisement {
            destination_node_id: "node-z".to_string(),
            metric: 100,
            hop_count: MAX_ROUTE_HOPS,
            seq_no: 1,
        };
        assert!(!table.process_advertisement("node-b", ep_b, 15.0, &adv_too_far));
    }
}
