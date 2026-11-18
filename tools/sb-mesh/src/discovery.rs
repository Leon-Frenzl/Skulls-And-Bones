use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub const DISCOVERY_PORT: u16 = 58889;
pub const DISCOVERY_MAGIC: &[u8; 4] = b"SBMD";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub node_id: String,
    pub wireguard_pubkey: String,
    pub listen_port: u16,
    pub observed_addr: SocketAddr,
    pub last_seen: DateTime<Utc>,
}

pub struct DiscoveryManager {
    pub devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
}

impl DiscoveryManager {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Spawns background listener for local LAN broadcast packets
    pub fn start_listener(
        &self,
        local_node_id: String,
    ) -> Result<tokio::task::JoinHandle<()>, String> {
        let devices = self.devices.clone();

        let socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT))
            .map_err(|e| format!("Failed to bind discovery socket: {}", e))?;
        socket.set_broadcast(true).map_err(|e| e.to_string())?;
        socket.set_nonblocking(true).map_err(|e| e.to_string())?;

        let async_socket = UdpSocket::from_std(socket)
            .map_err(|e| format!("Failed to convert to async UDP socket: {}", e))?;

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((len, peer_addr)) = async_socket.recv_from(&mut buf).await {
                    if len > 8 && &buf[0..4] == DISCOVERY_MAGIC {
                        if let Ok(msg) = String::from_utf8(buf[4..len].to_vec()) {
                            let parts: Vec<&str> = msg.split('|').collect();
                            if parts.len() >= 3 {
                                let remote_node_id = parts[0].to_string();
                                let remote_pubkey = parts[1].to_string();
                                let remote_port: u16 = parts[2].parse().unwrap_or(58888);

                                // Don't add ourselves
                                if remote_node_id != local_node_id {
                                    let mut real_addr = peer_addr;
                                    real_addr.set_port(remote_port);

                                    let device = DiscoveredDevice {
                                        node_id: remote_node_id.clone(),
                                        wireguard_pubkey: remote_pubkey,
                                        listen_port: remote_port,
                                        observed_addr: real_addr,
                                        last_seen: Utc::now(),
                                    };
                                    let mut lock = devices.write().await;
                                    lock.insert(remote_node_id, device);
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Broadcast our own node information on the local subnet
    pub async fn broadcast_presence(
        node_id: &str,
        wireguard_pubkey: &str,
        listen_port: u16,
    ) -> Result<(), String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to bind broadcast socket: {}", e))?;
        socket.set_broadcast(true).map_err(|e| e.to_string())?;

        let mut packet = Vec::with_capacity(128);
        packet.extend_from_slice(DISCOVERY_MAGIC);
        let payload = format!("{}|{}|{}", node_id, wireguard_pubkey, listen_port);
        packet.extend_from_slice(payload.as_bytes());

        let target = format!("255.255.255.255:{}", DISCOVERY_PORT);
        socket
            .send_to(&packet, &target)
            .await
            .map_err(|e| format!("Broadcast send failed: {}", e))?;

        Ok(())
    }
}
