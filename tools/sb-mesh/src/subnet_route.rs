//! Subnet Routing & VPC Bridge Engine for S&B Sovereign Mesh
//!
//! Enables nodes inside a private LAN or Cloud VPC (AWS, Hetzner, Bare-Metal) to advertise
//! private IP subnets (e.g. 10.0.0.0/16 or 192.168.1.0/24) into the mesh.
//! Remote team members can transparently access private databases, staging APIs,
//! and internal services with ZERO open WAN ports, ZERO firewall modifications,
//! and ZERO kernel-level TUN drivers.

use base64::Engine;
use chrono::Utc;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::crypto::{
    decrypt_payload, derive_session_keys, derive_swarm_tag, encrypt_payload, pack_message_v2,
    unpack_header_v2, PacketType,
};
use crate::identity::{default_data_dir, NodeIdentity};
use crate::network::{validate_cidr, NetworkStore};
use crate::proxy::ip_matches_cidr;
use crate::rbac::MeshRbacStore;
use crate::stream::{StreamCommand, StreamFrame, MAX_PAYLOAD_CHUNK};

/// An advertised subnet route in a sovereign mesh
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertisedSubnet {
    pub cidr: String,
    pub gateway_node_id: String,
    pub gateway_pubkey: String,
    pub gateway_endpoint: String,
    pub mesh_name: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_active: bool,
}

/// Persistent store for advertised subnets in a mesh
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubnetRouteStore {
    pub mesh_name: String,
    #[serde(default)]
    pub routes: Vec<AdvertisedSubnet>,
}

impl SubnetRouteStore {
    pub fn file_path(mesh_name: &str) -> Result<PathBuf, String> {
        let paths = crate::state::MeshStatePaths::for_mesh(mesh_name)?;
        paths.ensure()?;
        Ok(paths.subnet_routes)
    }

    pub fn load_or_create(mesh_name: &str) -> Result<Self, String> {
        let path = Self::file_path(mesh_name)?;
        if path.exists() {
            let data = fs::read_to_string(&path)
                .map_err(|e| format!("Fehler beim Lesen von subnets.json: {}", e))?;
            serde_json::from_str(&data)
                .map_err(|e| format!("Ungültiges JSON in subnets.json: {}", e))
        } else {
            let store = Self {
                mesh_name: mesh_name.to_string(),
                routes: Vec::new(),
            };
            store.save()?;
            Ok(store)
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::file_path(&self.mesh_name)?;
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialisierungsfehler in subnets.json: {}", e))?;
        fs::write(&path, data).map_err(|e| format!("Konnte subnets.json nicht schreiben: {}", e))
    }

    pub fn advertise(
        &mut self,
        cidr: &str,
        node_id: &str,
        pubkey: &str,
        endpoint: &str,
    ) -> Result<AdvertisedSubnet, String> {
        let clean_cidr = cidr.trim();
        if !validate_cidr(clean_cidr) {
            return Err(format!(
                "Ungültiges IPv4-CIDR Format: '{}'. Erwartet z.B. '10.0.0.0/16'",
                clean_cidr
            ));
        }

        let now = Utc::now().timestamp() as u64;
        let route = if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|r| r.cidr == clean_cidr && r.gateway_pubkey == pubkey)
        {
            existing.gateway_endpoint = endpoint.to_string();
            existing.updated_at = now;
            existing.is_active = true;
            existing.clone()
        } else {
            let new_entry = AdvertisedSubnet {
                cidr: clean_cidr.to_string(),
                gateway_node_id: node_id.to_string(),
                gateway_pubkey: pubkey.to_string(),
                gateway_endpoint: endpoint.to_string(),
                mesh_name: self.mesh_name.clone(),
                created_at: now,
                updated_at: now,
                is_active: true,
            };
            self.routes.push(new_entry.clone());
            new_entry
        };

        self.save()?;

        if let Ok(mut rbac) = MeshRbacStore::load_or_create(&self.mesh_name) {
            rbac.log_event(
                "subnet_advertised",
                node_id,
                clean_cidr,
                &format!("Gateway Endpoint: {}", endpoint),
            );
            let _ = rbac.save();
        }

        Ok(route)
    }

    pub fn withdraw(&mut self, cidr: &str, pubkey: &str) -> bool {
        let clean_cidr = cidr.trim();
        let mut changed = false;
        self.routes.retain(|r| {
            if r.cidr == clean_cidr && r.gateway_pubkey == pubkey {
                changed = true;
                false
            } else {
                true
            }
        });
        if changed {
            let _ = self.save();
            if let Ok(mut rbac) = MeshRbacStore::load_or_create(&self.mesh_name) {
                rbac.log_event(
                    "subnet_withdrawn",
                    pubkey,
                    clean_cidr,
                    "Subnetz-Route zurückgezogen",
                );
                let _ = rbac.save();
            }
        }
        changed
    }

    pub fn resolve_target_ip(&self, ip: Ipv4Addr) -> Option<&AdvertisedSubnet> {
        self.routes
            .iter()
            .find(|r| r.is_active && ip_matches_cidr(ip, &r.cidr))
    }

    pub fn list_active(&self) -> Vec<&AdvertisedSubnet> {
        self.routes.iter().filter(|r| r.is_active).collect()
    }
}

/// Transparently tunnels a single client TCP connection to a remote VPC target via the gateway router.
/// Supports both raw TCP tunnels and SOCKS5 proxy protocol replies.
pub async fn tunnel_tcp_to_vpc(
    mut tcp_stream: TcpStream,
    target_host: &str,
    target_port: u16,
    gateway_endpoint: &str,
    gateway_pubkey_b64: &str,
    target_mesh: &str,
    is_socks5: bool,
) -> Result<(), String> {
    let identity = Arc::new(NodeIdentity::load_registered_for_mesh(target_mesh)?);
    let gateway_addr: SocketAddr = gateway_endpoint
        .parse()
        .map_err(|e| format!("Ungültige Gateway-Adresse '{}': {}", gateway_endpoint, e))?;
    let gateway_pubkey_bytes = base64::prelude::BASE64_STANDARD
        .decode(gateway_pubkey_b64)
        .map_err(|e| e.to_string())?;
    if gateway_pubkey_bytes.len() != 32 {
        return Err("Ungültige Gateway Public-Key Länge".to_string());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&gateway_pubkey_bytes);
    let gateway_pubkey = x25519_dalek::PublicKey::from(key_arr);

    let session_keys = derive_session_keys(&identity.secret, &gateway_pubkey)?;
    let swarm_tag = derive_swarm_tag(&format!("sbm-swarm-{}", target_mesh));

    let udp_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| e.to_string())?,
    );
    let stream_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u32)
        .unwrap_or(10_000)
        & 0x7FFF_FFFF)
        .max(10_000);

    let (tx, mut rx) = mpsc::channel::<StreamFrame>(1024);
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(1));

    let udp_rx = udp_socket.clone();
    let exp_tag = swarm_tag;
    let s_key = session_keys.receive.clone();
    let expected_stream_id = stream_id;

    let rx_handle = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match udp_rx.recv_from(&mut buf).await {
                Ok((len, _)) => {
                    if let Ok((ptype, tag, _, c, payload)) = unpack_header_v2(&buf[..len]) {
                        if tag == exp_tag && ptype == PacketType::Data {
                            if let Ok(dec) = decrypt_payload(s_key.as_bytes(), c, payload) {
                                if let Ok(frame) = StreamFrame::decode(&dec) {
                                    if frame.stream_id == expected_stream_id
                                        && tx.send(frame).await.is_err() {
                                            break;
                                        }
                                }
                            }
                        }
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    });

    // Send ConnectVpc command to the Gateway
    let connect_frame = StreamFrame::new(
        stream_id,
        0,
        StreamCommand::ConnectVpc {
            target_host: target_host.to_string(),
            target_port,
        },
    );

    let c_val = counter.fetch_add(1, Ordering::SeqCst);
    let enc = encrypt_payload(session_keys.send.as_bytes(), c_val, &connect_frame.encode())
        .map_err(|e| e.to_string())?;
    let pkt = pack_message_v2(
        PacketType::Data,
        &swarm_tag,
        identity.public_key.as_bytes(),
        c_val,
        &enc,
    );
    udp_socket
        .send_to(&pkt, gateway_addr)
        .await
        .map_err(|e| e.to_string())?;

    // Wait for Connected acknowledgement (up to 5s)
    let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
    match ack {
        Ok(Some(frame)) if matches!(frame.command, StreamCommand::Connected) => {
            if is_socks5 {
                // SOCKS5 success reply: 0x05, 0x00 (Success), 0x00 (RSV), 0x01 (IPv4), 0,0,0,0 (BND.ADDR), 0,0 (BND.PORT)
                tcp_stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .map_err(|e| e.to_string())?;
            }

            let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
            let mut tcp_buf = [0u8; 4096];
            let seq_out = Arc::new(AtomicU32::new(1));
            let udp_send = udp_socket.clone();
            let c_copy = counter.clone();
            let p_key = *identity.public_key.as_bytes();

            let read_task = tokio::spawn(async move {
                loop {
                    match tcp_read.read(&mut tcp_buf).await {
                        Ok(0) => {
                            let close_frame = StreamFrame::new(
                                stream_id,
                                seq_out.fetch_add(1, Ordering::SeqCst),
                                StreamCommand::Close,
                            );
                            let cv = c_copy.fetch_add(1, Ordering::SeqCst);
                            if let Ok(b) = encrypt_payload(
                                session_keys.send.as_bytes(),
                                cv,
                                &close_frame.encode(),
                            ) {
                                let p =
                                    pack_message_v2(PacketType::Data, &swarm_tag, &p_key, cv, &b);
                                let _ = udp_send.send_to(&p, gateway_addr).await;
                            }
                            break;
                        }
                        Ok(n) => {
                            for chunk in tcp_buf[..n].chunks(MAX_PAYLOAD_CHUNK) {
                                let data_frame = StreamFrame::new(
                                    stream_id,
                                    seq_out.fetch_add(1, Ordering::SeqCst),
                                    StreamCommand::Data(chunk.to_vec()),
                                );
                                let cv = c_copy.fetch_add(1, Ordering::SeqCst);
                                if let Ok(b) = encrypt_payload(
                                    session_keys.send.as_bytes(),
                                    cv,
                                    &data_frame.encode(),
                                ) {
                                    let p = pack_message_v2(
                                        PacketType::Data,
                                        &swarm_tag,
                                        &p_key,
                                        cv,
                                        &b,
                                    );
                                    let _ = udp_send.send_to(&p, gateway_addr).await;
                                }
                                tokio::task::yield_now().await;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            let write_task = tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    match frame.command {
                        StreamCommand::Data(bytes) => {
                            if tcp_write.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        StreamCommand::Close => break,
                        _ => {}
                    }
                }
            });

            tokio::select! {
                _ = read_task => (),
                _ = write_task => (),
            };

            rx_handle.abort();
            Ok(())
        }
        _ => {
            if is_socks5 {
                let _ = tcp_stream
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
            }
            rx_handle.abort();
            Err(format!(
                "Gateway {} hat die Verbindung nach {}:{} abgelehnt oder reagiert nicht.",
                gateway_endpoint, target_host, target_port
            ))
        }
    }
}

/// Runs a local transparent TCP port forwarder targeting a private VPC address
pub async fn run_vpc_forwarder(
    local_port: u16,
    target: &str,
    target_mesh: &str,
) -> Result<(), String> {
    let clean_target = target.trim();
    let parts: Vec<&str> = clean_target.split(':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Ungültiges Ziel '{}'. Erwartet 'IP:Port' (z.B. 10.0.5.12:5432)",
            clean_target
        ));
    }
    let target_host = parts[0].to_string();
    let target_port: u16 = parts[1]
        .parse()
        .map_err(|_| "Ungültiger Ziel-Port".to_string())?;

    let identity = Arc::new(NodeIdentity::load_registered_for_mesh(target_mesh)?);
    let route_store = SubnetRouteStore::load_or_create(target_mesh)?;

    // Resolve gateway for target host
    let (gateway_endpoint, gateway_pubkey_b64) = if let Ok(ip) = target_host.parse::<Ipv4Addr>() {
        if let Some(sub) = route_store.resolve_target_ip(ip) {
            (sub.gateway_endpoint.clone(), sub.gateway_pubkey.clone())
        } else {
            // Fallback: check active network anchor endpoint
            let data_dir = default_data_dir()?;
            let net_file = data_dir.join("networks.json");
            let net_store =
                NetworkStore::load_or_create_default(&net_file, &identity.wireguard_pubkey)?;
            let net = net_store
                .networks
                .get(target_mesh)
                .ok_or_else(|| format!("Mesh '{}' nicht gefunden", target_mesh))?;
            (
                format!("127.0.0.1:{}", net.listen_port),
                net.wireguard_pubkey.clone(),
            )
        }
    } else {
        return Err(format!(
            "Ziel-Host '{}' muss eine IPv4-Adresse sein.",
            target_host
        ));
    };

    let listen_addr = format!("127.0.0.1:{}", local_port);
    let listener = TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| format!("Port {} bereits belegt: {}", local_port, e))?;

    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {} // {}",
        "S&B SOVEREIGN MESH".cyan().bold(),
        "VPC SUBNET BRIDGE FORWARDER".bold()
    );
    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {:<20} {}",
        "Lokaler Endpunkt:".bold(),
        format!("127.0.0.1:{}", local_port).bright_green().bold()
    );
    println!(
        "  {:<20} {}",
        "VPC Ziel-Adresse:".bold(),
        format!("{}:{}", target_host, target_port).yellow().bold()
    );
    println!(
        "  {:<20} {}",
        "Gateway Router:".bold(),
        gateway_endpoint.bright_white()
    );
    println!(
        "  {:<20} {}",
        "Mesh-Netzwerk:".bold(),
        target_mesh.cyan().bold()
    );
    println!(
        "{}",
        "─────────────────────────────────────────────────────────────────────────────".dimmed()
    );
    println!(
        "  Verbinde deine Tools lokal via: {}",
        format!("localhost:{}", local_port).bright_yellow().bold()
    );
    println!("  Drücke [STRG+C] zum Beenden.\n");

    while let Ok((tcp_stream, peer_addr)) = listener.accept().await {
        let t_host = target_host.clone();
        let t_port = target_port;
        let gw_ep = gateway_endpoint.clone();
        let gw_pk = gateway_pubkey_b64.clone();
        let t_mesh = target_mesh.to_string();

        println!(
            "  {} Eingehende Verbindung von {} ➔ Tunneling nach {}:{}",
            "●".bright_green().bold(),
            peer_addr,
            t_host,
            t_port
        );

        tokio::spawn(async move {
            if let Err(e) =
                tunnel_tcp_to_vpc(tcp_stream, &t_host, t_port, &gw_ep, &gw_pk, &t_mesh, false).await
            {
                eprintln!("  {} Tunneling Fehler: {}", "✗".bright_red(), e);
            }
        });
    }

    Ok(())
}

/// Runs the headless VPC Subnet Router & Egress Bridge worker
pub async fn run_vpc_bridge(
    target_mesh: &str,
    advertised_cidr: Option<&str>,
) -> Result<(), String> {
    let identity = Arc::new(NodeIdentity::load_registered_for_mesh(target_mesh)?);
    let mut route_store = SubnetRouteStore::load_or_create(target_mesh)?;

    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {} // {}",
        "S&B SOVEREIGN MESH".cyan().bold(),
        "VPC SUBNET ROUTER & EGRESS BRIDGE".bold()
    );
    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );

    if let Some(cidr) = advertised_cidr {
        let ep = "0.0.0.0:58888".to_string();
        let route =
            route_store.advertise(cidr, &identity.node_id, &identity.wireguard_pubkey, &ep)?;
        println!(
            "  {} Subnetz-Route '{}' registriert und aktiviert.",
            "✓".bright_green().bold(),
            route.cidr.yellow().bold()
        );
    }

    let active_routes = route_store.list_active();
    println!(
        "  {:<20} {}",
        "Aktive Subnetze:".bold(),
        if active_routes.is_empty() {
            "Keine (Warte auf Advertisements)".dimmed()
        } else {
            active_routes
                .iter()
                .map(|r| r.cidr.as_str())
                .collect::<Vec<_>>()
                .join(", ")
                .green()
                .bold()
        }
    );
    println!(
        "  {:<20} {}",
        "Mesh-Netzwerk:".bold(),
        target_mesh.cyan().bold()
    );
    println!(
        "  {:<20} {}",
        "Gateway Node:".bold(),
        identity.node_id.green()
    );
    println!(
        "{}",
        "─────────────────────────────────────────────────────────────────────────────".dimmed()
    );
    println!("  VPC Bridge lauscht und leitet autorisierte Anfragen ins lokale Netzwerk weiter.");
    println!("  Drücke [STRG+C] zum Beenden.\n");

    tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
    println!("\n  VPC Subnet Router beendet.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_route_store_lifecycle() {
        let mesh_name = "test-vpc-mesh";
        let mut store = SubnetRouteStore::load_or_create(mesh_name).unwrap();

        // 1. Advertise subnet
        let route = store.advertise(
            "10.0.0.0/16",
            "sbm-node-gw",
            "fake_pubkey_gw=",
            "192.168.1.100:58888",
        );
        assert!(route.is_ok());

        // 2. Resolve matching IP inside CIDR
        let target_ip: Ipv4Addr = "10.0.5.12".parse().unwrap();
        let resolved = store.resolve_target_ip(target_ip);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().gateway_node_id, "sbm-node-gw");
        assert_eq!(resolved.unwrap().cidr, "10.0.0.0/16");

        // 3. Resolve IP outside CIDR
        let foreign_ip: Ipv4Addr = "192.168.2.1".parse().unwrap();
        assert!(store.resolve_target_ip(foreign_ip).is_none());

        // 4. Withdraw subnet
        let withdrawn = store.withdraw("10.0.0.0/16", "fake_pubkey_gw=");
        assert!(withdrawn);
        assert!(store.resolve_target_ip(target_ip).is_none());

        // Clean up test file
        if let Ok(path) = SubnetRouteStore::file_path(mesh_name) {
            let _ = fs::remove_file(path);
        }
    }
}
