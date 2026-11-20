use crate::crypto::{
    decrypt_payload, derive_session_keys, encrypt_payload, pack_message, ratchet_session_keys,
    unpack_header, PacketType,
};
use crate::identity::NodeIdentity;
use crate::peer::{PathType, PeerStatus, PeerTable};
use base64::prelude::*;
use chrono::Utc;
use colored::Colorize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct MeshTransport {
    mesh_id: String,
    rbac_path: std::path::PathBuf,
    pub identity: Arc<NodeIdentity>,
    pub peer_table: Arc<RwLock<PeerTable>>,
    pub socket: Arc<UdpSocket>,
    pub air_gap: Arc<RwLock<bool>>,
    pub routing_table: Arc<RwLock<crate::routing::RoutingTable>>,
    pub gossip_engine: Arc<RwLock<crate::gossip::GossipEngine>>,
}

impl MeshTransport {
    pub fn mesh_id(&self) -> &str {
        &self.mesh_id
    }

    pub async fn bind(
        mesh_id: &str,
        listen_port: u16,
        identity: Arc<NodeIdentity>,
        peer_table: Arc<RwLock<PeerTable>>,
        air_gap: Arc<RwLock<bool>>,
    ) -> Result<Arc<Self>, String> {
        let mesh_id = crate::state::normalize_mesh_name(mesh_id)?.to_string();
        let rbac_path = crate::state::MeshStatePaths::for_mesh(&mesh_id)?.rbac;
        Self::bind_with_rbac_path(
            &mesh_id,
            listen_port,
            identity,
            peer_table,
            air_gap,
            rbac_path,
        )
        .await
    }

    async fn bind_with_rbac_path(
        mesh_id: &str,
        listen_port: u16,
        identity: Arc<NodeIdentity>,
        peer_table: Arc<RwLock<PeerTable>>,
        air_gap: Arc<RwLock<bool>>,
        rbac_path: std::path::PathBuf,
    ) -> Result<Arc<Self>, String> {
        let mesh_id = crate::state::normalize_mesh_name(mesh_id)?.to_string();
        let addr = format!("0.0.0.0:{}", listen_port);
        let socket = match UdpSocket::bind(&addr).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                return Err(format!(
                    "Port {} ist bereits belegt! Vermutlich laeuft bereits ein Sovereign Mesh Hintergrund-Daemon (sb-mesh/sb-ports). Beenden mit: 'sb-ports kill {}' oder Status pruefen mit 'sb mesh status'. (Detail: {})",
                    listen_port, listen_port, e
                ));
            }
            Err(e) => {
                return Err(format!(
                    "Failed to bind UDP transport socket on {}: {}",
                    addr, e
                ));
            }
        };

        let transport = Arc::new(Self {
            mesh_id,
            rbac_path,
            identity,
            peer_table,
            socket: Arc::new(socket),
            air_gap,
            routing_table: Arc::new(RwLock::new(crate::routing::RoutingTable::new())),
            gossip_engine: Arc::new(RwLock::new(crate::gossip::GossipEngine::new())),
        });

        // Start background packet receiver loop
        let recv_transport = transport.clone();
        tokio::spawn(async move {
            recv_transport.run_receiver().await;
        });

        Ok(transport)
    }

    /// Authorize an object operation only for a peer whose transport handshake has completed.
    /// The public key must come from the authenticated packet header, never request parameters.
    // CVE-Threat: Spoofed peer identities or reusing authorization across mesh boundaries.
    // Analysis: Request parameters and a connected peer from another mesh are insufficient identity proof.
    // Hardening: Require a canonical registered key in the connected peer table and the exact catalog mesh.
    pub async fn check_object_access(
        &self,
        peer_public_key_base64: &str,
        catalog: &crate::objects::MeshObjectCatalog,
        object_id: &crate::objects::MeshObjectId,
        required: &std::collections::BTreeSet<crate::objects::ObjectPermission>,
    ) -> Result<bool, String> {
        if catalog.mesh_id != self.mesh_id {
            return Err("Object catalog belongs to a different mesh transport".to_string());
        }
        let authenticated_public_key = {
            let peer_table = self.peer_table.read().await;
            authenticated_peer_key_for_object_access(&peer_table, peer_public_key_base64)?
        };
        let rbac = crate::rbac::MeshRbacStore::load_existing_at(&self.rbac_path, &self.mesh_id)?;
        let now = crate::runtime_status::MeshRuntimeStatus::now_unix()?;
        if !rbac.has_active_member_for_key(&self.mesh_id, &authenticated_public_key, now)? {
            return Err("Peer is not an active member of this mesh".to_string());
        }
        let context = catalog.access_context_for_authenticated_device(&authenticated_public_key)?;
        catalog.check_access(object_id, &context, required)
    }

    /// Primary incoming packet handler
    async fn run_receiver(&self) {
        let mut buf = [0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, sender_addr)) => {
                    // Check air-gap killswitch
                    if *self.air_gap.read().await {
                        continue; // Drop everything silently when air-gap is active
                    }

                    // Zero-Knowledge Multi-Hop Relay & Autonomous Routing Interceptor
                    if len >= 7 && buf[..4] == crate::relay::RELAY_MAGIC {
                        if let Ok(relay_pkt) = crate::relay::RelayPacket::from_bytes(&buf[..len]) {
                            let p_table = self.peer_table.read().await;
                            let r_table = self.routing_table.read().await;
                            let action = crate::relay::RelayManager::process_packet_with_routing(
                                relay_pkt,
                                &self.identity.node_id,
                                &p_table,
                                Some(&*r_table),
                            );
                            drop(p_table);
                            drop(r_table);

                            match action {
                                crate::relay::RelayAction::Forward { next_hop, packet } => {
                                    let bytes = packet.to_bytes();
                                    let _ = self.socket.send_to(&bytes, next_hop).await;
                                }
                                crate::relay::RelayAction::DeliverLocally(_pkt) => {}
                                crate::relay::RelayAction::Drop(_) => {}
                            }
                            continue;
                        }
                    }

                    // V2 Multi-Tenant & SBM-TEP Ticket Knocks Interceptor (SBM2)
                    if len >= 53 && buf[..4] == crate::crypto::PACKET_MAGIC_V2 {
                        let packet_data = &buf[..len];
                        if let Ok((ptype, _swarm_tag, sender_pubkey_bytes, _counter, _payload)) =
                            crate::crypto::unpack_header_v2(packet_data)
                        {
                            if ptype == crate::crypto::PacketType::TicketReq {
                                let auth_store =
                                    match crate::ticket::AuthorizedIdentitiesStore::load_or_create(
                                        &crate::ticket::AuthorizedIdentitiesStore::default_path(),
                                    ) {
                                        Ok(store) => store,
                                        Err(error) => {
                                            sb_core::logfmt::warn(
                                                "ERR_TICKET_AUTH_STATE",
                                                "mesh.transport",
                                                "Ticket authorization state unavailable",
                                                &[("error", &error.to_string())],
                                            );
                                            continue;
                                        }
                                    };

                                let data_dir = match crate::identity::default_data_dir() {
                                    Ok(path) => path,
                                    Err(error) => {
                                        sb_core::logfmt::warn(
                                            "ERR_MESH_STATE_DIR",
                                            "mesh.transport",
                                            "Mesh state directory unavailable",
                                            &[("error", &error.to_string())],
                                        );
                                        continue;
                                    }
                                };
                                let networks_file = data_dir.join("networks.json");
                                let networks_store =
                                    match crate::network::NetworkStore::load_or_create_default(
                                        &networks_file,
                                        &self.identity.wireguard_pubkey,
                                    ) {
                                        Ok(store) => store,
                                        Err(error) => {
                                            sb_core::logfmt::warn(
                                                "ERR_MESH_CATALOG",
                                                "mesh.transport",
                                                "Mesh catalog unavailable",
                                                &[("error", &error.to_string())],
                                            );
                                            continue;
                                        }
                                    };
                                match crate::ticket::process_ticket_request(
                                    packet_data,
                                    &self.identity,
                                    &auth_store,
                                    &networks_store,
                                ) {
                                    Ok(Some((grant_pkt, grant))) => {
                                        let _ = self.socket.send_to(&grant_pkt, sender_addr).await;

                                        let sender_pubkey_b64 =
                                            BASE64_STANDARD.encode(sender_pubkey_bytes);
                                        let mut peer_table = self.peer_table.write().await;
                                        mark_ticket_recipient(
                                            &mut peer_table,
                                            &sender_pubkey_b64,
                                            sender_addr,
                                        );

                                        println!(
                                            "  {} [ANCHOR] TicketGrant für Mesh '{}' an Rolle '{}' ({}) via {}",
                                            "●".bright_green().bold(),
                                            grant.granted_mesh.bright_cyan(),
                                            grant.role.yellow(),
                                            sender_addr.to_string().bright_white(),
                                            &sender_pubkey_b64[..12.min(sender_pubkey_b64.len())]
                                        );
                                    }

                                    Ok(None) => {}
                                    Err(error) => {
                                        sb_core::logfmt::warn(
                                            "ERR_TICKET_PROCESS",
                                            "mesh.transport",
                                            "Ticket request processing failed",
                                            &[("error", &error.to_string())],
                                        );
                                    }
                                }
                                continue;
                            }
                        }
                    }

                    if len < 45 {
                        continue;
                    }

                    let packet_data = &buf[..len];
                    if let Ok((ptype, sender_pubkey_bytes, counter, payload)) =
                        unpack_header(packet_data)
                    {
                        let sender_pubkey_b64 = BASE64_STANDARD.encode(sender_pubkey_bytes);

                        // Check CRL revocation list from gossip engine
                        if self
                            .gossip_engine
                            .read()
                            .await
                            .is_revoked(&sender_pubkey_b64)
                        {
                            continue; // Silently drop packets from revoked keys
                        }

                        let remote_public = PublicKey::from(sender_pubkey_bytes);

                        let mut table = self.peer_table.write().await;
                        if let Some(peer) = table.get_mut_by_pubkey(&sender_pubkey_b64) {
                            let session_keys = if let Some(ref keys) = peer.session_keys {
                                keys.clone()
                            } else {
                                match derive_session_keys(&self.identity.secret, &remote_public) {
                                    Ok(keys) => keys,
                                    Err(_) => continue,
                                }
                            };

                            if matches!(ptype, PacketType::TicketReq | PacketType::TicketGrant) {
                                continue;
                            }
                            let decrypted = match decrypt_payload(
                                session_keys.receive.as_bytes(),
                                counter,
                                payload,
                            ) {
                                Ok(plaintext) => plaintext,
                                Err(_) => continue,
                            };

                            // CVE-Threat: Spoofed packets could otherwise alter peer roaming state.
                            // Analysis: Packet source addresses are untrusted until AEAD validation succeeds.
                            // Hardening: Endpoint, replay and activity state changes happen after authentication.
                            // Anti-replay check: drop packet if sequence counter is invalid / already seen
                            // For HandshakeInit, we do not reject ahead of time because a peer restart
                            // could reset their sequence, but we verify its cryptographic MAC before resetting filter.
                            if ptype != PacketType::HandshakeInit
                                && !peer.anti_replay.check(counter)
                            {
                                continue;
                            }

                            peer.bytes_recv += len as u64;
                            if peer.parsed_endpoint != Some(sender_addr) {
                                peer.parsed_endpoint = Some(sender_addr);
                                peer.roaming_events += 1;
                            }
                            let current_path = if sender_addr.is_ipv6() {
                                PathType::DirectIPv6(sender_addr)
                            } else {
                                PathType::DirectIPv4(sender_addr)
                            };
                            peer.add_or_update_path(current_path.clone());

                            match ptype {
                                PacketType::HandshakeInit => {
                                    if decrypted == b"SBM_HANDSHAKE_INIT" {
                                        peer.anti_replay.reset();
                                        peer.anti_replay.update(counter);
                                        peer.status = PeerStatus::HandshakeInProgress;
                                        peer.last_handshake = Some(Utc::now());

                                        // Answer with HandshakeResp
                                        let resp_counter = peer.sequence_counter + 1;
                                        peer.sequence_counter = resp_counter;
                                        if let Ok(enc_payload) = encrypt_payload(
                                            session_keys.send.as_bytes(),
                                            resp_counter,
                                            b"SBM_HS_OK",
                                        ) {
                                            let reply = pack_message(
                                                PacketType::HandshakeResp,
                                                self.identity.public_key.as_bytes(),
                                                resp_counter,
                                                &enc_payload,
                                            );
                                            let _ = self.socket.send_to(&reply, sender_addr).await;
                                            peer.bytes_sent += reply.len() as u64;
                                            peer.status = PeerStatus::Connected;
                                        }
                                    }
                                }
                                PacketType::HandshakeResp => {
                                    if decrypted == b"SBM_HS_OK" {
                                        peer.anti_replay.update(counter);
                                        peer.status = PeerStatus::Connected;
                                        peer.last_handshake = Some(Utc::now());
                                    }
                                }
                                PacketType::Ping => {
                                    if decrypted == b"PING" {
                                        peer.anti_replay.update(counter);
                                        let resp_counter = peer.sequence_counter + 1;
                                        peer.sequence_counter = resp_counter;
                                        if let Ok(enc) = encrypt_payload(
                                            session_keys.send.as_bytes(),
                                            resp_counter,
                                            b"PONG",
                                        ) {
                                            let pong = pack_message(
                                                PacketType::Pong,
                                                self.identity.public_key.as_bytes(),
                                                resp_counter,
                                                &enc,
                                            );
                                            let _ = self.socket.send_to(&pong, sender_addr).await;
                                            peer.bytes_sent += pong.len() as u64;
                                        }
                                    }
                                }
                                PacketType::Pong => {
                                    if decrypted == b"PONG" {
                                        peer.anti_replay.update(counter);
                                        if let Some(sent_time) = peer.last_ping_sent {
                                            let rtt = (Utc::now() - sent_time)
                                                .num_microseconds()
                                                .unwrap_or(0)
                                                as f64
                                                / 1000.0;
                                            let rtt_val = rtt.max(0.1);
                                            peer.rtt_ms = Some(rtt_val);
                                            peer.record_path_success(&current_path, rtt_val);
                                            peer.status = PeerStatus::Connected;
                                        }
                                    }
                                }
                                PacketType::RekeyInit => {
                                    if decrypted.len() == 32 {
                                        peer.anti_replay.update(counter);
                                        let mut initiator_eph_pub_bytes = [0u8; 32];
                                        initiator_eph_pub_bytes.copy_from_slice(&decrypted);
                                        let initiator_eph_pub =
                                            PublicKey::from(initiator_eph_pub_bytes);

                                        let resp_eph_secret =
                                            StaticSecret::random_from_rng(rand::rngs::OsRng);
                                        let resp_eph_pub = PublicKey::from(&resp_eph_secret);
                                        let eph_shared =
                                            resp_eph_secret.diffie_hellman(&initiator_eph_pub);

                                        let next_epoch = peer.session_epoch + 1;
                                        if eph_shared.as_bytes().iter().all(|byte| *byte == 0) {
                                            continue;
                                        }
                                        let next_keys = ratchet_session_keys(
                                            &session_keys,
                                            eph_shared.as_bytes(),
                                            next_epoch,
                                        );

                                        let resp_counter = peer.sequence_counter + 1;
                                        peer.sequence_counter = resp_counter;
                                        if let Ok(enc_resp) = encrypt_payload(
                                            session_keys.send.as_bytes(),
                                            resp_counter,
                                            resp_eph_pub.as_bytes(),
                                        ) {
                                            let reply = pack_message(
                                                PacketType::RekeyResp,
                                                self.identity.public_key.as_bytes(),
                                                resp_counter,
                                                &enc_resp,
                                            );
                                            let _ = self.socket.send_to(&reply, sender_addr).await;
                                            peer.bytes_sent += reply.len() as u64;

                                            peer.session_keys = Some(next_keys);
                                            peer.session_epoch = next_epoch;
                                            peer.last_rekey = Some(Utc::now());
                                            peer.rekey_count += 1;
                                            peer.anti_replay.reset();
                                            peer.status = PeerStatus::Connected;
                                        }
                                    }
                                }
                                PacketType::RekeyResp => {
                                    if decrypted.len() == 32 {
                                        peer.anti_replay.update(counter);
                                        if let Some(init_eph_secret_bytes) =
                                            peer.pending_ephemeral_secret.take()
                                        {
                                            let init_eph_secret =
                                                StaticSecret::from(init_eph_secret_bytes);
                                            let mut resp_eph_pub_bytes = [0u8; 32];
                                            resp_eph_pub_bytes.copy_from_slice(&decrypted);
                                            let resp_eph_pub = PublicKey::from(resp_eph_pub_bytes);
                                            let eph_shared =
                                                init_eph_secret.diffie_hellman(&resp_eph_pub);
                                            if eph_shared.as_bytes().iter().all(|byte| *byte == 0) {
                                                continue;
                                            }

                                            let next_epoch = peer.session_epoch + 1;
                                            let next_keys = ratchet_session_keys(
                                                &session_keys,
                                                eph_shared.as_bytes(),
                                                next_epoch,
                                            );

                                            peer.session_keys = Some(next_keys);
                                            peer.session_epoch = next_epoch;
                                            peer.last_rekey = Some(Utc::now());
                                            peer.rekey_count += 1;
                                            peer.anti_replay.reset();
                                            peer.status = PeerStatus::Connected;
                                        }
                                    }
                                }
                                PacketType::Data => {
                                    peer.anti_replay.update(counter);
                                    peer.status = PeerStatus::Connected;
                                    peer.record_data_activity();
                                }
                                PacketType::TicketReq | PacketType::TicketGrant => {}
                            }
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// Send a cryptographically authenticated HandshakeInit to a peer
    pub async fn initiate_handshake(&self, pubkey_b64: &str) -> Result<(), String> {
        if *self.air_gap.read().await {
            return Err("Air-Gap is active. Network transmission blocked.".to_string());
        }

        let mut table = self.peer_table.write().await;
        let peer = table
            .get_mut_by_pubkey(pubkey_b64)
            .ok_or_else(|| "Peer not found".to_string())?;

        let endpoint = peer
            .parsed_endpoint
            .ok_or_else(|| "Peer has no endpoint IP:Port".to_string())?;

        let pubkey_bytes = BASE64_STANDARD
            .decode(pubkey_b64)
            .map_err(|e| format!("Invalid pubkey base64: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let remote_public = PublicKey::from(key_arr);

        let session_keys = derive_session_keys(&self.identity.secret, &remote_public)?;
        let counter = peer.sequence_counter + 1;
        peer.sequence_counter = counter;
        peer.status = PeerStatus::HandshakeInProgress;
        peer.last_handshake = Some(Utc::now());

        let encrypted =
            encrypt_payload(session_keys.send.as_bytes(), counter, b"SBM_HANDSHAKE_INIT")?;
        let packet = pack_message(
            PacketType::HandshakeInit,
            self.identity.public_key.as_bytes(),
            counter,
            &encrypted,
        );

        peer.bytes_sent += packet.len() as u64;
        self.socket
            .send_to(&packet, endpoint)
            .await
            .map_err(|e| format!("Failed to send handshake packet: {}", e))?;

        Ok(())
    }

    /// Send an authenticated Ping packet to calculate real RTT latency
    pub async fn send_ping(&self, pubkey_b64: &str) -> Result<(), String> {
        if *self.air_gap.read().await {
            return Err("Air-Gap is active. Ping blocked.".to_string());
        }

        let mut table = self.peer_table.write().await;
        let peer = table
            .get_mut_by_pubkey(pubkey_b64)
            .ok_or_else(|| "Peer not found".to_string())?;

        let endpoint = peer
            .parsed_endpoint
            .ok_or_else(|| "Peer has no valid endpoint configured".to_string())?;

        let pubkey_bytes = BASE64_STANDARD
            .decode(pubkey_b64)
            .map_err(|e| format!("Invalid pubkey base64: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let remote_public = PublicKey::from(key_arr);

        let session_keys = derive_session_keys(&self.identity.secret, &remote_public)?;
        let counter = peer.sequence_counter + 1;
        peer.sequence_counter = counter;
        peer.last_ping_sent = Some(Utc::now());

        let enc = encrypt_payload(session_keys.send.as_bytes(), counter, b"PING")?;
        let packet = pack_message(
            PacketType::Ping,
            self.identity.public_key.as_bytes(),
            counter,
            &enc,
        );

        peer.bytes_sent += packet.len() as u64;
        self.socket
            .send_to(&packet, endpoint)
            .await
            .map_err(|e| format!("Failed to send ping packet: {}", e))?;

        Ok(())
    }

    /// Sends an inner WireGuard payload encapsulated in a Zero-Knowledge Multi-Hop Relay packet
    pub async fn send_via_relay(
        &self,
        relay_endpoint: SocketAddr,
        target_node_id: &str,
        payload: &[u8],
    ) -> Result<(), String> {
        if *self.air_gap.read().await {
            return Err("Air-Gap is active. Relay transmission blocked.".to_string());
        }

        let relay_pkt = crate::relay::RelayPacket::new(
            target_node_id,
            &self.identity.node_id,
            payload.to_vec(),
        );
        let wire_bytes = relay_pkt.to_bytes();
        self.socket
            .send_to(&wire_bytes, relay_endpoint)
            .await
            .map_err(|e| format!("Failed to send via relay: {}", e))?;
        Ok(())
    }

    /// Sends a packet padded with pseudorandom noise or bucket-aligned to bypass DPI
    pub async fn send_obfuscated_packet(
        &self,
        target_endpoint: SocketAddr,
        payload: &[u8],
        target_bucket: Option<usize>,
    ) -> Result<(), String> {
        if *self.air_gap.read().await {
            return Err("Air-Gap is active. Transmission blocked.".to_string());
        }

        let padded = crate::obfuscation::apply_padding(payload, target_bucket);
        self.socket
            .send_to(&padded, target_endpoint)
            .await
            .map_err(|e| format!("Failed to send obfuscated packet: {}", e))?;
        Ok(())
    }

    /// Initiates an in-band ephemeral Diffie-Hellman Rekey (PFS Ratchet) with a peer
    pub async fn initiate_rekey(&self, pubkey_b64: &str) -> Result<(), String> {
        if *self.air_gap.read().await {
            return Err("Air-Gap is active. Network transmission blocked.".to_string());
        }

        let mut table = self.peer_table.write().await;
        let peer = table
            .get_mut_by_pubkey(pubkey_b64)
            .ok_or_else(|| "Peer not found".to_string())?;

        let endpoint = peer
            .parsed_endpoint
            .ok_or_else(|| "Peer has no endpoint IP:Port".to_string())?;

        let pubkey_bytes = BASE64_STANDARD
            .decode(pubkey_b64)
            .map_err(|e| format!("Invalid pubkey base64: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let remote_public = PublicKey::from(key_arr);

        let active_keys = if let Some(ref keys) = peer.session_keys {
            keys.clone()
        } else {
            derive_session_keys(&self.identity.secret, &remote_public)?
        };

        let eph_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pub = PublicKey::from(&eph_secret);
        peer.pending_ephemeral_secret = Some(eph_secret.to_bytes());

        let counter = peer.sequence_counter + 1;
        peer.sequence_counter = counter;

        let encrypted = encrypt_payload(active_keys.send.as_bytes(), counter, eph_pub.as_bytes())?;
        let packet = pack_message(
            PacketType::RekeyInit,
            self.identity.public_key.as_bytes(),
            counter,
            &encrypted,
        );

        peer.bytes_sent += packet.len() as u64;
        self.socket
            .send_to(&packet, endpoint)
            .await
            .map_err(|e| format!("Failed to send RekeyInit packet: {}", e))?;

        Ok(())
    }

    /// Probes all candidate network paths for a peer concurrently (Path Racing)
    pub async fn probe_candidate_paths(&self, pubkey_b64: &str) -> Result<usize, String> {
        if *self.air_gap.read().await {
            return Err("Air-Gap is active. Probe blocked.".to_string());
        }

        let mut table = self.peer_table.write().await;
        let peer = table
            .get_mut_by_pubkey(pubkey_b64)
            .ok_or_else(|| "Peer not found".to_string())?;

        let pubkey_bytes = BASE64_STANDARD
            .decode(pubkey_b64)
            .map_err(|e| format!("Invalid pubkey base64: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let remote_public = PublicKey::from(key_arr);

        let active_keys = if let Some(ref keys) = peer.session_keys {
            keys.clone()
        } else {
            derive_session_keys(&self.identity.secret, &remote_public)?
        };

        let candidate_endpoints: Vec<SocketAddr> = peer
            .candidate_paths
            .iter()
            .filter_map(|cp| match cp.path_type {
                PathType::DirectIPv4(sa) | PathType::DirectIPv6(sa) => Some(sa),
                PathType::Relay(_) => None,
            })
            .collect();

        if candidate_endpoints.is_empty() {
            return Ok(0);
        }

        let counter = peer.sequence_counter + 1;
        peer.sequence_counter = counter;
        peer.last_ping_sent = Some(Utc::now());

        let enc = encrypt_payload(active_keys.send.as_bytes(), counter, b"PING")?;
        let packet = pack_message(
            PacketType::Ping,
            self.identity.public_key.as_bytes(),
            counter,
            &enc,
        );

        let mut sent_count = 0;
        for ep in candidate_endpoints {
            if self.socket.send_to(&packet, ep).await.is_ok() {
                sent_count += 1;
            }
        }
        peer.bytes_sent += (packet.len() * sent_count) as u64;

        Ok(sent_count)
    }
}

fn mark_ticket_recipient(table: &mut PeerTable, sender_pubkey_b64: &str, sender_addr: SocketAddr) {
    let peer = if let Some(peer) = table.get_mut_by_pubkey(sender_pubkey_b64) {
        peer
    } else {
        let new_peer = crate::peer::PeerConfig::new(
            &format!(
                "client-{}",
                &sender_pubkey_b64[..8.min(sender_pubkey_b64.len())]
            ),
            sender_pubkey_b64,
            &sender_addr.to_string(),
        );
        table.add_peer(new_peer);
        table
            .get_mut_by_pubkey(sender_pubkey_b64)
            .expect("peer was inserted into the table")
    };
    peer.parsed_endpoint = Some(sender_addr);
    // A ticket grant is not proof that the recipient completed the authenticated AEAD handshake.
    peer.status = PeerStatus::HandshakeInProgress;
}

fn authenticated_peer_key_for_object_access(
    table: &PeerTable,
    peer_public_key_base64: &str,
) -> Result<String, String> {
    let decoded = BASE64_STANDARD
        .decode(peer_public_key_base64)
        .map_err(|error| format!("Invalid peer public key encoding: {error}"))?;
    if decoded.len() != 32 || BASE64_STANDARD.encode(&decoded) != peer_public_key_base64 {
        return Err("Peer public key must be canonical Base64 for 32 bytes".to_string());
    }
    let peer = table
        .get_by_pubkey(peer_public_key_base64)
        .ok_or_else(|| "Peer is not registered in the active transport".to_string())?;
    if peer.status != PeerStatus::Connected {
        return Err("Peer has not completed an authenticated mesh handshake".to_string());
    }
    Ok(peer_public_key_base64.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_grant_does_not_mark_peer_connected() {
        let identity = NodeIdentity::generate();
        let pubkey_b64 = BASE64_STANDARD.encode(identity.public_key.as_bytes());
        let mut table = PeerTable::new();
        let address: SocketAddr = "127.0.0.1:58888".parse().unwrap();

        mark_ticket_recipient(&mut table, &pubkey_b64, address);

        let peer = table
            .get_mut_by_pubkey(&pubkey_b64)
            .expect("ticket recipient is recorded");
        assert_eq!(peer.parsed_endpoint, Some(address));
        assert_eq!(peer.status, PeerStatus::HandshakeInProgress);
        assert!(authenticated_peer_key_for_object_access(&table, &pubkey_b64).is_err());

        table
            .get_mut_by_pubkey(&pubkey_b64)
            .expect("peer remains recorded")
            .status = PeerStatus::Connected;
        assert_eq!(
            authenticated_peer_key_for_object_access(&table, &pubkey_b64).unwrap(),
            pubkey_b64
        );
    }

    #[tokio::test]
    async fn object_access_rechecks_rbac_revocation_for_connected_peers() {
        let mesh_name = "transport-access";
        let peer_identity = NodeIdentity::generate();
        let peer_key = peer_identity.wireguard_pubkey.clone();
        let mut peers = PeerTable::new();
        peers.add_peer(crate::peer::PeerConfig::new(
            "authorized-peer",
            &peer_key,
            "127.0.0.1:58889",
        ));
        peers.get_mut_by_pubkey(&peer_key).unwrap().status = PeerStatus::Connected;

        let test_dir = std::env::temp_dir().join(format!(
            "sbm_transport_access_{}_{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let rbac_path = test_dir.join("rbac.json");

        let mut rbac = crate::rbac::MeshRbacStore::new(mesh_name);
        rbac.add_or_update(crate::rbac::MeshMember::new(
            "authorized-peer",
            &peer_key,
            &peer_identity.node_id,
            mesh_name,
            crate::rbac::MeshRole::Consumer,
        ));
        std::fs::write(&rbac_path, serde_json::to_vec(&rbac).unwrap()).unwrap();

        let transport = MeshTransport::bind_with_rbac_path(
            mesh_name,
            0,
            Arc::new(NodeIdentity::generate()),
            Arc::new(RwLock::new(peers)),
            Arc::new(RwLock::new(false)),
            rbac_path.clone(),
        )
        .await
        .unwrap();

        let mut catalog = crate::objects::MeshObjectCatalog::new(mesh_name).unwrap();
        let owner = crate::objects::PrincipalId::user("owner").unwrap();
        let device = crate::objects::PrincipalId::device("peer-device").unwrap();
        catalog
            .directory
            .add_user(owner.clone(), "Owner".to_string())
            .unwrap();
        catalog
            .directory
            .add_device(
                device.clone(),
                "Authorized peer".to_string(),
                peer_key.clone(),
                None,
            )
            .unwrap();
        let object_id = crate::objects::MeshObjectId::new("shared-file").unwrap();
        let mut object = crate::objects::MeshObject::new(
            object_id.clone(),
            crate::objects::MeshObjectKind::Blob {
                media_type: "text/plain".to_string(),
            },
            "Shared file".to_string(),
            None,
            owner,
        );
        object.acl.add_entry(
            device,
            crate::objects::AclEffect::Allow,
            [crate::objects::ObjectPermission::Read],
            false,
        );
        catalog.insert_object(object).unwrap();
        let required = [crate::objects::ObjectPermission::Read]
            .into_iter()
            .collect();

        assert!(transport
            .check_object_access(&peer_key, &catalog, &object_id, &required)
            .await
            .unwrap());

        rbac.revoke(&peer_identity.node_id, "access revoked");
        std::fs::write(&rbac_path, serde_json::to_vec(&rbac).unwrap()).unwrap();
        assert!(transport
            .check_object_access(&peer_key, &catalog, &object_id, &required)
            .await
            .unwrap_err()
            .contains("not an active member"));

        drop(transport);
        std::fs::remove_dir_all(test_dir).unwrap();
    }
}
