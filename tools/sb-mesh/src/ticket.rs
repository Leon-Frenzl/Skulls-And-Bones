//! Sovereign Mesh Ticket Exchange Protocol (SBM-TEP)
//! Kerberos-inspired Pre-Authentication, Dynamic Leases & Zero-Lockout Key Synchronization.
//!
//! Eliminates silent crypto mismatches and Catch-22 lockouts when server keys rotate or tickets expire.

use base64::prelude::*;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UdpSocket;
use x25519_dalek::PublicKey;

use crate::crypto::{
    decrypt_payload, derive_session_keys, derive_swarm_tag, encrypt_payload, pack_message_v2,
    unpack_header_v2, PacketType, PREAUTH_SWARM_TOPIC,
};
use crate::identity::{verify_pow_nonce, NodeIdentity, DEFAULT_POW_DIFFICULTY};
use crate::network::NetworkStore;

/// Default lease duration for a granted ticket (8 hours)
pub const DEFAULT_TICKET_LEASE_SECS: u64 = 8 * 3600;

/// Replay protection window in seconds
pub const TICKET_REPLAY_WINDOW_SECS: u64 = 60;

/// Single authorized developer / client identity entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedIdentity {
    pub name: String,
    pub node_id: String,
    pub public_key: String, // Base64 X25519 public key
    #[serde(default = "default_roles")]
    pub roles: Vec<String>,
    #[serde(default = "default_allowed_meshes")]
    pub allowed_meshes: Vec<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

fn default_roles() -> Vec<String> {
    Vec::new()
}

fn default_allowed_meshes() -> Vec<String> {
    Vec::new()
}

/// Store of all authorized identities on the server (the sovereign KDC database)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizedIdentitiesStore {
    pub identities: Vec<AuthorizedIdentity>,
}

impl AuthorizedIdentitiesStore {
    pub fn default_path() -> PathBuf {
        if Path::new("/etc/sb").exists() {
            PathBuf::from("/etc/sb/authorized_identities.json")
        } else {
            let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            home.join(".sb-mesh").join("authorized_identities.json")
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if path.exists() {
            let data = fs::read_to_string(path)
                .map_err(|e| format!("Fehler beim Lesen der authorized_identities.json: {}", e))?;
            serde_json::from_str(&data)
                .map_err(|e| format!("Ungültiges JSON in authorized_identities.json: {}", e))
        } else {
            let store = Self::default();
            let data = serde_json::to_string_pretty(&store)
                .map_err(|e| format!("Serialisierungsfehler: {}", e))?;
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(path, data).map_err(|e| {
                format!(
                    "Konnte initiales authorized_identities.json nicht schreiben: {}",
                    e
                )
            })?;
            Ok(store)
        }
    }

    pub fn is_authorized(
        &self,
        pubkey_b64: &str,
        requested_mesh: &str,
    ) -> Option<&AuthorizedIdentity> {
        let clean_key = pubkey_b64.trim();
        self.identities.iter().find(|id| {
            if id.public_key.trim() != clean_key {
                return false;
            }
            id.allowed_meshes.iter().any(|mesh| mesh == requested_mesh)
        })
    }

    pub fn authorization_profile(
        &self,
        pubkey_b64: &str,
        node_id: &str,
        requested_mesh: &str,
    ) -> Option<(String, Vec<String>)> {
        let identity = self.is_authorized(pubkey_b64, requested_mesh)?;
        if identity.node_id != node_id {
            return None;
        }
        let role = crate::rbac::MeshRole::from_str(identity.roles.first()?)?;
        Some((role.as_str().to_string(), role.default_capabilities()))
    }

    pub fn add_or_update(&mut self, id: AuthorizedIdentity) {
        if let Some(existing) = self
            .identities
            .iter_mut()
            .find(|i| i.public_key == id.public_key)
        {
            *existing = id;
        } else {
            self.identities.push(id);
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialisierungsfehler: {}", e))?;
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(path, data).map_err(|e| format!("Speicherfehler: {}", e))
    }
}

/// Request payload sent by client knocking on UDP 58888
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRequestPayload {
    pub client_node_id: String,
    pub client_pubkey: String,
    pub requested_mesh: String,
    pub timestamp: u64,
    pub nonce: u64,
    pub pow_nonce: u64,
    #[serde(default)]
    pub invite_token: Option<String>,
}

/// Grant payload returned by server encrypted with client DH session key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketGrantPayload {
    pub server_node_id: String,
    pub server_pubkey: String,
    #[serde(default)]
    pub subject_node_id: String,
    pub granted_mesh: String,
    #[serde(default)]
    pub overlay_subnet: String,
    pub swarm_topic: String,
    pub swarm_tag: [u8; 8],
    pub valid_until: u64,
    pub session_ticket: String,
    pub assigned_ip: Option<String>,
    pub relay_port: u16,
    pub request_nonce: u64,
    #[serde(default = "default_ticket_role")]
    pub role: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

fn default_ticket_role() -> String {
    "Developer".to_string()
}

/// Local cached ticket file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTicket {
    pub mesh_name: String,
    pub server_addr: String,
    pub grant: TicketGrantPayload,
    pub acquired_at: DateTime<Utc>,
}

impl CachedTicket {
    pub fn is_valid(&self) -> bool {
        let now = Utc::now().timestamp() as u64;
        self.grant.valid_until > (now + 60)
            && self.mesh_name == self.grant.granted_mesh
            && !self.grant.subject_node_id.is_empty()
            && !self.grant.capabilities.is_empty()
            && NodeIdentity::derive_node_id_from_pubkey(&self.grant.server_pubkey)
                == self.grant.server_node_id
    }
}

pub fn ticket_cache_path(mesh_name: &str) -> Result<PathBuf, String> {
    let paths = crate::state::MeshStatePaths::for_mesh(mesh_name)?;
    paths.ensure()?;
    let dir = paths.tickets;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Failed to create mesh ticket directory: {error}"))?;
    Ok(dir.join(format!("{}.json", mesh_name)))
}

pub fn load_cached_ticket(mesh_name: &str) -> Option<CachedTicket> {
    let path = ticket_cache_path(mesh_name).ok()?;
    if path.exists() {
        let content = fs::read_to_string(path).ok()?;
        let ticket: CachedTicket = serde_json::from_str(&content).ok()?;
        if ticket.is_valid() {
            return Some(ticket);
        }
    }
    None
}

pub fn save_cached_ticket(ticket: &CachedTicket) -> Result<(), String> {
    let path = ticket_cache_path(&ticket.mesh_name)?;
    let data = serde_json::to_string_pretty(ticket)
        .map_err(|e| format!("Failed to serialize ticket: {}", e))?;
    fs::write(path, data).map_err(|e| format!("Failed to save ticket: {}", e))
}

/// Connects to a sovereign mesh using an invite token, performs the pre-auth handshake,
/// and saves the granted ticket and network configuration locally.
pub async fn join_with_invite(
    invite_uri: &str,
    client_identity: &NodeIdentity,
    timeout_duration: Duration,
) -> Result<TicketGrantPayload, String> {
    let invite = crate::rbac::MeshInviteToken::decode_uri(invite_uri)?;
    let now = Utc::now().timestamp() as u64;
    if !invite.is_valid(now) {
        return Err("Dieses Einladungs-Token ist abgelaufen oder ungültig.".to_string());
    }

    let remote_addr: SocketAddr = invite.server_endpoint.parse().map_err(|e| {
        format!(
            "Ungültige Server-Adresse '{}' im Invite-Token: {}",
            invite.server_endpoint, e
        )
    })?;
    let expected_server_key = BASE64_STANDARD
        .decode(invite.server_pubkey.trim())
        .map_err(|e| format!("Ungültiger Anchor-Public-Key im Invite-Token: {}", e))?;
    let expected_server_key: [u8; 32] = expected_server_key
        .try_into()
        .map_err(|_| "Anchor-Public-Key im Invite-Token muss 32 Bytes lang sein.".to_string())?;
    let expected_server_node_id = NodeIdentity::derive_node_id_from_pubkey(&invite.server_pubkey);

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Konnte lokalen UDP-Socket nicht binden: {}", e))?;

    let preauth_tag = derive_swarm_tag(PREAUTH_SWARM_TOPIC);
    let my_pubkey_bytes = *client_identity.public_key.as_bytes();

    let mut attempts = 0;
    const MAX_ATTEMPTS: usize = 3;

    while attempts < MAX_ATTEMPTS {
        attempts += 1;
        let nonce = rand::random::<u64>();
        let now = Utc::now().timestamp() as u64;

        let req_payload = TicketRequestPayload {
            client_node_id: client_identity.node_id.clone(),
            client_pubkey: client_identity.wireguard_pubkey.clone(),
            requested_mesh: invite.mesh_name.clone(),
            timestamp: now,
            nonce,
            pow_nonce: client_identity.pow_nonce,
            invite_token: Some(invite_uri.to_string()),
        };

        let req_json = serde_json::to_vec(&req_payload)
            .map_err(|e| format!("Serialisierungsfehler für TicketRequest: {}", e))?;

        let packet = pack_message_v2(
            PacketType::TicketReq,
            &preauth_tag,
            &my_pubkey_bytes,
            nonce,
            &req_json,
        );

        socket
            .send_to(&packet, remote_addr)
            .await
            .map_err(|e| format!("Fehler beim Senden des Join-Pakets: {}", e))?;

        let mut buf = [0u8; 65535];
        let recv_fut = socket.recv_from(&mut buf);

        match tokio::time::timeout(timeout_duration, recv_fut).await {
            Ok(Ok((len, from_addr))) => {
                if from_addr != remote_addr {
                    continue;
                }
                let (ptype, tag, server_pubkey_bytes, _counter, payload) =
                    match unpack_header_v2(&buf[..len]) {
                        Ok(res) => res,
                        Err(_) => continue,
                    };

                if ptype != PacketType::TicketGrant
                    || tag != preauth_tag
                    || server_pubkey_bytes != expected_server_key
                {
                    continue;
                }

                let server_public = PublicKey::from(server_pubkey_bytes);
                let session_keys =
                    match derive_session_keys(&client_identity.secret, &server_public) {
                        Ok(keys) => keys,
                        Err(_) => continue,
                    };

                let grant_json =
                    match decrypt_payload(session_keys.receive.as_bytes(), _counter, payload) {
                        Ok(dec) => dec,
                        Err(_) => continue,
                    };

                let grant: TicketGrantPayload = match serde_json::from_slice(&grant_json) {
                    Ok(g) => g,
                    Err(_) => continue,
                };

                if grant.request_nonce != nonce
                    || grant.server_pubkey != invite.server_pubkey
                    || grant.server_node_id != expected_server_node_id
                    || grant.subject_node_id != client_identity.node_id
                    || !grant.granted_mesh.eq_ignore_ascii_case(&invite.mesh_name)
                    || grant.swarm_topic != invite.swarm_topic
                    || grant.swarm_tag != derive_swarm_tag(&invite.swarm_topic)
                {
                    continue;
                }

                // Cache locally
                let cached = CachedTicket {
                    mesh_name: invite.mesh_name.clone(),
                    server_addr: invite.server_endpoint.clone(),
                    grant: grant.clone(),
                    acquired_at: Utc::now(),
                };
                save_cached_ticket(&cached)?;

                return Ok(grant);
            }
            Ok(Err(e)) => {
                return Err(format!(
                    "UDP Socket Fehler beim Warten auf TicketGrant: {}",
                    e
                ));
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    Err(format!(
        "Server '{}' hat keinen Ticket-Grant für Mesh '{}' gesendet. Eine Admin-Freigabe kann ausstehen; alternativ ist das Token ungültig oder der Server offline.",
        invite.server_endpoint, invite.mesh_name
    ))
}

/// Sends a TicketReq knock to the remote server and awaits an encrypted TicketGrant.
/// Performs automatic retries and validates the cryptographic grant.
pub async fn request_ticket(
    server_addr: &str,
    client_identity: &NodeIdentity,
    requested_mesh: &str,
    timeout_duration: Duration,
) -> Result<TicketGrantPayload, String> {
    let remote_addr: SocketAddr = server_addr
        .parse()
        .map_err(|e| format!("Ungültige Server-Adresse '{}': {}", server_addr, e))?;

    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
        format!(
            "Konnte lokalen UDP-Socket für Ticket-Knock nicht binden: {}",
            e
        )
    })?;

    let preauth_tag = derive_swarm_tag(PREAUTH_SWARM_TOPIC);
    let my_pubkey_bytes = *client_identity.public_key.as_bytes();

    let mut attempts = 0;
    const MAX_ATTEMPTS: usize = 3;

    while attempts < MAX_ATTEMPTS {
        attempts += 1;
        let nonce = rand::random::<u64>();
        let now = Utc::now().timestamp() as u64;

        let req_payload = TicketRequestPayload {
            client_node_id: client_identity.node_id.clone(),
            client_pubkey: client_identity.wireguard_pubkey.clone(),
            requested_mesh: requested_mesh.to_string(),
            timestamp: now,
            nonce,
            pow_nonce: client_identity.pow_nonce,
            invite_token: None,
        };

        let req_json = serde_json::to_vec(&req_payload)
            .map_err(|e| format!("Serialisierungsfehler für TicketRequest: {}", e))?;

        let packet = pack_message_v2(
            PacketType::TicketReq,
            &preauth_tag,
            &my_pubkey_bytes,
            nonce,
            &req_json,
        );

        socket
            .send_to(&packet, remote_addr)
            .await
            .map_err(|e| format!("Fehler beim Senden des TicketReq-Pakets: {}", e))?;

        let mut buf = [0u8; 65535];
        let recv_fut = socket.recv_from(&mut buf);

        match tokio::time::timeout(timeout_duration, recv_fut).await {
            Ok(Ok((len, sender))) => {
                if sender.ip() != remote_addr.ip() {
                    continue;
                }
                match unpack_header_v2(&buf[..len]) {
                    Ok((ptype, tag, sender_pubkey_bytes, counter, payload)) => {
                        if ptype != PacketType::TicketGrant || tag != preauth_tag {
                            continue;
                        }
                        // Diffie-Hellman Shared Key mit dem empfangenen Server-Key ableiten
                        let remote_server_pub = PublicKey::from(sender_pubkey_bytes);
                        let session_keys = match derive_session_keys(
                            &client_identity.secret,
                            &remote_server_pub,
                        ) {
                            Ok(keys) => keys,
                            Err(_) => continue,
                        };

                        match decrypt_payload(session_keys.receive.as_bytes(), counter, payload) {
                            Ok(decrypted_bytes) => {
                                match serde_json::from_slice::<TicketGrantPayload>(&decrypted_bytes)
                                {
                                    Ok(grant) => {
                                        if grant.request_nonce != nonce {
                                            return Err("Replay-Verdacht: Nonce Mismatch im empfangenen TicketGrant".to_string());
                                        }
                                        if grant.granted_mesh != requested_mesh {
                                            return Err(format!(
                                                "Mesh Mismatch: Angefordert war '{}', gewährt wurde '{}'",
                                                requested_mesh, grant.granted_mesh
                                            ));
                                        }
                                        if grant.subject_node_id != client_identity.node_id {
                                            return Err("TicketGrant identity does not match the local mesh node".to_string());
                                        }
                                        let ticket = CachedTicket {
                                            mesh_name: requested_mesh.to_string(),
                                            server_addr: server_addr.to_string(),
                                            grant: grant.clone(),
                                            acquired_at: Utc::now(),
                                        };
                                        save_cached_ticket(&ticket)?;
                                        return Ok(grant);
                                    }
                                    Err(e) => {
                                        return Err(format!(
                                            "TicketGrant Payload JSON-Fehler: {}",
                                            e
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                return Err(format!(
                                    "TicketGrant AEAD-Entschlüsselung fehlgeschlagen: {}",
                                    e
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        return Err(format!("TicketGrant Header-Fehler: {}", e));
                    }
                }
            }
            Ok(Err(e)) => {
                return Err(format!(
                    "UDP Socket Fehler beim Warten auf TicketGrant: {}",
                    e
                ));
            }
            Err(_) => {
                // Timeout, retry
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    Err(format!(
        "Server '{}' hat nicht auf Ticket-Anfrage für Mesh '{}' geantwortet (Nach {} Versuchen). Zugriff verweigert oder Server offline.",
        server_addr, requested_mesh, MAX_ATTEMPTS
    ))
}

/// Processes an incoming raw packet on the server.
/// If it is a valid TicketReq from an active member, returns an encrypted TicketGrant.
/// A valid invite creates a pending request but never grants membership or a ticket.
/// Unauthorized or invalid requests return Ok(None) to preserve silent stealth.
pub fn process_ticket_request(
    raw_packet: &[u8],
    server_identity: &NodeIdentity,
    auth_store: &AuthorizedIdentitiesStore,
    networks_store: &NetworkStore,
) -> Result<Option<(Vec<u8>, TicketGrantPayload)>, String> {
    let (ptype, _tag, sender_pubkey_bytes, counter_in, payload) = match unpack_header_v2(raw_packet)
    {
        Ok(res) => res,
        Err(_) => return Ok(None),
    };

    if ptype != PacketType::TicketReq {
        return Ok(None);
    }

    let req: TicketRequestPayload = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    // 1. Replay & Timestamp Window Check (Strict ±60s)
    let now = Utc::now().timestamp() as u64;
    if now.abs_diff(req.timestamp) > TICKET_REPLAY_WINDOW_SECS {
        return Ok(None);
    }

    // 2. Pubkey consistency check: Header pubkey must match payload pubkey
    let client_pubkey_raw = match BASE64_STANDARD.decode(&req.client_pubkey) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return Ok(None),
    };

    if client_pubkey_raw != sender_pubkey_bytes {
        return Ok(None);
    }
    if NodeIdentity::derive_node_id_from_pubkey(&req.client_pubkey) != req.client_node_id {
        return Ok(None);
    }

    // 3. PoW Verification (Sybil & Flood Defense)
    if !verify_pow_nonce(&client_pubkey_raw, req.pow_nonce, DEFAULT_POW_DIFFICULTY) {
        return Ok(None);
    }

    // CVE-Threat: Cross-mesh ticket issuance using a daemon identity bound elsewhere.
    // Analysis: Authorization to one RBAC store must not let a daemon impersonate another mesh anchor.
    // Hardening: Drop requests unless this server identity matches the requested mesh catalog key.
    let net = match networks_store.networks.get(&req.requested_mesh) {
        Some(network) if network.wireguard_pubkey == server_identity.wireguard_pubkey => network,
        _ => return Ok(None),
    };

    // CVE-Threat: RBAC storage failure falling back to a broader identity store.
    // Analysis: A corrupt or unreadable mesh ACL must not silently switch trust authorities.
    // Hardening: Treat storage errors as request failures and bind grants to the mesh identity.
    // 4. Authorization & RBAC Check (members or invitation-backed join requests)
    let mut rbac_store = crate::rbac::MeshRbacStore::load_or_create(&req.requested_mesh)
        .map_err(|error| format!("Mesh RBAC state is unavailable: {error}"))?;
    if rbac_store.mesh_name != req.requested_mesh {
        return Err("Mesh RBAC state is bound to a different mesh".to_string());
    }
    let (role_str, capabilities) = {
        if let Some(member) = rbac_store.find_by_pubkey(&req.client_pubkey) {
            if !member.is_active(now)
                || member.node_id != req.client_node_id
                || member.mesh_name != req.requested_mesh
            {
                // Member revoked or expired -> Silent drop!
                return Ok(None);
            }
            (
                member.role.as_str().to_string(),
                member.capabilities.clone(),
            )
        } else if let Some(ref inv_str) = req.invite_token {
            // CVE-Threat: Invite redemption bypassing administrator approval or altering role claims.
            // Analysis: Invite URIs are bearer credentials and their other fields are client-controlled.
            // Hardening: Persist only a pending request from server-side invite data; issue no ticket.
            let invite = match crate::rbac::MeshInviteToken::decode_uri(inv_str) {
                Ok(invite) => invite,
                Err(_) => return Ok(None),
            };
            if !enqueue_invite_join_request(
                &mut rbac_store,
                &invite,
                &req.client_pubkey,
                &req.client_node_id,
                &req.requested_mesh,
                now,
            ) {
                return Ok(None);
            }
            rbac_store.save()?;
            return Ok(None);
        } else {
            match auth_store.authorization_profile(
                &req.client_pubkey,
                &req.client_node_id,
                &req.requested_mesh,
            ) {
                Some(profile) => profile,
                None => return Ok(None),
            }
        }
    };

    // 5. Generate Session Ticket Token
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let session_ticket = BASE64_STANDARD.encode(token_bytes);

    let grant = TicketGrantPayload {
        server_node_id: server_identity.node_id.clone(),
        server_pubkey: server_identity.wireguard_pubkey.clone(),
        subject_node_id: req.client_node_id.clone(),
        granted_mesh: net.name.clone(),
        overlay_subnet: net.overlay_subnet.clone(),
        swarm_topic: net.swarm_topic.clone(),
        swarm_tag: derive_swarm_tag(&net.swarm_topic),
        valid_until: now + DEFAULT_TICKET_LEASE_SECS,
        session_ticket,
        assigned_ip: None,
        relay_port: 58888,
        request_nonce: req.nonce,
        role: role_str,
        capabilities,
    };

    let grant_json =
        serde_json::to_vec(&grant).map_err(|e| format!("Failed to serialize grant: {}", e))?;

    // 6. DH Key Exchange: Shared secret using Server Private + Client Public
    let client_public = PublicKey::from(client_pubkey_raw);
    let session_keys = derive_session_keys(&server_identity.secret, &client_public)?;

    let counter_out = counter_in.wrapping_add(1);
    let enc_grant = encrypt_payload(session_keys.send.as_bytes(), counter_out, &grant_json)
        .map_err(|e| format!("Failed to encrypt ticket grant: {}", e))?;

    let preauth_tag = derive_swarm_tag(PREAUTH_SWARM_TOPIC);
    let reply_packet = pack_message_v2(
        PacketType::TicketGrant,
        &preauth_tag,
        server_identity.public_key.as_bytes(),
        counter_out,
        &enc_grant,
    );

    Ok(Some((reply_packet, grant)))
}

fn enqueue_invite_join_request(
    rbac_store: &mut crate::rbac::MeshRbacStore,
    presented_invite: &crate::rbac::MeshInviteToken,
    client_pubkey: &str,
    client_node_id: &str,
    requested_mesh: &str,
    now: u64,
) -> bool {
    if rbac_store.mesh_name != requested_mesh
        || rbac_store.join_requests.iter().any(|request| {
            request.pubkey == client_pubkey
                && request.status == crate::rbac::JoinRequestStatus::Pending
        })
    {
        return false;
    }

    let invite_details = {
        let Some(inv_entry) = rbac_store.find_invite_mut(&presented_invite.token_id) else {
            return false;
        };
        if inv_entry.mesh_name != requested_mesh
            || !inv_entry.is_valid(now)
            || !inv_entry.secret_matches(&presented_invite.signature)
        {
            return false;
        }
        inv_entry.current_uses += 1;
        (
            inv_entry.user_name.clone(),
            inv_entry.role,
            inv_entry.groups.clone(),
            inv_entry.capabilities.clone(),
        )
    };
    let join_request = crate::rbac::MeshJoinRequest::new(
        &invite_details.0,
        client_pubkey,
        client_node_id,
        requested_mesh,
        invite_details.1,
        invite_details.2,
        invite_details.3,
    );
    rbac_store.add_join_request(join_request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MeshNetwork;
    use crate::rbac::{JoinRequestStatus, MeshInviteToken, MeshRbacStore, MeshRole};
    use std::collections::HashMap;

    fn setup_test_networks(server_pubkey: &str) -> NetworkStore {
        let mut networks = HashMap::new();
        let dev = MeshNetwork::new(
            "dev-mesh",
            "Developer Mesh",
            "10.240.0.0/16",
            server_pubkey,
            Some("sbm-swarm-dev"),
            None,
            Some(58888),
        )
        .unwrap();
        networks.insert("dev-mesh".to_string(), dev);

        NetworkStore {
            path: PathBuf::from("dummy_networks.json"),
            active_network: "dev-mesh".to_string(),
            networks,
        }
    }

    #[test]
    fn invite_redemption_only_queues_request_using_server_side_claims() {
        let now = Utc::now().timestamp() as u64;
        let secret = MeshInviteToken::new_secret();
        let invite = MeshInviteToken {
            token_id: "inv-approval-test".to_string(),
            mesh_name: "dev-mesh".to_string(),
            user_name: "alice".to_string(),
            role: MeshRole::Consumer,
            groups: vec!["auditors".to_string()],
            capabilities: vec!["tunnel:ssh".to_string()],
            server_endpoint: "127.0.0.1:58888".to_string(),
            server_pubkey: "server-key".to_string(),
            swarm_topic: "dev-topic".to_string(),
            created_at: now,
            expires_at: now + 3600,
            max_uses: 1,
            current_uses: 0,
            revoked: false,
            signature: secret,
        };
        let mut store = MeshRbacStore::new("dev-mesh");
        store.add_invite(invite.to_stored());

        let mut tampered_presentation = invite.clone();
        tampered_presentation.user_name = "mallory".to_string();
        tampered_presentation.role = MeshRole::Admin;
        tampered_presentation.groups = vec!["admins".to_string()];
        tampered_presentation.capabilities = vec!["tunnel:any".to_string()];
        tampered_presentation.mesh_name = "other-mesh".to_string();
        let client = NodeIdentity::generate();

        assert!(enqueue_invite_join_request(
            &mut store,
            &tampered_presentation,
            &client.wireguard_pubkey,
            &client.node_id,
            "dev-mesh",
            now,
        ));
        assert!(store.members.is_empty());
        assert_eq!(store.invites[0].current_uses, 1);
        let request = &store.join_requests[0];
        assert_eq!(request.name, "alice");
        assert_eq!(request.role, MeshRole::Consumer);
        assert_eq!(request.groups, vec!["auditors".to_string()]);
        assert_eq!(request.capabilities, vec!["tunnel:ssh".to_string()]);
        assert_eq!(request.status, JoinRequestStatus::Pending);
        assert!(!enqueue_invite_join_request(
            &mut store,
            &tampered_presentation,
            &client.wireguard_pubkey,
            &client.node_id,
            "dev-mesh",
            now,
        ));
    }

    #[test]
    fn identity_fallback_requires_explicit_mesh_and_known_role() {
        let store = AuthorizedIdentitiesStore {
            identities: vec![AuthorizedIdentity {
                name: "alice".into(),
                node_id: "node-alice".into(),
                public_key: "key-alice".into(),
                roles: vec!["developer".into()],
                allowed_meshes: vec!["dev-mesh".into()],
                created_at: None,
            }],
        };

        assert!(store
            .authorization_profile("key-alice", "node-alice", "dev-mesh")
            .is_some());
        assert!(store
            .authorization_profile("key-alice", "node-impersonated", "dev-mesh")
            .is_none());
        assert!(store
            .authorization_profile("key-alice", "node-alice", "public-mesh")
            .is_none());

        let mut unknown_role = store.clone();
        unknown_role.identities[0].roles = vec!["unknown".into()];
        assert!(unknown_role
            .authorization_profile("key-alice", "node-alice", "dev-mesh")
            .is_none());
    }

    #[test]
    fn identity_deserialization_defaults_to_no_meshes_or_roles() {
        let identity: AuthorizedIdentity = serde_json::from_value(serde_json::json!({
            "name": "legacy",
            "node_id": "node-legacy",
            "public_key": "key-legacy"
        }))
        .unwrap();

        assert!(identity.allowed_meshes.is_empty());
        assert!(identity.roles.is_empty());
    }

    #[test]
    fn test_authorized_ticket_request_and_grant_exchange() {
        let server_id = NodeIdentity::generate();
        let client_id = NodeIdentity::generate();

        let mut auth_store = AuthorizedIdentitiesStore::default();
        auth_store.add_or_update(AuthorizedIdentity {
            name: "test_dev".to_string(),
            node_id: client_id.node_id.clone(),
            public_key: client_id.wireguard_pubkey.clone(),
            roles: vec!["dev".to_string()],
            allowed_meshes: vec!["dev-mesh".to_string()],
            created_at: Some(Utc::now()),
        });

        let networks = setup_test_networks(&server_id.wireguard_pubkey);

        // 1. Client creates request packet
        let nonce = 123456789;
        let now = Utc::now().timestamp() as u64;
        let req_payload = TicketRequestPayload {
            client_node_id: client_id.node_id.clone(),
            client_pubkey: client_id.wireguard_pubkey.clone(),
            requested_mesh: "dev-mesh".to_string(),
            timestamp: now,
            nonce,
            pow_nonce: client_id.pow_nonce,
            invite_token: None,
        };

        let req_json = serde_json::to_vec(&req_payload).unwrap();
        let preauth_tag = derive_swarm_tag(PREAUTH_SWARM_TOPIC);
        let req_packet = pack_message_v2(
            PacketType::TicketReq,
            &preauth_tag,
            client_id.public_key.as_bytes(),
            nonce,
            &req_json,
        );

        // 2. Server processes request
        let result =
            process_ticket_request(&req_packet, &server_id, &auth_store, &networks).unwrap();
        assert!(result.is_some(), "Authorized client must receive a grant");
        let (grant_packet, grant_payload) = result.unwrap();

        assert_eq!(grant_payload.granted_mesh, "dev-mesh");
        assert_eq!(grant_payload.server_pubkey, server_id.wireguard_pubkey);
        assert_eq!(grant_payload.subject_node_id, client_id.node_id);
        assert_eq!(grant_payload.request_nonce, nonce);

        // 3. Client decrypts grant
        let (ptype, tag, server_pub_bytes, counter, payload) =
            unpack_header_v2(&grant_packet).unwrap();
        assert_eq!(ptype, PacketType::TicketGrant);
        assert_eq!(tag, preauth_tag);
        assert_eq!(server_pub_bytes, *server_id.public_key.as_bytes());

        let server_pub = PublicKey::from(server_pub_bytes);
        let session_keys = derive_session_keys(&client_id.secret, &server_pub).unwrap();
        let decrypted = decrypt_payload(session_keys.receive.as_bytes(), counter, payload).unwrap();
        let client_received_grant: TicketGrantPayload = serde_json::from_slice(&decrypted).unwrap();

        assert_eq!(
            client_received_grant.server_pubkey,
            server_id.wireguard_pubkey
        );
        assert_eq!(client_received_grant.swarm_topic, "sbm-swarm-dev");
        assert_eq!(
            client_received_grant.session_ticket,
            grant_payload.session_ticket
        );
        assert!(!client_received_grant.role.is_empty());
        assert!(!client_received_grant.capabilities.is_empty());
    }

    #[test]
    fn test_unauthorized_client_gets_silent_drop() {
        let server_id = NodeIdentity::generate();
        let unauthorized_client = NodeIdentity::generate();

        let auth_store = AuthorizedIdentitiesStore::default(); // Empty, nobody authorized!
        let networks = setup_test_networks(&server_id.wireguard_pubkey);

        let nonce = 987654321;
        let now = Utc::now().timestamp() as u64;
        let req_payload = TicketRequestPayload {
            client_node_id: unauthorized_client.node_id.clone(),
            client_pubkey: unauthorized_client.wireguard_pubkey.clone(),
            requested_mesh: "dev-mesh".to_string(),
            timestamp: now,
            nonce,
            pow_nonce: unauthorized_client.pow_nonce,
            invite_token: None,
        };

        let req_json = serde_json::to_vec(&req_payload).unwrap();
        let preauth_tag = derive_swarm_tag(PREAUTH_SWARM_TOPIC);
        let req_packet = pack_message_v2(
            PacketType::TicketReq,
            &preauth_tag,
            unauthorized_client.public_key.as_bytes(),
            nonce,
            &req_json,
        );

        let result =
            process_ticket_request(&req_packet, &server_id, &auth_store, &networks).unwrap();
        assert!(
            result.is_none(),
            "Unauthorized client must receive ZERO bytes (silent drop)"
        );
    }

    #[test]
    fn ticket_request_is_dropped_when_server_identity_is_bound_to_another_mesh() {
        let server_id = NodeIdentity::generate();
        let client_id = NodeIdentity::generate();
        let other_mesh_identity = NodeIdentity::generate();
        let mut auth_store = AuthorizedIdentitiesStore::default();
        auth_store.add_or_update(AuthorizedIdentity {
            name: "test_dev".to_string(),
            node_id: client_id.node_id.clone(),
            public_key: client_id.wireguard_pubkey.clone(),
            roles: vec!["dev".to_string()],
            allowed_meshes: vec!["dev-mesh".to_string()],
            created_at: Some(Utc::now()),
        });
        let networks = setup_test_networks(&other_mesh_identity.wireguard_pubkey);
        let nonce = 246810;
        let req_payload = TicketRequestPayload {
            client_node_id: client_id.node_id.clone(),
            client_pubkey: client_id.wireguard_pubkey.clone(),
            requested_mesh: "dev-mesh".to_string(),
            timestamp: Utc::now().timestamp() as u64,
            nonce,
            pow_nonce: client_id.pow_nonce,
            invite_token: None,
        };
        let req_json = serde_json::to_vec(&req_payload).unwrap();
        let req_packet = pack_message_v2(
            PacketType::TicketReq,
            &derive_swarm_tag(PREAUTH_SWARM_TOPIC),
            client_id.public_key.as_bytes(),
            nonce,
            &req_json,
        );

        let result =
            process_ticket_request(&req_packet, &server_id, &auth_store, &networks).unwrap();
        assert!(
            result.is_none(),
            "A daemon identity must not issue grants for another mesh"
        );
    }

    #[test]
    fn ticket_request_rejects_node_id_not_derived_from_client_key() {
        let server_id = NodeIdentity::generate();
        let client_id = NodeIdentity::generate();
        let mut auth_store = AuthorizedIdentitiesStore::default();
        auth_store.add_or_update(AuthorizedIdentity {
            name: "test_dev".to_string(),
            node_id: client_id.node_id.clone(),
            public_key: client_id.wireguard_pubkey.clone(),
            roles: vec!["dev".to_string()],
            allowed_meshes: vec!["dev-mesh".to_string()],
            created_at: Some(Utc::now()),
        });
        let networks = setup_test_networks(&server_id.wireguard_pubkey);
        let nonce = 1357911;
        let req_payload = TicketRequestPayload {
            client_node_id: "sbm-0x00000000".to_string(),
            client_pubkey: client_id.wireguard_pubkey.clone(),
            requested_mesh: "dev-mesh".to_string(),
            timestamp: Utc::now().timestamp() as u64,
            nonce,
            pow_nonce: client_id.pow_nonce,
            invite_token: None,
        };
        let req_packet = pack_message_v2(
            PacketType::TicketReq,
            &derive_swarm_tag(PREAUTH_SWARM_TOPIC),
            client_id.public_key.as_bytes(),
            nonce,
            &serde_json::to_vec(&req_payload).unwrap(),
        );

        let result =
            process_ticket_request(&req_packet, &server_id, &auth_store, &networks).unwrap();
        assert!(
            result.is_none(),
            "Client-supplied node IDs must be derived from the authenticated public key"
        );
    }

    #[test]
    fn test_replayed_ticket_request_dropped() {
        let server_id = NodeIdentity::generate();
        let client_id = NodeIdentity::generate();

        let mut auth_store = AuthorizedIdentitiesStore::default();
        auth_store.add_or_update(AuthorizedIdentity {
            name: "test_dev".to_string(),
            node_id: client_id.node_id.clone(),
            public_key: client_id.wireguard_pubkey.clone(),
            roles: vec!["dev".to_string()],
            allowed_meshes: vec!["dev-mesh".to_string()],
            created_at: Some(Utc::now()),
        });

        let networks = setup_test_networks(&server_id.wireguard_pubkey);

        // Expired timestamp (>60s old)
        let expired_time = (Utc::now().timestamp() as u64) - 120;
        let req_payload = TicketRequestPayload {
            client_node_id: client_id.node_id.clone(),
            client_pubkey: client_id.wireguard_pubkey.clone(),
            requested_mesh: "dev-mesh".to_string(),
            timestamp: expired_time,
            nonce: 5555,
            pow_nonce: client_id.pow_nonce,
            invite_token: None,
        };

        let req_json = serde_json::to_vec(&req_payload).unwrap();
        let preauth_tag = derive_swarm_tag(PREAUTH_SWARM_TOPIC);
        let req_packet = pack_message_v2(
            PacketType::TicketReq,
            &preauth_tag,
            client_id.public_key.as_bytes(),
            5555,
            &req_json,
        );

        let result =
            process_ticket_request(&req_packet, &server_id, &auth_store, &networks).unwrap();
        assert!(
            result.is_none(),
            "Replayed/stale request must be dropped silently"
        );
    }
}
