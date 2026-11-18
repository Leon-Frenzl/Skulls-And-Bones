//! Programmatic Mesh Client SDK & Virtual Stream API
//!
//! Ermöglicht Entwicklern die native, asynchrone Interaktion mit sovereignen
//! Mesh-Netzwerken sowie den gesicherten, policy-kontrollierten Datenaustausch
//! zwischen getrennten Meshes (z. B. `app-mesh` ➔ `database-mesh`).

use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use x25519_dalek::PublicKey;

use crate::acl::CapabilityToken;
use crate::bridge::{CrossMeshBridge, CrossMeshEnvelope, CrossMeshError, CrossMeshPayload};
use crate::crypto::{
    decrypt_payload, derive_session_keys, derive_swarm_tag, encrypt_payload, pack_message_v2,
    unpack_header_v2, PacketType, SessionKeys,
};
use crate::identity::NodeIdentity;
use crate::ticket::load_cached_ticket;

struct PendingConnect {
    target_mesh: String,
    expected_anchor_node_id: String,
    ack_tx: oneshot::Sender<Result<u64, CrossMeshError>>,
    data_tx: mpsc::Sender<Vec<u8>>,
    fec_control_tx: mpsc::Sender<FecSenderControl>,
}

struct ActiveStream {
    target_mesh: String,
    expected_anchor_node_id: String,
    data_tx: mpsc::Sender<Vec<u8>>,
    fec_receiver: tokio::sync::Mutex<crate::fec::StreamFecReceiver>,
    fec_control_tx: mpsc::Sender<FecSenderControl>,
    response_finished: bool,
    upload_finished: bool,
}

#[derive(Debug)]
enum FecSenderControl {
    Ack {
        block_id: u64,
    },
    Repair {
        block_id: u64,
        symbol_indices: Vec<u16>,
        repair_round: u8,
    },
}

async fn mark_active_stream_response_finished(
    streams: &RwLock<HashMap<u64, ActiveStream>>,
    session_id: u64,
) {
    let mut streams = streams.write().await;
    if let Some(stream) = streams.get_mut(&session_id) {
        stream.response_finished = true;
        if stream.upload_finished {
            streams.remove(&session_id);
        }
    }
}

async fn mark_active_stream_upload_finished(
    streams: &RwLock<HashMap<u64, ActiveStream>>,
    session_id: u64,
) {
    let mut streams = streams.write().await;
    if let Some(stream) = streams.get_mut(&session_id) {
        stream.upload_finished = true;
        if stream.response_finished {
            streams.remove(&session_id);
        }
    }
}

/// Konfiguration für einen programmatischen Mesh-Client
#[derive(Clone)]
pub struct MeshClientConfig {
    pub mesh_name: String,
    pub swarm_topic: String,
    pub anchor_addr: SocketAddr,
    pub identity: Arc<NodeIdentity>,
    pub local_bind_port: Option<u16>,
}

/// Bidirektionaler Virtual Stream über Netzwerkgrenzen hinweg (z. B. App-Mesh ➔ DB-Mesh)
///
/// Implementiert standardkonform `AsyncRead + AsyncWrite + Unpin` von Tokio,
/// sodass beliebige Protokolle (wie der `sb-db` Datenbank-Client) direkt darauf
/// aufsetzen können.
pub struct CrossMeshStream {
    pub session_id: u64,
    pub target_mesh: String,
    pub target_port: u16,
    io: tokio::io::DuplexStream,
    expected_write_bytes: Option<u64>,
    written_bytes: u64,
}

async fn read_fec_block<R>(
    reader: &mut R,
    buffer: &mut [u8],
    target_len: usize,
    fill_block: bool,
) -> io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    if !fill_block {
        return reader.read(&mut buffer[..target_len]).await;
    }

    let mut filled = 0;
    while filled < target_len {
        match reader.read(&mut buffer[filled..]).await? {
            0 => break,
            count => filled += count,
        }
    }
    Ok(filled)
}

async fn send_fec_symbol_network(
    socket: &UdpSocket,
    anchor_addr: SocketAddr,
    session_keys: &SessionKeys,
    send_counter: &AtomicU64,
    swarm_tag: &[u8; 8],
    sender_public_key: &[u8; 32],
    mesh_name: &str,
    node_id: &str,
    target_mesh_name: &str,
    session_id: u64,
    block_id: u64,
    symbol_index: usize,
    profile: crate::fec::FecProfile,
    original_len: usize,
    block_digest: [u8; 32],
    symbol: &crate::fec::CodedPacket,
) -> Result<(), CrossMeshError> {
    let envelope = CrossMeshEnvelope::new(
        mesh_name,
        node_id,
        target_mesh_name,
        None,
        CrossMeshPayload::StreamDataFec {
            session_id,
            block_id,
            symbol_index: symbol_index as u16,
            data_symbols: profile.data_symbols as u16,
            parity_symbols: profile.parity_symbols as u16,
            original_len: original_len as u32,
            block_digest,
            coefficients: symbol.coefficients.clone(),
            data: symbol.payload.clone(),
        },
    );
    MeshClient::send_network_envelope_parts(
        socket,
        anchor_addr,
        session_keys,
        send_counter,
        swarm_tag,
        sender_public_key,
        envelope,
    )
    .await
}

async fn send_fec_block_end_network(
    socket: &UdpSocket,
    anchor_addr: SocketAddr,
    session_keys: &SessionKeys,
    send_counter: &AtomicU64,
    swarm_tag: &[u8; 8],
    sender_public_key: &[u8; 32],
    mesh_name: &str,
    node_id: &str,
    target_mesh_name: &str,
    session_id: u64,
    block_id: u64,
    profile: crate::fec::FecProfile,
    original_len: usize,
    block_digest: [u8; 32],
) -> Result<(), CrossMeshError> {
    let envelope = CrossMeshEnvelope::new(
        mesh_name,
        node_id,
        target_mesh_name,
        None,
        CrossMeshPayload::StreamFecBlockEnd {
            session_id,
            block_id,
            data_symbols: profile.data_symbols as u16,
            parity_symbols: profile.parity_symbols as u16,
            original_len: original_len as u32,
            block_digest,
        },
    );
    MeshClient::send_network_envelope_parts(
        socket,
        anchor_addr,
        session_keys,
        send_counter,
        swarm_tag,
        sender_public_key,
        envelope,
    )
    .await
}

impl CrossMeshStream {
    pub fn new(
        session_id: u64,
        target_mesh: &str,
        target_port: u16,
        io: tokio::io::DuplexStream,
    ) -> Self {
        Self::new_with_expected_write_bytes(session_id, target_mesh, target_port, io, None)
    }

    fn new_with_expected_write_bytes(
        session_id: u64,
        target_mesh: &str,
        target_port: u16,
        io: tokio::io::DuplexStream,
        expected_write_bytes: Option<u64>,
    ) -> Self {
        Self {
            session_id,
            target_mesh: target_mesh.to_string(),
            target_port,
            io,
            expected_write_bytes,
            written_bytes: 0,
        }
    }

    /// Sendet Bytes über den Virtual Stream
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_all(data).await?;
        self.flush().await
    }

    /// Empfängt Bytes aus dem Virtual Stream
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.read(buf).await
    }
}

impl AsyncRead for CrossMeshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for CrossMeshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let write_buf = if let Some(expected) = self.expected_write_bytes {
            let remaining = expected.saturating_sub(self.written_bytes);
            if remaining == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cross-mesh transfer exceeded its declared byte length",
                )));
            }
            &buf[..buf.len().min(remaining.min(usize::MAX as u64) as usize)]
        } else {
            buf
        };
        match Pin::new(&mut self.io).poll_write(cx, write_buf) {
            Poll::Ready(Ok(written)) => {
                self.written_bytes = self.written_bytes.saturating_add(written as u64);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(expected) = self.expected_write_bytes {
            if self.written_bytes != expected {
                return match Pin::new(&mut self.io).poll_shutdown(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "Cross-mesh transfer ended after {} of {expected} declared bytes",
                            self.written_bytes
                        ),
                    ))),
                };
            }
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Der programmatische Mesh-Client für Anwendungen und Services
pub struct MeshClient {
    pub mesh_name: String,
    pub swarm_tag: [u8; 8],
    pub identity: Arc<NodeIdentity>,
    pub anchor_addr: Option<SocketAddr>,
    udp_socket: Option<Arc<UdpSocket>>,
    direct_bridge: Option<Arc<CrossMeshBridge>>,
    anchor_node_id: Option<String>,
    session_keys: Option<SessionKeys>,
    send_counter: Arc<AtomicU64>,
    active_streams: Arc<RwLock<HashMap<u64, ActiveStream>>>,
    pending_connect: Arc<Mutex<Option<PendingConnect>>>,
    connect_lock: Arc<Mutex<()>>,
}

impl MeshClient {
    /// Erstellt einen Client, der direkt über eine In-Memory Cross-Mesh Bridge angebunden ist
    pub fn with_bridge(
        mesh_name: &str,
        identity: Arc<NodeIdentity>,
        bridge: Arc<CrossMeshBridge>,
    ) -> Self {
        let swarm_tag = derive_swarm_tag(&format!("sbm-swarm-{}", mesh_name));
        Self {
            mesh_name: mesh_name.to_string(),
            swarm_tag,
            identity,
            anchor_addr: None,
            udp_socket: None,
            direct_bridge: Some(bridge),
            anchor_node_id: None,
            session_keys: None,
            send_counter: Arc::new(AtomicU64::new(1)),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            pending_connect: Arc::new(Mutex::new(None)),
            connect_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Verbindet einen Client über das Netzwerk mit einem Anchor Node (Single-Port UDP Dispatcher)
    pub async fn connect(config: MeshClientConfig) -> Result<Self, CrossMeshError> {
        let ticket = load_cached_ticket(&config.mesh_name).ok_or_else(|| {
            CrossMeshError::EndpointUnavailable(format!(
                "No valid cached mesh ticket for '{}'; join the mesh before connecting",
                config.mesh_name
            ))
        })?;
        let ticket_addr: SocketAddr = ticket.server_addr.parse().map_err(|error| {
            CrossMeshError::EndpointUnavailable(format!(
                "Invalid anchor address in cached ticket: {error}"
            ))
        })?;
        if ticket_addr != config.anchor_addr
            || !ticket
                .grant
                .granted_mesh
                .eq_ignore_ascii_case(&config.mesh_name)
        {
            return Err(CrossMeshError::EndpointUnavailable(
                "Cached mesh ticket does not match the configured mesh and anchor address"
                    .to_string(),
            ));
        }
        let anchor_key_bytes = base64::prelude::BASE64_STANDARD
            .decode(ticket.grant.server_pubkey.trim())
            .map_err(|error| {
                CrossMeshError::EndpointUnavailable(format!(
                    "Invalid anchor public key in cached ticket: {error}"
                ))
            })?;
        let anchor_key_bytes: [u8; 32] = anchor_key_bytes.try_into().map_err(|_| {
            CrossMeshError::EndpointUnavailable(
                "Cached anchor public key must contain exactly 32 bytes".to_string(),
            )
        })?;
        let anchor_public_key = PublicKey::from(anchor_key_bytes);
        if NodeIdentity::derive_node_id_from_pubkey(&ticket.grant.server_pubkey)
            != ticket.grant.server_node_id
        {
            return Err(CrossMeshError::EndpointUnavailable(
                "Cached anchor node ID does not match its pinned public key".to_string(),
            ));
        }
        Self::connect_with_anchor_pin(config, anchor_public_key, ticket.grant.server_node_id).await
    }

    /// Connects using an explicitly trusted anchor key and its expected node ID.
    pub async fn connect_with_anchor_pin(
        config: MeshClientConfig,
        anchor_public_key: PublicKey,
        anchor_node_id: String,
    ) -> Result<Self, CrossMeshError> {
        if NodeIdentity::derive_node_id_from_pubkey(
            &base64::prelude::BASE64_STANDARD.encode(anchor_public_key.as_bytes()),
        ) != anchor_node_id
        {
            return Err(CrossMeshError::EndpointUnavailable(
                "Configured anchor node ID does not match its pinned public key".to_string(),
            ));
        }
        let session_keys = derive_session_keys(&config.identity.secret, &anchor_public_key)
            .map_err(CrossMeshError::EndpointUnavailable)?;
        let bind_port = config.local_bind_port.unwrap_or(0);
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", bind_port))
            .await
            .map_err(|e| CrossMeshError::IoError(format!("Cannot bind UDP socket: {}", e)))?;

        let swarm_tag = derive_swarm_tag(&config.swarm_topic);
        let udp_socket = Arc::new(socket);

        let client = Self {
            mesh_name: config.mesh_name,
            swarm_tag,
            identity: config.identity,
            anchor_addr: Some(config.anchor_addr),
            udp_socket: Some(udp_socket.clone()),
            direct_bridge: None,
            anchor_node_id: Some(anchor_node_id.clone()),
            session_keys: Some(session_keys.clone()),
            send_counter: Arc::new(AtomicU64::new(1)),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            pending_connect: Arc::new(Mutex::new(None)),
            connect_lock: Arc::new(Mutex::new(())),
        };

        // Empfangs-Loop für eingehende UDP-Pakete starten
        let active_streams_bg = client.active_streams.clone();
        let pending_connect_bg = client.pending_connect.clone();
        let expected_tag = swarm_tag;
        let expected_mesh = client.mesh_name.clone();
        let anchor_addr = config.anchor_addr;
        let anchor_public_key = anchor_public_key.to_bytes();
        let receive_key = session_keys.receive.clone();
        let send_keys = session_keys.clone();
        let send_counter_bg = client.send_counter.clone();
        let client_node_id = client.identity.node_id.clone();
        let client_public_key = *client.identity.public_key.as_bytes();

        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            let mut replay_window = crate::anti_replay::AntiReplayWindow::new();
            loop {
                match udp_socket.recv_from(&mut buf).await {
                    Ok((len, sender)) => {
                        if sender != anchor_addr {
                            continue;
                        }
                        let Ok((ptype, tag, sender_key, counter, payload)) =
                            unpack_header_v2(&buf[..len])
                        else {
                            continue;
                        };
                        if ptype != PacketType::Data
                            || tag != expected_tag
                            || sender_key != anchor_public_key
                            || !replay_window.check(counter)
                        {
                            continue;
                        }
                        let Ok(plaintext) =
                            decrypt_payload(receive_key.as_bytes(), counter, payload)
                        else {
                            continue;
                        };
                        replay_window.update(counter);
                        let Ok(envelope) = CrossMeshEnvelope::decode(&plaintext) else {
                            continue;
                        };
                        if !envelope.target_mesh.eq_ignore_ascii_case(&expected_mesh)
                            || envelope.source_node_id != anchor_node_id
                        {
                            continue;
                        }
                        match envelope.payload {
                            CrossMeshPayload::StreamAck { session_id } => {
                                let mut pending = pending_connect_bg.lock().await;
                                let valid_pending = pending.as_ref().is_some_and(|connect| {
                                    connect
                                        .target_mesh
                                        .eq_ignore_ascii_case(&envelope.source_mesh)
                                        && connect.expected_anchor_node_id
                                            == envelope.source_node_id
                                });
                                if valid_pending {
                                    if let Some(connect) = pending.take() {
                                        active_streams_bg.write().await.insert(
                                            session_id,
                                            ActiveStream {
                                                target_mesh: connect.target_mesh,
                                                expected_anchor_node_id: connect
                                                    .expected_anchor_node_id,
                                                data_tx: connect.data_tx,
                                                fec_control_tx: connect.fec_control_tx,
                                                fec_receiver: tokio::sync::Mutex::new(
                                                    crate::fec::StreamFecReceiver::default(),
                                                ),
                                                response_finished: false,
                                                upload_finished: false,
                                            },
                                        );
                                        let _ = connect.ack_tx.send(Ok(session_id));
                                    }
                                }
                            }
                            CrossMeshPayload::StreamData {
                                session_id, data, ..
                            } => {
                                let streams = active_streams_bg.read().await;
                                if let Some(stream) = streams.get(&session_id) {
                                    if stream
                                        .target_mesh
                                        .eq_ignore_ascii_case(&envelope.source_mesh)
                                        && stream.expected_anchor_node_id == envelope.source_node_id
                                    {
                                        let _ = stream.data_tx.send(data).await;
                                    }
                                }
                            }
                            CrossMeshPayload::StreamDataFec {
                                session_id,
                                block_id,
                                symbol_index,
                                data_symbols,
                                parity_symbols,
                                original_len,
                                block_digest,
                                coefficients,
                                data,
                            } => {
                                let decoded = {
                                    let streams = active_streams_bg.read().await;
                                    if let Some(stream) = streams.get(&session_id) {
                                        if stream
                                            .target_mesh
                                            .eq_ignore_ascii_case(&envelope.source_mesh)
                                            && stream.expected_anchor_node_id
                                                == envelope.source_node_id
                                        {
                                            let mut receiver = stream.fec_receiver.lock().await;
                                            Some(
                                                match receiver.add_indexed_symbol(
                                                    block_id,
                                                    Some(symbol_index as usize),
                                                    data_symbols as usize,
                                                    parity_symbols as usize,
                                                    original_len as usize,
                                                    block_digest,
                                                    crate::fec::CodedPacket::new(
                                                        coefficients,
                                                        data,
                                                    ),
                                                ) {
                                                    Ok(blocks) => Ok((
                                                        stream.data_tx.clone(),
                                                        blocks,
                                                        receiver.is_finished(),
                                                    )),
                                                    Err(error) => Err(error),
                                                },
                                            )
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                };
                                if let Some(decoded) = decoded {
                                    match decoded {
                                        Ok((data_tx, blocks, finished)) => {
                                            for block in blocks {
                                                let _ = data_tx.send(block).await;
                                            }
                                            if finished {
                                                mark_active_stream_response_finished(
                                                    &active_streams_bg,
                                                    session_id,
                                                )
                                                .await;
                                            }
                                        }
                                        Err(error) => {
                                            eprintln!(
                                                "Cross-mesh FEC stream {session_id} rejected a symbol: {error}"
                                            );
                                            active_streams_bg.write().await.remove(&session_id);
                                        }
                                    }
                                }
                            }
                            CrossMeshPayload::StreamFecBlockEnd {
                                session_id,
                                block_id,
                                data_symbols,
                                parity_symbols,
                                original_len,
                                block_digest,
                            } => {
                                let repair = {
                                    let streams = active_streams_bg.read().await;
                                    if let Some(stream) = streams.get(&session_id) {
                                        if stream
                                            .target_mesh
                                            .eq_ignore_ascii_case(&envelope.source_mesh)
                                            && stream.expected_anchor_node_id
                                                == envelope.source_node_id
                                        {
                                            Some(
                                                stream
                                                    .fec_receiver
                                                    .lock()
                                                    .await
                                                    .missing_symbol_indices(
                                                        block_id,
                                                        data_symbols as usize,
                                                        parity_symbols as usize,
                                                        original_len as usize,
                                                        block_digest,
                                                    ),
                                            )
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                };
                                let response = match repair {
                                    Some(Ok(None)) => Some(CrossMeshPayload::StreamFecBlockAck {
                                        session_id,
                                        block_id,
                                        origin_node_id: envelope.source_node_id.clone(),
                                    }),
                                    Some(Ok(Some((symbol_indices, repair_round)))) => {
                                        Some(CrossMeshPayload::StreamFecRepairRequest {
                                            session_id,
                                            block_id,
                                            origin_node_id: envelope.source_node_id.clone(),
                                            symbol_indices,
                                            repair_round,
                                        })
                                    }
                                    Some(Err(error)) => {
                                        eprintln!(
                                            "Cross-mesh FEC block {block_id} repair failed: {error}"
                                        );
                                        active_streams_bg.write().await.remove(&session_id);
                                        Some(CrossMeshPayload::StreamClose { session_id })
                                    }
                                    None => None,
                                };
                                if let Some(payload) = response {
                                    let response = CrossMeshEnvelope::new(
                                        &expected_mesh,
                                        &client_node_id,
                                        &envelope.source_mesh,
                                        None,
                                        payload,
                                    );
                                    if let Err(error) = MeshClient::send_network_envelope_parts(
                                        &udp_socket,
                                        anchor_addr,
                                        &send_keys,
                                        &send_counter_bg,
                                        &expected_tag,
                                        &client_public_key,
                                        response,
                                    )
                                    .await
                                    {
                                        eprintln!(
                                            "Cross-mesh FEC block response send failed: {error}"
                                        );
                                    }
                                }
                            }
                            CrossMeshPayload::StreamFecBlockAck {
                                session_id,
                                block_id,
                                origin_node_id,
                            } => {
                                let streams = active_streams_bg.read().await;
                                if let Some(stream) = streams.get(&session_id) {
                                    if stream
                                        .target_mesh
                                        .eq_ignore_ascii_case(&envelope.source_mesh)
                                        && stream.expected_anchor_node_id == envelope.source_node_id
                                        && origin_node_id == client_node_id
                                    {
                                        let _ = stream
                                            .fec_control_tx
                                            .send(FecSenderControl::Ack { block_id })
                                            .await;
                                    }
                                }
                            }
                            CrossMeshPayload::StreamFecRepairRequest {
                                session_id,
                                block_id,
                                origin_node_id,
                                symbol_indices,
                                repair_round,
                            } => {
                                let streams = active_streams_bg.read().await;
                                if let Some(stream) = streams.get(&session_id) {
                                    if stream
                                        .target_mesh
                                        .eq_ignore_ascii_case(&envelope.source_mesh)
                                        && stream.expected_anchor_node_id == envelope.source_node_id
                                        && origin_node_id == client_node_id
                                    {
                                        if !crate::fec::is_valid_stream_fec_repair_request(
                                            &symbol_indices,
                                            repair_round,
                                        ) {
                                            eprintln!(
                                                "Cross-mesh FEC stream {session_id} rejected an invalid repair request"
                                            );
                                            continue;
                                        }
                                        let _ = stream
                                            .fec_control_tx
                                            .send(FecSenderControl::Repair {
                                                block_id,
                                                symbol_indices,
                                                repair_round,
                                            })
                                            .await;
                                    }
                                }
                            }
                            CrossMeshPayload::StreamClose { session_id } => {
                                let mut streams = active_streams_bg.write().await;
                                if streams.get(&session_id).is_some_and(|stream| {
                                    stream
                                        .target_mesh
                                        .eq_ignore_ascii_case(&envelope.source_mesh)
                                        && stream.expected_anchor_node_id == envelope.source_node_id
                                }) {
                                    if let Some(stream) = streams.get_mut(&session_id) {
                                        stream.response_finished = true;
                                        if stream.upload_finished {
                                            streams.remove(&session_id);
                                        }
                                    }
                                }
                            }
                            CrossMeshPayload::StreamCloseFec {
                                session_id,
                                final_block_id,
                                stream_digest,
                            } => {
                                let finish_state = {
                                    let streams = active_streams_bg.read().await;
                                    if let Some(stream) = streams.get(&session_id) {
                                        if stream
                                            .target_mesh
                                            .eq_ignore_ascii_case(&envelope.source_mesh)
                                            && stream.expected_anchor_node_id
                                                == envelope.source_node_id
                                        {
                                            Some(
                                                stream
                                                    .fec_receiver
                                                    .lock()
                                                    .await
                                                    .mark_finished(final_block_id, stream_digest),
                                            )
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                };
                                match finish_state {
                                    Some(Ok(true)) => {
                                        mark_active_stream_response_finished(
                                            &active_streams_bg,
                                            session_id,
                                        )
                                        .await;
                                    }
                                    Some(Ok(false)) => {
                                        let streams = active_streams_bg.clone();
                                        tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_secs(5)).await;
                                            let mut streams = streams.write().await;
                                            if let Some(stream) = streams.get(&session_id) {
                                                if !stream.fec_receiver.lock().await.is_finished() {
                                                    eprintln!(
                                                        "Cross-mesh FEC stream {session_id} closed with missing blocks"
                                                    );
                                                    streams.remove(&session_id);
                                                }
                                            }
                                        });
                                    }
                                    Some(Err(error)) => {
                                        eprintln!(
                                            "Cross-mesh FEC stream {session_id} close rejected: {error}"
                                        );
                                        active_streams_bg.write().await.remove(&session_id);
                                    }
                                    None => {}
                                }
                            }
                            CrossMeshPayload::Error { message } => {
                                let mut pending = pending_connect_bg.lock().await;
                                let valid_pending = pending.as_ref().is_some_and(|connect| {
                                    connect
                                        .target_mesh
                                        .eq_ignore_ascii_case(&envelope.source_mesh)
                                        && connect.expected_anchor_node_id
                                            == envelope.source_node_id
                                });
                                if valid_pending {
                                    if let Some(connect) = pending.take() {
                                        let _ = connect
                                            .ack_tx
                                            .send(Err(CrossMeshError::PolicyViolation(message)));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });

        Ok(client)
    }

    /// Öffnet einen bidirektionalen Virtual Stream in ein Ziel-Mesh (z. B. database-mesh auf Port 58830)
    pub async fn open_cross_mesh_stream(
        &self,
        target_mesh: &str,
        target_port: u16,
        token: Option<CapabilityToken>,
    ) -> Result<CrossMeshStream, CrossMeshError> {
        self.open_cross_mesh_stream_with_profile(
            target_mesh,
            target_port,
            token,
            crate::fec::FecProfile::DEFAULT,
            None,
        )
        .await
    }

    /// Opens a size-declared upload using the default 10% loss estimate and 0.1% failure budget.
    ///
    /// `expected_bytes` is the exact number of bytes the caller must write in this direction.
    /// The reverse direction uses the negotiated profile but has no transfer-wide guarantee.
    pub async fn open_cross_mesh_transfer(
        &self,
        target_mesh: &str,
        target_port: u16,
        token: Option<CapabilityToken>,
        expected_bytes: u64,
    ) -> Result<CrossMeshStream, CrossMeshError> {
        self.open_cross_mesh_transfer_with_policy(
            target_mesh,
            target_port,
            token,
            expected_bytes,
            crate::fec::STREAM_FEC_DEFAULT_ESTIMATED_LOSS_PPM,
            crate::fec::STREAM_FEC_DEFAULT_TARGET_FAILURE_PPM,
        )
        .await
    }

    /// Opens a size-declared upload with caller-supplied independent-loss and failure estimates.
    ///
    /// Loss and target are parts per million. Burst loss is not covered by the probability model.
    pub async fn open_cross_mesh_transfer_with_policy(
        &self,
        target_mesh: &str,
        target_port: u16,
        token: Option<CapabilityToken>,
        expected_bytes: u64,
        estimated_loss_ppm: u32,
        target_failure_ppm: u32,
    ) -> Result<CrossMeshStream, CrossMeshError> {
        let profile = crate::fec::FecProfile::select_for_transfer(
            expected_bytes,
            estimated_loss_ppm,
            target_failure_ppm,
        )
        .map_err(CrossMeshError::SerializationError)?;
        self.open_cross_mesh_stream_with_profile(
            target_mesh,
            target_port,
            token,
            profile,
            Some(expected_bytes),
        )
        .await
    }

    async fn open_cross_mesh_stream_with_profile(
        &self,
        target_mesh: &str,
        target_port: u16,
        token: Option<CapabilityToken>,
        fec_profile: crate::fec::FecProfile,
        expected_bytes: Option<u64>,
    ) -> Result<CrossMeshStream, CrossMeshError> {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let negotiate_fec_profile = expected_bytes.is_some();

        if let Some(bridge) = &self.direct_bridge {
            let envelope = CrossMeshEnvelope::new(
                &self.mesh_name,
                &self.identity.node_id,
                target_mesh,
                token,
                if negotiate_fec_profile {
                    CrossMeshPayload::StreamConnectFec {
                        target_port,
                        data_symbols: fec_profile.data_symbols as u16,
                        parity_symbols: fec_profile.parity_symbols as u16,
                    }
                } else {
                    CrossMeshPayload::StreamConnect { target_port }
                },
            );

            let (ack_tx, ack_rx) = oneshot::channel::<Result<u64, CrossMeshError>>();
            let ack_tx_cell = Arc::new(tokio::sync::Mutex::new(Some(ack_tx)));
            let (to_client_tx, mut to_client_rx) = mpsc::channel::<Vec<u8>>(2048);
            let (fec_control_tx, mut fec_control_rx) = mpsc::channel(16);
            let to_client_tx_cell = Arc::new(to_client_tx);

            let ack_cb = ack_tx_cell.clone();
            let to_client_cb = to_client_tx_cell.clone();
            let fec_control_cb = fec_control_tx.clone();
            let local_node_id = self.identity.node_id.clone();

            let reply_sink = move |resp_env: CrossMeshEnvelope| match resp_env.payload {
                CrossMeshPayload::StreamAck { session_id } => {
                    let cell = ack_cb.clone();
                    tokio::spawn(async move {
                        let mut lock = cell.lock().await;
                        if let Some(tx) = lock.take() {
                            let _ = tx.send(Ok(session_id));
                        }
                    });
                }
                CrossMeshPayload::StreamData { data, .. } => {
                    let client_tx = to_client_cb.clone();
                    tokio::spawn(async move {
                        let _ = client_tx.send(data).await;
                    });
                }
                CrossMeshPayload::Error { message } => {
                    let cell = ack_cb.clone();
                    tokio::spawn(async move {
                        let mut lock = cell.lock().await;
                        if let Some(tx) = lock.take() {
                            let _ = tx.send(Err(CrossMeshError::PolicyViolation(message)));
                        }
                    });
                }
                CrossMeshPayload::StreamFecBlockAck {
                    block_id,
                    origin_node_id,
                    ..
                } if origin_node_id == local_node_id => {
                    let control = fec_control_cb.clone();
                    tokio::spawn(async move {
                        let _ = control.send(FecSenderControl::Ack { block_id }).await;
                    });
                }
                CrossMeshPayload::StreamFecRepairRequest {
                    block_id,
                    origin_node_id,
                    symbol_indices,
                    repair_round,
                    ..
                } if origin_node_id == local_node_id
                    && crate::fec::is_valid_stream_fec_repair_request(
                        &symbol_indices,
                        repair_round,
                    ) =>
                {
                    let control = fec_control_cb.clone();
                    tokio::spawn(async move {
                        let _ = control
                            .send(FecSenderControl::Repair {
                                block_id,
                                symbol_indices,
                                repair_round,
                            })
                            .await;
                    });
                }
                _ => {}
            };

            bridge
                .process_authenticated_envelope(
                    envelope,
                    &self.identity.wireguard_pubkey,
                    reply_sink,
                )
                .await?;

            let session_id = tokio::time::timeout(Duration::from_secs(3), ack_rx)
                .await
                .map_err(|_| CrossMeshError::EndpointUnavailable("Handshake timeout".to_string()))?
                .map_err(|_| {
                    CrossMeshError::EndpointUnavailable("Handshake dropped".to_string())
                })??;

            // Pump data from server_io to bridge, and from to_client_rx to server_io
            let (mut s_read, mut s_write) = tokio::io::split(server_io);
            let bridge_clone = bridge.clone();
            let src_mesh = self.mesh_name.clone();
            let tgt_mesh = target_mesh.to_string();
            let src_node_id = self.identity.node_id.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; fec_profile.max_block_bytes()];
                let mut block_id = 1u64;
                let mut remaining_bytes = expected_bytes;
                let mut stream_hasher = Sha256::new();
                let mut stream_aborted = false;
                loop {
                    let target_len = remaining_bytes
                        .map(|remaining| remaining.min(buf.len() as u64) as usize)
                        .unwrap_or(buf.len());
                    if target_len == 0 {
                        break;
                    }
                    match read_fec_block(
                        &mut s_read,
                        &mut buf,
                        target_len,
                        remaining_bytes.is_some(),
                    )
                    .await
                    {
                        Ok(0) => {
                            stream_aborted = remaining_bytes.is_some_and(|remaining| remaining > 0);
                            break;
                        }
                        Ok(n) => {
                            if let Some(remaining) = &mut remaining_bytes {
                                *remaining = remaining.saturating_sub(n as u64);
                            }
                            let payload = &buf[..n];
                            stream_hasher.update(payload);
                            let block_digest =
                                crate::fec::stream_fec_block_digest(block_id, payload);
                            let encoder =
                                crate::fec::FecEncoder::new(payload, fec_profile.data_symbols);
                            let symbols = encoder.generate_fec_block(fec_profile.parity_symbols);
                            let mut pending_symbols = (0..symbols.len()).collect::<Vec<usize>>();
                            let mut repair_round = 0u8;
                            let mut block_acked = false;
                            while repair_round <= crate::fec::STREAM_FEC_MAX_REPAIR_ROUNDS {
                                for symbol_index in std::mem::take(&mut pending_symbols) {
                                    let symbol = &symbols[symbol_index];
                                    let data_env = CrossMeshEnvelope::new(
                                        &src_mesh,
                                        &src_node_id,
                                        &tgt_mesh,
                                        None,
                                        CrossMeshPayload::StreamDataFec {
                                            session_id,
                                            block_id,
                                            symbol_index: symbol_index as u16,
                                            data_symbols: fec_profile.data_symbols as u16,
                                            parity_symbols: fec_profile.parity_symbols as u16,
                                            original_len: n as u32,
                                            block_digest,
                                            coefficients: symbol.coefficients.clone(),
                                            data: symbol.payload.clone(),
                                        },
                                    );
                                    if let Err(error) =
                                        bridge_clone.process_envelope(data_env, |_| {}).await
                                    {
                                        eprintln!(
                                        "Direct cross-mesh FEC stream {session_id} aborted: {error}"
                                    );
                                        stream_aborted = true;
                                        break;
                                    }
                                }
                                if stream_aborted {
                                    break;
                                }
                                let block_end = CrossMeshEnvelope::new(
                                    &src_mesh,
                                    &src_node_id,
                                    &tgt_mesh,
                                    None,
                                    CrossMeshPayload::StreamFecBlockEnd {
                                        session_id,
                                        block_id,
                                        data_symbols: fec_profile.data_symbols as u16,
                                        parity_symbols: fec_profile.parity_symbols as u16,
                                        original_len: n as u32,
                                        block_digest,
                                    },
                                );
                                if let Err(error) =
                                    bridge_clone.process_envelope(block_end, |_| {}).await
                                {
                                    eprintln!(
                                        "Direct cross-mesh FEC block {block_id} close failed: {error}"
                                    );
                                    stream_aborted = true;
                                    break;
                                }
                                match tokio::time::timeout(
                                    Duration::from_millis(250u64 << repair_round.min(3)),
                                    fec_control_rx.recv(),
                                )
                                .await
                                {
                                    Ok(Some(FecSenderControl::Ack {
                                        block_id: acked_block,
                                    })) if acked_block == block_id => {
                                        block_acked = true;
                                        break;
                                    }
                                    Ok(Some(FecSenderControl::Repair {
                                        block_id: requested_block,
                                        symbol_indices,
                                        repair_round: requested_round,
                                    })) if requested_block == block_id => {
                                        if requested_round
                                            > crate::fec::STREAM_FEC_MAX_REPAIR_ROUNDS
                                        {
                                            stream_aborted = true;
                                            break;
                                        }
                                        repair_round = requested_round;
                                        for index in symbol_indices {
                                            let index = index as usize;
                                            if index >= symbols.len() {
                                                stream_aborted = true;
                                                break;
                                            }
                                            pending_symbols.push(index);
                                        }
                                    }
                                    Ok(Some(_)) => continue,
                                    Ok(None) => {
                                        stream_aborted = true;
                                        break;
                                    }
                                    Err(_) => {
                                        repair_round = repair_round.saturating_add(1);
                                        pending_symbols = (0..symbols.len()).collect();
                                    }
                                }
                                if stream_aborted {
                                    break;
                                }
                            }
                            if stream_aborted || !block_acked {
                                stream_aborted = true;
                                break;
                            }
                            block_id = match block_id.checked_add(1) {
                                Some(next) => next,
                                None => {
                                    stream_aborted = true;
                                    break;
                                }
                            };
                            if (remaining_bytes.is_some() && n < target_len)
                                || remaining_bytes == Some(0)
                            {
                                stream_aborted =
                                    remaining_bytes.is_some_and(|remaining| remaining > 0);
                                break;
                            }
                        }
                        Err(error) => {
                            eprintln!(
                                "Direct cross-mesh FEC stream {session_id} read failed: {error}"
                            );
                            stream_aborted = true;
                            break;
                        }
                    }
                }
                let close_payload = if stream_aborted {
                    eprintln!("Direct cross-mesh FEC stream {session_id} closed incomplete");
                    CrossMeshPayload::StreamClose { session_id }
                } else {
                    CrossMeshPayload::StreamCloseFec {
                        session_id,
                        final_block_id: block_id.saturating_sub(1),
                        stream_digest: stream_hasher.clone().finalize().into(),
                    }
                };
                let close_env =
                    CrossMeshEnvelope::new(&src_mesh, &src_node_id, &tgt_mesh, None, close_payload);
                if let Err(error) = bridge_clone.process_envelope(close_env, |_| {}).await {
                    eprintln!("Direct cross-mesh stream {session_id} close failed: {error}");
                }
            });

            tokio::spawn(async move {
                while let Some(chunk) = to_client_rx.recv().await {
                    if s_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            });

            Ok(CrossMeshStream::new_with_expected_write_bytes(
                session_id,
                target_mesh,
                target_port,
                client_io,
                expected_bytes,
            ))
        } else if self.udp_socket.is_some() && self.anchor_addr.is_some() {
            let _connect_guard = self.connect_lock.lock().await;
            let (ack_tx, ack_rx) = oneshot::channel();
            let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(2048);
            let (fec_control_tx, mut fec_control_rx) = mpsc::channel(16);
            let anchor_node_id = self.anchor_node_id.clone().ok_or_else(|| {
                CrossMeshError::EndpointUnavailable("Anchor identity is not configured".to_string())
            })?;
            *self.pending_connect.lock().await = Some(PendingConnect {
                target_mesh: target_mesh.to_string(),
                expected_anchor_node_id: anchor_node_id,
                ack_tx,
                data_tx,
                fec_control_tx,
            });

            let connect = CrossMeshEnvelope::new(
                &self.mesh_name,
                &self.identity.node_id,
                target_mesh,
                token,
                if negotiate_fec_profile {
                    CrossMeshPayload::StreamConnectFec {
                        target_port,
                        data_symbols: fec_profile.data_symbols as u16,
                        parity_symbols: fec_profile.parity_symbols as u16,
                    }
                } else {
                    CrossMeshPayload::StreamConnect { target_port }
                },
            );
            if let Err(error) = self.send_network_envelope(connect).await {
                self.pending_connect.lock().await.take();
                return Err(error);
            }

            let session_id = match tokio::time::timeout(Duration::from_secs(3), ack_rx).await {
                Ok(Ok(Ok(session_id))) => session_id,
                Ok(Ok(Err(error))) => return Err(error),
                Ok(Err(_)) => {
                    self.pending_connect.lock().await.take();
                    return Err(CrossMeshError::EndpointUnavailable(
                        "Anchor dropped the stream handshake".to_string(),
                    ));
                }
                Err(_) => {
                    self.pending_connect.lock().await.take();
                    return Err(CrossMeshError::EndpointUnavailable(
                        "Stream handshake timed out".to_string(),
                    ));
                }
            };

            let (mut stream_read, mut stream_write) = tokio::io::split(server_io);
            let socket = self
                .udp_socket
                .as_ref()
                .expect("network socket checked")
                .clone();
            let anchor_addr = self.anchor_addr.expect("network anchor checked");
            let mesh_name = self.mesh_name.clone();
            let target_mesh_name = target_mesh.to_string();
            let node_id = self.identity.node_id.clone();
            let sender_public_key = *self.identity.public_key.as_bytes();
            let swarm_tag = self.swarm_tag;
            let send_counter = self.send_counter.clone();
            let active_streams = self.active_streams.clone();
            let active_streams_writer = active_streams.clone();
            let session_keys = self
                .session_keys
                .as_ref()
                .ok_or_else(|| {
                    CrossMeshError::EndpointUnavailable(
                        "Anchor session keys are unavailable".to_string(),
                    )
                })?
                .clone();

            tokio::spawn(async move {
                while let Some(chunk) = data_rx.recv().await {
                    if stream_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                active_streams_writer.write().await.remove(&session_id);
            });

            tokio::spawn(async move {
                let mut buf = vec![0u8; fec_profile.max_block_bytes()];
                let mut block_id = 1u64;
                let mut final_block_id = 0u64;
                let mut remaining_bytes = expected_bytes;
                let mut stream_hasher = Sha256::new();
                let mut stream_aborted = false;
                loop {
                    let target_len = remaining_bytes
                        .map(|remaining| remaining.min(buf.len() as u64) as usize)
                        .unwrap_or(buf.len());
                    if target_len == 0 {
                        break;
                    }
                    let count = match read_fec_block(
                        &mut stream_read,
                        &mut buf,
                        target_len,
                        remaining_bytes.is_some(),
                    )
                    .await
                    {
                        Ok(0) => {
                            stream_aborted = remaining_bytes.is_some_and(|remaining| remaining > 0);
                            break;
                        }
                        Ok(count) => count,
                        Err(error) => {
                            eprintln!("Cross-mesh FEC stream {session_id} read failed: {error}");
                            stream_aborted = true;
                            break;
                        }
                    };
                    if let Some(remaining) = &mut remaining_bytes {
                        *remaining = remaining.saturating_sub(count as u64);
                    }

                    let block_digest = crate::fec::stream_fec_block_digest(block_id, &buf[..count]);
                    let encoder =
                        crate::fec::FecEncoder::new(&buf[..count], fec_profile.data_symbols);
                    let symbols = encoder.generate_fec_block(fec_profile.parity_symbols);
                    let mut block_acked = false;
                    let mut repair_round = 0u8;
                    let mut pending_symbols = (0..symbols.len()).collect::<Vec<_>>();
                    while repair_round <= crate::fec::STREAM_FEC_MAX_REPAIR_ROUNDS {
                        for symbol_index in std::mem::take(&mut pending_symbols) {
                            if let Err(error) = send_fec_symbol_network(
                                &socket,
                                anchor_addr,
                                &session_keys,
                                &send_counter,
                                &swarm_tag,
                                &sender_public_key,
                                &mesh_name,
                                &node_id,
                                &target_mesh_name,
                                session_id,
                                block_id,
                                symbol_index,
                                fec_profile,
                                count,
                                block_digest,
                                &symbols[symbol_index],
                            )
                            .await
                            {
                                eprintln!(
                                    "Cross-mesh FEC stream {session_id} symbol send failed: {error}"
                                );
                                stream_aborted = true;
                                break;
                            }
                        }
                        if stream_aborted {
                            break;
                        }
                        if let Err(error) = send_fec_block_end_network(
                            &socket,
                            anchor_addr,
                            &session_keys,
                            &send_counter,
                            &swarm_tag,
                            &sender_public_key,
                            &mesh_name,
                            &node_id,
                            &target_mesh_name,
                            session_id,
                            block_id,
                            fec_profile,
                            count,
                            block_digest,
                        )
                        .await
                        {
                            eprintln!(
                                "Cross-mesh FEC stream {session_id} block-end send failed: {error}"
                            );
                            stream_aborted = true;
                            break;
                        }
                        let wait = Duration::from_millis(250u64 << repair_round.min(3));
                        match tokio::time::timeout(wait, fec_control_rx.recv()).await {
                            Ok(Some(FecSenderControl::Ack {
                                block_id: acked_block,
                            })) if acked_block == block_id => {
                                block_acked = true;
                                break;
                            }
                            Ok(Some(FecSenderControl::Repair {
                                block_id: requested_block,
                                symbol_indices,
                                repair_round: requested_round,
                            })) if requested_block == block_id => {
                                if requested_round > crate::fec::STREAM_FEC_MAX_REPAIR_ROUNDS {
                                    stream_aborted = true;
                                    break;
                                }
                                repair_round = requested_round;
                                for index in symbol_indices {
                                    let index = index as usize;
                                    if index >= symbols.len() {
                                        stream_aborted = true;
                                        break;
                                    }
                                    pending_symbols.push(index);
                                }
                            }
                            Ok(Some(_)) => continue,
                            Ok(None) => {
                                stream_aborted = true;
                                break;
                            }
                            Err(_) => {
                                repair_round = repair_round.saturating_add(1);
                                pending_symbols = (0..symbols.len()).collect();
                            }
                        }
                        if stream_aborted {
                            break;
                        }
                    }
                    if stream_aborted || !block_acked {
                        stream_aborted = true;
                        break;
                    }
                    final_block_id = block_id;
                    stream_hasher.update(&buf[..count]);
                    if (remaining_bytes.is_some() && count < target_len)
                        || remaining_bytes == Some(0)
                    {
                        stream_aborted = remaining_bytes.is_some_and(|remaining| remaining > 0);
                        break;
                    }
                    match block_id.checked_add(1) {
                        Some(next) => block_id = next,
                        None => {
                            stream_aborted = true;
                            break;
                        }
                    }
                }
                let close_payload = if stream_aborted {
                    CrossMeshPayload::StreamClose { session_id }
                } else {
                    CrossMeshPayload::StreamCloseFec {
                        session_id,
                        final_block_id,
                        stream_digest: stream_hasher.clone().finalize().into(),
                    }
                };
                let close = CrossMeshEnvelope::new(
                    &mesh_name,
                    &node_id,
                    &target_mesh_name,
                    None,
                    close_payload,
                );
                if let Err(error) = Self::send_network_envelope_parts(
                    &socket,
                    anchor_addr,
                    &session_keys,
                    &send_counter,
                    &swarm_tag,
                    &sender_public_key,
                    close,
                )
                .await
                {
                    eprintln!("Cross-mesh stream {session_id} close send failed: {error}");
                }
                mark_active_stream_upload_finished(&active_streams, session_id).await;
            });

            Ok(CrossMeshStream::new_with_expected_write_bytes(
                session_id,
                target_mesh,
                target_port,
                client_io,
                expected_bytes,
            ))
        } else {
            Err(CrossMeshError::EndpointUnavailable(
                "Neither direct bridge nor anchor address configured".to_string(),
            ))
        }
    }

    async fn send_network_envelope(
        &self,
        envelope: CrossMeshEnvelope,
    ) -> Result<(), CrossMeshError> {
        let socket = self.udp_socket.as_ref().ok_or_else(|| {
            CrossMeshError::EndpointUnavailable("UDP socket is unavailable".to_string())
        })?;
        let anchor_addr = self.anchor_addr.ok_or_else(|| {
            CrossMeshError::EndpointUnavailable("Anchor address is unavailable".to_string())
        })?;
        let session_keys = self.session_keys.as_ref().ok_or_else(|| {
            CrossMeshError::EndpointUnavailable("Anchor session keys are unavailable".to_string())
        })?;
        Self::send_network_envelope_parts(
            socket,
            anchor_addr,
            session_keys,
            &self.send_counter,
            &self.swarm_tag,
            self.identity.public_key.as_bytes(),
            envelope,
        )
        .await
    }

    async fn send_network_envelope_parts(
        socket: &UdpSocket,
        anchor_addr: SocketAddr,
        session_keys: &SessionKeys,
        send_counter: &AtomicU64,
        swarm_tag: &[u8; 8],
        sender_public_key: &[u8; 32],
        envelope: CrossMeshEnvelope,
    ) -> Result<(), CrossMeshError> {
        // CVE-Threat: Unauthenticated or misrouted UDP replies could expose or inject stream data.
        // Analysis: The client derives directional keys from its identity and the pinned ticket key,
        // while receive processing checks both the anchor address and public key before decryption.
        // Hardening: Authenticate every envelope with AEAD and refuse counter wrap before nonce reuse.
        let counter = send_counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                CrossMeshError::EndpointUnavailable("Anchor packet counter exhausted".to_string())
            })?;
        let serialized = envelope.encode();
        let encrypted = encrypt_payload(session_keys.send.as_bytes(), counter, &serialized)
            .map_err(CrossMeshError::IoError)?;
        let packet = pack_message_v2(
            PacketType::Data,
            swarm_tag,
            sender_public_key,
            counter,
            &encrypted,
        );
        let sent = socket
            .send_to(&packet, anchor_addr)
            .await
            .map_err(|error| CrossMeshError::IoError(error.to_string()))?;
        if sent != packet.len() {
            return Err(CrossMeshError::IoError(
                "UDP socket accepted only part of the encrypted packet".to_string(),
            ));
        }
        Ok(())
    }

    /// Sendet ein einmaliges Datagramm / RPC über den Cross-Mesh Bridge
    pub async fn send_cross_mesh_datagram(
        &self,
        target_mesh: &str,
        target_port: u16,
        data: Vec<u8>,
        token: Option<CapabilityToken>,
    ) -> Result<Vec<u8>, CrossMeshError> {
        if let Some(bridge) = &self.direct_bridge {
            let envelope = CrossMeshEnvelope::new(
                &self.mesh_name,
                &self.identity.node_id,
                target_mesh,
                token,
                CrossMeshPayload::Datagram { target_port, data },
            );

            let (tx, rx) = oneshot::channel::<Result<Vec<u8>, CrossMeshError>>();
            let tx_cell = Arc::new(tokio::sync::Mutex::new(Some(tx)));

            let reply_sink = move |resp_env: CrossMeshEnvelope| {
                let cell = tx_cell.clone();
                tokio::spawn(async move {
                    let mut lock = cell.lock().await;
                    if let Some(tx) = lock.take() {
                        match resp_env.payload {
                            CrossMeshPayload::DatagramReply { data } => {
                                let _ = tx.send(Ok(data));
                            }
                            CrossMeshPayload::Error { message } => {
                                let _ = tx.send(Err(CrossMeshError::PolicyViolation(message)));
                            }
                            _ => {}
                        }
                    }
                });
            };

            bridge.process_envelope(envelope, reply_sink).await?;

            tokio::time::timeout(Duration::from_secs(5), rx)
                .await
                .map_err(|_| {
                    CrossMeshError::EndpointUnavailable("RPC response timeout".to_string())
                })?
                .map_err(|_| {
                    CrossMeshError::EndpointUnavailable("RPC channel closed".to_string())
                })?
        } else {
            Err(CrossMeshError::EndpointUnavailable(
                "Datagram RPC currently supported via direct bridge".to_string(),
            ))
        }
    }
}
