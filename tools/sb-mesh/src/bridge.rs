//! Cross-Mesh Bridge & Policy Engine
//!
//! Ermöglicht die sichere, streng policy- und capability-kontrollierte Datenkommunikation
//! zwischen voneinander isolierten Mesh-Netzwerken (z. B. `app-mesh` und `database-mesh`),
//! welche am selben Sovereign Anchor Node konvergieren.
//!
//! Zero Cross-Talk Garantie:
//! - Kein L3/ARP-Leck zwischen den Swarms
//! - Striktes Port- und Capability-Whitelisting via Ristretto255/Schnorr Token
//! - Vollständige Mandantentrennung im RAM

use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};

use crate::acl::CapabilityToken;

mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::prelude::BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        base64::prelude::BASE64_STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

/// Standard Magic-Byte für Cross-Mesh Bridge Envelopes
pub const CROSS_MESH_MAGIC: [u8; 4] = [0x53, 0x42, 0x58, 0x4D]; // "SBXM"
pub const CROSS_MESH_VERSION: u8 = 3;

/// Mögliche Fehler bei Cross-Mesh Operationen
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CrossMeshError {
    PolicyViolation(String),
    TokenMissing,
    TokenExpired,
    TokenInvalid(String),
    UnauthorizedPort(u16),
    TargetMeshNotFound(String),
    EndpointUnavailable(String),
    SessionNotFound(u64),
    SerializationError(String),
    IoError(String),
}

impl std::fmt::Display for CrossMeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrossMeshError::PolicyViolation(msg) => {
                write!(f, "Cross-Mesh Policy Violation: {}", msg)
            }
            CrossMeshError::TokenMissing => {
                write!(f, "Capability token required for cross-mesh bridge")
            }
            CrossMeshError::TokenExpired => write!(f, "Capability token has expired"),
            CrossMeshError::TokenInvalid(msg) => write!(f, "Invalid capability token: {}", msg),
            CrossMeshError::UnauthorizedPort(port) => write!(
                f,
                "Target port {} is not authorized by cross-mesh policy",
                port
            ),
            CrossMeshError::TargetMeshNotFound(mesh) => {
                write!(f, "Target mesh '{}' not found on anchor", mesh)
            }
            CrossMeshError::EndpointUnavailable(msg) => {
                write!(f, "Service endpoint unavailable: {}", msg)
            }
            CrossMeshError::SessionNotFound(id) => {
                write!(f, "Cross-mesh stream session #{} not found", id)
            }
            CrossMeshError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            CrossMeshError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for CrossMeshError {}

/// Autorisierungsregel für den Datenaustausch zwischen zwei isolierten Meshes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossMeshRule {
    pub rule_id: String,
    /// Quell-Mesh (z. B. "app-mesh" oder "*" für alle)
    pub source_mesh: String,
    /// Ziel-Mesh (z. B. "database-mesh")
    pub target_mesh: String,
    /// Erlaubte Zielports (z. B. [58830] für sb-db)
    pub allowed_ports: Vec<u16>,
    /// Ob ein kryptografisches Schnorr Capability-Token zwingend erforderlich ist
    pub require_capability_token: bool,
    /// Menschenlesbare Beschreibung des Einsatzzwecks
    pub description: String,
}

impl CrossMeshRule {
    pub fn new(
        rule_id: &str,
        source_mesh: &str,
        target_mesh: &str,
        allowed_ports: Vec<u16>,
        require_capability_token: bool,
        description: &str,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            source_mesh: source_mesh.to_string(),
            target_mesh: target_mesh.to_string(),
            allowed_ports,
            require_capability_token,
            description: description.to_string(),
        }
    }

    /// Prüft, ob diese Regel auf die gegebene Route und den Port zutrifft
    pub fn matches(&self, source: &str, target: &str, port: u16) -> bool {
        let src_match = self.source_mesh == "*" || self.source_mesh.eq_ignore_ascii_case(source);
        let tgt_match = self.target_mesh.eq_ignore_ascii_case(target);
        let port_match = self.allowed_ports.is_empty() || self.allowed_ports.contains(&port);
        src_match && tgt_match && port_match
    }
}

/// Zentrale Cross-Mesh Policy Engine auf dem konvergierenden Anchor Node
#[derive(Debug, Clone)]
pub struct CrossMeshPolicy {
    pub rules: Vec<CrossMeshRule>,
    pub default_deny: bool,
}

impl Default for CrossMeshPolicy {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_deny: true,
        }
    }
}

impl CrossMeshPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: CrossMeshRule) {
        self.rules.push(rule);
    }

    /// Überprüft, ob eine Anfrage zwischen zwei Meshes autorisiert ist
    pub fn evaluate(
        &self,
        source_mesh: &str,
        target_mesh: &str,
        target_port: u16,
        token: Option<&CapabilityToken>,
        current_epoch: u64,
    ) -> Result<(), CrossMeshError> {
        // Suche passende Regel
        let matching_rule = self.rules.iter().find(|r| {
            let src_ok = r.source_mesh == "*" || r.source_mesh.eq_ignore_ascii_case(source_mesh);
            let tgt_ok = r.target_mesh.eq_ignore_ascii_case(target_mesh);
            src_ok && tgt_ok
        });

        let rule = match matching_rule {
            Some(r) => r,
            None => {
                if self.default_deny {
                    return Err(CrossMeshError::PolicyViolation(format!(
                        "No route allowed from mesh '{}' to mesh '{}'",
                        source_mesh, target_mesh
                    )));
                } else {
                    return Ok(());
                }
            }
        };

        // Port-Prüfung
        if !rule.allowed_ports.is_empty() && !rule.allowed_ports.contains(&target_port) {
            return Err(CrossMeshError::UnauthorizedPort(target_port));
        }

        // Capability Token Prüfung falls vorgeschrieben
        if rule.require_capability_token {
            let cap_token = token.ok_or(CrossMeshError::TokenMissing)?;
            cap_token
                .verify(current_epoch)
                .map_err(CrossMeshError::TokenInvalid)?;

            if !cap_token.allowed_ports.is_empty()
                && !cap_token.allowed_ports.contains(&target_port)
            {
                return Err(CrossMeshError::UnauthorizedPort(target_port));
            }
        } else if let Some(cap_token) = token {
            // Falls freiwillig übergeben, trotzdem Signatur prüfen
            cap_token
                .verify(current_epoch)
                .map_err(CrossMeshError::TokenInvalid)?;
        }

        Ok(())
    }
}

/// Nutzlast eines Cross-Mesh Pakets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CrossMeshPayload {
    /// Initialer Verbindungsaufbau zu einem Service im Ziel-Mesh
    StreamConnect { target_port: u16 },
    /// Bulk-stream setup with an explicitly selected bounded FEC profile.
    StreamConnectFec {
        target_port: u16,
        data_symbols: u16,
        parity_symbols: u16,
    },
    /// Bestätigung des Anchor Nodes, dass die Verbindung zum Ziel-Mesh steht
    StreamAck { session_id: u64 },
    /// Sequenzierte Datenübertragung im Virtual Stream
    StreamData {
        session_id: u64,
        seq: u32,
        data: Vec<u8>,
    },
    /// FEC symbol; the block digest is verified after decoding, and the symbol is mesh-AEAD protected.
    StreamDataFec {
        session_id: u64,
        block_id: u64,
        symbol_index: u16,
        data_symbols: u16,
        parity_symbols: u16,
        original_len: u32,
        block_digest: [u8; 32],
        #[serde(with = "base64_bytes")]
        coefficients: Vec<u8>,
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    /// Marks the end of the initial symbol batch for one FEC block.
    StreamFecBlockEnd {
        session_id: u64,
        block_id: u64,
        data_symbols: u16,
        parity_symbols: u16,
        original_len: u32,
        block_digest: [u8; 32],
    },
    /// Acknowledges successful decoding and integrity validation of one FEC block.
    StreamFecBlockAck {
        session_id: u64,
        block_id: u64,
        origin_node_id: String,
    },
    /// Requests bounded selective retransmission of missing symbol indexes.
    StreamFecRepairRequest {
        session_id: u64,
        block_id: u64,
        origin_node_id: String,
        symbol_indices: Vec<u16>,
        repair_round: u8,
    },
    /// Sauberes Schließen des Streams
    StreamClose { session_id: u64 },
    /// Close after ordered reconstruction and verification of the complete stream digest.
    StreamCloseFec {
        session_id: u64,
        final_block_id: u64,
        stream_digest: [u8; 32],
    },
    /// Einmalige RPC / Datagram Übertragung ohne persistenten Stream
    Datagram { target_port: u16, data: Vec<u8> },
    /// Antwort auf ein Datagram
    DatagramReply { data: Vec<u8> },
    /// Fehlermeldung bei Richtlinienverletzung oder Verbindungsabbruch
    Error { message: String },
}

/// Übertragungs-Umschlag (Envelope) für Cross-Mesh Datagramme über den Anchor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossMeshEnvelope {
    pub magic: [u8; 4],
    pub version: u8,
    pub source_mesh: String,
    pub source_node_id: String,
    pub target_mesh: String,
    pub token: Option<CapabilityToken>,
    pub payload: CrossMeshPayload,
}

impl CrossMeshEnvelope {
    pub fn new(
        source_mesh: &str,
        source_node_id: &str,
        target_mesh: &str,
        token: Option<CapabilityToken>,
        payload: CrossMeshPayload,
    ) -> Self {
        Self {
            magic: CROSS_MESH_MAGIC,
            version: CROSS_MESH_VERSION,
            source_mesh: source_mesh.to_string(),
            source_node_id: source_node_id.to_string(),
            target_mesh: target_mesh.to_string(),
            token,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CrossMeshError> {
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|e| CrossMeshError::SerializationError(e.to_string()))?;
        if envelope.magic != CROSS_MESH_MAGIC {
            return Err(CrossMeshError::SerializationError(
                "Invalid magic header".to_string(),
            ));
        }
        if envelope.version != CROSS_MESH_VERSION {
            return Err(CrossMeshError::SerializationError(format!(
                "Unsupported cross-mesh envelope version {}",
                envelope.version
            )));
        }
        Ok(envelope)
    }
}

/// Typ des Ziel-Dienstes im Ziel-Mesh
#[derive(Clone)]
pub enum ServiceEndpoint {
    /// Lokaler Loopback TCP-Service auf dem Anchor (z. B. sb-db auf 127.0.0.1:58830)
    LocalTcp(SocketAddr),
    /// TCP service that receives the verified Mesh source identity before payload bytes.
    LocalTcpWithIdentity(SocketAddr),
    /// In-Memory Sender für direkte asynchrone Weiterleitung
    InMemory(mpsc::Sender<CrossMeshEnvelope>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MeshStreamIdentity {
    pub source_mesh: String,
    pub source_node_id: String,
    pub source_public_key: String,
}

/// Telemetrie und Audit-Statistik des Cross-Mesh Bridges
#[derive(Debug, Clone, Default)]
pub struct BridgeStats {
    pub total_envelopes: u64,
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub datagrams_forwarded: u64,
    pub policy_violations: u64,
    pub tokens_rejected: u64,
    pub bytes_forwarded: u64,
}

struct ActiveBridgeStream {
    source_mesh: String,
    source_node_id: String,
    target_mesh: String,
    target_port: u16,
    data_tx: mpsc::Sender<Vec<u8>>,
    fec_receiver: tokio::sync::Mutex<crate::fec::StreamFecReceiver>,
    reply_sink: Arc<dyn Fn(CrossMeshEnvelope) + Send + Sync>,
}

/// Der Cross-Mesh Bridge Router auf dem Anchor Node
pub struct CrossMeshBridge {
    pub anchor_node_id: String,
    pub policy: Arc<RwLock<CrossMeshPolicy>>,
    endpoints: Arc<RwLock<HashMap<(String, u16), ServiceEndpoint>>>,
    active_streams: Arc<RwLock<HashMap<u64, ActiveBridgeStream>>>,
    next_session_id: AtomicU64,
    pub stats: Arc<RwLock<BridgeStats>>,
}

impl CrossMeshBridge {
    pub fn new(anchor_node_id: &str) -> Self {
        let initial_session = (Utc::now().timestamp_millis() as u64 & 0x00FF_FFFF) + 1000;
        Self {
            anchor_node_id: anchor_node_id.to_string(),
            policy: Arc::new(RwLock::new(CrossMeshPolicy::new())),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            next_session_id: AtomicU64::new(initial_session),
            stats: Arc::new(RwLock::new(BridgeStats::default())),
        }
    }

    pub async fn active_stream_target_port(
        &self,
        session_id: u64,
        source_mesh: &str,
        source_node_id: &str,
    ) -> Option<u16> {
        self.active_streams
            .read()
            .await
            .get(&session_id)
            .filter(|stream| {
                stream.source_mesh.eq_ignore_ascii_case(source_mesh)
                    && stream.source_node_id == source_node_id
            })
            .map(|stream| stream.target_port)
    }

    pub async fn abort_stream_for_peer(
        &self,
        session_id: u64,
        source_mesh: &str,
        source_node_id: &str,
    ) -> bool {
        let stream = {
            let mut streams = self.active_streams.write().await;
            let matches_peer = streams.get(&session_id).is_some_and(|stream| {
                stream.source_mesh.eq_ignore_ascii_case(source_mesh)
                    && stream.source_node_id == source_node_id
            });
            matches_peer.then(|| streams.remove(&session_id)).flatten()
        };
        let Some(stream) = stream else {
            return false;
        };

        (stream.reply_sink)(CrossMeshEnvelope::new(
            &stream.target_mesh,
            &self.anchor_node_id,
            &stream.source_mesh,
            None,
            CrossMeshPayload::StreamClose { session_id },
        ));
        self.stats.write().await.streams_closed += 1;
        true
    }

    /// Registriert einen Ziel-Service für ein bestimmtes Mesh und Port
    pub async fn register_service(&self, mesh_name: &str, port: u16, endpoint: ServiceEndpoint) {
        let mut ep = self.endpoints.write().await;
        ep.insert((mesh_name.to_lowercase(), port), endpoint);
    }

    /// Entfernt einen registrierten Service
    pub async fn unregister_service(&self, mesh_name: &str, port: u16) {
        let mut ep = self.endpoints.write().await;
        ep.remove(&(mesh_name.to_lowercase(), port));
    }

    /// Verarbeitet ein eingehendes Cross-Mesh Paket vom Quell-Mesh
    pub async fn process_envelope<F>(
        &self,
        envelope: CrossMeshEnvelope,
        reply_sink: F,
    ) -> Result<(), CrossMeshError>
    where
        F: Fn(CrossMeshEnvelope) + Send + Sync + 'static,
    {
        self.process_envelope_inner(envelope, None, reply_sink)
            .await
    }

    pub async fn process_authenticated_envelope<F>(
        &self,
        envelope: CrossMeshEnvelope,
        source_public_key: &str,
        reply_sink: F,
    ) -> Result<(), CrossMeshError>
    where
        F: Fn(CrossMeshEnvelope) + Send + Sync + 'static,
    {
        self.process_envelope_inner(envelope, Some(source_public_key), reply_sink)
            .await
    }

    async fn process_envelope_inner<F>(
        &self,
        envelope: CrossMeshEnvelope,
        authenticated_source_public_key: Option<&str>,
        reply_sink: F,
    ) -> Result<(), CrossMeshError>
    where
        F: Fn(CrossMeshEnvelope) + Send + Sync + 'static,
    {
        if envelope.magic != CROSS_MESH_MAGIC || envelope.version != CROSS_MESH_VERSION {
            return Err(CrossMeshError::SerializationError(
                "Invalid cross-mesh envelope header".to_string(),
            ));
        }
        {
            let mut st = self.stats.write().await;
            st.total_envelopes += 1;
        }

        let now = Utc::now().timestamp() as u64;

        // 1. Richtlinienauswertung
        let target_port = match &envelope.payload {
            CrossMeshPayload::StreamConnect { target_port } => *target_port,
            CrossMeshPayload::StreamConnectFec {
                target_port,
                data_symbols,
                parity_symbols,
            } => {
                if !crate::fec::FecProfile::is_supported(
                    *data_symbols as usize,
                    *parity_symbols as usize,
                ) {
                    return Err(CrossMeshError::SerializationError(
                        "Unsupported stream FEC profile".to_string(),
                    ));
                }
                *target_port
            }
            CrossMeshPayload::Datagram { target_port, .. } => *target_port,
            CrossMeshPayload::StreamData {
                session_id, data, ..
            } => {
                // Bei StreamData ist die Autorisierung bereits beim Connect erfolgt
                return self
                    .handle_stream_data(
                        *session_id,
                        &envelope.source_mesh,
                        &envelope.source_node_id,
                        data,
                    )
                    .await;
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
                return self
                    .handle_stream_fec_symbol(
                        *session_id,
                        &envelope.source_mesh,
                        &envelope.source_node_id,
                        *block_id,
                        *symbol_index as usize,
                        *data_symbols as usize,
                        *parity_symbols as usize,
                        *original_len as usize,
                        *block_digest,
                        crate::fec::CodedPacket::new(coefficients.clone(), data.clone()),
                    )
                    .await;
            }
            CrossMeshPayload::StreamFecBlockEnd {
                session_id,
                block_id,
                data_symbols,
                parity_symbols,
                original_len,
                block_digest,
            } => {
                let (repair, stream_reply_sink) = {
                    let streams = self.active_streams.read().await;
                    let stream = streams
                        .get(session_id)
                        .filter(|stream| {
                            stream
                                .source_mesh
                                .eq_ignore_ascii_case(&envelope.source_mesh)
                                && stream.source_node_id == envelope.source_node_id
                        })
                        .ok_or(CrossMeshError::SessionNotFound(*session_id))?;
                    let result = stream.fec_receiver.lock().await.missing_symbol_indices(
                        *block_id,
                        *data_symbols as usize,
                        *parity_symbols as usize,
                        *original_len as usize,
                        *block_digest,
                    );
                    (result, stream.reply_sink.clone())
                };
                match repair {
                    Ok(None) => stream_reply_sink(CrossMeshEnvelope::new(
                        &envelope.target_mesh,
                        &self.anchor_node_id,
                        &envelope.source_mesh,
                        None,
                        CrossMeshPayload::StreamFecBlockAck {
                            session_id: *session_id,
                            block_id: *block_id,
                            origin_node_id: envelope.source_node_id.clone(),
                        },
                    )),
                    Ok(Some((symbol_indices, repair_round))) => {
                        stream_reply_sink(CrossMeshEnvelope::new(
                            &envelope.target_mesh,
                            &self.anchor_node_id,
                            &envelope.source_mesh,
                            None,
                            CrossMeshPayload::StreamFecRepairRequest {
                                session_id: *session_id,
                                block_id: *block_id,
                                origin_node_id: envelope.source_node_id.clone(),
                                symbol_indices,
                                repair_round,
                            },
                        ));
                    }
                    Err(error) => {
                        self.active_streams.write().await.remove(session_id);
                        self.stats.write().await.streams_closed += 1;
                        stream_reply_sink(CrossMeshEnvelope::new(
                            &envelope.target_mesh,
                            &self.anchor_node_id,
                            &envelope.source_mesh,
                            None,
                            CrossMeshPayload::Error {
                                message: error.clone(),
                            },
                        ));
                        return Err(CrossMeshError::SerializationError(error));
                    }
                }
                return Ok(());
            }
            CrossMeshPayload::StreamFecBlockAck { session_id, .. } => {
                let streams = self.active_streams.read().await;
                let stream_reply_sink = streams.get(session_id).and_then(|stream| {
                    (stream
                        .source_mesh
                        .eq_ignore_ascii_case(&envelope.source_mesh)
                        && stream.source_node_id == envelope.source_node_id)
                        .then(|| stream.reply_sink.clone())
                });
                let Some(stream_reply_sink) = stream_reply_sink else {
                    return Err(CrossMeshError::SessionNotFound(*session_id));
                };
                stream_reply_sink(envelope);
                return Ok(());
            }
            CrossMeshPayload::StreamFecRepairRequest {
                session_id,
                symbol_indices,
                repair_round,
                ..
            } => {
                if !crate::fec::is_valid_stream_fec_repair_request(symbol_indices, *repair_round) {
                    return Err(CrossMeshError::SerializationError(
                        "Invalid FEC repair request".to_string(),
                    ));
                }
                let streams = self.active_streams.read().await;
                let stream_reply_sink = streams.get(session_id).and_then(|stream| {
                    (stream
                        .source_mesh
                        .eq_ignore_ascii_case(&envelope.source_mesh)
                        && stream.source_node_id == envelope.source_node_id)
                        .then(|| stream.reply_sink.clone())
                });
                let Some(stream_reply_sink) = stream_reply_sink else {
                    return Err(CrossMeshError::SessionNotFound(*session_id));
                };
                stream_reply_sink(envelope);
                return Ok(());
            }
            CrossMeshPayload::StreamClose { session_id } => {
                let mut streams = self.active_streams.write().await;
                let authorized = streams.get(session_id).is_some_and(|stream| {
                    stream
                        .source_mesh
                        .eq_ignore_ascii_case(&envelope.source_mesh)
                        && stream.source_node_id == envelope.source_node_id
                });
                if !authorized {
                    return Err(CrossMeshError::SessionNotFound(*session_id));
                }
                streams.remove(session_id);
                let mut st = self.stats.write().await;
                st.streams_closed += 1;
                return Ok(());
            }
            CrossMeshPayload::StreamCloseFec {
                session_id,
                final_block_id,
                stream_digest,
            } => {
                let mut streams = self.active_streams.write().await;
                let stream = streams
                    .get(session_id)
                    .filter(|stream| {
                        stream
                            .source_mesh
                            .eq_ignore_ascii_case(&envelope.source_mesh)
                            && stream.source_node_id == envelope.source_node_id
                    })
                    .ok_or(CrossMeshError::SessionNotFound(*session_id))?;
                let finish_result = stream
                    .fec_receiver
                    .lock()
                    .await
                    .mark_finished(*final_block_id, *stream_digest);
                match finish_result {
                    Ok(true) => {
                        streams.remove(session_id);
                        self.stats.write().await.streams_closed += 1;
                    }
                    Ok(false) => {
                        let active = self.active_streams.clone();
                        let stats = self.stats.clone();
                        let session_id = *session_id;
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            let mut streams = active.write().await;
                            if let Some(stream) = streams.get(&session_id) {
                                if !stream.fec_receiver.lock().await.is_finished() {
                                    eprintln!(
                                        "Cross-mesh FEC stream {session_id} closed with missing blocks"
                                    );
                                    streams.remove(&session_id);
                                    stats.write().await.streams_closed += 1;
                                }
                            }
                        });
                    }
                    Err(error) => {
                        streams.remove(session_id);
                        self.stats.write().await.streams_closed += 1;
                        return Err(CrossMeshError::SerializationError(error));
                    }
                }
                return Ok(());
            }
            _ => return Ok(()),
        };

        let policy = self.policy.read().await;
        if let Err(err) = policy.evaluate(
            &envelope.source_mesh,
            &envelope.target_mesh,
            target_port,
            envelope.token.as_ref(),
            now,
        ) {
            let mut st = self.stats.write().await;
            st.policy_violations += 1;
            if matches!(
                err,
                CrossMeshError::TokenInvalid(_)
                    | CrossMeshError::TokenMissing
                    | CrossMeshError::TokenExpired
            ) {
                st.tokens_rejected += 1;
            }

            reply_sink(CrossMeshEnvelope::new(
                &envelope.target_mesh,
                &self.anchor_node_id,
                &envelope.source_mesh,
                None,
                CrossMeshPayload::Error {
                    message: format!("{}", err),
                },
            ));
            return Err(err);
        }
        drop(policy);

        // 2. Finde registrierten Service-Endpoint
        let endpoints = self.endpoints.read().await;
        let endpoint = endpoints
            .get(&(envelope.target_mesh.to_lowercase(), target_port))
            .cloned();
        drop(endpoints);

        let endpoint = match endpoint {
            Some(ep) => ep,
            None => {
                let err = CrossMeshError::EndpointUnavailable(format!(
                    "No service registered in mesh '{}' on port {}",
                    envelope.target_mesh, target_port
                ));
                reply_sink(CrossMeshEnvelope::new(
                    &envelope.target_mesh,
                    &self.anchor_node_id,
                    &envelope.source_mesh,
                    None,
                    CrossMeshPayload::Error {
                        message: format!("{}", err),
                    },
                ));
                return Err(err);
            }
        };

        // 3. Routing ausführen
        match envelope.payload.clone() {
            CrossMeshPayload::StreamConnect { target_port } => {
                self.handle_stream_connect(
                    envelope,
                    target_port,
                    crate::fec::FecProfile::DEFAULT,
                    authenticated_source_public_key,
                    endpoint,
                    reply_sink,
                )
                .await
            }
            CrossMeshPayload::StreamConnectFec {
                target_port,
                data_symbols,
                parity_symbols,
            } => {
                let fec_profile = crate::fec::FecProfile {
                    data_symbols: data_symbols as usize,
                    parity_symbols: parity_symbols as usize,
                };
                self.handle_stream_connect(
                    envelope,
                    target_port,
                    fec_profile,
                    authenticated_source_public_key,
                    endpoint,
                    reply_sink,
                )
                .await
            }
            CrossMeshPayload::Datagram { target_port, data } => {
                self.handle_datagram(envelope, target_port, data, endpoint, reply_sink)
                    .await
            }
            _ => Ok(()),
        }
    }

    async fn handle_stream_connect<F>(
        &self,
        envelope: CrossMeshEnvelope,
        _target_port: u16,
        fec_profile: crate::fec::FecProfile,
        authenticated_source_public_key: Option<&str>,
        endpoint: ServiceEndpoint,
        reply_sink: F,
    ) -> Result<(), CrossMeshError>
    where
        F: Fn(CrossMeshEnvelope) + Send + Sync + 'static,
    {
        let reply_sink = Arc::new(reply_sink);
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let inject_identity = matches!(&endpoint, ServiceEndpoint::LocalTcpWithIdentity(_));

        match endpoint {
            ServiceEndpoint::LocalTcp(addr) | ServiceEndpoint::LocalTcpWithIdentity(addr) => {
                let stream_res =
                    tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await;
                let mut tcp_stream = match stream_res {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        reply_sink(CrossMeshEnvelope::new(
                            &envelope.target_mesh,
                            &self.anchor_node_id,
                            &envelope.source_mesh,
                            None,
                            CrossMeshPayload::Error {
                                message: format!(
                                    "Cannot connect to local service on {}: {}",
                                    addr, e
                                ),
                            },
                        ));
                        return Err(CrossMeshError::EndpointUnavailable(e.to_string()));
                    }
                    Err(_) => {
                        reply_sink(CrossMeshEnvelope::new(
                            &envelope.target_mesh,
                            &self.anchor_node_id,
                            &envelope.source_mesh,
                            None,
                            CrossMeshPayload::Error {
                                message: format!("Connection timeout to service on {}", addr),
                            },
                        ));
                        return Err(CrossMeshError::EndpointUnavailable(
                            "Connection timeout".to_string(),
                        ));
                    }
                };
                if inject_identity {
                    let source_public_key = authenticated_source_public_key.ok_or_else(|| {
                        CrossMeshError::PolicyViolation(
                            "Authenticated peer key required by this service".into(),
                        )
                    })?;
                    let decoded_key = base64::engine::general_purpose::STANDARD
                        .decode(source_public_key)
                        .map_err(|error| {
                            CrossMeshError::SerializationError(format!(
                                "Invalid authenticated peer public key: {error}"
                            ))
                        })?;
                    if decoded_key.len() != 32
                        || crate::identity::NodeIdentity::derive_node_id_from_pubkey(
                            source_public_key,
                        ) != envelope.source_node_id
                    {
                        return Err(CrossMeshError::PolicyViolation(
                            "Authenticated peer key does not match the stream identity".into(),
                        ));
                    }
                    let identity = MeshStreamIdentity {
                        source_mesh: envelope.source_mesh.clone(),
                        source_node_id: envelope.source_node_id.clone(),
                        source_public_key: source_public_key.to_string(),
                    };
                    let identity_bytes = serde_json::to_vec(&identity)
                        .map_err(|error| CrossMeshError::SerializationError(error.to_string()))?;
                    if identity_bytes.len() > 4096 {
                        return Err(CrossMeshError::SerializationError(
                            "Authenticated stream identity exceeds the local protocol limit".into(),
                        ));
                    }
                    let identity_len = u32::try_from(identity_bytes.len()).map_err(|_| {
                        CrossMeshError::SerializationError(
                            "Authenticated stream identity is too large".into(),
                        )
                    })?;
                    tcp_stream
                        .write_u32(identity_len)
                        .await
                        .map_err(|error| CrossMeshError::EndpointUnavailable(error.to_string()))?;
                    tcp_stream
                        .write_all(&identity_bytes)
                        .await
                        .map_err(|error| CrossMeshError::EndpointUnavailable(error.to_string()))?;
                }

                // Stream ACK zurück zum Quell-Mesh
                reply_sink(CrossMeshEnvelope::new(
                    &envelope.target_mesh,
                    &self.anchor_node_id,
                    &envelope.source_mesh,
                    None,
                    CrossMeshPayload::StreamAck { session_id },
                ));

                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2048);
                {
                    let mut streams = self.active_streams.write().await;
                    streams.insert(
                        session_id,
                        ActiveBridgeStream {
                            source_mesh: envelope.source_mesh.clone(),
                            source_node_id: envelope.source_node_id.clone(),
                            target_mesh: envelope.target_mesh.clone(),
                            target_port: _target_port,
                            data_tx: tx,
                            fec_receiver: tokio::sync::Mutex::new(
                                crate::fec::StreamFecReceiver::default(),
                            ),
                            reply_sink: reply_sink.clone(),
                        },
                    );
                }

                {
                    let mut st = self.stats.write().await;
                    st.streams_opened += 1;
                }

                let src_mesh = envelope.source_mesh.clone();
                let tgt_mesh = envelope.target_mesh.clone();
                let anchor_id = self.anchor_node_id.clone();
                let active_cleanup = self.active_streams.clone();
                let stats_cleanup = self.stats.clone();
                let sink_arc = reply_sink.clone();

                // Bidirektionales Proxying zwischen TCP Service und Cross-Mesh Virtual Stream
                tokio::spawn(async move {
                    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
                    let mut tcp_buf = vec![0u8; fec_profile.max_block_bytes()];
                    let mut seq_out = 1u32;
                    let mut final_block_id = 0u64;
                    let mut response_hasher = Sha256::new();
                    let sink_read = sink_arc.clone();
                    let src_mesh_read = src_mesh.clone();
                    let tgt_mesh_read = tgt_mesh.clone();
                    let anchor_read = anchor_id.clone();

                    let read_task = tokio::spawn(async move {
                        loop {
                            match tcp_read.read(&mut tcp_buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    response_hasher.update(&tcp_buf[..n]);
                                    sink_read(CrossMeshEnvelope::new(
                                        &tgt_mesh_read,
                                        &anchor_read,
                                        &src_mesh_read,
                                        None,
                                        CrossMeshPayload::StreamData {
                                            session_id,
                                            seq: seq_out,
                                            data: tcp_buf[..n].to_vec(),
                                        },
                                    ));
                                    final_block_id = seq_out as u64;
                                    match seq_out.checked_add(1) {
                                        Some(next) => seq_out = next,
                                        None => break,
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        sink_read(CrossMeshEnvelope::new(
                            &tgt_mesh_read,
                            &anchor_read,
                            &src_mesh_read,
                            None,
                            CrossMeshPayload::StreamCloseFec {
                                session_id,
                                final_block_id,
                                stream_digest: response_hasher.clone().finalize().into(),
                            },
                        ));
                    });

                    let write_task = tokio::spawn(async move {
                        while let Some(chunk) = rx.recv().await {
                            if tcp_write.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                    });

                    let mut read_handle = read_task;
                    let mut write_handle = write_task;

                    tokio::select! {
                        _ = &mut read_handle => {
                            write_handle.abort();
                        }
                        _ = &mut write_handle => {
                            read_handle.abort();
                        }
                    };

                    let removed = active_cleanup.write().await.remove(&session_id).is_some();
                    if removed {
                        stats_cleanup.write().await.streams_closed += 1;
                    }
                });

                Ok(())
            }
            ServiceEndpoint::InMemory(forwarder) => {
                reply_sink(CrossMeshEnvelope::new(
                    &envelope.target_mesh,
                    &self.anchor_node_id,
                    &envelope.source_mesh,
                    None,
                    CrossMeshPayload::StreamAck { session_id },
                ));

                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2048);
                {
                    let mut streams = self.active_streams.write().await;
                    streams.insert(
                        session_id,
                        ActiveBridgeStream {
                            source_mesh: envelope.source_mesh.clone(),
                            source_node_id: envelope.source_node_id.clone(),
                            target_mesh: envelope.target_mesh.clone(),
                            target_port: _target_port,
                            data_tx: tx,
                            fec_receiver: tokio::sync::Mutex::new(
                                crate::fec::StreamFecReceiver::default(),
                            ),
                            reply_sink: reply_sink.clone(),
                        },
                    );
                }

                let forward_envelope = CrossMeshEnvelope::new(
                    &envelope.source_mesh,
                    &envelope.source_node_id,
                    &envelope.target_mesh,
                    envelope.token.clone(),
                    match envelope.payload {
                        CrossMeshPayload::StreamConnectFec {
                            data_symbols,
                            parity_symbols,
                            ..
                        } => CrossMeshPayload::StreamConnectFec {
                            target_port: _target_port,
                            data_symbols,
                            parity_symbols,
                        },
                        _ => CrossMeshPayload::StreamConnect {
                            target_port: _target_port,
                        },
                    },
                );
                let _ = forwarder.send(forward_envelope).await;

                let fwd_copy = forwarder.clone();
                let active_cleanup = self.active_streams.clone();

                tokio::spawn(async move {
                    while let Some(data) = rx.recv().await {
                        let env = CrossMeshEnvelope::new(
                            &envelope.source_mesh,
                            &envelope.source_node_id,
                            &envelope.target_mesh,
                            None,
                            CrossMeshPayload::StreamData {
                                session_id,
                                seq: 0,
                                data,
                            },
                        );
                        if fwd_copy.send(env).await.is_err() {
                            break;
                        }
                    }
                    let mut streams = active_cleanup.write().await;
                    streams.remove(&session_id);
                });

                Ok(())
            }
        }
    }

    async fn handle_stream_data(
        &self,
        session_id: u64,
        source_mesh: &str,
        source_node_id: &str,
        data: &[u8],
    ) -> Result<(), CrossMeshError> {
        let sender = {
            let streams = self.active_streams.read().await;
            let stream = streams
                .get(&session_id)
                .filter(|stream| {
                    stream.source_mesh.eq_ignore_ascii_case(source_mesh)
                        && stream.source_node_id == source_node_id
                })
                .ok_or(CrossMeshError::SessionNotFound(session_id))?;
            stream.data_tx.clone()
        };
        sender
            .send(data.to_vec())
            .await
            .map_err(|_| CrossMeshError::SessionNotFound(session_id))?;
        let mut stats = self.stats.write().await;
        stats.bytes_forwarded += data.len() as u64;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_stream_fec_symbol(
        &self,
        session_id: u64,
        source_mesh: &str,
        source_node_id: &str,
        block_id: u64,
        symbol_index: usize,
        data_symbols: usize,
        parity_symbols: usize,
        original_len: usize,
        block_digest: [u8; 32],
        packet: crate::fec::CodedPacket,
    ) -> Result<(), CrossMeshError> {
        let decoded = {
            let streams = self.active_streams.read().await;
            let stream = streams
                .get(&session_id)
                .filter(|stream| {
                    stream.source_mesh.eq_ignore_ascii_case(source_mesh)
                        && stream.source_node_id == source_node_id
                })
                .ok_or(CrossMeshError::SessionNotFound(session_id))?;
            let mut receiver = stream.fec_receiver.lock().await;
            receiver
                .add_indexed_symbol(
                    block_id,
                    Some(symbol_index),
                    data_symbols,
                    parity_symbols,
                    original_len,
                    block_digest,
                    packet,
                )
                .map(|decoded_blocks| {
                    (
                        stream.data_tx.clone(),
                        decoded_blocks,
                        receiver.is_finished(),
                    )
                })
        };
        let (sender, decoded_blocks, finished) = match decoded {
            Ok(decoded) => decoded,
            Err(error) => {
                self.active_streams.write().await.remove(&session_id);
                self.stats.write().await.streams_closed += 1;
                return Err(CrossMeshError::SerializationError(error));
            }
        };
        for data in decoded_blocks {
            sender
                .send(data.clone())
                .await
                .map_err(|_| CrossMeshError::SessionNotFound(session_id))?;
            let mut stats = self.stats.write().await;
            stats.bytes_forwarded += data.len() as u64;
        }
        if finished {
            let mut streams = self.active_streams.write().await;
            streams.remove(&session_id);
            self.stats.write().await.streams_closed += 1;
        }
        Ok(())
    }

    async fn handle_datagram<F>(
        &self,
        envelope: CrossMeshEnvelope,
        _target_port: u16,
        data: Vec<u8>,
        endpoint: ServiceEndpoint,
        reply_sink: F,
    ) -> Result<(), CrossMeshError>
    where
        F: Fn(CrossMeshEnvelope) + Send + Sync + 'static,
    {
        match endpoint {
            ServiceEndpoint::LocalTcp(addr) => {
                let mut tcp_stream = TcpStream::connect(addr)
                    .await
                    .map_err(|e| CrossMeshError::EndpointUnavailable(e.to_string()))?;

                tcp_stream
                    .write_all(&data)
                    .await
                    .map_err(|e| CrossMeshError::IoError(e.to_string()))?;

                let mut reply_buf = vec![0u8; 4096];
                let n = tcp_stream
                    .read(&mut reply_buf)
                    .await
                    .map_err(|e| CrossMeshError::IoError(e.to_string()))?;

                reply_buf.truncate(n);

                {
                    let mut st = self.stats.write().await;
                    st.datagrams_forwarded += 1;
                    st.bytes_forwarded += (data.len() + n) as u64;
                }

                reply_sink(CrossMeshEnvelope::new(
                    &envelope.target_mesh,
                    &self.anchor_node_id,
                    &envelope.source_mesh,
                    None,
                    CrossMeshPayload::DatagramReply { data: reply_buf },
                ));

                Ok(())
            }
            ServiceEndpoint::LocalTcpWithIdentity(_) => Err(CrossMeshError::SerializationError(
                "Authenticated local services accept streams only".into(),
            )),
            ServiceEndpoint::InMemory(forwarder) => {
                let _ = forwarder.send(envelope).await;
                let mut st = self.stats.write().await;
                st.datagrams_forwarded += 1;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_cross_mesh_envelope_encode_decode() {
        let env = CrossMeshEnvelope::new(
            "app-mesh",
            "sbm-node-app-01",
            "database-mesh",
            None,
            CrossMeshPayload::StreamConnect { target_port: 58830 },
        );

        let bytes = env.encode();
        let decoded = CrossMeshEnvelope::decode(&bytes).expect("Failed to decode envelope");

        assert_eq!(env, decoded);
        assert_eq!(decoded.source_mesh, "app-mesh");
        assert_eq!(decoded.target_mesh, "database-mesh");
    }

    #[test]
    fn cross_mesh_envelope_rejects_unsupported_wire_versions() {
        let mut envelope = CrossMeshEnvelope::new(
            "app-mesh",
            "sbm-node-app-01",
            "database-mesh",
            None,
            CrossMeshPayload::StreamConnect { target_port: 58830 },
        );
        envelope.version = 1;
        assert!(CrossMeshEnvelope::decode(&envelope.encode()).is_err());
    }

    #[test]
    fn test_cross_mesh_policy_port_and_capability_token() {
        let authority_secret = Scalar::random(&mut OsRng);
        let now = Utc::now().timestamp() as u64;

        // Regel: app-mesh darf database-mesh auf Port 58830 ansprechen, benötigt aber ein gültiges Capability Token!
        let rule = CrossMeshRule::new(
            "allow-app-to-db",
            "app-mesh",
            "database-mesh",
            vec![58830],
            true, // Token erforderlich
            "Erlaube App-Mesh Zugriff auf Sovereign Database",
        );

        let mut policy = CrossMeshPolicy::new();
        policy.add_rule(rule);

        // 1. Anfrage ohne Token -> muss abgelehnt werden
        let res_no_token = policy.evaluate("app-mesh", "database-mesh", 58830, None, now);
        assert!(matches!(res_no_token, Err(CrossMeshError::TokenMissing)));

        // 2. Anfrage mit gültigem Token für Port 58830
        let valid_token = CapabilityToken::issue(
            "sbm-anchor-prod",
            "sbm-node-app-01",
            vec![58830],
            now + 3600,
            &authority_secret,
        );
        let res_valid =
            policy.evaluate("app-mesh", "database-mesh", 58830, Some(&valid_token), now);
        assert!(res_valid.is_ok());

        // 3. Anfrage auf unerlaubten Port (z. B. Port 22 SSH) -> muss abgelehnt werden
        let res_ssh = policy.evaluate("app-mesh", "database-mesh", 22, Some(&valid_token), now);
        assert!(matches!(res_ssh, Err(CrossMeshError::UnauthorizedPort(22))));

        // 4. Nicht erlaubte Mesh-Route (z. B. guest-mesh an database-mesh) -> muss abgelehnt werden
        let res_guest = policy.evaluate(
            "guest-mesh",
            "database-mesh",
            58830,
            Some(&valid_token),
            now,
        );
        assert!(matches!(res_guest, Err(CrossMeshError::PolicyViolation(_))));

        // 5. Abgelaufenes Token -> muss abgelehnt werden
        let expired_token = CapabilityToken::issue(
            "sbm-anchor-prod",
            "sbm-node-app-01",
            vec![58830],
            now - 100, // bereits abgelaufen
            &authority_secret,
        );
        let res_expired = policy.evaluate(
            "app-mesh",
            "database-mesh",
            58830,
            Some(&expired_token),
            now,
        );
        assert!(matches!(res_expired, Err(CrossMeshError::TokenInvalid(_))));
    }

    #[tokio::test]
    async fn stream_data_is_bound_to_the_identity_that_opened_the_session() {
        let bridge = CrossMeshBridge::new("anchor-node");
        bridge.policy.write().await.add_rule(CrossMeshRule::new(
            "app-to-db",
            "app-mesh",
            "database-mesh",
            vec![58830],
            false,
            "Test route",
        ));
        let (forward_tx, mut forward_rx) = mpsc::channel(8);
        bridge
            .register_service(
                "database-mesh",
                58830,
                ServiceEndpoint::InMemory(forward_tx),
            )
            .await;
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        bridge
            .process_envelope(
                CrossMeshEnvelope::new(
                    "app-mesh",
                    "client-node",
                    "database-mesh",
                    None,
                    CrossMeshPayload::StreamConnectFec {
                        target_port: 58830,
                        data_symbols: 8,
                        parity_symbols: 5,
                    },
                ),
                move |envelope| {
                    let _ = reply_tx.send(envelope);
                },
            )
            .await
            .unwrap();

        let ack = reply_rx.recv().unwrap();
        let session_id = match ack.payload {
            CrossMeshPayload::StreamAck { session_id } => session_id,
            other => panic!("Unexpected connect response: {other:?}"),
        };
        assert!(matches!(
            forward_rx.recv().await.unwrap().payload,
            CrossMeshPayload::StreamConnectFec {
                target_port: 58830,
                data_symbols: 8,
                parity_symbols: 5,
            }
        ));

        let forged = CrossMeshEnvelope::new(
            "app-mesh",
            "attacker-node",
            "database-mesh",
            None,
            CrossMeshPayload::StreamData {
                session_id,
                seq: 1,
                data: b"forged".to_vec(),
            },
        );
        assert!(matches!(
            bridge.process_envelope(forged, |_| {}).await,
            Err(CrossMeshError::SessionNotFound(id)) if id == session_id
        ));
        assert!(forward_rx.try_recv().is_err());

        let symbols = crate::fec::FecEncoder::new(b"valid", crate::fec::STREAM_FEC_DATA_SYMBOLS)
            .generate_fec_block(5);
        let digest = crate::fec::stream_fec_block_digest(1, b"valid");
        for (symbol_index, symbol) in symbols.iter().enumerate().skip(6) {
            let valid = CrossMeshEnvelope::new(
                "app-mesh",
                "client-node",
                "database-mesh",
                None,
                CrossMeshPayload::StreamDataFec {
                    session_id,
                    block_id: 1,
                    symbol_index: symbol_index as u16,
                    data_symbols: crate::fec::STREAM_FEC_DATA_SYMBOLS as u16,
                    parity_symbols: 5,
                    original_len: 5,
                    block_digest: digest,
                    coefficients: symbol.coefficients.clone(),
                    data: symbol.payload.clone(),
                },
            );
            bridge.process_envelope(valid, |_| {}).await.unwrap();
        }
        let block_end = CrossMeshEnvelope::new(
            "app-mesh",
            "client-node",
            "database-mesh",
            None,
            CrossMeshPayload::StreamFecBlockEnd {
                session_id,
                block_id: 1,
                data_symbols: crate::fec::STREAM_FEC_DATA_SYMBOLS as u16,
                parity_symbols: 5,
                original_len: 5,
                block_digest: digest,
            },
        );
        bridge
            .process_envelope(block_end.clone(), |_| {})
            .await
            .unwrap();
        assert!(matches!(
            reply_rx.recv().unwrap().payload,
            CrossMeshPayload::StreamFecRepairRequest {
                session_id: requested_session,
                block_id: 1,
                origin_node_id,
                symbol_indices,
                repair_round: 1,
            } if requested_session == session_id
                && origin_node_id == "client-node"
                && symbol_indices == (0..6).collect::<Vec<_>>()
        ));

        for symbol_index in 0..6 {
            let symbol = &symbols[symbol_index];
            bridge
                .process_envelope(
                    CrossMeshEnvelope::new(
                        "app-mesh",
                        "client-node",
                        "database-mesh",
                        None,
                        CrossMeshPayload::StreamDataFec {
                            session_id,
                            block_id: 1,
                            symbol_index: symbol_index as u16,
                            data_symbols: crate::fec::STREAM_FEC_DATA_SYMBOLS as u16,
                            parity_symbols: 5,
                            original_len: 5,
                            block_digest: digest,
                            coefficients: symbol.coefficients.clone(),
                            data: symbol.payload.clone(),
                        },
                    ),
                    |_| {},
                )
                .await
                .unwrap();
        }
        bridge.process_envelope(block_end, |_| {}).await.unwrap();
        assert!(matches!(
            reply_rx.recv().unwrap().payload,
            CrossMeshPayload::StreamFecBlockAck {
                session_id: acknowledged_session,
                block_id: 1,
                origin_node_id,
            } if acknowledged_session == session_id && origin_node_id == "client-node"
        ));
        let forwarded = tokio::time::timeout(Duration::from_secs(1), forward_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            forwarded.payload,
            CrossMeshPayload::StreamData { data, .. } if data == b"valid"
        ));
    }

    #[tokio::test]
    async fn active_stream_route_is_peer_bound_and_abortable() {
        let bridge = CrossMeshBridge::new("anchor-node");
        bridge.policy.write().await.add_rule(CrossMeshRule::new(
            "app-to-db",
            "app-mesh",
            "database-mesh",
            vec![58830],
            false,
            "Test route",
        ));
        let (forward_tx, mut forward_rx) = mpsc::channel(8);
        bridge
            .register_service(
                "database-mesh",
                58830,
                ServiceEndpoint::InMemory(forward_tx),
            )
            .await;
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        bridge
            .process_envelope(
                CrossMeshEnvelope::new(
                    "app-mesh",
                    "client-node",
                    "database-mesh",
                    None,
                    CrossMeshPayload::StreamConnect { target_port: 58830 },
                ),
                move |envelope| {
                    let _ = reply_tx.send(envelope);
                },
            )
            .await
            .unwrap();

        let session_id = match reply_rx.recv().unwrap().payload {
            CrossMeshPayload::StreamAck { session_id } => session_id,
            other => panic!("Unexpected connect response: {other:?}"),
        };
        let _ = forward_rx.recv().await.unwrap();
        assert_eq!(
            bridge
                .active_stream_target_port(session_id, "app-mesh", "client-node")
                .await,
            Some(58830)
        );
        assert_eq!(
            bridge
                .active_stream_target_port(session_id, "app-mesh", "other-node")
                .await,
            None
        );
        assert!(
            bridge
                .abort_stream_for_peer(session_id, "app-mesh", "client-node")
                .await
        );
        assert!(matches!(
            reply_rx.recv().unwrap().payload,
            CrossMeshPayload::StreamClose { session_id: closed_session }
                if closed_session == session_id
        ));
        assert_eq!(
            bridge
                .active_stream_target_port(session_id, "app-mesh", "client-node")
                .await,
            None
        );
        assert_eq!(bridge.stats.read().await.streams_closed, 1);
    }

    #[test]
    fn maximum_stream_fec_symbol_fits_the_udp_path_mtu_budget() {
        let envelope = CrossMeshEnvelope::new(
            "database-mesh",
            "sbm-0x12345678",
            "app-mesh",
            None,
            CrossMeshPayload::StreamDataFec {
                session_id: u64::MAX,
                block_id: u64::MAX,
                symbol_index: 0,
                data_symbols: crate::fec::STREAM_FEC_MAX_DATA_SYMBOLS as u16,
                parity_symbols: crate::fec::STREAM_FEC_MAX_PARITY_SYMBOLS as u16,
                original_len: crate::fec::STREAM_FEC_MAX_BLOCK_BYTES as u32,
                block_digest: [255; 32],
                coefficients: vec![255; crate::fec::STREAM_FEC_MAX_DATA_SYMBOLS],
                data: vec![
                    255;
                    crate::fec::STREAM_FEC_MAX_BLOCK_BYTES
                        / crate::fec::STREAM_FEC_MAX_DATA_SYMBOLS
                ],
            },
        );
        let packet_budget = envelope.encode().len() + 53 + 16;
        assert!(
            packet_budget <= 1200,
            "encoded stream FEC packet is {packet_budget} bytes"
        );
    }
}
