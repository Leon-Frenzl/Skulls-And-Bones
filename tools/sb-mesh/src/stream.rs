//! Mesh Virtual Stream Protocol (MVSP) & Stealth Ingress Bridge
//!
//! Enables zero-kernel, user-space TCP tunneling over authenticated ChaCha20-Poly1305 UDP packets.
//! Used for "Dark Fleet" stealth access where management ports (like SSH Port 22) are closed to the public WAN
//! and exclusively reachable via encrypted S&B Mesh datagrams on UDP port 58888.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};

use crate::crypto::{
    decrypt_payload, derive_session_keys, encrypt_payload, pack_message_v2, unpack_header_v2,
    PacketType,
};
use crate::identity::NodeIdentity;

/// Maximum payload chunk size in bytes to prevent IP fragmentation over WAN UDP
pub const MAX_PAYLOAD_CHUNK: usize = 1200;

/// Stream Command Opcode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamCommand {
    Connect {
        target_port: u16,
    },
    ConnectVpc {
        target_host: String,
        target_port: u16,
    },
    Connected,
    Data(Vec<u8>),
    Close,
    Error(String),
}

impl StreamCommand {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            StreamCommand::Connect { target_port } => {
                buf.push(0x01);
                buf.extend_from_slice(&target_port.to_be_bytes());
            }
            StreamCommand::Connected => {
                buf.push(0x02);
            }
            StreamCommand::Data(data) => {
                buf.push(0x03);
                buf.extend_from_slice(data);
            }
            StreamCommand::Close => {
                buf.push(0x04);
            }
            StreamCommand::Error(msg) => {
                buf.push(0x05);
                buf.extend_from_slice(msg.as_bytes());
            }
            StreamCommand::ConnectVpc {
                target_host,
                target_port,
            } => {
                buf.push(0x06);
                let host_bytes = target_host.as_bytes();
                buf.push(host_bytes.len() as u8);
                buf.extend_from_slice(host_bytes);
                buf.extend_from_slice(&target_port.to_be_bytes());
            }
        }
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, String> {
        if buf.is_empty() {
            return Err("Empty stream command".to_string());
        }
        match buf[0] {
            0x01 => {
                if buf.len() < 3 {
                    return Err("Malformed Connect command".to_string());
                }
                let port = u16::from_be_bytes([buf[1], buf[2]]);
                Ok(StreamCommand::Connect { target_port: port })
            }
            0x02 => Ok(StreamCommand::Connected),
            0x03 => Ok(StreamCommand::Data(buf[1..].to_vec())),
            0x04 => Ok(StreamCommand::Close),
            0x05 => {
                let msg = String::from_utf8_lossy(&buf[1..]).to_string();
                Ok(StreamCommand::Error(msg))
            }
            0x06 => {
                if buf.len() < 4 {
                    return Err("Malformed ConnectVpc command".to_string());
                }
                let host_len = buf[1] as usize;
                if buf.len() < 2 + host_len + 2 {
                    return Err("Malformed ConnectVpc host string".to_string());
                }
                let host = String::from_utf8_lossy(&buf[2..2 + host_len]).to_string();
                let port_offset = 2 + host_len;
                let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
                Ok(StreamCommand::ConnectVpc {
                    target_host: host,
                    target_port: port,
                })
            }
            other => Err(format!("Unknown stream command opcode: 0x{:02x}", other)),
        }
    }
}

/// A Framed Message inside a Virtual Mesh Stream
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub stream_id: u32,
    pub seq_num: u32,
    pub command: StreamCommand,
}

impl StreamFrame {
    pub fn new(stream_id: u32, seq_num: u32, command: StreamCommand) -> Self {
        Self {
            stream_id,
            seq_num,
            command,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 64);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&self.seq_num.to_be_bytes());
        buf.extend_from_slice(&self.command.encode());
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 8 {
            return Err("Stream frame too short (< 8 bytes)".to_string());
        }
        let stream_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let seq_num = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let command = StreamCommand::decode(&buf[8..])?;
        Ok(Self {
            stream_id,
            seq_num,
            command,
        })
    }
}

/// Stealth Ingress Bridge Server (runs inside sb-node on the server)
///
/// Listens for decrypted/dispatched stream frames, connects to local target ports (e.g. 127.0.0.1:22),
/// and pumps bidirectional traffic back through the encrypted UDP overlay.
pub struct StealthIngressBridge {
    active_streams: Arc<RwLock<HashMap<u32, mpsc::Sender<StreamFrame>>>>,
    allowed_ports: Vec<u16>,
}

impl StealthIngressBridge {
    pub fn new(allowed_ports: Vec<u16>) -> Self {
        Self {
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            allowed_ports,
        }
    }

    /// Process a stream frame received from a remote client.
    /// Returns optional response frame to send back to the client.
    pub async fn process_frame<F>(&self, frame: StreamFrame, reply_sink: F) -> Result<(), String>
    where
        F: Fn(StreamFrame) + Send + Sync + 'static,
    {
        let target_addr = match &frame.command {
            StreamCommand::Connect { target_port } => {
                if !self.allowed_ports.contains(target_port) {
                    reply_sink(StreamFrame::new(
                        frame.stream_id,
                        0,
                        StreamCommand::Error(format!(
                            "Port {} is not authorized for stealth ingress",
                            target_port
                        )),
                    ));
                    return Ok(());
                }
                format!("127.0.0.1:{}", target_port)
            }
            StreamCommand::ConnectVpc {
                target_host,
                target_port,
            } => {
                format!("{}:{}", target_host, target_port)
            }
            StreamCommand::Data(_) => {
                let streams = self.active_streams.read().await;
                if let Some(tx) = streams.get(&frame.stream_id) {
                    let _ = tx.send(frame).await;
                }
                return Ok(());
            }
            StreamCommand::Close => {
                let mut streams = self.active_streams.write().await;
                streams.remove(&frame.stream_id);
                return Ok(());
            }
            _ => return Ok(()),
        };

        // Connect to target destination service (Loopback or private VPC LAN host)
        let stream_res = TcpStream::connect(&target_addr).await;
        let tcp_stream = match stream_res {
            Ok(s) => s,
            Err(e) => {
                reply_sink(StreamFrame::new(
                    frame.stream_id,
                    0,
                    StreamCommand::Error(format!(
                        "Cannot connect to target service on {}: {}",
                        target_addr, e
                    )),
                ));
                return Ok(());
            }
        };

        // Acknowledge connection
        reply_sink(StreamFrame::new(
            frame.stream_id,
            0,
            StreamCommand::Connected,
        ));

        let (tx, mut rx) = mpsc::channel::<StreamFrame>(16384);
        {
            let mut streams = self.active_streams.write().await;
            streams.insert(frame.stream_id, tx);
        }

        let stream_id = frame.stream_id;
        let active_cleanup = self.active_streams.clone();
        let sink_arc = Arc::new(reply_sink);

        tokio::spawn(async move {
            let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
            let mut tcp_buf = [0u8; 4096];
            let out_seq = Arc::new(AtomicU32::new(1));

            let sink_read = sink_arc.clone();
            let seq_read = out_seq.clone();

            let read_task = tokio::spawn(async move {
                loop {
                    match tcp_read.read(&mut tcp_buf).await {
                        Ok(0) => {
                            sink_read(StreamFrame::new(
                                stream_id,
                                seq_read.fetch_add(1, Ordering::SeqCst),
                                StreamCommand::Close,
                            ));
                            break;
                        }
                        Ok(n) => {
                            for chunk in tcp_buf[..n].chunks(MAX_PAYLOAD_CHUNK) {
                                sink_read(StreamFrame::new(
                                    stream_id,
                                    seq_read.fetch_add(1, Ordering::SeqCst),
                                    StreamCommand::Data(chunk.to_vec()),
                                ));
                                tokio::task::yield_now().await;
                            }
                        }
                        Err(_) => {
                            sink_read(StreamFrame::new(
                                stream_id,
                                seq_read.fetch_add(1, Ordering::SeqCst),
                                StreamCommand::Close,
                            ));
                            break;
                        }
                    }
                }
            });

            let write_task = tokio::spawn(async move {
                let mut expected_seq = 1u32;
                let mut pending_buffer = std::collections::BTreeMap::<u32, Vec<u8>>::new();

                while let Some(incoming_frame) = rx.recv().await {
                    match incoming_frame.command {
                        StreamCommand::Data(data) => {
                            if incoming_frame.seq_num == expected_seq {
                                if tcp_write.write_all(&data).await.is_err() {
                                    break;
                                }
                                expected_seq += 1;
                                while let Some(buffered) = pending_buffer.remove(&expected_seq) {
                                    if tcp_write.write_all(&buffered).await.is_err() {
                                        break;
                                    }
                                    expected_seq += 1;
                                }
                            } else if incoming_frame.seq_num > expected_seq {
                                pending_buffer.insert(incoming_frame.seq_num, data);
                                // Puffer-Überlaufschutz (z.B. bei massiv verspäteten Paketen)
                                if pending_buffer.len() > 1024 {
                                    while let Some((_, chunk)) = pending_buffer.pop_first() {
                                        let _ = tcp_write.write_all(&chunk).await;
                                    }
                                }
                            }
                        }
                        StreamCommand::Close => break,
                        _ => {}
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

            let mut streams = active_cleanup.write().await;
            streams.remove(&stream_id);
        });

        Ok(())
    }
}

/// Stealth Stream Client (runs on the developer machine)
///
/// Binds a local port (e.g. 127.0.0.1:58822), intercepts TCP connections (from sb-ssh),
/// and tunnels them over encrypted Noise/UDP datagrams to the server's UDP port 58888.
pub struct StealthStreamClient {
    pub local_bind_port: u16,
    pub remote_server_addr: SocketAddr,
    pub remote_target_port: u16,
    pub swarm_tag: [u8; 8],
    pub identity: Arc<NodeIdentity>,
    pub remote_pubkey: [u8; 32],
    pub idle_timeout: u64,
    pub oneshot: bool,
}

impl StealthStreamClient {
    pub fn new(
        local_bind_port: u16,
        remote_server_addr: SocketAddr,
        remote_target_port: u16,
        swarm_topic: &str,
        identity: Arc<NodeIdentity>,
        remote_pubkey: [u8; 32],
    ) -> Self {
        let swarm_tag = crate::crypto::derive_swarm_tag(swarm_topic);
        Self {
            local_bind_port,
            remote_server_addr,
            remote_target_port,
            swarm_tag,
            identity,
            remote_pubkey,
            idle_timeout: 120,
            oneshot: false,
        }
    }

    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout = secs;
        self
    }

    pub fn with_oneshot(mut self, oneshot: bool) -> Self {
        self.oneshot = oneshot;
        self
    }

    /// Starts the local stealth stream listener
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.local_bind_port)).await?;
        println!(
            "🔒 S&B Stealth Stream Client aktiv auf 127.0.0.1:{} ➔ Remote {} (Port {})",
            self.local_bind_port, self.remote_server_addr, self.remote_target_port
        );

        let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let session_keys = derive_session_keys(
            &self.identity.secret,
            &x25519_dalek::PublicKey::from(self.remote_pubkey),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let initial_id = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u32)
            .unwrap_or(10_000)
            & 0x7FFF_FFFF)
            .max(10_000);
        let next_stream_id = Arc::new(AtomicU32::new(initial_id));

        let active_local_streams: Arc<RwLock<HashMap<u32, mpsc::Sender<StreamFrame>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let active_connections = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(2);
        let last_activity = Arc::new(RwLock::new(tokio::time::Instant::now()));

        // Background idle monitor
        if self.idle_timeout > 0 {
            let active_conns = active_connections.clone();
            let last_act = last_activity.clone();
            let idle_secs = self.idle_timeout;
            let s_tx = shutdown_tx.clone();

            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let conns = active_conns.load(Ordering::SeqCst);
                    if conns == 0 {
                        let elapsed = {
                            let act = last_act.read().await;
                            act.elapsed()
                        };
                        if elapsed >= Duration::from_secs(idle_secs) {
                            println!(
                                "⏱️  Stealth-Tunnel wegen Inaktivität ({}s ohne Verbindung) beendet.",
                                idle_secs
                            );
                            let _ = s_tx.send(()).await;
                            break;
                        }
                    }
                }
            });
        }

        // Background UDP receiver
        let udp_recv = udp_socket.clone();
        let streams_recv = active_local_streams.clone();
        let expected_tag = self.swarm_tag;
        let expected_key = session_keys.receive.clone();

        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match udp_recv.recv_from(&mut buf).await {
                    Ok((len, _addr)) => match unpack_header_v2(&buf[..len]) {
                        Ok((ptype, _tag, _pubkey, counter, payload)) => {
                            if _tag == expected_tag && ptype == PacketType::Data {
                                match decrypt_payload(expected_key.as_bytes(), counter, payload) {
                                    Ok(dec) => match StreamFrame::decode(&dec) {
                                        Ok(frame) => {
                                            let streams = streams_recv.read().await;
                                            if let Some(tx) = streams.get(&frame.stream_id) {
                                                let _ = tx.send(frame).await;
                                            }
                                        }
                                        Err(e) => sb_core::logfmt::warn(
                                            "ERR_STREAM_DECODE",
                                            "mesh.stream",
                                            "StreamFrame decode error",
                                            &[("error", &e.to_string())],
                                        ),
                                    },
                                    Err(e) => sb_core::logfmt::warn(
                                        "ERR_STREAM_DECRYPT",
                                        "mesh.stream",
                                        "Stream decrypt error",
                                        &[("error", &e.to_string())],
                                    ),
                                }
                            } else {
                                let tm = (_tag == expected_tag).to_string();
                                let pt = format!("{:?}", ptype);
                                sb_core::logfmt::warn(
                                    "ERR_STREAM_MISMATCH",
                                    "mesh.stream",
                                    "Tag or packet type mismatch",
                                    &[("tag_match", &tm), ("ptype", &pt)],
                                );
                            }
                        }
                        Err(e) => sb_core::logfmt::warn(
                            "ERR_STREAM_HEADER",
                            "mesh.stream",
                            "unpack_header_v2 error",
                            &[("error", &e.to_string())],
                        ),
                    },
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });

        // Loop accepting incoming TCP connections from sb-ssh
        loop {
            tokio::select! {
                        _ = shutdown_rx.recv() => {
                            break;
                        }
                        _ = tokio::signal::ctrl_c() => {
                            println!("\n🔒 Stealth-Tunnel wird beendet...");
                            break;
                        }
                        res = listener.accept() => {
                            match res {
                                Ok((tcp_stream, client_addr)) => {
                                    let stream_id = next_stream_id.fetch_add(1, Ordering::SeqCst);
                                    let udp_send = udp_socket.clone();
                                    let target_addr = self.remote_server_addr;
                                    let target_port = self.remote_target_port;
                                    let tag = self.swarm_tag;
                                    let pubkey = *self.identity.public_key.as_bytes();
                                    let s_key = session_keys.send.clone();
                                    let streams_map = active_local_streams.clone();

                                    active_connections.fetch_add(1, Ordering::SeqCst);
                                    {
                                        let mut act = last_activity.write().await;
                                        *act = tokio::time::Instant::now();
                                    }

                                    let active_conns_task = active_connections.clone();
                                    let last_act_task = last_activity.clone();
                                    let s_tx_task = shutdown_tx.clone();
                                    let oneshot_enabled = self.oneshot;

                                    println!(
                                        "  ► Neuer SSH-Client verbunden: {} (Mesh Stream #{})",
                                        client_addr, stream_id
                                    );

                                    tokio::spawn(async move {
                                        let (tx, mut rx) = mpsc::channel::<StreamFrame>(16384);
                                        {
                                            let mut map = streams_map.write().await;
                                            map.insert(stream_id, tx);
                                        }

                                        let counter = Arc::new(std::sync::atomic::AtomicU64::new(1));

                                // 1. Send CONNECT command
                                let connect_frame = StreamFrame::new(
                                    stream_id,
                                    0,
                                    StreamCommand::Connect { target_port },
                                );
                                let c_val = counter.fetch_add(1, Ordering::SeqCst);
                                let enc = encrypt_payload(
                                    s_key.as_bytes(),
                                    c_val,
                                    &connect_frame.encode(),
                                );
                                match enc {
                                    Ok(enc_bytes) => {
                                        let pkt = pack_message_v2(
                                            PacketType::Data,
                                            &tag,
                                            &pubkey,
                                            c_val,
                                            &enc_bytes,
                                        );
                                        let _ = udp_send.send_to(&pkt, target_addr).await;
                                    }
                                    Err(e) => {
                                        sb_core::logfmt::error("ERR_STREAM_ENCRYPT_CONNECT", "mesh.stream", "Encrypt connect error", &[("error", &e.to_string())]);
                                    }
                                }

                                // Wait for Connected ack
                                let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
                                match ack {
                                    Ok(Some(frame)) if matches!(frame.command, StreamCommand::Connected) => {
                                        // Stream established! Pump data bidirectionally
                                        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
                                        let mut tcp_buf = [0u8; 4096];
                                        let seq_out = Arc::new(AtomicU32::new(1));

                                        let udp_copy = udp_send.clone();
                                        let counter_copy = counter.clone();

                                        let read_half = tokio::spawn(async move {
                                            loop {
                                                match tcp_read.read(&mut tcp_buf).await {
                                                    Ok(0) => {
                                                        let frame = StreamFrame::new(
                                                            stream_id,
                                                            seq_out.fetch_add(1, Ordering::SeqCst),
                                                            StreamCommand::Close,
                                                        );
                                                        let c_val = counter_copy.fetch_add(1, Ordering::SeqCst);
                                                        let enc = encrypt_payload(
                                                            s_key.as_bytes(),
                                                            c_val,
                                                            &frame.encode(),
                                                        );
                                                        if let Ok(b) = enc {
                                                            let pkt = pack_message_v2(
                                                                PacketType::Data,
                                                                &tag,
                                                                &pubkey,
                                                                c_val,
                                                                &b,
                                                            );
                                                            let _ = udp_copy.send_to(&pkt, target_addr).await;
                                                        }
                                                        break;
                                                    }
                                                    Ok(n) => {
                                                        for chunk in tcp_buf[..n].chunks(MAX_PAYLOAD_CHUNK) {
                                                            let frame = StreamFrame::new(
                                                                stream_id,
                                                                seq_out.fetch_add(1, Ordering::SeqCst),
                                                                StreamCommand::Data(chunk.to_vec()),
                                                            );
                                                            let c_val = counter_copy.fetch_add(1, Ordering::SeqCst);
                                                            let enc = encrypt_payload(
                                                                s_key.as_bytes(),
                                                                c_val,
                                                                &frame.encode(),
                                                            );
                                                            if let Ok(b) = enc {
                                                                let pkt = pack_message_v2(
                                                                    PacketType::Data,
                                                                    &tag,
                                                                    &pubkey,
                                                                    c_val,
                                                                    &b,
                                                                );
                                                                let _ = udp_copy.send_to(&pkt, target_addr).await;
                                                                tokio::task::yield_now().await;
                                                            }
                                                        }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });

                                        let write_half = tokio::spawn(async move {
                                            let mut expected_seq = 1u32;
                                            let mut pending_buffer = std::collections::BTreeMap::<u32, Vec<u8>>::new();

                                            while let Some(incoming_frame) = rx.recv().await {
                                                match incoming_frame.command {
                                                    StreamCommand::Data(data) => {
                                                        if incoming_frame.seq_num == expected_seq {
                                                            if tcp_write.write_all(&data).await.is_err() {
                                                                break;
                                                            }
                                                            expected_seq += 1;
                                                            while let Some(buffered) = pending_buffer.remove(&expected_seq) {
                                                                if tcp_write.write_all(&buffered).await.is_err() {
                                                                    break;
                                                                }
                                                                expected_seq += 1;
                                                            }
                                                        } else if incoming_frame.seq_num > expected_seq {
                                                            pending_buffer.insert(incoming_frame.seq_num, data);
                                                            if pending_buffer.len() > 1024 {
                                                                while let Some((_, chunk)) = pending_buffer.pop_first() {
                                                                    let _ = tcp_write.write_all(&chunk).await;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    StreamCommand::Close | StreamCommand::Error(_) => break,
                                                    _ => {}
                                                }
                                            }
                                        });

                                        let mut read_h = read_half;
                                        let mut write_h = write_half;

                                        tokio::select! {
                                            _ = &mut read_h => {
                                                write_h.abort();
                                            }
                                            _ = &mut write_h => {
                                                read_h.abort();
                                            }
                                        };
                                    }
                                    Ok(Some(frame)) => {
                                        let sid = stream_id.to_string();
                                        if let StreamCommand::Error(err) = frame.command {
                                            sb_core::logfmt::error("ERR_STEALTH_STREAM_SERVER", "mesh.stream", "Stealth stream server error", &[("stream_id", &sid), ("error", &err)]);
                                        } else {
                                            let cmd = format!("{:?}", frame.command);
                                            sb_core::logfmt::warn("ERR_STEALTH_STREAM_PKT", "mesh.stream", "Unexpected stealth stream packet", &[("stream_id", &sid), ("command", &cmd)]);
                                        }
                                    }
                                    _ => {
                                        let sid = stream_id.to_string();
                                        sb_core::logfmt::error("ERR_STEALTH_STREAM_NO_ACK", "mesh.stream", "Stealth stream handshake failed without ACK", &[("stream_id", &sid)]);
                                    }
                                }

                                let mut map = streams_map.write().await;
                                map.remove(&stream_id);
                                drop(map);

                                let prev = active_conns_task.fetch_sub(1, Ordering::SeqCst);
                                {
                                    let mut act = last_act_task.write().await;
                                    *act = tokio::time::Instant::now();
                                }

                                if oneshot_enabled && prev == 1 {
                                    println!("⚡ Oneshot-Modus: SSH-Sitzung beendet, schließe Stealth-Tunnel.");
                                    let _ = s_tx_task.send(()).await;
                                }
                            });
                        }
                        Err(e) => {
                            sb_core::logfmt::warn("ERR_STREAM_TCP_ACCEPT", "mesh.stream", "Failed to accept TCP connection", &[("error", &e.to_string())]);
                        }
                    }
                }
            }
        }

        udp_task.abort();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_command_encode_decode() {
        let cmd = StreamCommand::Connect { target_port: 22 };
        let enc = cmd.encode();
        let dec = StreamCommand::decode(&enc).unwrap();
        assert_eq!(cmd, dec);

        let data = StreamCommand::Data(b"SSH-2.0-OpenSSH_9.6".to_vec());
        let enc_data = data.encode();
        let dec_data = StreamCommand::decode(&enc_data).unwrap();
        assert_eq!(data, dec_data);
    }

    #[test]
    fn test_stream_frame_roundtrip() {
        let frame = StreamFrame::new(42, 1, StreamCommand::Data(b"hello stealth world".to_vec()));
        let bytes = frame.encode();
        let decoded = StreamFrame::decode(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }
}
