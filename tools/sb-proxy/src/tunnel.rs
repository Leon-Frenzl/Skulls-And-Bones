use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelMetadataDto {
    pub domain: String,
    pub callsign: String,
    pub connected_at: String,
    pub streams_served: u64,
    pub bytes_transferred: u64,
}

pub struct TunnelClientRegistration {
    pub domain: String,
    pub callsign: String,
    pub control_tx: mpsc::Sender<String>,
    pub connected_at: chrono::DateTime<Utc>,
    pub streams_served: AtomicU64,
    pub bytes_transferred: AtomicU64,
}

pub struct SovereignTunnelHub {
    clients: Arc<RwLock<HashMap<String, Arc<TunnelClientRegistration>>>>,
    pending_streams: Arc<Mutex<HashMap<String, oneshot::Sender<TcpStream>>>>,
}

impl Default for SovereignTunnelHub {
    fn default() -> Self {
        Self::new()
    }
}

impl SovereignTunnelHub {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            pending_streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Global shared singleton instance for proxy routing and IPC queries.
    pub fn global() -> Arc<Self> {
        static INSTANCE: std::sync::OnceLock<Arc<SovereignTunnelHub>> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| Arc::new(Self::new())).clone()
    }

    /// Check if a developer's tunnel client is currently actively connected for the given domain.
    pub async fn is_tunnel_active(&self, domain: &str) -> bool {
        let clean = domain.trim().to_lowercase();
        let clients = self.clients.read().await;
        clients.contains_key(&clean)
    }

    /// List all currently connected sovereign tunnel clients.
    pub async fn list_active_tunnels(&self) -> Vec<TunnelMetadataDto> {
        let clients = self.clients.read().await;
        clients
            .values()
            .map(|c| TunnelMetadataDto {
                domain: c.domain.clone(),
                callsign: c.callsign.clone(),
                connected_at: c.connected_at.to_rfc3339(),
                streams_served: c.streams_served.load(Ordering::Relaxed),
                bytes_transferred: c.bytes_transferred.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Request a new proxied TCP data stream from the registered developer tunnel client.
    pub async fn open_stream(
        &self,
        domain: &str,
        timeout_dur: Duration,
    ) -> Result<TcpStream, String> {
        let clean = domain.trim().to_lowercase();
        let (control_tx, stream_id) = {
            let clients = self.clients.read().await;
            let reg = clients.get(&clean).ok_or_else(|| {
                format!("Kein aktiver Sovereign Tunnel für '{}' verbunden", clean)
            })?;
            reg.streams_served.fetch_add(1, Ordering::Relaxed);
            let stream_id = format!("st-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
            (reg.control_tx.clone(), stream_id)
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_streams.lock().await;
            pending.insert(stream_id.clone(), tx);
        }

        // Notify client over control channel to attach stream
        let cmd = format!("OPEN_STREAM\t{}\n", stream_id);
        if let Err(e) = control_tx.send(cmd).await {
            let mut pending = self.pending_streams.lock().await;
            pending.remove(&stream_id);
            return Err(format!(
                "Fehler beim Senden des Stream-Befehls an Tunnel-Client: {}",
                e
            ));
        }

        // Wait for client to connect and attach
        match tokio::time::timeout(timeout_dur, rx).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(_)) => {
                let mut pending = self.pending_streams.lock().await;
                pending.remove(&stream_id);
                Err("Tunnel-Verbindung wurde vorzeitig getrennt".to_string())
            }
            Err(_) => {
                let mut pending = self.pending_streams.lock().await;
                pending.remove(&stream_id);
                Err(format!(
                    "Timeout ({}s) beim Warten auf Entwickler-Tunnel-Stream",
                    timeout_dur.as_secs()
                ))
            }
        }
    }

    /// Starts the Tunnel Hub TCP server on the given bind address (default 0.0.0.0:58910).
    pub async fn run_server(
        self: Arc<Self>,
        bind_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(bind_addr).await?;
        println!("📡 Sovereign Tunnel Hub aktiv auf {}", bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let hub = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = hub.handle_incoming_connection(stream, peer_addr).await {
                            eprintln!("Tunnel Hub Verbindungsfehler von {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Tunnel Hub Listener Fehler: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_incoming_connection(
        self: Arc<Self>,
        mut stream: TcpStream,
        _peer_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = BufReader::new(&mut stream);
        let mut first_line = String::new();

        let n = reader.read_line(&mut first_line).await?;
        if n == 0 {
            return Ok(());
        }

        let parts: Vec<&str> = first_line.trim().split('\t').collect();
        match parts[0] {
            "REGISTER" if parts.len() >= 3 => {
                let domain = parts[1].trim().to_lowercase();
                let callsign = parts[2].trim().to_string();

                if !is_valid_domain(&domain) {
                    let _ = stream.write_all(b"ERR\tINVALID_DOMAIN\n").await;
                    return Ok(());
                }

                if callsign.is_empty()
                    || callsign.len() > 64
                    || !callsign
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    let _ = stream.write_all(b"ERR\tINVALID_CALLSIGN\n").await;
                    return Ok(());
                }

                let (tx, mut rx) = mpsc::channel::<String>(32);
                let reg = Arc::new(TunnelClientRegistration {
                    domain: domain.clone(),
                    callsign: callsign.clone(),
                    control_tx: tx,
                    connected_at: Utc::now(),
                    streams_served: AtomicU64::new(0),
                    bytes_transferred: AtomicU64::new(0),
                });

                {
                    let mut clients = self.clients.write().await;
                    if clients.contains_key(&domain) {
                        let _ = stream.write_all(b"ERR\tDOMAIN_ALREADY_REGISTERED\n").await;
                        return Ok(());
                    }
                    clients.insert(domain.clone(), reg);
                }

                stream.write_all(b"OK\tREGISTERED\n").await?;
                println!(
                    "✓ Sovereign Tunnel registriert: {} (Peer: {})",
                    domain, callsign
                );

                // Control loop
                let (mut read_half, mut write_half) = stream.into_split();
                let domain_cleanup = domain.clone();
                let hub_cleanup = self.clone();

                let write_task = tokio::spawn(async move {
                    while let Some(msg) = rx.recv().await {
                        if write_half.write_all(msg.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });

                let mut client_lines = BufReader::new(&mut read_half).lines();
                while let Ok(Some(line)) = client_lines.next_line().await {
                    let cmd = line.trim();
                    if cmd == "PING" {
                        // Keep-alive
                    }
                }

                write_task.abort();
                {
                    let mut clients = hub_cleanup.clients.write().await;
                    clients.remove(&domain_cleanup);
                }
                println!("ℹ Sovereign Tunnel beendet: {}", domain_cleanup);
            }
            "ATTACH_STREAM" if parts.len() >= 2 => {
                let stream_id = parts[1].trim().to_string();
                if stream_id.is_empty()
                    || stream_id.len() > 64
                    || !stream_id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
                {
                    let _ = stream.write_all(b"ERR\tINVALID_STREAM_ID\n").await;
                    return Ok(());
                }

                let sender = {
                    let mut pending = self.pending_streams.lock().await;
                    pending.remove(&stream_id)
                };

                if let Some(tx) = sender {
                    let _ = tx.send(stream);
                } else {
                    let _ = stream.write_all(b"ERR\tUNKNOWN_OR_EXPIRED_STREAM\n").await;
                }
            }
            _ => {
                let _ = stream.write_all(b"ERR\tINVALID_COMMAND\n").await;
            }
        }

        Ok(())
    }
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tunnel_hub_registration_and_stream_attachment() {
        let hub = Arc::new(SovereignTunnelHub::new());
        let hub_clone = hub.clone();

        // Bind on random port for testing
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, p_addr)) = listener.accept().await {
                    let h = hub_clone.clone();
                    tokio::spawn(async move {
                        let _ = h.handle_incoming_connection(stream, p_addr).await;
                    });
                }
            }
        });

        // 1. Client connects and registers domain
        let mut client_ctrl = TcpStream::connect(addr).await.unwrap();
        client_ctrl
            .write_all(b"REGISTER\tmydev.local\talice\n")
            .await
            .unwrap();

        let mut buf_reader = BufReader::new(&mut client_ctrl);
        let mut reply = String::new();
        buf_reader.read_line(&mut reply).await.unwrap();
        assert!(reply.starts_with("OK\tREGISTERED"));

        assert!(hub.is_tunnel_active("mydev.local").await);
        let active = hub.list_active_tunnels().await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].domain, "mydev.local");

        // 2. Hub opens stream for mydev.local in background
        let hub_for_stream = hub.clone();
        let stream_fut = tokio::spawn(async move {
            hub_for_stream
                .open_stream("mydev.local", Duration::from_secs(3))
                .await
        });

        // 3. Client receives OPEN_STREAM on control line
        let mut ctrl_line = String::new();
        buf_reader.read_line(&mut ctrl_line).await.unwrap();
        assert!(ctrl_line.starts_with("OPEN_STREAM\t"));
        let stream_id = ctrl_line.trim().split('\t').nth(1).unwrap().to_string();

        // 4. Client attaches data stream
        let mut data_stream = TcpStream::connect(addr).await.unwrap();
        let attach_cmd = format!("ATTACH_STREAM\t{}\n", stream_id);
        data_stream.write_all(attach_cmd.as_bytes()).await.unwrap();

        // 5. Hub receives attached stream
        let mut server_stream = stream_fut.await.unwrap().unwrap();

        // 6. Test bidirectional communication
        data_stream.write_all(b"PING_FROM_LAPTOP").await.unwrap();
        let mut buf = [0u8; 16];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING_FROM_LAPTOP");

        server_stream.write_all(b"PONG_FROM_GATEWAY").await.unwrap();
        let mut buf2 = [0u8; 17];
        data_stream.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"PONG_FROM_GATEWAY");
    }

    #[tokio::test]
    async fn test_sovereign_tunnel_client_e2e() {
        // 1. Start Tunnel Hub on random port
        let hub = Arc::new(SovereignTunnelHub::new());
        let hub_clone = hub.clone();
        let hub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub_addr = hub_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, p_addr)) = hub_listener.accept().await {
                    let h = hub_clone.clone();
                    tokio::spawn(async move {
                        let _ = h.handle_incoming_connection(stream, p_addr).await;
                    });
                }
            }
        });

        // 2. Start mock local dev server on random port
        let dev_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dev_port = dev_listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = dev_listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 256];
                        let _ = stream.read(&mut buf).await;
                        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\nHello from Local Laptop Dev!";
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
            }
        });

        // 3. Start SovereignTunnelClient in background
        let client = crate::escape::SovereignTunnelClient::new(
            "coolapp.local",
            dev_port,
            &hub_addr.to_string(),
            "alice-laptop",
        )
        .unwrap();

        let client_running = client.running.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        });

        // Give client time to connect and handshake
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(hub.is_tunnel_active("coolapp.local").await);

        // 4. Hub opens stream for incoming HTTP request
        let mut proxied_stream = hub
            .open_stream("coolapp.local", Duration::from_secs(3))
            .await
            .unwrap();

        // 5. Send HTTP GET over the proxied stream
        proxied_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: coolapp.local\r\n\r\n")
            .await
            .unwrap();

        let mut resp_buf = [0u8; 512];
        let n = proxied_stream.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("Hello from Local Laptop Dev!"));

        client_running.store(false, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn test_tunnel_hub_rejects_invalid_domain() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("-invalid.com"));
        assert!(!is_valid_domain("invalid-.com"));
        assert!(!is_valid_domain("inv@lid.com"));
        assert!(!is_valid_domain("in valid.com"));
        assert!(is_valid_domain("valid-app.local"));
        assert!(is_valid_domain("sub.domain.example.com"));

        let hub = Arc::new(SovereignTunnelHub::new());
        let hub_clone = hub.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((stream, p_addr)) = listener.accept().await {
                let _ = hub_clone.handle_incoming_connection(stream, p_addr).await;
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"REGISTER\t../evil/domain\talice\n")
            .await
            .unwrap();

        let mut buf_reader = BufReader::new(&mut client);
        let mut reply = String::new();
        buf_reader.read_line(&mut reply).await.unwrap();
        assert!(reply.starts_with("ERR\tINVALID_DOMAIN"));
    }

    #[tokio::test]
    async fn test_tunnel_hub_prevents_domain_hijacking() {
        let hub = Arc::new(SovereignTunnelHub::new());
        let hub_clone = hub.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, p_addr)) = listener.accept().await {
                    let h = hub_clone.clone();
                    tokio::spawn(async move {
                        let _ = h.handle_incoming_connection(stream, p_addr).await;
                    });
                }
            }
        });

        // Legitimate client registers
        let mut client1 = TcpStream::connect(addr).await.unwrap();
        client1
            .write_all(b"REGISTER\tsecure.local\talice\n")
            .await
            .unwrap();
        let mut reader1 = BufReader::new(&mut client1);
        let mut reply1 = String::new();
        reader1.read_line(&mut reply1).await.unwrap();
        assert!(reply1.starts_with("OK\tREGISTERED"));

        // Malicious client tries to hijack same domain
        let mut client2 = TcpStream::connect(addr).await.unwrap();
        client2
            .write_all(b"REGISTER\tsecure.local\tattacker\n")
            .await
            .unwrap();
        let mut reader2 = BufReader::new(&mut client2);
        let mut reply2 = String::new();
        reader2.read_line(&mut reply2).await.unwrap();
        assert!(reply2.starts_with("ERR\tDOMAIN_ALREADY_REGISTERED"));
    }
}
