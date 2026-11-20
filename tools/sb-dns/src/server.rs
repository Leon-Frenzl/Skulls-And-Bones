use crate::resolver::{DnsResolver, MAX_DNS_MESSAGE_SIZE};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

const MAX_CONCURRENT_QUERIES: usize = 256;
const UDP_SAFE_RESPONSE_SIZE: usize = 1232;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const RATE_LIMIT_MAX_TRACKED_IPS: usize = 4096;

#[derive(Default)]
struct ClientRateLimiter {
    buckets: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl ClientRateLimiter {
    fn allow(&self, ip: IpAddr, max_qps: u32) -> bool {
        if max_qps == 0 {
            return true;
        }
        let Ok(mut map) = self.buckets.lock() else {
            return true;
        };
        let now = Instant::now();
        if map.len() >= RATE_LIMIT_MAX_TRACKED_IPS {
            map.retain(|_, (ts, _)| now.duration_since(*ts) < Duration::from_secs(2));
        }
        let entry = map.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(1) {
            *entry = (now, 1);
            true
        } else if entry.1 < max_qps {
            entry.1 += 1;
            true
        } else {
            false
        }
    }
}

pub struct DnsServer {
    resolver: Arc<DnsResolver>,
    rate_limiter: Arc<ClientRateLimiter>,
}

impl DnsServer {
    pub fn new(resolver: DnsResolver) -> Self {
        Self {
            resolver: Arc::new(resolver),
            rate_limiter: Arc::new(ClientRateLimiter::default()),
        }
    }

    pub async fn run(&self, bind_addr: Option<SocketAddr>) -> Result<(), String> {
        let addr = match bind_addr {
            Some(addr) => addr,
            None => {
                let ip = self
                    .resolver
                    .config
                    .listen_ip
                    .parse::<IpAddr>()
                    .map_err(|error| format!("Invalid DNS listen IP: {error}"))?;
                SocketAddr::new(ip, self.resolver.config.listen_port)
            }
        };
        let udp_socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .map_err(|e| format!("Failed to bind DNS UDP socket {addr}: {e}"))?,
        );
        let addr = udp_socket
            .local_addr()
            .map_err(|error| format!("Failed to inspect DNS UDP socket address: {error}"))?;
        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("Failed to bind DNS TCP socket {addr}: {e}"))?;
        let concurrency = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));

        println!("Sovereign DNS listening on UDP and TCP {addr}");

        let mut udp_buffer = vec![0u8; MAX_DNS_MESSAGE_SIZE + 1];
        loop {
            tokio::select! {
                received = udp_socket.recv_from(&mut udp_buffer) => {
                    match received {
                        Ok((length, peer)) => {
                            if length > MAX_DNS_MESSAGE_SIZE {
                                continue;
                            }
                            let Ok(permit) = concurrency.clone().try_acquire_owned() else {
                                continue;
                            };
                            if !self
                                .rate_limiter
                                .allow(peer.ip(), self.resolver.config.rate_limit_qps)
                            {
                                continue;
                            }
                            let packet = udp_buffer[..length].to_vec();
                            let socket = udp_socket.clone();
                            let resolver = self.resolver.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                match process_packet(&resolver, &packet, Some(peer.ip())).await {
                                    Ok(response) => match limit_udp_response(response) {
                                        Ok(response) => {
                                            if let Err(error) = socket.send_to(&response, peer).await {
                                                let p = peer.to_string();
                                                let e = error.to_string();
                                                sb_core::logfmt::warn("ERR_DNS_UDP_SEND", "dns.server", "DNS UDP response failed", &[("peer", &p), ("error", &e)]);
                                            }
                                        }
                                        Err(error) => {
                                            let p = peer.to_string();
                                            let e = error.to_string();
                                            sb_core::logfmt::warn("ERR_DNS_UDP_ENCODE", "dns.server", "DNS UDP response encode failed", &[("peer", &p), ("error", &e)]);
                                        }
                                    },
                                    Err(error) => {
                                        let p = peer.to_string();
                                        let e = error.to_string();
                                        sb_core::logfmt::warn("ERR_DNS_UDP_QUERY", "dns.server", "DNS UDP query failed", &[("peer", &p), ("error", &e)]);
                                    }
                                }
                            });
                        }
                        Err(error) => {
                            let e = error.to_string();
                            sb_core::logfmt::error("ERR_DNS_UDP_RECV", "dns.server", "DNS UDP receive failed", &[("error", &e)]);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                accepted = tcp_listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let Ok(permit) = concurrency.clone().try_acquire_owned() else {
                                continue;
                            };
                            if !self
                                .rate_limiter
                                .allow(peer.ip(), self.resolver.config.rate_limit_qps)
                            {
                                continue;
                            }
                            let resolver = self.resolver.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(error) = handle_tcp_client(stream, peer.ip(), resolver).await {
                                    let p = peer.to_string();
                                    let e = error.to_string();
                                    sb_core::logfmt::warn("ERR_DNS_TCP_SESSION", "dns.server", "DNS TCP session failed", &[("peer", &p), ("error", &e)]);
                                }
                            });
                        }
                        Err(error) => {
                            let e = error.to_string();
                            sb_core::logfmt::error("ERR_DNS_TCP_ACCEPT", "dns.server", "DNS TCP accept failed", &[("error", &e)]);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }
}

async fn process_packet(
    resolver: &DnsResolver,
    packet: &[u8],
    client_ip: Option<IpAddr>,
) -> Result<Vec<u8>, String> {
    match Message::from_vec(packet) {
        Ok(query) => match tokio::time::timeout(
            QUERY_TIMEOUT,
            resolver.resolve_for_client(&query, client_ip),
        )
        .await
        {
            Ok(Ok(response)) => response
                .to_vec()
                .map_err(|error| format!("DNS response encoding failed: {error}")),
            Ok(Err(error)) => {
                let e = error.to_string();
                sb_core::logfmt::warn(
                    "ERR_DNS_RESOLVE",
                    "dns.server",
                    "DNS resolver failed",
                    &[("error", &e)],
                );
                error_response(query.id, ResponseCode::ServFail)
            }
            Err(_) => error_response(query.id, ResponseCode::ServFail),
        },
        Err(error) => {
            if packet.len() >= 2 {
                let e = error.to_string();
                sb_core::logfmt::warn(
                    "ERR_DNS_MALFORMED",
                    "dns.server",
                    "Malformed DNS query",
                    &[("error", &e)],
                );
                error_response(
                    u16::from_be_bytes([packet[0], packet[1]]),
                    ResponseCode::FormErr,
                )
            } else {
                Err("Malformed DNS query is too short to contain a transaction ID".to_string())
            }
        }
    }
}

fn error_response(id: u16, code: ResponseCode) -> Result<Vec<u8>, String> {
    let mut response = Message::new(id, MessageType::Response, OpCode::Query);
    response.metadata.response_code = code;
    response
        .to_vec()
        .map_err(|error| format!("DNS error response encoding failed: {error}"))
}

fn limit_udp_response(response: Vec<u8>) -> Result<Vec<u8>, String> {
    if response.len() <= UDP_SAFE_RESPONSE_SIZE {
        return Ok(response);
    }
    match Message::from_vec(&response) {
        Ok(message) => {
            let mut message = message.truncate();
            message.answers.clear();
            message.authorities.clear();
            message.additionals.clear();
            let truncated = message
                .to_vec()
                .map_err(|error| format!("DNS truncated response encoding failed: {error}"))?;
            if truncated.len() > UDP_SAFE_RESPONSE_SIZE {
                return Err("DNS truncated response still exceeds the UDP size limit".to_string());
            }
            Ok(truncated)
        }
        Err(error) => Err(format!(
            "Oversized DNS response could not be safely truncated: {error}"
        )),
    }
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    client_ip: IpAddr,
    resolver: Arc<DnsResolver>,
) -> Result<(), String> {
    loop {
        let mut prefix = [0u8; 2];
        match tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut prefix)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(format!("DNS TCP length read failed: {error}")),
            Err(_) => return Ok(()),
        }

        let length = u16::from_be_bytes(prefix) as usize;
        if !(12..=MAX_DNS_MESSAGE_SIZE).contains(&length) {
            return Err(format!(
                "DNS TCP message length {length} is outside allowed bounds"
            ));
        }
        let mut packet = vec![0u8; length];
        tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut packet))
            .await
            .map_err(|_| "DNS TCP query read timed out".to_string())?
            .map_err(|error| format!("DNS TCP query read failed: {error}"))?;

        let response = process_packet(&resolver, &packet, Some(client_ip)).await?;
        if response.len() > u16::MAX as usize {
            return Err("DNS TCP response exceeds protocol size".to_string());
        }
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .map_err(|error| format!("DNS TCP response prefix write failed: {error}"))?;
        stream
            .write_all(&response)
            .await
            .map_err(|error| format!("DNS TCP response write failed: {error}"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsConfig, RecordsConfig};
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn query() -> Message {
        let mut message = Message::new(452, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("dns-test.example").unwrap(),
            RecordType::A,
        ));
        message
    }

    #[tokio::test]
    async fn serves_dns_over_udp_and_tcp() {
        let reserver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = reserver.local_addr().unwrap();
        drop(reserver);

        let records = RecordsConfig {
            a: HashMap::from([("dns-test.example".to_string(), Ipv4Addr::new(192, 0, 2, 10))]),
            ..RecordsConfig::default()
        };
        let server = DnsServer::new(DnsResolver::new(DnsConfig::default(), records));
        let server_task = tokio::spawn(async move { server.run(Some(addr)).await });

        let udp_response = tokio::time::timeout(
            Duration::from_secs(2),
            crate::client::query_server(addr, &query()),
        )
        .await
        .expect("UDP DNS request should complete")
        .expect("UDP DNS request should succeed");
        assert_eq!(udp_response.answers.len(), 1);

        let mut tcp = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await
            .expect("TCP DNS listener should accept connections")
            .expect("TCP DNS connection should succeed");
        let packet = query().to_vec().unwrap();
        tcp.write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tcp.write_all(&packet).await.unwrap();
        let mut prefix = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), tcp.read_exact(&mut prefix))
            .await
            .expect("TCP DNS response prefix should arrive")
            .unwrap();
        let length = u16::from_be_bytes(prefix) as usize;
        let mut response_bytes = vec![0u8; length];
        tcp.read_exact(&mut response_bytes).await.unwrap();
        let tcp_response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(tcp_response.id, 452);
        assert_eq!(tcp_response.answers.len(), 1);

        server_task.abort();
    }
}
