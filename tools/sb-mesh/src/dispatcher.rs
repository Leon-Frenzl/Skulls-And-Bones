//! Single-Port UDP Packet-Dispatcher (Port 58888)
//! Multiplexing beliebig vieler isolierter Mesh-Netzwerke / VRFs über einen einzigen
//! offenen UDP-Port ohne zusätzliche Firewall-Öffnungen.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

use crate::crypto::{PACKET_MAGIC, PACKET_MAGIC_V2};
use crate::relay::RELAY_MAGIC;

/// Ein an einen spezifischen Tenant weitergeleitetes Datagramm
#[derive(Debug, Clone)]
pub struct DispatchedPacket {
    pub sender_addr: SocketAddr,
    pub raw_data: Vec<u8>,
    pub swarm_tag: Option<[u8; 8]>,
}

/// Registrierter Tenant für ein isoliertes Overlay-Netzwerk
#[derive(Clone)]
pub struct TenantRegistration {
    pub name: String,
    pub swarm_tag: [u8; 8],
    pub sender: mpsc::Sender<DispatchedPacket>,
    pub packets_routed: Arc<std::sync::atomic::AtomicU64>,
}

/// Telemetrie des Single-Port Dispatchers
#[derive(Debug, Clone, Default)]
pub struct DispatcherStats {
    pub total_received: u64,
    pub total_dispatched: u64,
    pub v1_legacy_packets: u64,
    pub v2_tagged_packets: u64,
    pub relay_packets: u64,
    pub dropped_unauthorized: u64,
}

/// Zentraler Single-Port UDP Multiplexer & Demultiplexer
pub struct SinglePortDispatcher {
    pub socket: Arc<UdpSocket>,
    pub listen_port: u16,
    pub air_gap: Arc<RwLock<bool>>,
    tenants: Arc<RwLock<HashMap<[u8; 8], TenantRegistration>>>,
    default_tenant: Arc<RwLock<Option<mpsc::Sender<DispatchedPacket>>>>,
    relay_handler: Arc<RwLock<Option<mpsc::Sender<DispatchedPacket>>>>,
    stats: Arc<RwLock<DispatcherStats>>,
}

impl SinglePortDispatcher {
    /// Bindet den Dispatcher an den angegebenen UDP-Port (Standard: 58888)
    pub async fn bind(listen_port: u16, air_gap: Arc<RwLock<bool>>) -> Result<Arc<Self>, String> {
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
                    "Dispatcher konnte Port {} nicht binden: {}",
                    listen_port, e
                ));
            }
        };

        let dispatcher = Arc::new(Self {
            socket: Arc::new(socket),
            listen_port,
            air_gap,
            tenants: Arc::new(RwLock::new(HashMap::new())),
            default_tenant: Arc::new(RwLock::new(None)),
            relay_handler: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(DispatcherStats::default())),
        });

        // Hintergrund Empfangs- und Dispatch-Loop starten
        let loop_dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            loop_dispatcher.run_dispatch_loop().await;
        });

        Ok(dispatcher)
    }

    /// Registriert ein benanntes Mesh-Netzwerk / VRF anhand seines 8-Byte Swarm-Tags
    pub async fn register_tenant(
        &self,
        name: &str,
        swarm_tag: [u8; 8],
        sender: mpsc::Sender<DispatchedPacket>,
    ) {
        let mut tenants = self.tenants.write().await;
        tenants.insert(
            swarm_tag,
            TenantRegistration {
                name: name.to_string(),
                swarm_tag,
                sender,
                packets_routed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            },
        );
    }

    /// Entfernt die Registrierung eines Netzwerks
    pub async fn unregister_tenant(&self, swarm_tag: &[u8; 8]) -> Option<String> {
        let mut tenants = self.tenants.write().await;
        tenants.remove(swarm_tag).map(|t| t.name)
    }

    /// Setzt den Fallback-Kanal für ungetaggte Legacy-Pakete (SBM1)
    pub async fn set_default_tenant(&self, sender: Option<mpsc::Sender<DispatchedPacket>>) {
        let mut def = self.default_tenant.write().await;
        *def = sender;
    }

    /// Setzt den Handler für Multi-Hop Relay Pakete (SBMR)
    pub async fn set_relay_handler(&self, sender: Option<mpsc::Sender<DispatchedPacket>>) {
        let mut relay = self.relay_handler.write().await;
        *relay = sender;
    }

    /// Liefert die Anzahl registrierter Tenants
    pub async fn tenant_count(&self) -> usize {
        self.tenants.read().await.len()
    }

    /// Gibt eine Kopie der aktuellen Statistiken zurück
    pub async fn stats(&self) -> DispatcherStats {
        self.stats.read().await.clone()
    }

    /// Sendet ein ausgehendes Datagramm über den zentralen Socket
    pub async fn send_to(&self, data: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        if *self.air_gap.read().await {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Air-Gap aktiv: Senden blockiert",
            ));
        }
        self.socket.send_to(data, target).await
    }

    /// Kern-Schleife: Empfängt Datagramme und leitet sie per Zero-Copy Demux im RAM weiter
    async fn run_dispatch_loop(&self) {
        let mut buf = [0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, sender_addr)) => {
                    // 1. Air-Gap Killswitch Check
                    if *self.air_gap.read().await {
                        let mut st = self.stats.write().await;
                        st.dropped_unauthorized += 1;
                        continue;
                    }

                    if len < 4 {
                        continue;
                    }

                    {
                        let mut st = self.stats.write().await;
                        st.total_received += 1;
                    }

                    let raw_packet = buf[..len].to_vec();

                    // 2. Case A: V2 Multi-Tenant Swarm Tag (SBM2)
                    if len >= 12 && &buf[..4] == &PACKET_MAGIC_V2 {
                        let mut swarm_tag = [0u8; 8];
                        swarm_tag.copy_from_slice(&buf[4..12]);

                        let tenants = self.tenants.read().await;
                        if let Some(tenant) = tenants.get(&swarm_tag) {
                            tenant
                                .packets_routed
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let pkt = DispatchedPacket {
                                sender_addr,
                                raw_data: raw_packet,
                                swarm_tag: Some(swarm_tag),
                            };
                            let _ = tenant.sender.try_send(pkt);

                            let mut st = self.stats.write().await;
                            st.v2_tagged_packets += 1;
                            st.total_dispatched += 1;
                        } else {
                            // Unbekanntes Swarm-Tag: Still im RAM verwerfen
                            let mut st = self.stats.write().await;
                            st.dropped_unauthorized += 1;
                        }
                        continue;
                    }

                    // 3. Case B: Multi-Hop Blind Relay (SBMR)
                    if len >= 7 && &buf[..4] == &RELAY_MAGIC {
                        let relay_opt = self.relay_handler.read().await;
                        if let Some(ref relay_tx) = *relay_opt {
                            let pkt = DispatchedPacket {
                                sender_addr,
                                raw_data: raw_packet,
                                swarm_tag: None,
                            };
                            let _ = relay_tx.try_send(pkt);
                            let mut st = self.stats.write().await;
                            st.relay_packets += 1;
                            st.total_dispatched += 1;
                        } else {
                            let mut st = self.stats.write().await;
                            st.dropped_unauthorized += 1;
                        }
                        continue;
                    }

                    // 4. Case C: Legacy SBM1 WireGuard Paket
                    if len >= 45 && &buf[..4] == &PACKET_MAGIC {
                        let def_opt = self.default_tenant.read().await;
                        if let Some(ref def_tx) = *def_opt {
                            let pkt = DispatchedPacket {
                                sender_addr,
                                raw_data: raw_packet,
                                swarm_tag: None,
                            };
                            let _ = def_tx.try_send(pkt);
                            let mut st = self.stats.write().await;
                            st.v1_legacy_packets += 1;
                            st.total_dispatched += 1;
                        } else {
                            let mut st = self.stats.write().await;
                            st.dropped_unauthorized += 1;
                        }
                        continue;
                    }

                    // 5. Unbekanntes Paketformat: Stillschweigender Drop
                    let mut st = self.stats.write().await;
                    st.dropped_unauthorized += 1;
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_swarm_tag, pack_message, pack_message_v2, PacketType};
    use std::time::Duration;

    #[tokio::test]
    async fn test_single_port_dispatcher_multi_tenant_routing() {
        let air_gap = Arc::new(RwLock::new(false));
        // Use port 0 for dynamic ephemeral port allocation in tests
        let dispatcher = SinglePortDispatcher::bind(0, air_gap.clone())
            .await
            .unwrap();
        let port = dispatcher.socket.local_addr().unwrap().port();

        // Channels for 2 separate mesh tenants
        let (acme_tx, mut acme_rx) = mpsc::channel(16);
        let (bank_tx, mut bank_rx) = mpsc::channel(16);

        let acme_tag = derive_swarm_tag("sbm-swarm-acme");
        let bank_tag = derive_swarm_tag("sbm-swarm-bank");

        dispatcher.register_tenant("acme", acme_tag, acme_tx).await;
        dispatcher.register_tenant("bank", bank_tag, bank_tx).await;
        assert_eq!(dispatcher.tenant_count().await, 2);

        // Send a V2 packet for ACME
        let sender_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let acme_packet = pack_message_v2(
            PacketType::Data,
            &acme_tag,
            &[0xAA; 32],
            1,
            b"ACME_CONFIDENTIAL_PAYLOAD",
        );
        sender_sock
            .send_to(&acme_packet, SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();

        // Send a V2 packet for BANK
        let bank_packet = pack_message_v2(
            PacketType::Data,
            &bank_tag,
            &[0xBB; 32],
            2,
            b"BANK_FINANCIAL_PAYLOAD",
        );
        sender_sock
            .send_to(&bank_packet, SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();

        // Verify ACME receives ACME packet and NOT bank packet
        let received_acme = tokio::time::timeout(Duration::from_millis(500), acme_rx.recv())
            .await
            .expect("Timeout waiting for ACME packet")
            .expect("Channel closed");
        assert_eq!(received_acme.swarm_tag, Some(acme_tag));
        assert!(received_acme
            .raw_data
            .windows(b"ACME_CONFIDENTIAL_PAYLOAD".len())
            .any(|w| w == b"ACME_CONFIDENTIAL_PAYLOAD"));

        // Verify BANK receives BANK packet
        let received_bank = tokio::time::timeout(Duration::from_millis(500), bank_rx.recv())
            .await
            .expect("Timeout waiting for BANK packet")
            .expect("Channel closed");
        assert_eq!(received_bank.swarm_tag, Some(bank_tag));
        assert!(received_bank
            .raw_data
            .windows(b"BANK_FINANCIAL_PAYLOAD".len())
            .any(|w| w == b"BANK_FINANCIAL_PAYLOAD"));

        // Verify stats
        let stats = dispatcher.stats().await;
        assert_eq!(stats.v2_tagged_packets, 2);
        assert_eq!(stats.total_dispatched, 2);
    }

    #[tokio::test]
    async fn test_dispatcher_legacy_sbm1_and_unauthorized_drop() {
        let air_gap = Arc::new(RwLock::new(false));
        let dispatcher = SinglePortDispatcher::bind(0, air_gap.clone())
            .await
            .unwrap();
        let port = dispatcher.socket.local_addr().unwrap().port();

        // Setup default legacy channel
        let (default_tx, mut default_rx) = mpsc::channel(16);
        dispatcher.set_default_tenant(Some(default_tx)).await;

        let sender_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 1. Send legacy SBM1 packet -> Should route to default tenant
        let sbm1_packet = pack_message(PacketType::Ping, &[0x11; 32], 100, b"LEGACY_PING");
        sender_sock
            .send_to(&sbm1_packet, SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();

        let rec_default = tokio::time::timeout(Duration::from_millis(500), default_rx.recv())
            .await
            .expect("Timeout waiting for SBM1 packet")
            .expect("Channel closed");
        assert_eq!(rec_default.swarm_tag, None);

        // 2. Send invalid/unauthorized packet (unknown swarm tag)
        let unknown_tag = [0xEE; 8];
        let unknown_packet = pack_message_v2(
            PacketType::Data,
            &unknown_tag,
            &[0xEE; 32],
            1,
            b"MALICIOUS_DROP",
        );
        sender_sock
            .send_to(&unknown_packet, SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let stats = dispatcher.stats().await;
        assert!(stats.dropped_unauthorized >= 1);
        assert_eq!(stats.v1_legacy_packets, 1);
    }
}
