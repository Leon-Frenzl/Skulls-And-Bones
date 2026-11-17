# S&B Sovereign Mesh (`sb-mesh`) — Tactical Roadmap & Architecture TODO

> **Dezentrales P2P Overlay-Netzwerk • Pure-Rust WireGuard • Kryptografische Node-Attestation**  
> Autarke P2P-Netzwerk-Engine im 14-Core-Ökosystem (historische Satelliten wie Sovereign Browser oder NetGate wurden ausgegliedert).  
> *Sicherheitsmarke: Skulls & Bones ([skulls-and-bones.org](https://www.skulls-and-bones.org))*  

---

## 1. Produkt-Vision & Kernprinzipien

Das heutige Internet basiert auf zentralisierten DNS-Servern, Certificate Authorities (CAs) und unverschlüsseltem IP-Routing, das von ISPs, Cloud-Providern und staatlichen Akteuren überwacht und zensiert werden kann.

**S&B Mesh (`sb-mesh`)** bricht mit dieser Abhängigkeit durch ein autarkes, kryptographisches Overlay-Netzwerk:

1. **Air-Gap First (Default: 0 Hops / 0 Peers):**
   - Das System ist standardmäßig zu 100% isoliert. Keine automatischen Verbindungen zu fremden Servern.
   - Keine Mockups, keine erfundenen Zwischenknoten. Jede Verbindung ist ein verifizierter, direkter kryptographischer Peer.
2. **Pure-Rust User-Space Transport:**
   - Keine Kernel-Treiber oder Root-Rechte erforderlich.
   - Basierend auf dem **Noise Protocol Framework (Noise_IK)** und Pure-Rust WireGuard (`boringtun`).
3. **End-to-End ChaCha20-Poly1305 Verschlüsselung:**
   - Sämtlicher Payload-Verkehr ist atomar authentifiziert und verschlüsselt.
   - Perfect Forward Secrecy (PFS) durch automatisches Key-Rekeying im Minutentakt.
4. **Entkoppeltes Schlüssel-Management (`sb-key`):**
   - Node-Identitäten und ephemere Session-Keys stammen aus der zentralen `sb-key` Engine. Hardware-Bindungen (TPM 2.0 / FIDO2) werden modular von `sb-key` verwaltet, wodurch der Mesh-Transport schlank und frei von Treiberabhängigkeiten bleibt.
5. **Direktes P2P & NAT-Traversal:**
   - Bevorzugt direkte Peer-to-Peer-Verbindungen (UDP Hole Punching / STUN).
   - Relays nur als Ausfall-Ebene bei strikten symmetrischen Firewalls — niemals als künstlich erzwungene Multi-Hop-Kette.

---

## 2. Geplante Modul-Architektur (`tools/sb-mesh/src/`)

```
tools/sb-mesh/
├── Cargo.toml
├── TODO.md
├── src/
│   ├── lib.rs                  # Öffentliche Crate-Schnittstelle & Engine-Handle
│   ├── main.rs                 # Standalone Mesh Daemon CLI (`sb-mesh daemon`)
│   ├── config.rs               # Konfiguration (MeshConfig, ListenPort, Interface)
│   ├── identity/               # Kryptographische Node-Identität
│   │   ├── mod.rs
│   │   └── keypair.rs          # Curve25519 Schlüsselpaar & Fingerprint (Delegation an sb-key)
│   ├── crypto/                 # Krypto-Primitive
│   │   ├── mod.rs
│   │   ├── noise.rs            # Noise_IK Handshake & State Machine
│   │   └── chacha.rs           # ChaCha20-Poly1305 Authenticated Encryption
│   ├── transport/              # Netzwerk-Transport-Schicht
│   │   ├── mod.rs
│   │   ├── wireguard.rs        # User-Space WireGuard Engine (Boringtun / Tokio)
│   │   └── udp_socket.rs       # Asynchrones Tokio UDP-Socket-Handling
│   ├── discovery/              # Peer-Erkennung & Adressierung
│   │   ├── mod.rs
│   │   ├── mdns.rs             # Lokale LAN-Peer-Erkennung (Multicast)
│   │   └── rendezvous.rs       # Dezentrales P2P Rendezvous / NAT-Hole-Punching
│   ├── topology/               # Mesh-Topologie & Zustandsverwaltung
│   │   ├── mod.rs
│   │   ├── peer_table.rs       # Verifizierte aktive Peers (ID, IP, Latenz, Keepalive)
│   │   └── telemetry.rs        # Live RTT-Messung, Paketverlust, Durchsatz
│   └── ipc/                    # Lokale Schnittstelle für Browser & Werkzeuge
│       ├── mod.rs
│       └── server.rs           # Inter-Process-Communication (Named Pipe / Unix Domain Socket)
└── tests/
    ├── test_identity.rs        # Tests für Schlüsselableitung & Node-ID
    ├── test_handshake.rs       # Tests für Noise_IK Handshake
    └── test_p2p_mesh.rs        # Integrationstest für 2-Node Verbindung
```

---

## 3. Entwicklungs-Phasen & Meilensteine

### Phase 1: Fundament & Kryptographische Node-Identität (Implementiert)
- [x] **Projekt-Scaffolding (`Cargo.toml`):**
  - Tokio (async I/O), Clap (CLI), `x25519-dalek`, `chacha20poly1305`, `sha2`, `serde`, `ratatui`, `crossterm`.
- [x] **`identity/keypair.rs`:**
  - Erzeugung von X25519 Ephemeral- & Static-Keypairs via `x25519-dalek`.
  - Generierung deterministischer Node-IDs im Format `sbm-0x<hex-hash>`.
  - Export von Public Keys als WireGuard-kompatible Base64-Strings.
- [x] **Entkopplung der Hardware-Schlüsselverwaltung an `sb-key`:**
  - Der Mesh-Transport operiert mit standardisierten X25519-Schlüsseln; Hardware-Bindungen (TPM 2.0, YubiKey FIDO2) obliegen dem dedizierten Werkzeug `sb-key`.
- [x] **Unit-Tests:**
  - Verifikation von Schlüsselpaar-Generierung, Fingerprinting und Serialisierung in `tests/test_mesh.rs`.

---

### Phase 2: Pure-Rust WireGuard & ZK-Platform-Attestation Engine (Implementiert)
- [x] **`crypto.rs`:**
  - Diffie-Hellman Session Key Derivation via Curve25519.
  - Authentifizierte ChaCha20-Poly1305 AEAD Verschlüsselung und Entschlüsselung.
  - 64-Bit Monotone Nonce-Counter gegen Replay-Attacken.
  - Paket-Packing und Header-Unpacking (`PacketType`, Pubkey, Nonce-Counter, Encrypted Payload).
- [x] **`zk_attest.rs` (Universelle Phase-2 ZK-Attestation für ALLE Nodes):**
  - Curve25519 / Ristretto-basierte Schnorr-Sigma Zero-Knowledge Proofs (ZK-PoK).
  - **Exakt 0 Bits Hardware-Leakage:** Keine TPM EK-Zertifikate, keine Seriennummern, keine CPU-IDs, keine BIOS-Hashes im Datenstrom.
  - Fiat-Shamir Heuristik mit kryptographischer Bindung an Peer-Public-Key, Session-Nonce und Policy-Merkle-Root (Anti-Replay & Anti-MitM).
  - Gegenseitige Verifikation bei `HandshakeInit` und `HandshakeResp` in < 5ms.
- [x] **`transport.rs`:**
  - Asynchroner Tokio UDP Socket Manager (`0.0.0.0:58888`).
  - Zero-Kernel / User-Space Transport ohne TUN/Wintun Treiber oder Root/Admin-Rechte.
  - Handshake Init / Handshake Response mit integrierter ZK-Validierung.
  - Ping / Pong RTT Latenzberechnung.
  - Vollständige Air-Gap Killswitch Durchsetzung (strikte Paket-Isolation).
- [x] **Integrationstests (`tests/test_mesh.rs`):**
  - Gegenseitige ZK-Attestation, Replay- und Manipulationsabwehr, Zero-Hardware-Leakage (136-Byte kompakter Beweis).

---

### Phase 3: Peer Discovery & Pairing Protocol (Implementiert)
- [x] **`discovery.rs`:**
  - Lokale LAN-Erkennung via UDP Broadcast Beacon auf Port 58889.
  - Automatisches Entdecken benachbarter S&B Nodes ohne externe Cloud-Server.
- [x] **`peer.rs` & `topology`:**
  - Thread-sichere Peer-Tabelle (`Arc<RwLock<PeerTable>>`).
  - Speichert: `NodeId`, `PublicEndpoint`, `OverlayIP`, `Status`, `BytesSent`, `BytesRecv`, `RttMs`.
  - Persistenz in `~/.sb-mesh/peers.toml`.
- [x] **`tui.rs` Ratatui Dashboard & CLI:**
  - Vollständiges Ratatui TUI Dashboard mit Cyberpunk-Palette (Header, Peer-Liste, 4 Tabs: Telemetrie, LAN Discovery, Handshake Log, Pairing Token).
  - CLI Subcommands: `tui`, `daemon`, `status`, `peer add|list|remove`, `pair generate|connect`, `ping`, `airgap`.

---

### Phase 4: Telemetrie & Reale Topologie (In Progress)
- [x] **`topology/telemetry.rs`:**
  - Authentifizierter Echo-Ping-Loop zu aktiven Peers.
  - Berechnung echter Round-Trip-Times (RTT in ms).
  - Ermittlung von RX/TX-Bytes.
- [x] **Zero-Mockup Garantie:**
  - Standardzustand bei Offline/Air-Gap: Exakt 0 Peers, 0 Hops, 0.0 ms.
  - Peer-Liste enthält ausschließlich reale Knoten.

---

### Phase 5: Historische Browser- & Satelliten-Integration (Ausgegliedert / Historisch)
> *Hinweis:* Die früheren experimentellen Komponenten `sb-browser`, `sb-ssh` und `sb-vault` wurden aus dem Kern-Workspace ausgegliedert. Die IPC- und Tunnel-Schnittstellen in `sb-mesh` verbleiben als generische Integrationspunkte für autorisierte Tools und Kern-Dienste.
- [x] **`src/ipc.rs`:**
  - Asynchroner TCP Loopback Server auf `127.0.0.1:58890` (Cross-Platform) & Named Pipe Support.
  - JSON-RPC-Schnittstelle (`GetStatus`, `ListPeers`, `SendPing`, `SetAirGap`).
  - `IpcClient` für externe Anwendungen und Kern-Tools.
- [x] **Historische Browser-Anbindung (Prototyp):**
  - Ursprüngliche IPC-Abfrage für Mesh-Status und Daemon-Visualisierung (`sbm://mesh`).
- [x] **Historische AutoSSH- & Fleet-Integration (Prototyp):**
  - **SSH-over-Mesh Transport:** Kapselung von SSH-Traffic über interne Streams zu `<node>.sbm` (Port 22 im WAN geschlossen).
  - **Flotten-Discovery:** Export aktiver Peer-Knoten mit OS-Tags und Latenzen über `127.0.0.1:58890` für Management-Werkzeuge.
  - **Atomare Hardware-Eviction:** `GossipKind::RevokeNode` trennt sofort alle Sockets, verwirft Pakete und löscht Routing-Einträge der gebannten Node-ID aus dem Schwarm.
  - **Selektiver Ingress & Port Gates:** Gesteuertes Exposing einzelner Ports mit Schnorr-basierten ZK-Capability-Tokens (Phase 13).

---

### Phase 6: Sovereign Name System (SNS / `.sbm`) & Name Layering (Implementiert)
> **Überwindung von Zooko's Triangle durch eine 3-Schichten-Architektur** (Zero ICANN, Zero CAs, Zero Name-Squatting, Zero DNS-Leaks)
- [x] **`src/dns.rs` (Sovereign Resolver Engine):**
  - **Schicht 0: Canonical Cryptographic Layer (Global & Objektiv):**
    - Direkte Auflösung von `<node_id>.sbm` (z. B. `0x12d3ae3b.sbm` / `sbm-0x12d3ae3b.sbm`).
    - $0\,\text{ms}$ Lookup-Latenz, da Ziel-Pubkey/Node-ID direkt im Domainnamen codiert ist.
  - **Schicht 1: Cryptographic Zone / Swarm Layer (Delegiert & Dezentral):**
    - Auflösung von `<service>.<zone>.sbm` (z. B. `vault.team-0x9a4f.sbm`).
    - Schnorr-signierte Name-Records (`NameRecord { service, zone, target_node_id, target_endpoint, target_port, epoch, ttl_secs, signature_r, signature_s }`).
    - In-Memory Cache und Kademlia DHT Topic Verteilung.
  - **Schicht 2: Petname / Cognitive Layer (Lokal & Subjektiv):**
    - Auflösung lokaler menschenlesbarer Aliase aus `~/.sb-mesh/peers.toml` (z. B. `nas.sbm`, `vault.sbm`).
    - Volle Souveränität des Nutzers über seinen Namensraum — kein globales Typosquatting möglich.
- [x] **SOCKS5 Domain-Name Hook (`src/proxy.rs`):**
  - RFC 1928 Adresstyp `0x03` (*Domain Name*): Intercept von `.sbm`-Domains im User-Space Proxy (`127.0.0.1:1080`).
  - Automatisches Routing in den authentifizierten ChaCha20-Poly1305 P2P-WireGuard-Tunnel.
- [x] **Unit- & Integrationstests:**
  - 10 Unit-Tests in `lib` + 14 Integrationstests in `tests/test_mesh.rs` (insgesamt 24 Tests erfolgreich).
  - Layer-0 bis Layer-2 Namensauflösung, Signaturvalidierung, Replay-Schutz, SOCKS5 Domain-Routing.

---

### Phase 7: Sovereign Multi-Hop Encrypted Relay (Implementiert)
> **Automatischer Zero-Knowledge Fallback bei beidseitigem symmetrischem NAT / CGNAT**
- [x] **`src/relay.rs` (Encrypted Transit Engine):**
  - Kapselung von WireGuard-Paketen in `RelayPacket` (`MAGIC_RELAY = [b'S', b'B', b'M', b'R']`).
  - Routing-Header mit `target_node_id`, `source_node_id` und `hop_count` (Loop-Schutz: max. 3 Hops).
  - Reiner Blind-Forwarder: Der Relay-Node besitzt zu keinem Zeitpunkt die ChaCha20-Poly1305 Session-Schlüssel der Endknoten.
  - Integration in `MeshTransport`: Empfang, Weiterleitung und lokales Ausliefern.

---

### Phase 8: Pluggable Traffic Obfuscation & Anti-DPI Framing (Implementiert)
> **Schutz vor WireGuard-Paketfilterung in Hotel-, Bahn-, Campus- und Zensur-Netzwerken**
- [x] **`src/obfuscation.rs` (Chameleon Noise Framing):**
  - **Randomized Noise Padding:** Polstert feste WireGuard-Paketlängen (148, 92, 32 Bytes) auf uniforme Buckets (128, 256, 512, 1024, 1400 Bytes) oder hängt 0–64 Byte pseudozufälliges Rauschen an.
  - **Header Masking:** Maskiert statische Paket-Header mit sitzungsbasiertem Entropie-Stream, sodass Traffic für DPI wie unstrukturiertes Rauschen oder DTLS 1.2 aussieht.
  - Konfigurierbar in `MeshConfig` via `traffic_obfuscation = true`.

---

### Phase 9: S/Kademlia Cryptographic Sybil Defense (Implementiert)
> **Mathematische Sybil- und Eclipse-Abwehr im isolierten S&B Kademlia DHT**
- [x] **`src/identity.rs` & `src/rendezvous.rs`:**
  - Krypto-Puzzle für Node-IDs: Statischer Proof-of-Work $\text{Sha256}(\text{PublicKey} \parallel \text{Nonce}) < 2^{256 - k}$ (16 führende Null-Bits).
  - $0\,\text{ms}$ Verifikation für legitime Peers; verhindert massenhafte Sybil-Erzeugung zur Manipulation von DHT-Topics.
  - Integration von PoW-Nonce in Pairing-Tokens (`sbm-pair://...`), `NodeIdentity` und DHT-Routing.

---

### Phase 10: Maybenot / WTF-PAD Timing-Jitter & Chaff Cover Traffic (Implementiert)
> **Schutz vor Machine-Learning Traffic-Fingerprinting (Inter-Packet Arrival Times)**
- [x] **`src/obfuscation.rs`:**
  - Micro-Timing Jitter (2–15ms stochastische Verzögerung bei Paket-Bursts via `compute_timing_jitter`).
  - Probabilistische Dummy-Cover-Pakete (`generate_chaff_packet`), die von Empfängern (`is_chaff_packet`) lautlos verworfen werden.
  - Zerstört Erkennungsgenauigkeit von Deep-Learning Traffic-Klassifikatoren (Var-CNN, Tik-Tok).

---

### Phase 11: Instant Connection Migration & QUIC-Style Roaming (Implementiert)
> **Nahtloser Wechsel zwischen Wi-Fi, LTE und wechselnden NAT-Endpoints ohne Verbindungsabbruch**
- [x] **`src/transport.rs` & `src/peer.rs`:**
  - Stateless Connection Migration: Wenn ein authentifiziertes Paket mit gültigem Counter von einer neuen IP:Port-Kombination eintrifft, wird `peer.parsed_endpoint` sofort migriert.
  - Zähler für `roaming_events` im `PeerState` für Telemetrie und Audit-Logs.
  - Keine Neu-Aushandlung, kein Handshake-Freeze für laufende Streams.
  - Verifiziert durch Integrationstest `test_instant_connection_roaming`.

---

### Phase 12: In-Memory Secret Zeroization & Anti-RAM-Dumping (Implementiert)
> **Schutz privater Schlüssel und ephemerer Secrets vor RAM-Dumps und Cold-Boot-Angriffen**
- [x] **`src/crypto.rs` & `src/identity.rs`:**
  - `ZeroizingKey([u8; 32])` mit `Zeroize` und `ZeroizeOnDrop`.
  - `derive_session_zeroizing_key()` erzeugt ephemere Sitzungsschlüssel, die beim Verlassen des Scopes mit Nullen überschrieben werden.
  - Verifiziert durch Unit-Test `test_zeroizing_key_clears_memory`.

---

### Phase 13: Decentralized Capability-Based ACLs (Implementiert)
> **Feingranulare Capability-Firewall auf Port-Ebene ohne zentralen Cloud-IdP (Macaroon-Prinzip)**
- [x] **`src/acl.rs` & `src/proxy.rs`:**
  - Signierte `CapabilityToken` (`allowed_ports`, `valid_until`, `issuer_sig`) via Schnorr-Sigma-Signaturen.
  - `AclEngine` mit Default-Deny- und Default-Allow-Modus.
  - Lokale Durchsetzung im SOCKS5-Proxy: Ablehnung unerlaubter Ziel-Ports mit RFC 1928 Fehler `0x02` (*Connection not allowed by ruleset*).
  - Verifiziert durch Unit-Tests in `acl.rs` und Integrationstest `test_socks5_capability_acl_enforcement`.

---

### Phase 14: In-Band Rekeying & Perfect Forward Secrecy (PFS Ratchet) (Implementiert)
> **Periodischer Austausch ephemerer Sitzungsschlüssel ohne Stream-Unterbrechung**
- [x] **`src/transport.rs` & `src/crypto.rs`:**
  - `PacketType::RekeyInit` (6) und `PacketType::RekeyResp` (7) für in-band Ephemeral-Diffie-Hellman Ratchet.
  - `ratchet_forward(current_key, eph_shared, epoch)` leitet deterministisch und kollisionsresistent neue 256-Bit Sitzungsschlüssel ab.
  - Alte Schlüssel werden im Speicher sicher mit Nullen überschrieben (`ZeroizeOnDrop`).
  - Verifiziert durch Unit-Test `test_ratchet_forward_pfs` und End-to-End-Integrationstest `test_in_band_rekeying_pfs_ratchet`.

---

### Phase 15: Multi-Path Fast Failover (IPv4 / IPv6 / Relay Racing) (Implementiert)
> **Maximale Ausfallsicherheit bei instabilen Leitungen durch paralleles Pfad-Racing**
- [x] **`src/transport.rs` & `src/peer.rs`:**
  - `PathType` (`DirectIPv4`, `DirectIPv6`, `Relay`) und `CandidatePath` mit Latenz-Tracking (`rtt_ms`), Erfolgs-Zeitstempel und Failure-Counter.
  - `probe_candidate_paths` sendet gleichzeitige Probes an alle Kandidaten-Endpunkte (Path Racing).
  - Automatisches Umschalten auf die schnellste und zuverlässigste Route (`failover_to_best_path()`).
  - Verifiziert durch Unit-Test `test_candidate_path_fast_failover` und Integrationstest `test_multi_path_candidate_racing_and_failover`.

---

### Phase 16: Ephemeral Air-Gapped Pairing & Terminal QR Scanning (Implementiert)
> **Sichere optische Übertragung flüchtiger Einladungen ohne Metadaten- oder Key-Risiko**
- [x] **`src/identity.rs` & `src/tui.rs`:**
  - Zeitbefristete Tokens (`generate_pairing_token_with_ttl`) mit TTL-Schutz (Standard: 300s). Abgelaufene Tokens werden mathematisch abgewiesen.
  - High-Density Terminal QR-Code Rendering (`render_terminal_qr`) mit Unicode-Half-Blocks für CLI (`sb-mesh pair generate <ENDPOINT> --qr`) und Tab `[4] Kopplung & Token` in der TUI.
  - 1-Klick Auto-Pairing in Tab `[2] LAN Discovery`: Sofortige Übernahme via `[Enter]` und Handshake-Start.
  - Periodischer LAN-Discovery Broadcast Loop (alle 15 Sekunden).
  - Verifiziert durch Unit-Tests `test_pairing_token_with_ttl_expiration` und `test_render_terminal_qr`.

---

### Phase 17: Autonomes Multi-Hop Mesh-Routing (Implementiert)
> **Dynamisches Distance-Vector Pathfinding über beliebige Knotenketten ($A \rightarrow B \rightarrow C \rightarrow D$)**
- [x] **`src/routing.rs` & `src/relay.rs` & `src/transport.rs`:**
  - `RoutingTable` & `RouteEntry` mit Loop-Defense (Sequenznummern & Max 8 Hops) und Metrik-Berechnung ($RouteCost = RTT + 20 \times Hops + Loss$).
  - `RouteAdvertisement` zur Verteilung von Distanz-Vektoren zwischen Nachbarknoten.
  - Zero-Knowledge Forwarding in `RelayManager::process_packet_with_routing`: Transit-Knoten leiten Pakete entlang der optimalen Route weiter, ohne den inneren Payload entschlüsseln zu können.
  - Verifiziert durch Unit-Tests in `routing.rs`, `relay.rs` und 4-Knoten-Ketten-Integrationstest `test_autonomous_multi_hop_mesh_routing`.

---

### Phase 18: Sovereign Subnet Router & Exit Nodes (Implementiert)
> **100% User-Space Routing für entfernte Heim-LAN-Subnetze und vollständiges Exit-Node Internet-Tunneling**
- [x] **`src/config.rs` & `src/proxy.rs`:**
  - `MeshConfig` erweitert um `advertised_subnets: Vec<String>`, `is_exit_node: bool`, `exit_node: Option<String>`.
  - `SubnetRouter` mit mathematischem CIDR-Prefix-Matching (`ip_matches_cidr`, z.B. `192.168.1.0/24`).
  - SOCKS5-Proxy fängt IPv4-Ziele ab und leitet Subnetz- oder Exit-Traffic nahtlos über den Subnet-Router um — ganz ohne Kernel-Treiber oder Root-Rechte.
  - Verifiziert durch Unit-Tests `test_ip_matches_cidr`, `test_subnet_router_resolution` und End-to-End-Integrationstest `test_subnet_router_and_exit_node`.

---

### Phase 19: Dezentraler P2P-Gossip & CRDT-Zustandssynchronisation (Implementiert)
> **Epidemische Verbreitung von Schlüssel-Widerrufen (CRL) und Swarm-Zone-Records**
- [x] **`src/gossip.rs` & `src/transport.rs`:**
  - `GossipEngine` mit Anti-Entropy Deduplizierung (SHA-256 Message ID History) gegen Replay- und Endlosschleifen.
  - Certificate Revocation List (CRL): `GossipKind::RevokeNode` führt zur sofortigen Trennung kompromittierter Peers aus der `PeerTable` und stillschweigendem Verwerfen von Paketen im Transport (`is_revoked`).
  - CRDT-Replizierung von Swarm Zone Records (`ZoneRecordSync`) im P2P-Schwarm.
  - Verifiziert durch Unit-Tests in `gossip.rs` und 3-Knoten-Gossip-Test `test_gossip_key_revocation_and_zone_sync`.

---

### Phase 20: Adaptives Energiespar-Keepalive (Implementiert)
> **Sleep-Aware Heartbeat mit dynamischem Backoff zur Akku- und Bandbreiten-Schonung**
- [x] **`src/peer.rs` & `src/transport.rs`:**
  - `HeartbeatMode`: `Active` (2s Keepalive bei Traffic), `Idle` (25s Keepalive nach 30s Inaktivität), `PowerSave` (120s Backoff nach 2min Inaktivität).
  - Wake-on-Traffic: Sobald Datenverkehr (`PacketType::Data` oder Relays) registriert wird, springt der Modus verzögerungsfrei auf `Active` zurück.
  - `is_heartbeat_due` steuert Pings adaptiv nach aktuellem Modus.
---

### Phase 21: Enterprise Politur — High-Speed Local Port Forwarding & Mesh Tunneling (Status: 🟢 Teilweise Erledigt)
- [x] **Loopback-Port-Forwarder (`sb-mesh share` & `sb share`):**
  - Bindet den Listener ausschließlich an `127.0.0.1`; Token-Option und falsche Mesh-/Verschlüsselungsbehauptungen wurden entfernt.
  - Der Forwarder ist nur lokal erreichbar und wird nicht als Mesh-Ingress oder Produktionsfreigabe beworben.
  - Automatischer Vorab-Check des lokalen Zielports (`check_local_service`) und Verbindungsstatistiken.
- [ ] **Authentisierter Mesh-Ressourcen-Ingress:**
  - Erst freigeben, wenn Verbindungen über authentisierten, verschlüsselten Mesh-Transport laufen und Identität, Ressourcen-ACL, Rechtewiderruf und Audit serverseitig geprüft werden.
- [ ] **Zero-Config NAT Traversal & STUN Hardening:**
  - Robustere STUN-Fallbacks bei extrem restriktiven Unternehmens-Firewalls.
  - Automatisches Fallback auf dezentrales Relay-Forwarding bei symmetrischem NAT.

---

### Phase 22: Multi-Meshing & Multi-Tenant Overlay Isolation (Status: � Implementiert)
> **Gleichzeitiger Betrieb mehrerer unabhängiger, benannter Overlay-Netzwerke auf einem einzelnen Knoten**
- [x] **Multi-Mesh Network Registry (`NetworkStore` in `~/.sb-mesh/networks.json`):**
  - Definition benannter isolierter Overlays (`name`, `swarm_topic`, `subnet_cidr`, `keypair`, `psk`, `created_at`).
  - Strikte Trennung aller kryptographischen Schlüssel pro Mesh — kein geteilter Noise-State.
- [x] **User-Space VRF & Zero-Cross-Talk Routing Filter:**
  - Isolierte Routing-Tabellen und CIDR-Subnetze (z. B. `acme-corp` auf `10.42.0.0/16`, `bank-prod` auf `10.43.0.0/16`).
  - Hermetische Firewall: Pakete zwischen verschiedenen Meshes werden im User-Space Kernel stillschweigend verworfen (`validate_vrf_boundary`).
- [x] **Single-Port UDP Packet-Dispatcher (Port 58888):**
  - Eingehende Noise_IK Handshake-Pakete werden anhand eines 8-Byte kryptographischen Swarm-Headers (`SBM2`) im RAM an die zuständige isolierte Mesh-Instanz geroutet (`SinglePortDispatcher`).
- [x] **Flottenknoten Multi-Tenancy (`sb-node`):**
  - Ein einzelner Linux VPS hostet parallel als Relay/Anchor für 10+ Kunden-Meshes ohne gegenseitige Sichtbarkeit (`sb-node daemon`, `sb-node telemetry`).
- [x] **CLI Subcommands (`sb-mesh network`):**
  - `sb-mesh network create <name> --subnet <cidr> [--psk] [--desc <text>]`
  - `sb-mesh network list`
  - `sb-mesh network current`
  - `sb-mesh network switch <name>`
  - `sb-mesh network delete <name>`
- [x] **Symbiose mit `sb context`:**
  - `sb use <context>` schaltet automatisch das lokal aktive Mesh-Netzwerk um (`sync_mesh_network_with_context`).

---

### Phase 23: Mesh-gebundenes Rollen- & Rechte-Management (Mesh-RBAC) mit SBM-TEP & TUI (Status: 🟢 Implementiert)
> **Mandanten-isoliertes kryptografisches User Management, feingranulare Capabilities & interaktive Ratatui-TUI**

- [x] **Phase 1: RBAC Data Engine & Mandanten-Storage (`src/rbac.rs`):**
  - Definition von `MeshRole` (`Admin`, `Developer`, `Operator`, `Consumer`, `Auditor`).
  - Definition von `Capability` (`tunnel:ssh`, `tunnel:port:<N>`, `tunnel:any`, `stream:transfer`, `mesh:invite`, `mesh:krl`, `telemetry:read`).
  - `MeshMember`: Bindung an Node-ID, X25519/Ed25519 Pubkey, Mesh-Name, Rolle, Capabilities, Erstellungs- und Verfallszeitpunkt (`expires_at`).
  - `MeshRbacStore`: Isolierte Speicherung pro Mesh unter `~/.sb-mesh/tenants/<mesh>/rbac.json` bzw. `/etc/sb/tenants/<mesh>/rbac.json` inklusive atomarer `sb-db`-Persistenz (`mesh_rbac.sbdb`).
  - Krypto-Enforcement via SBM-TEP Ticket Exchange: Tickets enthalten signierte Capabilities; Dispatcher und Stealth-Ingress erzwingen Permissions per Silent Drop bei unautorisierten Port- oder Frame-Zugriffen.
- [x] **Phase 2: CLI-Befehlssatz (`sb-mesh rbac` & `sb-node member`):**
  - `sb-mesh rbac list [--mesh <m>]`: Zeigt alle Mitglieder, Rollen und Capabilities eines Meshs.
  - `sb-mesh rbac add --mesh <m> --name <user> --pubkey <key> --role <role> [--caps <c1,c2>]`
  - `sb-mesh rbac revoke --mesh <m> --name <user> [--reason <text>]`: Sofortige KRL-Eviction und Ingress-Sperre.
  - `sb-mesh rbac remove --mesh <m> --name <user>`: Entfernt ein Mitglied vollständig aus dem Mesh.
  - `sb-node member list / add / revoke / remove`: Server-seitiges Pendant mit atomarer `.sbdb`-Dokumentensynchronisation.
- [x] **Phase 3: Interaktive Ratatui TUI (`sb-mesh rbac --ui`):**
  - Eigenständige TUI oder Tab in `sb-mesh tui` mit Mesh-Switcher (`[Tab]`).
  - Cyberpunk Dark-Mode Layout mit Live-Peers, Mitglieder-Liste und Detail-Rechte-Matrix.
  - Tastatur-Shortcuts: `[A]` Add Member, `[E]` Edit Capabilities / Cycle Role, `[R]` Revoke, `[D]` Delete Member, `[Q]` Exit.
- [x] **Phase 4: Stealth Tunnel Automatisierung & Lifecycle-Hardening (`sb-mesh stealth`):**
  - **Automatischer Key- & Swarm-Lookup:** Zero-Config Start — Server-Public-Key und Swarm-Topic werden ohne manuelle Flags direkt aus dem aktiven SBM-TEP Lease Ticket (oder per schnellem Pre-Auth Knock) geladen.
  - **Inaktivitäts-Watchdog (`--idle-timeout`, Standard: 120s):** Schließt den Stealth-Tunnel-Hintergrundprozess nach 2 Minuten Inaktivität sauber, sodass keine verwaisten Prozesse das System blockieren.
  - **Oneshot-Modus (`--oneshot` / `-o`):** Beendet den Daemon automatisch, sobald die erste SSH-Sitzung beendet wird.
  - **Socket AddrInUse Auto-Detection:** Erkennt bereits laufende Stealth-Tunnel und bindet sich transparent ein, anstatt mit Fehlermeldungen abzustürzen.

---

## 4. Sicherheits- & Architekturanforderungen

| Anforderung | Implementierung | Sicherheitsziel |
| :--- | :--- | :--- |
| **Air-Gap Strictness** | Default-Status `Disconnected`, 0 externe Verbindungen | Kein unbeabsichtigtes Phoning-Home |
| **Krypto-Standard** | ChaCha20-Poly1305, Curve25519, BLAKE2s | Post-Quantum-vorbereitet, moderne Primitive |
| **Replay-Schutz** | Monoton steigende 64-Bit Counter + Sliding Window | Schutz vor Paket-Injektion und Wiedergabe |
| **Zero Mockup** | Datenstrukturen spiegeln 1:1 reale Sockets wider | Keine irreführende UI oder falsche Sicherheit |
| **Hardware-Sicherheit** | Delegiert an `sb-key` (TPM 2.0 & FIDO2 YubiKey) | Modulare Trennung von Schlüsselverwaltung und Transport |
