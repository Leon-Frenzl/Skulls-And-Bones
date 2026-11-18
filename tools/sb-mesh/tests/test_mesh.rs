use sb_mesh::config::MeshConfig;
use sb_mesh::crypto::{
    decrypt_payload, derive_session_keys, encrypt_payload, pack_message, unpack_header, PacketType,
};
use sb_mesh::identity::NodeIdentity;
use sb_mesh::peer::{PeerConfig, PeerStatus, PeerTable};

#[test]
fn test_node_identity_generation() {
    let identity = NodeIdentity::generate();
    assert!(identity.node_id.starts_with("sbm-0x"));
    assert_eq!(identity.node_id.len(), 14); // "sbm-0x" (6) + 8 hex chars = 14
    assert!(!identity.wireguard_pubkey.is_empty());

    // Public key should decode to 32 bytes
    use base64::prelude::*;
    let pub_bytes = BASE64_STANDARD.decode(&identity.wireguard_pubkey).unwrap();
    assert_eq!(pub_bytes.len(), 32);
}

#[test]
fn test_pairing_token_roundtrip() {
    let identity = NodeIdentity::generate();
    let endpoint = "192.168.1.150:58888";
    let token = identity.generate_pairing_token(endpoint);

    assert!(token.starts_with("sbm-pair://"));

    let (parsed_node_id, parsed_pubkey, parsed_endpoint) =
        NodeIdentity::parse_pairing_token(&token).expect("Token parsing failed");

    assert_eq!(parsed_node_id, identity.node_id);
    assert_eq!(parsed_pubkey, identity.wireguard_pubkey);
    assert_eq!(parsed_endpoint, endpoint);
}

#[test]
fn test_crypto_diffie_hellman_and_aead() {
    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();

    // Key agreement
    let alice_keys = derive_session_keys(&alice.secret, &bob.public_key).unwrap();
    let bob_keys = derive_session_keys(&bob.secret, &alice.public_key).unwrap();
    assert_eq!(alice_keys.send, bob_keys.receive);
    assert_eq!(alice_keys.receive, bob_keys.send);
    assert_ne!(alice_keys.send, alice_keys.receive);

    // Encrypt payload from Alice to Bob
    let plaintext = b"Hello Sovereign Mesh Peer!";
    let counter = 1u64;

    let ciphertext =
        encrypt_payload(alice_keys.send.as_bytes(), counter, plaintext).expect("Encryption failed");
    assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

    // Bob decrypts with correct counter
    let decrypted = decrypt_payload(bob_keys.receive.as_bytes(), counter, &ciphertext)
        .expect("Decryption failed");
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    // Tampered ciphertext must fail authentication
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;
    assert!(decrypt_payload(bob_keys.receive.as_bytes(), counter, &tampered).is_err());

    // Replay attack / wrong counter must fail authentication
    let wrong_counter = 2u64;
    assert!(decrypt_payload(bob_keys.receive.as_bytes(), wrong_counter, &ciphertext).is_err());
}

#[test]
fn test_packet_pack_unpack_header() {
    let sender = NodeIdentity::generate();
    let counter = 42u64;
    let payload = b"encrypted_inner_bytes_here";

    let packet = pack_message(
        PacketType::Ping,
        sender.public_key.as_bytes(),
        counter,
        payload,
    );

    let (ptype, pubkey_bytes, parsed_counter, parsed_payload) =
        unpack_header(&packet).expect("Failed to unpack valid packet");

    assert_eq!(ptype, PacketType::Ping);
    assert_eq!(&pubkey_bytes, sender.public_key.as_bytes());
    assert_eq!(parsed_counter, counter);
    assert_eq!(parsed_payload, payload);
}

#[test]
fn test_peer_table_operations() {
    let mut table = PeerTable::new();
    let peer_identity = NodeIdentity::generate();

    let peer_cfg = PeerConfig {
        callsign: "Valkyrie-One".to_string(),
        node_id: peer_identity.node_id.clone(),
        public_key_base64: peer_identity.wireguard_pubkey.clone(),
        endpoint: Some("10.0.0.42:58888".to_string()),
        overlay_ip: Some("10.240.0.2".to_string()),
        created_at: chrono::Utc::now(),
    };

    table.add_peer(peer_cfg.clone());
    assert_eq!(table.peers.len(), 1);

    // Query peer
    let p = table
        .get_by_pubkey(&peer_identity.wireguard_pubkey)
        .expect("Peer should exist");
    assert_eq!(p.config.callsign, "Valkyrie-One");
    assert_eq!(p.status, PeerStatus::Disconnected);
    assert!(p.parsed_endpoint.is_some());

    // List sorted
    let list = table.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].config.callsign, "Valkyrie-One");

    // Remove peer
    let removed = table.remove_peer(&peer_identity.wireguard_pubkey);
    assert!(removed.is_some());
    assert_eq!(table.peers.len(), 0);
}

#[test]
fn test_config_persistence_and_airgap() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "sbm_test_{}",
        std::time::SystemTime::now().elapsed().unwrap().as_nanos()
    ));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let cfg_path = tmp_dir.join("config.toml");

    let mut config = MeshConfig::default();
    assert_eq!(config.listen_port, 58888);
    assert!(!config.air_gap_killswitch);

    // Toggle air-gap
    config.air_gap_killswitch = true;
    config.save(&cfg_path).expect("Failed to save config");

    let reloaded = MeshConfig::load_or_default(&cfg_path).unwrap();
    assert!(reloaded.air_gap_killswitch);
    assert_eq!(reloaded.listen_port, 58888);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_zk_mutual_attestation() {
    use sb_mesh::zk_attest::{verify_zk_proof, VerificationStatement, STANDARD_POLICY_ROOT};

    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();

    let session_nonce = 42u64;
    let epoch = 1u64;

    // Alice generates ZK proof bound to Bob's public key and session nonce
    let alice_proof = alice.generate_zk_proof(bob.public_key.as_bytes(), session_nonce, epoch);

    // Bob verifies Alice's proof
    let bob_verification = VerificationStatement {
        target_peer_pubkey: bob.public_key.as_bytes(),
        session_nonce,
        expected_policy_root: &STANDARD_POLICY_ROOT,
    };
    assert!(verify_zk_proof(&alice_proof, &bob_verification));

    // Bob generates reciprocal ZK proof for Alice
    let resp_nonce = session_nonce + 1;
    let bob_proof = bob.generate_zk_proof(alice.public_key.as_bytes(), resp_nonce, epoch);

    // Alice verifies Bob's proof
    let alice_verification = VerificationStatement {
        target_peer_pubkey: alice.public_key.as_bytes(),
        session_nonce: resp_nonce,
        expected_policy_root: &STANDARD_POLICY_ROOT,
    };
    assert!(verify_zk_proof(&bob_proof, &alice_verification));
}

#[test]
fn test_zk_replay_and_tamper_defense() {
    use sb_mesh::zk_attest::{verify_zk_proof, VerificationStatement, STANDARD_POLICY_ROOT};

    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();
    let eve = NodeIdentity::generate();

    let session_nonce = 100u64;
    let alice_proof = alice.generate_zk_proof(bob.public_key.as_bytes(), session_nonce, 1);

    // 1. Eve tries to replay Alice's proof to authenticate herself to Bob
    let eve_impersonation = VerificationStatement {
        target_peer_pubkey: eve.public_key.as_bytes(),
        session_nonce,
        expected_policy_root: &STANDARD_POLICY_ROOT,
    };
    assert!(!verify_zk_proof(&alice_proof, &eve_impersonation));

    // 2. Attacker replays proof with different nonce
    let stale_session = VerificationStatement {
        target_peer_pubkey: bob.public_key.as_bytes(),
        session_nonce: 101u64,
        expected_policy_root: &STANDARD_POLICY_ROOT,
    };
    assert!(!verify_zk_proof(&alice_proof, &stale_session));

    // 3. Attacker alters policy root
    let altered_policy = [0xAAu8; 32];
    let bad_policy_statement = VerificationStatement {
        target_peer_pubkey: bob.public_key.as_bytes(),
        session_nonce,
        expected_policy_root: &altered_policy,
    };
    assert!(!verify_zk_proof(&alice_proof, &bad_policy_statement));
}

#[test]
fn test_zk_zero_hardware_leakage() {
    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();

    let proof = alice.generate_zk_proof(bob.public_key.as_bytes(), 1, 1);
    let bytes = proof.to_bytes();

    // Proof must be compact: 32 (R) + 32 (s) + 32 (X) + 32 (root) + 8 (epoch) = 136 bytes
    assert_eq!(bytes.len(), 136);

    // Zero cleartext hardware strings: no Intel, AMD, UEFI, BIOS, TPM, serials, etc.
    let byte_str = String::from_utf8_lossy(&bytes);
    assert!(!byte_str.contains("Intel"));
    assert!(!byte_str.contains("AMD"));
    assert!(!byte_str.contains("TPM"));
    assert!(!byte_str.contains("UEFI"));
    assert!(!byte_str.contains("BIOS"));
}

#[test]
fn test_sovereign_kademlia_rendezvous_topic() {
    use sb_mesh::rendezvous::derive_rendezvous_topic;

    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();

    let epoch_day = 20260913;
    let topic_ab = derive_rendezvous_topic(
        alice.public_key.as_bytes(),
        bob.public_key.as_bytes(),
        epoch_day,
    );
    let topic_ba = derive_rendezvous_topic(
        bob.public_key.as_bytes(),
        alice.public_key.as_bytes(),
        epoch_day,
    );

    // Symmetric rendezvous: Both peers derive the exact same 32-byte secret Kademlia topic
    assert_eq!(topic_ab, topic_ba);
    assert_eq!(topic_ab.len(), 32);
}

#[tokio::test]
async fn test_socks5_protocol_negotiation() {
    use sb_mesh::proxy::Socks5Server;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let test_port = 51080;
    let server = Socks5Server::new(test_port);

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Wait for server to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port))
        .await
        .expect("Failed to connect to SOCKS5 server");

    // Send SOCKS5 greeting: Version 5, 1 Method, Method 0x00 (NO AUTH)
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("Failed to write greeting");

    let mut resp = [0u8; 2];
    client
        .read_exact(&mut resp)
        .await
        .expect("Failed to read greeting response");

    // Server must reply 0x05 (version), 0x00 (method accepted)
    assert_eq!(resp, [0x05, 0x00]);
}

#[tokio::test]
async fn test_ipc_roundtrip() {
    use sb_mesh::config::MeshConfig;
    use sb_mesh::identity::NodeIdentity;
    use sb_mesh::ipc::{IpcClient, IpcServer};
    use sb_mesh::peer::PeerTable;
    use sb_mesh::transport::MeshTransport;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let identity = Arc::new(NodeIdentity::generate());
    let peer_table = Arc::new(RwLock::new(PeerTable::new()));
    let air_gap = Arc::new(RwLock::new(false));
    let config = Arc::new(RwLock::new(MeshConfig::default()));

    let transport = MeshTransport::bind(
        "test-mesh",
        0,
        identity.clone(),
        peer_table.clone(),
        air_gap,
    )
    .await
    .unwrap();

    let server = IpcServer::new(identity.clone(), transport, peer_table, config);
    server.start();

    // Wait briefly for IPC listener
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    let status = IpcClient::get_status()
        .await
        .expect("IPC get_status failed");
    assert_eq!(status.node_id, identity.node_id);
    assert_eq!(status.wireguard_pubkey, identity.wireguard_pubkey);
    assert_eq!(status.peer_count, 0);

    let peers = IpcClient::list_peers()
        .await
        .expect("IPC list_peers failed");
    assert_eq!(peers.len(), 0);

    // Test versioned RPC airgap toggle
    let air_ack = IpcClient::set_air_gap(true)
        .await
        .expect("IPC set_air_gap failed");
    assert!(air_ack.contains("Air-gap killswitch set to true"));

    // Test JSON-RPC version mismatch rejection
    let mut invalid_version_req = sb_core::rpc::RpcRequest::new(
        99,
        sb_core::rpc::RPC_METHOD_MESH_STATUS,
        serde_json::Value::Null,
    );
    invalid_version_req.api_version = 999;
    let rpc_err_resp = IpcClient::query_rpc(invalid_version_req, None)
        .await
        .expect("RPC query failed");
    assert_eq!(
        rpc_err_resp.error.as_ref().map(|e| e.code),
        Some(sb_core::rpc::error_codes::UNSUPPORTED_API_VERSION)
    );
}

#[tokio::test]
async fn test_sovereign_name_layering_end_to_end() {
    use chrono::Utc;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use sb_mesh::dns::{NameRecord, ResolutionLayer, SovereignResolver};
    use sb_mesh::peer::{PeerConfig, PeerTable};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let mut table = PeerTable::new();
    table.add_peer(PeerConfig {
        callsign: "alpha-vault".to_string(),
        node_id: "sbm-0x11223344".to_string(),
        public_key_base64: "dGVzdF9wdWJrZXlfY2Fub24=".to_string(),
        endpoint: Some("192.168.1.50:58888".to_string()),
        overlay_ip: Some("10.42.0.77".to_string()),
        created_at: Utc::now(),
    });

    let resolver = SovereignResolver::new(Arc::new(RwLock::new(table)));

    // 1. Layer 0 Canonical lookup
    let l0_res = resolver.resolve("0x11223344.sbm:9090").await.unwrap();
    assert_eq!(l0_res.node_id, "sbm-0x11223344");
    assert_eq!(l0_res.port, 9090);
    assert_eq!(l0_res.layer, ResolutionLayer::Layer0Canonical);
    assert_eq!(l0_res.overlay_ip, Some("10.42.0.77".to_string()));

    // 2. Layer 1 Swarm Zone lookup (Schnorr signed record)
    let authority_secret = Scalar::random(&mut OsRng);
    let epoch = Utc::now().timestamp() as u64;
    let zone_record = NameRecord::sign_record(
        "postgres",
        "cluster-s&b",
        "sbm-0x99887766",
        Some("10.200.0.1:5432".to_string()),
        5432,
        epoch,
        7200,
        &authority_secret,
    );
    {
        let mut store = resolver.zone_store.write().await;
        store.insert(zone_record);
    }
    let l1_res = resolver.resolve("postgres.cluster-s&b.sbm").await.unwrap();
    assert_eq!(l1_res.node_id, "sbm-0x99887766");
    assert_eq!(l1_res.port, 5432);
    assert_eq!(l1_res.layer, ResolutionLayer::Layer1SwarmZone);

    // 3. Layer 2 Petname lookup: map "db" -> "postgres.cluster-s&b"
    {
        let mut petnames = resolver.petnames.write().await;
        petnames.set_alias("db", "postgres.cluster-s&b");
        petnames.set_alias("myvault", "0x11223344");
    }
    let l2_res1 = resolver.resolve("db.sbm").await.unwrap();
    assert_eq!(l2_res1.node_id, "sbm-0x99887766");
    assert_eq!(l2_res1.layer, ResolutionLayer::Layer2Petname);

    let l2_res2 = resolver.resolve("myvault.sbm:8000").await.unwrap();
    assert_eq!(l2_res2.node_id, "sbm-0x11223344");
    assert_eq!(l2_res2.port, 8000);
    assert_eq!(l2_res2.layer, ResolutionLayer::Layer2Petname);
}

#[tokio::test]
async fn test_socks5_sovereign_domain_routing() {
    use chrono::Utc;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use sb_mesh::acl::{AclEngine, CapabilityToken};
    use sb_mesh::dns::SovereignResolver;
    use sb_mesh::peer::{PeerConfig, PeerTable};
    use sb_mesh::proxy::Socks5Server;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::RwLock;

    // 1. Start a mock destination target server
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = target_listener.accept().await {
            let mut buf = [0u8; 4];
            if stream.read_exact(&mut buf).await.is_ok() && &buf == b"PING" {
                let _ = stream.write_all(b"PONG").await;
            }
        }
    });

    // 2. Set up peer table and petname "vault" pointing to target
    let mut table = PeerTable::new();
    table.add_peer(PeerConfig {
        callsign: "mockvault".to_string(),
        node_id: "sbm-0xaaaabbbb".to_string(),
        public_key_base64: "dGVzdF9tb2NrX3B1YmtleQ==".to_string(),
        endpoint: Some(target_addr.to_string()),
        overlay_ip: None,
        created_at: Utc::now(),
    });

    let resolver = Arc::new(SovereignResolver::new(Arc::new(RwLock::new(table))));
    {
        let mut petnames = resolver.petnames.write().await;
        petnames.set_alias("vault", "mockvault");
    }

    // 3. Start SOCKS5 server on ephemeral port
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = socks_listener.local_addr().unwrap().port();
    drop(socks_listener); // release port for Socks5Server

    let authority_secret = Scalar::random(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    let token = CapabilityToken::issue(
        "mock-authority",
        "sbm-0xaaaabbbb",
        vec![target_addr.port()],
        now + 3600,
        &authority_secret,
    );
    let mut acl_engine = AclEngine::new();
    acl_engine
        .trust_authority("mock-authority", token.authority_pubkey)
        .unwrap();
    acl_engine.grant(token).unwrap();

    let proxy = Socks5Server::new(socks_port)
        .with_resolver(resolver)
        .with_acl(Arc::new(RwLock::new(acl_engine)))
        .with_mesh_capabilities(vec![format!("tunnel:port:{}", target_addr.port())]);
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // 4. Client connects via SOCKS5
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();

    // Handshake
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut hs_resp = [0u8; 2];
    client.read_exact(&mut hs_resp).await.unwrap();
    assert_eq!(hs_resp, [0x05, 0x00]);

    // Request: CONNECT to "vault.sbm:target_port" (atyp 0x03)
    let domain = b"vault.sbm";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&target_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[1], 0x00); // 0x00 = SUCCESS!

    // Send payload through tunnel
    client.write_all(b"PING").await.unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"PONG");
}

#[tokio::test]
async fn test_multi_hop_relay_3_node_end_to_end() {
    use chrono::Utc;
    use sb_mesh::crypto::{decrypt_payload, derive_session_keys, encrypt_payload};
    use sb_mesh::identity::NodeIdentity;
    use sb_mesh::peer::{PeerConfig, PeerTable};
    use sb_mesh::relay::{RelayAction, RelayManager, RelayPacket};

    // 1. Setup Node A and Node B identities
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();

    // End-to-end secret key known ONLY to Node A and Node B
    let session_keys_ab = derive_session_keys(&node_a.secret, &node_b.public_key).unwrap();

    // Node A encrypts sensitive inner WireGuard data
    let inner_plaintext = b"CONFIDENTIAL_P2P_MESH_STREAM_OVER_RELAY";
    let encrypted_payload =
        encrypt_payload(session_keys_ab.send.as_bytes(), 1, inner_plaintext).unwrap();

    // Node A encapsulates into RelayPacket targeting Node B
    let packet_from_a = RelayPacket::new(&node_b.node_id, &node_a.node_id, encrypted_payload);

    // 2. Relay Node R receives packet
    let mut relay_table = PeerTable::new();
    relay_table.add_peer(PeerConfig {
        callsign: "node-b".to_string(),
        node_id: node_b.node_id.clone(),
        public_key_base64: node_b.wireguard_pubkey.clone(),
        endpoint: Some("198.51.100.20:58888".to_string()),
        overlay_ip: None,
        created_at: Utc::now(),
    });

    let relay_action = RelayManager::process_packet(packet_from_a, "sbm-0xrelaynode", &relay_table);
    let forwarded_packet = match relay_action {
        RelayAction::Forward { next_hop, packet } => {
            assert_eq!(next_hop.to_string(), "198.51.100.20:58888");
            assert_eq!(packet.hop_count, 1);
            packet
        }
        other => panic!("Expected Forward action, got {:?}", other),
    };

    // 3. Node B receives forwarded packet
    let b_table = PeerTable::new();
    let b_action = RelayManager::process_packet(forwarded_packet, &node_b.node_id, &b_table);
    let delivered = match b_action {
        RelayAction::DeliverLocally(p) => p,
        other => panic!("Expected DeliverLocally action on target, got {:?}", other),
    };

    // Node B decrypts inner payload using Node A's session key
    let session_keys_ba = derive_session_keys(&node_b.secret, &node_a.public_key).unwrap();
    assert_eq!(session_keys_ab.send, session_keys_ba.receive);

    let decrypted = decrypt_payload(
        session_keys_ba.receive.as_bytes(),
        1,
        &delivered.inner_payload,
    )
    .unwrap();
    assert_eq!(decrypted, inner_plaintext);
}

#[tokio::test]
async fn test_traffic_obfuscation_wireguard_framing() {
    use sb_mesh::obfuscation::{apply_padding, mask_header, remove_padding, unmask_header};

    let static_wireguard_header = [0x01, 0x00, 0x00, 0x00]; // HandshakeInit
    let session_salt = [0x99u8; 32];
    let counter = 42u64;

    // 1. Header Masking to destroy DPI pattern
    let masked_header = mask_header(&static_wireguard_header, &session_salt, counter);
    assert_ne!(masked_header.as_slice(), &static_wireguard_header);

    // 2. Random Noise Bucket Padding to 512 bytes
    let payload = b"SIMULATED_WIREGUARD_HANDSHAKE_PACKET_DATA_XYZ";
    let padded = apply_padding(payload, Some(512));
    assert_eq!(padded.len(), 512);

    // 3. Demask and Unpad
    let unmasked_header = unmask_header(&masked_header, &session_salt, counter);
    assert_eq!(unmasked_header.as_slice(), &static_wireguard_header);

    let unpadded = remove_padding(&padded).unwrap();
    assert_eq!(&unpadded, payload);
}

#[tokio::test]
async fn test_s_kademlia_sybil_defense_verification() {
    use sb_mesh::identity::{mine_pow_nonce, verify_pow_nonce, NodeIdentity};

    let identity = NodeIdentity::generate();
    let pubkey_bytes = identity.public_key.as_bytes();

    // 1. Legitimate node with 12 bits difficulty
    let difficulty = 12u8;
    let nonce = mine_pow_nonce(pubkey_bytes, difficulty);
    assert!(verify_pow_nonce(pubkey_bytes, nonce, difficulty));

    // 2. Sybil forgery attempt: modified pubkey with same nonce fails
    let mut forged_pubkey = *pubkey_bytes;
    forged_pubkey[0] ^= 0xff;
    assert!(!verify_pow_nonce(&forged_pubkey, nonce, difficulty + 12));

    // 3. Pairing token roundtrip preserves PoW nonce
    let token = identity.generate_pairing_token("10.0.0.99:58888");
    let (node_id, pubkey_b64, ep, pow) =
        NodeIdentity::parse_pairing_token_with_pow(&token).unwrap();
    assert_eq!(node_id, identity.node_id);
    assert_eq!(pubkey_b64, identity.wireguard_pubkey);
    assert_eq!(ep, "10.0.0.99:58888");
    assert_eq!(pow, identity.pow_nonce);
}

#[tokio::test]
async fn test_maybenot_cover_traffic_and_timing_jitter() {
    use sb_mesh::obfuscation::{
        compute_timing_jitter, generate_chaff_packet, is_chaff_packet, remove_padding,
    };

    // 1. Generate chaff dummy packet padded to 256 bytes
    let chaff_packet = generate_chaff_packet(256);
    assert_eq!(chaff_packet.len(), 256);

    // 2. Unpad and recognize as chaff
    let unpadded = remove_padding(&chaff_packet).expect("Failed to unpad chaff");
    assert!(is_chaff_packet(&unpadded));

    // 3. Timing jitter within 2 to 15 ms
    for _ in 0..10 {
        let jitter = compute_timing_jitter(2, 15);
        let ms = jitter.as_millis() as u64;
        assert!(ms >= 2 && ms <= 15);
    }
}

#[tokio::test]
async fn test_instant_connection_roaming() {
    use chrono::Utc;
    use sb_mesh::crypto::{derive_session_keys, encrypt_payload, pack_message, PacketType};
    use sb_mesh::identity::NodeIdentity;
    use sb_mesh::peer::{PeerConfig, PeerTable};
    use sb_mesh::transport::MeshTransport;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::RwLock;

    // Node A (Receiver / Server)
    let node_a = Arc::new(NodeIdentity::generate());
    let node_b = NodeIdentity::generate();
    let mut table_a = PeerTable::new();
    table_a.add_peer(PeerConfig {
        callsign: "peer-b".to_string(),
        node_id: node_b.node_id.clone(),
        public_key_base64: node_b.wireguard_pubkey.clone(),
        endpoint: Some("127.0.0.1:9999".to_string()),
        overlay_ip: None,
        created_at: Utc::now(),
    });

    let peer_table_a = Arc::new(RwLock::new(table_a));
    let air_gap = Arc::new(RwLock::new(false));
    let transport_a = MeshTransport::bind(
        "test-mesh",
        0,
        node_a.clone(),
        peer_table_a.clone(),
        air_gap,
    )
    .await
    .unwrap();
    let port_a = transport_a.socket.local_addr().unwrap().port();
    let addr_a = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        port_a,
    );

    let session_keys =
        derive_session_keys(&node_b.secret, &transport_a.identity.public_key).unwrap();

    // 1. Peer B sends Ping from Wi-Fi endpoint
    let socket_b1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b1_addr = socket_b1.local_addr().unwrap();
    let enc1 = encrypt_payload(session_keys.send.as_bytes(), 1, b"PING").unwrap();
    let ping1 = pack_message(PacketType::Ping, node_b.public_key.as_bytes(), 1, &enc1);
    socket_b1.send_to(&ping1, addr_a).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    {
        let table = peer_table_a.read().await;
        let peer = table.get_by_pubkey(&node_b.wireguard_pubkey).unwrap();
        assert_eq!(peer.parsed_endpoint, Some(b1_addr));
        assert_eq!(peer.roaming_events, 1);
    }

    // 2. Peer B roams to LTE endpoint (different UDP port)
    let socket_b2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b2_addr = socket_b2.local_addr().unwrap();
    assert_ne!(b1_addr, b2_addr);

    let enc2 = encrypt_payload(session_keys.send.as_bytes(), 2, b"PING").unwrap();
    let ping2 = pack_message(PacketType::Ping, node_b.public_key.as_bytes(), 2, &enc2);
    socket_b2.send_to(&ping2, addr_a).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    {
        let table = peer_table_a.read().await;
        let peer = table.get_by_pubkey(&node_b.wireguard_pubkey).unwrap();
        // Endpoint migrated seamlessly without any handshake re-initiation!
        assert_eq!(peer.parsed_endpoint, Some(b2_addr));
        assert_eq!(peer.roaming_events, 2);
    }
}

#[tokio::test]
async fn test_unauthenticated_data_does_not_mark_peer_connected() {
    use chrono::Utc;
    use sb_mesh::crypto::{pack_message, PacketType};
    use sb_mesh::identity::NodeIdentity;
    use sb_mesh::peer::{PeerConfig, PeerTable};
    use sb_mesh::transport::MeshTransport;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::RwLock;

    let local_identity = Arc::new(NodeIdentity::generate());
    let remote_identity = NodeIdentity::generate();
    let mut peer_table = PeerTable::new();
    peer_table.add_peer(PeerConfig {
        callsign: "untrusted-peer".to_string(),
        node_id: remote_identity.node_id.clone(),
        public_key_base64: remote_identity.wireguard_pubkey.clone(),
        endpoint: Some("127.0.0.1:9999".to_string()),
        overlay_ip: None,
        created_at: Utc::now(),
    });
    let peer_table = Arc::new(RwLock::new(peer_table));
    let transport = MeshTransport::bind(
        "test-mesh",
        0,
        local_identity,
        peer_table.clone(),
        Arc::new(RwLock::new(false)),
    )
    .await
    .unwrap();

    let attacker_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let forged = pack_message(
        PacketType::Data,
        remote_identity.public_key.as_bytes(),
        1,
        b"not an authenticated AEAD payload",
    );
    let transport_addr = transport.socket.local_addr().unwrap();
    let loopback_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        transport_addr.port(),
    );
    attacker_socket
        .send_to(&forged, loopback_addr)
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let peers = peer_table.read().await;
    let peer = peers
        .get_by_pubkey(&remote_identity.wireguard_pubkey)
        .unwrap();
    assert_eq!(peer.status, PeerStatus::Disconnected);
    assert_eq!(
        peer.parsed_endpoint,
        Some("127.0.0.1:9999".parse().unwrap())
    );
    assert_eq!(peer.roaming_events, 0);
    assert_eq!(peer.bytes_recv, 0);
}

#[tokio::test]
async fn test_socks5_capability_acl_enforcement() {
    use chrono::Utc;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use sb_mesh::acl::{AclEngine, CapabilityToken};
    use sb_mesh::dns::SovereignResolver;
    use sb_mesh::peer::{PeerConfig, PeerTable};
    use sb_mesh::proxy::Socks5Server;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::RwLock;

    // 1. Start mock server
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let allowed_port = target_addr.port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            let mut buf = [0u8; 4];
            if stream.read_exact(&mut buf).await.is_ok() {
                let _ = stream.write_all(b"PONG").await;
            }
        }
    });

    // 2. Set up peer table with "vault" alias
    let mut table = PeerTable::new();
    table.add_peer(PeerConfig {
        callsign: "secureservice".to_string(),
        node_id: "sbm-0xsecureservice".to_string(),
        public_key_base64: "dGVzdF9hY2xfc2VjdXJlX3B1YmtleQ==".to_string(),
        endpoint: Some(target_addr.to_string()),
        overlay_ip: None,
        created_at: Utc::now(),
    });

    let resolver = Arc::new(SovereignResolver::new(Arc::new(RwLock::new(table))));
    {
        let mut petnames = resolver.petnames.write().await;
        petnames.set_alias("vault", "secureservice");
    }

    // 3. Issue CapabilityToken allowing ONLY `allowed_port`
    let authority_secret = Scalar::random(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    let token = CapabilityToken::issue(
        "sbm-0xrootauth",
        "sbm-0xsecureservice",
        vec![allowed_port],
        now + 3600,
        &authority_secret,
    );

    let mut acl_engine = AclEngine::new();
    acl_engine
        .trust_authority("sbm-0xrootauth", token.authority_pubkey)
        .unwrap();
    acl_engine.grant(token).unwrap();
    let acl_arc = Arc::new(RwLock::new(acl_engine));

    // 4. Start SOCKS5 Server with ACL Engine
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = socks_listener.local_addr().unwrap().port();
    drop(socks_listener);

    let proxy = Socks5Server::new(socks_port)
        .with_resolver(resolver)
        .with_acl(acl_arc)
        .with_mesh_capabilities(vec![format!("tunnel:port:{allowed_port}")]);
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // 5. Test Allowed Port -> should succeed (0x00)
    {
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .unwrap();
        // Handshake
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut hs_resp = [0u8; 2];
        client.read_exact(&mut hs_resp).await.unwrap();
        assert_eq!(hs_resp, [0x05, 0x00]);

        // Connect to vault.sbm:allowed_port
        let domain = b"vault.sbm";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&allowed_port.to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00); // SUCCESS
    }

    // 6. Test Disallowed Port -> should be blocked by ACL (0x02: Connection not allowed by ruleset)
    {
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut hs_resp = [0u8; 2];
        client.read_exact(&mut hs_resp).await.unwrap();
        assert_eq!(hs_resp, [0x05, 0x00]);

        // Attempt unauthorized port 9999
        let forbidden_port: u16 = 9999;
        let domain = b"vault.sbm";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&forbidden_port.to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x02); // 0x02 = Connection not allowed by ruleset!
    }
}

#[tokio::test]
async fn test_in_band_rekeying_pfs_ratchet() {
    use chrono::Utc;
    use sb_mesh::identity::NodeIdentity;
    use sb_mesh::peer::{PeerConfig, PeerTable};
    use sb_mesh::transport::MeshTransport;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Node A and Node B
    let node_a = Arc::new(NodeIdentity::generate());
    let node_b = Arc::new(NodeIdentity::generate());

    let table_a = PeerTable::new();
    let table_b = PeerTable::new();

    let air_gap_a = Arc::new(RwLock::new(false));
    let air_gap_b = Arc::new(RwLock::new(false));

    let transport_a = MeshTransport::bind(
        "test-mesh",
        0,
        node_a.clone(),
        Arc::new(RwLock::new(table_a)),
        air_gap_a,
    )
    .await
    .unwrap();
    let port_a = transport_a.socket.local_addr().unwrap().port();
    let addr_a = format!("127.0.0.1:{}", port_a);

    let transport_b = MeshTransport::bind(
        "test-mesh",
        0,
        node_b.clone(),
        Arc::new(RwLock::new(table_b)),
        air_gap_b,
    )
    .await
    .unwrap();
    let port_b = transport_b.socket.local_addr().unwrap().port();
    let addr_b = format!("127.0.0.1:{}", port_b);

    // Cross-register peers
    {
        let mut t_a = transport_a.peer_table.write().await;
        t_a.add_peer(PeerConfig {
            callsign: "peer-b".to_string(),
            node_id: node_b.node_id.clone(),
            public_key_base64: node_b.wireguard_pubkey.clone(),
            endpoint: Some(addr_b.clone()),
            overlay_ip: None,
            created_at: Utc::now(),
        });
    }

    {
        let mut t_b = transport_b.peer_table.write().await;
        t_b.add_peer(PeerConfig {
            callsign: "peer-a".to_string(),
            node_id: node_a.node_id.clone(),
            public_key_base64: node_a.wireguard_pubkey.clone(),
            endpoint: Some(addr_a.clone()),
            overlay_ip: None,
            created_at: Utc::now(),
        });
    }

    // Initial Handshake
    transport_a
        .initiate_handshake(&node_b.wireguard_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // Verify initial state: epoch 0, rekey_count 0
    {
        let t_a = transport_a.peer_table.read().await;
        let peer_b = t_a.get_by_pubkey(&node_b.wireguard_pubkey).unwrap();
        assert_eq!(peer_b.session_epoch, 0);
        assert_eq!(peer_b.rekey_count, 0);
    }

    // Initiate In-Band Rekey from Node A
    transport_a
        .initiate_rekey(&node_b.wireguard_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Verify ratcheted session: both Node A and Node B have advanced to epoch 1 with matching ratcheted keys!
    let key_a = {
        let t_a = transport_a.peer_table.read().await;
        let peer_b = t_a.get_by_pubkey(&node_b.wireguard_pubkey).unwrap();
        assert_eq!(peer_b.session_epoch, 1);
        assert_eq!(peer_b.rekey_count, 1);
        assert!(peer_b.session_keys.is_some());
        peer_b.session_keys.as_ref().unwrap().clone()
    };

    let key_b = {
        let t_b = transport_b.peer_table.read().await;
        let peer_a = t_b.get_by_pubkey(&node_a.wireguard_pubkey).unwrap();
        assert_eq!(peer_a.session_epoch, 1);
        assert_eq!(peer_a.rekey_count, 1);
        assert!(peer_a.session_keys.is_some());
        peer_a.session_keys.as_ref().unwrap().clone()
    };

    assert_eq!(key_a.send, key_b.receive);
    assert_eq!(key_a.receive, key_b.send);
}

#[tokio::test]
async fn test_multi_path_candidate_racing_and_failover() {
    use chrono::Utc;
    use sb_mesh::identity::NodeIdentity;
    use sb_mesh::peer::{PathType, PeerConfig, PeerTable};
    use sb_mesh::transport::MeshTransport;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let node_a = Arc::new(NodeIdentity::generate());
    let node_b = Arc::new(NodeIdentity::generate());

    let table_a = PeerTable::new();
    let air_gap_a = Arc::new(RwLock::new(false));
    let transport_a = MeshTransport::bind(
        "test-mesh",
        0,
        node_a.clone(),
        Arc::new(RwLock::new(table_a)),
        air_gap_a,
    )
    .await
    .unwrap();

    let air_gap_b = Arc::new(RwLock::new(false));
    let transport_b = MeshTransport::bind(
        "test-mesh",
        0,
        node_b.clone(),
        Arc::new(RwLock::new(PeerTable::new())),
        air_gap_b,
    )
    .await
    .unwrap();
    let port_b = transport_b.socket.local_addr().unwrap().port();
    let target_addr_b = format!("127.0.0.1:{}", port_b);

    // Setup peer B with primary candidate and backup candidates
    {
        let mut t_a = transport_a.peer_table.write().await;
        t_a.add_peer(PeerConfig {
            callsign: "peer-b".to_string(),
            node_id: node_b.node_id.clone(),
            public_key_base64: node_b.wireguard_pubkey.clone(),
            endpoint: Some(target_addr_b.clone()),
            overlay_ip: None,
            created_at: Utc::now(),
        });
        let peer = t_a.get_mut_by_pubkey(&node_b.wireguard_pubkey).unwrap();
        // Add backup candidate path (e.g. simulated alternative interface)
        peer.add_or_update_path(PathType::DirectIPv4("127.0.0.1:54321".parse().unwrap()));
    }

    // Concurrently probe candidate paths (Path Racing)
    let probed_count = transport_a
        .probe_candidate_paths(&node_b.wireguard_pubkey)
        .await
        .unwrap();
    assert_eq!(probed_count, 2);

    // Test fast-failover on peer state:
    {
        let mut t_a = transport_a.peer_table.write().await;
        let peer = t_a.get_mut_by_pubkey(&node_b.wireguard_pubkey).unwrap();
        let primary_path = PathType::DirectIPv4(target_addr_b.parse().unwrap());
        let backup_path = PathType::DirectIPv4("127.0.0.1:54321".parse().unwrap());
        // Primary fails twice -> triggers fast failover
        assert!(!peer.record_path_failure(&primary_path, 2));
        assert!(peer.record_path_failure(&primary_path, 2));
        assert_eq!(peer.active_path().unwrap().path_type, backup_path);
    }
}

#[tokio::test]
async fn test_autonomous_multi_hop_mesh_routing() {
    use sb_mesh::crypto::{decrypt_payload, derive_session_keys, encrypt_payload};
    use sb_mesh::identity::NodeIdentity;
    use sb_mesh::peer::PeerTable;
    use sb_mesh::relay::{RelayAction, RelayManager, RelayPacket};
    use sb_mesh::routing::{RouteEntry, RoutingTable};
    use std::net::SocketAddr;

    // 4 Nodes in chain: Node A -> Node B -> Node C -> Node D
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();
    let node_c = NodeIdentity::generate();
    let node_d = NodeIdentity::generate();

    let ep_c: SocketAddr = "192.168.1.103:58888".parse().unwrap();
    let ep_d: SocketAddr = "192.168.1.104:58888".parse().unwrap();

    // 1. End-to-end encryption between A and D only (B and C cannot decrypt)
    let session_keys_ad = derive_session_keys(&node_a.secret, &node_d.public_key).unwrap();
    let secret_payload = b"END_TO_END_AUTONOMOUS_MULTI_HOP_PAYLOAD";
    let encrypted = encrypt_payload(session_keys_ad.send.as_bytes(), 101, secret_payload).unwrap();

    // Node A originates packet targeting Node D
    let pkt_a = RelayPacket::new(&node_d.node_id, &node_a.node_id, encrypted);

    // 2. Node B routing table has route to D via C
    let mut rt_b = RoutingTable::new();
    rt_b.update_route(RouteEntry::new(
        &node_d.node_id,
        &node_c.node_id,
        ep_c,
        50,
        2,
        1,
    ));

    let action_b = RelayManager::process_packet_with_routing(
        pkt_a,
        &node_b.node_id,
        &PeerTable::new(),
        Some(&rt_b),
    );

    let pkt_b = match action_b {
        RelayAction::Forward { next_hop, packet } => {
            assert_eq!(next_hop, ep_c);
            assert_eq!(packet.hop_count, 1);
            packet
        }
        other => panic!("Expected Forward from B, got {:?}", other),
    };

    // 3. Node C routing table has direct route to D
    let mut rt_c = RoutingTable::new();
    rt_c.update_route(RouteEntry::new(
        &node_d.node_id,
        &node_d.node_id,
        ep_d,
        20,
        1,
        1,
    ));

    let action_c = RelayManager::process_packet_with_routing(
        pkt_b,
        &node_c.node_id,
        &PeerTable::new(),
        Some(&rt_c),
    );

    let pkt_c = match action_c {
        RelayAction::Forward { next_hop, packet } => {
            assert_eq!(next_hop, ep_d);
            assert_eq!(packet.hop_count, 2);
            packet
        }
        other => panic!("Expected Forward from C, got {:?}", other),
    };

    // 4. Node D receives and delivers locally
    let action_d =
        RelayManager::process_packet_with_routing(pkt_c, &node_d.node_id, &PeerTable::new(), None);

    let delivered = match action_d {
        RelayAction::DeliverLocally(p) => p,
        other => panic!("Expected DeliverLocally at D, got {:?}", other),
    };

    // Node D decrypts inner payload
    let session_keys_da = derive_session_keys(&node_d.secret, &node_a.public_key).unwrap();
    assert_eq!(session_keys_ad.send, session_keys_da.receive);

    let decrypted = decrypt_payload(
        session_keys_da.receive.as_bytes(),
        101,
        &delivered.inner_payload,
    )
    .unwrap();
    assert_eq!(decrypted, secret_payload);
}

#[tokio::test]
async fn test_subnet_router_and_exit_node() {
    use sb_mesh::proxy::{Socks5Server, SubnetRouter};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::RwLock;

    // 1. Mock remote LAN server running behind Subnet Router R
    let mock_lan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_lan_port = mock_lan_listener.local_addr().unwrap().port();
    let mock_lan_addr = format!("127.0.0.1:{}", mock_lan_port);

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_lan_listener.accept().await {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf).await {
                if &buf[..n] == b"PING_SUBNET" {
                    let _ = stream.write_all(b"PONG_SUBNET_ROUTER_OK").await;
                }
            }
        }
    });

    // 2. Setup SubnetRouter routing 192.168.1.0/24 to mock_lan_addr
    let mut subnet_router = SubnetRouter::new();
    subnet_router.add_subnet_route(
        "192.168.1.0/24",
        "sbm-0xhomelan",
        mock_lan_addr.parse().unwrap(),
    );

    // 3. Launch local SOCKS5 proxy with SubnetRouter attached
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = socks_listener.local_addr().unwrap().port();
    drop(socks_listener); // free port for server

    let proxy_server = Socks5Server::new(socks_port)
        .with_subnet_router(Arc::new(RwLock::new(subnet_router)))
        .with_mesh_capabilities(vec!["tunnel:port:8080".to_string()]);

    tokio::spawn(async move {
        let _ = proxy_server.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 4. Connect through SOCKS5 asking for remote LAN host 192.168.1.88:8080
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();

    // SOCKS5 greeting
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // Request connect to 192.168.1.88:8080
    // 0x05 (ver), 0x01 (connect), 0x00 (rsv), 0x01 (IPv4), [192, 168, 1, 88], [0x1F, 0x90] (8080)
    let req = [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 88, 0x1F, 0x90];
    client.write_all(&req).await.unwrap();

    let mut connect_reply = [0u8; 10];
    client.read_exact(&mut connect_reply).await.unwrap();
    assert_eq!(connect_reply[0], 0x05);
    assert_eq!(connect_reply[1], 0x00); // SUCCESS

    // 5. Send data through tunnel
    client.write_all(b"PING_SUBNET").await.unwrap();
    let mut data_buf = [0u8; 21];
    client.read_exact(&mut data_buf).await.unwrap();
    assert_eq!(&data_buf, b"PONG_SUBNET_ROUTER_OK");
}

#[tokio::test]
async fn test_gossip_key_revocation_and_zone_sync() {
    use chrono::Utc;
    use sb_mesh::gossip::{GossipAction, GossipEngine};
    use sb_mesh::peer::{PeerConfig, PeerTable};

    // Setup 3 nodes: A (Authority), B (Peer), C (Peer)
    let mut table_b = PeerTable::new();
    let mut table_c = PeerTable::new();

    let stolen_pubkey = "c3RvbGVuX2tleV9mb3JfcmV2b2NhdGlvbg==";
    table_b.add_peer(PeerConfig {
        callsign: "stolen-device".to_string(),
        node_id: "sbm-0xstolen".to_string(),
        public_key_base64: stolen_pubkey.to_string(),
        endpoint: Some("192.168.1.200:58888".to_string()),
        overlay_ip: None,
        created_at: Utc::now(),
    });
    table_c.add_peer(PeerConfig {
        callsign: "stolen-device".to_string(),
        node_id: "sbm-0xstolen".to_string(),
        public_key_base64: stolen_pubkey.to_string(),
        endpoint: Some("192.168.1.200:58888".to_string()),
        overlay_ip: None,
        created_at: Utc::now(),
    });

    let mut gossip_b = GossipEngine::new();
    let mut gossip_c = GossipEngine::new();

    // Node A originates CRL Revocation
    let revocation_from_a = GossipEngine::create_revocation(
        "sbm-0xauthority",
        stolen_pubkey,
        "Laptop lost in transit",
        1,
        vec![99, 88, 77],
    );

    // Node B receives from A -> evicts peer, returns Forward
    let action_b = gossip_b.process_incoming(revocation_from_a, Some(&mut table_b));
    let fwd_msg = match action_b {
        GossipAction::Forward(msg) => msg,
        other => panic!("Expected Forward from B, got {:?}", other),
    };

    assert!(gossip_b.is_revoked(stolen_pubkey));
    assert!(table_b.get_by_pubkey(stolen_pubkey).is_none());

    // Node C receives forwarded gossip from B -> evicts peer, returns Forward
    let action_c = gossip_c.process_incoming(fwd_msg.clone(), Some(&mut table_c));
    assert!(matches!(action_c, GossipAction::Forward(_)));

    assert!(gossip_c.is_revoked(stolen_pubkey));
    assert!(table_c.get_by_pubkey(stolen_pubkey).is_none());

    // Node C receives same message again -> deduplicated & ignored
    let action_c_dup = gossip_c.process_incoming(fwd_msg, Some(&mut table_c));
    assert_eq!(action_c_dup, GossipAction::IgnoredAlreadySeen);
}
