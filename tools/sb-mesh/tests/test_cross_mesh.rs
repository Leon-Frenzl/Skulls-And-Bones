//! End-to-End Tests für die Cross-Mesh Bridge und das Programmatische Mesh Client SDK

use chrono::Utc;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use sb_mesh::acl::CapabilityToken;
use sb_mesh::bridge::{
    CrossMeshBridge, CrossMeshError, CrossMeshPolicy, CrossMeshRule, ServiceEndpoint,
};
use sb_mesh::client::MeshClient;
use sb_mesh::identity::NodeIdentity;

#[tokio::test]
async fn test_cross_mesh_policy_enforcement_and_unauthorized_drop() {
    let authority_secret = Scalar::random(&mut OsRng);
    let now = Utc::now().timestamp() as u64;

    // 1. Konvergierter Anchor Node mit Bridge
    let bridge = Arc::new(CrossMeshBridge::new("sbm-anchor-node"));

    // 2. Mock Database-Service auf Loopback Port binden
    let db_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db_addr = db_listener.local_addr().unwrap();

    // Als Service in "database-mesh" unter Port 58830 registrieren
    bridge
        .register_service("database-mesh", 58830, ServiceEndpoint::LocalTcp(db_addr))
        .await;

    // 3. Strikte Policy einrichten: Nur app-mesh darf auf database-mesh:58830 mit gültigem Token zugreifen
    let rule = CrossMeshRule::new(
        "rule-app-db-access",
        "app-mesh",
        "database-mesh",
        vec![58830],
        true, // Token erforderlich
        "Streng kontrollierter Zugriff vom App-Mesh auf Sovereign Database",
    );
    let mut policy = CrossMeshPolicy::new();
    policy.add_rule(rule);
    *bridge.policy.write().await = policy;

    // 4. Programmatischer Client im "app-mesh"
    let app_identity = Arc::new(NodeIdentity::load_or_generate_default().unwrap());
    let app_client = MeshClient::with_bridge("app-mesh", app_identity.clone(), bridge.clone());

    // TESTFALL A: Verbindungsversuch ohne Capability Token -> MUSS geblockt werden!
    let res_no_token = app_client
        .open_cross_mesh_stream("database-mesh", 58830, None)
        .await;
    assert!(res_no_token.is_err());
    let err = res_no_token.err().unwrap();
    assert!(matches!(
        err,
        CrossMeshError::TokenMissing | CrossMeshError::PolicyViolation(_)
    ));

    // TESTFALL B: Verbindungsversuch auf unerlaubten Port (z. B. SSH 22) -> MUSS geblockt werden!
    let token_ssh = CapabilityToken::issue(
        "sbm-anchor-node",
        &app_identity.node_id,
        vec![22],
        now + 3600,
        &authority_secret,
    );
    let res_ssh = app_client
        .open_cross_mesh_stream("database-mesh", 22, Some(token_ssh))
        .await;
    assert!(res_ssh.is_err());
    let err_ssh = res_ssh.err().unwrap();
    assert!(matches!(
        err_ssh,
        CrossMeshError::UnauthorizedPort(22) | CrossMeshError::PolicyViolation(_)
    ));

    // TESTFALL C: Verbindungsversuch aus einem unberechtigten Mesh (z. B. "guest-mesh") -> MUSS geblockt werden!
    let guest_client = MeshClient::with_bridge("guest-mesh", app_identity.clone(), bridge.clone());
    let valid_token = CapabilityToken::issue(
        "sbm-anchor-node",
        &app_identity.node_id,
        vec![58830],
        now + 3600,
        &authority_secret,
    );
    let res_guest = guest_client
        .open_cross_mesh_stream("database-mesh", 58830, Some(valid_token.clone()))
        .await;
    assert!(res_guest.is_err());
    let err_guest = res_guest.err().unwrap();
    assert!(matches!(err_guest, CrossMeshError::PolicyViolation(_)));

    // TESTFALL D: Abgelaufenes Token -> MUSS geblockt werden!
    let expired_token = CapabilityToken::issue(
        "sbm-anchor-node",
        &app_identity.node_id,
        vec![58830],
        now - 60,
        &authority_secret,
    );
    let res_expired = app_client
        .open_cross_mesh_stream("database-mesh", 58830, Some(expired_token))
        .await;
    assert!(res_expired.is_err());
    let err_expired = res_expired.err().unwrap();
    assert!(matches!(
        err_expired,
        CrossMeshError::TokenInvalid(_)
            | CrossMeshError::TokenExpired
            | CrossMeshError::PolicyViolation(_)
    ));

    // Telemetrie prüfen: Policy-Verstöße wurden protokolliert
    let stats = bridge.stats.read().await;
    assert!(stats.policy_violations >= 3);
}

#[tokio::test]
async fn test_cross_mesh_authorized_bidirectional_stream() {
    let authority_secret = Scalar::random(&mut OsRng);
    let now = Utc::now().timestamp() as u64;

    // 1. Konvergierter Anchor Node mit Bridge
    let bridge = Arc::new(CrossMeshBridge::new("sbm-anchor-node"));

    // 2. Mock Database TCP-Service (Echo-Server) im "database-mesh"
    let db_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db_addr = db_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = db_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let incoming = String::from_utf8_lossy(&buf[..n]);
                    let reply = format!("DB_REPLY:{}", incoming);
                    if socket.write_all(reply.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    bridge
        .register_service("database-mesh", 58830, ServiceEndpoint::LocalTcp(db_addr))
        .await;

    // 3. Policy: app-mesh darf database-mesh auf Port 58830 mit Token ansprechen
    let rule = CrossMeshRule::new(
        "rule-app-db-access",
        "app-mesh",
        "database-mesh",
        vec![58830],
        true,
        "Erlaube App-Mesh Datenbank-Zugriff",
    );
    let mut policy = CrossMeshPolicy::new();
    policy.add_rule(rule);
    *bridge.policy.write().await = policy;

    // 4. Programmatischer App-Mesh Client
    let app_identity = Arc::new(NodeIdentity::load_or_generate_default().unwrap());
    let app_client = MeshClient::with_bridge("app-mesh", app_identity.clone(), bridge.clone());

    // 5. Gültiges Capability Token ausstellen
    let token = CapabilityToken::issue(
        "sbm-anchor-node",
        &app_identity.node_id,
        vec![58830],
        now + 3600,
        &authority_secret,
    );

    // 6. Virtuellen Stream über die Cross-Mesh Bridge öffnen
    let mut stream = app_client
        .open_cross_mesh_stream("database-mesh", 58830, Some(token))
        .await
        .expect("Cross-Mesh Stream konnte nicht geöffnet werden");

    assert_eq!(stream.target_mesh, "database-mesh");
    assert_eq!(stream.target_port, 58830);

    // 7. Daten über den Stream senden
    stream.send(b"SELECT * FROM users").await.unwrap();

    // 8. Antwort über AsyncRead empfangen
    let mut reply_buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.recv(&mut reply_buf))
        .await
        .expect("Timeout beim Warten auf DB-Antwort")
        .expect("Fehler beim Empfang");

    let reply_str = String::from_utf8_lossy(&reply_buf[..n]);
    assert_eq!(reply_str, "DB_REPLY:SELECT * FROM users");

    // Zweite Anfrage über denselben Virtual Stream
    stream.send(b"SET key=42").await.unwrap();
    let n2 = stream.recv(&mut reply_buf).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&reply_buf[..n2]),
        "DB_REPLY:SET key=42"
    );

    // Telemetrie prüfen
    let stats = bridge.stats.read().await;
    assert_eq!(stats.streams_opened, 1);
    assert!(stats.bytes_forwarded > 0);
}

#[tokio::test]
async fn size_declared_upload_completes_over_the_direct_bridge_path() {
    let bridge = Arc::new(CrossMeshBridge::new("sbm-anchor-node"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service_addr = listener.local_addr().unwrap();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let service = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 5];
        socket.read_exact(&mut request).await.unwrap();
        let _ = received_tx.send(request);
    });

    bridge
        .register_service(
            "database-mesh",
            58830,
            ServiceEndpoint::LocalTcp(service_addr),
        )
        .await;
    let mut policy = CrossMeshPolicy::new();
    policy.add_rule(CrossMeshRule::new(
        "app-db-transfer",
        "app-mesh",
        "database-mesh",
        vec![58830],
        false,
        "Size-declared transfer test",
    ));
    *bridge.policy.write().await = policy;

    let identity = Arc::new(NodeIdentity::generate());
    let client = MeshClient::with_bridge("app-mesh", identity, bridge);
    let mut stream = client
        .open_cross_mesh_transfer("database-mesh", 58830, None, 5)
        .await
        .unwrap();
    stream.send(b"hello").await.unwrap();

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), received_rx)
            .await
            .unwrap()
            .unwrap(),
        *b"hello"
    );
    tokio::time::timeout(Duration::from_secs(3), service)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_cross_mesh_datagram_rpc() {
    let bridge = Arc::new(CrossMeshBridge::new("sbm-anchor-node"));

    // Echo-Server
    let db_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db_addr = db_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = db_listener.accept().await {
            let mut buf = [0u8; 512];
            if let Ok(n) = socket.read(&mut buf).await {
                let _ = socket.write_all(&buf[..n]).await;
            }
        }
    });

    bridge
        .register_service("database-mesh", 58830, ServiceEndpoint::LocalTcp(db_addr))
        .await;

    // Policy ohne Token-Zwang für interne RPCs
    let rule = CrossMeshRule::new(
        "rule-internal-rpc",
        "app-mesh",
        "database-mesh",
        vec![58830],
        false,
        "Interne Datagramm RPCs",
    );
    let mut policy = CrossMeshPolicy::new();
    policy.add_rule(rule);
    *bridge.policy.write().await = policy;

    let app_identity = Arc::new(NodeIdentity::load_or_generate_default().unwrap());
    let app_client = MeshClient::with_bridge("app-mesh", app_identity, bridge);

    let reply = app_client
        .send_cross_mesh_datagram("database-mesh", 58830, b"PING_DATAGRAM".to_vec(), None)
        .await
        .expect("Datagram RPC fehlgeschlagen");

    assert_eq!(reply, b"PING_DATAGRAM");
}

#[tokio::test]
async fn test_cross_mesh_framing_protocol_crc32_end_to_end() {
    let bridge = Arc::new(CrossMeshBridge::new("sbm-anchor-node"));

    // Server-Seite: Empfängt CRC32-gerahmte Datensätze [4B len][4B crc][payload] und antwortet gerahmt
    let db_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db_addr = db_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = db_listener.accept().await {
            let len = socket.read_u32().await.unwrap();
            let crc = socket.read_u32().await.unwrap();
            let mut payload = vec![0u8; len as usize];
            socket.read_exact(&mut payload).await.unwrap();

            // Checksumme prüfen
            let mut hasher = sha2::Sha256::default();
            use sha2::Digest;
            hasher.update(&payload);
            let calc_crc = u32::from_be_bytes([hasher.finalize()[0], 0, 0, 0]);
            assert_eq!(crc, calc_crc);

            // Gerahmte Antwort senden
            let resp_payload = b"OK_STORED";
            socket.write_u32(resp_payload.len() as u32).await.unwrap();
            socket.write_u32(1337).await.unwrap();
            socket.write_all(resp_payload).await.unwrap();
        }
    });

    bridge
        .register_service("database-mesh", 58830, ServiceEndpoint::LocalTcp(db_addr))
        .await;

    let mut policy = CrossMeshPolicy::new();
    policy.add_rule(CrossMeshRule::new(
        "allow-app-to-db",
        "app-mesh",
        "database-mesh",
        vec![58830],
        false,
        "DB Framing Stream",
    ));
    *bridge.policy.write().await = policy;

    let app_identity = Arc::new(NodeIdentity::load_or_generate_default().unwrap());
    let app_client = MeshClient::with_bridge("app-mesh", app_identity, bridge);

    let mut stream = app_client
        .open_cross_mesh_stream("database-mesh", 58830, None)
        .await
        .unwrap();

    // Client sendet gerahmte Anfrage via Tokio AsyncWrite
    use sha2::Digest;
    let data = b"SET sovereign:asset = 1000";
    let mut hasher = sha2::Sha256::default();
    hasher.update(data);
    let checksum = u32::from_be_bytes([hasher.finalize()[0], 0, 0, 0]);

    stream.write_u32(data.len() as u32).await.unwrap();
    stream.write_u32(checksum).await.unwrap();
    stream.write_all(data).await.unwrap();

    // Client liest gerahmte Antwort via Tokio AsyncRead
    let resp_len = stream.read_u32().await.unwrap();
    let resp_crc = stream.read_u32().await.unwrap();
    let mut resp_buf = vec![0u8; resp_len as usize];
    stream.read_exact(&mut resp_buf).await.unwrap();

    assert_eq!(resp_len, 9);
    assert_eq!(resp_crc, 1337);
    assert_eq!(&resp_buf, b"OK_STORED");
}
