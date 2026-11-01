//! End-to-End Test: Sovereign DB über Cross-Mesh Bridge (App-Mesh ➔ Database-Mesh)

use sb_db::client::DbClient;
use sb_db::db::Database;
use sb_db::server::DbServer;
use sb_mesh::bridge::{CrossMeshBridge, CrossMeshPolicy, CrossMeshRule, ServiceEndpoint};
use sb_mesh::client::MeshClient;
use sb_mesh::identity::NodeIdentity;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_database_cross_mesh_end_to_end() {
    let temp_dir = std::env::temp_dir().join(format!("sb_test_cross_db_{}", rand::random::<u32>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db_path = temp_dir.join("test.sbdb");

    // 1. Sovereign Database Engine & Server auf Loopback starten
    let db = Arc::new(Database::open(&db_path).expect("Failed to open test database"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind random TCP");
    let server_addr = listener.local_addr().expect("Failed to get local addr");

    let server_db = db.clone();
    tokio::spawn(async move {
        let server = DbServer::new(server_db);
        let _ = server.run_with_listener(listener).await;
    });

    // 2. Converged Anchor Node mit CrossMeshBridge
    let anchor_bridge = Arc::new(CrossMeshBridge::new("sbm-anchor-prod"));

    // Registriere den lokalen DB-Server im 'database-mesh' unter Port 58830
    anchor_bridge
        .register_service(
            "database-mesh",
            58830,
            ServiceEndpoint::LocalTcp(server_addr),
        )
        .await;

    // Erlaube app-mesh Zugriff auf database-mesh:58830
    let mut policy = CrossMeshPolicy::new();
    policy.add_rule(CrossMeshRule::new(
        "allow-app-to-db",
        "app-mesh",
        "database-mesh",
        vec![58830],
        false, // Standard-Routing
        "App-Mesh Zugriff auf Sovereign Database",
    ));
    *anchor_bridge.policy.write().await = policy;

    // 3. Client im 'app-mesh'
    let app_identity = Arc::new(NodeIdentity::generate());
    let app_mesh_client = MeshClient::with_bridge("app-mesh", app_identity, anchor_bridge.clone());

    // 4. Öffne Virtual Cross-Mesh Stream zum 'database-mesh'
    let cross_stream = app_mesh_client
        .open_cross_mesh_stream("database-mesh", 58830, None)
        .await
        .expect("Konnte Cross-Mesh Stream nicht öffnen");

    // 5. Native DbClient auf den Virtual Stream setzen!
    let mut db_client = DbClient::from_stream(cross_stream);

    // 6. Testfall Ping-Pong über Cross-Mesh
    db_client
        .ping()
        .await
        .expect("Ping über Cross-Mesh fehlgeschlagen");

    // 7. Testfall Set & Get über Cross-Mesh
    let test_user = serde_json::json!({
        "name": "Sovereign Alice",
        "role": "fleet-admin",
        "level": 42
    });
    db_client
        .set("users:alice", test_user.clone())
        .await
        .expect("Set über Cross-Mesh fehlgeschlagen");

    let retrieved = db_client
        .get("users:alice")
        .await
        .expect("Get über Cross-Mesh fehlgeschlagen")
        .expect("Key users:alice nicht gefunden");

    assert_eq!(retrieved, test_user);

    // 8. Testfall Dot-Notation Path Query über Cross-Mesh
    let role: Option<String> = db_client
        .get_path_typed("users:alice", "role")
        .await
        .expect("Path Query über Cross-Mesh fehlgeschlagen");
    assert_eq!(role, Some("fleet-admin".to_string()));

    // 9. Testfall Secondary Index über Cross-Mesh
    db_client
        .create_index("users:", "role")
        .await
        .expect("Index creation failed");

    let matches = db_client
        .find("users:", "role", serde_json::json!("fleet-admin"))
        .await
        .expect("Find query failed");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, "users:alice");

    // 10. Audit & Telemetrie auf dem Anchor prüfen
    let stats = anchor_bridge.stats.read().await;
    assert_eq!(stats.streams_opened, 1);
    assert!(stats.bytes_forwarded > 0);

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}
