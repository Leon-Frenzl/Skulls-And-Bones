use sb_db::{Database, DbClient, DbServer, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct UserProfile {
    name: String,
    age: u32,
    role: String,
}

#[tokio::test]
async fn test_client_server_full_roundtrip() {
    let tmp_dir = std::env::temp_dir().join(format!("sb_test_srv_{}", rand::random::<u64>()));
    let db_path = tmp_dir.join("test.sbdb");
    let db = Database::open(&db_path).unwrap();

    // Bind on random available port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // Free for DbServer to bind

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let server = DbServer::new(Arc::new(db));

    // Spawn server in background task
    tokio::spawn(async move {
        let _ = server.run(addr).await;
    });

    // Wait for server to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client
    let mut client = DbClient::connect(addr)
        .await
        .expect("Failed to connect client");

    // 1. Ping
    client.ping().await.expect("Ping failed");

    // 2. Set & Get
    client
        .set(
            "users:1",
            json!({"name": "Leon", "age": 28, "role": "admin"}),
        )
        .await
        .expect("Set failed");

    let val = client
        .get("users:1")
        .await
        .expect("Get failed")
        .expect("Expected value");
    assert_eq!(val["name"], "Leon");
    assert_eq!(val["age"], 28);

    // 3. Typed Deserialization
    let profile: UserProfile = client
        .get_typed("users:1")
        .await
        .expect("Get typed failed")
        .expect("Expected typed value");
    assert_eq!(
        profile,
        UserProfile {
            name: "Leon".to_string(),
            age: 28,
            role: "admin".to_string(),
        }
    );

    // 4. Dot-Notation GetPath & SetPath
    let name_val = client.get_path("users:1", "name").await.unwrap().unwrap();
    assert_eq!(name_val, "Leon");

    client
        .set_path("users:1", "profile.city", json!("Berlin"))
        .await
        .unwrap();
    let city_val = client
        .get_path("users:1", "profile.city")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(city_val, "Berlin");

    // 5. Scan
    client
        .set("users:2", json!({"name": "Alice"}))
        .await
        .unwrap();
    client
        .set("orders:100", json!({"total": 50}))
        .await
        .unwrap();

    let user_scan = client.scan("users:").await.unwrap();
    assert_eq!(user_scan.len(), 2);

    // 6. Secondary Indexing & Find
    client.create_index("users:", "role").await.unwrap();
    let admin_matches = client.find("users:", "role", json!("admin")).await.unwrap();
    assert_eq!(admin_matches.len(), 1);
    assert_eq!(admin_matches[0].0, "users:1");

    // 7. Atomic Transaction
    let mut tx = Transaction::new(0);
    tx.set("accounts:alice", json!({"balance": 900}));
    tx.set("accounts:bob", json!({"balance": 1100}));
    client.transaction(tx).await.unwrap();

    let alice_acc = client.get("accounts:alice").await.unwrap().unwrap();
    assert_eq!(alice_acc["balance"], 900);

    // 8. Stats & Compaction
    let stats = client.stats().await.unwrap();
    assert!(stats.key_count >= 5);
    assert_eq!(stats.index_count, 1);

    let reclaimed = client.compact().await.unwrap();
    let _ = reclaimed;

    // 9. Delete
    let deleted = client.delete("orders:100").await.unwrap();
    assert!(deleted);
    let deleted_again = client.delete("orders:100").await.unwrap();
    assert!(!deleted_again);

    // Cleanup
    let _ = std::fs::remove_dir_all(tmp_dir);
}

#[tokio::test]
async fn test_client_watch_cdc_stream() {
    let tmp_dir = std::env::temp_dir().join(format!("sb_test_watch_{}", rand::random::<u64>()));
    let db_path = tmp_dir.join("test_watch.sbdb");
    let db = Database::open(&db_path).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let server = DbServer::new(Arc::new(db));

    tokio::spawn(async move {
        let _ = server.run(addr).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect writer client and watcher client
    let mut writer = DbClient::connect(addr).await.unwrap();
    let watcher = DbClient::connect(addr).await.unwrap();

    // Start watching pattern "events:*"
    let mut stream = watcher.watch("events:*").await.unwrap();

    // Spawn a task to trigger writes after a short pause
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        writer
            .set("events:login", json!({"user": "Leon"}))
            .await
            .unwrap();
        writer.delete("events:login").await.unwrap();
        // This write shouldn't match
        writer.set("other:key", json!("ignore")).await.unwrap();
    });

    // 1st Event: SET events:login
    let ev1 = stream.next_event().await.unwrap();
    assert_eq!(ev1.key, "events:login");
    assert_eq!(ev1.kind, sb_db::EventKind::Set);
    assert_eq!(ev1.new_value.unwrap()["user"], "Leon");

    // 2nd Event: DEL events:login
    let ev2 = stream.next_event().await.unwrap();
    assert_eq!(ev2.key, "events:login");
    assert_eq!(ev2.kind, sb_db::EventKind::Delete);

    let _ = std::fs::remove_dir_all(tmp_dir);
}
