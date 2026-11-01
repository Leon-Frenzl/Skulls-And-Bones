use sb_db::Database;
use std::time::Duration;

#[tokio::test]
async fn test_ttl_and_automatic_expiration() {
    let dir = std::env::temp_dir().join(format!("sbdb_ttl_{}", rand::random::<u32>()));
    let db_path = dir.join("ttl.sbdb");

    let db = Database::open(&db_path).unwrap();

    // 1. Set key with 100ms TTL
    db.set_with_ttl(
        "session:ephemeral",
        &serde_json::json!({"user": "alice"}),
        Duration::from_millis(100),
    )
    .unwrap();
    assert!(db.get("session:ephemeral").is_some());

    // 2. Wait 150ms
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 3. Key should be expired
    assert!(db.get("session:ephemeral").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_compaction_reclaims_bytes() {
    let dir = std::env::temp_dir().join(format!("sbdb_compaction_{}", rand::random::<u32>()));
    let db_path = dir.join("compaction.sbdb");

    let db = Database::open(&db_path).unwrap();

    // Insert 100 keys, then overwrite them multiple times
    for i in 0..100 {
        db.set(
            &format!("key:{}", i),
            &serde_json::json!({"iteration": 1, "payload": "abcdefghijklmnopqrstuvwxyz"}),
        )
        .unwrap();
    }
    for i in 0..100 {
        db.set(
            &format!("key:{}", i),
            &serde_json::json!({"iteration": 2, "payload": "abcdefghijklmnopqrstuvwxyz"}),
        )
        .unwrap();
    }
    // Delete 50 of them
    for i in 0..50 {
        db.delete(&format!("key:{}", i)).unwrap();
    }

    let initial_size = db.stats().unwrap().file_size_bytes;

    let reclaimed = db.compact().unwrap();
    let new_size = db.stats().unwrap().file_size_bytes;

    assert!(reclaimed > 0);
    assert!(new_size < initial_size);
    assert_eq!(db.stats().unwrap().key_count, 50);

    // Verify remaining keys still intact
    for i in 50..100 {
        let doc = db.get(&format!("key:{}", i)).unwrap();
        assert_eq!(doc["iteration"], 2);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_crash_recovery_and_reopen() {
    let dir = std::env::temp_dir().join(format!("sbdb_recovery_{}", rand::random::<u32>()));
    let db_path = dir.join("recovery.sbdb");

    // Scope 1: Write data and drop DB handle
    {
        let db = Database::open(&db_path).unwrap();
        db.set("users:1", &serde_json::json!({"name": "Alice"}))
            .unwrap();
        db.set("users:2", &serde_json::json!({"name": "Bob"}))
            .unwrap();
        db.create_index("users:", "name").unwrap();
    }

    // Scope 2: Reopen from same file on disk
    {
        let db2 = Database::open(&db_path).unwrap();
        assert_eq!(db2.stats().unwrap().key_count, 2);

        let alice = db2.get("users:1").unwrap();
        assert_eq!(alice["name"], "Alice");

        let found = db2.find("users:", "name", &serde_json::json!("Bob"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "users:2");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_reactive_watch_events() {
    let dir = std::env::temp_dir().join(format!("sbdb_watch_{}", rand::random::<u32>()));
    let db_path = dir.join("watch.sbdb");

    let db = Database::open(&db_path).unwrap();
    let mut rx = db.watch();

    db.set("orders:100", &serde_json::json!({"status": "pending"}))
        .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(event.kind, sb_db::EventKind::Set);
    assert_eq!(event.key, "orders:100");
    assert_eq!(event.new_value.unwrap()["status"], "pending");

    let _ = std::fs::remove_dir_all(&dir);
}
