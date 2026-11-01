use sb_code::ast::{find_scope_by_name_or_line, parse_live_ast_scopes, AstLockTable};
use sb_code::baseline::BaselineCache;
use sb_code::stream::{apply_ast_diff, generate_ast_annotated_diff, AstDiffStreamPacket};
use std::fs;

#[test]
fn test_ast_scope_lock_and_unlock_flow() {
    let temp_dir = std::env::temp_dir().join(format!("sb_lock_flow_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(temp_dir.join("src")).unwrap();

    let file_path = "src/order.rs";
    let code = r#"use std::collections::HashMap;

pub struct Order {
    pub id: u64,
    pub total: f64,
}

pub fn calculate_subtotal(items: &[f64]) -> f64 {
    items.iter().sum()
}

pub fn apply_tax(subtotal: f64, rate: f64) -> f64 {
    subtotal * (1.0 + rate)
}
"#;

    fs::write(temp_dir.join(file_path), code).unwrap();

    let scopes = parse_live_ast_scopes(file_path, code).unwrap();
    assert!(scopes.len() >= 3);

    // 1. Resolve scope by name
    let tax_scope =
        find_scope_by_name_or_line(&scopes, "apply_tax").expect("apply_tax scope found");
    assert_eq!(tax_scope.name, "apply_tax");

    // 2. Resolve scope by line number
    let subtotal_scope =
        find_scope_by_name_or_line(&scopes, "9").expect("subtotal scope by line found");
    assert_eq!(subtotal_scope.name, "calculate_subtotal");

    // 3. Claim lock for Alice
    let now = chrono::Utc::now().timestamp();
    let mut lock_table = AstLockTable::new();
    assert!(lock_table.claim(tax_scope, "alice", now).is_ok());

    // 4. Bob tries to claim the same scope -> must fail
    let bob_claim = lock_table.claim(tax_scope, "bob", now + 10);
    assert!(bob_claim.is_err());
    assert!(bob_claim.unwrap_err().contains("gesperrt durch 'alice'"));

    // 5. Test persistence to workspace .sb/ast_locks.json
    assert!(lock_table.save_to_workspace(&temp_dir).is_ok());
    let loaded_table = AstLockTable::load_from_workspace(&temp_dir);
    assert_eq!(loaded_table.locks.len(), 1);
    assert!(loaded_table.locks.contains_key(&tax_scope.id));

    // 6. List active locks
    let active = loaded_table.list_active_locks(now + 20);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0.locked_by, "alice");
    assert!(active[0].1 > 0); // remaining TTL > 0

    // 7. Save baseline snapshot
    let mut baseline = BaselineCache::new();
    baseline.save_stable_scope(
        &tax_scope.id,
        "pub fn apply_tax(subtotal: f64, rate: f64) -> f64 {\n    subtotal * (1.0 + rate)\n}",
    );
    assert!(baseline.save_to_workspace(&temp_dir).is_ok());
    let loaded_baseline = BaselineCache::load_from_workspace(&temp_dir);
    assert!(loaded_baseline.get_stable_scope(&tax_scope.id).is_some());

    // 8. Bob attempts to release Alice's lock -> should not be removed
    lock_table.release(&tax_scope.id, "bob");
    assert!(lock_table.locks.contains_key(&tax_scope.id));

    // 9. Alice releases her lock -> should be removed
    lock_table.release(&tax_scope.id, "alice");
    assert!(!lock_table.locks.contains_key(&tax_scope.id));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_swarm_diff_streaming_flow() {
    let temp_dir = std::env::temp_dir().join(format!("sb_stream_flow_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(temp_dir.join("src")).unwrap();

    let file_path = "src/pricing.rs";
    let base_code = r#"pub fn compute_fee(amount: f64) -> f64 {
    amount * 0.05
}

pub fn compute_rebate(amount: f64) -> f64 {
    amount * 0.02
}
"#;

    fs::write(temp_dir.join(file_path), base_code).unwrap();

    // Initialize VCS so we have a clean committed baseline
    let mut vcs = sb_code::vcs::VcsEngine::init(&temp_dir).unwrap();
    vcs.commit("Initial commit", "sentinel").unwrap();

    // Developer modifies compute_fee
    let modified_code = r#"pub fn compute_fee(amount: f64) -> f64 {
    amount * 0.08
}

pub fn compute_rebate(amount: f64) -> f64 {
    amount * 0.02
}
"#;
    fs::write(temp_dir.join(file_path), modified_code).unwrap();

    let scopes = parse_live_ast_scopes(file_path, modified_code).unwrap();
    let fee_scope = scopes.iter().find(|s| s.name == "compute_fee").unwrap();

    let now = chrono::Utc::now().timestamp();
    let mut locks = AstLockTable::new();
    locks.claim(fee_scope, "dev-1", now).unwrap();

    // Generate diff packets
    let packets = generate_ast_annotated_diff(&temp_dir, file_path, "dev-1", &locks).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].scope_name, "compute_fee");
    assert!(packets[0].is_locked);
    assert_eq!(packets[0].locked_by.as_deref(), Some("dev-1"));

    // Attempt to apply a packet from unauthorized peer 'rogue' while dev-1 holds the lock
    let rogue_packet = AstDiffStreamPacket {
        file_path: file_path.to_string(),
        scope_id: fee_scope.id.clone(),
        scope_name: fee_scope.name.clone(),
        author: "rogue".to_string(),
        timestamp_us: 5000,
        diff_hunk: "-    amount * 0.05\n+    amount * 0.99".to_string(),
        is_locked: true,
        locked_by: Some("dev-1".to_string()),
    };

    let target_dir =
        std::env::temp_dir().join(format!("sb_stream_target_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(target_dir.join("src")).unwrap();
    fs::write(target_dir.join(file_path), base_code).unwrap();

    let rogue_res = apply_ast_diff(&target_dir, &rogue_packet, "dev-2", &locks);
    assert!(rogue_res.is_err());
    assert!(rogue_res
        .unwrap_err()
        .contains("ist gesperrt durch 'dev-1'"));

    // Dev-1's packet is accepted and applied cleanly
    let dev1_res = apply_ast_diff(&target_dir, &packets[0], "dev-2", &locks);
    assert!(dev1_res.is_ok());

    let target_content = fs::read_to_string(target_dir.join(file_path)).unwrap();
    assert!(target_content.contains("amount * 0.08"));
    assert!(!target_content.contains("amount * 0.05"));

    let _ = fs::remove_dir_all(&temp_dir);
    let _ = fs::remove_dir_all(&target_dir);
}
