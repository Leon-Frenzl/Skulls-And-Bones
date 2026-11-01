use sb_code::ast::{parse_live_ast_scopes, AstLockTable};
use sb_code::baseline::BaselineCache;
use sb_code::merkle::CommitStore;
use std::fs;

#[test]
fn test_e2e_zero_conflict_workflow() {
    let temp_dir = std::env::temp_dir().join(format!("sb_code_e2e_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    // 1. Initialize a clean code file
    let file_path = temp_dir.join("Service.java");
    let initial_code = r#"package com.app;

public class Service {
    public int calculate(int a) {
        return a * 2;
    }

    public String greet(String name) {
        return "Hello " + name;
    }
}
"#;
    fs::write(&file_path, initial_code).unwrap();

    // 2. Parse AST Scopes
    let scopes = parse_live_ast_scopes(&file_path.to_string_lossy(), initial_code).unwrap();
    assert_eq!(scopes.len(), 4); // package, class, calculate, greet

    let calc_scope = scopes
        .iter()
        .find(|s| s.name.contains("calculate"))
        .unwrap();
    let greet_scope = scopes.iter().find(|s| s.name.contains("greet")).unwrap();
    assert!(!calc_scope.is_container);
    assert!(!greet_scope.is_container);

    // 3. Peer A claims calculate scope, Peer B claims greet scope SIMULTANEOUSLY
    let mut locks = AstLockTable::new();
    assert!(locks.claim(calc_scope, "sentinel-prime", 1000).is_ok());
    assert!(locks.claim(greet_scope, "apex-vanguard", 1000).is_ok());

    // 4. Peer B tries to overwrite calculate -> MUST FAIL (Locked by Sentinel)
    let conflict_err = locks.claim(calc_scope, "apex-vanguard", 1005);
    assert!(conflict_err.is_err());
    assert!(conflict_err
        .unwrap_err()
        .contains("gesperrt durch 'sentinel-prime'"));

    // 5. Test Dual-View Shadow Baseline
    let mut baseline = BaselineCache::new();
    baseline.save_stable_scope(
        &calc_scope.id,
        "    public int calculate(int a) {\n        return a * 2;\n    }",
    );

    // Peer A introduces a syntax error in calculate
    let broken_wip_code = r#"package com.app;

public class Service {
    public int calculate(int a) {
        return a * // SYNTAX INCOMPLETE
    }

    public String greet(String name) {
        return "Hello " + name;
    }
}
"#;

    // View for Peer B: calculate is replaced by the STABLE baseline!
    let view_b = baseline.render_dual_view(broken_wip_code, &scopes, &locks, "apex-vanguard", 1010);
    assert!(view_b.contains("return a * 2;"));
    assert!(!view_b.contains("SYNTAX INCOMPLETE"));

    // View for Peer A: sees their live WIP code
    let view_a =
        baseline.render_dual_view(broken_wip_code, &scopes, &locks, "sentinel-prime", 1010);
    assert!(view_a.contains("SYNTAX INCOMPLETE"));

    // 6. Merkle VCS Commit Chain
    let mut store = CommitStore::default();
    let c1 = store.create_commit("Initial commit", "blake3_hash_v1", "sentinel-prime");
    assert_eq!(store.commits.len(), 1);
    assert_eq!(c1.author_callsign, "sentinel-prime");

    let _ = fs::remove_dir_all(&temp_dir);
}
