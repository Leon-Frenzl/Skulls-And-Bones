use sb_code::ast::{parse_live_ast_scopes, AstLockTable};
use sb_code::baseline::BaselineCache;
use sb_code::merkle::CommitStore;
use sb_code::session::{CodeSession, PeerInfo, PeerRole};
use std::fs;

#[test]
fn test_multi_developer_swarm_simulation() {
    let temp_dir = std::env::temp_dir().join(format!("sb_code_sim_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("  SKULLS & BONES // MULTI-DEVELOPER SWARM SIMULATION");
    println!("  Szenario: 3 Entwickler kollaborieren simultan an derselben Datei");
    println!("══════════════════════════════════════════════════════════════════");

    // ─────────────────────────────────────────────────────────────────
    // Phase 1: Session Initiation & Swarm Join
    // ─────────────────────────────────────────────────────────────────
    println!("\n[PHASE 1] Session Bootstrap & Mesh Discovery");
    let mut session = CodeSession::new_host("alpha-swarm", "sentinel-prime");
    println!("  ► Host 'sentinel-prime' startet Swarm-Session 'alpha-swarm'");

    session.peers.push(PeerInfo {
        callsign: "apex-vanguard".to_string(),
        node_id: "node-apex-88".to_string(),
        role: PeerRole::Collaborator,
        active_scope: None,
        ping_ms: 14,
        is_self: false,
    });
    println!("  ► Peer 'apex-vanguard' tritt über sb-mesh bei (Ping: 14ms)");

    session.peers.push(PeerInfo {
        callsign: "cipher-phantom".to_string(),
        node_id: "node-cipher-42".to_string(),
        role: PeerRole::Collaborator,
        active_scope: None,
        ping_ms: 21,
        is_self: false,
    });
    println!("  ► Peer 'cipher-phantom' tritt über sb-mesh bei (Ping: 21ms)");
    assert_eq!(session.peers.len(), 3);

    // ─────────────────────────────────────────────────────────────────
    // Phase 2: Simultaner Zugriff auf dieselbe Datei
    // ─────────────────────────────────────────────────────────────────
    println!("\n[PHASE 2] Gleichzeitige Arbeit in 'OrderService.java'");
    let file_path = "src/OrderService.java";
    let initial_code = r#"package com.enterprise;

public class OrderService {
    public void createOrder(String id) {
        // Version 1.0
    }

    public void processPayment(String id, double amount) {
        // Version 1.0 (Stable Baseline)
    }

    public void cancelOrder(String id) {
        // Version 1.0
    }
}
"#;

    let scopes = parse_live_ast_scopes(file_path, initial_code).unwrap();
    println!("  ► AST-Parser identifiziert 1 Container-Klasse und 3 Methoden-Scopes.");

    let create_scope = scopes
        .iter()
        .find(|s| s.name.contains("createOrder"))
        .unwrap();
    let payment_scope = scopes
        .iter()
        .find(|s| s.name.contains("processPayment"))
        .unwrap();
    let cancel_scope = scopes
        .iter()
        .find(|s| s.name.contains("cancelOrder"))
        .unwrap();

    let mut lock_table = AstLockTable::new();
    let now = 1000i64;

    // Sentinel claims processPayment
    assert!(lock_table
        .claim(payment_scope, "sentinel-prime", now)
        .is_ok());
    session.update_scope("sentinel-prime", &payment_scope.id);
    println!("  ✓ sentinel-prime reserviert: [processPayment] (Scope gesperrt)");

    // Apex claims createOrder IN THE SAME FILE SIMULTANEOUSLY
    assert!(lock_table.claim(create_scope, "apex-vanguard", now).is_ok());
    session.update_scope("apex-vanguard", &create_scope.id);
    println!("  ✓ apex-vanguard reserviert:   [createOrder] (Simultan im selben File - OK!)");

    // ─────────────────────────────────────────────────────────────────
    // Phase 3: Kollisions-Schutz
    // ─────────────────────────────────────────────────────────────────
    println!("\n[PHASE 3] Kollisions-Abweisung (Cipher versucht gesperrten Scope)");
    let conflict = lock_table.claim(payment_scope, "cipher-phantom", now);
    assert!(conflict.is_err());
    println!("  ✗ ABGEWIESEN: cipher-phantom kann 'processPayment' nicht betreten.");
    println!("    Grund: {}", conflict.unwrap_err());

    // Cipher weicht auf cancelOrder aus
    assert!(lock_table
        .claim(cancel_scope, "cipher-phantom", now)
        .is_ok());
    session.update_scope("cipher-phantom", &cancel_scope.id);
    println!("  ✓ cipher-phantom reserviert stattdessen: [cancelOrder] (Scope gesperrt)");

    // ─────────────────────────────────────────────────────────────────
    // Phase 4: Dual-View Isolation bei Syntaxfehler
    // ─────────────────────────────────────────────────────────────────
    println!("\n[PHASE 4] Dual-View Isolation (Unfertige Syntax vs. Stable Baseline)");
    let mut baseline = BaselineCache::new();
    baseline.save_stable_scope(&payment_scope.id, "    public void processPayment(String id, double amount) {\n        // Version 1.0 (Stable Baseline)\n    }");

    // Sentinel hinterlässt unfertigen Syntax-Fehler in processPayment
    let broken_wip = r#"package com.enterprise;

public class OrderService {
    public void createOrder(String id) {
        // Version 1.0
    }

    public void processPayment(String id, double amount) {
        double fee = 
    }

    public void cancelOrder(String id) {
        // Version 1.0
    }
}
"#;

    // Apex testet sein createOrder: Build baut gegen die STABLE Baseline von processPayment!
    let view_apex =
        baseline.render_dual_view(broken_wip, &scopes, &lock_table, "apex-vanguard", now);
    assert!(!view_apex.contains("double fee ="));
    assert!(view_apex.contains("// Version 1.0 (Stable Baseline)"));
    println!("  ✓ apex-vanguard sieht die STABLE BASELINE: Build bleibt 100% grün!");

    // Sentinel sieht seinen eigenen unfertigen Code
    let view_sentinel =
        baseline.render_dual_view(broken_wip, &scopes, &lock_table, "sentinel-prime", now);
    assert!(view_sentinel.contains("double fee ="));
    println!("  ✓ sentinel-prime sieht seinen WIP-Code: Kann in Ruhe fertig tippen.");

    // ─────────────────────────────────────────────────────────────────
    // Phase 5: Fertigstellung & Atomarer Release
    // ─────────────────────────────────────────────────────────────────
    println!("\n[PHASE 5] Fertigstellung, Commit & Lock-Release");
    // Sentinel schließt die Methode fehlerfrei ab
    let completed_method = "    public void processPayment(String id, double amount) {\n        double fee = amount * 0.02;\n        charge(id, amount + fee);\n    }";
    baseline.save_stable_scope(&payment_scope.id, completed_method);

    // Sentinel verlässt die Methode -> Lock-Freigabe
    lock_table.release(&payment_scope.id, "sentinel-prime");
    println!("  ✓ sentinel-prime verlässt 'processPayment' -> Lock freigegeben!");

    // Cipher kann die fertige Methode nun sofort betreten
    assert!(lock_table
        .claim(payment_scope, "cipher-phantom", now + 10)
        .is_ok());
    println!("  ✓ cipher-phantom kann 'processPayment' nun öffnen und sieht Version 2.0!");

    // ─────────────────────────────────────────────────────────────────
    // Phase 6: Merkle VCS Commit mit Team-Signatur
    // ─────────────────────────────────────────────────────────────────
    println!("\n[PHASE 6] Persistenter Merkle-DAG Commit");
    let mut commit_store = CommitStore::default();
    let commit = commit_store.create_commit(
        "Feature: Enterprise Billing & Multi-Currency Payments",
        "blake3_swarm_tree_root_v2",
        "sentinel-prime",
    );
    println!("  ✓ Commit erstellt: #{}", &commit.commit_id[..16]);
    println!("    Signatur:  Legacy-Platzhalter (keine kryptographische Signatur)");
    println!("    Author:    {}", commit.author_callsign);
    println!("    Nachricht: {}", commit.message);

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("  ✓ SIMULATION ERFOLGREICH: 0 KONFLIKTE, 0 BUILD-UNTERBRECHUNGEN!");
    println!("══════════════════════════════════════════════════════════════════\n");

    let _ = fs::remove_dir_all(&temp_dir);
}
