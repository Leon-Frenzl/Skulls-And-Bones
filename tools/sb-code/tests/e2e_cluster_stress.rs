use sb_code::dev_workspace::{DevWorkspaceEntry, DevWorkspacePolicy, DevWorkspaceRegistry};
use sb_code::mesh_sync::{
    handle_connection_with_registry, pull_workspace_over_stream, push_workspace_over_stream,
};
use sb_code::vcs::VcsEngine;
use std::fs;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_cluster_dev_workspace_concurrency_and_stress() {
    let base_temp =
        std::env::temp_dir().join(format!("sb_cluster_stress_{}", uuid::Uuid::new_v4()));
    let server_core_dir = base_temp.join("server_core");
    let server_mesh_dir = base_temp.join("server_mesh");
    let client_core_dir = base_temp.join("client_core");
    let client_mesh_dir = base_temp.join("client_mesh");
    let replica_core_dir = base_temp.join("replica_core");

    fs::create_dir_all(&server_core_dir).unwrap();
    fs::create_dir_all(&server_mesh_dir).unwrap();
    fs::create_dir_all(&client_core_dir).unwrap();
    fs::create_dir_all(&client_mesh_dir).unwrap();
    fs::create_dir_all(&replica_core_dir).unwrap();

    println!("\n══════════════════════════════════════════════════════════════════");
    println!("  SKULLS & BONES // E2E CLUSTER DEV-WORKSPACE STRESS TEST");
    println!("  Szenario: Concurrency, Multi-Workspace Isolation & CAS-Gates");
    println!("══════════════════════════════════════════════════════════════════");

    // 1. Initialisiere Server-Repositories
    let s_core = VcsEngine::init(&server_core_dir).unwrap();
    s_core.set_project_name("sb-core").unwrap();
    let s_mesh = VcsEngine::init(&server_mesh_dir).unwrap();
    s_mesh.set_project_name("sb-mesh").unwrap();

    // 2. Initialisiere Client-Repositories
    let mut c_core = VcsEngine::init(&client_core_dir).unwrap();
    c_core.set_project_name("sb-core").unwrap();
    let mut c_mesh = VcsEngine::init(&client_mesh_dir).unwrap();
    c_mesh.set_project_name("sb-mesh").unwrap();

    // 3. Konfiguriere Multi-Workspace Policies
    println!("\n[PHASE 1] Registry & Policy Setup");
    let mut registry = DevWorkspaceRegistry::new();
    let policy_core = DevWorkspacePolicy::new(
        "dev/tools/sb-core",
        "sb-core",
        "writer-core",
        vec!["replica-core".into()],
    )
    .unwrap();
    let policy_mesh = DevWorkspacePolicy::new(
        "dev/tools/sb-mesh",
        "sb-mesh",
        "writer-mesh",
        vec!["replica-mesh".into()],
    )
    .unwrap();

    registry
        .register(DevWorkspaceEntry {
            workspace_id: "dev/tools/sb-core".into(),
            repo_path: server_core_dir.clone(),
            policy: policy_core,
        })
        .unwrap();

    registry
        .register(DevWorkspaceEntry {
            workspace_id: "dev/tools/sb-mesh".into(),
            repo_path: server_mesh_dir.clone(),
            policy: policy_mesh,
        })
        .unwrap();

    let shared_registry = Arc::new(registry);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    println!("  ► Cluster Dev-Workspace Syncd lauscht auf TCP {address}");

    let srv_reg = shared_registry.clone();
    let server_task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let r = srv_reg.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection_with_registry(stream, &r).await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    // 4. Stresstest Phase 1: 15 Schnelle sequenzielle Commits & Pushes (Burst)
    println!("\n[PHASE 2] Stress-Burst: 15 Rapid Commits & Pushes auf 'sb-core'");
    let mut last_head = String::new();
    for i in 1..=15 {
        let code = format!("pub fn func_{i}() -> usize {{ {i} * 42 }}\n");
        fs::write(client_core_dir.join(format!("mod_{i}.rs")), code).unwrap();
        let commit = c_core
            .commit(
                &format!("feat: add module {i} with ast scope"),
                "writer-core",
            )
            .unwrap();
        last_head = commit.commit_id.clone();

        let mut stream = TcpStream::connect(address).await.unwrap();
        let report = push_workspace_over_stream(
            &mut stream,
            &c_core,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-core"),
            Some("writer-core"),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.new_head, last_head);
    }
    println!("  ✓ 15 aufeinanderfolgende Commits erfolgreich verifiziert und synchronisiert!");
    println!("  ► Letzter verifizierter HEAD: {last_head}");

    // 5. Stresstest Phase 2: Parallele Multi-Workspace Pushes (sb-core & sb-mesh zeitgleich)
    println!("\n[PHASE 3] Concurrency: Parallele Pushes auf 'sb-core' und 'sb-mesh'");
    fs::write(
        client_core_dir.join("concurrent.rs"),
        "// concurrent core\n",
    )
    .unwrap();
    let core_concurrent_commit = c_core
        .commit("feat: concurrent core push", "writer-core")
        .unwrap();

    fs::write(
        client_mesh_dir.join("concurrent.rs"),
        "// concurrent mesh\n",
    )
    .unwrap();
    let mesh_concurrent_commit = c_mesh
        .commit("feat: concurrent mesh push", "writer-mesh")
        .unwrap();

    let client_core_path = client_core_dir.clone();
    let client_mesh_path = client_mesh_dir.clone();
    let core_head = core_concurrent_commit.commit_id.clone();
    let mesh_head = mesh_concurrent_commit.commit_id.clone();

    let task_core = tokio::spawn(async move {
        let engine = VcsEngine::open(&client_core_path).unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        push_workspace_over_stream(
            &mut stream,
            &engine,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-core"),
            Some("writer-core"),
            None,
            None,
        )
        .await
    });

    let task_mesh = tokio::spawn(async move {
        let engine = VcsEngine::open(&client_mesh_path).unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        push_workspace_over_stream(
            &mut stream,
            &engine,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-mesh"),
            Some("writer-mesh"),
            None,
            None,
        )
        .await
    });

    let (res_core, res_mesh) = tokio::join!(task_core, task_mesh);
    let report_core = res_core.unwrap().unwrap();
    let report_mesh = res_mesh.unwrap().unwrap();
    assert_eq!(report_core.new_head, core_head);
    assert_eq!(report_mesh.new_head, mesh_head);
    println!("  ✓ Beide parallelen Pushes atomar und konfliktfrei abgeschlossen!");

    // 6. Stresstest Phase 3: Security & Isolation Gates
    println!("\n[PHASE 4] Security-Gates: Unberechtigter Zugriff & Cross-Workspace Schutz");
    let mut stream_intruder = TcpStream::connect(address).await.unwrap();
    let err_intruder = push_workspace_over_stream(
        &mut stream_intruder,
        &c_mesh,
        "dev-mesh",
        "main",
        Some("dev/tools/sb-core"), // Versucht fremden Namespace zu überschreiben
        Some("intruder-peer"),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(err_intruder.contains("Access Denied"));
    println!("  ✓ Fremder Peer 'intruder-peer' wurde strikt fail-closed abgewiesen.");

    // 7. Stresstest Phase 4: CAS Divergence Defense (expected_head)
    println!("\n[PHASE 5] CAS Divergence Defense: Veralteter expected_head");
    let mut stream_divergent = TcpStream::connect(address).await.unwrap();
    let err_divergent = push_workspace_over_stream(
        &mut stream_divergent,
        &c_core,
        "dev-mesh",
        "main",
        Some("dev/tools/sb-core"),
        Some("writer-core"),
        Some("stale_hash_from_past_head_12345"),
        None,
    )
    .await
    .unwrap_err();
    assert!(err_divergent.contains("Divergent head detected"));
    println!("  ✓ Nicht-übereinstimmender HEAD erkannt & abgewiesen (CAS-Garantie eingehalten).");

    // 8. Stresstest Phase 5: Replikation auf autorisierten Replica-Node
    println!("\n[PHASE 6] Replikations-Audit: Pull auf Replica-Node 'replica-core'");
    let mut r_core = VcsEngine::init(&replica_core_dir).unwrap();
    r_core.set_project_name("sb-core").unwrap();

    let mut stream_replica = TcpStream::connect(address).await.unwrap();
    let pull_report = pull_workspace_over_stream(
        &mut stream_replica,
        &mut r_core,
        "dev-mesh",
        "main",
        Some("dev/tools/sb-core"),
        Some("replica-core"),
        None,
    )
    .await
    .unwrap();

    assert_eq!(pull_report.new_head, core_head);
    println!(
        "  ✓ Replikation abgeschlossen! Neuer HEAD auf Replica: {}",
        pull_report.new_head
    );

    // Verifiziere Dateien und Ed25519-Commit-Signaturen auf der Replica
    let status = r_core.status().unwrap();
    assert!(status.is_clean);
    for i in 1..=15 {
        assert!(replica_core_dir.join(format!("mod_{i}.rs")).exists());
    }
    assert!(replica_core_dir.join("concurrent.rs").exists());

    let log = r_core.branch_ancestry_ids("main", 50).unwrap();
    assert!(log.len() >= 16);
    for commit_id in &log {
        let commit = r_core.get_commit(commit_id).unwrap();
        assert!(
            commit.verify_signature().is_ok(),
            "Commit-Signatur muss integer sein"
        );
    }
    println!("  ✓ Alle 16 replizierten Commits besitzen valide Ed25519-Signaturen!");

    server_task.abort();
    let _ = fs::remove_dir_all(&base_temp);

    println!("\n==================================================================");
    println!("  [ERFOLG] CLUSTER DEV-WORKSPACE E2E STRESSTEST BESTANDEN!");
    println!("==================================================================\n");
}
