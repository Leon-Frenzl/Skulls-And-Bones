use sb_code::mesh_sync;
use sb_code::vcs::VcsEngine;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::net::{TcpListener, TcpStream};

fn temporary_repo(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{name}_{}", uuid::Uuid::new_v4()))
}

async fn start_syncd(
    workspace: PathBuf,
) -> (
    std::net::SocketAddr,
    TcpStream,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let task = tokio::spawn(async move { mesh_sync::run_syncd(workspace, address).await });
    let stream = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await {
                break stream;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("syncd should bind and accept loopback connections");
    (address, stream, task)
}

fn write_source(root: &Path, value: u8) {
    fs::write(
        root.join("src.rs"),
        format!("pub fn shared_scope() -> u8 {{ {value} }}\n"),
    )
    .unwrap();
}

#[tokio::test]
async fn peers_push_pull_detect_scope_overlap_and_finalize_deferred_conflict() {
    let alice_path = temporary_repo("sb_mesh_e2e_alice");
    let bob_path = temporary_repo("sb_mesh_e2e_bob");
    let carol_path = temporary_repo("sb_mesh_e2e_carol");
    fs::create_dir_all(&alice_path).unwrap();
    fs::create_dir_all(&bob_path).unwrap();
    fs::create_dir_all(&carol_path).unwrap();

    let mut alice = VcsEngine::init(&alice_path).unwrap();
    alice.set_project_name("mesh-e2e").unwrap();
    write_source(&alice_path, 1);
    alice.commit("shared base", "alice").unwrap();

    let mut bob = VcsEngine::init(&bob_path).unwrap();
    bob.set_project_name("mesh-e2e").unwrap();
    let (bob_address, mut stream, bob_syncd) = start_syncd(bob_path.clone()).await;
    mesh_sync::push_over_stream(&mut stream, &alice, "mesh-e2e", "main")
        .await
        .unwrap();

    let mut carol = VcsEngine::init(&carol_path).unwrap();
    carol.set_project_name("mesh-e2e").unwrap();
    let (_alice_address, mut stream, alice_syncd) = start_syncd(alice_path.clone()).await;
    mesh_sync::pull_over_stream(&mut stream, &mut carol, "mesh-e2e", "main")
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(carol_path.join("src.rs")).unwrap(),
        fs::read_to_string(alice_path.join("src.rs")).unwrap()
    );

    write_source(&alice_path, 2);
    alice.commit("alice changes shared scope", "alice").unwrap();
    write_source(&bob_path, 3);
    bob.commit("bob changes shared scope", "bob").unwrap();

    let local_heads = alice.branch_head_ids().unwrap();
    let known_ancestry = local_heads
        .iter()
        .map(|(branch, head_commit)| {
            Ok(sb_code::vcs::KnownBranchHead {
                branch: branch.clone(),
                head_commit: head_commit.clone(),
                ancestors: alice.branch_ancestry_ids(branch, 128)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()
        .unwrap();
    let mut stream = TcpStream::connect(bob_address).await.unwrap();
    let divergence = mesh_sync::branch_divergence_over_stream(
        &alice,
        &local_heads,
        &known_ancestry,
        &mut stream,
    )
    .await
    .unwrap();
    assert_eq!(divergence.remote_branch_count, 1);
    assert_eq!(divergence.divergences.len(), 1);
    assert_eq!(divergence.divergences[0].local_commits, Some(1));
    assert_eq!(divergence.divergences[0].remote_commits, Some(1));
    assert_eq!(divergence.divergences[0].overlapping_scopes.len(), 1);

    let incoming_bundle = alice.export_bundle("main", None).unwrap();
    bob.import_bundle(&incoming_bundle, "incoming").unwrap();
    let before_finalize = fs::read_to_string(bob_path.join("src.rs")).unwrap();
    let conflicts = bob.prepare_integration_conflicts("incoming").unwrap();
    assert_eq!(conflicts.conflicts.len(), 1);
    assert_eq!(
        fs::read_to_string(bob_path.join("src.rs")).unwrap(),
        before_finalize
    );
    let scope_id = conflicts.conflicts[0].entry.change.scope_id.clone();
    bob.resolve_integration_conflict(&scope_id, sb_code::vcs::ConflictResolution::Other)
        .unwrap();
    let integration = bob.finalize_integration_conflicts("bob").unwrap();
    assert_eq!(integration.parent_ids.len(), 2);
    assert!(fs::read_to_string(bob_path.join("src.rs"))
        .unwrap()
        .contains("{ 2 }"));
    assert!(!bob_path.join(".sb").join("conflicts.json").exists());

    alice_syncd.abort();
    bob_syncd.abort();
    let _ = alice_syncd.await;
    let _ = bob_syncd.await;
    fs::remove_dir_all(alice_path).unwrap();
    fs::remove_dir_all(bob_path).unwrap();
    fs::remove_dir_all(carol_path).unwrap();
}
