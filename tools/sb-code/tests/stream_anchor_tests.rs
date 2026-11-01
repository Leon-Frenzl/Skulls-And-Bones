use sb_code::anchor::{self, AnchorInfo};
use sb_code::stream::{publish_project, subscribe_project};
use std::fs::{self, File};
use std::io::Write;

#[tokio::test]
async fn test_publish_with_sbignore_and_manifest() {
    let temp_workspace =
        std::env::temp_dir().join(format!("sb_stream_pub_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(temp_workspace.join("src")).unwrap();
    fs::create_dir_all(temp_workspace.join("target")).unwrap();
    fs::create_dir_all(temp_workspace.join("logs")).unwrap();

    // Create source files
    let mut f_rs = File::create(temp_workspace.join("src/main.rs")).unwrap();
    writeln!(f_rs, "fn main() {{ println!(\"Stream Test\"); }}").unwrap();

    let mut f_cargo = File::create(temp_workspace.join("Cargo.toml")).unwrap();
    writeln!(
        f_cargo,
        "[package]\nname = \"demo-stream\"\nversion = \"0.1.0\""
    )
    .unwrap();

    // Create .sbignore
    let mut f_ignore = File::create(temp_workspace.join(".sbignore")).unwrap();
    writeln!(f_ignore, "logs/\n*.cache").unwrap();

    // Create ignored files
    let mut f_log = File::create(temp_workspace.join("logs/stream.log")).unwrap();
    writeln!(f_log, "some log").unwrap();

    let mut f_cache = File::create(temp_workspace.join("app.cache")).unwrap();
    writeln!(f_cache, "some cache").unwrap();

    // Create kernel ignored file
    let mut f_env = File::create(temp_workspace.join(".env")).unwrap();
    writeln!(f_env, "SUPER_SECRET=xyz").unwrap();

    // Run publish_project
    let manifest = publish_project(&temp_workspace, Some("demo-stream".to_string()))
        .await
        .expect("publish_project failed");

    assert_eq!(manifest.project_name, "demo-stream");
    assert_eq!(manifest.swarm_topic, "sbm:code:demo-stream");
    assert_eq!(manifest.files_count, 4); // src, src/main.rs, Cargo.toml, .sbignore (logs, cache, target, and .env are excluded)

    // Check that manifest file was written into .sb/stream-manifest.json
    let manifest_file = temp_workspace.join(".sb").join("stream-manifest.json");
    assert!(manifest_file.is_file(), "Manifest file must exist in .sb");

    let _ = fs::remove_dir_all(&temp_workspace);
}

#[tokio::test]
async fn test_subscribe_project_workspace_setup() {
    let temp_dest = std::env::temp_dir().join(format!("sb_stream_sub_{}", uuid::Uuid::new_v4()));

    let dest = subscribe_project("demo-stream", Some(temp_dest.clone()))
        .await
        .expect("subscribe_project failed");

    assert_eq!(dest, temp_dest);
    assert!(temp_dest.exists());
    assert!(temp_dest.join(".sb").exists());

    let _ = fs::remove_dir_all(&temp_dest);
}

#[test]
fn test_anchor_status_report_formatting() {
    // 1. When Anchor exists
    let anchors = vec![AnchorInfo {
        callsign: "srv-hetzner-anchor".to_string(),
        node_id: "node-101".to_string(),
        overlay_ip: Some("10.42.0.2".to_string()),
        endpoint: Some("1.2.3.4:58888".to_string()),
        is_anchor: true,
        source: "sb-mesh IPC".to_string(),
    }];
    assert!(anchor::print_anchor_status_report(&anchors));

    // 2. When no Anchor exists (educational warning)
    let empty_anchors: Vec<AnchorInfo> = Vec::new();
    assert!(!anchor::print_anchor_status_report(&empty_anchors));
}
