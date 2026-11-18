use serde_json::Value;
use std::fs;
use std::io::Read;
use std::net::UdpSocket;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn separate_mesh_daemons_keep_identity_and_runtime_state_isolated() {
    let binary = env!("CARGO_BIN_EXE_sb-mesh");
    let home = std::env::temp_dir().join(format!(
        "sb-mesh-daemons-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::create_dir_all(&home).unwrap();
    let data_dir = home.join(".sb-mesh");

    let create_mesh = Command::new(binary)
        .args(["network", "create", "alpha", "--subnet", "10.241.0.0/16"])
        .env("SB_MESH_HOME", &data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        create_mesh.status.success(),
        "Mesh setup failed: {}",
        String::from_utf8_lossy(&create_mesh.stderr)
    );

    let first_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let first_port = first_socket.local_addr().unwrap().port();
    let second_port = second_socket.local_addr().unwrap().port();
    assert_ne!(first_port, second_port);
    drop((first_socket, second_socket));

    let default_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, "default").unwrap();
    let alpha_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, "alpha").unwrap();
    let default_public_key;
    {
        let mut default_daemon = start_daemon(binary, &home, "default", first_port);
        let mut alpha_daemon = start_daemon(binary, &home, "alpha", second_port);
        wait_for_runtime(&mut default_daemon.0, &default_paths.runtime_status);
        wait_for_runtime(&mut alpha_daemon.0, &alpha_paths.runtime_status);

        let default_status: Value =
            serde_json::from_slice(&fs::read(&default_paths.runtime_status).unwrap()).unwrap();
        let alpha_status: Value =
            serde_json::from_slice(&fs::read(&alpha_paths.runtime_status).unwrap()).unwrap();
        assert_eq!(default_status["mesh_name"], "default");
        assert_eq!(alpha_status["mesh_name"], "alpha");
        assert_ne!(
            default_status["process_id"], alpha_status["process_id"],
            "Both mesh daemons should be separate processes"
        );
        assert_ne!(
            default_status["local_public_key"], alpha_status["local_public_key"],
            "Each running mesh must use its own local identity"
        );
        default_public_key = default_status["local_public_key"]
            .as_str()
            .unwrap()
            .to_string();
        for path in [
            default_paths.identity,
            default_paths.config,
            default_paths.peers,
            alpha_paths.identity,
            alpha_paths.config,
            alpha_paths.peers,
        ] {
            assert!(
                path.is_file(),
                "Expected per-mesh state at {}",
                path.display()
            );
        }
    }

    fs::remove_file(&default_paths.runtime_status).unwrap();
    let mut restarted_daemon = start_daemon(binary, &home, "default", first_port);
    wait_for_runtime(&mut restarted_daemon.0, &default_paths.runtime_status);
    let restarted_status: Value =
        serde_json::from_slice(&fs::read(&default_paths.runtime_status).unwrap()).unwrap();
    assert_eq!(
        restarted_status["local_public_key"], default_public_key,
        "Mesh identity must survive a daemon restart"
    );
    drop(restarted_daemon);

    fs::remove_dir_all(home).unwrap();
}

fn start_daemon(binary: &str, home: &Path, mesh: &str, port: u16) -> ChildGuard {
    let child = Command::new(binary)
        .args(["daemon", "--mesh", mesh, "--port", &port.to_string()])
        .env("SB_MESH_HOME", home.join(".sb-mesh"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ChildGuard(child)
}

fn wait_for_runtime(child: &mut Child, path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if path.is_file() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(stderr_pipe) = child.stderr.as_mut() {
                stderr_pipe.read_to_string(&mut stderr).unwrap();
            }
            panic!("Mesh daemon exited before publishing runtime status: {status}; {stderr}");
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for runtime status at {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(50));
    }
}
