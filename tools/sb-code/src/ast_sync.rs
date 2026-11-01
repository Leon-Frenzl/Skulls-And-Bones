use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

pub const AST_LOCK_STREAM_PORT: u16 = 58834;
const MAX_CONTROL_FRAME: usize = 1024 * 1024;
const LOCK_TTL_SECONDS: i64 = 180;
const MAX_ACTIVE_LOCKS: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AstLockRecord {
    pub scope_id: String,
    pub scope_name: String,
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub locked_by: String,
    pub owner_node_id: String,
    pub acquired_at: i64,
    pub last_heartbeat: i64,
    pub ttl_seconds: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum AstLockRequest {
    Claim { record: AstLockRecord },
    Release { scope_id: String },
    Heartbeat { scope_id: String },
    List,
}

#[derive(Debug, Deserialize, Serialize)]
struct AstLockResponse {
    accepted: bool,
    message: String,
    locks: Vec<AstLockRecord>,
}

#[derive(Default)]
struct AstLockState {
    table: crate::ast::AstLockTable,
    metadata: HashMap<String, AstLockRecord>,
    owner_node_ids: HashMap<String, String>,
}

// CVE-Threat: Unauthorized lock mutation or unbounded stream input.
// Analysis: The listener is only reachable through sb-node's authenticated Mesh stream route.
// Hardening: Bind to loopback, cap frames/concurrency, and check peer ownership on release/heartbeat.
pub async fn start_ast_syncd(bind: SocketAddr) -> Result<(), String> {
    if !bind.ip().is_loopback() {
        return Err(
            "AST lock sync daemon must bind to loopback; expose it only through sb-node".into(),
        );
    }
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("Failed to bind AST lock sync daemon at {bind}: {error}"))?;
    println!(
        "AST lock sync daemon listening on {}",
        listener.local_addr().map_err(|error| error.to_string())?
    );
    tokio::spawn(async move {
        if let Err(error) = run_ast_syncd(listener).await {
            eprintln!("AST lock sync daemon stopped: {error}");
        }
    });
    Ok(())
}

async fn run_ast_syncd(listener: TcpListener) -> Result<(), String> {
    let state = Arc::new(Mutex::new(AstLockState::default()));
    let connection_limit = Arc::new(Semaphore::new(32));
    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .map_err(|error| format!("AST lock sync accept failed: {error}"))?;
        if !peer_addr.ip().is_loopback() {
            eprintln!("Rejected non-loopback AST lock connection from {peer_addr}");
            continue;
        }
        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!(
                    "Rejected AST lock connection from {peer_addr}: connection limit reached"
                );
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                handle_connection(stream, state),
            )
            .await
            .map_err(|_| "AST lock request timed out".to_string())
            .and_then(|result| result);
            if let Err(error) = result {
                eprintln!("AST lock request from {peer_addr} failed: {error}");
            }
        });
    }
}

pub async fn claim(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    record: AstLockRecord,
) -> Result<Vec<AstLockRecord>, String> {
    request(
        source_mesh,
        target_mesh,
        anchor_addr,
        AstLockRequest::Claim { record },
    )
    .await
}

pub async fn release(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    scope_id: String,
) -> Result<Vec<AstLockRecord>, String> {
    request(
        source_mesh,
        target_mesh,
        anchor_addr,
        AstLockRequest::Release { scope_id },
    )
    .await
}

pub async fn heartbeat(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    scope_id: String,
) -> Result<Vec<AstLockRecord>, String> {
    request(
        source_mesh,
        target_mesh,
        anchor_addr,
        AstLockRequest::Heartbeat { scope_id },
    )
    .await
}

pub async fn list(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
) -> Result<Vec<AstLockRecord>, String> {
    request(source_mesh, target_mesh, anchor_addr, AstLockRequest::List).await
}

async fn request(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    request: AstLockRequest,
) -> Result<Vec<AstLockRecord>, String> {
    let identity = Arc::new(
        sb_mesh::identity::NodeIdentity::load_or_generate_default()
            .map_err(|error| format!("Failed to load sb-mesh identity: {error}"))?,
    );
    if sb_mesh::ticket::load_cached_ticket(source_mesh).is_none() {
        return Err(format!(
            "No valid cached Mesh ticket for '{source_mesh}'; join that mesh first"
        ));
    }
    let client = sb_mesh::client::MeshClient::connect(sb_mesh::client::MeshClientConfig {
        mesh_name: source_mesh.to_string(),
        swarm_topic: format!("sbm-swarm-{source_mesh}"),
        anchor_addr,
        identity,
        local_bind_port: None,
    })
    .await
    .map_err(|error| format!("Failed to connect to source mesh: {error}"))?;
    let mut stream = client
        .open_cross_mesh_stream(target_mesh, AST_LOCK_STREAM_PORT, None)
        .await
        .map_err(|error| format!("Failed to open AST lock mesh stream: {error}"))?;
    write_frame(&mut stream, &request).await?;
    let response: AstLockResponse = read_frame(&mut stream).await?;
    if !response.accepted {
        return Err(format!(
            "Remote AST lock request rejected: {}",
            response.message
        ));
    }
    Ok(response.locks)
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<AstLockState>>,
) -> Result<(), String> {
    let identity: sb_mesh::bridge::MeshStreamIdentity = read_frame(&mut stream).await?;
    if identity.source_mesh.trim().is_empty()
        || identity.source_mesh.len() > 64
        || identity.source_node_id.trim().is_empty()
        || identity.source_node_id.len() > 128
    {
        return Err("Authenticated Mesh stream identity is invalid".into());
    }
    let request: AstLockRequest = read_frame(&mut stream).await?;
    let now = chrono::Utc::now().timestamp();
    let mut state = state.lock().await;
    state.table.cleanup_expired(now);
    let active_scope_ids = state
        .table
        .locks
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    state
        .metadata
        .retain(|scope_id, _| active_scope_ids.contains(scope_id));
    state
        .owner_node_ids
        .retain(|scope_id, _| active_scope_ids.contains(scope_id));

    let result = match request {
        AstLockRequest::Claim { mut record } => {
            if record.scope_id.trim().is_empty()
                || record.scope_id.len() > 1024
                || record.scope_name.len() > 512
                || record.file_path.len() > 4096
                || record.locked_by.trim().is_empty()
                || record.locked_by.len() > 128
                || record.start_line == 0
                || record.end_line < record.start_line
            {
                return write_frame(
                    &mut stream,
                    &AstLockResponse {
                        accepted: false,
                        message: "AST lock metadata is invalid".into(),
                        locks: Vec::new(),
                    },
                )
                .await;
            }
            if state.table.locks.len() >= MAX_ACTIVE_LOCKS
                && !state.table.locks.contains_key(&record.scope_id)
            {
                return write_frame(
                    &mut stream,
                    &AstLockResponse {
                        accepted: false,
                        message: "AST lock table capacity has been reached".into(),
                        locks: Vec::new(),
                    },
                )
                .await;
            }
            let scope = crate::ast::AstScope {
                id: record.scope_id.clone(),
                name: record.scope_name.clone(),
                kind: crate::ast::AstScopeKind::Function,
                start_line: record.start_line,
                end_line: record.end_line,
                is_container: false,
            };
            record.acquired_at = now;
            record.last_heartbeat = now;
            record.ttl_seconds = LOCK_TTL_SECONDS;
            record.owner_node_id = identity.source_node_id.clone();
            match state.table.claim(&scope, &identity.source_node_id, now) {
                Ok(()) => {
                    state
                        .owner_node_ids
                        .insert(record.scope_id.clone(), identity.source_node_id.clone());
                    state.metadata.insert(record.scope_id.clone(), record);
                    Ok("Lock claimed".to_string())
                }
                Err(error) => Err(error),
            }
        }
        AstLockRequest::Release { scope_id } => match state.table.locks.get(&scope_id) {
            Some(_) if state.owner_node_ids.get(&scope_id) == Some(&identity.source_node_id) => {
                state.table.release(&scope_id, &identity.source_node_id);
                state.metadata.remove(&scope_id);
                state.owner_node_ids.remove(&scope_id);
                Ok("Lock released".to_string())
            }
            Some(_) => Err("AST lock is owned by another peer".to_string()),
            None => Ok("Lock already released".to_string()),
        },
        AstLockRequest::Heartbeat { scope_id } => {
            let owned = state.owner_node_ids.get(&scope_id) == Some(&identity.source_node_id);
            if owned {
                state
                    .table
                    .heartbeat(&scope_id, &identity.source_node_id, now);
                if let Some(record) = state.metadata.get_mut(&scope_id) {
                    record.last_heartbeat = now;
                }
                Ok("Lock heartbeat accepted".to_string())
            } else {
                Err("AST lock does not exist or is owned by another peer".to_string())
            }
        }
        AstLockRequest::List => Ok("Active locks".to_string()),
    };
    let locks = state
        .table
        .list_active_locks(now)
        .into_iter()
        .filter_map(|(lock, _)| state.metadata.get(&lock.scope_id).cloned())
        .collect();
    let response = AstLockResponse {
        accepted: result.is_ok(),
        message: result.unwrap_or_else(|error| error),
        locks,
    };
    write_frame(&mut stream, &response).await
}

async fn write_frame<S, T>(stream: &mut S, value: &T) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_FRAME {
        return Err("AST lock control frame exceeds the protocol limit".into());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "AST lock control frame is too large")?;
    stream
        .write_u32(length)
        .await
        .map_err(|error| format!("Cannot write AST lock frame length: {error}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("Cannot write AST lock frame: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("Cannot flush AST lock frame: {error}"))
}

async fn read_frame<S, T>(stream: &mut S) -> Result<T, String>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let length = stream
        .read_u32()
        .await
        .map_err(|error| format!("Cannot read AST lock frame length: {error}"))?
        as usize;
    if length == 0 || length > MAX_CONTROL_FRAME {
        return Err("AST lock control frame length is invalid".into());
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| format!("Cannot read AST lock frame: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("Invalid AST lock frame: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stream_lock_authority_rejects_conflicts_and_unowned_mutations() {
        use sb_mesh::bridge::{CrossMeshBridge, CrossMeshRule, ServiceEndpoint};
        use sb_mesh::client::MeshClient;
        use sb_mesh::identity::NodeIdentity;

        let state = Arc::new(Mutex::new(AstLockState::default()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        let server = tokio::spawn(async move {
            for _ in 0..6 {
                let (stream, _) = listener.accept().await.unwrap();
                handle_connection(stream, Arc::clone(&server_state))
                    .await
                    .unwrap();
            }
        });
        let bridge = Arc::new(CrossMeshBridge::new("ast-lock-anchor"));
        bridge
            .register_service(
                "studio-mesh",
                AST_LOCK_STREAM_PORT,
                ServiceEndpoint::LocalTcpWithIdentity(address),
            )
            .await;
        let mut policy = sb_mesh::bridge::CrossMeshPolicy::new();
        policy.add_rule(CrossMeshRule::new(
            "studio-ast-locks",
            "studio-mesh",
            "studio-mesh",
            vec![AST_LOCK_STREAM_PORT],
            false,
            "AST lock live stream smoke test",
        ));
        *bridge.policy.write().await = policy;
        let alice_identity = Arc::new(NodeIdentity::generate());
        let alice_node_id = alice_identity.node_id.clone();
        let alice = MeshClient::with_bridge("studio-mesh", alice_identity, Arc::clone(&bridge));
        let bob =
            MeshClient::with_bridge("studio-mesh", Arc::new(NodeIdentity::generate()), bridge);

        let alice_lock = record("src/lib.rs::function:build", "Alice");
        let locks = mesh_request(&alice, AstLockRequest::Claim { record: alice_lock })
            .await
            .unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].owner_node_id, alice_node_id);
        let opaque = mesh_request(
            &alice,
            AstLockRequest::Claim {
                record: record("src/main.py::opaque:start->end", "Alice"),
            },
        )
        .await
        .expect_err("opaque file ranges cannot be claimed as semantic AST locks");
        assert!(opaque.contains("Opaque"), "{opaque}");
        let collision = mesh_request(
            &bob,
            AstLockRequest::Claim {
                record: record("src/lib.rs::function:build", "Bob"),
            },
        )
        .await
        .expect_err("a second peer cannot claim an active lock");
        assert!(collision.contains("gesperrt durch"), "{collision}");
        assert!(mesh_request(
            &bob,
            AstLockRequest::Release {
                scope_id: "src/lib.rs::function:build".into(),
            }
        )
        .await
        .is_err());
        let renewed = mesh_request(
            &alice,
            AstLockRequest::Heartbeat {
                scope_id: "src/lib.rs::function:build".into(),
            },
        )
        .await
        .expect("owner heartbeat renews the active lock");
        assert_eq!(renewed.len(), 1);
        assert!(renewed[0].last_heartbeat >= locks[0].last_heartbeat);
        let locks = mesh_request(&alice, AstLockRequest::List).await.unwrap();
        assert_eq!(locks[0].locked_by, "Alice");
        server.await.unwrap();
    }

    async fn mesh_request(
        client: &sb_mesh::client::MeshClient,
        request: AstLockRequest,
    ) -> Result<Vec<AstLockRecord>, String> {
        let mut stream = client
            .open_cross_mesh_stream("studio-mesh", AST_LOCK_STREAM_PORT, None)
            .await
            .map_err(|error| error.to_string())?;
        write_frame(&mut stream, &request).await?;
        let response: AstLockResponse = read_frame(&mut stream).await?;
        if response.accepted {
            Ok(response.locks)
        } else {
            Err(response.message)
        }
    }

    fn record(scope_id: &str, peer: &str) -> AstLockRecord {
        AstLockRecord {
            scope_id: scope_id.into(),
            scope_name: "build".into(),
            file_path: "src/lib.rs".into(),
            start_line: 1,
            end_line: 10,
            locked_by: peer.into(),
            owner_node_id: String::new(),
            acquired_at: 0,
            last_heartbeat: 0,
            ttl_seconds: LOCK_TTL_SECONDS,
        }
    }
}
