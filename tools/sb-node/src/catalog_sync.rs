use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const CATALOG_SYNC_PORT: u16 = 58831;
const MAX_CONTROL_FRAME: usize = 16 * 1024;
const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Inspect,
    ReadSnapshot,
    ApplySnapshot {
        expected_base_digest: Option<String>,
        payload_bytes: u64,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct Request {
    version: u8,
    operation: Operation,
}

#[derive(Debug, Deserialize, Serialize)]
struct Response {
    version: u8,
    accepted: bool,
    message: String,
    digest: Option<String>,
    payload_bytes: u64,
}

struct Service {
    mesh_id: String,
    catalog_path: PathBuf,
    membership_path: PathBuf,
    freshness_path: PathBuf,
    connection_limit: Arc<Semaphore>,
}

pub fn catalog_store_path(mesh_name: &str) -> Result<PathBuf, String> {
    let mesh_name = normalize_mesh_name(mesh_name)?;
    let root = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sb-node")
        .join("catalog")
        .join(mesh_name);
    Ok(root.join("object-catalog.json"))
}

pub fn control_plane_paths(mesh_name: &str) -> Result<(PathBuf, PathBuf), String> {
    let mesh_name = normalize_mesh_name(mesh_name)?;
    let root = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sb-node")
        .join("catalog")
        .join(mesh_name);
    Ok((root.join("membership.json"), root.join("freshness.json")))
}

pub fn read_capability_token(
    path: Option<&Path>,
) -> Result<Option<sb_mesh::acl::CapabilityToken>, String> {
    path.map(|path| {
        let content = std::fs::read(path).map_err(|error| {
            format!(
                "Failed to read capability token {}: {error}",
                path.display()
            )
        })?;
        serde_json::from_slice(&content)
            .map_err(|error| format!("Invalid capability token {}: {error}", path.display()))
    })
    .transpose()
}

pub async fn start_syncd(
    mesh_name: &str,
    catalog_path: PathBuf,
    membership_path: PathBuf,
    freshness_path: PathBuf,
) -> Result<SocketAddr, String> {
    let mesh_id = normalize_mesh_name(mesh_name)?;
    let membership = sb_node_membership(&membership_path)?;
    if !membership.mesh_id.eq_ignore_ascii_case(&mesh_id) {
        return Err("Catalog membership does not match the sync service mesh".into());
    }

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .map_err(|error| format!("Failed to bind catalog sync service: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("Failed to inspect catalog sync listener: {error}"))?;
    let service = Arc::new(Service {
        mesh_id: mesh_id.clone(),
        catalog_path,
        membership_path,
        freshness_path,
        connection_limit: Arc::new(Semaphore::new(8)),
    });

    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    sb_core::logfmt::warn("ERR_CATALOG_ACCEPT", "node.catalog_sync", "Catalog sync accept failed", &[("error", &error.to_string())]);
                    continue;
                }
            };
            if !peer.ip().is_loopback() {
                let p = peer.to_string();
                sb_core::logfmt::warn("ERR_CATALOG_NON_LOOPBACK", "node.catalog_sync", "Rejected non-loopback catalog sync connection", &[("peer", &p)]);
                continue;
            }
            let permit = match service.connection_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let p = peer.to_string();
                    sb_core::logfmt::warn("ERR_CATALOG_CONN_LIMIT", "node.catalog_sync", "Rejected catalog sync connection: limit reached", &[("peer", &p)]);
                    continue;
                }
            };
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                let _permit = permit;
                match tokio::time::timeout(
                    Duration::from_secs(180),
                    handle_connection(stream, &service),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let p = peer.to_string();
                        sb_core::logfmt::warn("ERR_CATALOG_REQ", "node.catalog_sync", "Catalog sync request failed", &[("peer", &p), ("error", &error.to_string())]);
                    }
                    Err(_) => {
                        let p = peer.to_string();
                        sb_core::logfmt::warn("ERR_CATALOG_TIMEOUT", "node.catalog_sync", "Catalog sync request timed out", &[("peer", &p)]);
                    }
                }
            });
        }
    });

    println!(
        "Catalog sync service for '{}' listening on {}; cross-mesh ingress is handled by sb-node",
        mesh_id, address
    );
    Ok(address)
}

async fn handle_connection(mut stream: TcpStream, service: &Service) -> Result<(), String> {
    let request: Request = read_frame(&mut stream).await?;
    if request.version != 1 {
        return Err(format!(
            "Unsupported catalog sync protocol version: {}",
            request.version
        ));
    }

    if let Err(error) = validate_fresh_membership(service) {
        return write_rejection(&mut stream, error).await;
    }
    let store = sb_mesh::MeshObjectCatalogStore::new(&service.catalog_path);

    match request.operation {
        Operation::Inspect => {
            let digest = store.digest()?;
            write_response(
                &mut stream,
                Response {
                    version: 1,
                    accepted: true,
                    message: "Catalog digest inspected".into(),
                    digest,
                    payload_bytes: 0,
                },
            )
            .await
        }
        Operation::ReadSnapshot => {
            let catalog = match store.load() {
                Ok(catalog) => catalog,
                Err(error) if !service.catalog_path.exists() => {
                    return write_rejection(&mut stream, error).await;
                }
                Err(error) => return Err(error),
            };
            if !catalog.mesh_id.eq_ignore_ascii_case(&service.mesh_id) {
                return write_rejection(
                    &mut stream,
                    "Stored catalog belongs to a different mesh".into(),
                )
                .await;
            }
            let payload = serde_json::to_vec(&catalog)
                .map_err(|error| format!("Failed to serialize catalog snapshot: {error}"))?;
            if payload.len() as u64 > MAX_CATALOG_BYTES {
                return write_rejection(&mut stream, "Catalog exceeds the transfer limit".into())
                    .await;
            }
            if let Err(error) = validate_fresh_membership(service) {
                return write_rejection(&mut stream, error).await;
            }
            let digest = format!("{:x}", Sha256::digest(&payload));
            write_response(
                &mut stream,
                Response {
                    version: 1,
                    accepted: true,
                    message: "Catalog snapshot ready".into(),
                    digest: Some(digest),
                    payload_bytes: payload.len() as u64,
                },
            )
            .await?;
            stream
                .write_all(&payload)
                .await
                .map_err(|error| format!("Failed to send catalog snapshot: {error}"))?;
            stream
                .flush()
                .await
                .map_err(|error| format!("Failed to flush catalog snapshot: {error}"))
        }
        Operation::ApplySnapshot {
            expected_base_digest,
            payload_bytes,
        } => {
            if payload_bytes == 0 || payload_bytes > MAX_CATALOG_BYTES {
                return write_rejection(
                    &mut stream,
                    "Catalog snapshot length is invalid or exceeds the transfer limit".into(),
                )
                .await;
            }
            let expected_base_digest =
                match normalize_digest_option(expected_base_digest.as_deref()) {
                    Ok(digest) => digest,
                    Err(error) => return write_rejection(&mut stream, error).await,
                };
            let length = usize::try_from(payload_bytes)
                .map_err(|_| "Catalog snapshot does not fit in memory".to_string())?;
            let mut payload = vec![0; length];
            stream
                .read_exact(&mut payload)
                .await
                .map_err(|error| format!("Failed to receive catalog snapshot: {error}"))?;

            // CVE-Threat: Network input could replace a catalog with invalid or wrong-mesh data.
            // Analysis: The authenticated stream still carries an untrusted serialized snapshot.
            // Hardening: Enforce the byte cap, deserialize and validate the schema, bind mesh ID, then CAS.
            let catalog: sb_mesh::objects::MeshObjectCatalog = serde_json::from_slice(&payload)
                .map_err(|error| format!("Invalid catalog snapshot: {error}"))?;
            catalog
                .validate()
                .map_err(|error| format!("Catalog snapshot failed validation: {error}"))?;
            if !catalog.mesh_id.eq_ignore_ascii_case(&service.mesh_id) {
                return write_rejection(
                    &mut stream,
                    "Catalog snapshot belongs to a different mesh".into(),
                )
                .await;
            }
            if let Err(error) = validate_fresh_membership(service) {
                return write_rejection(&mut stream, error).await;
            }
            match store.compare_and_swap(expected_base_digest.as_deref(), &catalog) {
                Ok(digest) => {
                    write_response(
                        &mut stream,
                        Response {
                            version: 1,
                            accepted: true,
                            message: "Catalog snapshot applied".into(),
                            digest: Some(digest),
                            payload_bytes: 0,
                        },
                    )
                    .await
                }
                Err(error) => write_rejection(&mut stream, error).await,
            }
        }
    }
}

fn validate_fresh_membership(service: &Service) -> Result<(), String> {
    let membership = sb_node_membership(&service.membership_path)?;
    if !membership.mesh_id.eq_ignore_ascii_case(&service.mesh_id) {
        return Err("Catalog membership changed to a different mesh".into());
    }
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    sb_node_freshness(&service.freshness_path, &membership, now)
        .map_err(|error| format!("Catalog quorum freshness unavailable: {error}"))
}

fn sb_node_membership(
    path: &Path,
) -> Result<sb_node_catalog_membership::CatalogMembership, String> {
    sb_node_catalog_membership::CatalogMembershipStore::new(path).membership()
}

fn sb_node_freshness(
    path: &Path,
    membership: &sb_node_catalog_membership::CatalogMembership,
    now: u64,
) -> Result<(), String> {
    sb_node_catalog_membership::CatalogQuorumLease::load_fresh(path, membership, now).map(|_| ())
}

mod sb_node_catalog_membership {
    pub use crate::catalog_membership::{
        CatalogMembership, CatalogMembershipStore, CatalogQuorumLease,
    };
}

fn validate_digest_option(digest: Option<&str>) -> Result<(), String> {
    if digest.is_some_and(|value| {
        value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err("Catalog base digest must be a 64-character SHA-256 hex string".into());
    }
    Ok(())
}

fn normalize_digest_option(digest: Option<&str>) -> Result<Option<String>, String> {
    validate_digest_option(digest)?;
    Ok(digest.map(str::to_ascii_lowercase))
}

fn normalize_mesh_name(mesh: &str) -> Result<String, String> {
    if mesh.is_empty()
        || mesh.len() > 64
        || !mesh
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("Invalid mesh name '{mesh}'"));
    }
    Ok(mesh.to_ascii_lowercase())
}

async fn write_rejection(stream: &mut TcpStream, message: String) -> Result<(), String> {
    write_response(
        stream,
        Response {
            version: 1,
            accepted: false,
            message,
            digest: None,
            payload_bytes: 0,
        },
    )
    .await
}

async fn write_response<S>(stream: &mut S, response: Response) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &response).await
}

async fn write_frame<S, T>(stream: &mut S, value: &T) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_CONTROL_FRAME {
        return Err("Catalog sync control frame exceeds the protocol limit".into());
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| "Catalog sync control frame is too large".to_string())?;
    stream
        .write_u32(length)
        .await
        .map_err(|error| format!("Failed to write catalog sync frame length: {error}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("Failed to write catalog sync frame: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("Failed to flush catalog sync frame: {error}"))
}

async fn read_frame<S, T>(stream: &mut S) -> Result<T, String>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let length = stream
        .read_u32()
        .await
        .map_err(|error| format!("Failed to read catalog sync frame length: {error}"))?
        as usize;
    if length == 0 || length > MAX_CONTROL_FRAME {
        return Err("Catalog sync control frame length is invalid".into());
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| format!("Failed to read catalog sync frame: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("Invalid catalog sync control frame: {error}"))
}

async fn open_mesh_stream(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<sb_mesh::client::CrossMeshStream, String> {
    let source_mesh = normalize_mesh_name(source_mesh)?;
    let target_mesh = normalize_mesh_name(target_mesh)?;
    let identity = Arc::new(
        sb_mesh::identity::NodeIdentity::load_or_generate_default()
            .map_err(|error| format!("Failed to load sb-mesh identity: {error}"))?,
    );
    let client = sb_mesh::client::MeshClient::connect(sb_mesh::client::MeshClientConfig {
        mesh_name: source_mesh.clone(),
        swarm_topic: format!("sbm-swarm-{source_mesh}"),
        anchor_addr,
        identity,
        local_bind_port: None,
    })
    .await
    .map_err(|error| format!("Failed to connect to source mesh: {error}"))?;
    client
        .open_cross_mesh_stream(&target_mesh, CATALOG_SYNC_PORT, token)
        .await
        .map_err(|error| format!("Failed to open catalog replication stream: {error}"))
}

pub async fn inspect_remote(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<Option<String>, String> {
    let mut stream = open_mesh_stream(source_mesh, target_mesh, anchor_addr, token).await?;
    write_frame(
        &mut stream,
        &Request {
            version: 1,
            operation: Operation::Inspect,
        },
    )
    .await?;
    let response: Response = read_frame(&mut stream).await?;
    validate_response(&response)?;
    validate_digest_option(response.digest.as_deref())?;
    if response.payload_bytes != 0 {
        return Err("Catalog inspect response unexpectedly contains a payload".into());
    }
    Ok(response.digest)
}

pub async fn push_catalog(
    store: &sb_mesh::MeshObjectCatalogStore,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    expected_target_digest: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<String, String> {
    let expected_target_digest = normalize_digest_option(expected_target_digest)?;
    let catalog = store.load()?;
    if !catalog.mesh_id.eq_ignore_ascii_case(target_mesh) {
        return Err("Local catalog belongs to a different target mesh".into());
    }
    let payload = serde_json::to_vec(&catalog)
        .map_err(|error| format!("Failed to serialize local catalog: {error}"))?;
    if payload.is_empty() || payload.len() as u64 > MAX_CATALOG_BYTES {
        return Err("Local catalog exceeds the transfer limit".into());
    }

    let mut stream = open_mesh_stream(source_mesh, target_mesh, anchor_addr, token).await?;
    write_frame(
        &mut stream,
        &Request {
            version: 1,
            operation: Operation::ApplySnapshot {
                expected_base_digest: expected_target_digest,
                payload_bytes: payload.len() as u64,
            },
        },
    )
    .await?;
    stream
        .write_all(&payload)
        .await
        .map_err(|error| format!("Failed to send catalog snapshot: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("Failed to flush catalog snapshot: {error}"))?;
    let response: Response = read_frame(&mut stream).await?;
    validate_response(&response)?;
    if response.payload_bytes != 0 {
        return Err("Catalog apply response unexpectedly contains a payload".into());
    }
    validate_digest_option(response.digest.as_deref())?;
    response
        .digest
        .ok_or_else(|| "Catalog replication response omitted its digest".into())
}

pub async fn pull_catalog(
    store: &sb_mesh::MeshObjectCatalogStore,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    expected_local_digest: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<String, String> {
    let expected_local_digest = normalize_digest_option(expected_local_digest)?;
    let mut stream = open_mesh_stream(source_mesh, target_mesh, anchor_addr, token).await?;
    write_frame(
        &mut stream,
        &Request {
            version: 1,
            operation: Operation::ReadSnapshot,
        },
    )
    .await?;
    let response: Response = read_frame(&mut stream).await?;
    validate_response(&response)?;
    if response.payload_bytes == 0 || response.payload_bytes > MAX_CATALOG_BYTES {
        return Err("Remote catalog snapshot length is invalid".into());
    }
    validate_digest_option(response.digest.as_deref())?;
    let length = usize::try_from(response.payload_bytes)
        .map_err(|_| "Remote catalog snapshot does not fit in memory".to_string())?;
    let mut payload = vec![0; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|error| format!("Failed to receive remote catalog: {error}"))?;
    let catalog: sb_mesh::objects::MeshObjectCatalog = serde_json::from_slice(&payload)
        .map_err(|error| format!("Invalid remote catalog snapshot: {error}"))?;
    if !catalog.mesh_id.eq_ignore_ascii_case(target_mesh) {
        return Err("Remote catalog belongs to a different target mesh".into());
    }
    catalog
        .validate()
        .map_err(|error| format!("Remote catalog failed validation: {error}"))?;
    let canonical_payload = serde_json::to_vec(&catalog)
        .map_err(|error| format!("Failed to canonicalize remote catalog: {error}"))?;
    let received_digest = format!("{:x}", Sha256::digest(canonical_payload));
    if Some(received_digest.as_str()) != response.digest.as_deref() {
        return Err("Remote catalog digest did not match its snapshot payload".into());
    }
    let digest = store.compare_and_swap(expected_local_digest.as_deref(), &catalog)?;
    Ok(digest)
}

fn validate_response(response: &Response) -> Result<(), String> {
    if response.version != 1 {
        return Err(format!(
            "Unsupported catalog sync protocol version: {}",
            response.version
        ));
    }
    if !response.accepted {
        return Err(format!("Catalog sync rejected: {}", response.message));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_membership::{
        AdminAuthority, CatalogDcMember, CatalogMembership, CatalogMembershipStore,
        CatalogQuorumLease,
    };
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sb-node-catalog-sync-{}-{nonce}",
            std::process::id()
        ))
    }

    fn provision_control_plane(root: &Path) -> (PathBuf, PathBuf) {
        let dc_key = SigningKey::from_bytes(&[31; 32]);
        let admin_key = SigningKey::from_bytes(&[32; 32]);
        let membership = CatalogMembership::bootstrap(
            "engineering",
            CatalogDcMember {
                dc_id: "dc-1".into(),
                mesh_node_id: "node-1".into(),
                signing_public_key: dc_key.verifying_key().to_bytes(),
            },
            AdminAuthority {
                threshold: 1,
                signers: BTreeMap::from([("admin".into(), admin_key.verifying_key().to_bytes())]),
            },
        )
        .unwrap();
        let membership_path = root.join("membership.json");
        let freshness_path = root.join("freshness.json");
        let store = CatalogMembershipStore::new(&membership_path);
        store.initialize(membership.clone(), "dc-1").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut lease = CatalogQuorumLease::for_membership(&membership, now).unwrap();
        let approval = store.sign_quorum_lease(&lease, &dc_key).unwrap();
        lease.add_approval(&membership, approval).unwrap();
        std::fs::write(&freshness_path, serde_json::to_vec(&lease).unwrap()).unwrap();
        (membership_path, freshness_path)
    }

    #[tokio::test]
    async fn stream_applies_only_valid_snapshots_with_the_expected_base_digest() {
        let root = test_root();
        std::fs::create_dir_all(&root).unwrap();
        let (membership_path, freshness_path) = provision_control_plane(&root);
        let catalog_path = root.join("object-catalog.json");
        let address = start_syncd(
            "engineering",
            catalog_path.clone(),
            membership_path,
            freshness_path,
        )
        .await
        .unwrap();

        let mut inspect = TcpStream::connect(address).await.unwrap();
        write_frame(
            &mut inspect,
            &Request {
                version: 1,
                operation: Operation::Inspect,
            },
        )
        .await
        .unwrap();
        let inspected: Response = read_frame(&mut inspect).await.unwrap();
        assert!(inspected.accepted);
        assert_eq!(inspected.digest, None);
        drop(inspect);

        let catalog = sb_mesh::objects::MeshObjectCatalog::new("engineering").unwrap();
        let payload = serde_json::to_vec(&catalog).unwrap();
        let mut apply = TcpStream::connect(address).await.unwrap();
        write_frame(
            &mut apply,
            &Request {
                version: 1,
                operation: Operation::ApplySnapshot {
                    expected_base_digest: None,
                    payload_bytes: payload.len() as u64,
                },
            },
        )
        .await
        .unwrap();
        apply.write_all(&payload).await.unwrap();
        let applied: Response = read_frame(&mut apply).await.unwrap();
        assert!(applied.accepted);
        assert!(applied.digest.is_some());
        drop(apply);

        let mut stale_apply = TcpStream::connect(address).await.unwrap();
        write_frame(
            &mut stale_apply,
            &Request {
                version: 1,
                operation: Operation::ApplySnapshot {
                    expected_base_digest: None,
                    payload_bytes: payload.len() as u64,
                },
            },
        )
        .await
        .unwrap();
        stale_apply.write_all(&payload).await.unwrap();
        let conflict: Response = read_frame(&mut stale_apply).await.unwrap();
        assert!(!conflict.accepted);
        assert!(conflict.message.contains("Catalog conflict"));
        assert_eq!(
            sb_mesh::MeshObjectCatalogStore::new(&catalog_path)
                .load()
                .unwrap(),
            catalog
        );

        std::fs::remove_dir_all(root).unwrap();
    }
}
