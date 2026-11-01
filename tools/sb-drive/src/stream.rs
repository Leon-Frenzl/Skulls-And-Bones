use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const DRIVE_STREAM_PORT: u16 = 58833;
const DRIVE_STREAM_VERSION: u8 = 3;
const MAX_CONTROL_FRAME: usize = 16 * 1024;
const MAX_FILE_BYTES: u64 = sb_app_protocol::MAX_OBJECT_BYTES;
const IO_BUFFER_BYTES: usize = sb_app_protocol::MAX_DATA_CHUNK_BYTES;
const MAX_ACTIVE_TRANSFERS: usize = 4;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DownloadRequest {
    version: u8,
    request_id: String,
    resource_id: String,
    resource_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app_grant: Option<sb_app_contract::OperationGrant>,
}

pub const DRIVE_SERVICE_ID: &str = "org.skullsandbones.drive.api";
pub const DRIVE_API_VERSION: u16 = 1;
pub const DRIVE_READ_OPERATION: &str = "object.read";

/// Provider-side SB-MAP policy: which app manifests are known, which issuers are trusted,
/// and whether a plain member download (no app grant) is still acceptable.
// CVE-Threat: Confused deputy — an untrusted app piggybacks on the device's membership.
// Analysis: Membership/ACL authorize the device, not the app; a grant binds the app digest.
// Hardening: When `require_grant` is set, requests without a valid single-use grant are denied;
// a presented grant without a configured policy is always denied (never silently ignored).
pub struct AppGrantPolicy {
    gate: std::sync::Mutex<sb_app_contract::GrantGate>,
    manifests: std::collections::BTreeMap<String, sb_app_contract::VerifiedManifest>,
    require_grant: bool,
}

impl AppGrantPolicy {
    pub fn new(
        gate: sb_app_contract::GrantGate,
        manifests: Vec<sb_app_contract::VerifiedManifest>,
        require_grant: bool,
    ) -> Self {
        Self {
            gate: std::sync::Mutex::new(gate),
            manifests: manifests
                .into_iter()
                .map(|manifest| (manifest.manifest().app_id.clone(), manifest))
                .collect(),
            require_grant,
        }
    }

    fn check(
        &self,
        grant: Option<&sb_app_contract::OperationGrant>,
        mesh_id: &str,
        subject_node_id: &str,
        object_id: &str,
        now: u64,
    ) -> Result<(), String> {
        let Some(grant) = grant else {
            return if self.require_grant {
                Err("This provider requires an SB-MAP operation grant".into())
            } else {
                Ok(())
            };
        };
        let manifest = self
            .manifests
            .get(&grant.app_id)
            .ok_or_else(|| "Grant references an unregistered app".to_string())?;
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| "Grant gate is unavailable".to_string())?;
        gate.authorize_once(
            manifest,
            grant,
            mesh_id,
            subject_node_id,
            DRIVE_SERVICE_ID,
            DRIVE_API_VERSION,
            DRIVE_READ_OPERATION,
            object_id,
            now,
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyIssuerConfig {
    mesh_id: String,
    node_id: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAppConfig {
    manifest: PathBuf,
    signature: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    #[serde(default)]
    require_grant: bool,
    policy_epoch: u64,
    issuers: std::collections::BTreeMap<String, PolicyIssuerConfig>,
    publishers: std::collections::BTreeMap<String, String>,
    apps: Vec<PolicyAppConfig>,
}

const MAX_POLICY_FILE_BYTES: u64 = 256 * 1024;

fn decode_hex_key(label: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be 64 hex characters"));
    }
    let mut key = [0u8; 32];
    for (index, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("{label} is invalid: {error}"))?;
    }
    Ok(key)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path)
        .map_err(|error| format!("Cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_POLICY_FILE_BYTES {
        return Err(format!("{} exceeds the policy size limit", path.display()));
    }
    Ok(bytes)
}

impl AppGrantPolicy {
    // CVE-Threat: Policy-file tampering / path traversal via manifest references.
    // Analysis: The policy file is local operator configuration, but its referenced manifests are
    // still data; an unsigned or foreign-signed manifest must never become an accepted app.
    // Hardening: bounded reads, deny_unknown_fields, referenced paths must stay relative to the
    // policy directory (no absolute/`..`), every manifest is signature-verified against the
    // listed publisher keys, and an empty app/issuer set is rejected (fail closed).
    pub fn from_config_file(path: &Path) -> Result<Self, String> {
        let config: PolicyConfig = serde_json::from_slice(&read_bounded(path)?)
            .map_err(|error| format!("Invalid grant policy: {error}"))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.issuers.is_empty() || config.apps.is_empty() {
            return Err("Grant policy needs at least one issuer and one app".into());
        }
        let mut publishers = std::collections::BTreeMap::new();
        for (key_id, hex_key) in &config.publishers {
            publishers.insert(key_id.clone(), decode_hex_key("Publisher key", hex_key)?);
        }
        let mut issuers = std::collections::BTreeMap::new();
        for (key_id, issuer) in config.issuers {
            issuers.insert(
                key_id,
                sb_app_contract::TrustedIssuer {
                    mesh_id: issuer.mesh_id,
                    node_id: issuer.node_id,
                    public_key: decode_hex_key("Issuer key", &issuer.public_key)?,
                },
            );
        }
        let mut manifests = Vec::new();
        for app in config.apps {
            for reference in [&app.manifest, &app.signature] {
                if !is_safe_relative_path(reference) {
                    return Err("Policy references an unsafe path".into());
                }
            }
            let manifest = read_bounded(&base.join(&app.manifest))?;
            let signature = String::from_utf8(read_bounded(&base.join(&app.signature))?)
                .map_err(|_| "Manifest signature is not text".to_string())?;
            manifests.push(
                sb_app_contract::verify_signed_manifest(&manifest, signature.trim(), &publishers)
                    .map_err(|error| format!("Policy manifest rejected: {error}"))?,
            );
        }
        Ok(Self::new(
            sb_app_contract::GrantGate::new(issuers, config.policy_epoch),
            manifests,
            config.require_grant,
        ))
    }
}

fn check_app_grant(
    policy: Option<&AppGrantPolicy>,
    grant: Option<&sb_app_contract::OperationGrant>,
    mesh_id: &str,
    subject_node_id: &str,
    object_id: &str,
    now: u64,
) -> Result<(), String> {
    match (policy, grant) {
        (Some(policy), grant) => policy.check(grant, mesh_id, subject_node_id, object_id, now),
        (None, Some(_)) => Err("This provider does not accept SB-MAP operation grants".into()),
        (None, None) => Ok(()),
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DownloadResponse {
    version: u8,
    accepted: bool,
    message: String,
    offer: Option<sb_app_protocol::TransferOffer>,
}

pub fn default_catalog_path(mesh_name: &str) -> Result<PathBuf, String> {
    let mesh_name = sb_mesh::state::normalize_mesh_name(mesh_name)?;
    let home = dirs::home_dir().ok_or_else(|| "Cannot resolve the home directory".to_string())?;
    Ok(home
        .join(".sb-node")
        .join("catalog")
        .join(mesh_name)
        .join("object-catalog.json"))
}

pub async fn serve(
    root: PathBuf,
    bind: std::net::SocketAddr,
    mesh_name: String,
    catalog_path: PathBuf,
) -> Result<(), String> {
    serve_with_policy(root, bind, mesh_name, catalog_path, None).await
}

pub async fn serve_with_policy(
    root: PathBuf,
    bind: std::net::SocketAddr,
    mesh_name: String,
    catalog_path: PathBuf,
    policy: Option<std::sync::Arc<AppGrantPolicy>>,
) -> Result<(), String> {
    if !bind.ip().is_loopback() {
        return Err(
            "sb-drive stream service must bind to loopback; expose it through sb-node".into(),
        );
    }
    let root = fs::canonicalize(&root)
        .await
        .map_err(|error| format!("Cannot open sb-drive root {}: {error}", root.display()))?;
    if !root.is_dir() {
        return Err(format!(
            "sb-drive root {} is not a directory",
            root.display()
        ));
    }
    let mesh_name = sb_mesh::state::normalize_mesh_name(&mesh_name)?;
    let rbac_path = sb_mesh::rbac::MeshRbacStore::storage_path(&mesh_name)?;
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("Cannot bind sb-drive stream service at {bind}: {error}"))?;
    println!(
        "sb-drive stream service listening on {}; root {}",
        listener.local_addr().map_err(|error| error.to_string())?,
        root.display()
    );
    serve_listener(
        listener,
        root,
        mesh_name.to_string(),
        catalog_path,
        rbac_path,
        policy,
    )
    .await
}

async fn serve_listener(
    listener: TcpListener,
    root: PathBuf,
    mesh_name: String,
    catalog_path: PathBuf,
    rbac_path: PathBuf,
    policy: Option<std::sync::Arc<AppGrantPolicy>>,
) -> Result<(), String> {
    let connection_limit = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_TRANSFERS));
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("sb-drive stream accept failed: {error}"))?;
        let root = root.clone();
        let mesh_name = mesh_name.clone();
        let catalog_path = catalog_path.clone();
        let rbac_path = rbac_path.clone();
        let policy = policy.clone();
        let permit = match connection_limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!("Rejected sb-drive connection from {peer}: transfer limit reached");
                continue;
            }
        };
        tokio::spawn(async move {
            let _permit = permit;
            if !peer.ip().is_loopback() {
                eprintln!("Rejected non-loopback sb-drive connection from {peer}");
                return;
            }
            if let Err(error) = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                serve_download(
                    stream,
                    &root,
                    &mesh_name,
                    &catalog_path,
                    &rbac_path,
                    policy.as_deref(),
                ),
            )
            .await
            .map_err(|_| "sb-drive transfer timed out".to_string())
            .and_then(|result| result)
            {
                eprintln!("sb-drive transfer from {peer} failed: {error}");
            }
        });
    }
}

// CVE-Threat: Path traversal, symlink escape, oversized payload, or partial cache publication.
// Analysis: Both the peer path and streamed bytes are untrusted at this boundary.
// Hardening: Jail paths, reject symlinks, cap bytes, hash the stream, then publish a synced temp file.
pub async fn download<S>(
    stream: &mut S,
    resource_id: &str,
    resource_version: &str,
    destination: &Path,
) -> Result<PathBuf, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    download_with_grant(stream, resource_id, resource_version, destination, None).await
}

pub async fn download_with_grant<S>(
    stream: &mut S,
    resource_id: &str,
    resource_version: &str,
    destination: &Path,
    app_grant: Option<sb_app_contract::OperationGrant>,
) -> Result<PathBuf, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_id = format!(
        "drive-{}-{}",
        std::process::id(),
        NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
    );
    write_frame(
        stream,
        &DownloadRequest {
            version: DRIVE_STREAM_VERSION,
            request_id: request_id.clone(),
            resource_id: resource_id.to_string(),
            resource_version: resource_version.to_string(),
            app_grant,
        },
    )
    .await?;
    let response: DownloadResponse = read_frame(stream).await?;
    if response.version != DRIVE_STREAM_VERSION {
        return Err(format!(
            "Unsupported sb-drive stream protocol version: {}",
            response.version
        ));
    }
    if !response.accepted {
        return Err(format!(
            "Remote sb-drive rejected download: {}",
            response.message
        ));
    }
    let offer = response
        .offer
        .ok_or_else(|| "Remote sb-drive response omitted its transfer offer".to_string())?;
    offer
        .validate()
        .map_err(|error| format!("Remote sb-drive transfer offer is invalid: {error}"))?;
    if offer.request_id != request_id {
        return Err("Remote sb-drive transfer offer does not match this request".into());
    }
    if offer.resource_id != resource_id || offer.resource_version != resource_version {
        return Err(
            "Remote sb-drive transfer offer does not match the requested object version".into(),
        );
    }
    if offer.total_bytes > MAX_FILE_BYTES {
        return Err("Remote file exceeds the sb-drive transfer limit".into());
    }
    let mut verifier = sb_app_protocol::TransferVerifier::new(offer.clone())
        .map_err(|error| format!("Remote sb-drive transfer offer was rejected: {error}"))?;

    let parent = destination
        .parent()
        .ok_or_else(|| "Cache destination must have a parent directory".to_string())?;
    fs::create_dir_all(parent).await.map_err(|error| {
        format!(
            "Cannot create cache directory {}: {error}",
            parent.display()
        )
    })?;
    let temp_path = temporary_path(destination);
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
        .map_err(|error| {
            format!(
                "Cannot create temporary cache file {}: {error}",
                temp_path.display()
            )
        })?;

    let transfer = async {
        let mut received_bytes = 0u64;
        while received_bytes < offer.total_bytes {
            let (header, payload) = sb_app_protocol::read_chunk(stream)
                .await
                .map_err(|error| format!("Invalid sb-drive data chunk: {error}"))?;
            verifier
                .accept_chunk(&header, &payload)
                .map_err(|error| format!("sb-drive transfer validation failed: {error}"))?;
            temp.write_all(&payload)
                .await
                .map_err(|error| format!("Cannot write cache file: {error}"))?;
            received_bytes += payload.len() as u64;
        }
        verifier
            .finish()
            .map_err(|error| format!("sb-drive transfer validation failed: {error}"))?;
        temp.flush()
            .await
            .map_err(|error| format!("Cannot flush cache file: {error}"))?;
        temp.sync_all()
            .await
            .map_err(|error| format!("Cannot sync cache file: {error}"))?;
        Ok::<(), String>(())
    }
    .await;
    drop(temp);
    if let Err(error) = transfer {
        return match fs::remove_file(&temp_path).await {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; temporary cache file {} could not be removed: {cleanup_error}",
                temp_path.display()
            )),
        };
    }
    if let Err(error) = publish_cache_file(&temp_path, destination).await {
        return match fs::remove_file(&temp_path).await {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; temporary cache file {} could not be removed: {cleanup_error}",
                temp_path.display()
            )),
        };
    }
    Ok(destination.to_path_buf())
}

#[cfg(not(windows))]
async fn publish_cache_file(temp_path: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(temp_path, destination).await.map_err(|error| {
        format!(
            "Cannot publish cache file {}: {error}",
            destination.display()
        )
    })
}

#[cfg(windows)]
async fn publish_cache_file(temp_path: &Path, destination: &Path) -> Result<(), String> {
    let exists = fs::try_exists(destination).await.map_err(|error| {
        format!(
            "Cannot inspect cache destination {}: {error}",
            destination.display()
        )
    })?;
    if !exists {
        return fs::rename(temp_path, destination).await.map_err(|error| {
            format!(
                "Cannot publish cache file {}: {error}",
                destination.display()
            )
        });
    }

    let backup_path = temporary_path(destination);
    fs::rename(destination, &backup_path)
        .await
        .map_err(|error| {
            format!(
                "Cannot preserve existing cache file {}: {error}",
                destination.display()
            )
        })?;
    if let Err(publish_error) = fs::rename(temp_path, destination).await {
        if let Err(restore_error) = fs::rename(&backup_path, destination).await {
            return Err(format!(
                "Cannot publish cache file {} ({publish_error}); restoring the prior cache also failed ({restore_error}); prior file remains at {}",
                destination.display(),
                backup_path.display()
            ));
        }
        return Err(format!(
            "Cannot publish cache file {}: {publish_error}; previous cache was restored",
            destination.display()
        ));
    }
    fs::remove_file(&backup_path).await.map_err(|error| {
        format!(
            "Cache published, but old cache backup {} could not be removed: {error}",
            backup_path.display()
        )
    })
}

pub async fn download_from_mesh(
    client: &sb_mesh::client::MeshClient,
    target_mesh: &str,
    resource_id: &str,
    resource_version: &str,
    destination: &Path,
    token: Option<sb_mesh::acl::CapabilityToken>,
    app_grant: Option<sb_app_contract::OperationGrant>,
) -> Result<PathBuf, String> {
    let mut stream = client
        .open_cross_mesh_stream(target_mesh, DRIVE_STREAM_PORT, token)
        .await
        .map_err(|error| format!("Cannot open sb-drive mesh stream: {error}"))?;
    download_with_grant(
        &mut stream,
        resource_id,
        resource_version,
        destination,
        app_grant,
    )
    .await
}

async fn serve_download(
    mut stream: TcpStream,
    root: &Path,
    mesh_name: &str,
    catalog_path: &Path,
    rbac_path: &Path,
    policy: Option<&AppGrantPolicy>,
) -> Result<(), String> {
    let identity: sb_mesh::bridge::MeshStreamIdentity = read_frame(&mut stream).await?;
    if sb_mesh::identity::NodeIdentity::derive_node_id_from_pubkey(&identity.source_public_key)
        != identity.source_node_id
    {
        return write_response(
            &mut stream,
            false,
            "Authenticated stream identity is invalid",
            None,
        )
        .await;
    }
    let request: DownloadRequest = read_frame(&mut stream).await?;
    if request.version != DRIVE_STREAM_VERSION {
        return write_response(&mut stream, false, "Unsupported protocol version", None).await;
    }
    let (object_id, version, locator) = match authorize_payload(
        mesh_name,
        catalog_path,
        rbac_path,
        &identity,
        &request.resource_id,
        &request.resource_version,
    ) {
        Ok(authorized) => authorized,
        Err(error) => return write_response(&mut stream, false, &error, None).await,
    };
    if let Err(error) = check_app_grant(
        policy,
        request.app_grant.as_ref(),
        mesh_name,
        &identity.source_node_id,
        object_id.as_str(),
        chrono::Utc::now().timestamp().max(0) as u64,
    ) {
        return write_response(&mut stream, false, &error, None).await;
    }
    let relative_path = Path::new(&locator);
    if !is_safe_relative_path(relative_path) {
        return write_response(
            &mut stream,
            false,
            "Catalog payload locator is invalid",
            None,
        )
        .await;
    }
    let file_path = match resolve_jailed_file(root, relative_path).await {
        Ok(path) => path,
        Err(error) => return write_response(&mut stream, false, &error, None).await,
    };
    let metadata = match fs::metadata(&file_path).await {
        Ok(metadata) => metadata,
        Err(error) => {
            return write_response(
                &mut stream,
                false,
                &format!("Cannot inspect requested file: {error}"),
                None,
            )
            .await
        }
    };
    if !metadata.is_file() {
        return write_response(
            &mut stream,
            false,
            "Requested path is not a regular file",
            None,
        )
        .await;
    }
    if metadata.len() > MAX_FILE_BYTES || metadata.len() != version.size_bytes {
        return write_response(
            &mut stream,
            false,
            "File size does not match the authorized object version or exceeds the transfer quota",
            None,
        )
        .await;
    }
    let offer = sb_app_protocol::TransferOffer {
        version: sb_app_protocol::PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        transfer_id: format!("{}-transfer", request.request_id),
        resource_id: object_id.to_string(),
        resource_version: version.id.to_string(),
        total_bytes: metadata.len(),
        sha256: format!("sha256:{}", encode_lower_hex(&version.content_hash)),
        max_chunk_bytes: IO_BUFFER_BYTES as u32,
    };
    offer
        .validate()
        .map_err(|error| format!("Cannot create sb-drive transfer offer: {error}"))?;
    write_response(&mut stream, true, "Download accepted", Some(offer.clone())).await?;

    let mut file = File::open(&file_path)
        .await
        .map_err(|error| format!("Cannot read requested file: {error}"))?;
    let mut remaining = metadata.len();
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; IO_BUFFER_BYTES];
    let mut sequence = 0u32;
    let mut offset = 0u64;
    while remaining > 0 {
        let read_len = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "Invalid sb-drive transfer chunk length".to_string())?;
        let count = file
            .read(&mut buffer[..read_len])
            .await
            .map_err(|error| format!("Cannot stream requested file: {error}"))?;
        if count == 0 {
            return Err("Requested file changed size during transfer".into());
        }
        sb_app_protocol::write_chunk(
            &mut stream,
            &offer.transfer_id,
            sequence,
            offset,
            &buffer[..count],
        )
        .await
        .map_err(|error| format!("Cannot send requested file chunk: {error}"))?;
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
        offset += count as u64;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "sb-drive transfer chunk sequence overflow".to_string())?;
    }
    let actual_hash: [u8; 32] = hasher.finalize().into();
    if actual_hash != version.content_hash {
        return Err("Payload content does not match the authorized object version".into());
    }
    stream
        .flush()
        .await
        .map_err(|error| format!("Cannot flush sb-drive stream: {error}"))?;
    Ok(())
}

fn authorize_payload(
    mesh_name: &str,
    catalog_path: &Path,
    rbac_path: &Path,
    identity: &sb_mesh::bridge::MeshStreamIdentity,
    resource_id: &str,
    resource_version: &str,
) -> Result<
    (
        sb_mesh::objects::MeshObjectId,
        sb_mesh::objects::ObjectVersion,
        String,
    ),
    String,
> {
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&identity.source_public_key)
        .map_err(|error| format!("Invalid authenticated peer key: {error}"))?;
    if public_key_bytes.len() != 32 {
        return Err("Authenticated peer key must contain exactly 32 bytes".into());
    }

    let rbac = sb_mesh::rbac::MeshRbacStore::load_existing_at(rbac_path, mesh_name)?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if !rbac.has_active_member_for_key(mesh_name, &identity.source_public_key, now)? {
        return Err("Peer is not an active member of the resource mesh".into());
    }

    let matches: Vec<_> = rbac
        .members
        .iter()
        .filter(|member| member.pubkey.trim() == identity.source_public_key)
        .collect();
    let [member] = matches.as_slice() else {
        return Err("Peer membership is missing or ambiguous".into());
    };
    if member.node_id != identity.source_node_id {
        return Err("Peer membership does not match the authenticated node identity".into());
    }

    let catalog_metadata = std::fs::symlink_metadata(catalog_path)
        .map_err(|error| format!("Object catalog could not be inspected: {error}"))?;
    if catalog_metadata.file_type().is_symlink() || !catalog_metadata.is_file() {
        return Err("Object catalog must be a regular, non-symlink file".into());
    }
    let catalog = sb_mesh::MeshObjectCatalogStore::new(catalog_path).load()?;
    if !catalog.mesh_id.eq_ignore_ascii_case(mesh_name) {
        return Err("Object catalog belongs to a different mesh".into());
    }

    let object_id = sb_mesh::objects::MeshObjectId::new(resource_id.to_string())?;
    let version_id = sb_mesh::objects::ObjectVersionId::new(resource_version.to_string())?;
    let object = catalog
        .objects
        .get(&object_id)
        .ok_or_else(|| "Requested object does not exist".to_string())?;
    if object.current_version.as_ref() != Some(&version_id) {
        return Err("Requested object version is not current".into());
    }
    let version = object
        .versions
        .iter()
        .find(|version| version.id == version_id)
        .ok_or_else(|| "Requested object version does not exist".to_string())?;
    if version.payload.provider != "sb-drive" {
        return Err("Requested object version is not served by sb-drive".into());
    }
    let read_permission = BTreeSet::from([sb_mesh::objects::ObjectPermission::Read]);
    if !catalog.check_access_for_authenticated_device_key(
        &object.id,
        &identity.source_public_key,
        &read_permission,
    )? {
        return Err("Object ACL denied read access".into());
    }
    Ok((
        object.id.clone(),
        version.clone(),
        version.payload.locator.clone(),
    ))
}

async fn resolve_jailed_file(root: &Path, relative_path: &Path) -> Result<PathBuf, String> {
    let mut current = root.to_path_buf();
    for component in relative_path.components() {
        let Component::Normal(segment) = component else {
            return Err("Remote file path contains an invalid component".into());
        };
        current.push(segment);
        let metadata = fs::symlink_metadata(&current)
            .await
            .map_err(|error| format!("Cannot access requested path: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("Remote file path must not traverse symbolic links".into());
        }
    }
    let canonical = fs::canonicalize(&current)
        .await
        .map_err(|error| format!("Cannot resolve requested file: {error}"))?;
    if !canonical.starts_with(root) {
        return Err("Remote file path escapes the configured sb-drive root".into());
    }
    Ok(canonical)
}

fn is_safe_relative_path(path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(is_safe_path_component)
}

fn is_safe_path_component(component: &str) -> bool {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.ends_with(['.', ' '])
        || component
            .chars()
            .any(|character| character.is_control() || "<>:\"|?*".contains(character))
    {
        return false;
    }
    let device_name = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(
        device_name.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn temporary_path(destination: &Path) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("drive-cache");
    destination.with_file_name(format!("{name}.part-{}-{nonce}", std::process::id()))
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

async fn write_response(
    stream: &mut TcpStream,
    accepted: bool,
    message: &str,
    offer: Option<sb_app_protocol::TransferOffer>,
) -> Result<(), String> {
    write_frame(
        stream,
        &DownloadResponse {
            version: DRIVE_STREAM_VERSION,
            accepted,
            message: message.to_string(),
            offer,
        },
    )
    .await
}

async fn write_frame<S, T>(stream: &mut S, value: &T) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    sb_app_protocol::write_control_with_limit(stream, value, MAX_CONTROL_FRAME)
        .await
        .map_err(|error| format!("Cannot write sb-drive control frame: {error}"))
}

async fn read_frame<S, T>(stream: &mut S) -> Result<T, String>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    sb_app_protocol::read_control_with_limit(stream, MAX_CONTROL_FRAME)
        .await
        .map_err(|error| format!("Cannot read sb-drive control frame: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_mesh::objects::{
        AclEffect, MeshObject, MeshObjectCatalog, MeshObjectId, MeshObjectKind, ObjectPermission,
        ObjectVersion, ObjectVersionId, PayloadReference, PrincipalId,
    };
    use sb_mesh::rbac::{MeshMember, MeshRbacStore, MeshRole};

    #[test]
    fn app_grant_policy_is_fail_closed_and_single_use() {
        use ed25519_dalek::SigningKey;
        use sb_app_contract::*;
        use std::collections::BTreeMap;

        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let manifest = AppManifest {
            schema_version: 1,
            app_id: "org.skullsandbones.viewer".into(),
            version: "0.1.0".into(),
            publisher_key_id: "org.skullsandbones.publisher".into(),
            client: ClientArtifact {
                target: "windows-x86_64".into(),
                artifact: format!("sha256:{}", "a".repeat(64)),
            },
            services: vec![ServiceDeclaration {
                service_id: DRIVE_SERVICE_ID.into(),
                api_version: DRIVE_API_VERSION,
                contract_digest: format!("sha256:{}", "b".repeat(64)),
            }],
            requested_capabilities: vec![CapabilityRequest {
                service_id: DRIVE_SERVICE_ID.into(),
                operation: DRIVE_READ_OPERATION.into(),
            }],
            sandbox_profile: "native-client-default".into(),
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let mut message = b"SB-MAP-MANIFEST-V1\0".to_vec();
        message.extend_from_slice(&bytes);
        let signature: String = ed25519_dalek::Signer::sign(&publisher, &message)
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let verified = verify_signed_manifest(
            &bytes,
            &signature,
            &BTreeMap::from([(
                "org.skullsandbones.publisher".to_string(),
                publisher.verifying_key().to_bytes(),
            )]),
        )
        .unwrap();
        let issuer = SigningKey::from_bytes(&[11u8; 32]);
        let trusted = BTreeMap::from([(
            "org.skullsandbones.authority".to_string(),
            TrustedIssuer {
                mesh_id: "drive-mesh".into(),
                node_id: "node-issuer".into(),
                public_key: issuer.verifying_key().to_bytes(),
            },
        )]);
        let claims = |id: &str, object: &str| GrantClaims {
            grant_id: id.into(),
            mesh_id: "drive-mesh".into(),
            issuer_node_id: "node-issuer".into(),
            issuer_key_id: "org.skullsandbones.authority".into(),
            subject_node_id: "node-client".into(),
            app_id: "org.skullsandbones.viewer".into(),
            client_digest: format!("sha256:{}", "a".repeat(64)),
            service_id: DRIVE_SERVICE_ID.into(),
            api_version: DRIVE_API_VERSION,
            operation: DRIVE_READ_OPERATION.into(),
            resource_id: object.into(),
            policy_epoch: 3,
            valid_until: 1_000,
        };
        let policy = AppGrantPolicy::new(GrantGate::new(trusted.clone(), 3), vec![verified], true);
        let grant = OperationGrant::issue(claims("g-1", "object:file"), &issuer).unwrap();

        assert!(check_app_grant(
            Some(&policy),
            Some(&grant),
            "drive-mesh",
            "node-client",
            "object:file",
            100
        )
        .is_ok());
        // replay
        assert!(check_app_grant(
            Some(&policy),
            Some(&grant),
            "drive-mesh",
            "node-client",
            "object:file",
            100
        )
        .is_err());
        // wrong resource, wrong subject
        let other = OperationGrant::issue(claims("g-2", "object:other"), &issuer).unwrap();
        assert!(check_app_grant(
            Some(&policy),
            Some(&other),
            "drive-mesh",
            "node-client",
            "object:file",
            100
        )
        .is_err());
        let third = OperationGrant::issue(claims("g-3", "object:file"), &issuer).unwrap();
        assert!(check_app_grant(
            Some(&policy),
            Some(&third),
            "drive-mesh",
            "node-evil",
            "object:file",
            100
        )
        .is_err());
        // grant required, none provided
        assert!(check_app_grant(
            Some(&policy),
            None,
            "drive-mesh",
            "node-client",
            "object:file",
            100
        )
        .is_err());
        // no policy: grant rejected, plain request still fine
        assert!(check_app_grant(
            None,
            Some(&grant),
            "drive-mesh",
            "node-client",
            "object:file",
            100
        )
        .is_err());
        assert!(
            check_app_grant(None, None, "drive-mesh", "node-client", "object:file", 100).is_ok()
        );
    }

    #[test]
    fn relative_path_guard_rejects_absolute_and_parent_paths() {
        assert!(is_safe_relative_path(Path::new("docs/readme.md")));
        assert!(!is_safe_relative_path(Path::new("../secrets.txt")));
        assert!(!is_safe_relative_path(Path::new("/etc/passwd")));
        assert!(!is_safe_relative_path(Path::new(r"docs\..\secrets.txt")));
        assert!(!is_safe_relative_path(Path::new("file.txt:secret")));
        assert!(!is_safe_relative_path(Path::new("NUL.txt")));
        assert!(!is_safe_relative_path(Path::new("trailing-dot.")));
    }

    #[tokio::test]
    async fn stream_download_rejects_paths_outside_the_peer_jail() {
        let root = std::env::temp_dir().join(format!(
            "sb_drive_jail_{}_{}",
            std::process::id(),
            temporary_nonce()
        ));
        fs::create_dir_all(&root).await.unwrap();
        let file = root.join("inside.txt");
        fs::write(&file, b"inside").await.unwrap();
        let root = fs::canonicalize(root).await.unwrap();
        assert!(resolve_jailed_file(&root, Path::new("inside.txt"))
            .await
            .is_ok());
        assert!(resolve_jailed_file(&root, Path::new("../outside.txt"))
            .await
            .is_err());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn live_mesh_stream_downloads_peer_file_into_verified_cache() {
        use sb_mesh::bridge::{CrossMeshBridge, CrossMeshRule, ServiceEndpoint};
        use sb_mesh::client::MeshClient;
        use sb_mesh::identity::NodeIdentity;
        use std::sync::Arc;

        let nonce = temporary_nonce();
        let peer_root =
            std::env::temp_dir().join(format!("sb_drive_peer_a_{}_{}", std::process::id(), nonce));
        let cache_root =
            std::env::temp_dir().join(format!("sb_drive_peer_b_{}_{}", std::process::id(), nonce));
        fs::create_dir_all(peer_root.join("project")).await.unwrap();
        fs::create_dir_all(&cache_root).await.unwrap();
        let payload = vec![0x5a; IO_BUFFER_BYTES * 2 + 137];
        fs::write(peer_root.join("project").join("artifact.bin"), &payload)
            .await
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service_addr = listener.local_addr().unwrap();
        let root = fs::canonicalize(&peer_root).await.unwrap();
        let identity = Arc::new(NodeIdentity::generate());
        let fixture_dir = cache_root.join("authorization");
        fs::create_dir_all(&fixture_dir).await.unwrap();
        let catalog_path = fixture_dir.join("object-catalog.json");
        let rbac_path = fixture_dir.join("mesh-rbac.json");
        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/artifact.bin",
            &payload,
            true,
            false,
        );
        let peer_task = tokio::spawn(serve_listener(
            listener,
            root,
            "drive-mesh".to_string(),
            catalog_path,
            rbac_path,
            None,
        ));

        let bridge = Arc::new(CrossMeshBridge::new("anchor-drive"));
        bridge
            .register_service(
                "drive-mesh",
                DRIVE_STREAM_PORT,
                ServiceEndpoint::LocalTcpWithIdentity(service_addr),
            )
            .await;
        let mut policy = sb_mesh::bridge::CrossMeshPolicy::new();
        policy.add_rule(CrossMeshRule::new(
            "project-drive-read",
            "project-mesh",
            "drive-mesh",
            vec![DRIVE_STREAM_PORT],
            false,
            "Peer filesystem read stream smoke test",
        ));
        *bridge.policy.write().await = policy;
        let client = MeshClient::with_bridge("project-mesh", identity, bridge);
        let destination = cache_root.join("artifact.bin");
        fs::write(&destination, b"stale cache").await.unwrap();
        let mut mesh_stream = client
            .open_cross_mesh_stream("drive-mesh", DRIVE_STREAM_PORT, None)
            .await
            .expect("open peer-to-peer mesh stream");
        let cached = download(&mut mesh_stream, "object:file", "version:1", &destination)
            .await
            .expect("stream peer file into cache");

        assert_eq!(cached, destination);
        assert_eq!(fs::read(&cached).await.unwrap(), payload);
        drop(mesh_stream);

        let rejected_destination = cache_root.join("stale-cache.bin");
        fs::write(&rejected_destination, b"preserve existing cache")
            .await
            .unwrap();
        fs::write(
            peer_root.join("project").join("artifact.bin"),
            b"wrong size",
        )
        .await
        .unwrap();
        let mut mismatch_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.open_cross_mesh_stream("drive-mesh", DRIVE_STREAM_PORT, None),
        )
        .await
        .expect("open mesh stream for catalog size check before timeout")
        .expect("open mesh stream for catalog size check");
        let mismatch = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            download(
                &mut mismatch_stream,
                "object:file",
                "version:1",
                &rejected_destination,
            ),
        )
        .await
        .expect("catalog size rejection before timeout")
        .unwrap_err();
        assert!(mismatch.contains("size"));
        drop(mismatch_stream);
        assert_eq!(
            fs::read(&rejected_destination).await.unwrap(),
            b"preserve existing cache"
        );

        fs::write(&peer_root.join("project").join("artifact.bin"), &payload)
            .await
            .unwrap();
        let mut hash_mismatch_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.open_cross_mesh_stream("drive-mesh", DRIVE_STREAM_PORT, None),
        )
        .await
        .expect("open mesh stream for catalog hash check before timeout")
        .expect("open mesh stream for catalog hash check");
        fs::write(
            peer_root.join("project").join("artifact.bin"),
            vec![0x6b; payload.len()],
        )
        .await
        .unwrap();
        let mismatch = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            download(
                &mut hash_mismatch_stream,
                "object:file",
                "version:1",
                &rejected_destination,
            ),
        )
        .await
        .expect("catalog hash rejection before timeout")
        .unwrap_err();
        assert!(mismatch.contains("digest"));
        drop(hash_mismatch_stream);
        assert_eq!(
            fs::read(&rejected_destination).await.unwrap(),
            b"preserve existing cache"
        );

        fs::write(peer_root.join("project").join("artifact.bin"), &payload)
            .await
            .unwrap();
        let mut jail_probe = client
            .open_cross_mesh_stream("drive-mesh", DRIVE_STREAM_PORT, None)
            .await
            .expect("open mesh stream for jail probe");
        write_frame(
            &mut jail_probe,
            &DownloadRequest {
                version: DRIVE_STREAM_VERSION,
                request_id: "probe-1".into(),
                resource_id: "missing-object".into(),
                resource_version: "version:1".into(),
                app_grant: None,
            },
        )
        .await
        .unwrap();
        let response: DownloadResponse = read_frame(&mut jail_probe).await.unwrap();
        assert!(!response.accepted);
        assert!(response.message.contains("does not exist"));

        peer_task.abort();
        let _ = peer_task.await;
        fs::remove_dir_all(peer_root).await.unwrap();
        fs::remove_dir_all(cache_root).await.unwrap();
    }

    #[tokio::test]
    async fn live_mesh_stream_enforces_app_grants_from_policy_file() {
        use ed25519_dalek::SigningKey;
        use sb_app_contract::*;
        use sb_mesh::bridge::{CrossMeshBridge, CrossMeshRule, ServiceEndpoint};
        use sb_mesh::client::MeshClient;
        use sb_mesh::identity::NodeIdentity;
        use std::sync::Arc;

        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        let nonce = temporary_nonce();
        let base =
            std::env::temp_dir().join(format!("sb_drive_grant_{}_{}", std::process::id(), nonce));
        let peer_root = base.join("peer");
        fs::create_dir_all(peer_root.join("project")).await.unwrap();
        let payload = vec![0x42; 4096 + 11];
        fs::write(peer_root.join("project").join("artifact.bin"), &payload)
            .await
            .unwrap();

        let identity = Arc::new(NodeIdentity::generate());
        let fixture_dir = base.join("authorization");
        fs::create_dir_all(&fixture_dir).await.unwrap();
        let catalog_path = fixture_dir.join("object-catalog.json");
        let rbac_path = fixture_dir.join("mesh-rbac.json");
        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/artifact.bin",
            &payload,
            true,
            false,
        );

        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let issuer = SigningKey::from_bytes(&[11u8; 32]);
        let manifest = AppManifest {
            schema_version: 1,
            app_id: "org.skullsandbones.viewer".into(),
            version: "0.1.0".into(),
            publisher_key_id: "org.skullsandbones.publisher".into(),
            client: ClientArtifact {
                target: "windows-x86_64".into(),
                artifact: format!("sha256:{}", "a".repeat(64)),
            },
            services: vec![ServiceDeclaration {
                service_id: DRIVE_SERVICE_ID.into(),
                api_version: DRIVE_API_VERSION,
                contract_digest: format!("sha256:{}", "b".repeat(64)),
            }],
            requested_capabilities: vec![CapabilityRequest {
                service_id: DRIVE_SERVICE_ID.into(),
                operation: DRIVE_READ_OPERATION.into(),
            }],
            sandbox_profile: "native-client-default".into(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let mut message = b"SB-MAP-MANIFEST-V1\0".to_vec();
        message.extend_from_slice(&manifest_bytes);
        let signature = hex(&ed25519_dalek::Signer::sign(&publisher, &message).to_bytes());
        std::fs::write(base.join("app.json"), &manifest_bytes).unwrap();
        std::fs::write(base.join("app.sig"), &signature).unwrap();
        let policy_path = base.join("policy.json");
        let write_policy = |relative: &str| {
            std::fs::write(
                &policy_path,
                serde_json::json!({
                    "require_grant": true,
                    "policy_epoch": 3,
                    "issuers": {"org.skullsandbones.authority": {
                        "mesh_id": "drive-mesh",
                        "node_id": "node-issuer",
                        "public_key": hex(&issuer.verifying_key().to_bytes())
                    }},
                    "publishers": {"org.skullsandbones.publisher":
                        hex(&publisher.verifying_key().to_bytes())},
                    "apps": [{"manifest": relative, "signature": "app.sig"}]
                })
                .to_string(),
            )
            .unwrap();
        };
        write_policy("../escape.json");
        assert!(AppGrantPolicy::from_config_file(&policy_path).is_err());
        write_policy("app.json");
        let policy = Arc::new(AppGrantPolicy::from_config_file(&policy_path).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service_addr = listener.local_addr().unwrap();
        let root = fs::canonicalize(&peer_root).await.unwrap();
        let peer_task = tokio::spawn(serve_listener(
            listener,
            root,
            "drive-mesh".to_string(),
            catalog_path,
            rbac_path,
            Some(policy),
        ));
        let bridge = Arc::new(CrossMeshBridge::new("anchor-drive"));
        bridge
            .register_service(
                "drive-mesh",
                DRIVE_STREAM_PORT,
                ServiceEndpoint::LocalTcpWithIdentity(service_addr),
            )
            .await;
        let mut rules = sb_mesh::bridge::CrossMeshPolicy::new();
        rules.add_rule(CrossMeshRule::new(
            "project-drive-read",
            "project-mesh",
            "drive-mesh",
            vec![DRIVE_STREAM_PORT],
            false,
            "Grant enforcement e2e",
        ));
        *bridge.policy.write().await = rules;
        let client = MeshClient::with_bridge("project-mesh", identity.clone(), bridge);

        let grant = |id: &str, resource: &str| {
            OperationGrant::issue(
                GrantClaims {
                    grant_id: id.into(),
                    mesh_id: "drive-mesh".into(),
                    issuer_node_id: "node-issuer".into(),
                    issuer_key_id: "org.skullsandbones.authority".into(),
                    subject_node_id: identity.node_id.clone(),
                    app_id: "org.skullsandbones.viewer".into(),
                    client_digest: format!("sha256:{}", "a".repeat(64)),
                    service_id: DRIVE_SERVICE_ID.into(),
                    api_version: DRIVE_API_VERSION,
                    operation: DRIVE_READ_OPERATION.into(),
                    resource_id: resource.into(),
                    policy_epoch: 3,
                    valid_until: 4_000_000_000,
                },
                &issuer,
            )
            .unwrap()
        };
        let attempt = |grant: Option<OperationGrant>, name: &str| {
            let destination = base.join(name);
            let client = &client;
            async move {
                let mut stream = client
                    .open_cross_mesh_stream("drive-mesh", DRIVE_STREAM_PORT, None)
                    .await
                    .expect("open mesh stream");
                download_with_grant(&mut stream, "object:file", "version:1", &destination, grant)
                    .await
                    .map(|_| destination)
            }
        };

        assert!(attempt(None, "no-grant.bin").await.is_err());
        let wrong = attempt(Some(grant("g-wrong", "object:other")), "wrong.bin").await;
        assert!(wrong.is_err());
        let good = grant("g-ok", "object:file");
        let ok = attempt(Some(good.clone()), "ok.bin").await.unwrap();
        assert_eq!(fs::read(ok).await.unwrap(), payload);
        assert!(attempt(Some(good), "replay.bin").await.is_err());
        assert!(!base.join("replay.bin").exists());

        peer_task.abort();
        let _ = peer_task.await;
        fs::remove_dir_all(base).await.unwrap();
    }

    #[test]
    fn payload_authorization_fails_closed_for_revoked_members_and_denied_acl() {
        let nonce = temporary_nonce();
        let fixture_dir =
            std::env::temp_dir().join(format!("sb_drive_acl_{}_{}", std::process::id(), nonce));
        std::fs::create_dir_all(&fixture_dir).unwrap();
        let catalog_path = fixture_dir.join("object-catalog.json");
        let rbac_path = fixture_dir.join("mesh-rbac.json");
        let identity = sb_mesh::identity::NodeIdentity::generate();
        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/file.txt",
            b"authorized",
            true,
            false,
        );
        let stream_identity = sb_mesh::bridge::MeshStreamIdentity {
            source_mesh: "project-mesh".to_string(),
            source_node_id: identity.node_id.clone(),
            source_public_key: identity.wireguard_pubkey.clone(),
        };
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .is_ok());

        let mut rbac: MeshRbacStore =
            serde_json::from_slice(&std::fs::read(&rbac_path).unwrap()).unwrap();
        rbac.members[0].revoked = true;
        std::fs::write(&rbac_path, serde_json::to_vec(&rbac).unwrap()).unwrap();
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .is_err());

        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/file.txt",
            b"authorized",
            false,
            false,
        );
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .unwrap_err()
        .contains("Object ACL denied"));

        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/file.txt",
            b"authorized",
            true,
            true,
        );
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .unwrap()
        .2
        .ends_with("file.txt"));
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:stale",
        )
        .unwrap_err()
        .contains("not current"));
        std::fs::remove_dir_all(fixture_dir).unwrap();
    }

    #[test]
    fn payload_authorization_denies_missing_catalog_or_rbac_state() {
        let nonce = temporary_nonce();
        let fixture_dir =
            std::env::temp_dir().join(format!("sb_drive_missing_{}_{}", std::process::id(), nonce));
        std::fs::create_dir_all(&fixture_dir).unwrap();
        let catalog_path = fixture_dir.join("object-catalog.json");
        let rbac_path = fixture_dir.join("mesh-rbac.json");
        let identity = sb_mesh::identity::NodeIdentity::generate();
        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/file.txt",
            b"authorized",
            true,
            false,
        );
        let stream_identity = sb_mesh::bridge::MeshStreamIdentity {
            source_mesh: "project-mesh".to_string(),
            source_node_id: identity.node_id.clone(),
            source_public_key: identity.wireguard_pubkey.clone(),
        };

        std::fs::remove_file(&catalog_path).unwrap();
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .is_err());

        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/file.txt",
            b"authorized",
            true,
            false,
        );
        std::fs::remove_file(&rbac_path).unwrap();
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .is_err());

        std::fs::remove_dir_all(fixture_dir).unwrap();
    }

    #[test]
    fn payload_authorization_rejects_expired_members_and_identity_mismatch() {
        let nonce = temporary_nonce();
        let fixture_dir =
            std::env::temp_dir().join(format!("sb_drive_expiry_{}_{}", std::process::id(), nonce));
        std::fs::create_dir_all(&fixture_dir).unwrap();
        let catalog_path = fixture_dir.join("object-catalog.json");
        let rbac_path = fixture_dir.join("mesh-rbac.json");
        let identity = sb_mesh::identity::NodeIdentity::generate();
        write_authorization_fixture(
            &catalog_path,
            &rbac_path,
            "drive-mesh",
            &identity,
            "project/file.txt",
            b"authorized",
            true,
            false,
        );
        let mut stream_identity = sb_mesh::bridge::MeshStreamIdentity {
            source_mesh: "project-mesh".to_string(),
            source_node_id: identity.node_id.clone(),
            source_public_key: identity.wireguard_pubkey.clone(),
        };

        stream_identity.source_node_id = "sbm-forged".into();
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .is_err());
        stream_identity.source_node_id.clone_from(&identity.node_id);

        stream_identity.source_public_key = "not-base64!".into();
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .unwrap_err()
        .contains("Invalid authenticated peer key"));

        stream_identity
            .source_public_key
            .clone_from(&identity.wireguard_pubkey);
        let mut rbac: MeshRbacStore =
            serde_json::from_slice(&std::fs::read(&rbac_path).unwrap()).unwrap();
        rbac.members[0].expires_at = Some(
            chrono::Utc::now()
                .timestamp()
                .max(0)
                .try_into()
                .unwrap_or(0),
        );
        std::fs::write(&rbac_path, serde_json::to_vec(&rbac).unwrap()).unwrap();
        assert!(authorize_payload(
            "drive-mesh",
            &catalog_path,
            &rbac_path,
            &stream_identity,
            "object:file",
            "version:1",
        )
        .is_err());
        std::fs::remove_dir_all(fixture_dir).unwrap();
    }

    fn write_authorization_fixture(
        catalog_path: &Path,
        rbac_path: &Path,
        mesh_name: &str,
        identity: &sb_mesh::identity::NodeIdentity,
        locator: &str,
        payload: &[u8],
        allow_read: bool,
        duplicate_locator: bool,
    ) {
        let user = PrincipalId::user("reader").unwrap();
        let device = PrincipalId::device("reader-device").unwrap();
        let mut catalog = MeshObjectCatalog::new(mesh_name).unwrap();
        catalog
            .directory
            .add_user(user.clone(), "Reader".into())
            .unwrap();
        catalog
            .directory
            .add_device(
                device,
                "Reader device".into(),
                identity.wireguard_pubkey.clone(),
                Some(user.clone()),
            )
            .unwrap();
        let object_id = MeshObjectId::new("object:file").unwrap();
        let mut object = MeshObject::new(
            object_id.clone(),
            MeshObjectKind::Blob {
                media_type: "application/octet-stream".into(),
            },
            "File".into(),
            None,
            user.clone(),
        );
        object.acl.inherit_from_parent = false;
        if allow_read {
            object.acl.add_entry(
                user.clone(),
                AclEffect::Allow,
                [ObjectPermission::Read],
                false,
            );
        }
        catalog.insert_object(object).unwrap();
        catalog
            .add_version(
                &object_id,
                ObjectVersion::from_content(
                    ObjectVersionId::new("version:1").unwrap(),
                    payload,
                    1,
                    user.clone(),
                    PayloadReference {
                        provider: "sb-drive".into(),
                        locator: locator.into(),
                    },
                ),
            )
            .unwrap();
        if duplicate_locator {
            let second_id = MeshObjectId::new("object:file-duplicate").unwrap();
            let mut second = MeshObject::new(
                second_id.clone(),
                MeshObjectKind::Blob {
                    media_type: "application/octet-stream".into(),
                },
                "Duplicate".into(),
                None,
                user.clone(),
            );
            second.acl.inherit_from_parent = false;
            if allow_read {
                second.acl.add_entry(
                    user.clone(),
                    AclEffect::Allow,
                    [ObjectPermission::Read],
                    false,
                );
            }
            catalog.insert_object(second).unwrap();
            catalog
                .add_version(
                    &second_id,
                    ObjectVersion::from_content(
                        ObjectVersionId::new("version:duplicate").unwrap(),
                        payload,
                        2,
                        user,
                        PayloadReference {
                            provider: "sb-drive".into(),
                            locator: locator.into(),
                        },
                    ),
                )
                .unwrap();
        }
        sb_mesh::MeshObjectCatalogStore::new(catalog_path)
            .save(&catalog)
            .unwrap();
        let mut rbac = MeshRbacStore::new(mesh_name);
        rbac.add_or_update(MeshMember::new(
            "reader",
            &identity.wireguard_pubkey,
            &identity.node_id,
            mesh_name,
            MeshRole::Consumer,
        ));
        std::fs::write(rbac_path, serde_json::to_vec(&rbac).unwrap()).unwrap();
    }

    fn temporary_nonce() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
