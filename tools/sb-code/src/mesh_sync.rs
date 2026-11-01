use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

use crate::vcs::{VcsEngine, VcsSyncReport};

pub const DEFAULT_CODE_MESH: &str = "dev-mesh";
pub const CODE_SYNC_PORT: u16 = 58832;
const MAX_CONTROL_FRAME: usize = 4 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_KNOWN_BRANCHES: usize = 1024;
const MAX_KNOWN_ANCESTORS: usize = 16_384;

fn is_commit_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_branch_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn known_ancestry_is_valid(known_ancestry: &[crate::vcs::KnownBranchHead]) -> bool {
    if known_ancestry.len() > MAX_KNOWN_BRANCHES
        || known_ancestry.iter().any(|known| {
            !is_branch_name(&known.branch)
                || !is_commit_id(&known.head_commit)
                || known.ancestors.is_empty()
                || known.ancestors.len() > 1024
                || !known.ancestors.iter().all(|id| is_commit_id(id))
                || !known.ancestors.contains(&known.head_commit)
                || known.ancestors.iter().collect::<HashSet<_>>().len() != known.ancestors.len()
        })
        || known_ancestry
            .iter()
            .map(|known| known.ancestors.len())
            .sum::<usize>()
            > MAX_KNOWN_ANCESTORS
    {
        return false;
    }
    known_ancestry
        .iter()
        .map(|known| known.branch.as_str())
        .collect::<HashSet<_>>()
        .len()
        == known_ancestry.len()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOperation {
    Push,
    Pull,
    ListBranches,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyncRequest {
    pub version: u8,
    pub operation: SyncOperation,
    pub project: String,
    pub branch: String,
    pub payload_bytes: u64,
    #[serde(default)]
    pub known_heads: Vec<(String, String)>,
    #[serde(default)]
    pub known_ancestry: Vec<crate::vcs::KnownBranchHead>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub caller_node_id: Option<String>,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub token: Option<sb_mesh::acl::CapabilityToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_grant: Option<sb_app_contract::OperationGrant>,
}

pub const CODE_SERVICE_ID: &str = "org.skullsandbones.code.api";
pub const CODE_API_VERSION: u16 = 1;

/// Provider-side SB-MAP `GrantGate` policy for `sb-code` mesh sync endpoints.
///
/// Enforces single-use, issuer-signed `OperationGrant`s bound to:
/// - `service_id: "org.skullsandbones.code.api"`, `api_version: 1`
/// - `operation`: `"workspace.push"`, `"workspace.pull"`, or `"workspace.list_branches"`
/// - `subject_node_id`: authenticated `caller_node_id`
/// - `resource_id`: `workspace_id` (if present) or `project`
pub struct CodeGrantPolicy {
    mesh_id: String,
    gate: sb_app_contract::GrantGate,
    manifests: std::collections::BTreeMap<String, sb_app_contract::VerifiedManifest>,
}

impl CodeGrantPolicy {
    pub fn new(
        mesh_id: impl Into<String>,
        gate: sb_app_contract::GrantGate,
        manifests: Vec<sb_app_contract::VerifiedManifest>,
    ) -> Self {
        Self {
            mesh_id: mesh_id.into(),
            gate,
            manifests: manifests
                .into_iter()
                .map(|m| (m.manifest().app_id.clone(), m))
                .collect(),
        }
    }

    pub fn authorize(
        &mut self,
        operation: SyncOperation,
        caller_node_id: &str,
        resource: &str,
        grant: Option<&sb_app_contract::OperationGrant>,
        now_unix: u64,
    ) -> Result<(), String> {
        if caller_node_id.trim().is_empty() {
            return Err("Access Denied: caller_node_id is required by CodeGrantPolicy".into());
        }
        let grant = grant.ok_or_else(|| {
            "Access Denied: missing required SB-MAP OperationGrant for sb-code sync".to_string()
        })?;
        let manifest = self
            .manifests
            .get(&grant.app_id)
            .ok_or_else(|| "Access Denied: grant references an unregistered app".to_string())?;
        let op_name = match operation {
            SyncOperation::Push => "workspace.push",
            SyncOperation::Pull => "workspace.pull",
            SyncOperation::ListBranches => "workspace.list_branches",
        };
        self.gate
            .authorize_once(
                manifest,
                grant,
                &self.mesh_id,
                caller_node_id,
                CODE_SERVICE_ID,
                CODE_API_VERSION,
                op_name,
                resource,
                now_unix,
            )
            .map_err(|e| format!("Access Denied: sb-code grant rejected: {e}"))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct SyncResponse {
    version: u8,
    accepted: bool,
    message: String,
    payload_bytes: u64,
    report: Option<VcsSyncReport>,
    #[serde(default)]
    branches: Vec<crate::vcs::BranchHeadAdvertisement>,
    #[serde(default)]
    branch_count: usize,
}

// CVE-Threat: A directly exposed sync daemon would bypass sb-node mesh admission checks.
// Analysis: The TCP listener is the local endpoint of the authenticated Cross-Mesh Bridge route.
// Hardening: Bind loopback only and reject non-loopback clients.
pub async fn run_syncd(workspace: PathBuf, bind: SocketAddr) -> Result<(), String> {
    if !bind.ip().is_loopback() {
        return Err(
            "sb-code syncd must bind to a loopback address; expose it only through sb-node".into(),
        );
    }
    let engine = VcsEngine::open(&workspace)?;
    let project = engine.project_name();
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("Failed to bind sb-code syncd at {}: {}", bind, error))?;
    println!(
        "sb-code syncd listening on {} for project '{}'; mesh ingress is handled by sb-node",
        listener.local_addr().map_err(|error| error.to_string())?,
        project
    );

    let operation_lock = Arc::new(Mutex::new(()));
    let connection_limit = Arc::new(Semaphore::new(8));
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("sb-code syncd accept failed: {}", error))?;
        if !peer.ip().is_loopback() {
            eprintln!("Rejected non-loopback syncd connection from {}", peer);
            continue;
        }
        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!(
                    "Rejected syncd connection from {}: connection limit reached",
                    peer
                );
                continue;
            }
        };

        let workspace = workspace.clone();
        let operation_lock = Arc::clone(&operation_lock);
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = operation_lock.lock().await;
            if let Err(error) = handle_connection(stream, &workspace).await {
                eprintln!("sb-code syncd request from {} failed: {}", peer, error);
            }
        });
    }
}

pub async fn push(
    engine: &VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    branch: &str,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String> {
    push_on_port(
        engine,
        source_mesh,
        target_mesh,
        anchor_addr,
        CODE_SYNC_PORT,
        branch,
        token,
    )
    .await
}

pub async fn push_on_port(
    engine: &VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    service_port: u16,
    branch: &str,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String> {
    push_workspace_on_port(
        engine,
        source_mesh,
        target_mesh,
        anchor_addr,
        service_port,
        branch,
        None,
        None,
        None,
        token,
    )
    .await
}

pub async fn push_workspace_on_port(
    engine: &VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    service_port: u16,
    branch: &str,
    workspace_id: Option<&str>,
    caller_node_id: Option<&str>,
    expected_head: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String> {
    let client = open_mesh_client(source_mesh, anchor_addr).await?;
    let mut stream = client
        .open_cross_mesh_stream(target_mesh, service_port, token.clone())
        .await
        .map_err(|error| format!("Failed to open code-sync mesh stream: {}", error))?;
    push_workspace_over_stream(
        &mut stream,
        engine,
        target_mesh,
        branch,
        workspace_id,
        caller_node_id,
        expected_head,
        token,
    )
    .await
}

pub async fn pull(
    engine: &mut VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    branch: &str,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String> {
    pull_on_port(
        engine,
        source_mesh,
        target_mesh,
        anchor_addr,
        CODE_SYNC_PORT,
        branch,
        token,
    )
    .await
}

pub async fn pull_on_port(
    engine: &mut VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    service_port: u16,
    branch: &str,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String> {
    pull_workspace_on_port(
        engine,
        source_mesh,
        target_mesh,
        anchor_addr,
        service_port,
        branch,
        None,
        None,
        token,
    )
    .await
}

pub async fn pull_workspace_on_port(
    engine: &mut VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    service_port: u16,
    branch: &str,
    workspace_id: Option<&str>,
    caller_node_id: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String> {
    let client = open_mesh_client(source_mesh, anchor_addr).await?;
    let mut stream = client
        .open_cross_mesh_stream(target_mesh, service_port, token.clone())
        .await
        .map_err(|error| format!("Failed to open code-sync mesh stream: {}", error))?;
    pull_workspace_over_stream(
        &mut stream,
        engine,
        target_mesh,
        branch,
        workspace_id,
        caller_node_id,
        token,
    )
    .await
}

pub async fn branch_divergence(
    engine: &VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<crate::vcs::BranchRadarReport, String> {
    branch_divergence_on_port(
        engine,
        source_mesh,
        target_mesh,
        anchor_addr,
        CODE_SYNC_PORT,
        token,
    )
    .await
}

pub async fn branch_divergence_on_port(
    engine: &VcsEngine,
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    service_port: u16,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<crate::vcs::BranchRadarReport, String> {
    let local_heads = engine.branch_head_ids()?;
    let ancestry_limit = (16_384 / local_heads.len().max(1)).clamp(1, 1024);
    let known_ancestry = local_heads
        .iter()
        .map(|(branch, head_commit)| {
            Ok(crate::vcs::KnownBranchHead {
                branch: branch.clone(),
                head_commit: head_commit.clone(),
                ancestors: engine.branch_ancestry_ids(branch, ancestry_limit)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let client = open_mesh_client(source_mesh, anchor_addr).await?;
    let mut stream = client
        .open_cross_mesh_stream(target_mesh, service_port, token)
        .await
        .map_err(|error| format!("Failed to open branch-radar mesh stream: {error}"))?;
    branch_divergence_over_stream(engine, &local_heads, &known_ancestry, &mut stream).await
}

pub async fn branch_divergence_over_stream<S>(
    engine: &VcsEngine,
    local_heads: &[(String, String)],
    known_ancestry: &[crate::vcs::KnownBranchHead],
    stream: &mut S,
) -> Result<crate::vcs::BranchRadarReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(
        stream,
        &SyncRequest {
            version: 1,
            operation: SyncOperation::ListBranches,
            project: engine.project_name(),
            branch: "__branches__".to_string(),
            payload_bytes: 0,
            known_heads: local_heads.to_vec(),
            known_ancestry: known_ancestry.to_vec(),
            workspace_id: None,
            caller_node_id: None,
            expected_head: None,
            token: None,
            app_grant: None,
        },
    )
    .await?;
    let response: SyncResponse = read_frame(stream).await.map_err(|error| {
        format!(
            "Remote peer did not provide the branch-radar protocol (it may be an older sb-code syncd): {error}"
        )
    })?;
    if response.version != 1 {
        return Err(format!(
            "Unsupported remote branch-radar protocol version: {}",
            response.version
        ));
    }
    if !response.accepted {
        return Err(format!(
            "Remote branch-radar query rejected: {}",
            response.message
        ));
    }

    let remote_branch_count = response.branch_count.max(response.branches.len());
    let divergences = compare_branch_advertisements(engine, local_heads, response.branches)?;
    Ok(crate::vcs::BranchRadarReport {
        remote_branch_count,
        divergences,
    })
}

fn compare_branch_advertisements(
    engine: &VcsEngine,
    local_heads: &[(String, String)],
    remote_branches: Vec<crate::vcs::BranchHeadAdvertisement>,
) -> Result<Vec<crate::vcs::BranchDivergence>, String> {
    let local_heads = local_heads.iter().cloned().collect::<HashMap<_, _>>();
    let mut divergence = Vec::new();
    for remote in remote_branches {
        let local_head = local_heads.get(&remote.branch).cloned();
        if local_head.as_deref() == Some(&remote.head_commit) {
            continue;
        }
        let (local_commits, overlapping_scopes, comparison_note) = match (
            local_head.as_deref(),
            remote.common_base.as_deref(),
        ) {
            (Some(local_head), Some(base)) => {
                let local_distance = engine
                    .commit_distance_between(local_head, base)?
                    .ok_or_else(|| {
                        format!(
                            "Advertised common base {} is not an ancestor of local head {}",
                            base, local_head
                        )
                    })?;
                let local_changes = engine.changed_scope_summaries(base, local_head)?;
                let remote_ids = remote
                    .changed_scopes
                    .iter()
                    .map(|scope| scope.scope_id.as_str())
                    .collect::<HashSet<_>>();
                let overlaps = local_changes
                    .into_iter()
                    .filter(|scope| remote_ids.contains(scope.scope_id.as_str()))
                    .collect();
                (Some(local_distance), overlaps, None)
            }
            _ => (
                None,
                Vec::new(),
                Some(
                    "No shared commit base is available; fetch the remote branch to compare scopes"
                        .into(),
                ),
            ),
        };
        divergence.push(crate::vcs::BranchDivergence {
            branch: remote.branch,
            local_head,
            remote_head: remote.head_commit,
            common_base: remote.common_base,
            local_commits,
            remote_commits: remote.ahead_commits,
            overlapping_scopes,
            comparison_note,
        });
    }
    divergence.sort_by(|left, right| left.branch.cmp(&right.branch));
    Ok(divergence)
}

async fn open_mesh_client(
    source_mesh: &str,
    anchor_addr: SocketAddr,
) -> Result<sb_mesh::client::MeshClient, String> {
    if source_mesh.trim().is_empty() {
        return Err("Source mesh name must not be empty".into());
    }
    let identity = Arc::new(
        sb_mesh::identity::NodeIdentity::load_or_generate_default()
            .map_err(|error| format!("Failed to load sb-mesh identity: {}", error))?,
    );
    if sb_mesh::ticket::load_cached_ticket(source_mesh).is_none() {
        let _ = sb_mesh::ticket::request_ticket(
            &anchor_addr.to_string(),
            &identity,
            source_mesh,
            std::time::Duration::from_millis(1500),
        )
        .await;
    }
    let client = sb_mesh::client::MeshClient::connect(sb_mesh::client::MeshClientConfig {
        mesh_name: source_mesh.to_string(),
        swarm_topic: format!("sbm-swarm-{}", source_mesh),
        anchor_addr,
        identity,
        local_bind_port: None,
    })
    .await
    .map_err(|error| format!("Failed to connect to source mesh: {}", error))?;
    Ok(client)
}

pub async fn push_over_stream<S>(
    stream: &mut S,
    engine: &VcsEngine,
    target_mesh: &str,
    branch: &str,
) -> Result<VcsSyncReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    push_workspace_over_stream(stream, engine, target_mesh, branch, None, None, None, None).await
}

pub async fn push_workspace_over_stream<S>(
    stream: &mut S,
    engine: &VcsEngine,
    target_mesh: &str,
    branch: &str,
    workspace_id: Option<&str>,
    caller_node_id: Option<&str>,
    expected_head: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    push_workspace_over_stream_with_grant(
        stream,
        engine,
        target_mesh,
        branch,
        workspace_id,
        caller_node_id,
        expected_head,
        token,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn push_workspace_over_stream_with_grant<S>(
    stream: &mut S,
    engine: &VcsEngine,
    target_mesh: &str,
    branch: &str,
    workspace_id: Option<&str>,
    caller_node_id: Option<&str>,
    expected_head: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
    app_grant: Option<sb_app_contract::OperationGrant>,
) -> Result<VcsSyncReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bundle = engine.export_bundle(branch, None)?;
    if bundle.len() as u64 > MAX_BUNDLE_BYTES {
        return Err("Exported bundle exceeds the code-sync transfer limit".into());
    }
    let version = if workspace_id.is_some()
        || caller_node_id.is_some()
        || expected_head.is_some()
        || token.is_some()
        || app_grant.is_some()
    {
        2
    } else {
        1
    };
    write_frame(
        stream,
        &SyncRequest {
            version,
            operation: SyncOperation::Push,
            project: engine.project_name(),
            branch: branch.to_string(),
            payload_bytes: bundle.len() as u64,
            known_heads: Vec::new(),
            known_ancestry: Vec::new(),
            workspace_id: workspace_id.map(|s| s.to_string()),
            caller_node_id: caller_node_id.map(|s| s.to_string()),
            expected_head: expected_head.map(|s| s.to_string()),
            token,
            app_grant,
        },
    )
    .await?;
    stream
        .write_all(&bundle)
        .await
        .map_err(|error| format!("Failed to send code bundle: {}", error))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("Failed to flush code bundle: {}", error))?;

    let response: SyncResponse = read_frame(stream).await?;
    if response.version != 1 && response.version != 2 {
        return Err(format!(
            "Unsupported remote code-sync protocol version: {}",
            response.version
        ));
    }
    if !response.accepted {
        return Err(format!(
            "Remote code-sync rejected push: {}",
            response.message
        ));
    }
    let mut report = response
        .report
        .ok_or_else(|| "Remote code-sync omitted the push report".to_string())?;
    report.anchor = target_mesh.to_string();
    Ok(report)
}

pub async fn pull_over_stream<S>(
    stream: &mut S,
    engine: &mut VcsEngine,
    target_mesh: &str,
    branch: &str,
) -> Result<VcsSyncReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pull_workspace_over_stream(stream, engine, target_mesh, branch, None, None, None).await
}

pub async fn pull_workspace_over_stream<S>(
    stream: &mut S,
    engine: &mut VcsEngine,
    target_mesh: &str,
    branch: &str,
    workspace_id: Option<&str>,
    caller_node_id: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
) -> Result<VcsSyncReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pull_workspace_over_stream_with_grant(
        stream,
        engine,
        target_mesh,
        branch,
        workspace_id,
        caller_node_id,
        token,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn pull_workspace_over_stream_with_grant<S>(
    stream: &mut S,
    engine: &mut VcsEngine,
    target_mesh: &str,
    branch: &str,
    workspace_id: Option<&str>,
    caller_node_id: Option<&str>,
    token: Option<sb_mesh::acl::CapabilityToken>,
    app_grant: Option<sb_app_contract::OperationGrant>,
) -> Result<VcsSyncReport, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = if workspace_id.is_some()
        || caller_node_id.is_some()
        || token.is_some()
        || app_grant.is_some()
    {
        2
    } else {
        1
    };
    write_frame(
        stream,
        &SyncRequest {
            version,
            operation: SyncOperation::Pull,
            project: engine.project_name(),
            branch: branch.to_string(),
            payload_bytes: 0,
            known_heads: Vec::new(),
            known_ancestry: Vec::new(),
            workspace_id: workspace_id.map(|s| s.to_string()),
            caller_node_id: caller_node_id.map(|s| s.to_string()),
            expected_head: None,
            token,
            app_grant,
        },
    )
    .await?;
    let response: SyncResponse = read_frame(stream).await?;
    if response.version != 1 && response.version != 2 {
        return Err(format!(
            "Unsupported remote code-sync protocol version: {}",
            response.version
        ));
    }
    if !response.accepted {
        return Err(format!(
            "Remote code-sync rejected pull: {}",
            response.message
        ));
    }
    if response.payload_bytes > MAX_BUNDLE_BYTES {
        return Err("Remote code bundle exceeds the code-sync transfer limit".into());
    }
    let size = usize::try_from(response.payload_bytes)
        .map_err(|_| "Remote code bundle does not fit in memory".to_string())?;
    let mut bundle = vec![0; size];
    stream
        .read_exact(&mut bundle)
        .await
        .map_err(|error| format!("Failed to receive code bundle: {}", error))?;
    let mut report = engine.import_bundle(&bundle, branch)?;
    report.anchor = target_mesh.to_string();
    Ok(report)
}

pub async fn run_multi_syncd(registry_path: PathBuf, bind: SocketAddr) -> Result<(), String> {
    if !bind.ip().is_loopback() {
        return Err(
            "sb-code syncd must bind to a loopback address; expose it only through sb-node".into(),
        );
    }
    let registry = Arc::new(crate::dev_workspace::DevWorkspaceRegistry::load_from_file(
        &registry_path,
    )?);
    let listener = TcpListener::bind(bind).await.map_err(|error| {
        format!(
            "Failed to bind multi-workspace syncd at {}: {}",
            bind, error
        )
    })?;
    println!(
        "sb-code multi-workspace syncd listening on {} managing {} workspaces; mesh ingress is handled by sb-node",
        listener.local_addr().map_err(|error| error.to_string())?,
        registry.workspaces.len()
    );

    let operation_lock = Arc::new(Mutex::new(()));
    let connection_limit = Arc::new(Semaphore::new(8));
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("multi-workspace syncd accept failed: {}", error))?;
        if !peer.ip().is_loopback() {
            eprintln!("Rejected non-loopback syncd connection from {}", peer);
            continue;
        }
        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!(
                    "Rejected syncd connection from {}: connection limit reached",
                    peer
                );
                continue;
            }
        };

        let registry = Arc::clone(&registry);
        let operation_lock = Arc::clone(&operation_lock);
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = operation_lock.lock().await;
            if let Err(error) = handle_connection_with_registry(stream, &registry).await {
                eprintln!(
                    "multi-workspace syncd request from {} failed: {}",
                    peer, error
                );
            }
        });
    }
}

// CVE-Threat: An untrusted peer could forge lengths or exhaust memory with an oversized bundle.
// Analysis: The request frame and payload length come from the network.
// Hardening: Bound frame/payload lengths and pass payloads through the validating VCS importer.
pub async fn handle_connection(stream: TcpStream, workspace: &Path) -> Result<(), String> {
    handle_connection_internal(stream, Some(workspace), None, None).await
}

pub async fn handle_connection_with_registry(
    stream: TcpStream,
    registry: &crate::dev_workspace::DevWorkspaceRegistry,
) -> Result<(), String> {
    handle_connection_internal(stream, None, Some(registry), None).await
}

pub async fn handle_connection_with_grant_policy(
    stream: TcpStream,
    workspace: Option<&Path>,
    registry: Option<&crate::dev_workspace::DevWorkspaceRegistry>,
    grant_policy: &mut CodeGrantPolicy,
) -> Result<(), String> {
    handle_connection_internal(stream, workspace, registry, Some(grant_policy)).await
}

async fn handle_connection_internal(
    mut stream: TcpStream,
    workspace: Option<&Path>,
    registry: Option<&crate::dev_workspace::DevWorkspaceRegistry>,
    grant_policy: Option<&mut CodeGrantPolicy>,
) -> Result<(), String> {
    let request: SyncRequest = read_frame(&mut stream).await?;
    if request.version != 1 && request.version != 2 {
        return Err(format!(
            "Unsupported code-sync protocol version: {}",
            request.version
        ));
    }
    if request.project.trim().is_empty()
        || (request.branch.trim().is_empty()
            && !matches!(request.operation, SyncOperation::ListBranches))
    {
        return Err("Project and branch are required".into());
    }
    if request.known_heads.len() > MAX_KNOWN_BRANCHES
        || request
            .known_heads
            .iter()
            .any(|(branch, commit)| !is_branch_name(branch) || !is_commit_id(commit))
        || request
            .known_heads
            .iter()
            .map(|(branch, _)| branch)
            .collect::<HashSet<_>>()
            .len()
            != request.known_heads.len()
    {
        return Err("Known branch head list is invalid".into());
    }
    if !known_ancestry_is_valid(&request.known_ancestry) {
        return Err("Known branch ancestry list is invalid".into());
    }

    let caller = request.caller_node_id.as_deref().unwrap_or("");
    let resource_id = request
        .workspace_id
        .as_deref()
        .unwrap_or(request.project.as_str());
    if let Some(gate_policy) = grant_policy {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(err) = gate_policy.authorize(
            request.operation,
            caller,
            resource_id,
            request.app_grant.as_ref(),
            now_unix,
        ) {
            write_response(
                &mut stream,
                SyncResponse {
                    version: request.version,
                    accepted: false,
                    message: err,
                    payload_bytes: 0,
                    report: None,
                    branches: Vec::new(),
                    branch_count: 0,
                },
            )
            .await?;
            return Ok(());
        }
    }

    let (mut engine, policy) = if let Some(ref wid) = request.workspace_id {
        let reg = match registry {
            Some(r) => r,
            None => {
                write_response(
                    &mut stream,
                    SyncResponse {
                        version: request.version,
                        accepted: false,
                        message: "Server is not configured with Dev-Mesh workspace registry".into(),
                        payload_bytes: 0,
                        report: None,
                        branches: Vec::new(),
                        branch_count: 0,
                    },
                )
                .await?;
                return Ok(());
            }
        };
        let entry = match reg.get(wid) {
            Some(e) => e,
            None => {
                write_response(
                    &mut stream,
                    SyncResponse {
                        version: request.version,
                        accepted: false,
                        message: format!("Unknown Dev-Mesh workspace: '{}'", wid),
                        payload_bytes: 0,
                        report: None,
                        branches: Vec::new(),
                        branch_count: 0,
                    },
                )
                .await?;
                return Ok(());
            }
        };
        let eng = match VcsEngine::open(&entry.repo_path) {
            Ok(e) => e,
            Err(e) => {
                write_response(
                    &mut stream,
                    SyncResponse {
                        version: request.version,
                        accepted: false,
                        message: format!("Failed to open workspace repository: {}", e),
                        payload_bytes: 0,
                        report: None,
                        branches: Vec::new(),
                        branch_count: 0,
                    },
                )
                .await?;
                return Ok(());
            }
        };
        (eng, Some(&entry.policy))
    } else {
        let ws = match workspace {
            Some(w) => w,
            None => {
                write_response(
                    &mut stream,
                    SyncResponse {
                        version: request.version,
                        accepted: false,
                        message: "Workspace ID is required in multi-workspace mode".into(),
                        payload_bytes: 0,
                        report: None,
                        branches: Vec::new(),
                        branch_count: 0,
                    },
                )
                .await?;
                return Ok(());
            }
        };
        let eng = VcsEngine::open(ws)?;
        if eng.project_name() != request.project {
            write_response(
                &mut stream,
                SyncResponse {
                    version: request.version,
                    accepted: false,
                    message: "Project name does not match this syncd workspace".into(),
                    payload_bytes: 0,
                    report: None,
                    branches: Vec::new(),
                    branch_count: 0,
                },
            )
            .await?;
            return Ok(());
        }
        (eng, None)
    };

    match request.operation {
        SyncOperation::Push => {
            if request.payload_bytes == 0 || request.payload_bytes > MAX_BUNDLE_BYTES {
                return Err("Push payload length is invalid or exceeds the transfer limit".into());
            }
            let size = usize::try_from(request.payload_bytes)
                .map_err(|_| "Push bundle does not fit in memory".to_string())?;
            let mut bundle = vec![0; size];
            stream
                .read_exact(&mut bundle)
                .await
                .map_err(|error| format!("Failed to receive push bundle: {}", error))?;

            if let Some(pol) = policy {
                if let Err(err) = pol.authorize_write(caller, request.token.as_ref()) {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: false,
                            message: err,
                            payload_bytes: 0,
                            report: None,
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await?;
                    return Ok(());
                }
                if let Some(ref expected) = request.expected_head {
                    let current = engine
                        .branch_head(&request.branch)
                        .ok()
                        .map(|c| c.commit_id);
                    if current.as_deref() != Some(expected) {
                        write_response(
                            &mut stream,
                            SyncResponse {
                                version: request.version,
                                accepted: false,
                                message: format!(
                                    "Divergent head detected: Expected '{}', but remote current head is '{:?}'",
                                    expected, current
                                ),
                                payload_bytes: 0,
                                report: None,
                                branches: Vec::new(),
                                branch_count: 0,
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                }
            }

            match engine.import_bundle(&bundle, &request.branch) {
                Ok(report) => {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: true,
                            message: "Push imported".into(),
                            payload_bytes: 0,
                            report: Some(report),
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await
                }
                Err(error) => {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: false,
                            message: error,
                            payload_bytes: 0,
                            report: None,
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await
                }
            }
        }
        SyncOperation::Pull => {
            if let Some(pol) = policy {
                if let Err(err) = pol.authorize_read(caller, request.token.as_ref()) {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: false,
                            message: err,
                            payload_bytes: 0,
                            report: None,
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await?;
                    return Ok(());
                }
            }
            if request.payload_bytes != 0 {
                return Err("Pull request must not contain a payload".into());
            }
            match engine.export_bundle(&request.branch, None) {
                Ok(bundle) if bundle.len() as u64 <= MAX_BUNDLE_BYTES => {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: true,
                            message: "Pull exported".into(),
                            payload_bytes: bundle.len() as u64,
                            report: None,
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await?;
                    stream
                        .write_all(&bundle)
                        .await
                        .map_err(|error| format!("Failed to send pull bundle: {}", error))?;
                    stream
                        .flush()
                        .await
                        .map_err(|error| format!("Failed to flush pull bundle: {}", error))
                }
                Ok(_) => {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: false,
                            message: "Exported bundle exceeds the transfer limit".into(),
                            payload_bytes: 0,
                            report: None,
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await
                }
                Err(error) => {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: false,
                            message: error,
                            payload_bytes: 0,
                            report: None,
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await
                }
            }
        }
        SyncOperation::ListBranches => {
            if let Some(pol) = policy {
                if let Err(err) = pol.authorize_read(caller, request.token.as_ref()) {
                    write_response(
                        &mut stream,
                        SyncResponse {
                            version: request.version,
                            accepted: false,
                            message: err,
                            payload_bytes: 0,
                            report: None,
                            branches: Vec::new(),
                            branch_count: 0,
                        },
                    )
                    .await?;
                    return Ok(());
                }
            }
            if request.payload_bytes != 0 || request.branch != "__branches__" {
                return Err("Branch-radar request is malformed".into());
            }
            let branches = engine.advertise_branch_heads(&request.known_ancestry)?;
            let branch_count = branches.len();
            write_response(
                &mut stream,
                SyncResponse {
                    version: request.version,
                    accepted: true,
                    message: "Branch heads and scope divergence".into(),
                    payload_bytes: 0,
                    report: None,
                    branches,
                    branch_count,
                },
            )
            .await
        }
    }
}

async fn write_response<S>(stream: &mut S, response: SyncResponse) -> Result<(), String>
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
        return Err("Code-sync control frame exceeds the protocol limit".into());
    }
    let len = u32::try_from(bytes.len())
        .map_err(|_| "Code-sync control frame is too large".to_string())?;
    stream
        .write_u32(len)
        .await
        .map_err(|error| format!("Failed to write code-sync control frame length: {}", error))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("Failed to write code-sync control frame: {}", error))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("Failed to flush code-sync control frame: {}", error))
}

async fn read_frame<S, T>(stream: &mut S) -> Result<T, String>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let len = stream
        .read_u32()
        .await
        .map_err(|error| format!("Failed to read code-sync frame length: {}", error))?
        as usize;
    if len == 0 || len > MAX_CONTROL_FRAME {
        return Err("Code-sync control frame length is invalid".into());
    }
    let mut bytes = vec![0; len];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| format!("Failed to read code-sync control frame: {}", error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("Invalid code-sync control frame: {}", error))
}

pub fn read_capability_token(
    path: Option<&Path>,
) -> Result<Option<sb_mesh::acl::CapabilityToken>, String> {
    path.map(|path| {
        let content = std::fs::read(path).map_err(|error| {
            format!(
                "Failed to read capability token {}: {}",
                path.display(),
                error
            )
        })?;
        serde_json::from_slice(&content)
            .map_err(|error| format!("Invalid capability token {}: {}", path.display(), error))
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn version_one_push_pull_frames_remain_compatible_without_radar_fields() {
        let request: SyncRequest = serde_json::from_str(
            r#"{"version":1,"operation":"pull","project":"compat","branch":"main","payload_bytes":0}"#,
        )
        .unwrap();
        assert!(request.known_heads.is_empty());
        assert!(request.known_ancestry.is_empty());
        let response: SyncResponse = serde_json::from_str(
            r#"{"version":1,"accepted":true,"message":"ok","payload_bytes":0,"report":null}"#,
        )
        .unwrap();
        assert!(response.branches.is_empty());
        assert_eq!(response.branch_count, 0);
    }

    #[tokio::test]
    async fn syncd_refuses_non_loopback_bind_addresses() {
        let error = run_syncd(PathBuf::from("unused"), "0.0.0.0:58832".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.contains("loopback"));
    }

    #[tokio::test]
    async fn push_protocol_imports_validated_objects_on_receiver() {
        let source =
            std::env::temp_dir().join(format!("sb_code_sync_source_{}", uuid::Uuid::new_v4()));
        let target =
            std::env::temp_dir().join(format!("sb_code_sync_target_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        let mut source_engine = VcsEngine::init(&source).unwrap();
        source_engine.set_project_name("protocol-test").unwrap();
        fs::write(source.join("main.rs"), "fn main() {}\n").unwrap();
        let source_commit = source_engine.commit("initial", "alice").unwrap();
        let target_engine = VcsEngine::init(&target).unwrap();
        target_engine.set_project_name("protocol-test").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_workspace = target.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, &server_workspace).await.unwrap();
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let report = push_over_stream(&mut stream, &source_engine, "dev-mesh", "main")
            .await
            .unwrap();
        assert_eq!(report.new_head, source_commit.commit_id);
        server.await.unwrap();

        let target_engine = VcsEngine::open(&target).unwrap();
        assert_eq!(
            target_engine.head_commit().unwrap().unwrap().commit_id,
            source_commit.commit_id
        );
        assert_eq!(
            fs::read_to_string(target.join("main.rs")).unwrap(),
            "fn main() {}\n"
        );
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(target);
    }

    #[tokio::test]
    async fn pull_protocol_exports_and_imports_a_branch_bundle() {
        let source =
            std::env::temp_dir().join(format!("sb_code_pull_source_{}", uuid::Uuid::new_v4()));
        let target =
            std::env::temp_dir().join(format!("sb_code_pull_target_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        let mut source_engine = VcsEngine::init(&source).unwrap();
        source_engine.set_project_name("protocol-test").unwrap();
        fs::write(source.join("lib.rs"), "pub fn value() -> u8 { 7 }\n").unwrap();
        let source_commit = source_engine.commit("initial", "alice").unwrap();
        let mut target_engine = VcsEngine::init(&target).unwrap();
        target_engine.set_project_name("protocol-test").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_workspace = source.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, &server_workspace).await.unwrap();
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let report = pull_over_stream(&mut stream, &mut target_engine, "dev-mesh", "main")
            .await
            .unwrap();
        assert_eq!(report.new_head, source_commit.commit_id);
        server.await.unwrap();
        assert_eq!(
            fs::read_to_string(target.join("lib.rs")).unwrap(),
            "pub fn value() -> u8 { 7 }\n"
        );
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(target);
    }

    #[tokio::test]
    async fn branch_listing_protocol_reports_changed_scopes_from_known_head() {
        let workspace =
            std::env::temp_dir().join(format!("sb_code_radar_{}", uuid::Uuid::new_v4()));
        let local_workspace =
            std::env::temp_dir().join(format!("sb_code_radar_local_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&workspace).unwrap();
        let mut engine = VcsEngine::init(&workspace).unwrap();
        engine.set_project_name("radar-test").unwrap();
        fs::write(workspace.join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
        let base = engine.commit("base", "alice").unwrap();
        fs::create_dir_all(&local_workspace).unwrap();
        let mut local_engine = VcsEngine::init(&local_workspace).unwrap();
        local_engine.set_project_name("radar-test").unwrap();
        let base_bundle = engine.export_bundle("main", None).unwrap();
        local_engine.import_bundle(&base_bundle, "main").unwrap();

        fs::write(workspace.join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
        let remote = engine.commit("remote change", "alice").unwrap();
        fs::write(
            local_workspace.join("lib.rs"),
            "pub fn value() -> u8 { 3 }\n",
        )
        .unwrap();
        local_engine.commit("local change", "bob").unwrap();
        let local_heads = local_engine.branch_head_ids().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_workspace = workspace.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, &server_workspace).await.unwrap();
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        write_frame(
            &mut stream,
            &SyncRequest {
                version: 1,
                operation: SyncOperation::ListBranches,
                project: "radar-test".to_string(),
                branch: "__branches__".to_string(),
                payload_bytes: 0,
                known_heads: local_heads.clone(),
                known_ancestry: local_heads
                    .iter()
                    .map(|(branch, head_commit)| {
                        Ok(crate::vcs::KnownBranchHead {
                            branch: branch.clone(),
                            head_commit: head_commit.clone(),
                            ancestors: local_engine.branch_ancestry_ids(branch, 1024)?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()
                    .unwrap(),
                workspace_id: None,
                caller_node_id: None,
                expected_head: None,
                token: None,
                app_grant: None,
            },
        )
        .await
        .unwrap();
        let response: SyncResponse = read_frame(&mut stream).await.unwrap();
        assert!(response.accepted);
        let branch = response
            .branches
            .iter()
            .find(|branch| branch.branch == "main")
            .unwrap();
        assert_eq!(branch.head_commit, remote.commit_id);
        assert_eq!(branch.common_base.as_deref(), Some(base.commit_id.as_str()));
        assert_eq!(branch.ahead_commits, Some(1));
        assert_eq!(branch.changed_scopes.len(), 1);
        assert_eq!(branch.changed_scopes[0].name, "value");
        let remote_scope_id = branch.changed_scopes[0].scope_id.clone();
        let divergences =
            compare_branch_advertisements(&local_engine, &local_heads, response.branches).unwrap();
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].local_commits, Some(1));
        assert_eq!(divergences[0].overlapping_scopes.len(), 1);
        assert_eq!(
            divergences[0].overlapping_scopes[0].scope_id,
            remote_scope_id
        );
        server.await.unwrap();
        let _ = fs::remove_dir_all(workspace);
        let _ = fs::remove_dir_all(local_workspace);
    }

    #[tokio::test]
    async fn code_grant_policy_enforces_single_use_grant_over_sync_stream() {
        use ed25519_dalek::SigningKey;
        use sb_app_contract::{GrantClaims, GrantGate, OperationGrant, TrustedIssuer};

        let base_temp =
            std::env::temp_dir().join(format!("sb_code_grant_test_{}", uuid::Uuid::new_v4()));
        let server_dir = base_temp.join("server");
        let client_dir = base_temp.join("client");
        fs::create_dir_all(&server_dir).unwrap();
        fs::create_dir_all(&client_dir).unwrap();

        let mut server_engine = VcsEngine::init(&server_dir).unwrap();
        server_engine.set_project_name("sb-core").unwrap();
        fs::write(
            server_dir.join("lib.rs"),
            "pub fn granted() -> u32 { 42 }\n",
        )
        .unwrap();
        let commit = server_engine.commit("initial", "writer").unwrap();

        let mut client_engine = VcsEngine::init(&client_dir).unwrap();
        client_engine.set_project_name("sb-core").unwrap();

        let publisher_key = SigningKey::from_bytes(&[29u8; 32]);
        let issuer_key = SigningKey::from_bytes(&[31u8; 32]);
        let client_artifact = b"fake-studio-client-binary";
        let client_digest = format!("sha256:{}", "a".repeat(64));
        let manifest_json = serde_json::json!({
            "schema_version": 1,
            "app_id": "org.skullsandbones.studio",
            "version": "0.1.0",
            "publisher_key_id": "org.skullsandbones.publisher",
            "client": {
                "target": "windows-x86_64",
                "artifact": client_digest
            },
            "services": [{
                "service_id": CODE_SERVICE_ID,
                "api_version": CODE_API_VERSION,
                "contract_digest": format!("sha256:{}", "b".repeat(64))
            }],
            "requested_capabilities": [{
                "service_id": CODE_SERVICE_ID,
                "operation": "workspace.pull"
            }],
            "sandbox_profile": "native-client-default"
        })
        .to_string();
        let packed = sb_app_contract::install::pack_signed_bundle(
            manifest_json.as_bytes(),
            client_artifact,
            &publisher_key,
        )
        .unwrap();
        let bundle = sb_app_contract::install::parse_bundle(&packed).unwrap();
        let publishers = std::collections::BTreeMap::from([(
            "org.skullsandbones.publisher".to_string(),
            publisher_key.verifying_key().to_bytes(),
        )]);
        let verified_manifest = sb_app_contract::verify_signed_manifest(
            &bundle.manifest,
            &bundle.signature_hex,
            &publishers,
        )
        .unwrap();
        let client_digest = verified_manifest.manifest().client.artifact.clone();

        let issuers = std::collections::BTreeMap::from([(
            "org.skullsandbones.issuer".to_string(),
            TrustedIssuer {
                mesh_id: "dev-mesh".to_string(),
                node_id: "issuer-node-1".to_string(),
                public_key: issuer_key.verifying_key().to_bytes(),
            },
        )]);
        let policy = Arc::new(Mutex::new(CodeGrantPolicy::new(
            "dev-mesh",
            GrantGate::new(issuers, 7),
            vec![verified_manifest],
        )));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_ws = server_dir.clone();
        let server_policy = Arc::clone(&policy);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let ws = server_ws.clone();
                let pol = Arc::clone(&server_policy);
                tokio::spawn(async move {
                    let mut guard = pol.lock().await;
                    let _ =
                        handle_connection_with_grant_policy(stream, Some(&ws), None, &mut guard)
                            .await;
                });
            }
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let make_grant = |grant_id: &str, resource: &str| -> OperationGrant {
            OperationGrant::issue(
                GrantClaims {
                    grant_id: grant_id.to_string(),
                    mesh_id: "dev-mesh".to_string(),
                    issuer_node_id: "issuer-node-1".to_string(),
                    issuer_key_id: "org.skullsandbones.issuer".to_string(),
                    subject_node_id: "studio-node-1".to_string(),
                    app_id: "org.skullsandbones.studio".to_string(),
                    client_digest: client_digest.clone(),
                    service_id: CODE_SERVICE_ID.to_string(),
                    api_version: CODE_API_VERSION,
                    operation: "workspace.pull".to_string(),
                    resource_id: resource.to_string(),
                    policy_epoch: 7,
                    valid_until: now + 120,
                },
                &issuer_key,
            )
            .unwrap()
        };

        // 1. Missing grant -> rejected
        let mut s1 = TcpStream::connect(address).await.unwrap();
        let no_grant_err = pull_workspace_over_stream_with_grant(
            &mut s1,
            &mut client_engine,
            "dev-mesh",
            "main",
            None,
            Some("studio-node-1"),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(no_grant_err.contains("missing required SB-MAP OperationGrant"));

        // 2. Wrong resource grant -> rejected
        let wrong_grant = make_grant("grant-wrong-res", "other-project");
        let mut s2 = TcpStream::connect(address).await.unwrap();
        let wrong_err = pull_workspace_over_stream_with_grant(
            &mut s2,
            &mut client_engine,
            "dev-mesh",
            "main",
            None,
            Some("studio-node-1"),
            None,
            Some(wrong_grant),
        )
        .await
        .unwrap_err();
        assert!(wrong_err.contains("sb-code grant rejected"));

        // 3. Valid grant -> succeeds
        let valid_grant = make_grant("grant-valid-1", "sb-core");
        let mut s3 = TcpStream::connect(address).await.unwrap();
        let report = pull_workspace_over_stream_with_grant(
            &mut s3,
            &mut client_engine,
            "dev-mesh",
            "main",
            None,
            Some("studio-node-1"),
            None,
            Some(valid_grant.clone()),
        )
        .await
        .unwrap();
        assert_eq!(report.new_head, commit.commit_id);

        // 4. Replayed grant -> rejected (single-use)
        let mut s4 = TcpStream::connect(address).await.unwrap();
        let replay_err = pull_workspace_over_stream_with_grant(
            &mut s4,
            &mut client_engine,
            "dev-mesh",
            "main",
            None,
            Some("studio-node-1"),
            None,
            Some(valid_grant),
        )
        .await
        .unwrap_err();
        assert!(replay_err.contains("sb-code grant rejected"));

        let _ = fs::remove_dir_all(base_temp);
    }

    #[tokio::test]
    async fn control_frames_reject_oversized_payloads() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let oversized = "x".repeat(MAX_CONTROL_FRAME);
        let error = write_frame(&mut writer, &oversized).await.unwrap_err();
        assert!(error.contains("exceeds the protocol limit"));
    }

    #[test]
    fn remote_branch_advertisement_handles_unrelated_commit_histories() {
        let local_path =
            std::env::temp_dir().join(format!("sb_code_no_base_local_{}", uuid::Uuid::new_v4()));
        let remote_path =
            std::env::temp_dir().join(format!("sb_code_no_base_remote_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&local_path).unwrap();
        fs::create_dir_all(&remote_path).unwrap();
        let mut local = VcsEngine::init(&local_path).unwrap();
        local.set_project_name("no-base").unwrap();
        fs::write(local_path.join("lib.rs"), "pub fn local() {}\n").unwrap();
        local.commit("local root", "alice").unwrap();
        let local_head = local.branch_head_ids().unwrap().into_iter().next().unwrap();
        let local_known = crate::vcs::KnownBranchHead {
            branch: local_head.0,
            head_commit: local_head.1.clone(),
            ancestors: local.branch_ancestry_ids("main", 16).unwrap(),
        };
        let mut remote = VcsEngine::init(&remote_path).unwrap();
        remote.set_project_name("no-base").unwrap();
        fs::write(remote_path.join("lib.rs"), "pub fn remote() {}\n").unwrap();
        remote.commit("remote root", "bob").unwrap();

        let advertisements = remote.advertise_branch_heads(&[local_known]).unwrap();
        assert_eq!(advertisements.len(), 1);
        assert_eq!(advertisements[0].common_base, None);
        assert_eq!(advertisements[0].ahead_commits, None);
        assert!(advertisements[0].changed_scopes.is_empty());
        let _ = fs::remove_dir_all(local_path);
        let _ = fs::remove_dir_all(remote_path);
    }

    #[tokio::test]
    async fn multi_workspace_isolation_and_authoritative_single_writer() {
        let base_temp =
            std::env::temp_dir().join(format!("sb_multi_ws_test_{}", uuid::Uuid::new_v4()));
        let core_server = base_temp.join("server_core");
        let mesh_server = base_temp.join("server_mesh");
        let core_client = base_temp.join("client_core");
        let mesh_client = base_temp.join("client_mesh");
        fs::create_dir_all(&core_server).unwrap();
        fs::create_dir_all(&mesh_server).unwrap();
        fs::create_dir_all(&core_client).unwrap();
        fs::create_dir_all(&mesh_client).unwrap();

        let s_core_engine = VcsEngine::init(&core_server).unwrap();
        s_core_engine.set_project_name("sb-core").unwrap();
        let s_mesh_engine = VcsEngine::init(&mesh_server).unwrap();
        s_mesh_engine.set_project_name("sb-mesh").unwrap();

        let mut c_core_engine = VcsEngine::init(&core_client).unwrap();
        c_core_engine.set_project_name("sb-core").unwrap();
        fs::write(core_client.join("lib.rs"), "pub fn core_v1() {}\n").unwrap();
        let core_commit = c_core_engine.commit("core v1", "writer-core").unwrap();

        let mut c_mesh_engine = VcsEngine::init(&mesh_client).unwrap();
        c_mesh_engine.set_project_name("sb-mesh").unwrap();
        fs::write(mesh_client.join("lib.rs"), "pub fn mesh_v1() {}\n").unwrap();
        let _mesh_commit = c_mesh_engine.commit("mesh v1", "writer-mesh").unwrap();

        let mut registry = crate::dev_workspace::DevWorkspaceRegistry::new();
        let policy_core = crate::dev_workspace::DevWorkspacePolicy::new(
            "dev/tools/sb-core",
            "sb-core",
            "writer-core",
            vec!["replica-core".into()],
        )
        .unwrap();
        let policy_mesh = crate::dev_workspace::DevWorkspacePolicy::new(
            "dev/tools/sb-mesh",
            "sb-mesh",
            "writer-mesh",
            vec!["replica-mesh".into()],
        )
        .unwrap();

        registry
            .register(crate::dev_workspace::DevWorkspaceEntry {
                workspace_id: "dev/tools/sb-core".into(),
                repo_path: core_server.clone(),
                policy: policy_core,
            })
            .unwrap();
        registry
            .register(crate::dev_workspace::DevWorkspaceEntry {
                workspace_id: "dev/tools/sb-mesh".into(),
                repo_path: mesh_server.clone(),
                policy: policy_mesh,
            })
            .unwrap();

        let shared_registry = std::sync::Arc::new(registry);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let reg_server = shared_registry.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let r = reg_server.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection_with_registry(stream, &r).await;
                    });
                } else {
                    break;
                }
            }
        });

        // Test 1: writer-core can push to dev/tools/sb-core
        let mut stream1 = TcpStream::connect(address).await.unwrap();
        let report1 = push_workspace_over_stream(
            &mut stream1,
            &c_core_engine,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-core"),
            Some("writer-core"),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report1.new_head, core_commit.commit_id);

        // Test 2: writer-mesh CANNOT push to dev/tools/sb-core (cross-workspace permission deny)
        let mut stream2 = TcpStream::connect(address).await.unwrap();
        let err2 = push_workspace_over_stream(
            &mut stream2,
            &c_mesh_engine,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-core"),
            Some("writer-mesh"),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(err2.contains("Access Denied"));
        assert!(err2.contains("not the authoritative writer"));

        // Test 3: Unauthorized node cannot pull from dev/tools/sb-core
        let mut pull_dest = VcsEngine::init(&base_temp.join("unauth_pull")).unwrap();
        pull_dest.set_project_name("sb-core").unwrap();
        let mut stream3 = TcpStream::connect(address).await.unwrap();
        let err3 = pull_workspace_over_stream(
            &mut stream3,
            &mut pull_dest,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-core"),
            Some("intruder-node"),
            None,
        )
        .await
        .unwrap_err();
        assert!(err3.contains("Access Denied"));

        // Test 4: Authorized replica-core CAN pull from dev/tools/sb-core
        let mut replica_engine = VcsEngine::init(&base_temp.join("replica_pull")).unwrap();
        replica_engine.set_project_name("sb-core").unwrap();
        let mut stream4 = TcpStream::connect(address).await.unwrap();
        let report4 = pull_workspace_over_stream(
            &mut stream4,
            &mut replica_engine,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-core"),
            Some("replica-core"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report4.new_head, core_commit.commit_id);

        // Test 5: CAS Divergence detection with expected_head
        fs::write(core_client.join("lib.rs"), "pub fn core_v2() {}\n").unwrap();
        let _core_commit2 = c_core_engine.commit("core v2", "writer-core").unwrap();
        let mut stream5 = TcpStream::connect(address).await.unwrap();
        let err5 = push_workspace_over_stream(
            &mut stream5,
            &c_core_engine,
            "dev-mesh",
            "main",
            Some("dev/tools/sb-core"),
            Some("writer-core"),
            Some("wrong-expected-head-hash"),
            None,
        )
        .await
        .unwrap_err();
        assert!(err5.contains("Divergent head detected"));

        let _ = fs::remove_dir_all(base_temp);
    }
}
