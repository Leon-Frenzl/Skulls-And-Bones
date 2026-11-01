use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::fastcdc::{compare_manifests, ChunkManifest, DeduplicationStats, FastCdc};
use crate::sync::{FileEntry, FileTreeSnapshot};

/// A single line change in a diff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineDiff {
    pub change_type: String, // "+", "-", " "
    pub old_line_num: Option<usize>,
    pub new_line_num: Option<usize>,
    pub text: String,
}

/// Diff summary for a specific file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    pub rel_path: String,
    pub status: String, // "modified", "added", "deleted", "identical"
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub lines: Vec<LineDiff>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitShow {
    pub commit: VcsCommit,
    pub parent_commit_id: Option<String>,
    pub changes: Vec<FileDiff>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeHistoryEntry {
    pub commit_id: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
    pub content_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeHistory {
    pub file_path: String,
    pub target: String,
    pub scope_id: String,
    pub changes: Vec<ScopeHistoryEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeDiffEntry {
    pub file_path: String,
    pub scope_id: String,
    pub name: String,
    pub status: String,
    pub old_start_line: Option<usize>,
    pub old_end_line: Option<usize>,
    pub new_start_line: Option<usize>,
    pub new_end_line: Option<usize>,
}

/// A tree object mapping relative paths to file metadata and blob hashes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcsTree {
    #[serde(default = "legacy_vcs_format_version")]
    pub format_version: u32,
    pub tree_hash: String,
    pub entries: HashMap<String, FileEntry>,
}

/// A content-addressed commit; signatures are optional until lease signing is wired.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcsCommit {
    #[serde(default = "legacy_vcs_format_version")]
    pub format_version: u32,
    pub commit_id: String,
    pub parent_ids: Vec<String>,
    pub tree_hash: String,
    pub author_callsign: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    #[serde(default)]
    pub signature_ed25519: Option<String>,
    #[serde(default)]
    pub ast_scopes: Vec<AstScopeSnapshot>,
    #[serde(default)]
    pub ast_parser_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstScopeSnapshot {
    pub scope_id: String,
    pub file_path: String,
    pub name: String,
    pub kind: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content_hash: String,
    pub ambiguous: bool,
    #[serde(
        default = "legacy_ast_parser_id",
        skip_serializing_if = "is_legacy_ast_parser_id"
    )]
    pub parser_id: String,
    #[serde(default, skip_serializing_if = "is_legacy_ast_parser_version")]
    pub parser_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_diagnostic: Option<String>,
}

fn legacy_ast_parser_id() -> String {
    "legacy-heuristic".to_string()
}

fn is_legacy_ast_parser_id(parser_id: &str) -> bool {
    parser_id == "legacy-heuristic"
}

fn is_legacy_ast_parser_version(version: &u32) -> bool {
    *version == 0
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeBranchChange {
    pub scope_id: String,
    pub file_path: String,
    pub name: String,
    pub status: String,
    pub base: Option<String>,
    pub current: Option<String>,
    pub other: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_diagnostic: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchScopeComparison {
    pub current_branch: String,
    pub other_branch: String,
    pub base_commit: String,
    pub current_commit: String,
    pub other_commit: String,
    pub changes: Vec<ScopeBranchChange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationPlanEntry {
    pub change: ScopeBranchChange,
    pub action: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationPlan {
    pub current_branch: String,
    pub other_branch: String,
    pub base_commit: String,
    pub current_commit: String,
    pub other_commit: String,
    pub ast_parser_version: u32,
    pub auto_mergeable: Vec<IntegrationPlanEntry>,
    pub manual_required: Vec<IntegrationPlanEntry>,
    pub blocked_reasons: Vec<String>,
    pub test_scope_candidates: Vec<String>,
    pub test_scope_basis: String,
    pub semantic_validation: String,
    pub workspace_clean: bool,
    pub ready_to_integrate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    Current,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationConflict {
    pub entry: IntegrationPlanEntry,
    pub resolution: Option<ConflictResolution>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationConflictState {
    pub format_version: u32,
    pub current_branch: String,
    pub other_branch: String,
    pub base_commit: String,
    pub current_commit: String,
    pub other_commit: String,
    pub conflicts: Vec<IntegrationConflict>,
}

impl VcsCommit {
    /// Signiert den Commit mit einem Ed25519-Schlüssel.
    /// Die Signatur wird über die kanonische `commit_id` gebildet und als
    /// `ed25519:<pubkey_hex>:<sig_hex>` im Feld `signature_ed25519` hinterlegt.
    pub fn sign(&mut self, key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let signature = key.sign(self.commit_id.as_bytes());
        let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());
        self.signature_ed25519 = Some(format!("ed25519:{}:{}", pubkey_hex, sig_hex));
    }

    /// Verifiziert die kryptographische Ed25519-Signatur dieses Commits.
    /// Gibt bei Erfolg den öffentlichen Schlüssel des Signierers zurück.
    pub fn verify_signature(&self) -> Result<ed25519_dalek::VerifyingKey, String> {
        let sig_str = match &self.signature_ed25519 {
            Some(s) => s.as_str(),
            None => return Err("Keine Signatur vorhanden".to_string()),
        };
        if sig_str.starts_with("ed25519_sig_") {
            return Err("Legacy-Platzhalter; nicht kryptographisch signiert".to_string());
        }
        let raw = sig_str.strip_prefix("ed25519:").unwrap_or(sig_str);
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 2 {
            return Err(
                "Ungültiges Signaturformat; erwartet 'ed25519:<pubkey_hex>:<signature_hex>'"
                    .to_string(),
            );
        }
        let pubkey_bytes =
            hex::decode(parts[0]).map_err(|e| format!("Ungültiger Public Key Hex: {}", e))?;
        if pubkey_bytes.len() != 32 {
            return Err("Public Key muss genau 32 Bytes lang sein".to_string());
        }
        let sig_bytes =
            hex::decode(parts[1]).map_err(|e| format!("Ungültiger Signatur Hex: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err("Ed25519-Signatur muss genau 64 Bytes lang sein".to_string());
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| format!("Ungültiger VerifyingKey: {}", e))?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("Ungültige Signatur-Bytes: {}", e))?;

        verifying_key
            .verify_strict(self.commit_id.as_bytes(), &signature)
            .map_err(|_| "Kryptographische Ed25519-Signaturprüfung fehlgeschlagen".to_string())?;

        Ok(verifying_key)
    }

    /// Gibt den öffentlichen Schlüssel des Signierers zurück, falls vorhanden.
    pub fn signer_pubkey(&self) -> Option<String> {
        let sig_str = self.signature_ed25519.as_deref()?;
        let raw = sig_str.strip_prefix("ed25519:").unwrap_or(sig_str);
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() == 2 && parts[0].len() == 64 {
            Some(parts[0].to_string())
        } else {
            None
        }
    }

    pub fn signature_status(&self) -> &'static str {
        match self.signature_ed25519.as_deref() {
            Some(signature) if signature.starts_with("ed25519_sig_") => {
                "Legacy-Platzhalter; nicht kryptographisch signiert"
            }
            Some(_) => match self.verify_signature() {
                Ok(_) => "Ed25519 verifiziert (valide)",
                Err(_) => "Ed25519 Signatur ungültig",
            },
            None => "nicht signiert",
        }
    }
}

/// Status of a file in the working directory compared to HEAD.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStatus {
    pub rel_path: String,
    pub status: String, // "modified", "added", "deleted"
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub size_bytes: u64,
}

/// Overall repository status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcsStatus {
    pub current_branch: String,
    pub head_commit: Option<VcsCommit>,
    pub is_clean: bool,
    pub modified_count: usize,
    pub added_count: usize,
    pub deleted_count: usize,
    pub changes: Vec<FileStatus>,
}

/// Statistics for a specific category of repository objects.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectTypeStats {
    pub count: usize,
    pub total_bytes: u64,
}

/// Overall storage and deduplication statistics for the sovereign repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcsStorageStats {
    pub workspace_root: String,
    pub active_branch: String,
    pub head_commit_id: Option<String>,
    pub total_vcs_bytes: u64,
    pub blobs: ObjectTypeStats,
    pub chunks: ObjectTypeStats,
    pub chunk_manifests: ObjectTypeStats,
    pub trees: ObjectTypeStats,
    pub commits: ObjectTypeStats,
    pub total_objects: usize,
    pub average_commit_bytes: u64,
    pub deduplication_ratio: Option<f64>,
    pub raw_blob_bytes: u64,
}

/// A scope entry in the repository churn and heatmap analysis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeHeatmapEntry {
    pub scope_id: String,
    pub name: String,
    pub file_path: String,
    pub kind: String,
    pub change_count: usize,
    pub status: String, // "🔥 HOT", "🟡 WARM", "🟢 STABLE"
}

/// A file entry with high churn in the repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileHeatmapEntry {
    pub file_path: String,
    pub change_count: usize,
}

/// Full AST scope churn and heatmap report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeHeatmapReport {
    pub commits_analyzed: usize,
    pub total_scopes_tracked: usize,
    pub hot_scopes: Vec<ScopeHeatmapEntry>,
    pub hot_files: Vec<FileHeatmapEntry>,
}

/// Report after performing a rollback.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackReport {
    pub previous_commit_id: String,
    pub target_commit_id: String,
    pub branch: String,
    pub single_file: Option<String>,
    pub message: String,
}

/// Outline item representing an AST structure in a source file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeOutlineItem {
    pub name: String,
    pub kind: String,
    pub signature: String,
    pub start_line: usize,
    pub end_line: usize,
    pub is_container: bool,
}

/// Structural outline of a source module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleOutline {
    pub file_path: String,
    pub total_lines: usize,
    pub items: Vec<ScopeOutlineItem>,
}

/// Logical co-change coupling between two files in the repository history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileCoupling {
    pub file_a: String,
    pub file_b: String,
    pub co_changes: usize,
    pub confidence_a_to_b: f64,
    pub confidence_b_to_a: f64,
}

/// Report summarizing historical co-change couplings across commits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CouplingReport {
    pub commits_analyzed: usize,
    pub target_filter: Option<String>,
    pub couplings: Vec<FileCoupling>,
}

/// Remote sync status compared to a P2P Swarm Anchor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcsRemoteStatus {
    pub anchor: String,
    pub branch: String,
    pub local_head: Option<String>,
    pub remote_head: Option<String>,
    pub ahead: usize,
    pub behind: usize,
    pub in_sync: bool,
}

/// Sync report after push or pull operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcsSyncReport {
    pub branch: String,
    pub anchor: String,
    pub commits_synced: usize,
    pub blobs_synced: usize,
    pub old_head: Option<String>,
    pub new_head: String,
    pub message: String,
}

/// Manifest inside an exported Merkle bundle (.tar.gz).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcsBundleManifest {
    pub branch: String,
    pub head_commit_id: String,
    pub commits_count: usize,
    pub blobs_count: usize,
    pub exported_at: String,
}

/// Pure-Rust Sovereign VCS Engine.
pub struct VcsEngine {
    workspace_root: PathBuf,
    vcs_dir: PathBuf,
    workspace_head_path: PathBuf,
    workspace_base_path: Option<PathBuf>,
    workspace_ports: Option<WorkspacePortAssignments>,
    chunk_index: Mutex<Option<HashMap<String, ChunkLocation>>>,
}

#[derive(Clone, Debug)]
struct ChunkLocation {
    blob_hash: String,
    offset: usize,
    length: usize,
}

const MAX_COMMIT_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspacePortAssignments {
    pub base: u16,
    pub code_sync: u16,
    pub drive_sync: u16,
    pub ast_lock_sync: u16,
    pub dev_server: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedWorkspace {
    pub format_version: u32,
    pub id: String,
    pub path: PathBuf,
    pub repository_vcs_dir: PathBuf,
    pub branch: String,
    pub ports: WorkspacePortAssignments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedScopeSummary {
    pub scope_id: String,
    pub file_path: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchDivergence {
    pub branch: String,
    pub local_head: Option<String>,
    pub remote_head: String,
    pub common_base: Option<String>,
    pub local_commits: Option<usize>,
    pub remote_commits: Option<usize>,
    pub overlapping_scopes: Vec<ChangedScopeSummary>,
    pub comparison_note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchRadarReport {
    pub remote_branch_count: usize,
    pub divergences: Vec<BranchDivergence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchHeadAdvertisement {
    pub branch: String,
    pub head_commit: String,
    pub known_head: Option<String>,
    pub common_base: Option<String>,
    pub ahead_commits: Option<usize>,
    pub changed_scopes: Vec<ChangedScopeSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownBranchHead {
    pub branch: String,
    pub head_commit: String,
    pub ancestors: Vec<String>,
}

fn with_branch_ref_lock<T>(
    vcs_dir: &Path,
    branch: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let lock_dir = vcs_dir.join("refs").join("locks");
    fs::create_dir_all(&lock_dir)
        .map_err(|error| format!("Could not create branch ref lock directory: {error}"))?;
    let lock_path = lock_dir.join(format!("{branch}.lock"));
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .map_err(|error| format!("Could not open branch ref lock: {error}"))?;
    let mut lock = fd_lock::RwLock::new(file);
    let _guard = lock
        .write()
        .map_err(|error| format!("Could not lock branch '{branch}' ref: {error}"))?;
    operation()
}

fn with_workspace_registry_lock<T>(
    registry_dir: &Path,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    fs::create_dir_all(registry_dir)
        .map_err(|error| format!("Could not create workspace registry: {error}"))?;
    let lock_path = registry_dir.join(".ports.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .map_err(|error| format!("Could not open workspace registry lock: {error}"))?;
    let mut lock = fd_lock::RwLock::new(file);
    let _guard = lock
        .write()
        .map_err(|error| format!("Could not lock workspace registry: {error}"))?;
    operation()
}

fn allocate_workspace_ports(registry_dir: &Path) -> Result<WorkspacePortAssignments, String> {
    const FIRST_PORT: u16 = 59_000;
    const PORT_STRIDE: u16 = 4;
    const LAST_BASE: u16 = 65_532;
    let mut occupied = HashSet::new();
    for entry in fs::read_dir(registry_dir)
        .map_err(|error| format!("Could not inspect workspace port registry: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("Could not read workspace port reservation: {error}"))?;
        if entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("json")
        {
            continue;
        }
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("Could not read workspace port reservation: {error}"))?;
        let workspace: ManagedWorkspace = serde_json::from_slice(&bytes)
            .map_err(|error| format!("Invalid workspace port reservation: {error}"))?;
        occupied.insert(workspace.ports.base);
    }
    let mut base = FIRST_PORT;
    while base <= LAST_BASE {
        if !occupied.contains(&base) {
            return Ok(WorkspacePortAssignments {
                base,
                code_sync: base,
                drive_sync: base + 1,
                ast_lock_sync: base + 2,
                dev_server: base + 3,
            });
        }
        base = base.saturating_add(PORT_STRIDE);
    }
    Err("No isolated managed-workspace port range is available".into())
}

fn legacy_vcs_format_version() -> u32 {
    1
}

fn is_object_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn commit_object_path(commits_dir: &Path, commit_id: &str) -> PathBuf {
    let compressed = commits_dir.join(format!("{commit_id}.json.gz"));
    if compressed.exists() {
        compressed
    } else {
        commits_dir.join(format!("{commit_id}.json"))
    }
}

fn read_commit_object(path: &Path, commit_id: &str) -> Result<VcsCommit, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("Failed to open commit {commit_id}: {error}"))?;
    let mut content = Vec::new();
    if path.extension().is_some_and(|extension| extension == "gz") {
        let mut decoder = flate2::read::GzDecoder::new(file).take(MAX_COMMIT_OBJECT_BYTES + 1);
        decoder
            .read_to_end(&mut content)
            .map_err(|error| format!("Failed to decompress commit {commit_id}: {error}"))?;
    } else {
        file.take(MAX_COMMIT_OBJECT_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|error| format!("Failed to read commit {commit_id}: {error}"))?;
    }
    if content.len() as u64 > MAX_COMMIT_OBJECT_BYTES {
        return Err(format!(
            "Commit object {commit_id} exceeds the permitted decompressed size"
        ));
    }
    serde_json::from_slice(&content)
        .map_err(|error| format!("Corrupted commit object {commit_id}: {error}"))
}

fn write_commit_object(commits_dir: &Path, commit: &VcsCommit) -> Result<(), String> {
    let path = commits_dir.join(format!("{}.json.gz", commit.commit_id));
    let content = serde_json::to_vec(commit)
        .map_err(|error| format!("Failed to serialize commit: {error}"))?;
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(&content)
        .map_err(|error| format!("Failed to compress commit: {error}"))?;
    let compressed = encoder
        .finish()
        .map_err(|error| format!("Failed to finish compressed commit: {error}"))?;
    atomicwrites::AtomicFile::new(&path, atomicwrites::AllowOverwrite)
        .write(|file| file.write_all(&compressed))
        .map_err(|error| format!("Failed to write compressed commit atomically: {error}"))
}

fn is_valid_branch_name(value: &str) -> bool {
    value.len() <= 128
        && value != "."
        && value != ".."
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !is_windows_reserved_component(value)
}

fn normalize_commit_selector(value: &str) -> Result<String, String> {
    if value.starts_with(['/', '\\']) {
        return Err(format!(
            "Invalid repository-relative path selector '{value}'"
        ));
    }
    let normalized = value.replace('\\', "/").trim_end_matches('/').to_string();
    let path = Path::new(&normalized);
    if normalized.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "Invalid repository-relative path selector '{value}'"
        ));
    }
    Ok(normalized)
}

fn path_matches_selector(path: &str, selector: &str) -> bool {
    path == selector
        || path
            .strip_prefix(selector)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn stage_scope_changes(
    file_path: &str,
    base_content: &[u8],
    working_content: &[u8],
    targets: &[String],
) -> Result<Vec<u8>, String> {
    let base_source = std::str::from_utf8(base_content)
        .map_err(|_| format!("Cannot select AST scopes in binary file '{file_path}'"))?;
    let working_source = std::str::from_utf8(working_content)
        .map_err(|_| format!("Cannot select AST scopes in binary file '{file_path}'"))?;
    let base_scopes = capture_ast_scopes(file_path, base_source)?;
    let working_scopes = capture_ast_scopes(file_path, working_source)?;
    if base_scopes
        .iter()
        .any(|scope| scope.parser_diagnostic.is_some())
        || working_scopes
            .iter()
            .any(|scope| scope.parser_diagnostic.is_some())
    {
        return Err(format!(
            "Cannot safely select scopes in '{file_path}' while either version has parser errors"
        ));
    }
    let mut base_lines = base_source.split_inclusive('\n').collect::<Vec<_>>();
    let working_lines = working_source.split_inclusive('\n').collect::<Vec<_>>();
    let mut edits = Vec::<(usize, usize, Vec<&str>, String)>::new();
    for target in targets {
        let base_matches = base_scopes
            .iter()
            .filter(|scope| {
                scope.kind != "opaque"
                    && (scope.scope_id == *target
                        || scope.name == *target
                        || scope.scope_id.contains(target)
                        || scope.name.contains(target))
            })
            .collect::<Vec<_>>();
        if base_matches.len() != 1 {
            return Err(if base_matches.is_empty() {
                format!(
                    "Scope '{target}' is not present in HEAD for '{file_path}'; new scopes must be committed with --only"
                )
            } else {
                format!("Scope '{target}' is ambiguous in '{file_path}'; use its complete scope ID")
            });
        }
        let base_scope = base_matches[0];
        let start = base_scope.start_line.saturating_sub(1);
        let end = base_scope.end_line;
        if start >= end || end > base_lines.len() {
            return Err(format!(
                "Invalid HEAD source range for scope '{}' in '{file_path}'",
                base_scope.name
            ));
        }
        let working_scope = working_scopes
            .iter()
            .find(|scope| scope.scope_id == base_scope.scope_id && scope.kind != "opaque");
        let replacement = if let Some(scope) = working_scope {
            let working_start = scope.start_line.saturating_sub(1);
            let working_end = scope.end_line;
            if working_start >= working_end || working_end > working_lines.len() {
                return Err(format!(
                    "Invalid working source range for scope '{}' in '{file_path}'",
                    scope.name
                ));
            }
            working_lines[working_start..working_end].to_vec()
        } else {
            Vec::new()
        };
        edits.push((start, end, replacement, base_scope.name.clone()));
    }
    edits.sort_by_key(|(start, _, _, _)| *start);
    if edits.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(format!(
            "Selected AST scopes overlap in '{file_path}'; select their containing scope instead"
        ));
    }
    edits.sort_by_key(|(start, _, _, _)| std::cmp::Reverse(*start));
    for (start, end, replacement, _) in edits {
        base_lines.splice(start..end, replacement);
    }
    Ok(base_lines.concat().into_bytes())
}

fn is_windows_reserved_component(component: &str) -> bool {
    matches!(
        component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase()
            .as_str(),
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

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn capture_ast_scopes(file_path: &str, content: &str) -> Result<Vec<AstScopeSnapshot>, String> {
    let parsed = crate::language::parse_source(file_path, content)?;
    capture_scope_snapshots(
        file_path,
        content,
        parsed.scopes,
        &parsed.parser_id,
        parsed.parser_version,
        parsed.parser_diagnostic.as_deref(),
    )
}

fn capture_ast_scopes_v2(file_path: &str, content: &str) -> Result<Vec<AstScopeSnapshot>, String> {
    capture_scope_snapshots(
        file_path,
        content,
        crate::ast::parse_ast_scopes_with_opaque(file_path, content),
        "legacy-heuristic",
        0,
        None,
    )
}

fn capture_scope_snapshots(
    file_path: &str,
    content: &str,
    scopes: Vec<crate::ast::AstScope>,
    parser_id: &str,
    parser_version: u32,
    parser_diagnostic: Option<&str>,
) -> Result<Vec<AstScopeSnapshot>, String> {
    let mut recognized_totals = HashMap::<String, usize>::new();
    for scope in scopes
        .iter()
        .filter(|scope| scope.kind != crate::ast::AstScopeKind::Opaque)
    {
        if let Some((base_id, occurrence)) = scope.id.rsplit_once('#') {
            if occurrence.parse::<usize>().is_ok() {
                *recognized_totals.entry(base_id.to_string()).or_default() += 1;
            }
        }
    }
    let lines = content.split_inclusive('\n').collect::<Vec<_>>();
    scopes
        .into_iter()
        .map(|scope| {
            let start = scope
                .start_line
                .checked_sub(1)
                .ok_or_else(|| format!("Invalid AST start line for '{}'", scope.id))?;
            let end = scope.end_line;
            if end > lines.len() || start >= end {
                return Err(format!("Invalid AST line range for '{}'", scope.id));
            }
            let raw = lines[start..end].concat();
            let ambiguous = scope
                .id
                .rsplit_once('#')
                .filter(|(_, occurrence)| occurrence.parse::<usize>().is_ok())
                .and_then(|(base_id, _)| recognized_totals.get(base_id))
                .is_some_and(|total| *total > 1);
            Ok(AstScopeSnapshot {
                scope_id: scope.id,
                file_path: file_path.to_string(),
                name: scope.name,
                kind: scope.kind.to_string(),
                start_line: scope.start_line,
                end_line: scope.end_line,
                content_hash: blake3::hash(raw.as_bytes()).to_hex().to_string(),
                ambiguous,
                parser_id: parser_id.to_string(),
                parser_version,
                parser_diagnostic: parser_diagnostic.map(str::to_string),
            })
        })
        .collect()
}

fn capture_ast_scopes_v1(file_path: &str, content: &str) -> Result<Vec<AstScopeSnapshot>, String> {
    let scopes = crate::ast::parse_ast_scopes(file_path, content)
        .into_iter()
        .filter(|scope| !scope.is_container)
        .collect::<Vec<_>>();
    let mut totals = HashMap::<String, usize>::new();
    for scope in &scopes {
        *totals.entry(scope.id.clone()).or_default() += 1;
    }
    let mut occurrences = HashMap::<String, usize>::new();
    let lines = content.split_inclusive('\n').collect::<Vec<_>>();
    scopes
        .into_iter()
        .map(|scope| {
            let start = scope
                .start_line
                .checked_sub(1)
                .ok_or_else(|| format!("Invalid AST start line for '{}'", scope.id))?;
            let end = scope.end_line;
            if end > lines.len() || start >= end {
                return Err(format!("Invalid AST line range for '{}'", scope.id));
            }
            let raw = lines[start..end].concat();
            let occurrence = occurrences.entry(scope.id.clone()).or_default();
            let scope_id = format!("{}#{}", scope.id, *occurrence);
            *occurrence += 1;
            Ok(AstScopeSnapshot {
                scope_id,
                file_path: file_path.to_string(),
                name: scope.name,
                kind: scope.kind.to_string(),
                start_line: scope.start_line,
                end_line: scope.end_line,
                content_hash: blake3::hash(raw.as_bytes()).to_hex().to_string(),
                ambiguous: totals.get(&scope.id).copied().unwrap_or_default() > 1,
                parser_id: "legacy-heuristic".to_string(),
                parser_version: 0,
                parser_diagnostic: None,
            })
        })
        .collect()
}

fn compute_tree_id(tree: &VcsTree) -> Result<String, String> {
    for (path, entry) in &tree.entries {
        if !is_safe_tree_path(path) || entry.rel_path != *path {
            return Err(format!("Invalid or non-canonical tree path: {}", path));
        }
        if entry.is_dir {
            if entry.blake3_hash != "directory" || entry.size_bytes != 0 {
                return Err(format!("Invalid directory entry: {}", path));
            }
        } else if !is_object_id(&entry.blake3_hash) {
            return Err(format!("Invalid blob ID in tree entry: {}", path));
        }
    }

    match tree.format_version {
        1 => {
            let mut hashes: Vec<&str> = tree
                .entries
                .values()
                .map(|entry| entry.blake3_hash.as_str())
                .collect();
            hashes.sort_unstable();
            let mut hasher = blake3::Hasher::new();
            for hash in hashes {
                hasher.update(hash.as_bytes());
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        2 => {
            let mut entries: Vec<_> = tree.entries.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"sb-code-tree-v2\0");
            for (path, entry) in entries {
                hash_field(&mut hasher, path.as_bytes());
                hasher.update(&[u8::from(entry.is_dir)]);
                hasher.update(&entry.size_bytes.to_be_bytes());
                hash_field(&mut hasher, entry.blake3_hash.as_bytes());
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        version => Err(format!("Unsupported tree format version: {}", version)),
    }
}

fn is_safe_tree_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.ends_with('.')
                && !component.ends_with(' ')
                && !component
                    .chars()
                    .any(|character| character.is_control() || "<>:\"|?*\\/".contains(character))
                && !is_windows_reserved_component(component)
        })
}

// CVE-Threat: Imported paths could escape through a pre-existing workspace symlink.
// Analysis: Lexical path checks alone do not constrain filesystem resolution.
// Hardening: Inspect every existing parent and target with symlink_metadata before reads or writes.
fn safe_workspace_file_path(
    workspace_root: &Path,
    rel_path: &str,
    create_parents: bool,
) -> Result<PathBuf, String> {
    if !is_safe_tree_path(rel_path) {
        return Err("Invalid workspace-relative file path".to_string());
    }

    let components: Vec<_> = rel_path.split('/').collect();
    let mut parent = workspace_root.to_path_buf();
    for component in &components[..components.len() - 1] {
        parent.push(component);
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(format!(
                    "Workspace path traverses a symlink or non-directory: {}",
                    parent.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create_parents => {
                fs::create_dir(&parent)
                    .map_err(|error| format!("Failed to create workspace directory: {}", error))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(workspace_root.join(rel_path));
            }
            Err(error) => {
                return Err(format!("Failed to inspect workspace path: {}", error));
            }
        }
    }

    let full_path = workspace_root.join(rel_path);
    match fs::symlink_metadata(&full_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "Workspace target is a symlink or non-file: {}",
            rel_path
        )),
        Ok(_) => Ok(full_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(full_path),
        Err(error) => Err(format!("Failed to inspect workspace target: {}", error)),
    }
}

fn compute_commit_id(commit: &VcsCommit) -> Result<String, String> {
    match commit.format_version {
        1 => {
            let mut hasher = blake3::Hasher::new();
            for parent in &commit.parent_ids {
                hasher.update(parent.as_bytes());
            }
            hasher.update(commit.tree_hash.as_bytes());
            hasher.update(commit.author_callsign.as_bytes());
            hasher.update(commit.timestamp.to_rfc3339().as_bytes());
            hasher.update(commit.message.as_bytes());
            Ok(hasher.finalize().to_hex().to_string())
        }
        2 => {
            if !is_object_id(&commit.tree_hash)
                || commit.parent_ids.iter().any(|parent| !is_object_id(parent))
            {
                return Err("Invalid tree or parent ID in commit".to_string());
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"sb-code-commit-v2\0");
            hasher.update(&(commit.parent_ids.len() as u64).to_be_bytes());
            for parent in &commit.parent_ids {
                hash_field(&mut hasher, parent.as_bytes());
            }
            hash_field(&mut hasher, commit.tree_hash.as_bytes());
            hash_field(&mut hasher, commit.author_callsign.as_bytes());
            hasher.update(&commit.timestamp.timestamp().to_be_bytes());
            hasher.update(&commit.timestamp.timestamp_subsec_nanos().to_be_bytes());
            hash_field(&mut hasher, commit.message.as_bytes());
            Ok(hasher.finalize().to_hex().to_string())
        }
        3 => {
            if !is_object_id(&commit.tree_hash)
                || commit.parent_ids.iter().any(|parent| !is_object_id(parent))
            {
                return Err("Invalid tree or parent ID in commit".to_string());
            }
            let mut scopes = commit.ast_scopes.iter().collect::<Vec<_>>();
            scopes.sort_by(|left, right| left.scope_id.cmp(&right.scope_id));
            if scopes
                .windows(2)
                .any(|pair| pair[0].scope_id == pair[1].scope_id)
            {
                return Err("Duplicate AST scope identity in commit".to_string());
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"sb-code-commit-v3\0");
            hasher.update(&(commit.parent_ids.len() as u64).to_be_bytes());
            for parent in &commit.parent_ids {
                hash_field(&mut hasher, parent.as_bytes());
            }
            hash_field(&mut hasher, commit.tree_hash.as_bytes());
            hash_field(&mut hasher, commit.author_callsign.as_bytes());
            hasher.update(&commit.timestamp.timestamp().to_be_bytes());
            hasher.update(&commit.timestamp.timestamp_subsec_nanos().to_be_bytes());
            hash_field(&mut hasher, commit.message.as_bytes());
            hasher.update(&commit.ast_parser_version.to_be_bytes());
            hasher.update(&(scopes.len() as u64).to_be_bytes());
            for scope in scopes {
                hash_field(&mut hasher, scope.scope_id.as_bytes());
                hash_field(&mut hasher, scope.file_path.as_bytes());
                hash_field(&mut hasher, scope.name.as_bytes());
                hash_field(&mut hasher, scope.kind.as_bytes());
                hasher.update(&(scope.start_line as u64).to_be_bytes());
                hasher.update(&(scope.end_line as u64).to_be_bytes());
                hash_field(&mut hasher, scope.content_hash.as_bytes());
                hasher.update(&[u8::from(scope.ambiguous)]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        version => Err(format!("Unsupported commit format version: {}", version)),
    }
}

impl VcsEngine {
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Initialize a new Sovereign VCS repository in `workspace_root`.
    pub fn init(workspace_root: &Path) -> Result<Self, String> {
        let vcs_dir = workspace_root.join(".sb").join("vcs");
        fs::create_dir_all(vcs_dir.join("objects").join("blobs"))
            .map_err(|e| format!("Failed to create blobs dir: {}", e))?;
        fs::create_dir_all(vcs_dir.join("objects").join("chunks"))
            .map_err(|e| format!("Failed to create chunks dir: {}", e))?;
        fs::create_dir_all(vcs_dir.join("objects").join("chunk_manifests"))
            .map_err(|e| format!("Failed to create chunk_manifests dir: {}", e))?;
        fs::create_dir_all(vcs_dir.join("objects").join("trees"))
            .map_err(|e| format!("Failed to create trees dir: {}", e))?;
        fs::create_dir_all(vcs_dir.join("objects").join("commits"))
            .map_err(|e| format!("Failed to create commits dir: {}", e))?;
        fs::create_dir_all(vcs_dir.join("refs").join("heads"))
            .map_err(|e| format!("Failed to create refs dir: {}", e))?;

        let workspace_head_path = workspace_root.join(".sb").join("HEAD");
        if !workspace_head_path.exists() {
            let legacy_head = vcs_dir.join("HEAD");
            let head = if legacy_head.exists() {
                fs::read_to_string(legacy_head)
                    .map_err(|error| format!("Failed to migrate legacy HEAD: {error}"))?
            } else {
                "ref: refs/heads/main\n".to_string()
            };
            fs::write(&workspace_head_path, head)
                .map_err(|e| format!("Failed to write workspace HEAD: {}", e))?;
        }

        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            vcs_dir,
            workspace_head_path,
            workspace_base_path: None,
            workspace_ports: None,
            chunk_index: Mutex::new(None),
        })
    }

    /// Open an existing Sovereign VCS repository.
    pub fn open(workspace_root: &Path) -> Result<Self, String> {
        let workspace_metadata_path = workspace_root.join(".sb").join("workspace.json");
        let managed_workspace = if workspace_metadata_path.is_file() {
            let bytes = fs::read(&workspace_metadata_path)
                .map_err(|error| format!("Failed to read managed workspace metadata: {error}"))?;
            let managed: ManagedWorkspace = serde_json::from_slice(&bytes)
                .map_err(|error| format!("Invalid managed workspace metadata: {error}"))?;
            if managed.format_version != 1 {
                return Err(format!(
                    "Unsupported managed workspace metadata version: {}",
                    managed.format_version
                ));
            }
            if uuid::Uuid::parse_str(&managed.id).is_err()
                || !is_valid_branch_name(&managed.branch)
                || managed.ports.base < 59_000
                || managed.ports.base > 65_532
                || managed.ports.code_sync != managed.ports.base
                || managed.ports.drive_sync != managed.ports.base.saturating_add(1)
                || managed.ports.ast_lock_sync != managed.ports.base.saturating_add(2)
                || managed.ports.dev_server != managed.ports.base.saturating_add(3)
            {
                return Err(
                    "Managed workspace metadata contains invalid identity, branch, or ports".into(),
                );
            }
            let canonical_workspace = workspace_root
                .canonicalize()
                .map_err(|error| format!("Could not canonicalize workspace root: {error}"))?;
            let recorded_workspace = managed
                .path
                .canonicalize()
                .map_err(|error| format!("Managed workspace path is unavailable: {error}"))?;
            if canonical_workspace != recorded_workspace {
                return Err(
                    "Managed workspace metadata points at a different working directory".into(),
                );
            }
            let canonical_vcs_dir = managed
                .repository_vcs_dir
                .canonicalize()
                .map_err(|error| format!("Managed VCS object store is unavailable: {error}"))?;
            if canonical_vcs_dir.file_name().and_then(|name| name.to_str()) != Some("vcs")
                || canonical_vcs_dir
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    != Some(".sb")
                || !canonical_vcs_dir.join("objects").is_dir()
                || !canonical_vcs_dir.join("refs").join("heads").is_dir()
            {
                return Err(
                    "Managed workspace VCS path is not a valid sb-code object store".into(),
                );
            }
            Some(managed)
        } else {
            None
        };
        let vcs_dir = managed_workspace
            .as_ref()
            .map(|managed| managed.repository_vcs_dir.clone())
            .unwrap_or_else(|| workspace_root.join(".sb").join("vcs"));
        if !vcs_dir.exists() {
            return Err(
                "Sovereign VCS is not initialized in this workspace. Run 'sb code init' first."
                    .to_string(),
            );
        }
        let workspace_head_path = workspace_root.join(".sb").join("HEAD");
        let workspace_base_path = managed_workspace
            .as_ref()
            .map(|_| workspace_root.join(".sb").join("BASE"));
        if let Some(base_path) = &workspace_base_path {
            if !base_path.is_file() {
                return Err("Managed workspace baseline is missing; refusing to guess its working-tree state".into());
            }
        }
        if !workspace_head_path.exists() {
            let legacy_head_path = vcs_dir.join("HEAD");
            if legacy_head_path.exists() {
                let head = fs::read_to_string(&legacy_head_path)
                    .map_err(|error| format!("Failed to read legacy HEAD: {error}"))?;
                fs::create_dir_all(workspace_head_path.parent().unwrap_or(workspace_root))
                    .map_err(|error| {
                        format!("Failed to create workspace metadata directory: {error}")
                    })?;
                fs::write(&workspace_head_path, head)
                    .map_err(|error| format!("Failed to migrate workspace HEAD: {error}"))?;
            }
        }
        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            vcs_dir,
            workspace_head_path,
            workspace_base_path,
            workspace_ports: managed_workspace.map(|managed| managed.ports),
            chunk_index: Mutex::new(None),
        })
    }

    pub fn assigned_workspace_ports(&self) -> Option<&WorkspacePortAssignments> {
        self.workspace_ports.as_ref()
    }

    fn workspace_base_commit(&self) -> Result<Option<VcsCommit>, String> {
        let Some(path) = &self.workspace_base_path else {
            return self.head_commit();
        };
        let commit_id = fs::read_to_string(path)
            .map_err(|error| format!("Failed to read managed workspace baseline: {error}"))?;
        let commit_id = commit_id.trim();
        if commit_id.is_empty() {
            return Ok(None);
        }
        if !is_object_id(commit_id) {
            return Err("Managed workspace baseline contains an invalid commit ID".into());
        }
        self.get_commit(commit_id).map(Some)
    }

    fn update_workspace_base(&self, commit_id: Option<&str>) -> Result<(), String> {
        let Some(path) = &self.workspace_base_path else {
            return Ok(());
        };
        let bytes = commit_id.unwrap_or("").as_bytes();
        atomicwrites::AtomicFile::new(path, atomicwrites::AllowOverwrite)
            .write(|file| {
                use std::io::Write;
                file.write_all(bytes)
            })
            .map_err(|error| format!("Failed to update managed workspace baseline: {error}"))?;
        Ok(())
    }

    fn workspace_base_matches_head(&self) -> Result<bool, String> {
        if self.workspace_base_path.is_none() {
            return Ok(true);
        }
        let base = self.workspace_base_commit()?.map(|commit| commit.commit_id);
        let head = self.head_commit()?.map(|commit| commit.commit_id);
        Ok(base == head)
    }

    /// Check if Sovereign VCS is initialized.
    pub fn is_initialized(workspace_root: &Path) -> bool {
        Self::open(workspace_root).is_ok()
    }

    /// Get the current active branch or detached HEAD info.
    pub fn current_branch(&self) -> Result<String, String> {
        let head_path = &self.workspace_head_path;
        if !head_path.exists() {
            return Ok("main".to_string());
        }
        let content =
            fs::read_to_string(head_path).map_err(|e| format!("Failed to read HEAD: {}", e))?;
        let trimmed = content.trim();
        if let Some(branch_ref) = trimmed.strip_prefix("ref: refs/heads/") {
            if !is_valid_branch_name(branch_ref) {
                return Err("Invalid branch reference in HEAD".to_string());
            }
            Ok(branch_ref.to_string())
        } else {
            Ok(format!("detached:{}", &trimmed[..8.min(trimmed.len())]))
        }
    }

    /// Get HEAD commit if available.
    pub fn head_commit(&self) -> Result<Option<VcsCommit>, String> {
        let head_path = &self.workspace_head_path;
        if !head_path.exists() {
            return Ok(None);
        }
        let content =
            fs::read_to_string(head_path).map_err(|e| format!("Failed to read HEAD: {}", e))?;
        let trimmed = content.trim();

        let commit_id = if let Some(branch_ref) = trimmed.strip_prefix("ref: refs/heads/") {
            if !is_valid_branch_name(branch_ref) {
                return Err("Invalid branch reference in HEAD".to_string());
            }
            let ref_path = self.vcs_dir.join("refs").join("heads").join(branch_ref);
            if !ref_path.exists() {
                return Ok(None);
            }
            fs::read_to_string(&ref_path)
                .map_err(|e| format!("Failed to read ref {}: {}", branch_ref, e))?
                .trim()
                .to_string()
        } else {
            trimmed.to_string()
        };

        if commit_id.is_empty() {
            return Ok(None);
        }

        self.get_commit(&commit_id).map(Some)
    }

    /// Load a commit by its ID.
    pub fn get_commit(&self, commit_id: &str) -> Result<VcsCommit, String> {
        if !is_object_id(commit_id) {
            return Err("Invalid commit ID".to_string());
        }
        let commits_dir = self.vcs_dir.join("objects").join("commits");
        let commit_path = commit_object_path(&commits_dir, commit_id);
        if !commit_path.exists() {
            return Err(format!("Commit not found: {}", commit_id));
        }
        let commit = read_commit_object(&commit_path, commit_id)?;
        if commit.commit_id != commit_id || compute_commit_id(&commit)? != commit_id {
            return Err(format!("Commit ID verification failed: {}", commit_id));
        }
        Ok(commit)
    }

    /// Load a tree by its tree hash.
    pub fn get_tree(&self, tree_hash: &str) -> Result<VcsTree, String> {
        if !is_object_id(tree_hash) {
            return Err("Invalid tree ID".to_string());
        }
        let tree_path = self
            .vcs_dir
            .join("objects")
            .join("trees")
            .join(format!("{}.json", tree_hash));
        if !tree_path.exists() {
            return Err(format!("Tree not found: {}", tree_hash));
        }
        let content = fs::read_to_string(&tree_path)
            .map_err(|e| format!("Failed to read tree {}: {}", tree_hash, e))?;
        let tree: VcsTree = serde_json::from_str(&content)
            .map_err(|e| format!("Corrupted tree file {}: {}", tree_hash, e))?;
        if tree.tree_hash != tree_hash || compute_tree_id(&tree)? != tree_hash {
            return Err(format!("Tree ID verification failed: {}", tree_hash));
        }
        Ok(tree)
    }

    /// Read raw blob content by hash.
    pub fn get_blob(&self, blob_hash: &str) -> Result<Vec<u8>, String> {
        if !is_object_id(blob_hash) {
            return Err("Invalid blob ID".to_string());
        }
        let blob_path = self.vcs_dir.join("objects").join("blobs").join(blob_hash);
        if !blob_path.exists() {
            return Err(format!("Blob not found: {}", blob_hash));
        }
        let content = fs::read(&blob_path)
            .map_err(|e| format!("Failed to read blob {}: {}", blob_hash, e))?;
        if blake3::hash(&content).to_hex().as_str() != blob_hash {
            return Err(format!("Blob ID verification failed: {}", blob_hash));
        }
        Ok(content)
    }

    pub fn get_blob_limited(&self, blob_hash: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
        if !is_object_id(blob_hash) {
            return Err("Invalid blob ID".to_string());
        }
        let blob_path = self.vcs_dir.join("objects").join("blobs").join(blob_hash);
        let metadata = fs::metadata(&blob_path)
            .map_err(|error| format!("Failed to inspect blob {blob_hash}: {error}"))?;
        if metadata.len() > max_bytes {
            return Err(format!(
                "Blob exceeds the maximum readable size of {max_bytes} bytes"
            ));
        }
        self.get_blob(blob_hash)
    }

    pub fn show_commit(&self, prefix: &str) -> Result<CommitShow, String> {
        let commits_dir = self.vcs_dir.join("objects").join("commits");
        let mut matches = fs::read_dir(&commits_dir)
            .map_err(|error| format!("Failed to read commits: {error}"))?
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter_map(|name| {
                name.strip_suffix(".json.gz")
                    .or_else(|| name.strip_suffix(".json"))
                    .map(str::to_string)
            })
            .filter(|commit_id| commit_id.starts_with(prefix));
        let commit_id = matches
            .next()
            .ok_or_else(|| format!("No commit matches '{prefix}'"))?;
        if matches.next().is_some() {
            return Err(format!("Commit prefix '{prefix}' is ambiguous"));
        }
        let commit = self.get_commit(&commit_id)?;
        let parent = commit.parent_ids.first().cloned();
        let new_tree = self.get_tree(&commit.tree_hash)?;
        let old_tree = match &parent {
            Some(parent_id) => self.get_tree(&self.get_commit(parent_id)?.tree_hash)?,
            None => VcsTree::default(),
        };
        let mut paths = old_tree
            .entries
            .keys()
            .chain(new_tree.entries.keys())
            .cloned()
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();

        let mut changes = Vec::new();
        for path in paths {
            let old = old_tree.entries.get(&path).filter(|entry| !entry.is_dir);
            let new = new_tree.entries.get(&path).filter(|entry| !entry.is_dir);
            if old.map(|entry| &entry.blake3_hash) == new.map(|entry| &entry.blake3_hash) {
                continue;
            }
            let old_text = match old {
                Some(entry) => {
                    String::from_utf8_lossy(&self.get_blob(&entry.blake3_hash)?).into_owned()
                }
                None => String::new(),
            };
            let new_text = match new {
                Some(entry) => {
                    String::from_utf8_lossy(&self.get_blob(&entry.blake3_hash)?).into_owned()
                }
                None => String::new(),
            };
            changes.push(FileDiff {
                rel_path: path,
                status: if old.is_none() {
                    "added".to_string()
                } else if new.is_none() {
                    "deleted".to_string()
                } else {
                    "modified".to_string()
                },
                old_hash: old.map(|entry| entry.blake3_hash.clone()),
                new_hash: new.map(|entry| entry.blake3_hash.clone()),
                lines: compute_unified_diff(&old_text, &new_text),
            });
        }
        Ok(CommitShow {
            commit,
            parent_commit_id: parent,
            changes,
        })
    }

    pub fn why_scope(&self, file_path: &str, target: &str) -> Result<ScopeHistory, String> {
        let normalized_file = file_path.replace('\\', "/");
        let commits = self.log(None)?;
        if commits.is_empty() {
            return Err("Repository has no commits".to_string());
        }

        let find_scope = |commit: &VcsCommit, scope_id: Option<&str>| {
            let scopes = commit
                .ast_scopes
                .iter()
                .filter(|scope| scope.file_path == normalized_file && scope.kind != "opaque");
            if let Some(scope_id) = scope_id {
                return scopes
                    .filter(|scope| scope.scope_id == scope_id)
                    .cloned()
                    .collect::<Vec<_>>();
            }
            let scopes = scopes.cloned().collect::<Vec<_>>();
            let exact_id = scopes
                .iter()
                .filter(|scope| scope.scope_id == target)
                .map(|scope| scope.clone())
                .collect::<Vec<_>>();
            if !exact_id.is_empty() {
                return exact_id;
            }
            let exact_name = scopes
                .iter()
                .filter(|scope| scope.name == target)
                .map(|scope| scope.clone())
                .collect::<Vec<_>>();
            if !exact_name.is_empty() {
                return exact_name;
            }
            scopes
                .into_iter()
                .filter(|scope| scope.name.contains(target) || scope.scope_id.contains(target))
                .collect()
        };

        let mut scope_id = None;
        for commit in &commits {
            let matches = find_scope(commit, None);
            if matches.len() > 1 {
                return Err(format!(
                    "Target '{target}' matches multiple scopes in '{normalized_file}'; use a scope ID"
                ));
            }
            if let Some(scope) = matches.first() {
                scope_id = Some(scope.scope_id.clone());
                break;
            }
        }
        let scope_id = scope_id.ok_or_else(|| {
            format!("No historical AST scope matches '{target}' in '{normalized_file}'")
        })?;

        let mut chronological = commits;
        chronological.reverse();
        let states = chronological
            .iter()
            .map(|commit| {
                let matches = find_scope(commit, Some(&scope_id));
                if matches.len() > 1 {
                    return Err(format!(
                        "Commit {} contains an ambiguous scope ID '{}'",
                        commit.commit_id, scope_id
                    ));
                }
                Ok(matches.first().cloned())
            })
            .collect::<Result<Vec<_>, String>>()?;

        let mut changes = Vec::new();
        for index in 0..states.len() {
            let newer = states[index].as_ref();
            let older = index
                .checked_sub(1)
                .and_then(|previous| states[previous].as_ref());
            let status = match (older, newer) {
                (None, Some(_)) => Some("added"),
                (Some(old), Some(new)) if old.content_hash != new.content_hash => Some("modified"),
                (Some(_), None) => Some("deleted"),
                _ => None,
            };
            if let Some(status) = status {
                let commit = &chronological[index];
                changes.push(ScopeHistoryEntry {
                    commit_id: commit.commit_id.clone(),
                    message: commit.message.clone(),
                    timestamp: commit.timestamp,
                    status: status.to_string(),
                    start_line: newer.or(older).map(|scope| scope.start_line),
                    end_line: newer.or(older).map(|scope| scope.end_line),
                    content_hash: newer.map(|scope| scope.content_hash.clone()),
                });
            }
        }
        Ok(ScopeHistory {
            file_path: normalized_file,
            target: target.to_string(),
            scope_id,
            changes,
        })
    }

    pub fn diff_scopes(&self, file_path: Option<&str>) -> Result<Vec<ScopeDiffEntry>, String> {
        let head = self.head_commit()?;
        let head_tree = match &head {
            Some(commit) => self.get_tree(&commit.tree_hash)?,
            None => VcsTree::default(),
        };
        let working_tree = FileTreeSnapshot::scan(&self.workspace_root)
            .map_err(|error| format!("Failed to scan workspace: {error}"))?;
        let normalized_filter = file_path.map(|path| path.replace('\\', "/"));
        let mut paths = head_tree
            .entries
            .keys()
            .chain(working_tree.entries.keys())
            .filter(|path| {
                normalized_filter
                    .as_ref()
                    .map_or(true, |filter| *path == filter)
            })
            .cloned()
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();

        let mut changes = Vec::new();
        for path in paths {
            let old_scopes = head
                .as_ref()
                .map(|commit| {
                    commit
                        .ast_scopes
                        .iter()
                        .filter(|scope| scope.file_path == path && scope.kind != "opaque")
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let new_scopes = if working_tree
                .entries
                .get(&path)
                .is_some_and(|entry| !entry.is_dir)
            {
                let content = fs::read(self.workspace_root.join(&path))
                    .map_err(|error| format!("Cannot read '{path}': {error}"))?;
                let source = std::str::from_utf8(&content)
                    .map_err(|_| format!("Cannot diff AST scopes in binary file '{path}'"))?;
                let parsed = crate::language::parse_source(&path, source)?;
                if parsed.parser_diagnostic.is_some() {
                    return Err(format!(
                        "Cannot produce AST diff for '{path}': {}",
                        parsed.parser_diagnostic.unwrap_or_default()
                    ));
                }
                capture_scope_snapshots(
                    &path,
                    source,
                    parsed.scopes,
                    &parsed.parser_id,
                    parsed.parser_version,
                    None,
                )?
                .into_iter()
                .filter(|scope| scope.kind != "opaque")
                .collect::<Vec<_>>()
            } else {
                Vec::new()
            };

            let old_by_id = old_scopes
                .into_iter()
                .map(|scope| (scope.scope_id.clone(), scope))
                .collect::<HashMap<_, _>>();
            let new_by_id = new_scopes
                .into_iter()
                .map(|scope| (scope.scope_id.clone(), scope))
                .collect::<HashMap<_, _>>();
            let mut ids = old_by_id
                .keys()
                .chain(new_by_id.keys())
                .cloned()
                .collect::<Vec<_>>();
            ids.sort();
            ids.dedup();
            for id in ids {
                let old = old_by_id.get(&id);
                let new = new_by_id.get(&id);
                let status = match (old, new) {
                    (None, Some(_)) => "added",
                    (Some(_), None) => "deleted",
                    (Some(old), Some(new)) if old.content_hash != new.content_hash => "modified",
                    _ => continue,
                };
                let scope = new.or(old).expect("scope ID came from one version");
                changes.push(ScopeDiffEntry {
                    file_path: path.clone(),
                    scope_id: id,
                    name: scope.name.clone(),
                    status: status.to_string(),
                    old_start_line: old.map(|scope| scope.start_line),
                    old_end_line: old.map(|scope| scope.end_line),
                    new_start_line: new.map(|scope| scope.start_line),
                    new_end_line: new.map(|scope| scope.end_line),
                });
            }
        }
        Ok(changes)
    }

    /// Write raw blob content and return its BLAKE3 hash.
    pub fn put_blob(&self, content: &[u8]) -> Result<String, String> {
        let hash = blake3::hash(content).to_hex().to_string();
        let blob_path = self.vcs_dir.join("objects").join("blobs").join(&hash);
        if !blob_path.exists() {
            fs::write(&blob_path, content)
                .map_err(|e| format!("Failed to write blob {}: {}", hash, e))?;
            *self
                .chunk_index
                .lock()
                .map_err(|_| "Chunk index lock is poisoned".to_string())? = None;
        }
        Ok(hash)
    }

    /// Derive a FastCDC manifest from the verified blob.
    pub fn get_chunk_manifest(&self, blob_hash: &str) -> Option<ChunkManifest> {
        if !is_object_id(blob_hash) {
            return None;
        }
        let content = self.get_blob(blob_hash).ok()?;
        Some(FastCdc::with_default().generate_manifest(&content))
    }

    /// Read a cached chunk or derive it from a verified blob when needed.
    pub fn get_chunk(&self, chunk_hash: &str) -> Result<Vec<u8>, String> {
        if !is_object_id(chunk_hash) {
            return Err("Invalid chunk ID".to_string());
        }
        let chunk_path = self.vcs_dir.join("objects").join("chunks").join(chunk_hash);
        if chunk_path.exists() {
            let content = fs::read(&chunk_path)
                .map_err(|e| format!("Failed to read chunk {}: {}", chunk_hash, e))?;
            if blake3::hash(&content).to_hex().as_str() != chunk_hash {
                return Err(format!("Chunk ID verification failed: {}", chunk_hash));
            }
            return Ok(content);
        }

        let location = {
            let mut index = self
                .chunk_index
                .lock()
                .map_err(|_| "Chunk index lock is poisoned".to_string())?;
            if index.is_none() {
                *index = Some(self.build_chunk_index()?);
            }
            index
                .as_ref()
                .and_then(|locations| locations.get(chunk_hash))
                .cloned()
        }
        .ok_or_else(|| format!("Chunk not found: {}", chunk_hash))?;
        let content = self.get_blob(&location.blob_hash)?;
        let end = location
            .offset
            .checked_add(location.length)
            .ok_or_else(|| "Chunk range overflow".to_string())?;
        let bytes = content
            .get(location.offset..end)
            .ok_or_else(|| "Chunk range exceeds blob size".to_string())?;
        if blake3::hash(bytes).to_hex().as_str() != chunk_hash {
            return Err(format!("Chunk ID verification failed: {}", chunk_hash));
        }
        Ok(bytes.to_vec())
    }

    fn build_chunk_index(&self) -> Result<HashMap<String, ChunkLocation>, String> {
        let blobs_dir = self.vcs_dir.join("objects").join("blobs");
        let blobs = fs::read_dir(&blobs_dir)
            .map_err(|e| format!("Failed to read blobs while resolving chunk: {}", e))?;
        let mut index = HashMap::new();
        for entry in blobs {
            let entry = entry.map_err(|e| format!("Failed to inspect blob entry: {}", e))?;
            let blob_hash = entry.file_name();
            let Some(blob_hash) = blob_hash.to_str().filter(|hash| is_object_id(hash)) else {
                continue;
            };
            let content = self.get_blob(blob_hash)?;
            let manifest = FastCdc::with_default().generate_manifest(&content);
            for chunk in manifest.chunks {
                let offset = usize::try_from(chunk.offset)
                    .map_err(|_| "Chunk offset exceeds platform limits".to_string())?;
                index.entry(chunk.blake3_hash).or_insert(ChunkLocation {
                    blob_hash: blob_hash.to_string(),
                    offset,
                    length: chunk.length,
                });
            }
        }
        Ok(index)
    }

    /// Calculate FastCDC deduplication delta between two blob versions.
    pub fn diff_blob_fastcdc(
        &self,
        old_blob_hash: &str,
        new_blob_hash: &str,
    ) -> Option<DeduplicationStats> {
        let m1 = self.get_chunk_manifest(old_blob_hash)?;
        let m2 = self.get_chunk_manifest(new_blob_hash)?;
        Some(compare_manifests(&m1, &m2))
    }

    /// Compute repository status against HEAD commit tree.
    pub fn status(&self) -> Result<VcsStatus, String> {
        let current_branch = self.current_branch()?;
        let head = self.workspace_base_commit()?;

        let head_tree = match &head {
            Some(c) => self.get_tree(&c.tree_hash)?,
            None => VcsTree::default(),
        };

        let scan = FileTreeSnapshot::scan(&self.workspace_root)
            .map_err(|e| format!("Failed to scan workspace: {}", e))?;

        let mut changes = Vec::new();
        let mut modified_count = 0;
        let mut added_count = 0;
        let mut deleted_count = 0;

        // Check for added & modified files
        for (path, current_entry) in &scan.entries {
            if current_entry.is_dir {
                continue;
            }
            if let Some(old_entry) = head_tree.entries.get(path) {
                if old_entry.blake3_hash != current_entry.blake3_hash {
                    modified_count += 1;
                    changes.push(FileStatus {
                        rel_path: path.clone(),
                        status: "modified".to_string(),
                        old_hash: Some(old_entry.blake3_hash.clone()),
                        new_hash: Some(current_entry.blake3_hash.clone()),
                        size_bytes: current_entry.size_bytes,
                    });
                }
            } else {
                added_count += 1;
                changes.push(FileStatus {
                    rel_path: path.clone(),
                    status: "added".to_string(),
                    old_hash: None,
                    new_hash: Some(current_entry.blake3_hash.clone()),
                    size_bytes: current_entry.size_bytes,
                });
            }
        }

        // Check for deleted files
        for (path, old_entry) in &head_tree.entries {
            if old_entry.is_dir {
                continue;
            }
            if !scan.entries.contains_key(path) {
                deleted_count += 1;
                changes.push(FileStatus {
                    rel_path: path.clone(),
                    status: "deleted".to_string(),
                    old_hash: Some(old_entry.blake3_hash.clone()),
                    new_hash: None,
                    size_bytes: old_entry.size_bytes,
                });
            }
        }

        // Sort alphabetically for clean UI presentation
        changes.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

        let is_clean = changes.is_empty();

        Ok(VcsStatus {
            current_branch,
            head_commit: head,
            is_clean,
            modified_count,
            added_count,
            deleted_count,
            changes,
        })
    }

    /// Calculate detailed repository storage and deduplication statistics.
    pub fn storage_stats(&self) -> Result<VcsStorageStats, String> {
        let active_branch = self.current_branch()?;
        let head = self.workspace_base_commit()?;
        let head_commit_id = head.map(|c| c.commit_id);

        let scan_dir = |sub: &str| -> ObjectTypeStats {
            let dir = self.vcs_dir.join("objects").join(sub);
            let mut count = 0;
            let mut total_bytes = 0;
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() {
                            count += 1;
                            total_bytes += meta.len();
                        }
                    }
                }
            }
            ObjectTypeStats { count, total_bytes }
        };

        let blobs = scan_dir("blobs");
        let chunks = scan_dir("chunks");
        let chunk_manifests = scan_dir("chunk_manifests");
        let trees = scan_dir("trees");
        let commits = scan_dir("commits");

        let total_objects =
            blobs.count + chunks.count + chunk_manifests.count + trees.count + commits.count;
        let total_vcs_bytes = blobs.total_bytes
            + chunks.total_bytes
            + chunk_manifests.total_bytes
            + trees.total_bytes
            + commits.total_bytes;

        let average_commit_bytes = if commits.count > 0 {
            commits.total_bytes / (commits.count as u64)
        } else {
            0
        };

        let raw_blob_bytes = blobs.total_bytes;
        let chunk_bytes = chunks.total_bytes;
        let deduplication_ratio = (chunk_bytes > 0 && raw_blob_bytes > 0)
            .then(|| (raw_blob_bytes as f64) / (chunk_bytes as f64));

        Ok(VcsStorageStats {
            workspace_root: self.workspace_root.to_string_lossy().to_string(),
            active_branch,
            head_commit_id,
            total_vcs_bytes,
            blobs,
            chunks,
            chunk_manifests,
            trees,
            commits,
            total_objects,
            average_commit_bytes,
            deduplication_ratio,
            raw_blob_bytes,
        })
    }

    /// Calculate AST Scope churn and heatmap over the commit history.
    /// Files matched by the `.sbignore` analysis filter are excluded.
    pub fn heatmap(
        &self,
        limit: Option<usize>,
        filter: &crate::sync::AnalysisFilter,
    ) -> Result<ScopeHeatmapReport, String> {
        let commits = self.log(limit)?;
        if commits.is_empty() {
            return Ok(ScopeHeatmapReport {
                commits_analyzed: 0,
                total_scopes_tracked: 0,
                hot_scopes: Vec::new(),
                hot_files: Vec::new(),
            });
        }

        let mut scope_change_counts: HashMap<String, (usize, AstScopeSnapshot)> = HashMap::new();
        let mut file_change_counts: HashMap<String, usize> = HashMap::new();

        for window in commits.windows(2) {
            let child = &window[0];
            let parent = &window[1];

            let parent_scopes: HashMap<&str, &str> = parent
                .ast_scopes
                .iter()
                .map(|s| (s.scope_id.as_str(), s.content_hash.as_str()))
                .collect();

            let mut files_touched_in_commit = HashSet::new();

            for s in child
                .ast_scopes
                .iter()
                .filter(|s| !filter.is_filtered(&s.file_path))
            {
                let changed = match parent_scopes.get(s.scope_id.as_str()) {
                    Some(parent_hash) => *parent_hash != s.content_hash.as_str(),
                    None => true,
                };
                if changed {
                    let entry = scope_change_counts
                        .entry(s.scope_id.clone())
                        .or_insert_with(|| (0, s.clone()));
                    entry.0 += 1;
                    entry.1 = s.clone();
                    files_touched_in_commit.insert(s.file_path.clone());
                }
            }

            for f in files_touched_in_commit {
                *file_change_counts.entry(f).or_insert(0) += 1;
            }
        }

        if commits.len() == 1 {
            for s in commits[0]
                .ast_scopes
                .iter()
                .filter(|s| !filter.is_filtered(&s.file_path))
            {
                let entry = scope_change_counts
                    .entry(s.scope_id.clone())
                    .or_insert_with(|| (0, s.clone()));
                entry.0 += 1;
                *file_change_counts.entry(s.file_path.clone()).or_insert(0) += 1;
            }
        }

        let mut hot_scopes: Vec<ScopeHeatmapEntry> = scope_change_counts
            .into_values()
            .map(|(count, s)| {
                let status = if count >= 3 {
                    "🔥 HOT".to_string()
                } else if count == 2 {
                    "🟡 WARM".to_string()
                } else {
                    "🟢 STABLE".to_string()
                };
                ScopeHeatmapEntry {
                    scope_id: s.scope_id,
                    name: s.name,
                    file_path: s.file_path,
                    kind: s.kind,
                    change_count: count,
                    status,
                }
            })
            .collect();

        hot_scopes.sort_by(|a, b| {
            b.change_count
                .cmp(&a.change_count)
                .then_with(|| a.name.cmp(&b.name))
        });

        let mut hot_files: Vec<FileHeatmapEntry> = file_change_counts
            .into_iter()
            .map(|(file_path, change_count)| FileHeatmapEntry {
                file_path,
                change_count,
            })
            .collect();

        hot_files.sort_by(|a, b| {
            b.change_count
                .cmp(&a.change_count)
                .then_with(|| a.file_path.cmp(&b.file_path))
        });

        let total_scopes_tracked = hot_scopes.len();

        Ok(ScopeHeatmapReport {
            commits_analyzed: commits.len(),
            total_scopes_tracked,
            hot_scopes,
            hot_files,
        })
    }

    /// Rollback active branch or specific file to a parent commit.
    pub fn rollback(
        &mut self,
        steps: usize,
        to_commit: Option<&str>,
        file: Option<&str>,
        force: bool,
    ) -> Result<RollbackReport, String> {
        if !force && !self.status()?.is_clean {
            return Err(
                "Uncommittete Änderungen im Arbeitsbereich. Bitte committen oder --force nutzen."
                    .to_string(),
            );
        }

        let current_branch = self.current_branch()?;
        let current_head = self
            .workspace_base_commit()?
            .ok_or_else(|| "Keine Commits vorhanden für einen Rollback".to_string())?;

        let target_commit = if let Some(target_id) = to_commit {
            self.get_commit(target_id)?
        } else {
            let mut curr = current_head.clone();
            for _ in 0..steps {
                if curr.parent_ids.is_empty() {
                    return Err(format!(
                        "Wurzel-Commit '{}' erreicht; kann nicht um {} Schritte zurückrollen",
                        curr.commit_id, steps
                    ));
                }
                curr = self.get_commit(&curr.parent_ids[0])?;
            }
            curr
        };

        let target_tree = self.get_tree(&target_commit.tree_hash)?;

        if let Some(target_file) = file {
            let restored = if let Some(entry) = target_tree.entries.get(target_file) {
                let blob = self.get_blob(&entry.blake3_hash)?;
                let full_path = safe_workspace_file_path(&self.workspace_root, target_file, true)?;
                fs::write(&full_path, blob)
                    .map_err(|e| format!("Konnte Datei '{target_file}' nicht schreiben: {e}"))?;
                true
            } else {
                let full_path = safe_workspace_file_path(&self.workspace_root, target_file, false)?;
                if full_path.exists() {
                    let _ = fs::remove_file(full_path);
                }
                false
            };

            let short_id =
                target_commit.commit_id[..8.min(target_commit.commit_id.len())].to_string();
            return Ok(RollbackReport {
                previous_commit_id: current_head.commit_id,
                target_commit_id: target_commit.commit_id,
                branch: current_branch,
                single_file: Some(target_file.to_string()),
                message: if restored {
                    format!("Datei '{target_file}' auf Stand von Commit {short_id} zurückgesetzt")
                } else {
                    format!("Datei '{target_file}' existierte in Commit {short_id} nicht; gelöscht")
                },
            });
        }

        let current_tree = match self.get_tree(&current_head.tree_hash) {
            Ok(t) => t,
            Err(_) => VcsTree::default(),
        };

        for (rel_path, _) in &current_tree.entries {
            if !target_tree.entries.contains_key(rel_path) {
                let full_path = safe_workspace_file_path(&self.workspace_root, rel_path, false)?;
                if full_path.exists() {
                    let _ = fs::remove_file(&full_path);
                }
            }
        }

        for (rel_path, entry) in &target_tree.entries {
            if entry.is_dir {
                continue;
            }
            let blob = self.get_blob(&entry.blake3_hash)?;
            let full_path = safe_workspace_file_path(&self.workspace_root, rel_path, true)?;
            fs::write(&full_path, blob)
                .map_err(|e| format!("Konnte Datei '{rel_path}' nicht wiederherstellen: {e}"))?;
        }

        let branch_ref_path = self
            .vcs_dir
            .join("refs")
            .join("heads")
            .join(&current_branch);
        if branch_ref_path
            .parent()
            .map(|p| p.is_dir())
            .unwrap_or(false)
        {
            fs::write(&branch_ref_path, format!("{}\n", target_commit.commit_id))
                .map_err(|e| format!("Konnte Branch Ref nicht aktualisieren: {e}"))?;
        }

        fs::write(
            &self.workspace_head_path,
            format!("ref: refs/heads/{}\n", current_branch),
        )
        .map_err(|e| format!("Konnte HEAD nicht aktualisieren: {e}"))?;
        self.update_workspace_base(Some(&target_commit.commit_id))?;

        let short_target =
            target_commit.commit_id[..8.min(target_commit.commit_id.len())].to_string();
        Ok(RollbackReport {
            previous_commit_id: current_head.commit_id,
            target_commit_id: target_commit.commit_id,
            branch: current_branch,
            single_file: None,
            message: format!(
                "Branch erfolgreich auf Commit {short_target} ({}) zurückgesetzt",
                target_commit.message
            ),
        })
    }

    /// Generate a concise structural outline of a source module.
    pub fn outline(file_path: &Path) -> Result<ModuleOutline, String> {
        if !file_path.exists() {
            return Err(format!("Datei '{}' existiert nicht", file_path.display()));
        }
        let content =
            fs::read_to_string(file_path).map_err(|e| format!("Konnte Datei nicht lesen: {e}"))?;
        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        let parsed = crate::language::parse_source(&file_path.to_string_lossy(), &content)
            .map_err(|e| format!("Parser-Fehler: {e}"))?;
        let scopes = parsed.scopes;
        let container_scopes = if parsed.parser_diagnostic.is_some() {
            Vec::new()
        } else {
            crate::language::parse_outline_containers(&file_path.to_string_lossy(), &content)
                .map_err(|e| format!("Parser-Fehler: {e}"))?
        };

        let mut items = Vec::new();
        for s in scopes {
            if s.kind == crate::ast::AstScopeKind::Opaque {
                continue;
            }

            let start_idx = s.start_line.saturating_sub(1);
            let raw_sig = if start_idx < lines.len() {
                lines[start_idx].trim().to_string()
            } else {
                s.name.clone()
            };

            items.push(ScopeOutlineItem {
                name: s.name,
                kind: format!("{}", s.kind),
                signature: raw_sig,
                start_line: s.start_line,
                end_line: s.end_line,
                is_container: s.is_container,
            });
        }
        items.extend(container_scopes.into_iter().map(|scope| {
            let start_idx = scope.start_line.saturating_sub(1);
            let signature = lines
                .get(start_idx)
                .map(|line| line.trim().to_string())
                .unwrap_or_else(|| scope.name.clone());
            ScopeOutlineItem {
                name: scope.name,
                kind: scope.kind.to_string(),
                signature,
                start_line: scope.start_line,
                end_line: scope.end_line,
                is_container: scope.is_container,
            }
        }));

        Ok(ModuleOutline {
            file_path: file_path.to_string_lossy().to_string(),
            total_lines,
            items,
        })
    }

    /// Analyze co-change coupling between files across commit history.
    /// Files matched by the `.sbignore` analysis filter are excluded.
    pub fn coupling(
        &self,
        limit: Option<usize>,
        target_file: Option<&str>,
        min_co_changes: usize,
        filter: &crate::sync::AnalysisFilter,
    ) -> Result<CouplingReport, String> {
        let commits = self.log(limit)?;
        if commits.is_empty() {
            return Ok(CouplingReport {
                commits_analyzed: 0,
                target_filter: target_file.map(|s| s.to_string()),
                couplings: Vec::new(),
            });
        }

        let mut file_change_counts: HashMap<String, usize> = HashMap::new();
        let mut co_change_counts: HashMap<(String, String), usize> = HashMap::new();

        for window in commits.windows(2) {
            let child = &window[0];
            let parent = &window[1];

            let parent_scopes: HashMap<&str, &str> = parent
                .ast_scopes
                .iter()
                .map(|s| (s.scope_id.as_str(), s.content_hash.as_str()))
                .collect();

            let mut commit_files = HashSet::new();
            for s in child
                .ast_scopes
                .iter()
                .filter(|s| !filter.is_filtered(&s.file_path))
            {
                let changed = match parent_scopes.get(s.scope_id.as_str()) {
                    Some(parent_hash) => *parent_hash != s.content_hash.as_str(),
                    None => true,
                };
                if changed {
                    commit_files.insert(s.file_path.clone());
                }
            }

            for f in &commit_files {
                *file_change_counts.entry(f.clone()).or_insert(0) += 1;
            }

            let file_vec: Vec<String> = commit_files.into_iter().collect();
            for i in 0..file_vec.len() {
                for j in (i + 1)..file_vec.len() {
                    let a = &file_vec[i];
                    let b = &file_vec[j];
                    let pair = if a < b {
                        (a.clone(), b.clone())
                    } else {
                        (b.clone(), a.clone())
                    };
                    *co_change_counts.entry(pair).or_insert(0) += 1;
                }
            }
        }

        let mut couplings = Vec::new();
        for ((a, b), co_changes) in co_change_counts {
            if co_changes < min_co_changes {
                continue;
            }

            if let Some(filter) = target_file {
                if !a.contains(filter) && !b.contains(filter) {
                    continue;
                }
            }

            let count_a = *file_change_counts.get(&a).unwrap_or(&1);
            let count_b = *file_change_counts.get(&b).unwrap_or(&1);

            let confidence_a_to_b = (co_changes as f64 / count_a as f64).min(1.0);
            let confidence_b_to_a = (co_changes as f64 / count_b as f64).min(1.0);

            couplings.push(FileCoupling {
                file_a: a,
                file_b: b,
                co_changes,
                confidence_a_to_b,
                confidence_b_to_a,
            });
        }

        couplings.sort_by(|x, y| {
            y.co_changes.cmp(&x.co_changes).then_with(|| {
                let conf_y = y.confidence_a_to_b + y.confidence_b_to_a;
                let conf_x = x.confidence_a_to_b + x.confidence_b_to_a;
                conf_y
                    .partial_cmp(&conf_x)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        Ok(CouplingReport {
            commits_analyzed: commits.len(),
            target_filter: target_file.map(|s| s.to_string()),
            couplings,
        })
    }

    /// Commit the current workspace state.
    pub fn commit(&mut self, message: &str, author_callsign: &str) -> Result<VcsCommit, String> {
        self.commit_with_parents(message, author_callsign, None)
    }

    pub fn commit_selected(
        &mut self,
        message: &str,
        author_callsign: &str,
        only_paths: &[String],
        scope_specs: &[(String, String)],
    ) -> Result<VcsCommit, String> {
        self.commit_with_selection(
            message,
            author_callsign,
            None,
            Some(only_paths),
            scope_specs,
            None,
            None,
        )
    }

    pub fn preview_commit_selection(
        &self,
        only_paths: &[String],
        scope_specs: &[(String, String)],
    ) -> Result<Vec<String>, String> {
        let working_tree = FileTreeSnapshot::scan(&self.workspace_root)
            .map_err(|error| format!("Failed to scan workspace: {error}"))?;
        let head = self.head_commit()?;
        let head_tree = match &head {
            Some(commit) => self.get_tree(&commit.tree_hash)?,
            None => VcsTree::default(),
        };
        let selectors = only_paths
            .iter()
            .map(|path| normalize_commit_selector(path))
            .collect::<Result<Vec<_>, _>>()?;
        let mut selected = Vec::new();
        for selector in &selectors {
            let matches = head_tree
                .entries
                .keys()
                .chain(working_tree.entries.keys())
                .filter(|path| path_matches_selector(path, selector))
                .cloned()
                .collect::<Vec<_>>();
            if matches.is_empty() {
                return Err(format!("No tracked or working file matches '{selector}'"));
            }
            selected.extend(matches);
        }

        let mut scope_targets = HashMap::<String, Vec<String>>::new();
        for (path, target) in scope_specs {
            let path = normalize_commit_selector(path)?;
            if selectors
                .iter()
                .any(|selector| path_matches_selector(&path, selector))
            {
                return Err(format!(
                    "Do not combine --only for '{path}' with --scope selections from that file"
                ));
            }
            scope_targets.entry(path).or_default().push(target.clone());
        }
        for (path, targets) in scope_targets {
            let base_entry = head_tree
                .entries
                .get(&path)
                .ok_or_else(|| format!("Cannot stage scopes in '{path}': file is not in HEAD"))?;
            let base_content = self.get_blob(&base_entry.blake3_hash)?;
            let working_content = fs::read(self.workspace_root.join(&path))
                .map_err(|error| format!("Cannot read selected scope file '{path}': {error}"))?;
            stage_scope_changes(&path, &base_content, &working_content, &targets)?;
            selected.push(path);
        }
        if selectors.is_empty() && scope_specs.is_empty() {
            selected.extend(
                self.status()?
                    .changes
                    .into_iter()
                    .map(|change| change.rel_path),
            );
        }
        selected.sort();
        selected.dedup();
        Ok(selected)
    }

    pub fn create_checkpoint(
        &mut self,
        name: &str,
        message: Option<&str>,
        author_callsign: &str,
    ) -> Result<(VcsCommit, PathBuf), String> {
        if !is_valid_branch_name(name) || name.contains('/') {
            return Err("Checkpoint name must be a safe single path segment".to_string());
        }
        let checkpoints_dir = self.vcs_dir.join("refs").join("checkpoints");
        fs::create_dir_all(&checkpoints_dir)
            .map_err(|error| format!("Cannot create checkpoint refs: {error}"))?;
        let reference = checkpoints_dir.join(name);
        if reference.exists() {
            return Err(format!("Checkpoint '{name}' already exists"));
        }
        let commit = self.commit(
            &message
                .map(|message| format!("checkpoint: {message}"))
                .unwrap_or_else(|| format!("checkpoint: {name}")),
            author_callsign,
        )?;
        atomicwrites::AtomicFile::new(&reference, atomicwrites::AllowOverwrite)
            .write(|file| {
                use std::io::Write;
                file.write_all(commit.commit_id.as_bytes())
            })
            .map_err(|error| {
                format!(
                    "Checkpoint commit {} was created, but its reference could not be saved: {error}",
                    commit.commit_id
                )
            })?;
        Ok((commit, reference))
    }

    fn commit_with_parents(
        &mut self,
        message: &str,
        author_callsign: &str,
        parent_override: Option<Vec<String>>,
    ) -> Result<VcsCommit, String> {
        self.commit_with_selection(
            message,
            author_callsign,
            parent_override,
            None,
            &[],
            None,
            None,
        )
    }

    /// Compare-and-swap commit for editors: fails unless the branch head is still the one the
    /// caller last observed (`None` means "no commit yet"), then commits the selected paths.
    // CVE-Threat: Lost update / TOCTOU between an editor's view of HEAD and the commit.
    // Analysis: The caller-held head is verified against the head the commit is parented on, and
    // the branch-ref write below re-checks that head under the branch lock.
    // Hardening: Mismatch aborts before any ref changes; no implicit rebase.
    pub fn commit_selected_cas(
        &mut self,
        expected_head: Option<&str>,
        message: &str,
        author_callsign: &str,
        only_paths: &[String],
    ) -> Result<VcsCommit, String> {
        self.commit_with_selection(
            message,
            author_callsign,
            None,
            Some(only_paths),
            &[],
            Some(expected_head),
            None,
        )
    }

    /// Signed compare-and-swap commit for native Studio/Workbench: requires `expected_head` to
    /// match the current HEAD and produces a verified Ed25519 signature before advancing refs.
    pub fn commit_signed_cas(
        &mut self,
        expected_head: Option<&str>,
        message: &str,
        author_callsign: &str,
        only_paths: &[String],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<VcsCommit, String> {
        let selection = if only_paths.is_empty() {
            None
        } else {
            Some(only_paths)
        };
        self.commit_with_selection(
            message,
            author_callsign,
            None,
            selection,
            &[],
            Some(expected_head),
            Some(signing_key),
        )
    }

    /// Signed compare-and-swap AST-scope commit for native Workbench.
    pub fn commit_scopes_signed_cas(
        &mut self,
        expected_head: Option<&str>,
        message: &str,
        author_callsign: &str,
        scope_specs: &[(String, String)],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<VcsCommit, String> {
        if scope_specs.is_empty() {
            return Err("At least one AST scope must be selected for a scope commit".into());
        }
        self.commit_with_selection(
            message,
            author_callsign,
            None,
            Some(&[]),
            scope_specs,
            Some(expected_head),
            Some(signing_key),
        )
    }

    fn commit_with_selection(
        &mut self,
        message: &str,
        author_callsign: &str,
        parent_override: Option<Vec<String>>,
        only_paths: Option<&[String]>,
        scope_specs: &[(String, String)],
        caller_expected_head: Option<Option<&str>>,
        explicit_signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> Result<VcsCommit, String> {
        let mut scan = FileTreeSnapshot::scan(&self.workspace_root)
            .map_err(|e| format!("Failed to scan workspace: {}", e))?;
        let partial_commit = only_paths.is_some() || !scope_specs.is_empty();
        let mut staged_scope_contents = HashMap::<String, Vec<u8>>::new();
        if partial_commit {
            let selectors = only_paths
                .unwrap_or_default()
                .iter()
                .map(|path| normalize_commit_selector(path))
                .collect::<Result<Vec<_>, _>>()?;
            let current = self.head_commit()?;
            let base_tree = match &current {
                Some(commit) => self.get_tree(&commit.tree_hash)?,
                None => VcsTree::default(),
            };
            let mut scope_targets = HashMap::<String, Vec<String>>::new();
            for (path, target) in scope_specs {
                scope_targets
                    .entry(normalize_commit_selector(path)?)
                    .or_default()
                    .push(target.clone());
            }
            let scope_files = scope_targets.keys().cloned().collect::<Vec<_>>();

            for selector in &selectors {
                let tracked_match = base_tree
                    .entries
                    .keys()
                    .any(|path| path_matches_selector(path, selector));
                let working_match = scan
                    .entries
                    .keys()
                    .any(|path| path_matches_selector(path, selector));
                if !tracked_match && !working_match {
                    return Err(format!("No tracked or working file matches '{selector}'"));
                }
            }

            for (path, targets) in &scope_targets {
                if selectors
                    .iter()
                    .any(|selector| path_matches_selector(path, selector))
                {
                    return Err(format!(
                        "Do not combine --only for '{}' with --scope selections from that file",
                        path
                    ));
                }
                let base_entry = base_tree.entries.get(path).ok_or_else(|| {
                    format!(
                        "Cannot stage scopes '{}': '{path}' is not present in HEAD",
                        targets.join(", ")
                    )
                })?;
                let base_content = self.get_blob(&base_entry.blake3_hash)?;
                let work_content = fs::read(self.workspace_root.join(path)).map_err(|error| {
                    format!("Cannot read selected scope file '{path}': {error}")
                })?;
                let staged = stage_scope_changes(path, &base_content, &work_content, targets)?;
                staged_scope_contents.insert(path.clone(), staged);
            }

            let selected_files = |path: &str| {
                selectors
                    .iter()
                    .any(|selector| path_matches_selector(path, selector))
                    || scope_files.iter().any(|scope_file| path == scope_file)
            };
            scan.entries.retain(|path, _| selected_files(path));
            for (path, entry) in &base_tree.entries {
                if !entry.is_dir && !selected_files(path) {
                    scan.entries.insert(path.clone(), entry.clone());
                }
            }
            for (path, content) in &staged_scope_contents {
                let mut entry = scan.entries.get(path).cloned().ok_or_else(|| {
                    format!("Selected scope file '{path}' is absent from the workspace")
                })?;
                entry.size_bytes = content.len() as u64;
                entry.blake3_hash = blake3::hash(content).to_hex().to_string();
                scan.entries.insert(path.clone(), entry);
            }
        }

        let mut tree_entries = HashMap::new();
        let mut ast_scopes = Vec::new();

        // 1. Store blobs for all files
        for (rel_path, entry) in scan.entries {
            if entry.is_dir {
                continue;
            }
            let content = if let Some(content) = staged_scope_contents.get(&rel_path) {
                content.clone()
            } else if partial_commit
                && !only_paths.unwrap_or_default().iter().any(|selector| {
                    normalize_commit_selector(selector)
                        .is_ok_and(|selector| path_matches_selector(&rel_path, &selector))
                })
            {
                self.get_blob(&entry.blake3_hash)?
            } else {
                fs::read(self.workspace_root.join(&rel_path))
                    .map_err(|e| format!("Failed to read file {}: {}", rel_path, e))?
            };
            let blob_hash = self.put_blob(&content)?;
            if let Ok(source) = std::str::from_utf8(&content) {
                ast_scopes.extend(capture_ast_scopes(&rel_path, source)?);
            }

            let mut updated_entry = entry;
            updated_entry.blake3_hash = blob_hash;
            tree_entries.insert(rel_path, updated_entry);
        }
        ast_scopes.sort_by(|left, right| left.scope_id.cmp(&right.scope_id));

        // 2. Build and store VcsTree
        let mut vcs_tree = VcsTree {
            format_version: 2,
            tree_hash: String::new(),
            entries: tree_entries,
        };
        let tree_hash = compute_tree_id(&vcs_tree)?;
        vcs_tree.tree_hash = tree_hash.clone();

        let tree_file = self
            .vcs_dir
            .join("objects")
            .join("trees")
            .join(format!("{}.json", tree_hash));
        let tree_json = serde_json::to_string_pretty(&vcs_tree)
            .map_err(|e| format!("Failed to serialize tree: {}", e))?;
        fs::write(&tree_file, tree_json)
            .map_err(|e| format!("Failed to write tree file: {}", e))?;

        // 3. Construct commit
        let head = self.head_commit()?;
        let expected_head = head.as_ref().map(|commit| commit.commit_id.clone());
        if let Some(caller_head) = caller_expected_head {
            if caller_head != expected_head.as_deref() {
                return Err(
                    "Branch head changed since the editor loaded it; refresh before committing"
                        .to_string(),
                );
            }
        }
        if self.workspace_base_path.is_some()
            && self.workspace_base_commit()?.map(|commit| commit.commit_id) != expected_head
        {
            let branch = self.current_branch()?;
            return Err(format!(
                "Branch '{branch}' advanced in another workspace; run `sb code checkout {branch}` to refresh before committing"
            ));
        }
        let parent_ids = parent_override.unwrap_or_else(|| {
            head.map(|commit| vec![commit.commit_id])
                .unwrap_or_default()
        });

        let timestamp = Utc::now();
        let mut commit = VcsCommit {
            format_version: 3,
            commit_id: String::new(),
            parent_ids,
            tree_hash,
            author_callsign: author_callsign.to_string(),
            timestamp,
            message: message.to_string(),
            signature_ed25519: None,
            ast_scopes,
            ast_parser_version: 3,
        };
        let commit_id = compute_commit_id(&commit)?;
        commit.commit_id = commit_id.clone();

        if let Some(signing_key) = explicit_signing_key {
            commit.sign(signing_key);
            commit.verify_signature()?;
        } else if let Ok(signing_key) = crate::session::get_active_signing_key() {
            commit.sign(&signing_key);
        }

        // 4. Store commit object
        let commits_dir = self.vcs_dir.join("objects").join("commits");
        write_commit_object(&commits_dir, &commit)?;

        // 5. Update branch ref or HEAD
        let branch = self.current_branch()?;
        if branch.starts_with("detached:") {
            fs::write(&self.workspace_head_path, &commit_id)
                .map_err(|e| format!("Failed to update detached HEAD: {}", e))?;
        } else {
            with_branch_ref_lock(&self.vcs_dir, &branch, || {
                let branch_path = self.vcs_dir.join("refs").join("heads").join(&branch);
                let observed_head = if branch_path.exists() {
                    Some(
                        fs::read_to_string(&branch_path)
                            .map_err(|error| format!("Failed to read branch {branch}: {error}"))?
                            .trim()
                            .to_string(),
                    )
                } else {
                    None
                };
                if observed_head != expected_head {
                    return Err(format!(
                        "Branch '{branch}' advanced in another workspace; refresh this workspace before committing"
                    ));
                }
                atomicwrites::AtomicFile::new(&branch_path, atomicwrites::AllowOverwrite)
                    .write(|file| {
                        use std::io::Write;
                        file.write_all(commit_id.as_bytes())
                    })
                    .map_err(|error| format!("Failed to update branch {branch}: {error}"))?;
                Ok(())
            })?;
        }
        self.update_workspace_base(Some(&commit_id))?;

        Ok(commit)
    }

    /// Retrieve commit history (DAG traversal from HEAD).
    pub fn log(&self, limit: Option<usize>) -> Result<Vec<VcsCommit>, String> {
        let mut commits = Vec::new();
        let max = limit.unwrap_or(usize::MAX);

        let mut pending = self
            .workspace_base_commit()?
            .map(|commit| vec![commit.commit_id])
            .unwrap_or_default();
        let mut visited = HashSet::new();

        while let Some(id) = pending.pop() {
            if commits.len() >= max || !visited.insert(id.clone()) {
                continue;
            }
            let commit = self.get_commit(&id)?;
            pending.extend(commit.parent_ids.iter().rev().cloned());
            commits.push(commit);
        }

        Ok(commits)
    }

    /// List all local branches.
    pub fn branch_list(&self) -> Result<Vec<String>, String> {
        let heads_dir = self.vcs_dir.join("refs").join("heads");
        if !heads_dir.exists() {
            return Ok(vec!["main".to_string()]);
        }
        let mut branches = Vec::new();
        for entry in
            fs::read_dir(&heads_dir).map_err(|e| format!("Read heads dir failed: {}", e))?
        {
            let entry = entry.map_err(|e| format!("Entry error: {}", e))?;
            if entry.path().is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    branches.push(name.to_string());
                }
            }
        }
        if branches.is_empty() {
            branches.push("main".to_string());
        }
        branches.sort();
        Ok(branches)
    }

    pub fn branch_head_ids(&self) -> Result<Vec<(String, String)>, String> {
        let mut heads = Vec::new();
        for branch in self.branch_list()? {
            let path = self.vcs_dir.join("refs").join("heads").join(&branch);
            if path.is_file() {
                heads.push((branch.clone(), self.branch_head(&branch)?.commit_id));
            }
        }
        Ok(heads)
    }

    pub fn branch_ancestry_ids(&self, branch: &str, limit: usize) -> Result<Vec<String>, String> {
        if limit == 0 || limit > 1024 {
            return Err("Branch ancestry limit must be between 1 and 1024".into());
        }
        let head = self.branch_head(branch)?;
        let mut ancestors = self
            .ancestor_distances(&head.commit_id)?
            .into_iter()
            .collect::<Vec<_>>();
        ancestors.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
        ancestors.truncate(limit);
        Ok(ancestors.into_iter().map(|(id, _)| id).collect())
    }

    pub fn advertise_branch_heads(
        &self,
        known_heads: &[KnownBranchHead],
    ) -> Result<Vec<BranchHeadAdvertisement>, String> {
        if known_heads.len() > 1024 {
            return Err("Too many known branch heads in divergence request".into());
        }
        let mut known_by_branch = HashMap::new();
        let mut total_ancestors = 0usize;
        for known in known_heads {
            if !is_valid_branch_name(&known.branch)
                || !is_object_id(&known.head_commit)
                || known.ancestors.len() > 1024
                || !known.ancestors.iter().all(|id| is_object_id(id))
                || !known.ancestors.contains(&known.head_commit)
                || known_by_branch
                    .insert(known.branch.as_str(), known)
                    .is_some()
            {
                return Err("Known branch ancestry list is invalid".into());
            }
            total_ancestors = total_ancestors
                .checked_add(known.ancestors.len())
                .ok_or_else(|| "Known branch ancestry count overflow".to_string())?;
        }
        if total_ancestors > 16_384 {
            return Err("Known branch ancestry exceeds the divergence request limit".into());
        }
        let mut advertisements = Vec::new();
        for branch in self.branch_list()? {
            if !self
                .vcs_dir
                .join("refs")
                .join("heads")
                .join(&branch)
                .is_file()
            {
                continue;
            }
            let remote = self.branch_head(&branch)?;
            let known = known_by_branch.get(branch.as_str()).copied();
            let known_head = known.map(|known| known.head_commit.clone());
            let common = if let Some(known) = known {
                let remote_ancestors = self.ancestor_distances(&remote.commit_id)?;
                known
                    .ancestors
                    .iter()
                    .filter_map(|id| remote_ancestors.get(id).map(|distance| (*distance, id)))
                    .min_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)))
            } else {
                None
            };
            let (common_base, ahead_commits, changed_scopes) =
                if let Some((distance, base_id)) = common {
                    let changed = self.changed_scope_summaries(base_id, &remote.commit_id)?;
                    (Some(base_id.clone()), Some(distance), changed)
                } else {
                    (None, None, Vec::new())
                };
            advertisements.push(BranchHeadAdvertisement {
                branch,
                head_commit: remote.commit_id,
                known_head,
                common_base,
                ahead_commits,
                changed_scopes,
            });
        }
        Ok(advertisements)
    }

    pub fn changed_scope_summaries(
        &self,
        base_commit_id: &str,
        head_commit_id: &str,
    ) -> Result<Vec<ChangedScopeSummary>, String> {
        let base = self.get_commit(base_commit_id)?;
        let head = self.get_commit(head_commit_id)?;
        let base_snapshot = self.current_ast_scopes(&base)?;
        let head_snapshot = self.current_ast_scopes(&head)?;
        let base_scopes = scope_map(&base_snapshot)?;
        let head_scopes = scope_map(&head_snapshot)?;
        let mut ids = base_scopes
            .keys()
            .chain(head_scopes.keys())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        ids.sort();
        let mut changed = Vec::new();
        for scope_id in ids {
            let base_scope = base_scopes.get(&scope_id).copied();
            let head_scope = head_scopes.get(&scope_id).copied();
            if same_scope_content(base_scope, head_scope) {
                continue;
            }
            let representative = head_scope.or(base_scope).unwrap();
            changed.push(ChangedScopeSummary {
                scope_id,
                file_path: representative.file_path.clone(),
                name: representative.name.clone(),
            });
        }
        Ok(changed)
    }

    pub fn commit_distance_between(
        &self,
        head_id: &str,
        ancestor_id: &str,
    ) -> Result<Option<usize>, String> {
        let mut pending = vec![(head_id.to_string(), 0usize)];
        let mut visited = HashSet::new();
        while let Some((commit_id, distance)) = pending.pop() {
            if commit_id == ancestor_id {
                return Ok(Some(distance));
            }
            if !visited.insert(commit_id.clone()) {
                continue;
            }
            if visited.len() > 100_000 {
                return Err("Commit ancestry exceeds divergence scan limit".into());
            }
            let commit = self.get_commit(&commit_id)?;
            pending.extend(
                commit
                    .parent_ids
                    .into_iter()
                    .map(|parent| (parent, distance.saturating_add(1))),
            );
        }
        Ok(None)
    }

    pub fn compare_branch_scopes(
        &self,
        other_branch: &str,
    ) -> Result<BranchScopeComparison, String> {
        if !is_valid_branch_name(other_branch) {
            return Err("Invalid branch name".into());
        }
        let current_branch = self.current_branch()?;
        if current_branch.starts_with("detached:") {
            return Err("Branch comparison requires a checked-out branch".into());
        }
        let current = self.branch_head(&current_branch)?;
        let other = self.branch_head(other_branch)?;
        let base = self.common_ancestor(&current.commit_id, &other.commit_id)?;
        if base.format_version < 3 || current.format_version < 3 || other.format_version < 3 {
            return Err(
                "AST ghost comparison requires commits created with sb-code format v3 or newer"
                    .into(),
            );
        }
        if base.ast_parser_version == 0
            || current.ast_parser_version == 0
            || other.ast_parser_version == 0
        {
            return Err(
                "AST comparison requires parser-versioned snapshots; re-save these commits with a supported sb-code version"
                    .into(),
            );
        }
        let base_snapshot = self.current_ast_scopes(&base)?;
        let current_snapshot = self.current_ast_scopes(&current)?;
        let other_snapshot = self.current_ast_scopes(&other)?;
        let base_scopes = scope_map(&base_snapshot)?;
        let current_scopes = scope_map(&current_snapshot)?;
        let other_scopes = scope_map(&other_snapshot)?;
        let mut ids = base_scopes
            .keys()
            .chain(current_scopes.keys())
            .chain(other_scopes.keys())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        ids.sort();
        let mut changes = Vec::new();
        for id in ids {
            let base_scope = base_scopes.get(&id).copied();
            let current_scope = current_scopes.get(&id).copied();
            let other_scope = other_scopes.get(&id).copied();
            let current_changed = !same_scope_content(base_scope, current_scope);
            let other_changed = !same_scope_content(base_scope, other_scope);
            if !current_changed && !other_changed {
                continue;
            }
            let status = if [base_scope, current_scope, other_scope]
                .into_iter()
                .flatten()
                .any(|scope| scope.ambiguous)
            {
                "ambiguous"
            } else if current_changed
                && other_changed
                && !same_scope_content(current_scope, other_scope)
            {
                "conflict"
            } else if current_changed && other_changed {
                "same-change"
            } else if other_changed {
                "other-only"
            } else {
                "current-only"
            };
            let representative = other_scope.or(current_scope).or(base_scope).unwrap();
            let base_content = base_scope
                .map(|scope| self.read_scope_content(&base, scope))
                .transpose()?;
            let current_content = current_scope
                .map(|scope| self.read_scope_content(&current, scope))
                .transpose()?;
            let other_content = other_scope
                .map(|scope| self.read_scope_content(&other, scope))
                .transpose()?;
            let parser_diagnostic = [base_scope, current_scope, other_scope]
                .into_iter()
                .flatten()
                .find_map(|scope| scope.parser_diagnostic.clone());
            changes.push(ScopeBranchChange {
                scope_id: id,
                file_path: representative.file_path.clone(),
                name: representative.name.clone(),
                status: status.to_string(),
                base: base_content,
                current: current_content,
                other: other_content,
                parser_diagnostic,
            });
        }
        Ok(BranchScopeComparison {
            current_branch,
            other_branch: other_branch.to_string(),
            base_commit: base.commit_id,
            current_commit: current.commit_id,
            other_commit: other.commit_id,
            changes,
        })
    }

    pub fn plan_branch_integration(&self, other_branch: &str) -> Result<IntegrationPlan, String> {
        let comparison = self.compare_branch_scopes(other_branch)?;
        let workspace_clean = self.status()?.is_clean && self.workspace_base_matches_head()?;
        let mut auto_mergeable = Vec::new();
        let mut manual_required = Vec::new();

        for change in &comparison.changes {
            if let Some(diagnostic) = &change.parser_diagnostic {
                manual_required.push(IntegrationPlanEntry {
                    change: change.clone(),
                    action: "manual".to_string(),
                    reason: format!(
                        "Parser could not classify this source and preserved it as Opaque: {}",
                        diagnostic
                    ),
                });
                continue;
            }
            let opaque =
                change.scope_id.contains("::opaque:") || change.name.starts_with("opaque region");
            let entry = match change.status.as_str() {
                "other-only" if !opaque => Some((
                    &mut auto_mergeable,
                    "take-other",
                    "Nur der Quell-Branch hat diesen eindeutig erkannten Scope geändert.",
                )),
                "other-only"
                    if change.base.is_some()
                        && change.current.is_some()
                        && change.other.is_some() =>
                {
                    Some((
                        &mut auto_mergeable,
                        "replace-opaque",
                        "Einseitige Ersetzung eines stabil begrenzten Opaque-Bereichs; manuelle semantische Prüfung empfohlen.",
                    ))
                }
                "other-only" => Some((
                    &mut manual_required,
                    "manual",
                    "Opaque-Bereich wurde strukturell hinzugefügt, entfernt oder umgrenzt; Identität ist nicht stabil genug für automatische Übernahme.",
                )),
                "same-change" => Some((
                    &mut auto_mergeable,
                    "already-identical",
                    "Beide Branches enthalten bereits denselben Scope-Inhalt.",
                )),
                "current-only" => Some((
                    &mut auto_mergeable,
                    "keep-current",
                    "Nur der aktuelle Branch hat diesen Scope geändert; keine Übernahme erforderlich.",
                )),
                _ => Some((
                    &mut manual_required,
                    "manual",
                    "Konflikt, mehrdeutige Identität oder beidseitige Opaque-Änderung benötigt manuelle Entscheidung.",
                )),
            };
            if let Some((destination, action, reason)) = entry {
                destination.push(IntegrationPlanEntry {
                    change: change.clone(),
                    action: action.to_string(),
                    reason: reason.to_string(),
                });
            }
        }

        let mut blocked_reasons = Vec::new();
        if !workspace_clean {
            blocked_reasons.push(
                "Arbeitsverzeichnis ist verändert oder sein Branch-Head wurde in einem anderen Workspace aktualisiert; erst committen oder mit `sb code checkout <branch>` aktualisieren."
                    .to_string(),
            );
        }
        if !manual_required.is_empty() {
            let manual_summary = manual_required
                .iter()
                .map(|entry| format!("{} [{}]", entry.change.name, entry.change.status))
                .collect::<Vec<_>>()
                .join(", ");
            blocked_reasons.push(format!(
                "{} Scope(s) benötigen eine manuelle Entscheidung: {}.",
                manual_required.len(),
                manual_summary
            ));
        }
        if comparison.changes.is_empty() {
            blocked_reasons
                .push("Die Branches enthalten keine unterschiedlichen AST-Scopes.".into());
        }

        let changed_names = comparison
            .changes
            .iter()
            .map(|change| change.name.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let mut test_scope_candidates = comparison
            .changes
            .iter()
            .filter(|change| {
                let path = change.file_path.replace('\\', "/").to_ascii_lowercase();
                path.contains("/tests/")
                    || path.starts_with("tests/")
                    || change.name.to_ascii_lowercase().starts_with("test")
                    || changed_names.iter().any(|name| {
                        name.starts_with("test")
                            && (change.name.to_ascii_lowercase().contains(name)
                                || name.contains(&change.name.to_ascii_lowercase()))
                    })
            })
            .map(|change| format!("{} ({})", change.name, change.file_path))
            .collect::<Vec<_>>();
        test_scope_candidates.sort();
        test_scope_candidates.dedup();

        Ok(IntegrationPlan {
            current_branch: comparison.current_branch,
            other_branch: comparison.other_branch,
            base_commit: comparison.base_commit,
            current_commit: comparison.current_commit,
            other_commit: comparison.other_commit,
            ast_parser_version: 3,
            auto_mergeable,
            manual_required,
            blocked_reasons: blocked_reasons.clone(),
            test_scope_candidates,
            test_scope_basis:
                "Heuristische Namens- und Pfadübereinstimmung; keine vollständige Abhängigkeitsanalyse."
                    .to_string(),
            semantic_validation: "Nicht ausgeführt; syntaktische Scope-Kompatibilität garantiert keine semantische Korrektheit."
                .to_string(),
            workspace_clean,
            ready_to_integrate: blocked_reasons.is_empty(),
        })
    }

    pub fn prepare_integration_conflicts(
        &self,
        other_branch: &str,
    ) -> Result<IntegrationConflictState, String> {
        let plan = self.plan_branch_integration(other_branch)?;
        if !plan.workspace_clean {
            return Err(
                "Cannot prepare integration conflicts with uncommitted workspace changes".into(),
            );
        }
        if plan.manual_required.is_empty() {
            return Err("The integration plan contains no manual scope conflicts".into());
        }
        let state = IntegrationConflictState {
            format_version: 1,
            current_branch: plan.current_branch,
            other_branch: plan.other_branch,
            base_commit: plan.base_commit,
            current_commit: plan.current_commit,
            other_commit: plan.other_commit,
            conflicts: plan
                .manual_required
                .into_iter()
                .map(|entry| IntegrationConflict {
                    entry,
                    resolution: None,
                })
                .collect(),
        };
        self.write_conflict_state(&state)?;
        Ok(state)
    }

    pub fn integration_conflicts(&self) -> Result<Option<IntegrationConflictState>, String> {
        let path = self.integration_conflict_path();
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(&path)
            .map_err(|error| format!("Failed to read integration conflicts: {error}"))?;
        let state: IntegrationConflictState = serde_json::from_slice(&data)
            .map_err(|error| format!("Invalid integration conflict state: {error}"))?;
        if state.format_version != 1 {
            return Err(format!(
                "Unsupported integration conflict state version: {}",
                state.format_version
            ));
        }
        Ok(Some(state))
    }

    pub fn discard_integration_conflicts(&self) -> Result<bool, String> {
        let path = self.integration_conflict_path();
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!(
                "Could not discard integration conflict state: {error}"
            )),
        }
    }

    pub fn resolve_integration_conflict(
        &self,
        scope_id: &str,
        resolution: ConflictResolution,
    ) -> Result<IntegrationConflictState, String> {
        let mut state = self
            .integration_conflicts()?
            .ok_or_else(|| "No pending integration conflicts".to_string())?;
        self.validate_conflict_heads(&state)?;
        let conflict = state
            .conflicts
            .iter_mut()
            .find(|conflict| conflict.entry.change.scope_id == scope_id)
            .ok_or_else(|| format!("Unknown integration conflict scope '{}'", scope_id))?;
        conflict.resolution = Some(resolution);
        self.write_conflict_state(&state)?;
        Ok(state)
    }

    pub fn finalize_integration_conflicts(
        &mut self,
        author_callsign: &str,
    ) -> Result<VcsCommit, String> {
        let state = self
            .integration_conflicts()?
            .ok_or_else(|| "No pending integration conflicts".to_string())?;
        self.validate_conflict_heads(&state)?;
        let unresolved = state
            .conflicts
            .iter()
            .filter(|conflict| conflict.resolution.is_none())
            .map(|conflict| conflict.entry.change.scope_id.as_str())
            .collect::<Vec<_>>();
        if !unresolved.is_empty() {
            return Err(format!(
                "Resolve every scope conflict before finalizing: {}",
                unresolved.join(", ")
            ));
        }
        let resolutions = state
            .conflicts
            .iter()
            .filter_map(|conflict| {
                conflict
                    .resolution
                    .clone()
                    .map(|resolution| (conflict.entry.change.scope_id.clone(), resolution))
            })
            .collect::<HashMap<_, _>>();
        let commit = self.integrate_branch_scopes_with_resolutions(
            &state.other_branch,
            author_callsign,
            Some(&state.current_commit),
            Some(&state.other_commit),
            &resolutions,
        )?;
        fs::remove_file(self.integration_conflict_path()).map_err(|error| {
            format!("Integration committed but conflict cleanup failed: {error}")
        })?;
        Ok(commit)
    }

    fn integration_conflict_path(&self) -> PathBuf {
        self.workspace_root.join(".sb").join("conflicts.json")
    }

    fn write_conflict_state(&self, state: &IntegrationConflictState) -> Result<(), String> {
        let path = self.integration_conflict_path();
        let parent = path
            .parent()
            .ok_or_else(|| "Integration conflict path has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create conflict state directory: {error}"))?;
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|error| format!("Failed to serialize integration conflicts: {error}"))?;
        atomicwrites::AtomicFile::new(&path, atomicwrites::AllowOverwrite)
            .write(|file| {
                use std::io::Write;
                file.write_all(&bytes)
            })
            .map_err(|error| format!("Failed to atomically store conflict state: {error}"))
    }

    fn validate_conflict_heads(&self, state: &IntegrationConflictState) -> Result<(), String> {
        let current_branch = self.current_branch()?;
        if current_branch != state.current_branch {
            return Err("Current branch changed while integration conflicts were pending".into());
        }
        let current = self.branch_head(&state.current_branch)?;
        let other = self.branch_head(&state.other_branch)?;
        if current.commit_id != state.current_commit || other.commit_id != state.other_commit {
            return Err(
                "Branch heads changed while integration conflicts were pending; recreate the conflict plan"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn add_managed_workspace(
        &self,
        branch: &str,
        target_path: &Path,
    ) -> Result<ManagedWorkspace, String> {
        with_workspace_registry_lock(&self.vcs_dir.join("workspaces"), || {
            self.add_managed_workspace_locked(branch, target_path)
        })
    }

    fn add_managed_workspace_locked(
        &self,
        branch: &str,
        target_path: &Path,
    ) -> Result<ManagedWorkspace, String> {
        if !is_valid_branch_name(branch) {
            return Err("Invalid workspace branch name".into());
        }
        let commit = self.branch_head(branch)?;
        if target_path.exists() {
            return Err(format!(
                "Workspace destination already exists: {}",
                target_path.display()
            ));
        }
        let absolute_target = if target_path.is_absolute() {
            target_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| format!("Could not resolve current directory: {error}"))?
                .join(target_path)
        };
        let parent = absolute_target
            .parent()
            .ok_or_else(|| "Workspace destination must have a parent directory".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create workspace parent: {error}"))?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|error| format!("Could not canonicalize workspace parent: {error}"))?;
        let target_name = absolute_target
            .file_name()
            .ok_or_else(|| "Workspace destination must have a file name".to_string())?;
        let canonical_target = canonical_parent.join(target_name);
        let canonical_repo = self
            .workspace_root
            .canonicalize()
            .map_err(|error| format!("Could not canonicalize repository root: {error}"))?;
        if canonical_target.starts_with(&canonical_repo)
            || canonical_repo.starts_with(&canonical_target)
        {
            return Err("Managed workspaces must be outside the repository tree".into());
        }

        let registry_dir = self.vcs_dir.join("workspaces");
        fs::create_dir_all(&registry_dir)
            .map_err(|error| format!("Could not create workspace registry: {error}"))?;
        let ports = allocate_workspace_ports(&registry_dir)?;
        let id = uuid::Uuid::new_v4().to_string();
        let repository_vcs_dir = self
            .vcs_dir
            .canonicalize()
            .map_err(|error| format!("Could not canonicalize VCS object store: {error}"))?;
        let managed = ManagedWorkspace {
            format_version: 1,
            id: id.clone(),
            path: canonical_target.clone(),
            repository_vcs_dir,
            branch: branch.to_string(),
            ports,
        };
        let created_path = canonical_target.clone();
        let result = (|| {
            fs::create_dir(&canonical_target)
                .map_err(|error| format!("Could not create workspace directory: {error}"))?;
            let tree = self.get_tree(&commit.tree_hash)?;
            for (rel_path, entry) in &tree.entries {
                if entry.is_dir {
                    continue;
                }
                let destination = safe_workspace_file_path(&canonical_target, rel_path, true)?;
                let blob = self.get_blob(&entry.blake3_hash)?;
                fs::write(destination, blob)
                    .map_err(|error| format!("Could not materialize '{rel_path}': {error}"))?;
            }
            let sb_dir = canonical_target.join(".sb");
            fs::create_dir(&sb_dir).map_err(|error| {
                format!("Could not create workspace metadata directory: {error}")
            })?;
            fs::write(sb_dir.join("HEAD"), format!("ref: refs/heads/{branch}\n"))
                .map_err(|error| format!("Could not initialize workspace HEAD: {error}"))?;
            fs::write(sb_dir.join("BASE"), format!("{}\n", commit.commit_id))
                .map_err(|error| format!("Could not initialize workspace baseline: {error}"))?;
            let metadata_bytes = serde_json::to_vec_pretty(&managed)
                .map_err(|error| format!("Could not serialize workspace metadata: {error}"))?;
            atomicwrites::AtomicFile::new(
                sb_dir.join("workspace.json"),
                atomicwrites::AllowOverwrite,
            )
            .write(|file| {
                use std::io::Write;
                file.write_all(&metadata_bytes)
            })
            .map_err(|error| format!("Could not persist workspace metadata: {error}"))?;

            let registry_bytes = serde_json::to_vec_pretty(&managed).map_err(|error| {
                format!("Could not serialize workspace registry entry: {error}")
            })?;
            atomicwrites::AtomicFile::new(
                registry_dir.join(format!("{id}.json")),
                atomicwrites::AllowOverwrite,
            )
            .write(|file| {
                use std::io::Write;
                file.write_all(&registry_bytes)
            })
            .map_err(|error| format!("Could not register managed workspace: {error}"))?;
            Ok(())
        })();
        if let Err(error) = result {
            let registry_entry = registry_dir.join(format!("{id}.json"));
            if registry_entry.exists() {
                fs::remove_file(&registry_entry).map_err(|cleanup| {
                    format!("{error}; additionally failed to remove workspace registry entry: {cleanup}")
                })?;
            }
            if created_path.exists() {
                fs::remove_dir_all(&created_path).map_err(|cleanup| {
                    format!("{error}; additionally failed to clean new workspace: {cleanup}")
                })?;
            }
            return Err(error);
        }
        Ok(managed)
    }

    pub fn managed_workspaces(&self) -> Result<Vec<ManagedWorkspace>, String> {
        let registry_dir = self.vcs_dir.join("workspaces");
        if !registry_dir.exists() {
            return Ok(Vec::new());
        }
        let mut workspaces = Vec::new();
        for entry in fs::read_dir(registry_dir)
            .map_err(|error| format!("Could not read workspace registry: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("Could not read workspace registry entry: {error}"))?;
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("json")
            {
                continue;
            }
            let bytes = fs::read(entry.path())
                .map_err(|error| format!("Could not read workspace registry entry: {error}"))?;
            let workspace: ManagedWorkspace = serde_json::from_slice(&bytes)
                .map_err(|error| format!("Invalid workspace registry entry: {error}"))?;
            if workspace.format_version != 1 {
                return Err(format!(
                    "Unsupported managed workspace version in '{}'",
                    entry.path().display()
                ));
            }
            workspaces.push(workspace);
        }
        workspaces.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(workspaces)
    }

    pub fn remove_managed_workspace(&self, target_path: &Path, force: bool) -> Result<(), String> {
        with_workspace_registry_lock(&self.vcs_dir.join("workspaces"), || {
            self.remove_managed_workspace_locked(target_path, force)
        })
    }

    fn remove_managed_workspace_locked(
        &self,
        target_path: &Path,
        force: bool,
    ) -> Result<(), String> {
        let requested_path = if target_path.is_absolute() {
            target_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| format!("Could not resolve workspace path: {error}"))?
                .join(target_path)
        };
        let canonical_target = requested_path.canonicalize().map_err(|error| {
            format!(
                "Could not resolve workspace '{}': {error}",
                requested_path.display()
            )
        })?;
        if fs::symlink_metadata(&canonical_target)
            .map_err(|error| format!("Could not inspect workspace path: {error}"))?
            .file_type()
            .is_symlink()
        {
            return Err("Refusing to remove a symlink as a managed workspace".into());
        }
        let canonical_repo = self
            .workspace_root
            .canonicalize()
            .map_err(|error| format!("Could not canonicalize repository root: {error}"))?;
        if canonical_target == canonical_repo
            || canonical_target.starts_with(&canonical_repo)
            || canonical_repo.starts_with(&canonical_target)
        {
            return Err("Refusing to remove the repository or a path containing it".into());
        }
        let metadata_path = canonical_target.join(".sb").join("workspace.json");
        let metadata_bytes = fs::read(&metadata_path)
            .map_err(|error| format!("Could not read managed workspace metadata: {error}"))?;
        let workspace: ManagedWorkspace = serde_json::from_slice(&metadata_bytes)
            .map_err(|error| format!("Invalid managed workspace metadata: {error}"))?;
        let canonical_metadata_vcs_dir = workspace
            .repository_vcs_dir
            .canonicalize()
            .map_err(|error| format!("Could not resolve workspace object store: {error}"))?;
        let canonical_engine_vcs_dir = self
            .vcs_dir
            .canonicalize()
            .map_err(|error| format!("Could not resolve repository object store: {error}"))?;
        if workspace.path.canonicalize().ok().as_deref() != Some(canonical_target.as_path())
            || canonical_metadata_vcs_dir != canonical_engine_vcs_dir
        {
            return Err(
                "Workspace metadata does not match this repository and working directory".into(),
            );
        }
        let registry_dir = self.vcs_dir.join("workspaces");
        let registry_path = registry_dir.join(format!("{}.json", workspace.id));
        let registered_bytes = fs::read(&registry_path)
            .map_err(|error| format!("Workspace is not registered in this repository: {error}"))?;
        let registered: ManagedWorkspace = serde_json::from_slice(&registered_bytes)
            .map_err(|error| format!("Invalid workspace registry entry: {error}"))?;
        if registered != workspace {
            return Err("Workspace metadata and repository registry entry do not match".into());
        }
        if !force {
            let managed_engine = Self::open(&canonical_target)?;
            if !managed_engine.status()?.is_clean
                || !managed_engine.workspace_base_matches_head()?
            {
                return Err(
                    "Workspace has uncommitted changes or is behind its branch; use --force to remove it anyway"
                        .into(),
                );
            }
        }

        let quarantine_path = canonical_target
            .with_file_name(format!(".sb-workspace-remove-{}", uuid::Uuid::new_v4()));
        fs::rename(&canonical_target, &quarantine_path).map_err(|error| {
            format!("Could not stage workspace removal (it may be in use): {error}")
        })?;
        if let Err(error) = fs::remove_file(&registry_path) {
            fs::rename(&quarantine_path, &canonical_target).map_err(|restore| {
                format!(
                    "Could not remove workspace registry entry: {error}; also could not restore workspace: {restore}"
                )
            })?;
            return Err(format!(
                "Could not remove workspace registry entry: {error}"
            ));
        }
        fs::remove_dir_all(&quarantine_path).map_err(|error| {
            format!(
                "Workspace was unregistered but staged directory '{}' could not be removed: {error}",
                quarantine_path.display()
            )
        })
    }

    pub fn prune_managed_workspaces(&self) -> Result<Vec<PathBuf>, String> {
        with_workspace_registry_lock(&self.vcs_dir.join("workspaces"), || {
            self.prune_managed_workspaces_locked()
        })
    }

    fn prune_managed_workspaces_locked(&self) -> Result<Vec<PathBuf>, String> {
        let workspaces = self.managed_workspaces()?;
        let registry_dir = self.vcs_dir.join("workspaces");

        let mut removed = Vec::new();
        for workspace in workspaces {
            if workspace.path.exists() {
                continue;
            }
            let registry_path = registry_dir.join(format!("{}.json", workspace.id));
            fs::remove_file(&registry_path).map_err(|error| {
                format!(
                    "Could not prune missing workspace '{}' from registry: {error}",
                    workspace.path.display()
                )
            })?;
            removed.push(workspace.path);
        }
        Ok(removed)
    }

    pub fn integrate_branch_scopes(
        &mut self,
        other_branch: &str,
        author_callsign: &str,
    ) -> Result<VcsCommit, String> {
        self.integrate_branch_scopes_for_heads(other_branch, author_callsign, None, None)
    }

    pub fn integrate_branch_scopes_for_heads(
        &mut self,
        other_branch: &str,
        author_callsign: &str,
        expected_current_commit: Option<&str>,
        expected_other_commit: Option<&str>,
    ) -> Result<VcsCommit, String> {
        self.integrate_branch_scopes_with_resolutions(
            other_branch,
            author_callsign,
            expected_current_commit,
            expected_other_commit,
            &HashMap::new(),
        )
    }

    pub fn integrate_branch_scopes_with_resolutions(
        &mut self,
        other_branch: &str,
        author_callsign: &str,
        expected_current_commit: Option<&str>,
        expected_other_commit: Option<&str>,
        resolutions: &HashMap<String, ConflictResolution>,
    ) -> Result<VcsCommit, String> {
        let plan = self.plan_branch_integration(other_branch)?;
        if expected_current_commit.is_some_and(|expected| expected != plan.current_commit)
            || expected_other_commit.is_some_and(|expected| expected != plan.other_commit)
        {
            return Err(
                "Branch heads changed after the integration preview; refresh the plan before applying."
                    .into(),
            );
        }
        if !plan.workspace_clean {
            return Err("Cannot integrate with uncommitted workspace changes".into());
        }
        let unresolved = plan
            .manual_required
            .iter()
            .filter(|entry| !resolutions.contains_key(&entry.change.scope_id))
            .map(|entry| entry.change.scope_id.as_str())
            .collect::<Vec<_>>();
        if !unresolved.is_empty() {
            return Err(format!(
                "Integration has unresolved scope conflicts: {}",
                unresolved.join(", ")
            ));
        }
        if plan.auto_mergeable.is_empty() && plan.manual_required.is_empty() {
            return Err("There are no AST scope changes to integrate".into());
        }

        let comparison = self.compare_branch_scopes(other_branch)?;
        let base = self.get_commit(&plan.base_commit)?;
        let current = self.get_commit(&plan.current_commit)?;
        let other = self.get_commit(&plan.other_commit)?;
        let base_tree = self.get_tree(&base.tree_hash)?;
        let current_tree = self.get_tree(&current.tree_hash)?;
        let other_tree = self.get_tree(&other.tree_hash)?;
        let base_snapshot = self.current_ast_scopes(&base)?;
        let current_snapshot = self.current_ast_scopes(&current)?;
        let other_snapshot = self.current_ast_scopes(&other)?;
        let current_scopes = scope_map(&current_snapshot)?;
        let other_scopes = scope_map(&other_snapshot)?;

        let file_paths = [&base_tree, &current_tree, &other_tree]
            .into_iter()
            .flat_map(|tree| {
                tree.entries
                    .iter()
                    .filter(|(_, entry)| !entry.is_dir)
                    .map(|(path, _)| path.clone())
            })
            .collect::<HashSet<_>>();
        for path in &file_paths {
            let base_entry = base_tree.entries.get(path).filter(|entry| !entry.is_dir);
            let current_entry = current_tree.entries.get(path).filter(|entry| !entry.is_dir);
            let other_entry = other_tree.entries.get(path).filter(|entry| !entry.is_dir);
            let unchanged = match (base_entry, current_entry, other_entry) {
                (Some(base), Some(current), Some(other)) => {
                    base.blake3_hash == current.blake3_hash && base.blake3_hash == other.blake3_hash
                }
                (None, None, None) => true,
                _ => false,
            };
            if unchanged {
                continue;
            }

            let base_content = base_entry
                .map(|_| self.read_tree_file(&base_tree, path))
                .transpose()?;
            let current_content = current_entry
                .map(|_| self.read_tree_file(&current_tree, path))
                .transpose()?;
            let other_content = other_entry
                .map(|_| self.read_tree_file(&other_tree, path))
                .transpose()?;
            let base_outside = extract_outside_scopes(
                base_content.as_deref().unwrap_or_default(),
                &base_snapshot,
                path,
            )?;
            let current_outside = extract_outside_scopes(
                current_content.as_deref().unwrap_or_default(),
                &current_snapshot,
                path,
            )?;
            let other_outside = extract_outside_scopes(
                other_content.as_deref().unwrap_or_default(),
                &other_snapshot,
                path,
            )?;
            let structural_file_change =
                base_entry.is_none() || current_entry.is_none() || other_entry.is_none();
            let outside_matches = if structural_file_change {
                [
                    base_outside.as_str(),
                    current_outside.as_str(),
                    other_outside.as_str(),
                ]
                .into_iter()
                .all(|outside| outside.trim().is_empty())
            } else {
                base_outside == current_outside && base_outside == other_outside
            };
            if !outside_matches {
                return Err(format!(
                    "Cannot safely integrate '{}': changes outside recognized AST scopes are present",
                    path
                ));
            }
        }

        let mut contents = HashMap::<String, String>::new();
        let mut other_contents = HashMap::<String, String>::new();
        let mut patches = HashMap::<String, Vec<(usize, usize, String, String)>>::new();
        let mut deleted_files = HashSet::<String>::new();
        for change in &comparison.changes {
            let take_other = change.status == "other-only"
                || (plan
                    .manual_required
                    .iter()
                    .any(|entry| entry.change.scope_id == change.scope_id)
                    && resolutions.get(&change.scope_id) == Some(&ConflictResolution::Other));
            if !take_other {
                continue;
            }
            let current_scope = current_scopes.get(&change.scope_id).copied();
            let other_scope = other_scopes.get(&change.scope_id).copied();
            match (current_scope, other_scope) {
                (Some(current_scope), Some(other_scope)) => {
                    let source_content = other_contents
                        .entry(other_scope.file_path.clone())
                        .or_insert(self.read_tree_file(&other_tree, &other_scope.file_path)?);
                    let replacement = snapshot_content(source_content, other_scope)?;
                    if current_scope.content_hash != other_scope.content_hash {
                        let start = current_scope.start_line.checked_sub(1).ok_or_else(|| {
                            format!("Invalid AST line range for '{}'", change.scope_id)
                        })?;
                        patches
                            .entry(current_scope.file_path.clone())
                            .or_default()
                            .push((
                                start,
                                current_scope.end_line,
                                replacement,
                                current_scope.scope_id.clone(),
                            ));
                    }
                }
                (Some(current_scope), None) => {
                    let start = current_scope.start_line.checked_sub(1).ok_or_else(|| {
                        format!("Invalid AST line range for '{}'", change.scope_id)
                    })?;
                    patches
                        .entry(current_scope.file_path.clone())
                        .or_default()
                        .push((
                            start,
                            current_scope.end_line,
                            String::new(),
                            current_scope.scope_id.clone(),
                        ));
                }
                (None, Some(other_scope)) => {
                    let path = &other_scope.file_path;
                    let source_content = other_contents
                        .entry(path.clone())
                        .or_insert(self.read_tree_file(&other_tree, path)?);
                    if !current_tree
                        .entries
                        .get(path)
                        .is_some_and(|entry| !entry.is_dir)
                    {
                        if base_tree
                            .entries
                            .get(path)
                            .is_some_and(|entry| !entry.is_dir)
                        {
                            return Err(format!(
                                "Cannot safely add AST scope '{}' to a missing current file",
                                change.scope_id
                            ));
                        }
                        if extract_outside_scopes(source_content, &other_snapshot, path)?
                            .trim()
                            .is_empty()
                        {
                            contents.insert(path.clone(), source_content.clone());
                            continue;
                        }
                        return Err(format!(
                            "Cannot create '{}': it contains source outside recognized AST scopes",
                            path
                        ));
                    }

                    contents
                        .entry(path.clone())
                        .or_insert(self.read_tree_file(&current_tree, path)?);
                    let insertion_line = find_scope_insertion_line(
                        &change.scope_id,
                        other_scope,
                        &other_snapshot,
                        &current_scopes,
                    )
                    .ok_or_else(|| {
                        format!(
                            "Cannot place new AST scope '{}' unambiguously in '{}'",
                            change.scope_id, path
                        )
                    })?;
                    patches.entry(path.clone()).or_default().push((
                        insertion_line,
                        insertion_line,
                        snapshot_content(source_content, other_scope)?,
                        change.scope_id.clone(),
                    ));
                }
                (None, None) => {
                    return Err(format!(
                        "AST scope '{}' is absent from both branch heads",
                        change.scope_id
                    ));
                }
            }
        }

        for (path, file_patches) in &mut patches {
            let content = contents
                .entry(path.clone())
                .or_insert(self.read_tree_file(&current_tree, path)?);
            file_patches
                .sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.3.cmp(&right.3)));
            for pair in file_patches.windows(2) {
                let overlaps = pair[1].1 > pair[0].0
                    || (pair[1].0 == pair[0].0
                        && (pair[1].0 == pair[1].1 || pair[0].0 == pair[0].1));
                if overlaps {
                    return Err(format!(
                        "Cannot automatically integrate overlapping or co-located AST scopes in '{}'",
                        path
                    ));
                }
            }
            let mut lines = content
                .split_inclusive('\n')
                .map(str::to_string)
                .collect::<Vec<_>>();
            for (start_line, end_line, replacement, scope_id) in file_patches {
                let start = *start_line;
                let end = *end_line;
                if start > end || end > lines.len() {
                    return Err(format!("Invalid AST line range for '{}'", scope_id));
                }
                let replacement_lines = replacement
                    .split_inclusive('\n')
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                lines.splice(start..end, replacement_lines);
            }
            contents.insert(path.clone(), lines.concat());
        }

        for path in &file_paths {
            if current_tree
                .entries
                .get(path)
                .is_some_and(|entry| !entry.is_dir)
                && !other_tree
                    .entries
                    .get(path)
                    .is_some_and(|entry| !entry.is_dir)
                && !current_scopes
                    .values()
                    .any(|scope| scope.file_path == *path)
            {
                continue;
            }
            let current_has_file = current_tree
                .entries
                .get(path)
                .is_some_and(|entry| !entry.is_dir);
            let other_has_file = other_tree
                .entries
                .get(path)
                .is_some_and(|entry| !entry.is_dir);
            if current_has_file && !other_has_file {
                let file_scopes = current_scopes
                    .values()
                    .filter(|scope| scope.file_path == *path)
                    .collect::<Vec<_>>();
                if !file_scopes.is_empty()
                    && file_scopes.iter().all(|scope| {
                        comparison.changes.iter().any(|change| {
                            change.scope_id == scope.scope_id
                                && (change.status == "other-only"
                                    || resolutions.get(&change.scope_id)
                                        == Some(&ConflictResolution::Other))
                        })
                    })
                {
                    deleted_files.insert(path.clone());
                    contents.remove(path);
                }
            }
        }

        let mut originals = HashMap::<String, Option<Vec<u8>>>::new();
        let mut changed_paths = contents
            .keys()
            .filter(|path| !deleted_files.contains(*path))
            .cloned()
            .collect::<HashSet<_>>();
        changed_paths.extend(deleted_files.iter().cloned());
        let mut destinations = HashMap::<String, PathBuf>::new();
        for path in &changed_paths {
            let destination = safe_workspace_file_path(&self.workspace_root, path, false)?;
            let original = match fs::read(&destination) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(format!(
                        "Cannot stage integration source '{}': {error}",
                        path
                    ))
                }
            };
            if original.is_none() && deleted_files.contains(path) {
                return Err(format!(
                    "Cannot delete missing integration source '{}'",
                    path
                ));
            }
            originals.insert(path.clone(), original);
            destinations.insert(path.clone(), destination);
        }
        let mut written = Vec::<String>::new();
        let mut ordered_paths = changed_paths.into_iter().collect::<Vec<_>>();
        ordered_paths.sort();
        for path in ordered_paths {
            let destination = destinations.get(&path).unwrap();
            written.push(path.clone());
            let result = if deleted_files.contains(&path) {
                fs::remove_file(destination)
                    .map_err(|error| format!("Cannot remove AST-empty file '{}': {error}", path))
            } else {
                safe_workspace_file_path(&self.workspace_root, &path, true).and_then(
                    |destination| {
                        fs::write(destination, &contents[&path]).map_err(|error| {
                            format!("Cannot apply AST patch to '{}': {error}", path)
                        })
                    },
                )
            };
            if let Err(error) = result {
                let rollback = restore_workspace_files(&self.workspace_root, &originals, &written);
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback_error) => {
                        format!("{error}; rollback failed: {rollback_error}")
                    }
                });
            }
        }

        match self.commit_with_parents(
            &format!("Integrate branch {}", other_branch),
            author_callsign,
            Some(vec![
                comparison.current_commit.clone(),
                comparison.other_commit.clone(),
            ]),
        ) {
            Ok(commit) => Ok(commit),
            Err(error) => {
                let rollback = restore_workspace_files(&self.workspace_root, &originals, &written);
                match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(format!(
                        "{error}; integration rollback failed: {rollback_error}"
                    )),
                }
            }
        }
    }

    pub fn branch_head(&self, branch: &str) -> Result<VcsCommit, String> {
        if !is_valid_branch_name(branch) {
            return Err("Invalid branch name".into());
        }
        let path = self.vcs_dir.join("refs").join("heads").join(branch);
        let id = fs::read_to_string(&path)
            .map_err(|error| format!("Cannot read branch '{}': {error}", branch))?;
        self.get_commit(id.trim())
    }

    fn common_ancestor(&self, left: &str, right: &str) -> Result<VcsCommit, String> {
        let left_ancestors = self.ancestor_distances(left)?;
        let right_ancestors = self.ancestor_distances(right)?;
        let mut common = left_ancestors
            .iter()
            .filter_map(|(id, left_distance)| {
                right_ancestors
                    .get(id)
                    .map(|right_distance| (left_distance + right_distance, id))
            })
            .collect::<Vec<_>>();
        common.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
        let (_, id) = common
            .first()
            .ok_or_else(|| "Branches do not share a common ancestor".to_string())?;
        self.get_commit(id)
    }

    fn ancestor_distances(&self, start: &str) -> Result<HashMap<String, usize>, String> {
        let mut distances = HashMap::new();
        let mut pending = vec![(start.to_string(), 0usize)];
        while let Some((id, distance)) = pending.pop() {
            if distances.get(&id).is_some_and(|known| *known <= distance) {
                continue;
            }
            let commit = self.get_commit(&id)?;
            distances.insert(id, distance);
            if distances.len() > 100_000 {
                return Err("Commit ancestry exceeds divergence scan limit".into());
            }
            pending.extend(
                commit
                    .parent_ids
                    .into_iter()
                    .map(|parent| (parent, distance + 1)),
            );
        }
        Ok(distances)
    }

    fn read_tree_file(&self, tree: &VcsTree, path: &str) -> Result<String, String> {
        let entry = tree
            .entries
            .get(path)
            .ok_or_else(|| format!("File '{}' is missing from commit tree", path))?;
        let bytes = self.get_blob(&entry.blake3_hash)?;
        String::from_utf8(bytes)
            .map_err(|_| format!("Cannot AST-integrate non-UTF-8 file '{}'", path))
    }

    fn read_scope_content(
        &self,
        commit: &VcsCommit,
        scope: &AstScopeSnapshot,
    ) -> Result<String, String> {
        let tree = self.get_tree(&commit.tree_hash)?;
        let source = self.read_tree_file(&tree, &scope.file_path)?;
        snapshot_content(&source, scope)
    }

    fn validate_ast_snapshots(&self, commit: &VcsCommit) -> Result<(), String> {
        let tree = self.get_tree(&commit.tree_hash)?;
        let mut expected = Vec::new();
        for (path, entry) in &tree.entries {
            if entry.is_dir {
                continue;
            }
            let content = self.get_blob(&entry.blake3_hash)?;
            if let Ok(source) = std::str::from_utf8(&content) {
                expected.extend(match commit.ast_parser_version {
                    1 => capture_ast_scopes_v1(path, source)?,
                    2 => capture_ast_scopes_v2(path, source)?,
                    3 => capture_ast_scopes(path, source)?,
                    version => {
                        return Err(format!(
                            "Unsupported AST parser snapshot version: {}",
                            version
                        ))
                    }
                });
            }
        }
        expected.sort_by(|left, right| left.scope_id.cmp(&right.scope_id));
        let mut actual = commit.ast_scopes.clone();
        actual.sort_by(|left, right| left.scope_id.cmp(&right.scope_id));
        if expected != actual {
            return Err(format!(
                "AST scope snapshots do not match commit tree {}",
                commit.commit_id
            ));
        }
        Ok(())
    }

    fn current_ast_scopes(&self, commit: &VcsCommit) -> Result<Vec<AstScopeSnapshot>, String> {
        self.validate_ast_snapshots(commit)?;
        let tree = self.get_tree(&commit.tree_hash)?;
        let mut scopes = Vec::new();
        for (path, entry) in &tree.entries {
            if entry.is_dir {
                continue;
            }
            let content = self.get_blob(&entry.blake3_hash)?;
            if let Ok(source) = std::str::from_utf8(&content) {
                scopes.extend(capture_ast_scopes(path, source)?);
            }
        }
        scopes.sort_by(|left, right| left.scope_id.cmp(&right.scope_id));
        Ok(scopes)
    }

    /// Create a new branch pointing to current HEAD.
    pub fn create_branch(&mut self, branch_name: &str) -> Result<(), String> {
        let branch_name = branch_name.trim();
        if !is_valid_branch_name(branch_name) {
            return Err("Invalid branch name".to_string());
        }

        let head = self
            .head_commit()?
            .ok_or_else(|| "Cannot create branch: repository has no commits yet.".to_string())?;

        let ref_path = self.vcs_dir.join("refs").join("heads").join(branch_name);
        if ref_path.exists() {
            return Err(format!("Branch '{}' already exists", branch_name));
        }

        let mut ref_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ref_path)
            .map_err(|error| format!("Failed to create branch ref: {error}"))?;
        use std::io::Write;
        ref_file
            .write_all(head.commit_id.as_bytes())
            .map_err(|error| format!("Failed to write branch ref: {error}"))?;

        Ok(())
    }

    /// Switch active branch or checkout target commit.
    pub fn checkout(&mut self, target: &str) -> Result<(), String> {
        if !self.status()?.is_clean {
            return Err("Cannot switch branches with uncommitted workspace changes".into());
        }
        let target = target.trim();
        let target_branch_ref = is_valid_branch_name(target)
            .then(|| self.vcs_dir.join("refs").join("heads").join(target));

        let (target_commit_id, is_branch) =
            if let Some(target_branch_ref) = target_branch_ref.filter(|path| path.exists()) {
                let commit_id = fs::read_to_string(&target_branch_ref)
                    .map_err(|e| format!("Failed to read branch ref: {}", e))?
                    .trim()
                    .to_string();
                (commit_id, true)
            } else if is_valid_branch_name(target)
                && self
                    .vcs_dir
                    .join("refs")
                    .join("checkpoints")
                    .join(target)
                    .is_file()
            {
                let checkpoint_ref = self.vcs_dir.join("refs").join("checkpoints").join(target);
                let commit_id = fs::read_to_string(checkpoint_ref)
                    .map_err(|error| format!("Failed to read checkpoint ref: {error}"))?
                    .trim()
                    .to_string();
                (commit_id, false)
            } else if is_object_id(target) {
                let commit_file =
                    commit_object_path(&self.vcs_dir.join("objects").join("commits"), target);
                if commit_file.exists() {
                    (target.to_string(), false)
                } else {
                    return Err(format!("Branch or commit '{}' not found", target));
                }
            } else {
                return Err(format!("Branch or commit '{}' not found", target));
            };

        // Load target commit & tree
        let target_commit = self.get_commit(&target_commit_id)?;
        let target_tree = self.get_tree(&target_commit.tree_hash)?;

        // Current tree to know which files to delete
        let current_head = self.workspace_base_commit()?;
        let current_tree = match &current_head {
            Some(c) => self.get_tree(&c.tree_hash)?,
            None => VcsTree::default(),
        };

        // 1. Delete files that are in current_tree but not in target_tree
        for (rel_path, _) in &current_tree.entries {
            if !target_tree.entries.contains_key(rel_path) {
                let full_path = safe_workspace_file_path(&self.workspace_root, rel_path, false)?;
                if full_path.exists() {
                    fs::remove_file(&full_path).map_err(|e| {
                        format!("Failed to remove workspace file {}: {}", rel_path, e)
                    })?;
                }
            }
        }

        // 2. Write all files from target_tree
        for (rel_path, entry) in &target_tree.entries {
            if entry.is_dir {
                continue;
            }
            let blob = self.get_blob(&entry.blake3_hash)?;
            let full_path = safe_workspace_file_path(&self.workspace_root, rel_path, true)?;
            fs::write(&full_path, blob)
                .map_err(|e| format!("Failed to restore file {}: {}", rel_path, e))?;
        }

        // 3. Update HEAD
        if is_branch {
            fs::write(
                &self.workspace_head_path,
                format!("ref: refs/heads/{}\n", target),
            )
            .map_err(|e| format!("Failed to update HEAD: {}", e))?;
        } else {
            fs::write(&self.workspace_head_path, format!("{}\n", target_commit_id))
                .map_err(|e| format!("Failed to update HEAD: {}", e))?;
        }
        self.update_workspace_base(Some(&target_commit_id))?;

        Ok(())
    }

    /// Compute line diff for a specific file between working directory and HEAD.
    pub fn diff_file(&self, rel_path: &str) -> Result<FileDiff, String> {
        let head = self.workspace_base_commit()?;
        let head_tree = match &head {
            Some(c) => self.get_tree(&c.tree_hash)?,
            None => VcsTree::default(),
        };

        let old_entry = head_tree.entries.get(rel_path);
        let current_path = safe_workspace_file_path(&self.workspace_root, rel_path, false)?;
        let exists_now = current_path.exists();

        if old_entry.is_none() && !exists_now {
            return Err(format!(
                "File '{}' does not exist in HEAD or workspace",
                rel_path
            ));
        }

        let old_text = if let Some(old) = old_entry {
            let bytes = self.get_blob(&old.blake3_hash)?;
            String::from_utf8_lossy(&bytes).to_string()
        } else {
            String::new()
        };

        let new_text = if exists_now {
            fs::read_to_string(&current_path).unwrap_or_default()
        } else {
            String::new()
        };

        let old_hash = old_entry.map(|e| e.blake3_hash.clone());
        let new_hash = if exists_now {
            Some(blake3::hash(new_text.as_bytes()).to_hex().to_string())
        } else {
            None
        };

        let status = if old_entry.is_none() {
            "added".to_string()
        } else if !exists_now {
            "deleted".to_string()
        } else if old_hash == new_hash {
            "identical".to_string()
        } else {
            "modified".to_string()
        };

        let lines = compute_unified_diff(&old_text, &new_text);

        Ok(FileDiff {
            rel_path: rel_path.to_string(),
            status,
            old_hash,
            new_hash,
            lines,
        })
    }

    /// Export a Merkle bundle containing commits, trees, and blobs for `branch`.
    pub fn export_bundle(
        &self,
        branch: &str,
        since_commit: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        if !is_valid_branch_name(branch) {
            return Err("Invalid branch name".to_string());
        }
        let branch_ref_path = self.vcs_dir.join("refs").join("heads").join(branch);
        if !branch_ref_path.exists() {
            return Err(format!("Branch '{}' does not exist", branch));
        }
        let head_commit_id = fs::read_to_string(&branch_ref_path)
            .map_err(|e| format!("Failed to read branch ref: {}", e))?
            .trim()
            .to_string();

        let mut commits_to_pack = Vec::new();
        let mut pending = vec![head_commit_id.clone()];
        let since_id = since_commit.map(str::to_string);
        let mut visited = HashSet::new();
        while let Some(id) = pending.pop() {
            if Some(&id) == since_id.as_ref() || !visited.insert(id.clone()) {
                continue;
            }
            let commit = self.get_commit(&id)?;
            pending.extend(commit.parent_ids.iter().rev().cloned());
            commits_to_pack.push(commit);
        }

        // Collect trees and blobs
        let mut trees_to_pack = HashMap::new();
        let mut blobs_to_pack = HashSet::new();

        for commit in &commits_to_pack {
            let tree = self.get_tree(&commit.tree_hash)?;
            for entry in tree.entries.values() {
                if !entry.is_dir {
                    blobs_to_pack.insert(entry.blake3_hash.clone());
                }
            }
            trees_to_pack.insert(tree.tree_hash.clone(), tree);
        }

        let manifest = VcsBundleManifest {
            branch: branch.to_string(),
            head_commit_id: head_commit_id.clone(),
            commits_count: commits_to_pack.len(),
            blobs_count: blobs_to_pack.len(),
            exported_at: Utc::now().to_rfc3339(),
        };

        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut enc);

            // 1. Manifest
            let m_json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
            let mut header = tar::Header::new_gnu();
            header.set_size(m_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "manifest.json", &m_json[..])
                .map_err(|e| format!("Tar append manifest failed: {}", e))?;

            // 2. Commits
            for commit in &commits_to_pack {
                let c_json = serde_json::to_vec_pretty(commit).map_err(|e| e.to_string())?;
                let mut header = tar::Header::new_gnu();
                header.set_size(c_json.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(
                    &mut header,
                    format!("commits/{}.json", commit.commit_id),
                    &c_json[..],
                )
                .map_err(|e| format!("Tar append commit failed: {}", e))?;
            }

            // 3. Trees
            let mut sorted_trees: Vec<_> = trees_to_pack.values().collect();
            sorted_trees.sort_unstable_by(|left, right| left.tree_hash.cmp(&right.tree_hash));
            for tree in sorted_trees {
                let t_json = serde_json::to_vec_pretty(tree).map_err(|e| e.to_string())?;
                let mut header = tar::Header::new_gnu();
                header.set_size(t_json.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(
                    &mut header,
                    format!("trees/{}.json", tree.tree_hash),
                    &t_json[..],
                )
                .map_err(|e| format!("Tar append tree failed: {}", e))?;
            }

            // 4. Blobs
            let mut sorted_blobs: Vec<_> = blobs_to_pack.iter().collect();
            sorted_blobs.sort_unstable();
            for blob_hash in sorted_blobs {
                let blob_bytes = self.get_blob(blob_hash)?;
                let mut header = tar::Header::new_gnu();
                header.set_size(blob_bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, format!("blobs/{}", blob_hash), &blob_bytes[..])
                    .map_err(|e| format!("Tar append blob failed: {}", e))?;
            }

            tar.finish()
                .map_err(|e| format!("Tar finish failed: {}", e))?;
        }

        enc.finish()
            .map_err(|e| format!("Gzip finish failed: {}", e))
    }

    /// Import a Merkle bundle into local VCS objects and update target branch.
    // CVE-Threat: A crafted archive could overwrite repository refs or restore files through path traversal.
    // Analysis: Bundle entries and object references are untrusted network input.
    // Hardening: Bound decompressed sizes, stage and verify content IDs/paths, and move refs only after validation.
    pub fn import_bundle(
        &mut self,
        bundle_bytes: &[u8],
        target_branch: &str,
    ) -> Result<VcsSyncReport, String> {
        use flate2::read::GzDecoder;
        use std::io::{Cursor, Read};

        const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
        const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;

        if !is_valid_branch_name(target_branch) {
            return Err("Invalid target branch name".to_string());
        }

        let dec = GzDecoder::new(Cursor::new(bundle_bytes));
        let mut archive = tar::Archive::new(dec);

        let mut manifest: Option<VcsBundleManifest> = None;
        let mut commits = HashMap::<String, VcsCommit>::new();
        let mut trees = HashMap::<String, VcsTree>::new();
        let mut blobs = HashMap::<String, Vec<u8>>::new();
        let mut auxiliary_seen = HashSet::new();
        let mut total_bytes = 0u64;

        let entries = archive
            .entries()
            .map_err(|e| format!("Archive read error: {}", e))?;
        for entry in entries {
            let mut entry = entry.map_err(|e| format!("Entry error: {}", e))?;
            if !entry.header().entry_type().is_file() {
                return Err("Bundle contains a non-file entry".to_string());
            }
            let path = entry
                .path()
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let size = entry.size();
            total_bytes = total_bytes
                .checked_add(size)
                .ok_or_else(|| "Bundle size overflow".to_string())?;
            if size > MAX_OBJECT_BYTES || total_bytes > MAX_BUNDLE_BYTES {
                return Err("Bundle exceeds the permitted uncompressed size".to_string());
            }
            let mut content = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut content).map_err(|e| e.to_string())?;
            if content.len() as u64 != size {
                return Err(format!("Truncated bundle object: {}", path));
            }

            if path == "manifest.json" {
                if manifest.is_some() {
                    return Err("Bundle contains duplicate manifest.json".to_string());
                }
                manifest = Some(
                    serde_json::from_slice(&content)
                        .map_err(|e| format!("Invalid bundle manifest: {}", e))?,
                );
            } else if let Some(id) = path
                .strip_prefix("commits/")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if !is_object_id(id) {
                    return Err(format!("Invalid commit object path: {}", path));
                }
                let commit: VcsCommit = serde_json::from_slice(&content)
                    .map_err(|e| format!("Invalid commit object {}: {}", id, e))?;
                if commit.commit_id != id
                    || compute_commit_id(&commit)? != id
                    || commits.insert(id.to_string(), commit).is_some()
                {
                    return Err(format!("Commit object ID mismatch or duplicate: {}", id));
                }
            } else if let Some(id) = path
                .strip_prefix("trees/")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if !is_object_id(id) {
                    return Err(format!("Invalid tree object path: {}", path));
                }
                let tree: VcsTree = serde_json::from_slice(&content)
                    .map_err(|e| format!("Invalid tree object {}: {}", id, e))?;
                if tree.tree_hash != id
                    || compute_tree_id(&tree)? != id
                    || trees.insert(id.to_string(), tree).is_some()
                {
                    return Err(format!("Tree object ID mismatch or duplicate: {}", id));
                }
            } else if let Some(id) = path.strip_prefix("blobs/") {
                if !is_object_id(id)
                    || blake3::hash(&content).to_hex().as_str() != id
                    || blobs.insert(id.to_string(), content).is_some()
                {
                    return Err(format!("Blob object ID mismatch or duplicate: {}", id));
                }
            } else if let Some(name) = path
                .strip_prefix("chunk_manifests/")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if !is_object_id(name) || !auxiliary_seen.insert(path.clone()) {
                    return Err(format!(
                        "Invalid or duplicate chunk manifest path: {}",
                        path
                    ));
                }
                serde_json::from_slice::<ChunkManifest>(&content)
                    .map_err(|error| format!("Invalid chunk manifest {name}: {error}"))?;
            } else if let Some(id) = path.strip_prefix("chunks/") {
                if !is_object_id(id)
                    || blake3::hash(&content).to_hex().as_str() != id
                    || !auxiliary_seen.insert(path.clone())
                {
                    return Err(format!("Invalid or duplicate chunk path: {}", path));
                }
            } else {
                return Err(format!("Unsupported bundle entry: {}", path));
            }
        }

        let m = manifest.ok_or_else(|| "Invalid bundle: manifest.json missing".to_string())?;
        if !is_object_id(&m.head_commit_id)
            || m.commits_count != commits.len()
            || m.blobs_count != blobs.len()
        {
            return Err("Bundle manifest counts or head ID do not match its contents".to_string());
        }

        let mut required_commits: Vec<&VcsCommit> = commits.values().collect();
        required_commits.sort_unstable_by(|left, right| left.commit_id.cmp(&right.commit_id));
        for commit in &required_commits {
            if !trees.contains_key(&commit.tree_hash) {
                self.get_tree(&commit.tree_hash).map_err(|_| {
                    format!(
                        "Missing tree object referenced by commit {}",
                        commit.commit_id
                    )
                })?;
            }
            for parent in &commit.parent_ids {
                if !commits.contains_key(parent) {
                    self.get_commit(parent).map_err(|_| {
                        format!(
                            "Missing parent commit {} referenced by {}",
                            parent, commit.commit_id
                        )
                    })?;
                }
            }
        }
        let head_commit = commits
            .get(&m.head_commit_id)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| self.get_commit(&m.head_commit_id))?;
        let head_tree = trees
            .get(&head_commit.tree_hash)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| self.get_tree(&head_commit.tree_hash))?;
        for tree in trees.values() {
            for entry in tree.entries.values().filter(|entry| !entry.is_dir) {
                if let Some(blob) = blobs.get(&entry.blake3_hash) {
                    if blob.len() as u64 != entry.size_bytes {
                        return Err(format!(
                            "Blob size mismatch for tree path {}",
                            entry.rel_path
                        ));
                    }
                } else {
                    let blob = self.get_blob(&entry.blake3_hash).map_err(|_| {
                        format!("Missing blob referenced by tree path {}", entry.rel_path)
                    })?;
                    if blob.len() as u64 != entry.size_bytes {
                        return Err(format!(
                            "Blob size mismatch for tree path {}",
                            entry.rel_path
                        ));
                    }
                }
            }
        }
        for entry in head_tree.entries.values().filter(|entry| !entry.is_dir) {
            if !blobs.contains_key(&entry.blake3_hash) {
                self.get_blob(&entry.blake3_hash).map_err(|_| {
                    format!("Missing blob referenced by HEAD path {}", entry.rel_path)
                })?;
            }
        }

        let branch_path = self.vcs_dir.join("refs").join("heads").join(target_branch);
        let branch_head = if branch_path.exists() {
            Some(
                fs::read_to_string(&branch_path)
                    .map_err(|e| format!("Failed to read target branch: {}", e))?
                    .trim()
                    .to_string(),
            )
        } else {
            None
        };
        if let Some(existing_head) = &branch_head {
            if existing_head != &m.head_commit_id {
                let mut pending = vec![m.head_commit_id.clone()];
                let mut visited = HashSet::new();
                let mut contains_existing = false;
                while let Some(id) = pending.pop() {
                    if id == *existing_head {
                        contains_existing = true;
                        break;
                    }
                    if !visited.insert(id.clone()) {
                        continue;
                    }
                    let commit = if let Some(commit) = commits.get(&id) {
                        commit.clone()
                    } else {
                        self.get_commit(&id)?
                    };
                    pending.extend(commit.parent_ids);
                }
                if !contains_existing {
                    return Err("Refusing non-fast-forward bundle import".to_string());
                }
            }
        }

        let current_branch = self.current_branch()?;
        if current_branch == target_branch && !self.status()?.is_clean {
            return Err(
                "Cannot import into the checked-out branch with uncommitted changes".to_string(),
            );
        }
        if current_branch == target_branch && !self.workspace_base_matches_head()? {
            return Err(format!(
                "Workspace is behind branch '{target_branch}'; check out the branch to refresh before pulling"
            ));
        }

        let old_head = self.head_commit()?.map(|c| c.commit_id);

        let commits_dir = self.vcs_dir.join("objects").join("commits");
        let trees_dir = self.vcs_dir.join("objects").join("trees");
        let blobs_dir = self.vcs_dir.join("objects").join("blobs");
        fs::create_dir_all(&commits_dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(&trees_dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(&blobs_dir).map_err(|e| e.to_string())?;
        for (id, commit) in &commits {
            let path = commit_object_path(&commits_dir, id);
            if path.exists() {
                let existing_commit = read_commit_object(&path, id)?;
                if compute_commit_id(&existing_commit).map_err(|e| e.to_string())? != *id {
                    return Err(format!("Conflicting local commit object: {}", id));
                }
            } else {
                write_commit_object(&commits_dir, commit)?;
            }
        }
        for (id, tree) in &trees {
            let path = trees_dir.join(format!("{}.json", id));
            if path.exists() {
                let existing_bytes = fs::read(&path).map_err(|e| e.to_string())?;
                let existing_tree: VcsTree = serde_json::from_slice(&existing_bytes)
                    .map_err(|_| format!("Corrupt local tree object: {}", id))?;
                if compute_tree_id(&existing_tree).map_err(|e| e.to_string())? != *id {
                    return Err(format!("Conflicting local tree object: {}", id));
                }
            } else {
                let bytes = serde_json::to_vec_pretty(tree).map_err(|e| e.to_string())?;
                fs::write(path, bytes).map_err(|e| e.to_string())?;
            }
        }
        for (id, blob) in &blobs {
            let path = blobs_dir.join(id);
            if path.exists() && fs::read(&path).map_err(|e| e.to_string())? != *blob {
                return Err(format!("Conflicting local blob object: {}", id));
            }
            if !path.exists() {
                fs::write(path, blob).map_err(|e| e.to_string())?;
            }
        }
        *self
            .chunk_index
            .lock()
            .map_err(|_| "Chunk index lock is poisoned".to_string())? = None;
        with_branch_ref_lock(&self.vcs_dir, target_branch, || {
            let current_branch_head = if branch_path.exists() {
                Some(
                    fs::read_to_string(&branch_path)
                        .map_err(|error| format!("Failed to recheck target branch: {error}"))?
                        .trim()
                        .to_string(),
                )
            } else {
                None
            };
            if current_branch_head != branch_head {
                return Err(format!(
                    "Target branch '{target_branch}' advanced during bundle import; retry after fetching its new head"
                ));
            }
            atomicwrites::AtomicFile::new(&branch_path, atomicwrites::AllowOverwrite)
                .write(|file| {
                    use std::io::Write;
                    file.write_all(m.head_commit_id.as_bytes())
                })
                .map_err(|error| format!("Failed to update target branch: {error}"))?;
            Ok(())
        })?;

        // If current branch is target_branch, fast-forward working directory
        if current_branch == target_branch && old_head.as_deref() != Some(&m.head_commit_id) {
            let old_tree = match &old_head {
                Some(id) => match self.get_commit(id) {
                    Ok(c) => self.get_tree(&c.tree_hash).unwrap_or_default(),
                    Err(_) => VcsTree::default(),
                },
                None => VcsTree::default(),
            };

            for (rel_path, _) in &old_tree.entries {
                if !head_tree.entries.contains_key(rel_path) {
                    let full_path =
                        safe_workspace_file_path(&self.workspace_root, rel_path, false)?;
                    if full_path.exists() {
                        fs::remove_file(&full_path).map_err(|e| {
                            format!("Failed to remove workspace file {}: {}", rel_path, e)
                        })?;
                    }
                }
            }

            for (rel_path, entry) in &head_tree.entries {
                if entry.is_dir {
                    continue;
                }
                let blob = if let Some(b) = blobs.get(&entry.blake3_hash) {
                    b.clone()
                } else {
                    self.get_blob(&entry.blake3_hash)?
                };
                let full_path = safe_workspace_file_path(&self.workspace_root, rel_path, true)?;
                fs::write(&full_path, blob)
                    .map_err(|e| format!("Failed to restore file {}: {}", rel_path, e))?;
            }

            fs::write(
                &self.workspace_head_path,
                format!("ref: refs/heads/{}\n", target_branch),
            )
            .map_err(|e| format!("Failed to update HEAD: {}", e))?;
            self.update_workspace_base(Some(&m.head_commit_id))?;
        }

        Ok(VcsSyncReport {
            branch: target_branch.to_string(),
            anchor: "swarm".to_string(),
            commits_synced: commits.len(),
            blobs_synced: blobs.len(),
            old_head,
            new_head: m.head_commit_id,
            message: format!(
                "Synchronisiert: {} Commits, {} Blobs",
                commits.len(),
                blobs.len()
            ),
        })
    }

    pub fn project_name(&self) -> String {
        let name_file = self.vcs_dir.join("project_name");
        if let Ok(name) = fs::read_to_string(&name_file) {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        self.workspace_root
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("project")
            .to_string()
    }

    pub fn set_project_name(&self, name: &str) -> Result<(), String> {
        let name_file = self.vcs_dir.join("project_name");
        fs::write(&name_file, name.trim()).map_err(|e| format!("Failed to set project name: {}", e))
    }

    fn get_anchor_vcs_store(&self, anchor_name: &str) -> PathBuf {
        let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let proj = self.project_name();
        base.join(".sb")
            .join("vcs-store")
            .join(anchor_name)
            .join(proj)
    }

    /// Push local branch commits to the given anchor in the P2P Swarm.
    pub fn push_to_anchor(&self, anchor_name: &str, branch: &str) -> Result<VcsSyncReport, String> {
        let store = self.get_anchor_vcs_store(anchor_name);
        fs::create_dir_all(&store).map_err(|e| format!("Failed to create anchor store: {}", e))?;

        let remote_head_file = store.join(format!("{}.head", branch));
        let remote_head = fs::read_to_string(&remote_head_file)
            .ok()
            .map(|s| s.trim().to_string());

        let bundle = self.export_bundle(branch, remote_head.as_deref())?;

        // Write bundle to anchor store
        let bundle_file = store.join(format!("{}.bundle.tar.gz", branch));
        fs::write(&bundle_file, &bundle)
            .map_err(|e| format!("Failed to write anchor bundle: {}", e))?;

        // Update remote HEAD on anchor
        let head = self
            .head_commit()?
            .ok_or_else(|| "No commits to push".to_string())?;
        fs::write(&remote_head_file, &head.commit_id)
            .map_err(|e| format!("Failed to update anchor branch ref: {}", e))?;

        // Cache remote ref locally under refs/remotes/<anchor>/<branch>
        let remotes_dir = self.vcs_dir.join("refs").join("remotes").join(anchor_name);
        let _ = fs::create_dir_all(&remotes_dir);
        let _ = fs::write(remotes_dir.join(branch), &head.commit_id);

        Ok(VcsSyncReport {
            branch: branch.to_string(),
            anchor: anchor_name.to_string(),
            commits_synced: 1,
            blobs_synced: 0,
            old_head: remote_head,
            new_head: head.commit_id,
            message: format!(
                "Branch '{}' erfolgreich zu Swarm-Anchor '{}' übertragen",
                branch, anchor_name
            ),
        })
    }

    /// Pull branch commits from the given anchor in the P2P Swarm.
    pub fn pull_from_anchor(
        &mut self,
        anchor_name: &str,
        branch: &str,
    ) -> Result<VcsSyncReport, String> {
        let store = self.get_anchor_vcs_store(anchor_name);
        let bundle_file = store.join(format!("{}.bundle.tar.gz", branch));

        if !bundle_file.exists() {
            return Err(format!(
                "Anchor '{}' has no published commits for branch '{}'",
                anchor_name, branch
            ));
        }

        let bundle_bytes = fs::read(&bundle_file)
            .map_err(|e| format!("Failed to read bundle from anchor: {}", e))?;

        let mut report = self.import_bundle(&bundle_bytes, branch)?;
        report.anchor = anchor_name.to_string();

        // Update local remote ref
        let remotes_dir = self.vcs_dir.join("refs").join("remotes").join(anchor_name);
        let _ = fs::create_dir_all(&remotes_dir);
        let _ = fs::write(remotes_dir.join(branch), &report.new_head);

        Ok(report)
    }

    /// Get remote sync status (ahead / behind) compared to the anchor.
    pub fn get_remote_status(
        &self,
        anchor_name: &str,
        branch: &str,
    ) -> Result<VcsRemoteStatus, String> {
        let store = self.get_anchor_vcs_store(anchor_name);
        let remote_head_file = store.join(format!("{}.head", branch));
        let remote_head = fs::read_to_string(&remote_head_file)
            .ok()
            .map(|s| s.trim().to_string());

        let branch_ref_path = self.vcs_dir.join("refs").join("heads").join(branch);
        let local_head = fs::read_to_string(&branch_ref_path)
            .ok()
            .map(|s| s.trim().to_string());

        let in_sync = local_head == remote_head && local_head.is_some();

        let mut ahead = 0;
        let mut behind = 0;

        if !in_sync {
            if let Some(ref _l_id) = local_head {
                let local_history = self.log(Some(50)).unwrap_or_default();
                if let Some(ref r_id) = remote_head {
                    if let Some(pos) = local_history.iter().position(|c| &c.commit_id == r_id) {
                        ahead = pos;
                    } else {
                        ahead = local_history.len();
                    }
                } else {
                    ahead = local_history.len();
                }
            }

            if remote_head.is_some() && local_head.is_none() {
                behind = 1;
            }
        }

        Ok(VcsRemoteStatus {
            anchor: anchor_name.to_string(),
            branch: branch.to_string(),
            local_head,
            remote_head,
            ahead,
            behind,
            in_sync,
        })
    }
}

/// Compute line-by-line diff between two strings.
pub fn compute_unified_diff(old_text: &str, new_text: &str) -> Vec<LineDiff> {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    // Fast path: both empty
    if old_lines.is_empty() && new_lines.is_empty() {
        return Vec::new();
    }

    // Fast path: file created (added)
    if old_lines.is_empty() {
        return new_lines
            .into_iter()
            .enumerate()
            .map(|(idx, line)| LineDiff {
                change_type: "+".to_string(),
                old_line_num: None,
                new_line_num: Some(idx + 1),
                text: line.to_string(),
            })
            .collect();
    }

    // Fast path: file deleted
    if new_lines.is_empty() {
        return old_lines
            .into_iter()
            .enumerate()
            .map(|(idx, line)| LineDiff {
                change_type: "-".to_string(),
                old_line_num: Some(idx + 1),
                new_line_num: None,
                text: line.to_string(),
            })
            .collect();
    }

    // Compute LCS matrix for accurate diffing
    let m = old_lines.len();
    let n = new_lines.len();
    let mut dp = vec![vec![0u32; n + 1]; m + 1];

    for i in 0..m {
        for j in 0..n {
            if old_lines[i] == new_lines[j] {
                dp[i + 1][j + 1] = dp[i][j] + 1;
            } else {
                dp[i + 1][j + 1] = dp[i + 1][j].max(dp[i][j + 1]);
            }
        }
    }

    // Backtrack to build diff
    let mut diff = Vec::new();
    let mut i = m;
    let mut j = n;

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old_lines[i - 1] == new_lines[j - 1] {
            diff.push(LineDiff {
                change_type: " ".to_string(),
                old_line_num: Some(i),
                new_line_num: Some(j),
                text: old_lines[i - 1].to_string(),
            });
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            diff.push(LineDiff {
                change_type: "+".to_string(),
                old_line_num: None,
                new_line_num: Some(j),
                text: new_lines[j - 1].to_string(),
            });
            j -= 1;
        } else if i > 0 && (j == 0 || dp[i][j - 1] < dp[i - 1][j]) {
            diff.push(LineDiff {
                change_type: "-".to_string(),
                old_line_num: Some(i),
                new_line_num: None,
                text: old_lines[i - 1].to_string(),
            });
            i -= 1;
        }
    }

    diff.reverse();
    diff
}

fn snapshot_content(content: &str, scope: &AstScopeSnapshot) -> Result<String, String> {
    let lines = content.split_inclusive('\n').collect::<Vec<_>>();
    let start = scope
        .start_line
        .checked_sub(1)
        .ok_or_else(|| format!("Invalid AST start line for '{}'", scope.scope_id))?;
    if scope.end_line > lines.len() || start >= scope.end_line {
        return Err(format!("Invalid AST line range for '{}'", scope.scope_id));
    }
    let source = lines[start..scope.end_line].concat();
    let actual_hash = blake3::hash(source.as_bytes()).to_hex().to_string();
    if actual_hash != scope.content_hash {
        return Err(format!(
            "AST scope snapshot does not match tree content for '{}'",
            scope.scope_id
        ));
    }
    Ok(source)
}

fn scope_map(scopes: &[AstScopeSnapshot]) -> Result<HashMap<String, &AstScopeSnapshot>, String> {
    let mut mapped = HashMap::new();
    for scope in scopes {
        if mapped.insert(scope.scope_id.clone(), scope).is_some() {
            return Err(format!("Duplicate AST scope identity '{}'", scope.scope_id));
        }
    }
    Ok(mapped)
}

fn same_scope_content(left: Option<&AstScopeSnapshot>, right: Option<&AstScopeSnapshot>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.content_hash == right.content_hash,
        (None, None) => true,
        _ => false,
    }
}

fn extract_outside_scopes(
    content: &str,
    scopes: &[AstScopeSnapshot],
    file_path: &str,
) -> Result<String, String> {
    let mut file_scopes = scopes
        .iter()
        .filter(|scope| scope.file_path == file_path)
        .collect::<Vec<_>>();
    file_scopes.sort_by_key(|scope| (scope.start_line, scope.end_line));
    if file_scopes
        .windows(2)
        .any(|pair| pair[0].end_line >= pair[1].start_line)
    {
        return Err(format!(
            "Overlapping or ambiguous AST scope ranges in '{}'",
            file_path
        ));
    }

    let mut lines = content
        .split_inclusive('\n')
        .map(str::to_string)
        .collect::<Vec<_>>();
    for scope in file_scopes.into_iter().rev() {
        let start = scope
            .start_line
            .checked_sub(1)
            .ok_or_else(|| format!("Invalid AST start line for '{}'", scope.scope_id))?;
        let end = scope.end_line;
        if end > lines.len() || start >= end {
            return Err(format!("Invalid AST line range for '{}'", scope.scope_id));
        }
        lines.drain(start..end);
    }
    Ok(lines
        .into_iter()
        .filter(|line| !line.trim().is_empty())
        .collect::<String>())
}

fn find_scope_insertion_line(
    scope_id: &str,
    added_scope: &AstScopeSnapshot,
    branch_scopes: &[AstScopeSnapshot],
    current_scopes: &HashMap<String, &AstScopeSnapshot>,
) -> Option<usize> {
    let preceding = branch_scopes
        .iter()
        .filter(|scope| {
            scope.file_path == added_scope.file_path
                && scope.scope_id != scope_id
                && scope.end_line <= added_scope.start_line
                && current_scopes.contains_key(&scope.scope_id)
        })
        .max_by_key(|scope| scope.end_line);
    if let Some(anchor) = preceding {
        return current_scopes
            .get(&anchor.scope_id)
            .map(|scope| scope.end_line);
    }

    branch_scopes
        .iter()
        .filter(|scope| {
            scope.file_path == added_scope.file_path
                && scope.scope_id != scope_id
                && scope.start_line >= added_scope.end_line
                && current_scopes.contains_key(&scope.scope_id)
        })
        .min_by_key(|scope| scope.start_line)
        .and_then(|anchor| {
            current_scopes
                .get(&anchor.scope_id)
                .and_then(|scope| scope.start_line.checked_sub(1))
        })
}

fn restore_workspace_files(
    workspace_root: &Path,
    originals: &HashMap<String, Option<Vec<u8>>>,
    paths: &[String],
) -> Result<(), String> {
    let mut failures = Vec::new();
    for path in paths.iter().rev() {
        let Some(original) = originals.get(path) else {
            continue;
        };
        let result = match original {
            Some(original) => {
                safe_workspace_file_path(workspace_root, path, true).and_then(|destination| {
                    fs::write(destination, original)
                        .map_err(|error| format!("Cannot restore '{}': {error}", path))
                })
            }
            None => safe_workspace_file_path(workspace_root, path, false).and_then(|destination| {
                match fs::remove_file(destination) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(format!("Cannot remove added file '{}': {error}", path)),
                }
            }),
        };
        match result {
            Ok(()) => {}
            Err(error) => failures.push(error),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_unified_diff_basic() {
        let old = "line 1\nline 2\nline 3";
        let new = "line 1\nline 2 modified\nline 3\nline 4";
        let diff = compute_unified_diff(old, new);

        assert!(diff
            .iter()
            .any(|d| d.change_type == " " && d.text == "line 1"));
        assert!(diff
            .iter()
            .any(|d| d.change_type == "-" && d.text == "line 2"));
        assert!(diff
            .iter()
            .any(|d| d.change_type == "+" && d.text == "line 2 modified"));
        assert!(diff
            .iter()
            .any(|d| d.change_type == "+" && d.text == "line 4"));
    }

    #[test]
    fn tree_id_commits_to_paths_and_is_order_independent() {
        let blob_id = blake3::hash(b"same content").to_hex().to_string();
        let entry = |path: &str| FileEntry {
            rel_path: path.to_string(),
            blake3_hash: blob_id.clone(),
            size_bytes: 12,
            is_dir: false,
        };
        let first = VcsTree {
            format_version: 2,
            tree_hash: String::new(),
            entries: HashMap::from([
                ("a.txt".to_string(), entry("a.txt")),
                ("b.txt".to_string(), entry("b.txt")),
            ]),
        };
        let reordered = VcsTree {
            format_version: 2,
            tree_hash: String::new(),
            entries: HashMap::from([
                ("b.txt".to_string(), entry("b.txt")),
                ("a.txt".to_string(), entry("a.txt")),
            ]),
        };
        let renamed = VcsTree {
            format_version: 2,
            tree_hash: String::new(),
            entries: HashMap::from([
                ("a.txt".to_string(), entry("a.txt")),
                ("c.txt".to_string(), entry("c.txt")),
            ]),
        };

        assert_eq!(
            compute_tree_id(&first).unwrap(),
            compute_tree_id(&reordered).unwrap()
        );
        assert_ne!(
            compute_tree_id(&first).unwrap(),
            compute_tree_id(&renamed).unwrap()
        );
    }

    #[test]
    fn bundle_import_rejects_traversal_before_writing_refs() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let tmp = std::env::temp_dir().join(format!("sb_vcs_bad_bundle_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        let bundle_manifest = VcsBundleManifest {
            branch: "main".to_string(),
            head_commit_id: "a".repeat(64),
            commits_count: 0,
            blobs_count: 0,
            exported_at: Utc::now().to_rfc3339(),
        };
        let manifest_bytes = serde_json::to_vec(&bundle_manifest).unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut archive = tar::Builder::new(&mut encoder);
            for (path, bytes) in [
                ("manifest.json", manifest_bytes.as_slice()),
                ("commits/not-a-hash.json", b"{}" as &[u8]),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                archive.append_data(&mut header, path, bytes).unwrap();
            }
            archive.finish().unwrap();
        }
        let bundle = encoder.finish().unwrap();

        assert!(engine.import_bundle(&bundle, "main").is_err());
        assert_eq!(
            fs::read_to_string(tmp.join(".sb").join("HEAD")).unwrap(),
            "ref: refs/heads/main\n"
        );
        assert!(!tmp
            .join(".sb")
            .join("vcs")
            .join("refs")
            .join("heads")
            .join("main")
            .exists());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn object_reads_reject_corrupted_blob_data() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_corrupt_blob_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let engine = VcsEngine::init(&tmp).unwrap();
        let blob_id = engine.put_blob(b"trusted").unwrap();
        let blob_path = tmp
            .join(".sb")
            .join("vcs")
            .join("objects")
            .join("blobs")
            .join(&blob_id);
        fs::write(&blob_path, b"tampered").unwrap();

        assert!(engine.get_blob(&blob_id).is_err());
        assert!(engine.diff_file("../outside.txt").is_err());
        assert!(!is_valid_branch_name(".."));
        assert!(!is_valid_branch_name("CON"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn fastcdc_objects_are_derived_on_demand_instead_of_written_with_blobs() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_lazy_fastcdc_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let engine = VcsEngine::init(&tmp).unwrap();
        let content = (0..96_000)
            .map(|index| ((index * 31 + index / 7) % 251) as u8)
            .collect::<Vec<_>>();
        let blob_id = engine.put_blob(&content).unwrap();
        let objects_dir = tmp.join(".sb").join("vcs").join("objects");
        let chunks_dir = objects_dir.join("chunks");
        let manifests_dir = objects_dir.join("chunk_manifests");

        assert!(fs::read_dir(&chunks_dir).unwrap().next().is_none());
        assert!(fs::read_dir(&manifests_dir).unwrap().next().is_none());

        let manifest = engine.get_chunk_manifest(&blob_id).unwrap();
        assert_eq!(
            manifest,
            FastCdc::with_default().generate_manifest(&content)
        );
        assert!(fs::read_dir(&chunks_dir).unwrap().next().is_none());
        assert!(fs::read_dir(&manifests_dir).unwrap().next().is_none());
        let stats = engine.storage_stats().unwrap();
        assert_eq!(stats.chunks.count, 0);
        assert_eq!(stats.chunk_manifests.count, 0);
        assert_eq!(stats.deduplication_ratio, None);

        let chunk = &manifest.chunks[0];
        let start = chunk.offset as usize;
        let expected = &content[start..start + chunk.length];
        assert_eq!(engine.get_chunk(&chunk.blake3_hash).unwrap(), expected);
        assert!(engine.get_chunk("../outside").is_err());

        let later_content = (0..48_000)
            .map(|index| ((index * 17 + index / 11 + 83) % 251) as u8)
            .collect::<Vec<_>>();
        engine.put_blob(&later_content).unwrap();
        let later_manifest = FastCdc::with_default().generate_manifest(&later_content);
        let later_chunk = &later_manifest.chunks[0];
        let start = later_chunk.offset as usize;
        assert_eq!(
            engine.get_chunk(&later_chunk.blake3_hash).unwrap(),
            &later_content[start..start + later_chunk.length]
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn compressed_commit_objects_roundtrip_and_legacy_json_remains_readable() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_compressed_commit_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(
            tmp.join("src.rs"),
            (0..300)
                .map(|index| format!("fn repeated_scope_{index}() {{ let value = {index}; }}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        let commit = engine.commit("compressed", "tester").unwrap();
        let commits_dir = tmp.join(".sb").join("vcs").join("objects").join("commits");
        let compressed_path = commits_dir.join(format!("{}.json.gz", commit.commit_id));
        let legacy_path = commits_dir.join(format!("{}.json", commit.commit_id));
        assert!(compressed_path.is_file());
        let pretty = serde_json::to_vec_pretty(&commit).unwrap();
        assert!(fs::metadata(&compressed_path).unwrap().len() < (pretty.len() as u64 / 2));
        assert_eq!(
            engine.get_commit(&commit.commit_id).unwrap().commit_id,
            commit.commit_id
        );

        fs::write(&legacy_path, pretty).unwrap();
        fs::remove_file(&compressed_path).unwrap();
        assert_eq!(
            engine.get_commit(&commit.commit_id).unwrap().commit_id,
            commit.commit_id
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn test_vcs_lifecycle_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("sb_vcs_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();

        // 1. Init
        let mut engine = VcsEngine::init(&tmp).unwrap();
        assert_eq!(engine.current_branch().unwrap(), "main");

        // 2. Status on empty repo
        let status = engine.status().unwrap();
        assert!(status.is_clean);

        // 3. Create a file and check status
        fs::write(tmp.join("hello.txt"), "Hello Sovereign World\n").unwrap();
        let status = engine.status().unwrap();
        assert!(!status.is_clean);
        assert_eq!(status.added_count, 1);

        // 4. Commit
        let commit1 = engine.commit("Initial commit", "sentinel-1").unwrap();
        assert_eq!(commit1.message, "Initial commit");
        assert!(commit1.parent_ids.is_empty());

        let status_after_commit = engine.status().unwrap();
        assert!(status_after_commit.is_clean);

        // 5. Modify file
        fs::write(tmp.join("hello.txt"), "Hello Sovereign World!\nVersion 2\n").unwrap();
        let status2 = engine.status().unwrap();
        assert_eq!(status2.modified_count, 1);

        // 6. Diff
        let diff = engine.diff_file("hello.txt").unwrap();
        assert_eq!(diff.status, "modified");
        assert!(diff.lines.iter().any(|l| l.change_type == "+"));

        // 7. Commit 2
        let commit2 = engine.commit("Update greeting", "sentinel-1").unwrap();
        assert_eq!(commit2.parent_ids, vec![commit1.commit_id.clone()]);

        // 8. Log
        let log = engine.log(None).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].commit_id, commit2.commit_id);
        assert_eq!(log[1].commit_id, commit1.commit_id);

        // 9. Branching
        engine.create_branch("feature-mesh").unwrap();
        let branches = engine.branch_list().unwrap();
        assert!(branches.contains(&"main".to_string()));
        assert!(branches.contains(&"feature-mesh".to_string()));

        // 10. Checkout commit 1 (Rollback)
        engine.checkout(&commit1.commit_id).unwrap();
        let restored_content = fs::read_to_string(tmp.join("hello.txt")).unwrap();
        assert_eq!(restored_content, "Hello Sovereign World\n");

        // Cleanup
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn ghost_image_and_scope_integration_preserve_both_branch_changes() {
        let tmp = std::env::temp_dir().join(format!("sb_vcs_scope_merge_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        let source = "pub fn alpha() { 1 }\npub fn beta() { 1 }\n";
        fs::write(tmp.join("src.rs"), source).unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 2 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("change alpha", "alice").unwrap();

        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 1 }\npub fn beta() { 2 }\n",
        )
        .unwrap();
        engine.commit("change beta", "bob").unwrap();

        let comparison = engine.compare_branch_scopes("feature").unwrap();
        assert!(comparison
            .changes
            .iter()
            .any(|change| change.name == "alpha" && change.status == "other-only"));
        assert!(comparison
            .changes
            .iter()
            .any(|change| change.name == "beta" && change.status == "current-only"));

        let integrated = engine.integrate_branch_scopes("feature", "bob").unwrap();
        assert_eq!(integrated.parent_ids.len(), 2);
        assert_eq!(integrated.format_version, 3);
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "pub fn alpha() { 2 }\npub fn beta() { 2 }\n"
        );
        assert_eq!(engine.log(None).unwrap().len(), 4);
        let bundle = engine.export_bundle("main", None).unwrap();
        let replica = std::env::temp_dir().join(format!(
            "sb_vcs_scope_merge_replica_{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&replica).unwrap();
        let mut replica_engine = VcsEngine::init(&replica).unwrap();
        replica_engine.import_bundle(&bundle, "main").unwrap();
        assert_eq!(replica_engine.log(None).unwrap().len(), 4);
        let _ = fs::remove_dir_all(replica);

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scope_integration_merges_scope_additions_and_deletions() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_scope_structure_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 1 }\npub fn beta() { 1 }\npub fn delta() { 1 }\n",
        )
        .unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 1 }\npub fn gamma() { 1 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine
            .commit("add gamma and remove delta", "alice")
            .unwrap();

        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 2 }\npub fn beta() { 1 }\npub fn delta() { 1 }\n",
        )
        .unwrap();
        engine.commit("change alpha", "bob").unwrap();

        engine.integrate_branch_scopes("feature", "bob").unwrap();
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "pub fn alpha() { 2 }\npub fn gamma() { 1 }\npub fn beta() { 1 }\n"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scope_integration_merges_ast_only_file_addition_and_deletion() {
        let tmp = std::env::temp_dir().join(format!(
            "sb_vcs_scope_file_structure_{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 1 }\n").unwrap();
        fs::write(tmp.join("remove.rs"), "pub fn obsolete() { 1 }\n").unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::remove_file(tmp.join("remove.rs")).unwrap();
        fs::write(tmp.join("new.rs"), "pub fn added() { 1 }\n").unwrap();
        engine.commit("add and remove AST files", "alice").unwrap();

        engine.checkout("main").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 2 }\n").unwrap();
        engine.commit("change alpha", "bob").unwrap();

        engine.integrate_branch_scopes("feature", "bob").unwrap();
        assert!(!tmp.join("remove.rs").exists());
        assert_eq!(
            fs::read_to_string(tmp.join("new.rs")).unwrap(),
            "pub fn added() { 1 }\n"
        );
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "pub fn alpha() { 2 }\n"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scope_integration_moves_ast_scope_between_files() {
        let tmp = std::env::temp_dir().join(format!("sb_vcs_scope_move_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 1 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 1 }\n").unwrap();
        fs::write(tmp.join("beta.rs"), "pub fn beta() { 1 }\n").unwrap();
        engine.commit("move beta", "alice").unwrap();

        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 2 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("change alpha", "bob").unwrap();

        engine.integrate_branch_scopes("feature", "bob").unwrap();
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "pub fn alpha() { 2 }\n"
        );
        assert_eq!(
            fs::read_to_string(tmp.join("beta.rs")).unwrap(),
            "pub fn beta() { 1 }\n"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scope_integration_requires_manual_review_for_two_sided_opaque_changes() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_scope_non_ast_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 1 }\n").unwrap();
        fs::write(tmp.join("README.txt"), "base documentation\n").unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(tmp.join("README.txt"), "feature documentation\n").unwrap();
        engine.commit("change documentation", "alice").unwrap();

        engine.checkout("main").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 2 }\n").unwrap();
        fs::write(tmp.join("README.txt"), "main documentation\n").unwrap();
        engine.commit("change alpha", "bob").unwrap();

        let error = engine
            .integrate_branch_scopes("feature", "bob")
            .unwrap_err();
        assert!(error.contains("conflict"));
        assert_eq!(
            fs::read_to_string(tmp.join("README.txt")).unwrap(),
            "main documentation\n"
        );
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "pub fn alpha() { 2 }\n"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn integration_plan_explains_safe_changes_and_is_bound_to_branch_heads() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_integration_plan_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 1 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 2 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("change alpha", "alice").unwrap();
        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn alpha() { 1 }\npub fn beta() { 2 }\n",
        )
        .unwrap();
        engine.commit("change beta", "bob").unwrap();

        let plan = engine.plan_branch_integration("feature").unwrap();
        assert!(plan.ready_to_integrate);
        assert!(plan.manual_required.is_empty());
        assert_eq!(plan.auto_mergeable.len(), 2);
        assert!(plan
            .auto_mergeable
            .iter()
            .any(|entry| entry.action == "take-other" && entry.change.name == "alpha"));
        assert!(plan.semantic_validation.contains("Nicht ausgeführt"));

        engine.checkout("feature").unwrap();
        let stale_plan = engine.integrate_branch_scopes_for_heads(
            "main",
            "alice",
            Some(&plan.current_commit),
            Some(&plan.other_commit),
        );
        assert!(stale_plan.unwrap_err().contains("Branch heads changed"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn parser_v1_base_is_validated_and_reprojected_for_v2_branch_comparison() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_parser_upgrade_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 1;\npub fn alpha() { 1 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        let mut legacy_base = engine.commit("base", "alice").unwrap();
        let base_tree = engine.get_tree(&legacy_base.tree_hash).unwrap();
        let base_source = engine.read_tree_file(&base_tree, "src.rs").unwrap();
        legacy_base.ast_parser_version = 1;
        legacy_base.ast_scopes = capture_ast_scopes_v1("src.rs", &base_source).unwrap();
        legacy_base.commit_id = compute_commit_id(&legacy_base).unwrap();
        let legacy_path = engine
            .vcs_dir
            .join("objects")
            .join("commits")
            .join(format!("{}.json", legacy_base.commit_id));
        fs::write(
            &legacy_path,
            serde_json::to_vec_pretty(&legacy_base).unwrap(),
        )
        .unwrap();
        fs::write(
            engine.vcs_dir.join("refs").join("heads").join("main"),
            &legacy_base.commit_id,
        )
        .unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 1;\npub fn alpha() { 2 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("change alpha", "alice").unwrap();
        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 1;\npub fn alpha() { 1 }\npub fn beta() { 2 }\n",
        )
        .unwrap();
        engine.commit("change beta", "bob").unwrap();

        let plan = engine.plan_branch_integration("feature").unwrap();
        assert!(plan.ready_to_integrate);
        assert_eq!(plan.ast_parser_version, 3);
        assert!(plan
            .auto_mergeable
            .iter()
            .any(|entry| entry.change.name == "alpha" && entry.action == "take-other"));
        engine.integrate_branch_scopes("feature", "bob").unwrap();
        assert!(fs::read_to_string(tmp.join("src.rs"))
            .unwrap()
            .contains("pub fn alpha() { 2 }"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn parser_v2_snapshot_without_adapter_metadata_remains_valid() {
        let tmp = std::env::temp_dir().join(format!("sb_vcs_parser_v2_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 1 }\n").unwrap();
        let mut commit = engine.commit("legacy parser snapshot", "alice").unwrap();
        let tree = engine.get_tree(&commit.tree_hash).unwrap();
        let source = engine.read_tree_file(&tree, "src.rs").unwrap();
        commit.ast_parser_version = 2;
        commit.ast_scopes = capture_ast_scopes_v2("src.rs", &source).unwrap();
        commit.commit_id = compute_commit_id(&commit).unwrap();
        let commit_path = engine
            .vcs_dir
            .join("objects")
            .join("commits")
            .join(format!("{}.json", commit.commit_id));
        fs::write(&commit_path, serde_json::to_vec_pretty(&commit).unwrap()).unwrap();
        fs::write(
            engine.vcs_dir.join("refs").join("heads").join("main"),
            &commit.commit_id,
        )
        .unwrap();

        let projected = engine.current_ast_scopes(&commit).unwrap();
        assert!(projected.iter().any(|scope| {
            scope.name == "alpha" && scope.parser_id == "tree-sitter-rust@0.24.2"
        }));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scope_conflicts_persist_resolutions_and_leave_workspace_untouched_until_finalize() {
        let tmp = std::env::temp_dir().join(format!("sb_vcs_conflicts_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        let base = "pub fn authorize() {\n    true\n}\n";
        fs::write(tmp.join("src.rs"), base).unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn authorize() {\n    false\n}\n").unwrap();
        engine.commit("feature change", "alice").unwrap();
        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "pub fn authorize() {\n    true && false\n}\n",
        )
        .unwrap();
        engine.commit("main change", "bob").unwrap();
        let before = fs::read_to_string(tmp.join("src.rs")).unwrap();

        let state = engine.prepare_integration_conflicts("feature").unwrap();
        assert_eq!(state.conflicts.len(), 1);
        assert_eq!(
            fs::read_to_string(tmp.join(".sb").join("conflicts.json")).unwrap(),
            serde_json::to_string_pretty(&state).unwrap()
        );
        let scope_id = state.conflicts[0].entry.change.scope_id.clone();
        let resolved = engine
            .resolve_integration_conflict(&scope_id, ConflictResolution::Other)
            .unwrap();
        assert_eq!(
            resolved.conflicts[0].resolution,
            Some(ConflictResolution::Other)
        );
        assert_eq!(fs::read_to_string(tmp.join("src.rs")).unwrap(), before);

        let commit = engine.finalize_integration_conflicts("alice").unwrap();
        assert_eq!(commit.parent_ids.len(), 2);
        assert!(!tmp.join(".sb").join("conflicts.json").exists());
        assert!(fs::read_to_string(tmp.join("src.rs"))
            .unwrap()
            .contains("false"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn stale_conflict_state_cannot_finalize_and_can_be_discarded() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_stale_conflicts_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(tmp.join("src.rs"), "pub fn authorize() { true }\n").unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();
        engine.checkout("feature").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn authorize() { false }\n").unwrap();
        engine.commit("feature update", "alice").unwrap();
        engine.checkout("main").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn authorize() { true && false }\n").unwrap();
        engine.commit("main update", "bob").unwrap();

        let pending = engine.prepare_integration_conflicts("feature").unwrap();
        let scope = pending.conflicts[0].entry.change.scope_id.clone();
        engine
            .resolve_integration_conflict(&scope, ConflictResolution::Other)
            .unwrap();
        engine.checkout("feature").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn authorize() { true || false }\n").unwrap();
        engine.commit("feature moved", "alice").unwrap();
        engine.checkout("main").unwrap();

        assert!(engine
            .finalize_integration_conflicts("bob")
            .unwrap_err()
            .contains("Branch heads changed"));
        assert!(engine.integration_conflicts().unwrap().is_some());
        assert!(engine.discard_integration_conflicts().unwrap());
        assert!(engine.integration_conflicts().unwrap().is_none());
        assert!(!engine.discard_integration_conflicts().unwrap());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn managed_workspaces_share_objects_but_keep_branch_heads_and_files_isolated() {
        let tmp = std::env::temp_dir().join(format!("sb_vcs_worktrees_{}", uuid::Uuid::new_v4()));
        let repo = tmp.join("repo");
        let first_path = tmp.join("work-feature");
        let second_path = tmp.join("work-main");
        let stale_path = tmp.join("work-feature-stale");
        fs::create_dir_all(&repo).unwrap();
        let mut engine = VcsEngine::init(&repo).unwrap();
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join("src/lib.rs"), "pub fn value() { 1 }\n").unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();
        engine.checkout("feature").unwrap();
        fs::write(repo.join("src/lib.rs"), "pub fn value() { 2 }\n").unwrap();
        engine.commit("feature", "alice").unwrap();
        engine.checkout("main").unwrap();

        let feature_workspace = engine
            .add_managed_workspace("feature", &first_path)
            .unwrap();
        let main_workspace = engine.add_managed_workspace("main", &second_path).unwrap();
        engine
            .add_managed_workspace("feature", &stale_path)
            .unwrap();
        assert_eq!(
            feature_workspace.repository_vcs_dir,
            main_workspace.repository_vcs_dir
        );
        assert_ne!(feature_workspace.ports.base, main_workspace.ports.base);
        assert_eq!(
            fs::read_to_string(first_path.join("src/lib.rs")).unwrap(),
            "pub fn value() { 2 }\n"
        );
        assert_eq!(
            fs::read_to_string(second_path.join("src/lib.rs")).unwrap(),
            "pub fn value() { 1 }\n"
        );
        assert_eq!(
            fs::read_to_string(repo.join(".sb/HEAD")).unwrap(),
            "ref: refs/heads/main\n"
        );

        let mut feature_engine = VcsEngine::open(&first_path).unwrap();
        fs::write(first_path.join("src/lib.rs"), "pub fn value() { 3 }\n").unwrap();
        let feature_commit = feature_engine.commit("feature update", "bob").unwrap();
        assert_eq!(
            engine.branch_head("feature").unwrap().commit_id,
            feature_commit.commit_id
        );
        assert_eq!(engine.current_branch().unwrap(), "main");
        assert_eq!(
            fs::read_to_string(repo.join("src/lib.rs")).unwrap(),
            "pub fn value() { 1 }\n"
        );
        assert_eq!(engine.managed_workspaces().unwrap().len(), 3);
        let mut stale_engine = VcsEngine::open(&stale_path).unwrap();
        fs::write(stale_path.join("src/lib.rs"), "pub fn value() { 4 }\n").unwrap();
        let stale_error = stale_engine
            .commit("stale feature update", "carol")
            .unwrap_err();
        assert!(stale_error.contains("advanced in another workspace"));
        fs::write(stale_path.join("src/lib.rs"), "pub fn value() { 2 }\n").unwrap();
        stale_engine.checkout("feature").unwrap();
        assert_eq!(
            fs::read_to_string(stale_path.join("src/lib.rs")).unwrap(),
            "pub fn value() { 3 }\n"
        );

        let dirty_path = tmp.join("work-dirty");
        engine.add_managed_workspace("main", &dirty_path).unwrap();
        fs::write(dirty_path.join("src/lib.rs"), "pub fn value() { 9 }\n").unwrap();
        assert!(engine
            .remove_managed_workspace(&dirty_path, false)
            .unwrap_err()
            .contains("--force"));
        engine.remove_managed_workspace(&dirty_path, true).unwrap();
        assert!(!dirty_path.exists());

        let orphan_path = tmp.join("work-orphan");
        engine.add_managed_workspace("main", &orphan_path).unwrap();
        fs::remove_dir_all(&orphan_path).unwrap();
        let pruned = engine.prune_managed_workspaces().unwrap();
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].file_name(), orphan_path.file_name());
        engine.remove_managed_workspace(&stale_path, false).unwrap();
        assert!(!stale_path.exists());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn concurrent_managed_workspace_commits_serialize_branch_ref_updates() {
        let tmp = std::env::temp_dir().join(format!("sb_vcs_parallel_{}", uuid::Uuid::new_v4()));
        let repo = tmp.join("repo");
        let left_path = tmp.join("left");
        let right_path = tmp.join("right");
        fs::create_dir_all(&repo).unwrap();
        let mut repository = VcsEngine::init(&repo).unwrap();
        fs::write(repo.join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
        repository.commit("base", "alice").unwrap();
        repository
            .add_managed_workspace("main", &left_path)
            .unwrap();
        repository
            .add_managed_workspace("main", &right_path)
            .unwrap();
        fs::write(left_path.join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
        fs::write(right_path.join("lib.rs"), "pub fn value() -> u8 { 3 }\n").unwrap();
        let left = VcsEngine::open(&left_path).unwrap();
        let right = VcsEngine::open(&right_path).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let left_barrier = std::sync::Arc::clone(&barrier);
        let left_thread = std::thread::spawn(move || {
            let mut engine = left;
            left_barrier.wait();
            engine.commit("left update", "alice")
        });
        let right_barrier = std::sync::Arc::clone(&barrier);
        let right_thread = std::thread::spawn(move || {
            let mut engine = right;
            right_barrier.wait();
            engine.commit("right update", "bob")
        });
        let left_result = left_thread.join().unwrap();
        let right_result = right_thread.join().unwrap();
        let (winning_commit, losing_error) = match (left_result, right_result) {
            (Ok(commit), Err(error)) | (Err(error), Ok(commit)) => (commit, error),
            (Ok(_), Ok(_)) => panic!("both concurrent branch updates unexpectedly succeeded"),
            (Err(left), Err(right)) => panic!("both branch updates failed: {left}; {right}"),
        };
        assert_eq!(
            repository.branch_head("main").unwrap().commit_id,
            winning_commit.commit_id
        );
        assert!(losing_error.contains("advanced in another workspace"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn integration_plan_marks_opaque_conflicts_for_manual_review() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_opaque_conflict_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 1;\npub fn alpha() { 1 }\n",
        )
        .unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 2;\npub fn alpha() { 1 }\n",
        )
        .unwrap();
        engine
            .commit("change constant on feature", "alice")
            .unwrap();
        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 3;\npub fn alpha() { 1 }\n",
        )
        .unwrap();
        engine.commit("change constant on main", "bob").unwrap();

        let plan = engine.plan_branch_integration("feature").unwrap();
        assert!(!plan.ready_to_integrate);
        assert!(plan
            .manual_required
            .iter()
            .any(|entry| entry.change.name.starts_with("opaque")));
        assert!(plan
            .blocked_reasons
            .iter()
            .any(|reason| reason.contains("conflict")));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn parser_failures_are_explained_and_never_auto_integrated() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_parser_failure_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 1 }\n").unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha( {\n").unwrap();
        engine.commit("incomplete source", "alice").unwrap();
        engine.checkout("main").unwrap();

        let plan = engine.plan_branch_integration("feature").unwrap();
        let parser_failure = plan
            .manual_required
            .iter()
            .find(|entry| entry.change.parser_diagnostic.is_some())
            .expect("parser failure should be included in the manual review");
        assert!(parser_failure.reason.contains("preserved it as Opaque"));
        assert!(!plan
            .auto_mergeable
            .iter()
            .any(|entry| { entry.change.parser_diagnostic.is_some() }));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn one_sided_stable_opaque_region_is_previewed_and_applied() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_opaque_one_sided_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 1;\n\npub fn alpha() { 1 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 2;\n\npub fn alpha() { 1 }\npub fn beta() { 1 }\n",
        )
        .unwrap();
        engine.commit("change opaque constant", "alice").unwrap();
        engine.checkout("main").unwrap();
        fs::write(
            tmp.join("src.rs"),
            "const LIMIT: u32 = 1;\n\npub fn alpha() { 1 }\npub fn beta() { 2 }\n",
        )
        .unwrap();
        engine.commit("change beta", "bob").unwrap();

        let plan = engine.plan_branch_integration("feature").unwrap();
        assert!(plan.ready_to_integrate);
        assert!(plan
            .auto_mergeable
            .iter()
            .any(|entry| entry.action == "replace-opaque"));
        engine.integrate_branch_scopes("feature", "bob").unwrap();
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "const LIMIT: u32 = 2;\n\npub fn alpha() { 1 }\npub fn beta() { 2 }\n"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn scope_integration_refuses_same_scope_conflicts_without_changing_worktree() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_scope_conflict_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 1 }\n").unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();

        engine.checkout("feature").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 2 }\n").unwrap();
        engine.commit("feature alpha", "alice").unwrap();
        engine.checkout("main").unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 3 }\n").unwrap();
        engine.commit("main alpha", "bob").unwrap();

        let comparison = engine.compare_branch_scopes("feature").unwrap();
        assert_eq!(comparison.changes[0].status, "conflict");
        assert!(engine
            .integrate_branch_scopes("feature", "bob")
            .unwrap_err()
            .contains("conflict"));
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "pub fn alpha() { 3 }\n"
        );
        assert_eq!(engine.current_branch().unwrap(), "main");

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn checkout_refuses_to_discard_uncommitted_changes() {
        let tmp =
            std::env::temp_dir().join(format!("sb_vcs_dirty_checkout_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut engine = VcsEngine::init(&tmp).unwrap();
        fs::write(tmp.join("src.rs"), "pub fn alpha() { 1 }\n").unwrap();
        engine.commit("base", "alice").unwrap();
        engine.create_branch("feature").unwrap();
        fs::write(tmp.join("src.rs"), "uncommitted work\n").unwrap();

        assert!(engine.checkout("feature").is_err());
        assert_eq!(
            fs::read_to_string(tmp.join("src.rs")).unwrap(),
            "uncommitted work\n"
        );
        assert_eq!(engine.current_branch().unwrap(), "main");

        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn test_bundle_export_import_roundtrip() {
        let repo_a = std::env::temp_dir().join(format!("sb_vcs_bundle_a_{}", uuid::Uuid::new_v4()));
        let repo_b = std::env::temp_dir().join(format!("sb_vcs_bundle_b_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&repo_a).unwrap();
        fs::create_dir_all(&repo_b).unwrap();

        // 1. Repo A creates commit
        let mut engine_a = VcsEngine::init(&repo_a).unwrap();
        fs::write(
            repo_a.join("code.rs"),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .unwrap();
        let commit_a = engine_a.commit("Add math function", "alice").unwrap();

        // 2. Export bundle from A
        let bundle = engine_a.export_bundle("main", None).unwrap();
        assert!(!bundle.is_empty());

        // 3. Repo B imports bundle
        let mut engine_b = VcsEngine::init(&repo_b).unwrap();
        let report = engine_b.import_bundle(&bundle, "main").unwrap();
        assert_eq!(report.new_head, commit_a.commit_id);

        // 4. Verify Repo B has code and commit history
        let b_history = engine_b.log(None).unwrap();
        assert_eq!(b_history.len(), 1);
        assert_eq!(b_history[0].commit_id, commit_a.commit_id);

        let restored = fs::read_to_string(repo_b.join("code.rs")).unwrap();
        assert_eq!(restored, "pub fn add(a: i32, b: i32) -> i32 { a + b }\n");

        let _ = fs::remove_dir_all(repo_a);
        let _ = fs::remove_dir_all(repo_b);
    }

    #[test]
    fn test_push_pull_anchor_roundtrip() {
        let repo_local =
            std::env::temp_dir().join(format!("sb_vcs_push_local_{}", uuid::Uuid::new_v4()));
        let repo_peer =
            std::env::temp_dir().join(format!("sb_vcs_pull_peer_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&repo_local).unwrap();
        fs::create_dir_all(&repo_peer).unwrap();

        let anchor = "test-anchor";
        let project = "test_project";

        // 1. Local commits and pushes to anchor
        let mut engine_local = VcsEngine::init(&repo_local).unwrap();
        engine_local.set_project_name(project).unwrap();
        fs::write(
            repo_local.join("lib.rs"),
            "pub const VERSION: &str = \"1.0.0\";\n",
        )
        .unwrap();
        let local_commit = engine_local.commit("Initial release", "bob").unwrap();

        let push_report = engine_local.push_to_anchor(anchor, "main").unwrap();
        assert_eq!(push_report.new_head, local_commit.commit_id);

        // 2. Check remote status
        let status = engine_local.get_remote_status(anchor, "main").unwrap();
        assert!(status.in_sync);
        assert_eq!(status.ahead, 0);

        // 3. Peer pulls from anchor
        let mut engine_peer = VcsEngine::init(&repo_peer).unwrap();
        engine_peer.set_project_name(project).unwrap();
        let pull_report = engine_peer.pull_from_anchor(anchor, "main").unwrap();
        assert_eq!(pull_report.new_head, local_commit.commit_id);

        let peer_code = fs::read_to_string(repo_peer.join("lib.rs")).unwrap();
        assert_eq!(peer_code, "pub const VERSION: &str = \"1.0.0\";\n");

        let _ = fs::remove_dir_all(repo_local);
        let _ = fs::remove_dir_all(repo_peer);
        if let Some(home) = dirs::home_dir() {
            let _ = fs::remove_dir_all(home.join(".sb").join("vcs-store").join(anchor));
        }
    }

    #[test]
    fn test_ed25519_commit_signing_and_verification() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[123u8; 32]);
        let mut commit = VcsCommit {
            format_version: 3,
            commit_id: "53c3e45b943d4c7a7b75c1bdef47da9cb0ea7704cf3979092dce967834e5bf76"
                .to_string(),
            parent_ids: vec![],
            tree_hash: "0de77d0ba8abca45542ba8902c216b36ec9214e93dfa7dc7fc7c2e524d54c532"
                .to_string(),
            author_callsign: "sentinel-alpha".to_string(),
            timestamp: Utc::now(),
            message: "Initial signed commit".to_string(),
            signature_ed25519: None,
            ast_scopes: vec![],
            ast_parser_version: 3,
        };

        // 1. Initial state: unsigned
        assert_eq!(commit.signature_status(), "nicht signiert");
        assert!(commit.verify_signature().is_err());

        // 2. Sign commit
        commit.sign(&signing_key);
        assert!(commit.signature_ed25519.is_some());
        assert!(commit
            .signature_ed25519
            .as_ref()
            .unwrap()
            .starts_with("ed25519:"));

        // 3. Verify signature
        let vk = commit.verify_signature().expect("Signature must be valid");
        assert_eq!(vk, signing_key.verifying_key());
        assert_eq!(commit.signature_status(), "Ed25519 verifiziert (valide)");
        assert_eq!(
            commit.signer_pubkey(),
            Some(hex::encode(signing_key.verifying_key().as_bytes()))
        );

        // 4. Tampering commit_id must fail verification
        let mut tampered = commit.clone();
        tampered.commit_id =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(tampered.verify_signature().is_err());
        assert_eq!(tampered.signature_status(), "Ed25519 Signatur ungültig");

        // 5. Legacy placeholder handling
        let mut legacy = commit.clone();
        legacy.signature_ed25519 = Some("ed25519_sig_abcdef0123456789".to_string());
        assert_eq!(
            legacy.signature_status(),
            "Legacy-Platzhalter; nicht kryptographisch signiert"
        );
    }

    #[test]
    fn test_module_outline_extraction() {
        let ws = std::env::temp_dir().join(format!("sb_vcs_outline_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&ws).unwrap();
        let file_path = ws.join("lib.rs");
        fs::write(
            &file_path,
            "pub struct Resolver {\n    x: i32,\n}\n\nimpl Resolver {\n    pub fn resolve(&self) -> i32 {\n        self.x\n    }\n}\n\nmod tests {\n    #[test]\n    fn resolves_value() {\n        assert_eq!(1, 1);\n    }\n}\n\npub fn helper() -> i32 {\n    1\n}\n",
        )
        .unwrap();

        let outline = VcsEngine::outline(&file_path).unwrap();
        assert_eq!(outline.total_lines, 20);
        assert!(outline.items.iter().any(|i| i.name.contains("Resolver")));
        assert!(outline.items.iter().any(|i| {
            i.kind == "impl" && i.is_container && i.signature.starts_with("impl Resolver")
        }));
        assert!(outline
            .items
            .iter()
            .any(|i| { i.name == "resolve" && i.start_line > 5 && i.end_line < 10 }));
        assert!(outline
            .items
            .iter()
            .any(|i| { i.kind == "mod" && i.name == "tests" && i.is_container }));
        assert!(outline
            .items
            .iter()
            .any(|i| { i.kind == "function" && i.name == "resolves_value" && i.start_line > 10 }));
        let helper = outline
            .items
            .iter()
            .find(|i| i.name.contains("helper"))
            .expect("helper must be in outline");
        assert!(helper.signature.starts_with("pub fn helper"));
        assert_eq!(helper.start_line, 18);
        assert!(outline
            .items
            .iter()
            .all(|i| i.kind != format!("{}", crate::ast::AstScopeKind::Opaque)));

        assert!(VcsEngine::outline(&ws.join("missing.rs")).is_err());
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn test_logical_co_change_coupling() {
        let ws = std::env::temp_dir().join(format!("sb_vcs_coupling_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&ws).unwrap();
        let mut engine = VcsEngine::init(&ws).unwrap();

        let a = ws.join("a.rs");
        let b = ws.join("b.rs");
        let c = ws.join("c.rs");
        fs::write(&a, "pub fn fa() -> i32 { 0 }").unwrap();
        fs::write(&b, "pub fn fb() -> i32 { 0 }").unwrap();
        fs::write(&c, "pub fn fc() -> i32 { 0 }").unwrap();
        engine.commit("init", "tester").unwrap();

        // a und b ändern sich zweimal gemeinsam, c nur einmal allein.
        for v in 1..=2 {
            fs::write(&a, format!("pub fn fa() -> i32 {{ {v} }}")).unwrap();
            fs::write(&b, format!("pub fn fb() -> i32 {{ {v} }}")).unwrap();
            engine.commit(&format!("ab {v}"), "tester").unwrap();
        }
        fs::write(&c, "pub fn fc() -> i32 { 9 }").unwrap();
        engine.commit("c only", "tester").unwrap();

        let no_filter = crate::sync::AnalysisFilter::default();
        let report = engine.coupling(None, None, 2, &no_filter).unwrap();
        assert_eq!(report.commits_analyzed, 4);
        assert_eq!(report.couplings.len(), 1);
        let pair = &report.couplings[0];
        assert!(pair.file_a.ends_with("a.rs") && pair.file_b.ends_with("b.rs"));
        assert_eq!(pair.co_changes, 2);
        assert!((pair.confidence_a_to_b - 1.0).abs() < f64::EPSILON);

        let filtered = engine.coupling(None, Some("c.rs"), 1, &no_filter).unwrap();
        assert!(filtered.couplings.is_empty());

        // .sbignore-Filter blendet b.rs aus -> keine Kopplung mehr übrig.
        let sbignore = crate::sync::AnalysisFilter::from_str("# Analyse-Rauschen\nb.rs\n");
        let ignored = engine.coupling(None, None, 1, &sbignore).unwrap();
        assert!(ignored.couplings.is_empty());
        let heat = engine.heatmap(None, &sbignore).unwrap();
        assert!(heat
            .hot_files
            .iter()
            .all(|f| !f.file_path.ends_with("b.rs")));

        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn selective_scope_commit_preserves_other_working_changes_and_history_is_queryable() {
        let ws = std::env::temp_dir().join(format!("sb_vcs_selective_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&ws).unwrap();
        let source_path = ws.join("src").join("lib.rs");
        fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        fs::write(
            &source_path,
            "pub fn alpha() -> i32 { 1 }\npub fn beta() -> i32 { 1 }\npub fn gamma() -> i32 { 1 }\n",
        )
        .unwrap();
        let mut engine = VcsEngine::init(&ws).unwrap();
        engine.commit("base", "tester").unwrap();

        fs::write(
            &source_path,
            "pub fn alpha() -> i32 { 2 }\npub fn beta() -> i32 { 2 }\npub fn gamma() -> i32 { 2 }\n",
        )
        .unwrap();
        let commit = engine
            .commit_selected(
                "update alpha only",
                "tester",
                &[],
                &[
                    ("src/lib.rs".to_string(), "alpha".to_string()),
                    ("src/lib.rs".to_string(), "beta".to_string()),
                ],
            )
            .unwrap();
        let tree = engine.get_tree(&commit.tree_hash).unwrap();
        let blob = engine
            .get_blob(&tree.entries["src/lib.rs"].blake3_hash)
            .unwrap();
        let committed_source = String::from_utf8(blob).unwrap();
        assert!(committed_source.contains("alpha() -> i32 { 2 }"));
        assert!(committed_source.contains("beta() -> i32 { 2 }"));
        assert!(committed_source.contains("gamma() -> i32 { 1 }"));
        assert!(engine
            .status()
            .unwrap()
            .changes
            .iter()
            .any(|change| { change.rel_path == "src/lib.rs" && change.status == "modified" }));

        let history = engine.why_scope("src/lib.rs", "alpha").unwrap();
        assert_eq!(history.changes.len(), 2);
        assert_eq!(history.changes.last().unwrap().status, "modified");
        let ast_diff = engine.diff_scopes(Some("src/lib.rs")).unwrap();
        assert_eq!(ast_diff.len(), 1);
        assert_eq!(ast_diff[0].name, "gamma");
        assert_eq!(ast_diff[0].status, "modified");
        let shown = engine.show_commit(&commit.commit_id[..8]).unwrap();
        assert_eq!(shown.changes.len(), 1);
        assert_eq!(shown.changes[0].status, "modified");

        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn selective_file_commit_leaves_unselected_files_out_of_commit() {
        let ws = std::env::temp_dir().join(format!("sb_vcs_only_files_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("a.txt"), "a1\n").unwrap();
        fs::write(ws.join("b.txt"), "b1\n").unwrap();
        let mut engine = VcsEngine::init(&ws).unwrap();
        engine.commit("base", "tester").unwrap();
        fs::write(ws.join("a.txt"), "a2\n").unwrap();
        fs::write(ws.join("b.txt"), "b2\n").unwrap();

        let preview = engine
            .preview_commit_selection(&["a.txt".to_string()], &[])
            .unwrap();
        assert_eq!(preview, vec!["a.txt"]);
        let commit = engine
            .commit_selected("a only", "tester", &["a.txt".to_string()], &[])
            .unwrap();
        let tree = engine.get_tree(&commit.tree_hash).unwrap();
        let a = engine.get_blob(&tree.entries["a.txt"].blake3_hash).unwrap();
        let b = engine.get_blob(&tree.entries["b.txt"].blake3_hash).unwrap();
        assert_eq!(a, b"a2\n");
        assert_eq!(b, b"b1\n");
        assert!(engine
            .status()
            .unwrap()
            .changes
            .iter()
            .any(|change| change.rel_path == "b.txt"));
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn checkpoints_can_be_checked_out_and_selectors_reject_parent_paths() {
        let ws = std::env::temp_dir().join(format!("sb_vcs_checkpoint_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("value.txt"), "before\n").unwrap();
        let mut engine = VcsEngine::init(&ws).unwrap();
        let (checkpoint, reference) = engine
            .create_checkpoint("before-refactor", None, "tester")
            .unwrap();
        assert!(reference.is_file());

        fs::write(ws.join("value.txt"), "after\n").unwrap();
        engine.commit("after", "tester").unwrap();
        engine.checkout("before-refactor").unwrap();
        assert_eq!(
            fs::read_to_string(ws.join("value.txt")).unwrap(),
            "before\n"
        );
        assert_eq!(
            engine.head_commit().unwrap().unwrap().commit_id,
            checkpoint.commit_id
        );

        let error = engine
            .commit_selected("unsafe", "tester", &["../outside".to_string()], &[])
            .unwrap_err();
        assert!(error.contains("Invalid repository-relative"));
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn test_heatmap_and_churn_analysis() {
        let ws = std::env::temp_dir().join(format!("sb_vcs_heatmap_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&ws).unwrap();
        let mut engine = VcsEngine::init(&ws).unwrap();

        let file_path = ws.join("src").join("lib.rs");
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();

        // Commit 1: Erste Version von compute()
        fs::write(
            &file_path,
            "pub fn compute() -> i32 { 1 }\npub fn stable() -> i32 { 10 }",
        )
        .unwrap();
        engine.commit("Initial version", "tester").unwrap();

        // Commit 2: compute() geändert, stable() unverändert
        fs::write(
            &file_path,
            "pub fn compute() -> i32 { 2 }\npub fn stable() -> i32 { 10 }",
        )
        .unwrap();
        engine.commit("Update compute", "tester").unwrap();

        // Commit 3: compute() nochmals geändert
        fs::write(
            &file_path,
            "pub fn compute() -> i32 { 3 }\npub fn stable() -> i32 { 10 }",
        )
        .unwrap();
        engine.commit("Update compute again", "tester").unwrap();

        let report = engine
            .heatmap(None, &crate::sync::AnalysisFilter::default())
            .unwrap();
        assert_eq!(report.commits_analyzed, 3);
        assert!(!report.hot_scopes.is_empty());

        let compute_scope = report
            .hot_scopes
            .iter()
            .find(|s| s.name == "compute")
            .expect("compute must be in heatmap");
        assert_eq!(compute_scope.change_count, 2);
        assert_eq!(compute_scope.status, "🟡 WARM");

        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn test_rollback_full_and_single_file() {
        let ws = std::env::temp_dir().join(format!("sb_vcs_rollback_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&ws).unwrap();
        let mut engine = VcsEngine::init(&ws).unwrap();

        let file_a = ws.join("a.txt");
        let file_b = ws.join("b.txt");

        // Commit 1:
        fs::write(&file_a, "version 1").unwrap();
        fs::write(&file_b, "initial b").unwrap();
        let _c1 = engine.commit("Commit 1", "tester").unwrap();

        // Commit 2:
        fs::write(&file_a, "version 2").unwrap();
        let c2 = engine.commit("Commit 2", "tester").unwrap();

        // Commit 3:
        fs::write(&file_a, "version 3").unwrap();
        fs::write(&file_b, "modified b").unwrap();
        let _c3 = engine.commit("Commit 3", "tester").unwrap();

        // 1. Rollback einer einzelnen Datei (file_a auf Stand von Commit 2, 1 Schritt zurück)
        let report_file = engine.rollback(1, None, Some("a.txt"), false).unwrap();
        assert_eq!(report_file.target_commit_id, c2.commit_id);
        assert_eq!(fs::read_to_string(&file_a).unwrap(), "version 2");
        assert_eq!(fs::read_to_string(&file_b).unwrap(), "modified b");

        // Commit die Änderung wieder, damit Workspace sauber ist
        engine.commit("Revert a.txt", "tester").unwrap();

        // 2. Rollback des gesamten Repositories um 2 Schritte (zurück zu c2)
        let report_full = engine.rollback(2, None, None, false).unwrap();
        assert_eq!(report_full.target_commit_id, c2.commit_id);
        assert_eq!(fs::read_to_string(&file_a).unwrap(), "version 2");
        assert_eq!(fs::read_to_string(&file_b).unwrap(), "initial b");
        assert_eq!(
            engine.head_commit().unwrap().unwrap().commit_id,
            c2.commit_id
        );

        let _ = fs::remove_dir_all(&ws);
    }
}
