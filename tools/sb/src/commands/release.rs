use colored::*;
use ed25519_dalek::{Signer, SigningKey};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::meta::{get_sb_dir, resolve_tools};

pub const RELEASE_BASE_URL: &str = "https://skulls-and-bones.org/bin";
pub const RELEASE_MANIFEST_NAME: &str = "release-manifest.json";
pub const INSTALLED_LEDGER_NAME: &str = "installed_ledger.json";
/// Rotated root trust anchor for verifying official S&B release packages.
/// Conforms to IETF RFC 8032 (Ed25519) and NIST FIPS 180-4.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Compromised or spoofed release key allowing malicious binary distribution.
/// - CVE / CWE Mapping: CWE-347 (Improper Verification of Cryptographic Signature), CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: High (Score: 8/10) if private seed leaks; mitigated by local offline seed generation.
/// - Applied Mitigation: Hardcoded 32-byte Ed25519 public key strictly verified via ed25519_dalek::VerifyingKey::verify_strict before unpacking.
pub const RELEASE_PUBLIC_KEY: [u8; 32] = [
    0x3c, 0x98, 0xbe, 0xb9, 0xca, 0x90, 0xc6, 0x13, 0xf1, 0xbe, 0xdb, 0x16, 0x56, 0xf7, 0x03, 0x25,
    0x47, 0xa7, 0xf5, 0x4a, 0xfb, 0xc9, 0x32, 0xa1, 0x5c, 0x46, 0x05, 0x22, 0xb1, 0x65, 0x39, 0xaa,
];
const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024;
const MAX_DOWNLOAD_SIZE: u64 = 1024 * 1024 * 1024;
const RELEASE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const RELEASE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const RELEASE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseSource {
    RemoteUrl(String),
    LocalDir(PathBuf),
    Mesh {
        mesh_name: String,
        namespace: String,
    },
}

impl Default for ReleaseSource {
    fn default() -> Self {
        if let Ok(dir) = std::env::var("SB_RELEASE_DIR") {
            if !dir.trim().is_empty() {
                return Self::LocalDir(PathBuf::from(dir.trim()));
            }
        }
        if let Ok(url) = std::env::var("SB_RELEASE_URL") {
            if !url.trim().is_empty() {
                return Self::RemoteUrl(url.trim().to_string());
            }
        }
        Self::RemoteUrl(RELEASE_BASE_URL.to_string())
    }
}

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    InvalidVersion(String),
    InvalidTarget(String),
    InvalidManifest(String),
    SignatureVerification(String),
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    ArtifactNotFound {
        name: String,
        target: String,
    },
    BinaryNotFound(String),
    LedgerCorrupted(String),
    DowngradeBlocked {
        installed: String,
        attempted: String,
    },
    KeyError(String),
    DownloadFailed(String),
    PackagingError(String),
    Io(String),
    Custom(String),
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(msg) => write!(f, "Ungültige Release-Version: {msg}"),
            Self::InvalidTarget(msg) => write!(f, "Ungültiges Release-Target: {msg}"),
            Self::InvalidManifest(msg) => write!(f, "Ungültiges Release-Manifest: {msg}"),
            Self::SignatureVerification(msg) => write!(f, "Signaturprüfung fehlgeschlagen: {msg}"),
            Self::ChecksumMismatch {
                path,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "SHA-256 stimmt nicht überein für '{path}': erwartet {expected}, erhalten {actual}"
                )
            }
            Self::ArtifactNotFound { name, target } => {
                write!(f, "Release-Artefakt {name} nicht in {target} gefunden.")
            }
            Self::BinaryNotFound(name) => {
                write!(f, "Binärdatei '{name}' nicht im Release-Archiv gefunden")
            }
            Self::LedgerCorrupted(msg) => write!(f, "Installations-Ledger ist beschädigt: {msg}"),
            Self::DowngradeBlocked {
                installed,
                attempted,
            } => {
                write!(
                    f,
                    "Downgrade von {installed} auf {attempted} blockiert. Verwende --allow-downgrade."
                )
            }
            Self::KeyError(msg) => write!(f, "Schlüsselfehler: {msg}"),
            Self::DownloadFailed(msg) => write!(f, "Download fehlgeschlagen: {msg}"),
            Self::PackagingError(msg) => write!(f, "Paketierungsfehler: {msg}"),
            Self::Io(msg) => write!(f, "E/A-Fehler: {msg}"),
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ReleaseError {}

impl From<std::io::Error> for ReleaseError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<serde_json::Error> for ReleaseError {
    fn from(err: serde_json::Error) -> Self {
        Self::Custom(err.to_string())
    }
}

impl From<String> for ReleaseError {
    fn from(s: String) -> Self {
        Self::Custom(s)
    }
}

impl From<&str> for ReleaseError {
    fn from(s: &str) -> Self {
        Self::Custom(s.to_string())
    }
}

impl From<ReleaseError> for String {
    fn from(err: ReleaseError) -> Self {
        err.to_string()
    }
}

impl ReleaseError {
    pub fn contains(&self, pattern: &str) -> bool {
        self.to_string().contains(pattern)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub version: String,
    pub artifacts: Vec<ReleaseArtifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseArtifact {
    pub target: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstalledBinaryLedger {
    pub schema_version: u32,
    pub release_version: String,
    pub target: String,
    pub installed_at_unix: u64,
    pub binaries: BTreeMap<String, BinaryLedgerEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BinaryLedgerEntry {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct BinaryAuditReport {
    pub total_installed: usize,
    pub verified_count: usize,
    pub tampered: Vec<String>,
    pub unmanaged: Vec<String>,
    pub manifest_version: Option<String>,
    pub signature_valid: bool,
}

#[allow(dead_code)]
pub fn install_requested(requested: &[String], force: bool) -> Result<(), ReleaseError> {
    install_requested_with_source(requested, force, &ReleaseSource::default())
}

pub fn install_requested_with_source(
    requested: &[String],
    force: bool,
    source: &ReleaseSource,
) -> Result<(), ReleaseError> {
    install_requested_with_source_and_key(requested, force, source, &RELEASE_PUBLIC_KEY)
}

pub fn install_requested_with_source_and_key(
    requested: &[String],
    force: bool,
    source: &ReleaseSource,
    public_key: &[u8; 32],
) -> Result<(), ReleaseError> {
    install_requested_with_options_and_key(requested, force, false, source, public_key)
}

pub fn install_requested_with_options(
    requested: &[String],
    force: bool,
    allow_downgrade: bool,
    source: &ReleaseSource,
) -> Result<(), ReleaseError> {
    install_requested_with_options_and_key(
        requested,
        force,
        allow_downgrade,
        source,
        &RELEASE_PUBLIC_KEY,
    )
}

fn install_requested_with_options_and_key(
    requested: &[String],
    force: bool,
    allow_downgrade: bool,
    source: &ReleaseSource,
    public_key: &[u8; 32],
) -> Result<(), ReleaseError> {
    let target_dir = get_sb_dir().join("bin");
    install_requested_to_dir_with_options(
        requested,
        force,
        allow_downgrade,
        source,
        public_key,
        &target_dir,
    )
}

#[allow(dead_code)]
pub fn install_requested_to_dir(
    requested: &[String],
    force: bool,
    source: &ReleaseSource,
    public_key: &[u8; 32],
    target_dir: &Path,
) -> Result<(), ReleaseError> {
    install_requested_to_dir_with_options(requested, force, false, source, public_key, target_dir)
}

pub fn install_requested_to_dir_with_options(
    requested: &[String],
    force: bool,
    allow_downgrade: bool,
    source: &ReleaseSource,
    public_key: &[u8; 32],
    target_dir: &Path,
) -> Result<(), ReleaseError> {
    if requested.is_empty() {
        print_install_inventory_at(target_dir);
        return Ok(());
    }

    let (tools, include_cli) = resolve_tools(requested)?;
    let mut binaries: BTreeSet<String> = tools
        .iter()
        .filter_map(|tool| tool.binary_name.as_deref())
        .map(executable_name)
        .collect();
    if include_cli {
        binaries.insert(executable_name("sb"));
    }

    fs::create_dir_all(target_dir).map_err(|error| {
        format!(
            "Installationsverzeichnis {} kann nicht angelegt werden: {error}",
            target_dir.display()
        )
    })?;

    let temp = TempDir::create()?;

    let (manifest_bytes, signature_str) = match source {
        ReleaseSource::LocalDir(local_dir) => {
            let manifest_path = local_dir.join(RELEASE_MANIFEST_NAME);
            let manifest = fs::read(&manifest_path).map_err(|error| {
                format!(
                    "Release-Manifest kann nicht aus {} gelesen werden: {error}",
                    manifest_path.display()
                )
            })?;
            let signature_path = local_dir.join(format!("{RELEASE_MANIFEST_NAME}.ed25519"));
            let signature = fs::read_to_string(&signature_path).map_err(|error| {
                format!(
                    "Manifest-Signatur kann nicht aus {} gelesen werden: {error}",
                    signature_path.display()
                )
            })?;
            (manifest, signature)
        }
        ReleaseSource::RemoteUrl(base_url) => {
            let manifest_path = temp.path.join(RELEASE_MANIFEST_NAME);
            download(
                &format!("{base_url}/{RELEASE_MANIFEST_NAME}"),
                &manifest_path,
                4 * 1024 * 1024,
            )?;
            let manifest = fs::read(&manifest_path)
                .map_err(|error| format!("Release-Manifest kann nicht gelesen werden: {error}"))?;
            let signature_path = temp.path.join(format!("{RELEASE_MANIFEST_NAME}.ed25519"));
            download(
                &format!("{base_url}/{RELEASE_MANIFEST_NAME}.ed25519"),
                &signature_path,
                4096,
            )?;
            let signature = fs::read_to_string(&signature_path)
                .map_err(|error| format!("Manifest-Signatur kann nicht gelesen werden: {error}"))?;
            (manifest, signature)
        }
        ReleaseSource::Mesh {
            mesh_name,
            namespace,
        } => {
            let mesh_data_dir =
                sb_mesh::identity::default_data_dir().map_err(ReleaseError::Custom)?;
            let mesh_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&mesh_data_dir, mesh_name)
                .map_err(ReleaseError::Custom)?;
            let namespace_dir = mesh_paths.root.join("releases").join(namespace);
            if !namespace_dir.exists() {
                return Err(ReleaseError::ArtifactNotFound {
                    name: format!("Releases in Namespace '{namespace}'"),
                    target: format!("Mesh '{mesh_name}' unter {}", namespace_dir.display()),
                });
            }
            let mut versions: Vec<String> = Vec::new();
            if let Ok(entries) = fs::read_dir(&namespace_dir) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if validate_version(&name).is_ok() {
                            versions.push(name);
                        }
                    }
                }
            }
            versions.sort_by(|a, b| {
                compare_release_versions(b, a).unwrap_or(std::cmp::Ordering::Equal)
            });
            let latest_version =
                versions
                    .first()
                    .ok_or_else(|| ReleaseError::ArtifactNotFound {
                        name: "Release-Versionen".to_string(),
                        target: format!("Mesh '{mesh_name}' ({namespace})"),
                    })?;
            let release_dir = namespace_dir.join(latest_version);
            let manifest_path = release_dir.join(RELEASE_MANIFEST_NAME);
            let manifest = fs::read(&manifest_path).map_err(|error| {
                ReleaseError::Io(format!(
                    "Release-Manifest kann nicht aus {} gelesen werden: {error}",
                    manifest_path.display()
                ))
            })?;
            let signature_path = release_dir.join(format!("{RELEASE_MANIFEST_NAME}.ed25519"));
            let signature = fs::read_to_string(&signature_path).map_err(|error| {
                ReleaseError::Io(format!(
                    "Manifest-Signatur kann nicht aus {} gelesen werden: {error}",
                    signature_path.display()
                ))
            })?;
            (manifest, signature)
        }
    };

    verify_manifest_signature(&manifest_bytes, &signature_str, public_key)?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        ReleaseError::InvalidManifest(format!(
            "Signiertes Release-Manifest ist ungültiges JSON: {error}"
        ))
    })?;
    validate_manifest(&manifest)?;

    let sb_dir = target_dir.parent().unwrap_or(target_dir);
    let ledger_path = sb_dir.join(INSTALLED_LEDGER_NAME);
    let existing_ledger = read_installed_ledger(&ledger_path)?;
    // CVE-Threat: A replayed, correctly signed old manifest can roll back installed binaries.
    // Analysis: Signatures authenticate a release but do not establish freshness.
    // Hardening: Compare SemVer against the local ledger; only an explicit flag allows rollback.
    if !allow_downgrade {
        if let Some(ledger) = &existing_ledger {
            if compare_release_versions(&manifest.version, &ledger.release_version)?
                == std::cmp::Ordering::Less
            {
                return Err(ReleaseError::DowngradeBlocked {
                    installed: ledger.release_version.clone(),
                    attempted: manifest.version.clone(),
                });
            }
        }
    }

    let target = current_target();
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.target == target)
        .ok_or_else(|| ReleaseError::ArtifactNotFound {
            name: manifest.version.clone(),
            target: target.to_string(),
        })?;

    let archive_path = match source {
        ReleaseSource::LocalDir(local_dir) => {
            let path = local_dir.join(&artifact.path);
            if !path.is_file() {
                return Err(ReleaseError::ArtifactNotFound {
                    name: artifact.path.clone(),
                    target: local_dir.display().to_string(),
                });
            }
            path
        }
        ReleaseSource::RemoteUrl(base_url) => {
            let path = temp.path.join(&artifact.path);
            download(
                &format!("{base_url}/{}", artifact.path),
                &path,
                MAX_DOWNLOAD_SIZE,
            )?;
            path
        }
        ReleaseSource::Mesh {
            mesh_name,
            namespace,
        } => {
            let mesh_data_dir =
                sb_mesh::identity::default_data_dir().map_err(ReleaseError::Custom)?;
            let mesh_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&mesh_data_dir, mesh_name)
                .map_err(ReleaseError::Custom)?;
            let path = mesh_paths
                .root
                .join("releases")
                .join(namespace)
                .join(&manifest.version)
                .join(&artifact.path);
            if !path.is_file() {
                return Err(ReleaseError::ArtifactNotFound {
                    name: artifact.path.clone(),
                    target: format!("Mesh-Verzeichnis {}", path.display()),
                });
            }
            path
        }
    };

    let digest = sha256_file(&archive_path)?;
    if !constant_time_hex_eq(&digest, &artifact.sha256) {
        return Err(ReleaseError::ChecksumMismatch {
            path: artifact.path.clone(),
            expected: artifact.sha256.clone(),
            actual: digest,
        });
    }

    let files = read_selected_binaries(&archive_path, &binaries)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut ledger: InstalledBinaryLedger =
        existing_ledger.unwrap_or_else(|| InstalledBinaryLedger {
            schema_version: 1,
            release_version: manifest.version.clone(),
            target: target.to_string(),
            installed_at_unix: now,
            binaries: BTreeMap::new(),
        });
    ledger.release_version = manifest.version.clone();
    ledger.target = target.to_string();
    ledger.installed_at_unix = now;

    for (name, bytes) in &files {
        let destination = target_dir.join(name);
        if !force && destination.exists() {
            println!(
                "  i {} ist bereits installiert (verwende --force zum Ersetzen).",
                name
            );
            continue;
        }
        atomic_install(&destination, bytes)?;
        let digest = hex::encode(Sha256::digest(bytes));
        ledger.binaries.insert(
            name.clone(),
            BinaryLedgerEntry {
                sha256: digest,
                size_bytes: bytes.len() as u64,
            },
        );
        println!("  Installiert: {}", destination.display());
    }

    write_json_atomic(&ledger_path, &ledger)?;
    write_bytes_atomic(&sb_dir.join(RELEASE_MANIFEST_NAME), &manifest_bytes)?;
    write_bytes_atomic(
        &sb_dir.join(format!("{RELEASE_MANIFEST_NAME}.ed25519")),
        signature_str.as_bytes(),
    )?;

    println!(
        "S&B Release {} wurde verifiziert und installiert.",
        manifest.version
    );
    Ok(())
}

#[allow(dead_code)]
pub fn update_installed(requested: &[String]) -> Result<(), ReleaseError> {
    update_installed_with_source(requested, &ReleaseSource::default())
}

pub fn update_installed_with_source(
    requested: &[String],
    source: &ReleaseSource,
) -> Result<(), ReleaseError> {
    update_installed_with_source_and_key(requested, source, &RELEASE_PUBLIC_KEY)
}

pub fn update_installed_with_source_and_key(
    requested: &[String],
    source: &ReleaseSource,
    public_key: &[u8; 32],
) -> Result<(), ReleaseError> {
    update_installed_with_options_and_key(requested, false, source, public_key)
}

pub fn update_installed_with_options(
    requested: &[String],
    allow_downgrade: bool,
    source: &ReleaseSource,
) -> Result<(), ReleaseError> {
    update_installed_with_options_and_key(requested, allow_downgrade, source, &RELEASE_PUBLIC_KEY)
}

fn update_installed_with_options_and_key(
    requested: &[String],
    allow_downgrade: bool,
    source: &ReleaseSource,
    public_key: &[u8; 32],
) -> Result<(), ReleaseError> {
    let bin_dir = get_sb_dir().join("bin");
    update_installed_to_dir_with_options(requested, allow_downgrade, source, public_key, &bin_dir)
}

#[allow(dead_code)]
pub fn update_installed_to_dir(
    requested: &[String],
    source: &ReleaseSource,
    public_key: &[u8; 32],
    bin_dir: &Path,
) -> Result<(), ReleaseError> {
    update_installed_to_dir_with_options(requested, false, source, public_key, bin_dir)
}

pub fn update_installed_to_dir_with_options(
    requested: &[String],
    allow_downgrade: bool,
    source: &ReleaseSource,
    public_key: &[u8; 32],
    bin_dir: &Path,
) -> Result<(), ReleaseError> {
    let selected: Vec<String> = if requested.is_empty() {
        let mut installed = Vec::new();
        for tool in crate::meta::available_tools() {
            let path = bin_dir.join(executable_name(
                tool.binary_name.as_deref().unwrap_or_default(),
            ));
            if path.is_file() {
                installed.push(tool.id.to_string());
            }
        }
        if bin_dir.join(executable_name("sb")).is_file() {
            installed.push("sb".to_string());
        }
        installed
    } else {
        requested.to_vec()
    };

    if selected.is_empty() {
        return Err(ReleaseError::BinaryNotFound(format!(
            "Keine installierten S&B-Binaries unter {} gefunden.",
            bin_dir.display()
        )));
    }
    install_requested_to_dir_with_options(
        &selected,
        true,
        allow_downgrade,
        source,
        public_key,
        bin_dir,
    )
}

pub fn pack_release(
    version: &str,
    target: &str,
    input_dir: &Path,
    output_dir: &Path,
    format: &str,
) -> Result<PathBuf, ReleaseError> {
    validate_version(version)?;
    validate_target(target)?;
    if !input_dir.is_dir() {
        return Err(ReleaseError::PackagingError(format!(
            "Eingabeverzeichnis existiert nicht: {}",
            input_dir.display()
        )));
    }
    if !matches!(format, "tar.gz" | "zip") {
        return Err(ReleaseError::PackagingError(
            "Format muss 'tar.gz' oder 'zip' sein.".to_string(),
        ));
    }
    fs::create_dir_all(output_dir).map_err(|error| {
        ReleaseError::Io(format!(
            "Ausgabeverzeichnis kann nicht angelegt werden: {error}"
        ))
    })?;

    let mut binaries = Vec::new();
    for entry in fs::read_dir(input_dir)
        .map_err(|error| ReleaseError::Io(format!("Input kann nicht gelesen werden: {error}")))?
    {
        let entry = entry.map_err(|error| {
            ReleaseError::Io(format!("Input-Eintrag kann nicht gelesen werden: {error}"))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            ReleaseError::Io(format!("Dateityp kann nicht gelesen werden: {error}"))
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !file_type.is_file() || !is_release_binary_for_target(&name, target) {
            continue;
        }
        binaries.push((name, entry.path()));
    }
    binaries.sort_by(|left, right| left.0.cmp(&right.0));
    if binaries.is_empty() {
        return Err(ReleaseError::PackagingError(
            "Eingabeverzeichnis enthält keine regulären sb-Binaries.".to_string(),
        ));
    }

    let extension = if format == "zip" { "zip" } else { "tar.gz" };
    let archive_name = format!("sb-{version}-{target}.{extension}");
    let archive_path = output_dir.join(&archive_name);
    let temp_archive = output_dir.join(format!(".{archive_name}.tmp-{}", std::process::id()));
    let pack_result = if format == "zip" {
        pack_zip(&binaries, &temp_archive)
    } else {
        pack_tar_gz(&binaries, &temp_archive)
    };
    if let Err(error) = pack_result {
        let _ = fs::remove_file(&temp_archive);
        return Err(error);
    }
    replace_file(&temp_archive, &archive_path)?;

    let artifact = ReleaseArtifact {
        target: target.to_string(),
        path: archive_name,
        sha256: sha256_file(&archive_path)?,
    };
    let manifest_path = output_dir.join(RELEASE_MANIFEST_NAME);
    let mut manifest = if manifest_path.exists() {
        serde_json::from_slice::<ReleaseManifest>(&fs::read(&manifest_path).map_err(|error| {
            ReleaseError::Io(format!("Manifest kann nicht gelesen werden: {error}"))
        })?)
        .map_err(|error| {
            ReleaseError::InvalidManifest(format!("Bestehendes Manifest ist ungültig: {error}"))
        })?
    } else {
        ReleaseManifest {
            schema_version: 1,
            version: version.to_string(),
            artifacts: Vec::new(),
        }
    };
    if manifest.schema_version != 1 || manifest.version != version {
        return Err(ReleaseError::InvalidManifest(
            "Bestehendes Manifest hat ein anderes Schema oder eine andere Version.".to_string(),
        ));
    }
    manifest
        .artifacts
        .retain(|existing| existing.target != target);
    manifest.artifacts.push(artifact);
    manifest
        .artifacts
        .sort_by(|left, right| left.target.cmp(&right.target));
    validate_manifest(&manifest)?;
    write_json_atomic(&manifest_path, &manifest)?;
    let signature_path = PathBuf::from(format!("{}.ed25519", manifest_path.display()));
    match fs::remove_file(&signature_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ReleaseError::Io(format!(
                "Veraltete Manifest-Signatur kann nicht entfernt werden: {error}"
            )))
        }
    }
    println!("Archiv: {}", archive_path.display());
    println!("Manifest aktualisiert: {}", manifest_path.display());
    Ok(archive_path)
}

pub fn sign_release_manifest_with_seed(
    manifest_path: &Path,
    seed: &[u8; 32],
) -> Result<PathBuf, ReleaseError> {
    let manifest_bytes = fs::read(manifest_path).map_err(|error| {
        ReleaseError::Io(format!("Manifest kann nicht gelesen werden: {error}"))
    })?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        ReleaseError::InvalidManifest(format!("Manifest ist ungültiges JSON: {error}"))
    })?;
    validate_manifest(&manifest)?;
    let signing_key = SigningKey::from_bytes(seed);
    let signature = signing_key.sign(&manifest_bytes);
    let signature_path = PathBuf::from(format!("{}.ed25519", manifest_path.display()));
    write_bytes_atomic(
        &signature_path,
        hex::encode(signature.to_bytes()).as_bytes(),
    )?;
    Ok(signature_path)
}

pub fn sign_release_manifest(
    manifest_path: &Path,
    key_path: &Path,
) -> Result<PathBuf, ReleaseError> {
    let key_bytes = Zeroizing::new(fs::read(key_path).map_err(|error| {
        ReleaseError::Io(format!("Signing-Key kann nicht gelesen werden: {error}"))
    })?);
    let seed = Zeroizing::new(parse_signing_seed(&key_bytes)?);
    let signing_key = SigningKey::from_bytes(&seed);
    if signing_key.verifying_key().to_bytes() != RELEASE_PUBLIC_KEY {
        return Err(ReleaseError::KeyError(
            "Signing-Key passt nicht zum im Installer gepinnten Release-Key.".to_string(),
        ));
    }
    let signature_path = sign_release_manifest_with_seed(manifest_path, &seed)?;
    println!("Manifest signiert: {}", signature_path.display());
    Ok(signature_path)
}

pub fn pack_all_release(
    version: &str,
    target: Option<&str>,
    input_dir: &Path,
    output_dir: &Path,
    format: &str,
    key_file: Option<&Path>,
) -> Result<PathBuf, ReleaseError> {
    validate_version(version)?;
    let resolved_target = match target {
        Some(t) => t,
        None => current_target(),
    };
    validate_target(resolved_target)?;

    if !input_dir.is_dir() {
        return Err(ReleaseError::Io(format!(
            "Eingabeverzeichnis existiert nicht: {}",
            input_dir.display()
        )));
    }
    if !matches!(format, "tar.gz" | "zip") {
        return Err(ReleaseError::PackagingError(
            "Format muss 'tar.gz' oder 'zip' sein.".to_string(),
        ));
    }

    println!(
        "  {} {}\n",
        "► SUITE RELEASE PACKAGING".bold(),
        format!("[{version} // {resolved_target}]").bright_cyan()
    );

    let expected_tools: Vec<&str> = sb_core::catalog::products()
        .map_err(ReleaseError::Custom)?
        .iter()
        .filter(|product| product.installable)
        .filter(|product| {
            product
                .release_targets
                .iter()
                .any(|supported| supported == resolved_target)
        })
        .filter_map(|product| product.binary_name.as_deref())
        .collect();
    let expected_count = expected_tools.len();

    let mut found_binaries = Vec::new();
    let mut missing = Vec::new();

    for bin_base in expected_tools {
        let exe_name = executable_name(bin_base);
        let path = input_dir.join(&exe_name);
        if path.is_file() {
            found_binaries.push((exe_name, path));
        } else {
            missing.push(exe_name);
        }
    }

    if !missing.is_empty() {
        return Err(ReleaseError::PackagingError(format!(
            "Suite-Release für {resolved_target} ist unvollständig. Fehlende Binaries in {}: {}",
            input_dir.display(),
            missing.join(", ")
        )));
    }

    println!(
        "  Gefundene Binaries ({}/{}):",
        found_binaries.len(),
        expected_count
    );
    for (name, path) in &found_binaries {
        let size_mb = fs::metadata(path)
            .map(|m| m.len() as f64 / (1024.0 * 1024.0))
            .unwrap_or(0.0);
        println!("    ✓ {:<20} ({:.2} MB)", name.bright_green(), size_mb);
    }
    fs::create_dir_all(output_dir).map_err(|e| {
        ReleaseError::Io(format!(
            "Ausgabeverzeichnis kann nicht angelegt werden: {e}"
        ))
    })?;

    let extension = if format == "zip" { "zip" } else { "tar.gz" };
    let archive_name = format!("sb-{version}-{resolved_target}.{extension}");
    let archive_path = output_dir.join(&archive_name);
    let temp_archive = output_dir.join(format!(".{archive_name}.tmp-{}", std::process::id()));

    let pack_result = if format == "zip" {
        pack_zip(&found_binaries, &temp_archive)
    } else {
        pack_tar_gz(&found_binaries, &temp_archive)
    };
    if let Err(error) = pack_result {
        let _ = fs::remove_file(&temp_archive);
        return Err(error);
    }
    replace_file(&temp_archive, &archive_path)?;

    let artifact_hash = sha256_file(&archive_path)?;
    println!(
        "\n  Archiv erstellt: {} (SHA-256: {})",
        archive_path.display().to_string().bold(),
        artifact_hash[..16].bright_yellow()
    );

    let manifest_path = output_dir.join(RELEASE_MANIFEST_NAME);
    let mut manifest = if manifest_path.exists() {
        serde_json::from_slice::<ReleaseManifest>(
            &fs::read(&manifest_path).map_err(|e| ReleaseError::Io(e.to_string()))?,
        )
        .unwrap_or_else(|_| ReleaseManifest {
            schema_version: 1,
            version: version.to_string(),
            artifacts: Vec::new(),
        })
    } else {
        ReleaseManifest {
            schema_version: 1,
            version: version.to_string(),
            artifacts: Vec::new(),
        }
    };

    manifest.version = version.to_string();
    manifest.artifacts.retain(|a| a.target != resolved_target);
    manifest.artifacts.push(ReleaseArtifact {
        target: resolved_target.to_string(),
        path: archive_name,
        sha256: artifact_hash,
    });
    manifest.artifacts.sort_by(|a, b| a.target.cmp(&b.target));

    validate_manifest(&manifest)?;
    write_json_atomic(&manifest_path, &manifest)?;
    println!(
        "  Release-Manifest aktualisiert: {}",
        manifest_path.display()
    );

    let signature_path = PathBuf::from(format!("{}.ed25519", manifest_path.display()));
    let _ = fs::remove_file(&signature_path);

    let key_path = key_file
        .map(PathBuf::from)
        .or_else(|| std::env::var("SB_RELEASE_KEY").ok().map(PathBuf::from));

    if let Some(ref k) = key_path {
        let sig = sign_release_manifest(&manifest_path, k)?;
        println!(
            "  {} Manifest erfolgreich Ed25519-signiert: {}",
            "✓".bright_green().bold(),
            sig.display()
        );
    } else {
        println!(
            "  {} Kein Signing-Key angegeben. Manifest ist noch unsigniert (Signieren mit 'sb release sign --key-file <key>').",
            "i".bright_yellow()
        );
    }

    Ok(archive_path)
}

pub fn publish_release_to_mesh(
    manifest_path: &Path,
    key_file: Option<&Path>,
    mesh_name: &str,
    namespace: &str,
) -> Result<PathBuf, ReleaseError> {
    publish_release_to_mesh_with_key(
        manifest_path,
        key_file,
        mesh_name,
        namespace,
        &RELEASE_PUBLIC_KEY,
    )
}

pub fn publish_release_to_mesh_with_key(
    manifest_path: &Path,
    key_file: Option<&Path>,
    mesh_name: &str,
    namespace: &str,
    expected_public_key: &[u8; 32],
) -> Result<PathBuf, ReleaseError> {
    if !manifest_path.exists() {
        return Err(ReleaseError::InvalidManifest(format!(
            "Manifest-Datei existiert nicht: {}",
            manifest_path.display()
        )));
    }
    let manifest_bytes = fs::read(manifest_path)
        .map_err(|e| ReleaseError::Io(format!("Manifest kann nicht gelesen werden: {e}")))?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ReleaseError::InvalidManifest(format!("Ungültiges Release-Manifest: {e}")))?;
    validate_manifest(&manifest)?;

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let sig_path = PathBuf::from(format!("{}.ed25519", manifest_path.display()));

    // 1. Wenn key_file übergeben, signieren bzw. prüfen
    let sig_str = if let Some(key_p) = key_file {
        let key_bytes = Zeroizing::new(fs::read(key_p).map_err(|error| {
            ReleaseError::KeyError(format!("Signing-Key kann nicht gelesen werden: {error}"))
        })?);
        let seed = Zeroizing::new(parse_signing_seed(&key_bytes)?);
        let signing_key = SigningKey::from_bytes(&seed);
        if &signing_key.verifying_key().to_bytes() != expected_public_key {
            return Err(ReleaseError::KeyError(
                "Signing-Key passt nicht zum erwarteten Release-Key.".to_string(),
            ));
        }
        let sig_p = sign_release_manifest_with_seed(manifest_path, &seed)?;
        fs::read_to_string(&sig_p).map_err(|e| {
            ReleaseError::Io(format!("Signaturdatei kann nicht gelesen werden: {e}"))
        })?
    } else {
        if !sig_path.exists() {
            return Err(ReleaseError::SignatureVerification(format!(
                "Manifest ist nicht signiert ({}.ed25519 fehlt). Bitte --key-file angeben.",
                manifest_path.display()
            )));
        }
        fs::read_to_string(&sig_path).map_err(|e| {
            ReleaseError::Io(format!("Signaturdatei kann nicht gelesen werden: {e}"))
        })?
    };

    // 2. Unabhängige Signaturprüfung vor Veröffentlichung (Fail-Closed)
    verify_manifest_signature(&manifest_bytes, &sig_str, expected_public_key)?;

    // 3. Vollständigkeitsprüfung: Alle Artefakte müssen existieren, Größenlimits einhalten und SHA-256 stimmen
    if manifest.artifacts.is_empty() {
        return Err(ReleaseError::InvalidManifest(
            "Manifest enthält keine Artefakte zum Publizieren".to_string(),
        ));
    }
    for artifact in &manifest.artifacts {
        let artifact_path = manifest_dir.join(&artifact.path);
        if !artifact_path.exists() {
            return Err(ReleaseError::PackagingError(format!(
                "Unvollständiges Release-Paket: Artefakt '{}' nicht gefunden unter {}",
                artifact.path,
                artifact_path.display()
            )));
        }
        let data = fs::read(&artifact_path).map_err(|e| {
            ReleaseError::Io(format!(
                "Artefakt '{}' kann nicht gelesen werden: {e}",
                artifact.path
            ))
        })?;
        if data.len() as u64 > MAX_DOWNLOAD_SIZE {
            return Err(ReleaseError::PackagingError(format!(
                "Artefakt '{}' überschreitet maximale Größe",
                artifact.path
            )));
        }
        let digest = hex::encode(Sha256::digest(&data));
        if digest != artifact.sha256 {
            return Err(ReleaseError::ChecksumMismatch {
                path: artifact.path.clone(),
                expected: artifact.sha256.clone(),
                actual: digest,
            });
        }
    }

    // 4. Mesh-Zielverzeichnis auflösen
    let mesh_data_dir = sb_mesh::identity::default_data_dir().map_err(ReleaseError::Custom)?;
    let mesh_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&mesh_data_dir, mesh_name)
        .map_err(ReleaseError::Custom)?;
    let target_release_dir = mesh_paths
        .root
        .join("releases")
        .join(namespace)
        .join(&manifest.version);

    // 5. Idempotenz- / Divergenzprüfung
    if target_release_dir.exists() {
        let existing_manifest_path = target_release_dir.join(RELEASE_MANIFEST_NAME);
        if existing_manifest_path.exists() {
            if let Ok(existing_bytes) = fs::read(&existing_manifest_path) {
                if existing_bytes == manifest_bytes {
                    println!(
                        "  {} Release v{} ist bereits identisch in Mesh '{}' ({}) publiziert (idempotent).",
                        "✓".bright_green().bold(),
                        manifest.version,
                        mesh_name,
                        namespace
                    );
                    return Ok(target_release_dir);
                } else {
                    return Err(ReleaseError::Custom(format!(
                        "Release v{} existiert bereits in Mesh '{}', weicht jedoch im Inhalt ab! Erneutes Überschreiben abgewiesen.",
                        manifest.version, mesh_name
                    )));
                }
            }
        }
    }

    // 6. Schreiben in Mesh-Verzeichnis
    fs::create_dir_all(&target_release_dir).map_err(|e| {
        ReleaseError::Io(format!(
            "Konnte Release-Verzeichnis in Mesh nicht anlegen: {e}"
        ))
    })?;

    write_bytes_atomic(
        &target_release_dir.join(RELEASE_MANIFEST_NAME),
        &manifest_bytes,
    )?;
    write_bytes_atomic(
        &target_release_dir.join(format!("{RELEASE_MANIFEST_NAME}.ed25519")),
        sig_str.trim().as_bytes(),
    )?;

    for artifact in &manifest.artifacts {
        let src = manifest_dir.join(&artifact.path);
        let dst = target_release_dir.join(&artifact.path);
        fs::copy(&src, &dst).map_err(|e| {
            ReleaseError::Io(format!(
                "Konnte Artefakt '{}' nicht in Mesh kopieren: {e}",
                artifact.path
            ))
        })?;
    }

    // 7. Im MeshObjectCatalog registrieren
    let catalog_store =
        sb_mesh::object_store::MeshObjectCatalogStore::new(mesh_paths.root.join("catalog.json"));
    let mut catalog = catalog_store
        .load()
        .unwrap_or_else(|_| sb_mesh::objects::MeshObjectCatalog::new(mesh_name).unwrap());
    if let Ok(obj_id) =
        sb_mesh::objects::MeshObjectId::new(format!("release:{}:{}", namespace, manifest.version))
    {
        if let Ok(owner) = sb_mesh::objects::PrincipalId::user("release-publisher") {
            let mut obj = sb_mesh::objects::MeshObject::new(
                obj_id,
                sb_mesh::objects::MeshObjectKind::Container(
                    sb_mesh::objects::ContainerKind::Collection,
                ),
                format!("Release {} ({})", manifest.version, namespace),
                None,
                owner,
            );
            obj.acl.inherit_from_parent = false;
            let _ = catalog.insert_object(obj);
            let _ = catalog_store.save(&catalog);
        }
    }

    println!(
        "  {} Release v{} erfolgreich in Mesh '{}' (Namespace: '{}') publiziert.",
        "✓".bright_green().bold(),
        manifest.version,
        mesh_name,
        namespace
    );
    println!("  Verzeichnis: {}", target_release_dir.display());
    Ok(target_release_dir)
}

pub fn fetch_release_from_mesh(
    version: &str,
    target: Option<&str>,
    mesh_name: &str,
    namespace: &str,
    out_dir: &Path,
) -> Result<PathBuf, ReleaseError> {
    fetch_release_from_mesh_with_key(
        version,
        target,
        mesh_name,
        namespace,
        out_dir,
        &RELEASE_PUBLIC_KEY,
    )
}

pub fn fetch_release_from_mesh_with_key(
    version: &str,
    target: Option<&str>,
    mesh_name: &str,
    namespace: &str,
    out_dir: &Path,
    expected_public_key: &[u8; 32],
) -> Result<PathBuf, ReleaseError> {
    validate_version(version)?;
    let resolved_target = match target {
        Some(t) => t,
        None => current_target(),
    };
    validate_target(resolved_target)?;

    let mesh_data_dir = sb_mesh::identity::default_data_dir().map_err(ReleaseError::Custom)?;
    let mesh_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&mesh_data_dir, mesh_name)
        .map_err(ReleaseError::Custom)?;
    let release_dir = mesh_paths
        .root
        .join("releases")
        .join(namespace)
        .join(version);

    if !release_dir.exists() {
        return Err(ReleaseError::ArtifactNotFound {
            name: format!("v{version}"),
            target: format!("Mesh '{mesh_name}' (Namespace '{namespace}')"),
        });
    }

    let manifest_path = release_dir.join(RELEASE_MANIFEST_NAME);
    let sig_path = release_dir.join(format!("{RELEASE_MANIFEST_NAME}.ed25519"));

    if !manifest_path.exists() || !sig_path.exists() {
        return Err(ReleaseError::PackagingError(format!(
            "Release v{} im Mesh ist unvollständig (Manifest oder Signatur fehlt)",
            version
        )));
    }

    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|e| ReleaseError::Io(format!("Manifest kann nicht gelesen werden: {e}")))?;
    let sig_str = fs::read_to_string(&sig_path)
        .map_err(|e| ReleaseError::Io(format!("Signatur kann nicht gelesen werden: {e}")))?;

    // Ed25519-Signaturprüfung mit Trust Anchor (gepinnter Release-Key)
    verify_manifest_signature(&manifest_bytes, &sig_str, expected_public_key)?;

    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ReleaseError::InvalidManifest(format!("Ungültiges Manifest: {e}")))?;
    validate_manifest(&manifest)?;

    let artifact = manifest
        .artifacts
        .iter()
        .find(|a| a.target == resolved_target)
        .ok_or_else(|| ReleaseError::ArtifactNotFound {
            name: format!("Release v{version}"),
            target: format!("Plattform '{resolved_target}'"),
        })?;

    let artifact_src = release_dir.join(&artifact.path);
    if !artifact_src.exists() {
        return Err(ReleaseError::PackagingError(format!(
            "Artefakt-Datei '{}' fehlt im Mesh-Release-Verzeichnis",
            artifact.path
        )));
    }

    let artifact_bytes = fs::read(&artifact_src)
        .map_err(|e| ReleaseError::Io(format!("Konnte Artefakt nicht lesen: {e}")))?;
    if artifact_bytes.len() as u64 > MAX_DOWNLOAD_SIZE {
        return Err(ReleaseError::PackagingError(format!(
            "Artefakt '{}' überschreitet maximale Größe",
            artifact.path
        )));
    }
    let digest = hex::encode(Sha256::digest(&artifact_bytes));
    if digest != artifact.sha256 {
        return Err(ReleaseError::ChecksumMismatch {
            path: artifact.path.clone(),
            expected: artifact.sha256.clone(),
            actual: digest,
        });
    }

    fs::create_dir_all(out_dir).map_err(|e| {
        ReleaseError::Io(format!(
            "Ausgabeverzeichnis kann nicht erstellt werden: {e}"
        ))
    })?;
    let out_manifest = out_dir.join(RELEASE_MANIFEST_NAME);
    let out_sig = out_dir.join(format!("{RELEASE_MANIFEST_NAME}.ed25519"));
    let out_artifact = out_dir.join(&artifact.path);

    write_bytes_atomic(&out_manifest, &manifest_bytes)?;
    write_bytes_atomic(&out_sig, sig_str.trim().as_bytes())?;
    write_bytes_atomic(&out_artifact, &artifact_bytes)?;

    println!(
        "  {} Release v{} für '{}' aus Mesh '{}' bezogen und verifiziert.",
        "✓".bright_green().bold(),
        version,
        resolved_target,
        mesh_name
    );
    println!("  Gespeichert in: {}", out_dir.display());
    Ok(out_artifact)
}

pub fn audit_installed_binaries(bin_dir: &Path) -> BinaryAuditReport {
    audit_installed_binaries_with_key(bin_dir, &RELEASE_PUBLIC_KEY)
}

pub fn audit_installed_binaries_with_key(
    bin_dir: &Path,
    public_key: &[u8; 32],
) -> BinaryAuditReport {
    let mut report = BinaryAuditReport::default();
    let sb_dir = bin_dir.parent().unwrap_or(bin_dir);
    let manifest_path = sb_dir.join(RELEASE_MANIFEST_NAME);
    let sig_path = sb_dir.join(format!("{RELEASE_MANIFEST_NAME}.ed25519"));
    let ledger_path = sb_dir.join(INSTALLED_LEDGER_NAME);

    if manifest_path.exists() && sig_path.exists() {
        if let (Ok(manifest_bytes), Ok(sig_str)) =
            (fs::read(&manifest_path), fs::read_to_string(&sig_path))
        {
            if verify_manifest_signature(&manifest_bytes, sig_str.trim(), public_key).is_ok() {
                report.signature_valid = true;
                if let Ok(manifest) = serde_json::from_slice::<ReleaseManifest>(&manifest_bytes) {
                    report.manifest_version = Some(manifest.version);
                }
            }
        }
    }

    let ledger: Option<InstalledBinaryLedger> = if ledger_path.exists() {
        fs::read(&ledger_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    } else {
        None
    };

    if let Ok(entries) = fs::read_dir(bin_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if !is_release_binary(&name) {
                continue;
            }
            report.total_installed += 1;
            let current_hash = match sha256_file(&path) {
                Ok(h) => h,
                Err(_) => {
                    report.tampered.push(name);
                    continue;
                }
            };

            if let Some(ref l) = ledger {
                if let Some(expected) = l.binaries.get(&name) {
                    if constant_time_hex_eq(&current_hash, &expected.sha256) {
                        report.verified_count += 1;
                    } else {
                        report.tampered.push(name);
                    }
                } else {
                    report.unmanaged.push(name);
                }
            } else {
                report.unmanaged.push(name);
            }
        }
    }

    report
}

pub fn verify_release_integrity(
    bin_dir: Option<&Path>,
    _manifest_path: Option<&Path>,
) -> Result<(), ReleaseError> {
    let default_bin = get_sb_dir().join("bin");
    let bin_dir = bin_dir.unwrap_or(&default_bin);
    println!(
        "  {} {}\n",
        "► S&B BINARY INTEGRITÄTS-AUDIT".bold(),
        "[VERIFY]".bright_cyan()
    );

    let report = audit_installed_binaries(bin_dir);
    println!("  Installationsverzeichnis: {}", bin_dir.display());
    if let Some(ref ver) = report.manifest_version {
        let sig_status = if report.signature_valid {
            "GÜLTIG (Ed25519 Pinning)".bright_green().bold()
        } else {
            "UNGÜLTIG ODER FEHLT".bright_red().bold()
        };
        println!(
            "  Release-Version:          {} (Signatur: {})",
            ver.bright_yellow(),
            sig_status
        );
    } else {
        println!(
            "  Release-Manifest:         {}",
            "Kein signiertes Release-Manifest in ~/.sb gefunden".bright_black()
        );
    }

    println!("\n  {:<24} {:<24} {:<16}", "BINARY", "STATUS", "SHA-256");
    println!("  {}", "─".repeat(64).bright_black());

    let sb_dir = bin_dir.parent().unwrap_or(bin_dir);
    let ledger_path = sb_dir.join(INSTALLED_LEDGER_NAME);
    let ledger: Option<InstalledBinaryLedger> = if ledger_path.exists() {
        fs::read(&ledger_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    } else {
        None
    };

    if let Ok(entries) = fs::read_dir(bin_dir) {
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if !is_release_binary(&name) {
                continue;
            }
            let hash = sha256_file(&path).unwrap_or_else(|_| "err".to_string());
            let short_hash = if hash.len() >= 12 { &hash[..12] } else { &hash };
            if let Some(ref l) = ledger {
                if let Some(expected) = l.binaries.get(&name) {
                    if constant_time_hex_eq(&hash, &expected.sha256) {
                        println!(
                            "  {:<24} {:<24} {}",
                            name.bold(),
                            "✓ VERIFIZIERT".bright_green().bold(),
                            short_hash.bright_black()
                        );
                    } else {
                        println!(
                            "  {:<24} {:<24} {}",
                            name.bold(),
                            "✗ MANIPULIERT".bright_red().bold(),
                            short_hash.bright_red()
                        );
                    }
                    continue;
                }
            }
            println!(
                "  {:<24} {:<24} {}",
                name.bold(),
                "i LOKAL / UNVERIF".bright_yellow(),
                short_hash.bright_black()
            );
        }
    }

    println!();
    if !report.tampered.is_empty() {
        return Err(ReleaseError::ChecksumMismatch {
            path: report.tampered.join(", "),
            expected: "valid signature/ledger hash".to_string(),
            actual: "tampered".to_string(),
        });
    }
    if report.verified_count > 0 && report.signature_valid {
        println!(
            "  {} Alle {} geprüften Binaries sind kryptographisch intakt und unverändert.",
            "✓".bright_green().bold(),
            report.verified_count
        );
    } else if report.total_installed > 0 {
        println!(
            "  {} {} Binaries gefunden (lokale Entwickler-Builds ohne signiertes Release-Ledger).",
            "i".bright_yellow(),
            report.total_installed
        );
    } else {
        println!(
            "  Keine installierten Binaries in {} gefunden.",
            bin_dir.display()
        );
    }
    Ok(())
}

pub fn generate_release_keypair(output_path: &Path) -> Result<(), ReleaseError> {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();

    let hex_seed = hex::encode(seed);
    if let Some(parent) = output_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .map_err(|e| ReleaseError::Io(format!("Schlüsseldatei kann nicht erstellt werden: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(output_path, fs::Permissions::from_mode(0o600));
    }

    file.write_all(hex_seed.as_bytes())
        .map_err(|e| ReleaseError::Io(format!("Schlüssel kann nicht geschrieben werden: {e}")))?;
    drop(file);

    println!(
        "  {} {}\n",
        "► NEUES ED25519 RELEASE-SCHLÜSSELPAAR ERZEUGT".bold(),
        "[KEYGEN]".bright_green()
    );
    println!(
        "  Privater Seed gespeichert in: {}",
        output_path.display().to_string().bold()
    );
    println!(
        "  Public Key (Hex):             {}",
        hex::encode(pub_bytes).bright_yellow()
    );
    print!("  Public Key (Rust Array):      [");
    for (i, b) in pub_bytes.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{:02x}", b);
    }
    println!("];\n");
    println!(
        "  {} Bewahre die Schlüsseldatei sicher auf und teile niemals den privaten Seed!",
        "ACHTUNG:".bright_red().bold()
    );
    Ok(())
}

pub fn verify_release_key(key_path: &Path) -> Result<(), ReleaseError> {
    let key_bytes = Zeroizing::new(fs::read(key_path).map_err(|error| {
        ReleaseError::KeyError(format!("Schlüsseldatei kann nicht gelesen werden: {error}"))
    })?);
    let seed = Zeroizing::new(parse_signing_seed(&key_bytes)?);
    let signing_key = SigningKey::from_bytes(&seed);
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let is_pinned = pub_bytes == RELEASE_PUBLIC_KEY;

    println!(
        "  {} {}\n",
        "► RELEASE-SCHLÜSSEL VALIDIERUNG".bold(),
        "[KEY-AUDIT]".bright_cyan()
    );
    println!("  Schlüsseldatei:               {}", key_path.display());
    println!("  Format:                       Gültiger Ed25519 Private Seed");
    println!(
        "  Public Key (Hex):             {}",
        hex::encode(pub_bytes).bright_yellow()
    );
    print!("  Public Key (Rust Array):      [");
    for (i, b) in pub_bytes.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{:02x}", b);
    }
    println!("];\n");

    if is_pinned {
        println!(
            "  Status:                       {}",
            "VERIFIZIERT — Entspricht dem im Client gepinnten Produktions-Schlüssel"
                .bright_green()
                .bold()
        );
    } else {
        println!(
            "  Status:                       {}",
            "GÜLTIG — Weicht vom gepinnten Produktions-Schlüssel ab (neuer Rotations- oder Testschlüssel)".bright_yellow().bold()
        );
    }
    Ok(())
}

pub fn verify_manifest_signature(
    manifest: &[u8],
    signature_hex: &str,
    public_key: &[u8; 32],
) -> Result<(), ReleaseError> {
    use ed25519_dalek::VerifyingKey;

    let encoded = signature_hex.trim();
    if encoded.len() != 128 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReleaseError::SignatureVerification(
            "Ed25519-Signatur muss aus genau 64 Bytes Hex bestehen.".to_string(),
        ));
    }
    let key = VerifyingKey::from_bytes(public_key).map_err(|error| {
        ReleaseError::SignatureVerification(format!("Gepinnter Release-Key ist ungültig: {error}"))
    })?;
    let bytes = hex::decode(encoded).map_err(|error| {
        ReleaseError::SignatureVerification(format!("Signatur ist ungültiges Hex: {error}"))
    })?;
    let signature = ed25519_dalek::Signature::from_slice(&bytes).map_err(|error| {
        ReleaseError::SignatureVerification(format!("Signatur hat ungültige Länge: {error}"))
    })?;
    key.verify_strict(manifest, &signature).map_err(|_| {
        ReleaseError::SignatureVerification(
            "Ed25519-Signaturprüfung des Release-Manifests fehlgeschlagen.".to_string(),
        )
    })
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    if manifest.schema_version != 1 {
        return Err(ReleaseError::InvalidManifest(format!(
            "Nicht unterstützte Manifest-Version: {}",
            manifest.schema_version
        )));
    }
    validate_version(&manifest.version)?;
    if manifest.artifacts.is_empty() {
        return Err(ReleaseError::InvalidManifest(
            "Release-Manifest enthält keine Artefakte.".to_string(),
        ));
    }
    let mut targets = BTreeSet::new();
    for artifact in &manifest.artifacts {
        validate_target(&artifact.target)?;
        if !targets.insert(&artifact.target) {
            return Err(ReleaseError::InvalidManifest(format!(
                "Doppeltes Release-Ziel: {}",
                artifact.target
            )));
        }
        let path = Path::new(&artifact.path);
        if path.file_name().and_then(|name| name.to_str()) != Some(artifact.path.as_str())
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || !(artifact.path.ends_with(".zip") || artifact.path.ends_with(".tar.gz"))
            || !artifact
                .path
                .starts_with(&format!("sb-{}-", manifest.version))
            || !artifact.path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+')
            })
        {
            return Err(ReleaseError::InvalidManifest(format!(
                "Unsicherer oder ungültiger Artefaktpfad: {}",
                artifact.path
            )));
        }
        if artifact.sha256.len() != 64
            || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ReleaseError::InvalidManifest(format!(
                "Ungültiger SHA-256-Hash für {}",
                artifact.path
            )));
        }
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), ReleaseError> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(ReleaseError::InvalidVersion(version.to_string()));
    }
    Ok(())
}

fn read_installed_ledger(path: &Path) -> Result<Option<InstalledBinaryLedger>, ReleaseError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ReleaseError::Io(format!(
                "Installations-Ledger {} kann nicht gelesen werden: {error}",
                path.display()
            )))
        }
    };
    let ledger: InstalledBinaryLedger = serde_json::from_slice(&bytes).map_err(|error| {
        ReleaseError::LedgerCorrupted(format!(
            "Installations-Ledger {} ist ungültig; Update aus Sicherheitsgründen abgebrochen: {error}",
            path.display()
        ))
    })?;
    if ledger.schema_version != 1 {
        return Err(ReleaseError::LedgerCorrupted(format!(
            "Nicht unterstützte Installations-Ledger-Version: {}",
            ledger.schema_version
        )));
    }
    Ok(Some(ledger))
}

fn compare_release_versions(
    candidate: &str,
    installed: &str,
) -> Result<std::cmp::Ordering, ReleaseError> {
    let parse = |version: &str| {
        semver::Version::parse(version.strip_prefix('v').unwrap_or(version)).map_err(|error| {
            ReleaseError::InvalidVersion(format!(
                "Release-Version {version} ist kein vergleichbares SemVer: {error}"
            ))
        })
    };
    let candidate = parse(candidate)?;
    let installed = parse(installed)?;
    Ok(candidate.cmp(&installed))
}

fn validate_target(target: &str) -> Result<(), ReleaseError> {
    if target.is_empty()
        || target.len() > 100
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ReleaseError::InvalidTarget(target.to_string()));
    }
    Ok(())
}

fn current_target() -> &'static str {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-musl"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else {
        "unsupported"
    }
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn is_release_binary(name: &str) -> bool {
    let name_without_extension = name.strip_suffix(".exe").unwrap_or(name);
    sb_core::catalog::products()
        .expect("embedded product inventory must be valid")
        .iter()
        .any(|product| {
            product
                .binary_name
                .as_deref()
                .is_some_and(|binary| binary == name_without_extension)
        })
}

fn is_release_binary_for_target(name: &str, target: &str) -> bool {
    let is_windows = target.contains("windows");
    sb_core::catalog::products()
        .expect("embedded product inventory must be valid")
        .iter()
        .any(|product| {
            product.binary_name.as_deref().is_some_and(|binary| {
                if is_windows {
                    name == format!("{binary}.exe")
                } else {
                    name == binary
                }
            }) && product
                .release_targets
                .iter()
                .any(|supported| supported == target)
        })
}

fn read_selected_binaries(
    archive_path: &Path,
    requested: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    // CVE-Threat: Crafted archive paths could overwrite files outside ~/.sb/bin.
    // Hardening: Read only exact requested root-level regular-file names; never extract archive paths.
    let mut files = BTreeMap::new();
    if archive_path.extension().and_then(|value| value.to_str()) == Some("zip") {
        let archive_file = File::open(archive_path).map_err(|error| {
            ReleaseError::Io(format!("ZIP-Artefakt kann nicht geöffnet werden: {error}"))
        })?;
        let mut archive = zip::ZipArchive::new(archive_file).map_err(|error| {
            ReleaseError::PackagingError(format!("ZIP-Artefakt ist ungültig: {error}"))
        })?;
        for index in 0..archive.len() {
            let entry = archive.by_index(index).map_err(|error| {
                ReleaseError::PackagingError(format!(
                    "ZIP-Eintrag kann nicht gelesen werden: {error}"
                ))
            })?;
            let name = entry.name().to_string();
            if !requested.contains(&name) {
                continue;
            }
            if entry.is_dir() || entry.size() > MAX_BINARY_SIZE || files.contains_key(&name) {
                return Err(ReleaseError::PackagingError(format!(
                    "Ungültiger oder doppelter Binärdatei-Eintrag: {name}"
                )));
            }
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry
                .take(MAX_BINARY_SIZE + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    ReleaseError::Io(format!(
                        "ZIP-Binärdatei {name} kann nicht gelesen werden: {error}"
                    ))
                })?;
            if bytes.len() as u64 > MAX_BINARY_SIZE {
                return Err(ReleaseError::PackagingError(format!(
                    "Binärdatei {name} überschreitet das Größenlimit."
                )));
            }
            files.insert(name, bytes);
        }
    } else {
        let input = File::open(archive_path).map_err(|error| {
            ReleaseError::Io(format!("TAR-Artefakt kann nicht geöffnet werden: {error}"))
        })?;
        let decoder = GzDecoder::new(input);
        let mut archive = tar::Archive::new(decoder);
        let entries = archive.entries().map_err(|error| {
            ReleaseError::PackagingError(format!("TAR-Artefakt ist ungültig: {error}"))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                ReleaseError::PackagingError(format!("TAR-Eintrag ist ungültig: {error}"))
            })?;
            let entry_type = entry.header().entry_type();
            if !entry_type.is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(|error| {
                    ReleaseError::PackagingError(format!("TAR-Pfad ist ungültig: {error}"))
                })?
                .into_owned();
            let Some(name) = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            if path.components().count() != 1 || !requested.contains(&name) {
                continue;
            }
            let size = entry.header().size().map_err(|error| {
                ReleaseError::PackagingError(format!("TAR-Dateigröße ist ungültig: {error}"))
            })?;
            if size > MAX_BINARY_SIZE || files.contains_key(&name) {
                return Err(ReleaseError::PackagingError(format!(
                    "Ungültiger oder doppelter Binärdatei-Eintrag: {name}"
                )));
            }
            let mut bytes = Vec::with_capacity(size as usize);
            entry
                .take(MAX_BINARY_SIZE + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    ReleaseError::Io(format!(
                        "TAR-Binärdatei {name} kann nicht gelesen werden: {error}"
                    ))
                })?;
            if bytes.len() as u64 > MAX_BINARY_SIZE {
                return Err(ReleaseError::PackagingError(format!(
                    "Binärdatei {name} überschreitet das Größenlimit."
                )));
            }
            files.insert(name, bytes);
        }
    }
    let missing: Vec<_> = requested
        .difference(&files.keys().cloned().collect())
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(ReleaseError::BinaryNotFound(missing.join(", ")));
    }
    Ok(files)
}

fn pack_tar_gz(binaries: &[(String, PathBuf)], destination: &Path) -> Result<(), ReleaseError> {
    let output = File::create(destination)
        .map_err(|error| ReleaseError::Io(format!("Archiv kann nicht angelegt werden: {error}")))?;
    let encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (name, path) in binaries {
        archive.append_path_with_name(path, name).map_err(|error| {
            ReleaseError::PackagingError(format!(
                "{name} kann nicht ins Archiv geschrieben werden: {error}"
            ))
        })?;
    }
    let encoder = archive.into_inner().map_err(|error| {
        ReleaseError::PackagingError(format!("TAR kann nicht finalisiert werden: {error}"))
    })?;
    encoder.finish().map_err(|error| {
        ReleaseError::PackagingError(format!("GZIP kann nicht finalisiert werden: {error}"))
    })?;
    Ok(())
}

fn pack_zip(binaries: &[(String, PathBuf)], destination: &Path) -> Result<(), ReleaseError> {
    let output = File::create(destination)
        .map_err(|error| ReleaseError::Io(format!("Archiv kann nicht angelegt werden: {error}")))?;
    let mut archive = zip::ZipWriter::new(output);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, path) in binaries {
        archive.start_file(name, options).map_err(|error| {
            ReleaseError::PackagingError(format!(
                "ZIP-Eintrag {name} kann nicht angelegt werden: {error}"
            ))
        })?;
        let mut file = File::open(path).map_err(|error| {
            ReleaseError::Io(format!("{name} kann nicht geöffnet werden: {error}"))
        })?;
        std::io::copy(&mut file, &mut archive).map_err(|error| {
            ReleaseError::PackagingError(format!(
                "{name} kann nicht ins ZIP geschrieben werden: {error}"
            ))
        })?;
    }
    archive.finish().map_err(|error| {
        ReleaseError::PackagingError(format!("ZIP kann nicht finalisiert werden: {error}"))
    })?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, ReleaseError> {
    let mut file = File::open(path).map_err(|error| {
        ReleaseError::Io(format!("Artefakt kann nicht geöffnet werden: {error}"))
    })?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash).map_err(|error| {
        ReleaseError::Io(format!("Artefakt kann nicht gehasht werden: {error}"))
    })?;
    Ok(hex::encode(hash.finalize()))
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |difference, (a, b)| {
            difference | (a.to_ascii_lowercase() ^ b.to_ascii_lowercase())
        })
        == 0
}

fn parse_signing_seed(bytes: &[u8]) -> Result<[u8; 32], ReleaseError> {
    if bytes.len() == 32 {
        return bytes.try_into().map_err(|_| {
            ReleaseError::KeyError("Signing-Key muss exakt 32 Bytes enthalten.".to_string())
        });
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| {
            ReleaseError::KeyError(
                "Signing-Key muss 32 rohe Bytes oder 64 Hex-Zeichen enthalten.".to_string(),
            )
        })?
        .trim();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReleaseError::KeyError(
            "Signing-Key muss 32 rohe Bytes oder 64 Hex-Zeichen enthalten.".to_string(),
        ));
    }
    let decoded = hex::decode(text).map_err(|error| {
        ReleaseError::KeyError(format!("Signing-Key ist ungültiges Hex: {error}"))
    })?;
    decoded.try_into().map_err(|_| {
        ReleaseError::KeyError("Signing-Key muss exakt 32 Bytes enthalten.".to_string())
    })
}

fn atomic_install(destination: &Path, bytes: &[u8]) -> Result<(), ReleaseError> {
    let parent = destination.parent().ok_or_else(|| {
        ReleaseError::Io("Installationspfad besitzt kein Elternverzeichnis".to_string())
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        ReleaseError::Io(format!(
            "Installationsverzeichnis kann nicht angelegt werden: {error}"
        ))
    })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ReleaseError::Io(format!("Systemzeit ist ungültig: {error}")))?
        .as_nanos();
    let temp = parent.join(format!(".sb-install-{}-{nonce}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| {
            ReleaseError::Io(format!(
                "Temporäre Binary kann nicht angelegt werden: {error}"
            ))
        })?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(ReleaseError::Io(format!(
            "Temporäre Binary kann nicht geschrieben werden: {error}"
        )));
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(&temp, fs::Permissions::from_mode(0o755)) {
            let _ = fs::remove_file(&temp);
            return Err(ReleaseError::Io(format!(
                "Binary-Berechtigungen können nicht gesetzt werden: {error}"
            )));
        }
    }
    if let Err(error) = atomic_replace(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(ReleaseError::Io(format!(
            "Neue Binary konnte nicht atomar installiert werden: {error}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // CVE-Threat: A failed replacement must not leave a partial executable at the destination.
    // Hardening: Windows MoveFileExW replaces same-volume files in one operation with write-through.
    let succeeded = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

fn replace_file(source: &Path, destination: &Path) -> Result<(), ReleaseError> {
    if destination.exists() {
        let backup = destination.with_extension("old");
        if backup.exists() {
            fs::remove_file(&backup).map_err(|error| {
                ReleaseError::Io(format!("Altes Backup kann nicht entfernt werden: {error}"))
            })?;
        }
        fs::rename(destination, &backup).map_err(|error| {
            ReleaseError::Io(format!(
                "Bestehendes Artefakt kann nicht gesichert werden: {error}"
            ))
        })?;
        if let Err(error) = fs::rename(source, destination) {
            return match fs::rename(&backup, destination) {
                Ok(()) => Err(ReleaseError::Io(format!("Neues Artefakt kann nicht installiert werden: {error}"))),
                Err(restore_error) => Err(ReleaseError::Io(format!(
                    "Neues Artefakt konnte nicht installiert werden ({error}); Wiederherstellung fehlgeschlagen ({restore_error})"
                ))),
            };
        }
        fs::remove_file(backup).map_err(|error| {
            ReleaseError::Io(format!("Backup kann nicht entfernt werden: {error}"))
        })?;
    } else {
        fs::rename(source, destination).map_err(|error| {
            ReleaseError::Io(format!("Artefakt kann nicht installiert werden: {error}"))
        })?;
    }
    Ok(())
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), ReleaseError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        ReleaseError::PackagingError(format!("Manifest kann nicht serialisiert werden: {error}"))
    })?;
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReleaseError> {
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| {
            ReleaseError::Io(format!(
                "Temporäre Datei kann nicht angelegt werden: {error}"
            ))
        })?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(ReleaseError::Io(format!(
            "Datei kann nicht geschrieben werden: {error}"
        )));
    }
    drop(file);
    replace_file(&temp, path)
}

fn download(url: &str, path: &Path, max_size: u64) -> Result<(), ReleaseError> {
    if !url.starts_with("https://") {
        return Err(ReleaseError::DownloadFailed(
            "Release-Downloads müssen HTTPS verwenden.".to_string(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            ReleaseError::Io(format!(
                "Download-Verzeichnis kann nicht angelegt werden: {error}"
            ))
        })?;
    }
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(RELEASE_CONNECT_TIMEOUT)
        .timeout_read(RELEASE_READ_TIMEOUT)
        .timeout_write(RELEASE_WRITE_TIMEOUT)
        .build();
    let response = agent.get(url).call().map_err(|error| {
        ReleaseError::DownloadFailed(format!("HTTPS-Download fehlgeschlagen von {url}: {error}"))
    })?;
    if response.status() != 200 {
        return Err(ReleaseError::DownloadFailed(format!(
            "HTTPS-Download von {url} lieferte Status {}.",
            response.status()
        )));
    }
    let mut reader = response.into_reader().take(max_size + 1);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            ReleaseError::Io(format!(
                "Download-Datei kann nicht angelegt werden: {error}"
            ))
        })?;
    let copied = match std::io::copy(&mut reader, &mut output) {
        Ok(size) => size,
        Err(error) => {
            let _ = fs::remove_file(path);
            return Err(ReleaseError::DownloadFailed(format!(
                "Download von {url} fehlgeschlagen: {error}"
            )));
        }
    };
    if copied == 0 || copied > max_size {
        let _ = fs::remove_file(path);
        return Err(ReleaseError::DownloadFailed(format!(
            "Download von {url} war leer oder überschritt das Größenlimit."
        )));
    }
    if let Err(error) = output.sync_all() {
        let _ = fs::remove_file(path);
        return Err(ReleaseError::Io(format!(
            "Download-Datei kann nicht synchronisiert werden: {error}"
        )));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn print_install_inventory() {
    print_install_inventory_at(&get_sb_dir().join("bin"))
}

fn print_install_inventory_at(bin_dir: &Path) {
    println!("S&B Sovereign Package Manager — {}", bin_dir.display());
    for tool in crate::meta::available_tools() {
        let path = bin_dir.join(executable_name(
            tool.binary_name.as_deref().unwrap_or_default(),
        ));
        let status = if path.is_file() {
            "installiert"
        } else {
            "nicht installiert"
        };
        println!("  {:<12} {:<18} {status}", tool.id, tool.description);
    }
    let cli = bin_dir.join(executable_name("sb"));
    println!(
        "  {:<12} {}",
        "sb",
        if cli.is_file() {
            "installiert"
        } else {
            "nicht installiert"
        }
    );
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Result<Self, ReleaseError> {
        let base = sb_core::paths::sb_run_dir().join("releases");
        fs::create_dir_all(&base).map_err(|error| {
            ReleaseError::Io(format!(
                "Temporärer Release-Ordner kann nicht erstellt werden: {error}"
            ))
        })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ReleaseError::Io(format!("Systemzeit ist ungültig: {error}")))?
            .as_nanos();
        let path = base.join(format!("install-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).map_err(|error| {
            ReleaseError::Io(format!(
                "Temporärer Release-Ordner kann nicht erstellt werden: {error}"
            ))
        })?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            eprintln!(
                "Hinweis: Temporärer Release-Ordner {} konnte nicht entfernt werden: {error}",
                self.path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn manifest_requires_clean_paths_unique_targets_and_sha256() {
        let valid = ReleaseManifest {
            schema_version: 1,
            version: "v1.2.3".into(),
            artifacts: vec![ReleaseArtifact {
                target: "x86_64-pc-windows-msvc".into(),
                path: "sb-v1.2.3-x86_64-pc-windows-msvc.zip".into(),
                sha256: "a".repeat(64),
            }],
        };
        assert!(validate_manifest(&valid).is_ok());
        let mut traversal = valid.clone();
        traversal.artifacts[0].path = "../evil.zip".into();
        assert!(validate_manifest(&traversal).is_err());
        let mut duplicate = valid.clone();
        duplicate.artifacts.push(duplicate.artifacts[0].clone());
        assert!(validate_manifest(&duplicate).is_err());
    }

    #[test]
    fn signature_is_checked_before_manifest_trust() {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let data = br#"{"schema_version":1}"#;
        let signature = hex::encode(signing_key.sign(data).to_bytes());
        assert!(verify_manifest_signature(
            data,
            &signature,
            &signing_key.verifying_key().to_bytes()
        )
        .is_ok());
        assert!(verify_manifest_signature(
            b"tampered",
            &signature,
            &signing_key.verifying_key().to_bytes()
        )
        .is_err());
    }

    #[test]
    fn signing_key_parser_accepts_raw_seed_and_hex_seed() {
        let seed = [7u8; 32];
        assert_eq!(parse_signing_seed(&seed).unwrap(), seed);
        assert_eq!(
            parse_signing_seed(hex::encode(seed).as_bytes()).unwrap(),
            seed
        );
        assert!(parse_signing_seed(b"not a key").is_err());
    }

    #[test]
    fn release_version_comparison_handles_semver_and_rejects_unknown_formats() {
        assert_eq!(
            compare_release_versions("v1.10.0", "v1.9.9").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_release_versions("v1.0.0-rc.1", "v1.0.0").unwrap(),
            std::cmp::Ordering::Less
        );
        assert!(compare_release_versions("v1_custom", "v1.0.0").is_err());
    }

    #[test]
    fn installed_ledger_corruption_fails_closed() {
        let path = std::env::temp_dir().join(format!(
            "sb-release-ledger-test-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"{malformed").unwrap();
        assert!(read_installed_ledger(&path)
            .unwrap_err()
            .contains("Installations-Ledger"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn production_signing_rejects_a_key_that_does_not_match_the_pinned_key() {
        let base = std::env::temp_dir().join(format!(
            "sb-release-wrong-key-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let manifest_path = base.join(RELEASE_MANIFEST_NAME);
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "v1.2.3".to_string(),
            artifacts: vec![ReleaseArtifact {
                target: "x86_64-pc-windows-msvc".to_string(),
                path: "sb-v1.2.3-x86_64-pc-windows-msvc.zip".to_string(),
                sha256: "a".repeat(64),
            }],
        };
        write_json_atomic(&manifest_path, &manifest).unwrap();

        let mut seed = [1u8; 32];
        if SigningKey::from_bytes(&seed).verifying_key().to_bytes() == RELEASE_PUBLIC_KEY {
            seed[0] = 2;
        }
        let key_path = base.join("release-key");
        fs::write(&key_path, seed).unwrap();

        assert!(sign_release_manifest(&manifest_path, &key_path)
            .unwrap_err()
            .contains("gepinnten Release-Key"));
        assert!(!base
            .join(format!("{RELEASE_MANIFEST_NAME}.ed25519"))
            .exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn pack_and_extract_only_named_binaries_from_both_formats() {
        let base = std::env::temp_dir().join(format!(
            "sb-release-pack-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let input = base.join("input");
        let output = base.join("output");
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join("sb"), b"cli binary").unwrap();
        fs::write(input.join("sb-mesh"), b"mesh binary").unwrap();
        fs::write(input.join("sb-not-in-inventory"), b"not a product").unwrap();
        fs::write(input.join("skully"), b"separate prototype").unwrap();
        fs::write(input.join("README.md"), b"not a binary").unwrap();
        let requested = BTreeSet::from(["sb".to_string(), "sb-mesh".to_string()]);

        for format in ["tar.gz", "zip"] {
            let archive = pack_release(
                "v1.2.3",
                "x86_64-unknown-linux-musl",
                &input,
                &output,
                format,
            )
            .unwrap();
            let binaries = read_selected_binaries(&archive, &requested).unwrap();
            assert_eq!(binaries["sb"], b"cli binary");
            assert_eq!(binaries["sb-mesh"], b"mesh binary");
            assert!(!binaries.contains_key("sb-not-in-inventory"));
            assert!(!binaries.contains_key("skully"));
            let manifest: ReleaseManifest =
                serde_json::from_slice(&fs::read(output.join(RELEASE_MANIFEST_NAME)).unwrap())
                    .unwrap();
            assert_eq!(manifest.artifacts.len(), 1);
            assert_eq!(manifest.artifacts[0].sha256, sha256_file(&archive).unwrap());
            if format == "tar.gz" {
                fs::write(
                    output.join(format!("{RELEASE_MANIFEST_NAME}.ed25519")),
                    b"stale signature",
                )
                .unwrap();
            }
        }
        assert!(!output
            .join(format!("{RELEASE_MANIFEST_NAME}.ed25519"))
            .exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn release_packaging_requires_platform_correct_binary_suffixes() {
        assert!(is_release_binary_for_target(
            "sb.exe",
            "x86_64-pc-windows-msvc"
        ));
        assert!(!is_release_binary_for_target(
            "sb",
            "x86_64-pc-windows-msvc"
        ));
        assert!(is_release_binary_for_target(
            "sb",
            "x86_64-unknown-linux-musl"
        ));
        assert!(!is_release_binary_for_target(
            "sb.exe",
            "x86_64-unknown-linux-musl"
        ));
    }

    #[test]
    fn archive_entries_cannot_escape_the_expected_root_level_names() {
        let archive_path = std::env::temp_dir().join(format!(
            "sb-release-traversal-test-{}-{}.zip",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let output = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(output);
        archive
            .start_file("../sb", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"outside").unwrap();
        archive.finish().unwrap();
        let requested = BTreeSet::from(["sb".to_string()]);
        assert!(read_selected_binaries(&archive_path, &requested).is_err());
        fs::remove_file(archive_path).unwrap();
    }

    #[test]
    fn atomic_install_replaces_existing_file_without_leaving_temp_data() {
        let base = std::env::temp_dir().join(format!(
            "sb-release-install-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let destination = base.join(executable_name("sb-test"));
        fs::write(&destination, b"old").unwrap();
        atomic_install(&destination, b"new").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert_eq!(fs::read_dir(&base).unwrap().count(), 1);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_local_release_pack_sign_and_install_e2e() {
        let base = std::env::temp_dir().join(format!(
            "sb-release-e2e-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let input = base.join("input");
        let dist = base.join("dist");
        let install_dir = base.join("installed_bin");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&dist).unwrap();
        fs::create_dir_all(&install_dir).unwrap();

        let sb_bin_name = executable_name("sb");
        let mesh_bin_name = executable_name("sb-mesh");
        fs::write(input.join(&sb_bin_name), b"sb-binary-v1").unwrap();
        fs::write(input.join(&mesh_bin_name), b"mesh-binary-v1").unwrap();

        let format = if cfg!(windows) { "zip" } else { "tar.gz" };
        let archive = pack_release("v1.0.0", current_target(), &input, &dist, format).unwrap();
        assert!(archive.exists());

        let seed = [55u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let test_public_key = signing_key.verifying_key().to_bytes();
        let manifest_path = dist.join(RELEASE_MANIFEST_NAME);
        let sig_path = sign_release_manifest_with_seed(&manifest_path, &seed).unwrap();
        assert!(sig_path.exists());

        // 1. Install only mesh
        install_requested_to_dir(
            &["mesh".to_string()],
            false,
            &ReleaseSource::LocalDir(dist.clone()),
            &test_public_key,
            &install_dir,
        )
        .unwrap();

        assert!(install_dir.join(&mesh_bin_name).is_file());
        assert!(!install_dir.join(&sb_bin_name).exists());
        assert_eq!(
            fs::read(install_dir.join(&mesh_bin_name)).unwrap(),
            b"mesh-binary-v1"
        );

        // 2. Install sb as well
        install_requested_to_dir(
            &["sb".to_string()],
            false,
            &ReleaseSource::LocalDir(dist.clone()),
            &test_public_key,
            &install_dir,
        )
        .unwrap();
        assert!(install_dir.join(&sb_bin_name).is_file());
        assert_eq!(
            fs::read(install_dir.join(&sb_bin_name)).unwrap(),
            b"sb-binary-v1"
        );

        // Missing signed artifacts must fail without replacing an installed binary.
        let unavailable_archive = dist.join("temporarily-unavailable.zip");
        fs::rename(&archive, &unavailable_archive).unwrap();
        let missing_artifact = install_requested_to_dir(
            &["mesh".to_string()],
            true,
            &ReleaseSource::LocalDir(dist.clone()),
            &test_public_key,
            &install_dir,
        );
        assert!(missing_artifact.unwrap_err().contains("nicht in"));
        assert_eq!(
            fs::read(install_dir.join(&mesh_bin_name)).unwrap(),
            b"mesh-binary-v1"
        );
        fs::rename(&unavailable_archive, &archive).unwrap();

        // 3. Test tamper detection: corrupted signature must fail
        fs::write(&sig_path, "0".repeat(128)).unwrap();
        let sig_tamper_res = install_requested_to_dir(
            &["mesh".to_string()],
            true,
            &ReleaseSource::LocalDir(dist.clone()),
            &test_public_key,
            &install_dir,
        );
        assert!(sig_tamper_res.is_err());
        assert!(sig_tamper_res.unwrap_err().contains("Signaturprüfung"));

        // Re-sign properly
        sign_release_manifest_with_seed(&manifest_path, &seed).unwrap();

        // 4. Test tamper detection: corrupted archive SHA-256 must fail
        let mut archive_bytes = fs::read(&archive).unwrap();
        archive_bytes.push(0xff);
        fs::write(&archive, archive_bytes).unwrap();
        let hash_tamper_res = install_requested_to_dir(
            &["mesh".to_string()],
            true,
            &ReleaseSource::LocalDir(dist.clone()),
            &test_public_key,
            &install_dir,
        );
        assert!(hash_tamper_res.is_err());
        assert!(hash_tamper_res
            .unwrap_err()
            .contains("SHA-256 stimmt nicht überein"));

        // 5. Test Update to v2.0.0
        let dist2 = base.join("dist2");
        let input2 = base.join("input2");
        fs::create_dir_all(&input2).unwrap();
        fs::create_dir_all(&dist2).unwrap();
        fs::write(input2.join(&sb_bin_name), b"sb-binary-v2").unwrap();
        fs::write(input2.join(&mesh_bin_name), b"mesh-binary-v2").unwrap();

        pack_release("v2.0.0", current_target(), &input2, &dist2, format).unwrap();
        sign_release_manifest_with_seed(&dist2.join(RELEASE_MANIFEST_NAME), &seed).unwrap();

        update_installed_to_dir(
            &[],
            &ReleaseSource::LocalDir(dist2.clone()),
            &test_public_key,
            &install_dir,
        )
        .unwrap();

        assert_eq!(
            fs::read(install_dir.join(&mesh_bin_name)).unwrap(),
            b"mesh-binary-v2"
        );
        assert_eq!(
            fs::read(install_dir.join(&sb_bin_name)).unwrap(),
            b"sb-binary-v2"
        );

        let ledger_path = base.join(INSTALLED_LEDGER_NAME);
        let ledger_bytes = fs::read(&ledger_path).unwrap();
        fs::write(&ledger_path, b"{malformed").unwrap();
        let corrupt_ledger_install = install_requested_to_dir(
            &["mesh".to_string()],
            true,
            &ReleaseSource::LocalDir(dist2.clone()),
            &test_public_key,
            &install_dir,
        );
        assert!(corrupt_ledger_install
            .unwrap_err()
            .contains("Installations-Ledger"));
        assert_eq!(
            fs::read(install_dir.join(&mesh_bin_name)).unwrap(),
            b"mesh-binary-v2"
        );
        fs::write(&ledger_path, ledger_bytes).unwrap();

        // A valid older signature cannot silently roll the installed release back.
        pack_release("v1.0.0", current_target(), &input, &dist, format).unwrap();
        sign_release_manifest_with_seed(&dist.join(RELEASE_MANIFEST_NAME), &seed).unwrap();
        let downgrade = install_requested_to_dir(
            &["mesh".to_string()],
            true,
            &ReleaseSource::LocalDir(dist.clone()),
            &test_public_key,
            &install_dir,
        );
        assert!(downgrade.unwrap_err().contains("--allow-downgrade"));
        assert_eq!(
            fs::read(install_dir.join(&mesh_bin_name)).unwrap(),
            b"mesh-binary-v2"
        );

        install_requested_to_dir_with_options(
            &["mesh".to_string()],
            true,
            true,
            &ReleaseSource::LocalDir(dist),
            &test_public_key,
            &install_dir,
        )
        .unwrap();
        assert_eq!(
            fs::read(install_dir.join(&mesh_bin_name)).unwrap(),
            b"mesh-binary-v1"
        );
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn test_pack_all_release_keygen_and_audit() {
        let base = std::env::temp_dir().join(format!(
            "sb-release-packall-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let input = base.join("input");
        let dist = base.join("dist");
        let install_dir = base.join("sb_root").join("bin");
        let key_file = base.join("test_release.key");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&dist).unwrap();
        fs::create_dir_all(&install_dir).unwrap();

        // 1. Generate keypair
        generate_release_keypair(&key_file).unwrap();
        assert!(key_file.exists());
        let key_bytes = fs::read(&key_file).unwrap();
        let seed = parse_signing_seed(&key_bytes).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let test_public_key = signing_key.verifying_key().to_bytes();

        // 2. Mock every required binary for the selected target
        for product in sb_core::catalog::products()
            .unwrap()
            .iter()
            .filter(|product| product.installable)
            .filter(|product| {
                product
                    .release_targets
                    .iter()
                    .any(|supported| supported == current_target())
            })
        {
            let name = executable_name(product.binary_name.as_deref().unwrap());
            let bytes = match product.binary_name.as_deref() {
                Some("sb") => b"binary-sb-v1".as_slice(),
                Some("sb-drive") => b"binary-drive-v1".as_slice(),
                _ => b"test-binary".as_slice(),
            };
            fs::write(input.join(name), bytes).unwrap();
        }

        let sb_bin = executable_name("sb");
        let drive_bin = executable_name("sb-drive");

        let format = if cfg!(windows) { "zip" } else { "tar.gz" };
        let archive = pack_all_release(
            "v1.0.0",
            Some(current_target()),
            &input,
            &dist,
            format,
            None,
        )
        .unwrap();
        sign_release_manifest_with_seed(&dist.join(RELEASE_MANIFEST_NAME), &seed).unwrap();
        assert!(archive.exists());
        assert!(dist.join(RELEASE_MANIFEST_NAME).exists());
        assert!(dist
            .join(format!("{RELEASE_MANIFEST_NAME}.ed25519"))
            .exists());

        // 3. Install
        install_requested_to_dir(
            &["sb".to_string(), "drive".to_string()],
            false,
            &ReleaseSource::LocalDir(dist.clone()),
            &test_public_key,
            &install_dir,
        )
        .unwrap();

        assert!(install_dir.join(&sb_bin).is_file());
        assert!(install_dir.join(&drive_bin).is_file());
        assert!(base.join("sb_root").join(INSTALLED_LEDGER_NAME).exists());

        // 4. Audit: All verified
        let audit = audit_installed_binaries_with_key(&install_dir, &test_public_key);
        assert_eq!(audit.total_installed, 2);
        assert_eq!(audit.verified_count, 2);
        assert!(audit.tampered.is_empty());
        assert!(audit.signature_valid);
        assert_eq!(audit.manifest_version.as_deref(), Some("v1.0.0"));

        // 5. Tamper with one binary
        fs::write(install_dir.join(&sb_bin), b"tampered-binary-evil").unwrap();
        let audit_tampered = audit_installed_binaries_with_key(&install_dir, &test_public_key);
        assert_eq!(audit_tampered.verified_count, 1);
        assert_eq!(audit_tampered.tampered.len(), 1);
        assert_eq!(audit_tampered.tampered[0], sb_bin);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn pack_all_release_rejects_missing_inventory_binaries() {
        let base = std::env::temp_dir().join(format!(
            "sb-release-packall-missing-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let input = base.join("input");
        let dist = base.join("dist");
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join(executable_name("sb")), b"sb binary").unwrap();

        let format = if cfg!(windows) { "zip" } else { "tar.gz" };
        let error = pack_all_release(
            "v1.0.0",
            Some(current_target()),
            &input,
            &dist,
            format,
            None,
        )
        .unwrap_err();

        assert!(error.contains("ist unvollständig"));
        assert!(error.contains("sb-code"));
        assert!(!dist.exists());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn verify_release_key_validates_pinned_and_unpinned_keys() {
        let temp = TempDir::create().unwrap();
        let key_path = temp.path.join("test.key");

        // 1. Generate new keypair
        generate_release_keypair(&key_path).unwrap();
        assert!(key_path.exists());

        // 2. verify_release_key should accept valid Ed25519 seed
        assert!(verify_release_key(&key_path).is_ok());

        // 3. Corrupt key file
        fs::write(&key_path, b"corrupted-key-data").unwrap();
        assert!(verify_release_key(&key_path).is_err());
    }

    #[test]
    fn download_rejects_insecure_protocols_fail_closed() {
        let temp = TempDir::create().unwrap();
        let target = temp.path.join("file.bin");
        let error = download("http://insecure-domain.com/bin", &target, 1024).unwrap_err();
        assert!(error.contains("HTTPS"));
        assert!(!target.exists());

        let error_ftp = download("ftp://insecure-domain.com/bin", &target, 1024).unwrap_err();
        assert!(error_ftp.contains("HTTPS"));
        assert!(!target.exists());
    }

    #[test]
    fn test_mesh_package_distribution_publish_fetch_verify_and_install() {
        let temp = TempDir::create().unwrap();
        let base = temp.path.clone();

        let fake_home = base.join("home");
        let sb_root = fake_home.join(".sb");
        let install_dir = sb_root.join("bin");
        let mesh_home = base.join("mesh_home");
        let input = base.join("input");
        let dist = base.join("dist");
        let fetched_dir = base.join("fetched");

        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&install_dir).unwrap();
        fs::create_dir_all(&mesh_home).unwrap();
        std::env::set_var("SB_PATH", &sb_root);
        std::env::set_var("SB_MESH_HOME", &mesh_home);

        // 1. Generate test signing key
        let seed = [0x55u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let test_public_key = signing_key.verifying_key().to_bytes();
        let key_file = base.join("test-release.key");
        fs::write(&key_file, hex::encode(seed)).unwrap();

        // 2. Prepare binaries
        for product in sb_core::catalog::products()
            .unwrap()
            .iter()
            .filter(|product| product.installable)
            .filter(|product| {
                product
                    .release_targets
                    .iter()
                    .any(|supported| supported == current_target())
            })
        {
            let name = executable_name(product.binary_name.as_deref().unwrap());
            fs::write(input.join(name), format!("test-payload-{}", product.id)).unwrap();
        }

        let format = if cfg!(windows) { "zip" } else { "tar.gz" };
        let version = "0.9.9";
        let archive =
            pack_all_release(version, Some(current_target()), &input, &dist, format, None)
                .expect("pack_all_release must succeed");
        assert!(archive.exists());

        let manifest_path = dist.join(RELEASE_MANIFEST_NAME);
        sign_release_manifest_with_seed(&manifest_path, &seed).expect("sign manifest must succeed");

        // 3. Publish to mesh
        let mesh_name = "testmesh";
        let namespace = "releases";

        let publish_result = publish_release_to_mesh_with_key(
            &manifest_path,
            Some(&key_file),
            mesh_name,
            namespace,
            &test_public_key,
        );
        assert!(
            publish_result.is_ok(),
            "publish to mesh should succeed: {:?}",
            publish_result
        );

        // Idempotent publish should also succeed without error
        let republish_result = publish_release_to_mesh_with_key(
            &manifest_path,
            Some(&key_file),
            mesh_name,
            namespace,
            &test_public_key,
        );
        assert!(republish_result.is_ok());

        // 4. Fetch from mesh
        let fetched_manifest_path = fetch_release_from_mesh_with_key(
            version,
            Some(current_target()),
            mesh_name,
            namespace,
            &fetched_dir,
            &test_public_key,
        )
        .expect("fetch from mesh must succeed");

        assert!(fetched_manifest_path.exists());
        assert!(fetched_dir.join(RELEASE_MANIFEST_NAME).exists());
        assert!(fetched_dir
            .join(format!("{RELEASE_MANIFEST_NAME}.ed25519"))
            .exists());

        // 5. Install from fetched release
        install_requested_to_dir(
            &["sb".to_string(), "code".to_string()],
            false,
            &ReleaseSource::LocalDir(fetched_dir.clone()),
            &test_public_key,
            &install_dir,
        )
        .expect("installation of fetched release should succeed");

        assert!(install_dir.join(executable_name("sb")).is_file());
        assert!(install_dir.join(executable_name("sb-code")).is_file());
    }
}
