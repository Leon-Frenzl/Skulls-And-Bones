//! Opt-in, per-user installation store for SB-MAP client apps.
//!
//! Apps are never bundled: they are installed from a signed manifest plus an artifact whose
//! SHA-256 is pinned by that manifest, after the user consented to the exact capability set.

use super::{
    encode_lower_hex, validate_dns_id, verify_signed_manifest, CapabilityRequest, ContractError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
const STATE_FILE: &str = "state.json";
const BUNDLE_MAGIC: &[u8; 8] = b"SBAPP\x00\x01\n";
const MAX_SIGNATURE_BYTES: usize = 256;

/// Single-object distribution format so an app is one ACL-protected mesh object:
/// `SBAPP\0\1\n | u32le manifest_len | u32le sig_len | manifest | signature(hex) | artifact`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppBundle {
    pub manifest: Vec<u8>,
    pub signature_hex: String,
    pub artifact: Vec<u8>,
}

// CVE-Threat: Length-field integer overflow / allocation bomb in a peer-supplied container.
// Analysis: Both lengths are attacker-controlled u32 values.
// Hardening: Limits are checked before slicing; arithmetic is checked; trailing data is the artifact.
pub fn parse_bundle(bytes: &[u8]) -> Result<AppBundle, InstallError> {
    let bad = |reason: &str| InstallError::Io(format!("Invalid app bundle: {reason}"));
    let header = BUNDLE_MAGIC.len() + 8;
    if bytes.len() < header || &bytes[..BUNDLE_MAGIC.len()] != BUNDLE_MAGIC {
        return Err(bad("bad header"));
    }
    let word = |offset: usize| {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4 bytes")) as usize
    };
    let manifest_len = word(BUNDLE_MAGIC.len());
    let signature_len = word(BUNDLE_MAGIC.len() + 4);
    if manifest_len > super::MAX_MANIFEST_BYTES || signature_len > MAX_SIGNATURE_BYTES {
        return Err(bad("section exceeds limit"));
    }
    let manifest_end = header
        .checked_add(manifest_len)
        .ok_or_else(|| bad("length overflow"))?;
    let signature_end = manifest_end
        .checked_add(signature_len)
        .ok_or_else(|| bad("length overflow"))?;
    if signature_end > bytes.len() {
        return Err(bad("truncated"));
    }
    let signature_hex = std::str::from_utf8(&bytes[manifest_end..signature_end])
        .map_err(|_| bad("signature is not text"))?
        .to_string();
    Ok(AppBundle {
        manifest: bytes[header..manifest_end].to_vec(),
        signature_hex,
        artifact: bytes[signature_end..].to_vec(),
    })
}

pub fn build_bundle(manifest: &[u8], signature_hex: &str, artifact: &[u8]) -> Vec<u8> {
    let mut out = BUNDLE_MAGIC.to_vec();
    out.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    out.extend_from_slice(&(signature_hex.len() as u32).to_le_bytes());
    out.extend_from_slice(manifest);
    out.extend_from_slice(signature_hex.as_bytes());
    out.extend_from_slice(artifact);
    out
}

/// Publisher-side packaging: pins the artifact digest into the manifest, signs it with the
/// publisher key and returns the single-object bundle plus the final manifest bytes.
// CVE-Threat: Signing a manifest that does not match the shipped artifact (confused publisher).
// Analysis: The digest is computed here from the artifact, never taken from the input manifest.
// Hardening: The result is re-verified against the signer's own key before being returned.
pub fn pack_signed_bundle(
    manifest_json: &[u8],
    artifact: &[u8],
    key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, InstallError> {
    use ed25519_dalek::Signer;
    if artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(InstallError::ArtifactTooLarge);
    }
    let mut manifest: super::AppManifest = serde_json::from_slice(manifest_json)
        .map_err(|error| InstallError::Io(format!("Invalid manifest: {error}")))?;
    manifest.client.artifact = format!(
        "sha256:{}",
        encode_lower_hex(Sha256::digest(artifact).as_slice())
    );
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|error| InstallError::Io(format!("Cannot encode manifest: {error}")))?;
    let mut message = super::MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    let signature = encode_lower_hex(&key.sign(&message).to_bytes());
    let trusted = BTreeMap::from([(
        manifest.publisher_key_id.clone(),
        key.verifying_key().to_bytes(),
    )]);
    verify_signed_manifest(&bytes, &signature, &trusted)?;
    Ok(build_bundle(&bytes, &signature, artifact))
}

/// Parses user-controlled publisher trust anchors: `{ "<publisher_key_id>": "<64 hex chars>" }`.
pub fn parse_trusted_publishers(json: &[u8]) -> Result<BTreeMap<String, [u8; 32]>, InstallError> {
    let raw: BTreeMap<String, String> = serde_json::from_slice(json)
        .map_err(|error| InstallError::Io(format!("Invalid publisher trust file: {error}")))?;
    let mut trusted = BTreeMap::new();
    for (key_id, hex_key) in raw {
        validate_dns_id("publisher key id", &key_id)?;
        if hex_key.len() != 64 || !hex_key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(InstallError::Io(
                "Publisher key must be 64 hex characters".into(),
            ));
        }
        let mut key = [0u8; 32];
        for (index, slot) in key.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex_key[index * 2..index * 2 + 2], 16)
                .map_err(|error| InstallError::Io(error.to_string()))?;
        }
        trusted.insert(key_id, key);
    }
    Ok(trusted)
}

#[derive(Debug)]
pub enum InstallError {
    Contract(ContractError),
    ArtifactMismatch,
    ArtifactTooLarge,
    ConsentMismatch(&'static str),
    Downgrade { installed: String, offered: String },
    AlreadyInstalled,
    NotInstalled,
    NoPreviousVersion,
    Io(String),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "{error}"),
            Self::ArtifactMismatch => {
                formatter.write_str("Artifact digest does not match the signed manifest")
            }
            Self::ArtifactTooLarge => formatter.write_str("Artifact exceeds the size limit"),
            Self::ConsentMismatch(reason) => write!(formatter, "Consent rejected: {reason}"),
            Self::Downgrade { installed, offered } => write!(
                formatter,
                "Refusing downgrade from {installed} to {offered}; use rollback"
            ),
            Self::AlreadyInstalled => formatter.write_str("This app version is already installed"),
            Self::NotInstalled => formatter.write_str("App is not installed"),
            Self::NoPreviousVersion => formatter.write_str("No previous version to roll back to"),
            Self::Io(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for InstallError {}

impl From<ContractError> for InstallError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

fn io(context: &str, error: std::io::Error) -> InstallError {
    InstallError::Io(format!("{context}: {error}"))
}

/// What the user approved in the install dialog; bound to one exact manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallConsent {
    pub manifest_digest: String,
    pub granted: Vec<CapabilityRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledApp {
    pub app_id: String,
    pub version: String,
    pub manifest_digest: String,
    pub publisher_key_id: String,
    pub artifact_sha256: String,
    pub granted: Vec<CapabilityRequest>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppState {
    current: String,
    previous: Option<String>,
}

pub struct AppStore {
    root: PathBuf,
}

impl AppStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn app_dir(&self, app_id: &str) -> Result<PathBuf, InstallError> {
        // CVE-Threat: Path traversal through a hostile app_id.
        // Analysis: app_id becomes a directory name.
        // Hardening: strict DNS-style identifier validation before any path join.
        validate_dns_id("app_id", app_id)?;
        Ok(self.root.join(app_id))
    }

    fn read_state(dir: &Path) -> Result<Option<AppState>, InstallError> {
        match fs::read(dir.join(STATE_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| InstallError::Io(format!("Corrupt install state: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io("Cannot read install state", error)),
        }
    }

    fn write_state(dir: &Path, state: &AppState) -> Result<(), InstallError> {
        let bytes =
            serde_json::to_vec(state).map_err(|error| InstallError::Io(error.to_string()))?;
        let temp = dir.join(format!("{STATE_FILE}.tmp"));
        let mut file = fs::File::create(&temp).map_err(|error| io("Cannot write state", error))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| io("Cannot write state", error))?;
        drop(file);
        fs::rename(&temp, dir.join(STATE_FILE)).map_err(|error| io("Cannot commit state", error))
    }

    fn read_installed(&self, app_id: &str, version: &str) -> Result<InstalledApp, InstallError> {
        let path = self
            .app_dir(app_id)?
            .join("versions")
            .join(version)
            .join("install.json");
        let bytes = fs::read(path).map_err(|error| io("Cannot read install record", error))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| InstallError::Io(format!("Corrupt install record: {error}")))
    }

    // CVE-Threat: Supply-chain tampering, consent confusion, downgrade to a vulnerable build.
    // Analysis: manifest, artifact and user consent come from three different trust domains.
    // Hardening: publisher signature, artifact digest pin, exact-capability consent bound to the
    // manifest digest, strictly increasing versions, staged directory published by rename.
    pub fn install(
        &self,
        manifest_bytes: &[u8],
        signature_hex: &str,
        artifact: &[u8],
        trusted_publishers: &BTreeMap<String, [u8; 32]>,
        consent: &InstallConsent,
    ) -> Result<InstalledApp, InstallError> {
        let verified = verify_signed_manifest(manifest_bytes, signature_hex, trusted_publishers)?;
        let manifest = verified.manifest();
        if artifact.len() > MAX_ARTIFACT_BYTES {
            return Err(InstallError::ArtifactTooLarge);
        }
        let artifact_sha256 = format!(
            "sha256:{}",
            encode_lower_hex(Sha256::digest(artifact).as_slice())
        );
        if artifact_sha256 != manifest.client.artifact {
            return Err(InstallError::ArtifactMismatch);
        }
        if consent.manifest_digest != verified.manifest_digest() {
            return Err(InstallError::ConsentMismatch(
                "consent is for another manifest",
            ));
        }
        let mut granted = consent.granted.clone();
        let mut requested = manifest.requested_capabilities.clone();
        granted.sort_by(|a, b| (&a.service_id, &a.operation).cmp(&(&b.service_id, &b.operation)));
        requested.sort_by(|a, b| (&a.service_id, &a.operation).cmp(&(&b.service_id, &b.operation)));
        if granted != requested {
            return Err(InstallError::ConsentMismatch(
                "granted capabilities must equal the requested set",
            ));
        }

        let dir = self.app_dir(&manifest.app_id)?;
        let offered = semver::Version::parse(&manifest.version)
            .map_err(|error| InstallError::Io(format!("Invalid version: {error}")))?;
        let state = Self::read_state(&dir)?;
        if let Some(state) = &state {
            let installed = semver::Version::parse(&state.current)
                .map_err(|error| InstallError::Io(format!("Corrupt install state: {error}")))?;
            if offered == installed {
                return Err(InstallError::AlreadyInstalled);
            }
            if offered < installed {
                return Err(InstallError::Downgrade {
                    installed: installed.to_string(),
                    offered: offered.to_string(),
                });
            }
        }

        let versions = dir.join("versions");
        fs::create_dir_all(&versions).map_err(|error| io("Cannot create app directory", error))?;
        let target = versions.join(offered.to_string());
        if target.exists() {
            return Err(InstallError::AlreadyInstalled);
        }
        let staging = versions.join(format!(".staging-{}", offered));
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir(&staging).map_err(|error| io("Cannot create staging directory", error))?;
        let record = InstalledApp {
            app_id: manifest.app_id.clone(),
            version: offered.to_string(),
            manifest_digest: verified.manifest_digest().to_string(),
            publisher_key_id: verified.publisher_key_id().to_string(),
            artifact_sha256,
            granted: requested,
        };
        let staged = (|| -> Result<(), InstallError> {
            fs::write(staging.join("manifest.json"), manifest_bytes)
                .and_then(|()| fs::write(staging.join("manifest.sig"), signature_hex))
                .and_then(|()| fs::write(staging.join("app.bin"), artifact))
                .map_err(|error| io("Cannot stage app", error))?;
            let json =
                serde_json::to_vec(&record).map_err(|error| InstallError::Io(error.to_string()))?;
            fs::write(staging.join("install.json"), json)
                .map_err(|error| io("Cannot stage record", error))?;
            fs::rename(&staging, &target).map_err(|error| io("Cannot publish app", error))
        })();
        if let Err(error) = staged {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
        let new_state = AppState {
            current: record.version.clone(),
            previous: state.map(|state| state.current),
        };
        if let Err(error) = Self::write_state(&dir, &new_state) {
            let _ = fs::remove_dir_all(&target);
            return Err(error);
        }
        Ok(record)
    }

    pub fn current(&self, app_id: &str) -> Result<Option<InstalledApp>, InstallError> {
        let dir = self.app_dir(app_id)?;
        match Self::read_state(&dir)? {
            Some(state) => self.read_installed(app_id, &state.current).map(Some),
            None => Ok(None),
        }
    }

    /// Path of the pinned artifact of the current version; it is re-hashed before use.
    pub fn verified_artifact_path(&self, app_id: &str) -> Result<PathBuf, InstallError> {
        let record = self.current(app_id)?.ok_or(InstallError::NotInstalled)?;
        let path = self
            .app_dir(app_id)?
            .join("versions")
            .join(&record.version)
            .join("app.bin");
        let bytes = fs::read(&path).map_err(|error| io("Cannot read artifact", error))?;
        let digest = format!(
            "sha256:{}",
            encode_lower_hex(Sha256::digest(&bytes).as_slice())
        );
        if digest != record.artifact_sha256 {
            return Err(InstallError::ArtifactMismatch);
        }
        Ok(path)
    }

    pub fn list(&self) -> Result<Vec<InstalledApp>, InstallError> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io("Cannot list apps", error)),
        };
        let mut apps = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io("Cannot list apps", error))?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if validate_dns_id("app_id", &name).is_err() {
                continue;
            }
            if let Some(app) = self.current(&name)? {
                apps.push(app);
            }
        }
        apps.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        Ok(apps)
    }

    pub fn rollback(&self, app_id: &str) -> Result<InstalledApp, InstallError> {
        let dir = self.app_dir(app_id)?;
        let state = Self::read_state(&dir)?.ok_or(InstallError::NotInstalled)?;
        let previous = state.previous.ok_or(InstallError::NoPreviousVersion)?;
        let record = self.read_installed(app_id, &previous)?;
        Self::write_state(
            &dir,
            &AppState {
                current: previous,
                previous: None,
            },
        )?;
        Ok(record)
    }

    pub fn uninstall(&self, app_id: &str) -> Result<(), InstallError> {
        let dir = self.app_dir(app_id)?;
        if Self::read_state(&dir)?.is_none() {
            return Err(InstallError::NotInstalled);
        }
        fs::remove_dir_all(dir).map_err(|error| io("Cannot remove app", error))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        AppManifest, ClientArtifact, ServiceDeclaration, MANIFEST_SIGNATURE_DOMAIN,
    };
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const APP: &str = "org.skullsandbones.notes";

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sb_app_store_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    struct Release {
        manifest: Vec<u8>,
        signature: String,
        artifact: Vec<u8>,
        consent: InstallConsent,
    }

    fn release(version: &str, body: &[u8], key: &SigningKey) -> Release {
        let capability = CapabilityRequest {
            service_id: "org.skullsandbones.notes.api".into(),
            operation: "notes.read".into(),
        };
        let manifest = AppManifest {
            schema_version: 1,
            app_id: APP.into(),
            version: version.into(),
            publisher_key_id: "org.skullsandbones.publisher".into(),
            client: ClientArtifact {
                target: "windows-x86_64".into(),
                artifact: format!(
                    "sha256:{}",
                    encode_lower_hex(Sha256::digest(body).as_slice())
                ),
            },
            services: vec![ServiceDeclaration {
                service_id: "org.skullsandbones.notes.api".into(),
                api_version: 1,
                contract_digest: format!("sha256:{}", "b".repeat(64)),
            }],
            requested_capabilities: vec![capability.clone()],
            sandbox_profile: "native-client-default".into(),
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let mut message = MANIFEST_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&bytes);
        let signature = encode_lower_hex(&key.sign(&message).to_bytes());
        let digest = format!(
            "sha256:{}",
            encode_lower_hex(Sha256::digest(&bytes).as_slice())
        );
        Release {
            manifest: bytes,
            signature,
            artifact: body.to_vec(),
            consent: InstallConsent {
                manifest_digest: digest,
                granted: vec![capability],
            },
        }
    }

    fn trust(key: &SigningKey) -> BTreeMap<String, [u8; 32]> {
        BTreeMap::from([(
            "org.skullsandbones.publisher".to_string(),
            key.verifying_key().to_bytes(),
        )])
    }

    fn install(
        store: &AppStore,
        release: &Release,
        key: &SigningKey,
    ) -> Result<InstalledApp, InstallError> {
        store.install(
            &release.manifest,
            &release.signature,
            &release.artifact,
            &trust(key),
            &release.consent,
        )
    }

    #[test]
    fn packed_bundle_pins_artifact_and_installs_end_to_end() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let template = release("1.0.0", b"ignored", &key);
        let packed = pack_signed_bundle(&template.manifest, b"real-binary", &key).unwrap();
        let bundle = parse_bundle(&packed).unwrap();
        let verified =
            verify_signed_manifest(&bundle.manifest, &bundle.signature_hex, &trust(&key)).unwrap();
        assert_eq!(
            verified.manifest().client.artifact,
            format!(
                "sha256:{}",
                encode_lower_hex(Sha256::digest(b"real-binary").as_slice())
            )
        );
        let root = temp_root("pack");
        let store = AppStore::new(&root);
        store
            .install(
                &bundle.manifest,
                &bundle.signature_hex,
                &bundle.artifact,
                &trust(&key),
                &InstallConsent {
                    manifest_digest: verified.manifest_digest().to_string(),
                    granted: template.consent.granted.clone(),
                },
            )
            .unwrap();
        assert!(pack_signed_bundle(b"not json", b"x", &key).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bundle_roundtrip_and_hostile_lengths() {
        let bundle = build_bundle(b"{}", "abcd", b"binary");
        let parsed = parse_bundle(&bundle).unwrap();
        assert_eq!(parsed.manifest, b"{}");
        assert_eq!(parsed.signature_hex, "abcd");
        assert_eq!(parsed.artifact, b"binary");
        assert!(parse_bundle(&bundle[..bundle.len().min(10)]).is_err());
        let mut hostile = bundle.clone();
        hostile[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_bundle(&hostile).is_err());
        let mut truncated = bundle.clone();
        truncated[8..12].copy_from_slice(&1000u32.to_le_bytes());
        assert!(parse_bundle(&truncated).is_err());
        assert!(parse_bundle(b"NOTABUNDLE_______________").is_err());
    }

    #[test]
    fn trusted_publisher_file_is_strict() {
        let ok = format!(
            r#"{{"org.skullsandbones.publisher":"{}"}}"#,
            "ab".repeat(32)
        );
        assert_eq!(parse_trusted_publishers(ok.as_bytes()).unwrap().len(), 1);
        assert!(parse_trusted_publishers(br#"{"x":"zz"}"#).is_err());
        assert!(parse_trusted_publishers(b"[]").is_err());
    }

    #[test]
    fn install_list_rollback_and_uninstall_roundtrip() {
        let root = temp_root("roundtrip");
        let store = AppStore::new(&root);
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let v1 = release("1.0.0", b"binary-one", &key);
        let v2 = release("1.1.0", b"binary-two", &key);

        assert!(store.list().unwrap().is_empty());
        install(&store, &v1, &key).unwrap();
        install(&store, &v2, &key).unwrap();
        assert_eq!(store.current(APP).unwrap().unwrap().version, "1.1.0");
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store
            .verified_artifact_path(APP)
            .unwrap()
            .ends_with("app.bin"));

        assert_eq!(store.rollback(APP).unwrap().version, "1.0.0");
        assert!(matches!(
            store.rollback(APP),
            Err(InstallError::NoPreviousVersion)
        ));
        store.uninstall(APP).unwrap();
        assert!(store.current(APP).unwrap().is_none());
        assert!(matches!(
            store.uninstall(APP),
            Err(InstallError::NotInstalled)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_rejects_tampering_bad_consent_and_downgrade() {
        let root = temp_root("reject");
        let store = AppStore::new(&root);
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let v2 = release("2.0.0", b"binary-two", &key);

        let mut tampered = release("2.0.0", b"binary-two", &key);
        tampered.artifact = b"evil".to_vec();
        assert!(matches!(
            install(&store, &tampered, &key),
            Err(InstallError::ArtifactMismatch)
        ));

        let mut wrong_signer = release("2.0.0", b"binary-two", &key);
        wrong_signer.signature = "00".repeat(64);
        assert!(matches!(
            install(&store, &wrong_signer, &key),
            Err(InstallError::Contract(_))
        ));

        let mut other_manifest = release("2.0.0", b"binary-two", &key);
        other_manifest.consent.manifest_digest = format!("sha256:{}", "0".repeat(64));
        assert!(matches!(
            install(&store, &other_manifest, &key),
            Err(InstallError::ConsentMismatch(_))
        ));

        let mut no_consent = release("2.0.0", b"binary-two", &key);
        no_consent.consent.granted.clear();
        assert!(matches!(
            install(&store, &no_consent, &key),
            Err(InstallError::ConsentMismatch(_))
        ));
        let mut extra = release("2.0.0", b"binary-two", &key);
        extra.consent.granted.push(CapabilityRequest {
            service_id: "org.skullsandbones.notes.api".into(),
            operation: "notes.write".into(),
        });
        assert!(matches!(
            install(&store, &extra, &key),
            Err(InstallError::ConsentMismatch(_))
        ));
        assert!(store.list().unwrap().is_empty());

        install(&store, &v2, &key).unwrap();
        assert!(matches!(
            install(&store, &v2, &key),
            Err(InstallError::AlreadyInstalled)
        ));
        let old = release("1.0.0", b"binary-one", &key);
        assert!(matches!(
            install(&store, &old, &key),
            Err(InstallError::Downgrade { .. })
        ));
        assert_eq!(store.current(APP).unwrap().unwrap().version, "2.0.0");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn store_rejects_traversal_ids_and_detects_artifact_corruption() {
        let root = temp_root("corrupt");
        let store = AppStore::new(&root);
        assert!(store.current("../escape").is_err());
        assert!(store.uninstall("..\\escape").is_err());

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let v1 = release("1.0.0", b"binary-one", &key);
        install(&store, &v1, &key).unwrap();
        let path = store.verified_artifact_path(APP).unwrap();
        fs::write(path, b"swapped").unwrap();
        assert!(matches!(
            store.verified_artifact_path(APP),
            Err(InstallError::ArtifactMismatch)
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
