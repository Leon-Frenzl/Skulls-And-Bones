//! Publisher tooling for SB-MAP apps: key generation and signed single-object bundles.

use ed25519_dalek::SigningKey;
use std::path::Path;
use zeroize::Zeroize;

fn hex_seed(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// CVE-Threat: Publisher private key leakage via loose permissions or lingering memory.
// Analysis: The seed is the only secret that lets an attacker ship "trusted" apps.
// Hardening: create_new (no overwrite/follow), owner-only mode on Unix, seed zeroized after use.
pub fn keygen(out: &Path) -> Result<String, String> {
    use std::io::Write;
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let key = SigningKey::from_bytes(&seed);
    let mut encoded = hex_seed(&seed);
    seed.zeroize();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options
        .open(out)
        .and_then(|mut file| file.write_all(encoded.as_bytes()))
        .map_err(|error| format!("Cannot write {}: {error}", out.display()));
    encoded.zeroize();
    result?;
    Ok(hex::encode(key.verifying_key().to_bytes()))
}

fn load_key(path: &Path) -> Result<SigningKey, String> {
    let mut text = std::fs::read_to_string(path)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    let decoded = hex::decode(text.trim());
    text.zeroize();
    let mut seed: [u8; 32] = decoded
        .map_err(|_| "Key file must contain 64 hex characters".to_string())?
        .try_into()
        .map_err(|_| "Key file must contain 64 hex characters".to_string())?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

pub fn pack(manifest: &Path, artifact: &Path, key: &Path, out: &Path) -> Result<String, String> {
    let manifest_bytes = std::fs::read(manifest)
        .map_err(|error| format!("Cannot read {}: {error}", manifest.display()))?;
    let metadata = std::fs::metadata(artifact)
        .map_err(|error| format!("Cannot read {}: {error}", artifact.display()))?;
    if metadata.len() > sb_app_contract::install::MAX_ARTIFACT_BYTES as u64 {
        return Err("Artifact exceeds the size limit".into());
    }
    let artifact_bytes = std::fs::read(artifact)
        .map_err(|error| format!("Cannot read {}: {error}", artifact.display()))?;
    let bundle = sb_app_contract::install::pack_signed_bundle(
        &manifest_bytes,
        &artifact_bytes,
        &load_key(key)?,
    )
    .map_err(|error| error.to_string())?;
    std::fs::write(out, &bundle)
        .map_err(|error| format!("Cannot write {}: {error}", out.display()))?;
    Ok(format!("{} bytes", bundle.len()))
}

fn parse_principal_id(raw: &str) -> Result<sb_mesh::PrincipalId, String> {
    serde_json::from_value(serde_json::Value::String(raw.to_string()))
        .map_err(|error| format!("Invalid principal ID '{raw}': {error}"))
}

// CVE-Threat: Untrusted or tampered bundle registration / path traversal in drive root / TOCTOU
// overwrite of immutable catalog versions.
// Analysis: A catalog publisher supplies a bundle path, a drive root, and ACL principals.
// Hardening: Re-verify bundle signature + artifact SHA-256 against trusted publishers before
// touching the drive or catalog; confine destination under canonical drive_root; write with
// create_new(true); update catalog via CAS (compare_and_swap).
pub fn publish_to_catalog(
    bundle_path: &Path,
    drive_root: &Path,
    catalog_path: &Path,
    trusted_publishers_path: &Path,
    owner: &str,
    readers: &[String],
) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let max_bundle_bytes = (sb_app_contract::install::MAX_ARTIFACT_BYTES
        + sb_app_contract::MAX_MANIFEST_BYTES
        + 4096) as u64;
    let bundle_meta = std::fs::metadata(bundle_path)
        .map_err(|error| format!("Cannot inspect {}: {error}", bundle_path.display()))?;
    if bundle_meta.len() > max_bundle_bytes {
        return Err("Bundle exceeds the size limit".into());
    }
    let bundle_bytes = std::fs::read(bundle_path)
        .map_err(|error| format!("Cannot read {}: {error}", bundle_path.display()))?;
    let parsed =
        sb_app_contract::install::parse_bundle(&bundle_bytes).map_err(|e| e.to_string())?;
    let trusted_bytes = std::fs::read(trusted_publishers_path).map_err(|error| {
        format!(
            "Cannot read trusted publishers {}: {error}",
            trusted_publishers_path.display()
        )
    })?;
    let trusted = sb_app_contract::install::parse_trusted_publishers(&trusted_bytes)
        .map_err(|e| e.to_string())?;
    let verified =
        sb_app_contract::verify_signed_manifest(&parsed.manifest, &parsed.signature_hex, &trusted)
            .map_err(|e| e.to_string())?;
    let manifest = verified.manifest();
    let actual_artifact_digest =
        format!("sha256:{}", hex::encode(Sha256::digest(&parsed.artifact)));
    if actual_artifact_digest != manifest.client.artifact {
        return Err("Bundle artifact digest does not match signed manifest".into());
    }

    let owner_id = parse_principal_id(owner)?;
    let reader_ids: Vec<sb_mesh::PrincipalId> = readers
        .iter()
        .map(|reader| parse_principal_id(reader))
        .collect::<Result<_, _>>()?;

    let store = sb_mesh::MeshObjectCatalogStore::new(catalog_path);
    let expected_digest = store.digest()?;
    let mut catalog = store.load()?;
    if !catalog.directory.principals().contains_key(&owner_id) {
        return Err(format!(
            "Owner principal '{owner}' is not in catalog directory"
        ));
    }
    for reader_id in &reader_ids {
        if !catalog.directory.principals().contains_key(reader_id) {
            return Err(format!(
                "Reader principal '{reader_id:?}' is not in catalog directory"
            ));
        }
    }

    std::fs::create_dir_all(drive_root)
        .map_err(|error| format!("Cannot create drive root {}: {error}", drive_root.display()))?;
    let canonical_root = std::fs::canonicalize(drive_root).map_err(|error| {
        format!(
            "Cannot canonicalize drive root {}: {error}",
            drive_root.display()
        )
    })?;
    let app_dir = canonical_root.join("apps").join(&manifest.app_id);
    std::fs::create_dir_all(&app_dir)
        .map_err(|error| format!("Cannot create app directory {}: {error}", app_dir.display()))?;
    let canonical_app_dir = std::fs::canonicalize(&app_dir).map_err(|error| {
        format!(
            "Cannot canonicalize app directory {}: {error}",
            app_dir.display()
        )
    })?;
    if !canonical_app_dir.starts_with(&canonical_root) {
        return Err("Drive app directory escapes canonical drive root".into());
    }
    let file_name = format!("{}.sbapp", manifest.version);
    let locator = format!("apps/{}/{file_name}", manifest.app_id);
    let target_path = canonical_app_dir.join(&file_name);
    write_new_bundle(&target_path, &bundle_bytes)?;

    let object_id = sb_mesh::MeshObjectId::new(format!("app:{}", manifest.app_id))?;
    let version_id = sb_mesh::ObjectVersionId::new(format!("v:{}", manifest.version))?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let object_version = sb_mesh::ObjectVersion::from_content(
        version_id.clone(),
        &bundle_bytes,
        now_unix,
        owner_id.clone(),
        sb_mesh::PayloadReference {
            provider: "sb-drive".into(),
            locator: locator.clone(),
        },
    );

    if let Some(existing) = catalog.objects.get(&object_id) {
        if existing.owner != owner_id {
            let _ = std::fs::remove_file(&target_path);
            return Err("Existing catalog object belongs to a different owner".into());
        }
        if let Err(error) = catalog.add_version(&object_id, object_version) {
            let _ = std::fs::remove_file(&target_path);
            return Err(error);
        }
        if let Some(obj) = catalog.objects.get_mut(&object_id) {
            for reader_id in reader_ids {
                let already_granted = obj.acl.entries.iter().any(|ace| {
                    ace.principal == reader_id && ace.effect == sb_mesh::AclEffect::Allow
                });
                if !already_granted {
                    obj.acl.add_entry(
                        reader_id,
                        sb_mesh::AclEffect::Allow,
                        [
                            sb_mesh::ObjectPermission::Discover,
                            sb_mesh::ObjectPermission::List,
                            sb_mesh::ObjectPermission::Read,
                        ],
                        false,
                    );
                }
            }
        }
    } else {
        let mut object = sb_mesh::MeshObject::new(
            object_id.clone(),
            sb_mesh::MeshObjectKind::Blob {
                media_type: "application/vnd.sb.app-bundle".into(),
            },
            format!("{} {}", manifest.app_id, manifest.version),
            None,
            owner_id.clone(),
        );
        object.acl.inherit_from_parent = false;
        object.acl.add_entry(
            owner_id,
            sb_mesh::AclEffect::Allow,
            [
                sb_mesh::ObjectPermission::Discover,
                sb_mesh::ObjectPermission::List,
                sb_mesh::ObjectPermission::Read,
                sb_mesh::ObjectPermission::ReadVersions,
                sb_mesh::ObjectPermission::ManageAcl,
            ],
            false,
        );
        for reader_id in reader_ids {
            object.acl.add_entry(
                reader_id,
                sb_mesh::AclEffect::Allow,
                [
                    sb_mesh::ObjectPermission::Discover,
                    sb_mesh::ObjectPermission::List,
                    sb_mesh::ObjectPermission::Read,
                ],
                false,
            );
        }
        object.current_version = Some(version_id.clone());
        object.versions.push(object_version);
        if let Err(error) = catalog.insert_object(object) {
            let _ = std::fs::remove_file(&target_path);
            return Err(error);
        }
    }

    if let Err(error) = store.compare_and_swap(expected_digest.as_deref(), &catalog) {
        let _ = std::fs::remove_file(&target_path);
        return Err(error);
    }

    fn write_new_bundle(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("Cannot create {}: {error}", path.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("Cannot write {}: {error}", path.display()))
    }

    Ok(format!("{object_id}@{version_id} ({locator})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_pack_and_publish_to_catalog_creates_acl_readable_mesh_object() {
        let dir = std::env::temp_dir().join(format!("sb_publish_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("publisher.key");
        let public = keygen(&key_path).unwrap();
        assert_eq!(public.len(), 64);
        assert!(keygen(&key_path).is_err());

        let manifest = serde_json::json!({
            "schema_version": 1,
            "app_id": "org.skullsandbones.viewer",
            "version": "0.1.0",
            "publisher_key_id": "org.skullsandbones.publisher",
            "client": {"target": "windows-x86_64", "artifact": format!("sha256:{}", "0".repeat(64))},
            "services": [{"service_id": "org.skullsandbones.drive.api", "api_version": 1,
                "contract_digest": format!("sha256:{}", "b".repeat(64))}],
            "requested_capabilities": [{"service_id": "org.skullsandbones.drive.api",
                "operation": "object.read"}],
            "sandbox_profile": "native-client-default"
        });
        std::fs::write(dir.join("m.json"), manifest.to_string()).unwrap();
        std::fs::write(dir.join("app.bin"), b"payload").unwrap();
        let out = dir.join("app.sbapp");
        pack(&dir.join("m.json"), &dir.join("app.bin"), &key_path, &out).unwrap();

        let trusted_path = dir.join("trusted.json");
        std::fs::write(
            &trusted_path,
            serde_json::json!({ "org.skullsandbones.publisher": public }).to_string(),
        )
        .unwrap();

        let catalog_path = dir.join("object-catalog.json");
        let mut catalog = sb_mesh::MeshObjectCatalog::new("corp-mesh").unwrap();
        let owner = sb_mesh::PrincipalId::user("publisher").unwrap();
        let reader = sb_mesh::PrincipalId::user("alice").unwrap();
        let reader_device = sb_mesh::PrincipalId::device("alice-laptop").unwrap();
        catalog
            .directory
            .add_user(owner, "Publisher".into())
            .unwrap();
        catalog
            .directory
            .add_user(reader.clone(), "Alice".into())
            .unwrap();
        catalog
            .directory
            .add_device(
                reader_device,
                "Alice Laptop".into(),
                "alice-pubkey-hex".into(),
                Some(reader),
            )
            .unwrap();
        sb_mesh::MeshObjectCatalogStore::new(&catalog_path)
            .save(&catalog)
            .unwrap();

        let drive_root = dir.join("drive");
        let summary = publish_to_catalog(
            &out,
            &drive_root,
            &catalog_path,
            &trusted_path,
            "user:publisher",
            &["user:alice".to_string()],
        )
        .unwrap();
        assert!(summary.contains("app:org.skullsandbones.viewer@v:0.1.0"));
        assert!(
            publish_to_catalog(
                &out,
                &drive_root,
                &catalog_path,
                &trusted_path,
                "user:publisher",
                &["user:alice".to_string()],
            )
            .is_err(),
            "immutable version must not be overwritten"
        );

        let loaded = sb_mesh::MeshObjectCatalogStore::new(&catalog_path)
            .load()
            .unwrap();
        let visible = loaded
            .visible_summaries_for_authenticated_device("alice-pubkey-hex", 10)
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id.as_str(), "app:org.skullsandbones.viewer");
        assert!(visible[0].readable);
        assert_eq!(
            visible[0].version_id.as_ref().map(|v| v.as_str()),
            Some("v:0.1.0")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
