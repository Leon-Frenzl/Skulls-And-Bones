use crate::objects::{MeshObjectCatalog, OBJECT_MODEL_SCHEMA_VERSION};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CATALOG_SIZE_BYTES: u64 = 64 * 1024 * 1024;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct MeshObjectCatalogStore {
    path: PathBuf,
}

impl MeshObjectCatalogStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<MeshObjectCatalog, String> {
        let file = File::open(&self.path)
            .map_err(|error| format!("Failed to open object catalog {:?}: {error}", self.path))?;
        let mut content = Vec::new();
        file.take(MAX_CATALOG_SIZE_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|error| format!("Failed to read object catalog {:?}: {error}", self.path))?;
        if content.len() as u64 > MAX_CATALOG_SIZE_BYTES {
            return Err(format!(
                "Object catalog {:?} exceeds the maximum size of {MAX_CATALOG_SIZE_BYTES} bytes",
                self.path
            ));
        }

        let value: Value = serde_json::from_slice(&content).map_err(|error| {
            format!(
                "Object catalog {:?} contains invalid JSON: {error}",
                self.path
            )
        })?;
        let schema_version = value
            .get("schema_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("Object catalog {:?} has no valid schema_version", self.path))?;
        if schema_version != u64::from(OBJECT_MODEL_SCHEMA_VERSION) {
            return Err(format!(
                "Object catalog {:?} uses unsupported schema version {schema_version}; supported version is {OBJECT_MODEL_SCHEMA_VERSION}",
                self.path
            ));
        }

        let catalog: MeshObjectCatalog = serde_json::from_value(value).map_err(|error| {
            format!(
                "Object catalog {:?} does not match schema version {OBJECT_MODEL_SCHEMA_VERSION}: {error}",
                self.path
            )
        })?;
        catalog.validate().map_err(|error| {
            format!("Object catalog {:?} failed validation: {error}", self.path)
        })?;
        Ok(catalog)
    }

    pub fn digest(&self) -> Result<Option<String>, String> {
        self.load_optional()?
            .map(|catalog| catalog_digest(&catalog))
            .transpose()
    }

    pub fn compare_and_swap(
        &self,
        expected_digest: Option<&str>,
        replacement: &MeshObjectCatalog,
    ) -> Result<String, String> {
        replacement
            .validate()
            .map_err(|error| format!("Refusing to apply invalid object catalog: {error}"))?;
        let replacement_digest = catalog_digest(replacement)?;

        let _lock = self.acquire_write_lock()?;
        let current_digest = self
            .load_optional()?
            .as_ref()
            .map(catalog_digest)
            .transpose()?;
        if current_digest.as_deref() != expected_digest {
            return Err(format!(
                "Catalog conflict: expected base digest {}, current digest {}",
                expected_digest.unwrap_or("absent"),
                current_digest.as_deref().unwrap_or("absent")
            ));
        }

        self.save_unlocked(replacement)?;
        Ok(replacement_digest)
    }

    pub fn save(&self, catalog: &MeshObjectCatalog) -> Result<(), String> {
        catalog
            .validate()
            .map_err(|error| format!("Refusing to save invalid object catalog: {error}"))?;
        let _lock = self.acquire_write_lock()?;
        self.save_unlocked(catalog)
    }

    fn save_unlocked(&self, catalog: &MeshObjectCatalog) -> Result<(), String> {
        let content = serde_json::to_vec_pretty(catalog)
            .map_err(|error| format!("Failed to serialize object catalog: {error}"))?;
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create object catalog directory {:?}: {error}",
                parent
            )
        })?;

        let temporary_path = self.temporary_path()?;
        let mut temporary_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| {
                format!(
                    "Failed to create temporary object catalog {:?}: {error}",
                    temporary_path
                )
            })?;

        if let Err(error) = temporary_file
            .write_all(&content)
            .and_then(|()| temporary_file.sync_all())
        {
            drop(temporary_file);
            return Err(self.cleanup_temp_after_error(
                &temporary_path,
                format!("Failed to write temporary object catalog: {error}"),
            ));
        }
        drop(temporary_file);

        if let Err(error) = fs::rename(&temporary_path, &self.path) {
            return Err(self.cleanup_temp_after_error(
                &temporary_path,
                format!(
                    "Failed to atomically replace object catalog {:?}: {error}",
                    self.path
                ),
            ));
        }
        Ok(())
    }

    pub fn load_optional(&self) -> Result<Option<MeshObjectCatalog>, String> {
        match fs::metadata(&self.path) {
            Ok(_) => self.load().map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "Failed to inspect object catalog {:?}: {error}",
                self.path
            )),
        }
    }

    fn acquire_write_lock(&self) -> Result<CatalogWriteLock, String> {
        let lock_path = lock_path(&self.path);
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create object catalog directory {:?}: {error}",
                parent
            )
        })?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(file) => {
                    drop(file);
                    return Ok(CatalogWriteLock { path: lock_path });
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(format!(
                        "Timed out waiting for object catalog write lock {:?}",
                        lock_path
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "Failed to acquire object catalog write lock {:?}: {error}",
                        lock_path
                    ));
                }
            }
        }
    }

    fn temporary_path(&self) -> Result<PathBuf, String> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let filename = self
            .path
            .file_name()
            .ok_or_else(|| format!("Object catalog path {:?} has no file name", self.path))?;
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(parent.join(format!(
            ".{}.{}.{}.tmp",
            filename.to_string_lossy(),
            std::process::id(),
            sequence
        )))
    }

    fn cleanup_temp_after_error(&self, temporary_path: &Path, message: String) -> String {
        match fs::remove_file(temporary_path) {
            Ok(()) => message,
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => message,
            Err(cleanup_error) => format!(
                "{message}; additionally failed to remove temporary file {:?}: {cleanup_error}",
                temporary_path
            ),
        }
    }
}

struct CatalogWriteLock {
    path: PathBuf,
}

impl Drop for CatalogWriteLock {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                let p = self.path.display().to_string();
                let e = error.to_string();
                sb_core::logfmt::warn(
                    "ERR_CATALOG_LOCK_CLEANUP",
                    "mesh.object_store",
                    "Failed to remove object catalog write lock",
                    &[("path", &p), ("error", &e)],
                );
            }
        }
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn catalog_digest(catalog: &MeshObjectCatalog) -> Result<String, String> {
    let bytes = serde_json::to_vec(catalog)
        .map_err(|error| format!("Failed to serialize object catalog for digest: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::PrincipalId;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sb-mesh-object-store-{}-{nonce}",
            std::process::id()
        ))
    }

    fn catalog() -> MeshObjectCatalog {
        let mut catalog = MeshObjectCatalog::new("store-test").unwrap();
        let user = PrincipalId::user("alice").unwrap();
        catalog
            .directory
            .add_user(user, "Alice".to_string())
            .unwrap();
        catalog
    }

    #[test]
    fn catalog_round_trips_and_replaces_atomically() {
        let directory = test_directory();
        let store = MeshObjectCatalogStore::new(directory.join("nested").join("catalog.json"));
        let mut first = catalog();
        store.save(&first).unwrap();
        assert_eq!(store.load().unwrap(), first);

        first.mesh_id = "updated".to_string();
        store.save(&first).unwrap();
        assert_eq!(store.load().unwrap(), first);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compare_and_swap_requires_the_exact_current_digest() {
        let directory = test_directory();
        let store = MeshObjectCatalogStore::new(directory.join("catalog.json"));
        let first = catalog();
        assert_eq!(store.digest().unwrap(), None);

        let first_digest = store.compare_and_swap(None, &first).unwrap();
        assert_eq!(
            store.digest().unwrap().as_deref(),
            Some(first_digest.as_str())
        );

        let mut second = first.clone();
        second.mesh_id = "store-test-updated".to_string();
        assert!(store
            .compare_and_swap(None, &second)
            .unwrap_err()
            .contains("Catalog conflict"));
        assert_eq!(store.load().unwrap(), first);

        let second_digest = store
            .compare_and_swap(Some(&first_digest), &second)
            .unwrap();
        assert_eq!(
            store.digest().unwrap().as_deref(),
            Some(second_digest.as_str())
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unsupported_schema_and_invalid_catalog_are_rejected() {
        let directory = test_directory();
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("catalog.json");
        let store = MeshObjectCatalogStore::new(&path);

        fs::write(&path, r#"{"schema_version":2}"#).unwrap();
        assert!(store
            .load()
            .unwrap_err()
            .contains("unsupported schema version"));

        let mut invalid = catalog();
        invalid.schema_version = OBJECT_MODEL_SCHEMA_VERSION + 1;
        assert!(store
            .save(&invalid)
            .unwrap_err()
            .contains("invalid object catalog"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn corrupt_or_oversized_catalog_is_not_replaced_by_a_default() {
        let directory = test_directory();
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("catalog.json");
        let store = MeshObjectCatalogStore::new(&path);
        fs::write(&path, b"{").unwrap();
        assert!(store.load().unwrap_err().contains("invalid JSON"));

        let oversized = vec![b' '; (MAX_CATALOG_SIZE_BYTES + 1) as usize];
        fs::write(&path, oversized).unwrap();
        assert!(store
            .load()
            .unwrap_err()
            .contains("exceeds the maximum size"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn versioned_file_with_invalid_mesh_id_is_rejected() {
        let directory = test_directory();
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("catalog.json");
        let store = MeshObjectCatalogStore::new(&path);
        let mut value = serde_json::to_value(catalog()).unwrap();
        value["mesh_id"] = serde_json::Value::String("bad/id".to_string());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(store.load().unwrap_err().contains("failed validation"));
        fs::remove_dir_all(directory).unwrap();
    }
}
