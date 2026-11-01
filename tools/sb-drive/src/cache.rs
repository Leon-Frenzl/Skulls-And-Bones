use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct GhostCache {
    base_dir: PathBuf,
}

impl Default for GhostCache {
    fn default() -> Self {
        let dir = dirs::home_dir()
            .map(|h| h.join(".sb-drive").join("cache"))
            .unwrap_or_else(|| PathBuf::from(".sb-drive-cache"));
        Self::new(dir)
    }
}

impl GhostCache {
    pub fn new<P: Into<PathBuf>>(base_dir: P) -> Self {
        let dir = base_dir.into();
        let _ = fs::create_dir_all(&dir);
        Self { base_dir: dir }
    }

    /// Legt einen ephemeren lokalen Dateipfad für eine Remote-Mesh-Ressource an
    pub fn cache_path(&self, origin_peer: &str, remote_path: &str) -> PathBuf {
        let clean_peer = origin_peer.trim_start_matches('@');
        let normalized_path = remote_path
            .trim_start_matches('/')
            .replace(['/', '\\'], "_");
        let folder = self.base_dir.join(clean_peer);
        let _ = fs::create_dir_all(&folder);
        folder.join(normalized_path)
    }

    /// Schreibt empfangene Chunks/Bytes in den lokalen Ghost-Cache
    pub fn write_file(
        &self,
        origin_peer: &str,
        remote_path: &str,
        data: &[u8],
    ) -> Result<PathBuf, String> {
        let path = self.cache_path(origin_peer, remote_path);
        fs::write(&path, data).map_err(|e| {
            format!(
                "Fehler beim Schreiben des Ghost-Cache für {:?}: {}",
                path, e
            )
        })?;
        Ok(path)
    }

    /// Berechnet den SHA256-Hash einer Datei im Cache zur Integritäts- und Änderungsprüfung
    pub fn hash_cached_file<P: AsRef<Path>>(path: P) -> Result<String, String> {
        let bytes =
            fs::read(path.as_ref()).map_err(|e| format!("Fehler beim Lesen für SHA256: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghost_cache_write_and_hash() {
        let temp_dir = std::env::temp_dir().join("sb_drive_test_cache");
        let cache = GhostCache::new(&temp_dir);

        let data = b"Hello Sovereign Mesh World! Bilanzen 2026";
        let path = cache
            .write_file("finance-nas", "q1_bilanz.xlsx", data)
            .expect("write ok");
        assert!(path.exists());

        let hash = GhostCache::hash_cached_file(&path).expect("hash ok");
        assert_eq!(hash.len(), 64);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
