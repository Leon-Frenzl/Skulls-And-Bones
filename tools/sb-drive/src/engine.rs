use crate::cache::GhostCache;
use crate::launcher::HostLauncher;
use sb_mesh::rbac::{MeshRbacStore, SovereignPermissions};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveFileMetadata {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub modified_at: u64,
}

#[derive(Default)]
pub struct GhostEngine {
    pub cache: GhostCache,
}

impl GhostEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Führt den 'Ghost Launch' einer Mesh-Datei aus:
    /// 1. Prüft NTFS-inspirierte ACLs im Mesh-RBAC (darf der User lesen?).
    /// 2. Schreibt Daten in den lokalen ephemeren Ghost-Cache.
    /// 3. Startet die native Host-OS Standard-Anwendung (z. B. Word, Excel, VS Code).
    pub fn ghost_launch(
        &self,
        origin_peer: &str,
        remote_path: &str,
        data: &[u8],
        user: &str,
        groups: &[String],
        mesh_name: &str,
    ) -> Result<PathBuf, String> {
        // 1. ACL Check
        let rbac = MeshRbacStore::load_or_create(mesh_name)
            .map_err(|e| format!("RBAC Load Error: {}", e))?;
        let resource_key = format!("{}:{}", origin_peer.trim_start_matches('@'), remote_path);

        // Falls eine ACL für diesen Pfad existiert, prüfen wir strikt nach NTFS-Regeln
        if let Some(acl) = rbac.get_resource_acl(&resource_key) {
            let required = SovereignPermissions::read_only();
            if !acl.check_access(user, groups, &required) {
                return Err(format!(
                    "Zugriff verweigert (NTFS-ACL Deny): Nutzer '{}' darf '{}' nicht lesen.",
                    user, resource_key
                ));
            }
        }

        // 2. Cache Write
        let local_cached = self.cache.write_file(origin_peer, remote_path, data)?;

        // 3. Native App Launch
        HostLauncher::open_with_default_app(&local_cached)?;

        Ok(local_cached)
    }

    /// Überwacht eine Datei auf lokale Änderungen nach dem Bearbeiten in Word/Excel
    /// Berechnet bei Speicherung die FastCDC Chunks für den Delta-Push
    pub fn detect_changes_and_chunk<P: AsRef<Path>>(
        &self,
        cached_path: P,
        original_hash: &str,
    ) -> Result<Option<(String, Vec<sb_code::fastcdc::Chunk>)>, String> {
        let current_hash = GhostCache::hash_cached_file(cached_path.as_ref())?;
        if current_hash == original_hash {
            return Ok(None); // Keine Änderungen
        }

        // Datei wurde in nativer Host-App geändert! FastCDC Zerlegung durchführen
        let content = std::fs::read(cached_path.as_ref())
            .map_err(|e| format!("Fehler beim Lesen der geänderten Datei: {}", e))?;

        let chunker = sb_code::fastcdc::FastCdc::with_default();
        let chunks = chunker.chunk_slice(&content);

        Ok(Some((current_hash, chunks)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghost_engine_change_detection_with_fastcdc() {
        let temp_dir = std::env::temp_dir().join("sb_drive_engine_test");
        let cache = GhostCache::new(&temp_dir);
        let engine = GhostEngine { cache };

        let original_data = b"Initial Invoice Data 2026";
        let path = engine
            .cache
            .write_file("test-peer", "invoice.txt", original_data)
            .unwrap();
        let orig_hash = GhostCache::hash_cached_file(&path).unwrap();

        // 1. Unchanged check
        let no_change = engine.detect_changes_and_chunk(&path, &orig_hash).unwrap();
        assert!(no_change.is_none());

        // 2. Simulate User modifying the file in Word/Editor
        std::fs::write(
            &path,
            b"Modified Invoice Data 2026 - Approved by Management!",
        )
        .unwrap();

        let changed = engine.detect_changes_and_chunk(&path, &orig_hash).unwrap();
        assert!(changed.is_some());
        let (new_hash, chunks) = changed.unwrap();
        assert_ne!(new_hash, orig_hash);
        assert!(!chunks.is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
