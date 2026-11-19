//! Multi-Meshing & User-Space VRF (Virtual Routing and Forwarding)
//! Ermöglicht den gleichzeitigen Betrieb mehrerer isolierter, benannter Overlay-Netzwerke
//! mit hermetischen Routing-Tabellen und Zero Cross-Talk.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::proxy::ip_matches_cidr;

/// Definition eines benannten, isolierten Overlay-Netzwerks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshNetwork {
    pub name: String,
    pub description: String,
    pub swarm_topic: String,
    pub overlay_subnet: String,
    pub listen_port: u16,
    pub wireguard_pubkey: String,
    pub psk: Option<String>,
    pub created_at: String,
    pub last_active_at: String,
}

impl MeshNetwork {
    pub fn new(
        name: &str,
        description: &str,
        overlay_subnet: &str,
        wireguard_pubkey: &str,
        swarm_topic: Option<&str>,
        psk: Option<String>,
        listen_port: Option<u16>,
    ) -> Result<Self, String> {
        let clean_name = name.trim().to_lowercase();
        crate::state::normalize_mesh_name(&clean_name)?;

        if !validate_cidr(overlay_subnet) {
            return Err(format!(
                "Ungültiges IPv4-CIDR Subnetz: '{}'. Erwartet z. B. '10.42.0.0/16'",
                overlay_subnet
            ));
        }

        let now = Utc::now().to_rfc3339();
        let topic = swarm_topic
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("sbm-swarm-{}", clean_name));

        Ok(Self {
            name: clean_name,
            description: description.to_string(),
            swarm_topic: topic,
            overlay_subnet: overlay_subnet.to_string(),
            listen_port: listen_port.unwrap_or(58888),
            wireguard_pubkey: wireguard_pubkey.to_string(),
            psk,
            created_at: now.clone(),
            last_active_at: now,
        })
    }

    /// Prüft, ob eine Ziel-IP innerhalb des hermetischen Subnets dieses Netzwerks liegt
    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        ip_matches_cidr(ip, &self.overlay_subnet)
    }
}

/// Validiert IPv4 CIDR-Format (z. B. "10.42.0.0/16")
pub fn validate_cidr(cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    if parts[0].parse::<Ipv4Addr>().is_err() {
        return false;
    }
    match parts[1].parse::<u8>() {
        Ok(prefix) => prefix <= 32,
        Err(_) => false,
    }
}

/// Inklusiver (start, end) u32-Adressbereich eines IPv4 CIDR
pub fn cidr_range(cidr: &str) -> Option<(u32, u32)> {
    if !validate_cidr(cidr) {
        return None;
    }
    let (ip, prefix) = cidr.split_once('/')?;
    let ip = u32::from(ip.parse::<Ipv4Addr>().ok()?);
    let prefix: u32 = prefix.parse().ok()?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((ip & mask, (ip & mask) | !mask))
}

/// JSON-Persistenzstruktur für Netzwerke
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworksFile {
    pub active_network: String,
    pub networks: HashMap<String, MeshNetwork>,
}

/// Zentraler Store zur Verwaltung isolierter Multi-Mesh Netzwerke
#[derive(Debug, Clone)]
pub struct NetworkStore {
    pub path: PathBuf,
    pub active_network: String,
    pub networks: HashMap<String, MeshNetwork>,
}

impl NetworkStore {
    /// Lädt den Store oder erzeugt das 'default' Netzwerk (10.240.0.0/16)
    pub fn load_or_create_default(path: &Path, default_pubkey: &str) -> Result<Self, String> {
        match path.symlink_metadata() {
            Ok(_) => return Self::load_existing(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Mesh network catalog could not be inspected: {error}"
                ))
            }
        }

        // Default Netzwerk initialisieren
        let default_net = MeshNetwork::new(
            "default",
            "Standard Sovereign Overlay",
            "10.240.0.0/16",
            default_pubkey,
            Some("sbm-swarm-default"),
            None,
            Some(58888),
        )?;

        let mut networks = HashMap::new();
        networks.insert("default".to_string(), default_net);

        let store = Self {
            path: path.to_path_buf(),
            active_network: "default".to_string(),
            networks,
        };
        store.save()?;
        Ok(store)
    }

    pub fn load_existing(path: &Path) -> Result<Self, String> {
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("Konnte networks.json nicht prüfen: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("Network catalog path must not be a symbolic link".to_string());
        }
        if !metadata.is_file() {
            return Err("Network catalog path must be a regular file".to_string());
        }
        let content = fs::read_to_string(path)
            .map_err(|error| format!("Konnte networks.json nicht lesen: {error}"))?;
        let clean = content.trim_start_matches('\u{feff}');
        let mut file: NetworksFile = serde_json::from_str(clean)
            .map_err(|error| format!("Ungültiges networks.json: {error}"))?;
        if file.networks.is_empty() || !file.networks.contains_key(&file.active_network) {
            return Err("Mesh network catalog has no valid active network".to_string());
        }
        let base_dir = path
            .parent()
            .ok_or_else(|| "Mesh network catalog has no parent directory".to_string())?;
        for (key, network) in &mut file.networks {
            crate::state::normalize_mesh_name(key)?;
            crate::state::normalize_mesh_name(&network.name)?;
            if key != &network.name {
                return Err(format!(
                    "Network key '{}' does not match network name '{}'",
                    key, network.name
                ));
            }
            let paths = crate::state::MeshStatePaths::for_mesh_at(base_dir, key)?;
            match paths.psk.symlink_metadata() {
                Ok(_) => {
                    paths.ensure()?;
                    if let Some(psk) = Self::read_private_psk(&paths.psk)? {
                        if network.psk.as_ref().is_some_and(|legacy| legacy != &psk) {
                            return Err(format!(
                                "PSK-Datei und Legacy-Katalogwert für Mesh '{}' stimmen nicht überein",
                                key
                            ));
                        }
                        network.psk = Some(psk);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "PSK-Pfad für Mesh '{}' konnte nicht geprüft werden: {error}",
                        key
                    ))
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            active_network: file.active_network,
            networks: file.networks,
        })
    }

    /// Speichert den aktuellen Zustand atomar auf der Festplatte
    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("Mesh-Katalogverzeichnis konnte nicht erstellt werden: {error}")
            })?;
        }

        let mut file = NetworksFile {
            active_network: self.active_network.clone(),
            networks: self.networks.clone(),
        };
        let base_dir = self
            .path
            .parent()
            .ok_or_else(|| "Mesh network catalog has no parent directory".to_string())?;
        for (mesh_name, network) in &mut file.networks {
            let Some(legacy_psk) = network.psk.as_ref() else {
                continue;
            };
            let paths = crate::state::MeshStatePaths::for_mesh_at(base_dir, mesh_name)?;
            match paths.psk.symlink_metadata() {
                Ok(_) => {
                    paths.ensure()?;
                    let sidecar = Self::read_private_psk(&paths.psk)?.ok_or_else(|| {
                        format!("PSK-Datei für Mesh '{}' ist nicht verfügbar", mesh_name)
                    })?;
                    if &sidecar != legacy_psk {
                        return Err(format!(
                            "PSK-Datei und Katalogwert für Mesh '{}' stimmen nicht überein",
                            mesh_name
                        ));
                    }
                    network.psk = None;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "PSK-Pfad für Mesh '{}' konnte nicht geprüft werden: {error}",
                        mesh_name
                    ))
                }
            }
        }

        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| format!("Fehler beim Serialisieren der Netzwerke: {}", e))?;

        Self::atomic_write(&self.path, content.as_bytes())
            .map_err(|e| format!("Fehler beim Schreiben von networks.json: {}", e))?;
        Ok(())
    }

    /// Moves legacy catalog PSKs into verified, owner-only per-mesh files.
    /// The shared catalog is only cleared after every sidecar has been written and read back.
    pub fn migrate_psks(&mut self) -> Result<usize, String> {
        // CVE-Threat: Secret disclosure or irreversible loss during catalog-to-sidecar migration.
        // Analysis: Partial copies and conflicting existing secrets must never clear the source values.
        // Hardening: Create/verify all private sidecars first, then atomically replace the shared catalog.
        let base_dir = self
            .path
            .parent()
            .ok_or_else(|| "Mesh network catalog has no parent directory".to_string())?;
        let secrets: Vec<(String, String)> = self
            .networks
            .iter()
            .filter_map(|(name, network)| {
                network.psk.as_ref().map(|psk| (name.clone(), psk.clone()))
            })
            .collect();
        if secrets.is_empty() {
            return Ok(0);
        }

        for (mesh_name, psk) in &secrets {
            let paths = crate::state::MeshStatePaths::for_mesh_at(base_dir, mesh_name)?;
            paths.ensure()?;
            Self::write_private_psk(&paths.psk, psk)?;
            if Self::read_private_psk(&paths.psk)?.as_ref() != Some(psk) {
                return Err(format!(
                    "PSK-Verifikation für Mesh '{}' fehlgeschlagen; Katalog wurde nicht geändert",
                    mesh_name
                ));
            }
        }

        for network in self.networks.values_mut() {
            network.psk = None;
        }
        let save_result = self.save();
        for (mesh_name, psk) in &secrets {
            if let Some(network) = self.networks.get_mut(mesh_name) {
                network.psk = Some(psk.clone());
            }
        }
        save_result?;
        Ok(secrets.len())
    }

    /// Liefert das aktuell aktive Netzwerk
    pub fn get_active(&self) -> &MeshNetwork {
        self.networks
            .get(&self.active_network)
            .or_else(|| self.networks.get("default"))
            .expect("Mindestens ein Netzwerk (default) muss existieren")
    }

    fn read_private_psk(path: &Path) -> Result<Option<String>, String> {
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("PSK-Datei konnte nicht geprüft werden: {error}")),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "PSK-Pfad muss eine reguläre Datei ohne Symlink sein: {}",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "PSK-Datei besitzt zu offene Berechtigungen: {}",
                    path.display()
                ));
            }
        }
        fs::read_to_string(path)
            .map(Some)
            .map_err(|error| format!("PSK-Datei konnte nicht gelesen werden: {error}"))
    }

    fn write_private_psk(path: &Path, psk: &str) -> Result<(), String> {
        // CVE-Threat: Symlink clobbering or disclosure through permissive PSK file modes.
        // Analysis: An existing path may be attacker-controlled; ordinary create/write can follow links.
        // Hardening: Reject links, use create_new, and enforce owner-only Unix permissions.
        match path.symlink_metadata() {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(format!(
                        "PSK-Pfad muss eine reguläre Datei ohne Symlink sein: {}",
                        path.display()
                    ));
                }
                let existing = fs::read_to_string(path).map_err(|error| {
                    format!("Vorhandene PSK-Datei konnte nicht gelesen werden: {error}")
                })?;
                if existing != psk {
                    return Err(format!(
                        "Vorhandene PSK-Datei für Mesh '{}' weicht vom Katalog ab",
                        path.parent()
                            .and_then(Path::file_name)
                            .and_then(|name| name.to_str())
                            .unwrap_or("<unbekannt>")
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(
                        |error| format!("PSK-Dateirechte konnten nicht gesetzt werden: {error}"),
                    )?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(path).map_err(|error| {
                    format!("PSK-Datei konnte nicht sicher angelegt werden: {error}")
                })?;
                if let Err(error) = std::io::Write::write_all(&mut file, psk.as_bytes())
                    .and_then(|()| file.sync_all())
                {
                    let cleanup_error = fs::remove_file(path).err();
                    if let Some(cleanup_error) = cleanup_error {
                        return Err(format!(
                            "PSK-Datei konnte nicht geschrieben werden: {error}; unvollständige Datei {} konnte nicht entfernt werden: {cleanup_error}",
                            path.display()
                        ));
                    }
                    return Err(format!(
                        "PSK-Datei konnte nicht geschrieben werden: {error}"
                    ));
                }
                Ok(())
            }
            Err(error) => Err(format!("PSK-Pfad konnte nicht geprüft werden: {error}")),
        }
    }

    fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
        // CVE-Threat: Truncated or partially written network catalog during replacement.
        // Analysis: Directly overwriting the only catalog can destroy metadata on write failure.
        // Hardening: Flush a unique same-directory file before atomic rename.
        use std::io::Write;

        let parent = path
            .parent()
            .ok_or_else(|| "Atomic file path has no parent directory".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create catalog directory: {error}"))?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "Atomic file path has an invalid name".to_string())?;
        let temp_path = parent.join(format!(".{file_name}.tmp-{}", rand::random::<u64>()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .map_err(|error| format!("Could not create catalog temp file: {error}"))?;
        if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
            let cleanup_error = fs::remove_file(&temp_path).err();
            if let Some(cleanup_error) = cleanup_error {
                return Err(format!(
                    "Could not write catalog temp file: {error}; temporary file {} could not be removed: {cleanup_error}",
                    temp_path.display()
                ));
            }
            return Err(format!("Could not write catalog temp file: {error}"));
        }
        drop(file);
        if let Err(error) = fs::rename(&temp_path, path) {
            let cleanup_error = fs::remove_file(&temp_path).err();
            if let Some(cleanup_error) = cleanup_error {
                return Err(format!(
                    "Could not atomically replace catalog: {error}; temporary file {} could not be removed: {cleanup_error}",
                    temp_path.display()
                ));
            }
            return Err(format!("Could not atomically replace catalog: {error}"));
        }
        Ok(())
    }

    /// Schaltet das aktive Overlay-Netzwerk um
    pub fn switch_network(&mut self, name: &str) -> Result<MeshNetwork, String> {
        let clean = name.trim().to_lowercase();
        if let Some(net) = self.networks.get_mut(&clean) {
            net.last_active_at = Utc::now().to_rfc3339();
            self.active_network = clean;
            let current = net.clone();
            self.save()?;
            Ok(current)
        } else {
            Err(format!(
                "Netzwerk '{}' existiert nicht. Verfügbare Netze: {}",
                name,
                self.list()
                    .into_iter()
                    .map(|n| n.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    }

    /// Erstellt ein neues isoliertes Overlay-Netzwerk
    #[allow(clippy::too_many_arguments)]
    pub fn create_network(
        &mut self,
        name: &str,
        description: &str,
        overlay_subnet: &str,
        wireguard_pubkey: &str,
        swarm_topic: Option<&str>,
        psk: Option<String>,
        listen_port: Option<u16>,
    ) -> Result<MeshNetwork, String> {
        let clean = name.trim().to_lowercase();
        if self.networks.contains_key(&clean) {
            return Err(format!("Netzwerk '{}' existiert bereits.", clean));
        }

        let net = MeshNetwork::new(
            &clean,
            description,
            overlay_subnet,
            wireguard_pubkey,
            swarm_topic,
            psk,
            listen_port,
        )?;

        // CVE-Threat: Cross-mesh traffic leakage / routing ambiguity via overlapping overlay CIDRs.
        // Analysis: Two meshes sharing a range make overlay IP -> mesh resolution ambiguous.
        // Hardening: Reject creation when the range overlaps any existing network.
        if let Some(other) = self.find_overlap(overlay_subnet) {
            return Err(format!(
                "CIDR {} überlappt mit Netzwerk '{}' ({}). Nächster freier Bereich: {}",
                overlay_subnet,
                other.name,
                other.overlay_subnet,
                self.next_free_cidr().unwrap_or_else(|| "keiner".into())
            ));
        }

        self.networks.insert(clean, net.clone());
        self.save()?;
        Ok(net)
    }

    /// Liefert ein bestehendes Netzwerk, dessen Subnetz sich mit `cidr` überlappt
    pub fn find_overlap(&self, cidr: &str) -> Option<&MeshNetwork> {
        let a = cidr_range(cidr)?;
        self.networks
            .values()
            .find(|n| cidr_range(&n.overlay_subnet).is_some_and(|b| a.0 <= b.1 && b.0 <= a.1))
    }

    /// Nächster freier /16 aus 10.240.0.0/12 (10.240–10.255)
    pub fn next_free_cidr(&self) -> Option<String> {
        (240u8..=255)
            .map(|o| format!("10.{}.0.0/16", o))
            .find(|c| self.find_overlap(c).is_none())
    }

    /// Löscht ein Netzwerk (geschützt gegen Löschen von 'default' und dem aktiven Netz)
    pub fn delete_network(&mut self, name: &str) -> Result<(), String> {
        let clean = name.trim().to_lowercase();
        if clean == "default" {
            return Err("Das Standard-Netzwerk 'default' kann nicht gelöscht werden.".to_string());
        }
        if self.active_network == clean {
            return Err(format!(
                "Netzwerk '{}' ist aktuell aktiv. Bitte zuerst auf ein anderes Netz umschalten ('sb-mesh network switch default').",
                clean
            ));
        }
        if self.networks.remove(&clean).is_none() {
            return Err(format!("Netzwerk '{}' existiert nicht.", clean));
        }
        self.save()?;
        Ok(())
    }

    /// Gibt alle Netzwerke sortiert zurück
    pub fn list(&self) -> Vec<&MeshNetwork> {
        let mut list: Vec<&MeshNetwork> = self.networks.values().collect();
        list.sort_by(|a, b| {
            if a.name == "default" {
                std::cmp::Ordering::Less
            } else if b.name == "default" {
                std::cmp::Ordering::Greater
            } else {
                a.name.cmp(&b.name)
            }
        });
        list
    }

    /// User-Space VRF Boundary Check:
    /// Stellt sicher, dass das übergebene Paket innerhalb des aktiven Netzwerks bleibt
    /// und verwirft Pakete, die für andere isolierte Mesh-Subnetze bestimmt sind.
    pub fn validate_vrf_boundary(&self, dest_ip: Ipv4Addr) -> Result<(), String> {
        let active = self.get_active();
        if active.contains_ip(dest_ip) {
            return Ok(());
        }

        // Prüfe, ob es in ein anderes existierendes Mesh gehört (Cross-Talk Versuch)
        for (other_name, other_net) in &self.networks {
            if other_name != &self.active_network && other_net.contains_ip(dest_ip) {
                return Err(format!(
                    "VRF Isolation Violation: Paket an {} blockiert (gehört zu getrenntem Mesh '{}', aktiv ist '{}').",
                    dest_ip, other_name, self.active_network
                ));
            }
        }

        // Falls die IP in gar keinem Mesh ist
        Err(format!(
            "VRF Routing Error: Ziel-IP {} liegt außerhalb des aktiven Subnetzes {} ('{}').",
            dest_ip, active.overlay_subnet, active.name
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sbm_test_{}_{}",
            name,
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_cidr_overlap_detection() {
        let dir = create_test_dir("overlap");
        let path = dir.join("networks.json");
        let pk = "pk=";
        let mut store = NetworkStore::load_or_create_default(&path, pk).unwrap();
        assert!(store
            .create_network("dup", "d", "10.240.0.0/16", pk, None, None, None)
            .is_err());
        assert!(store
            .create_network("inner", "d", "10.240.5.0/24", pk, None, None, None)
            .is_err());
        assert_eq!(store.next_free_cidr().as_deref(), Some("10.241.0.0/16"));
        assert!(store
            .create_network("ok", "d", "10.241.0.0/16", pk, None, None, None)
            .is_ok());
        assert_eq!(store.next_free_cidr().as_deref(), Some("10.242.0.0/16"));
    }

    #[test]
    fn test_network_store_lifecycle() {
        let dir = create_test_dir("lifecycle");
        let path = dir.join("networks.json");
        let pubkey = "test_pubkey_base64_1234=";

        assert!(NetworkStore::load_existing(&path).is_err());
        assert!(!path.exists());

        // 1. Initial creation
        let mut store = NetworkStore::load_or_create_default(&path, pubkey).unwrap();
        assert_eq!(store.active_network, "default");
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.get_active().overlay_subnet, "10.240.0.0/16");

        // 2. Create new network
        let acme = store
            .create_network(
                "acme-dev",
                "Kunde ACME Dev Mesh",
                "10.42.0.0/16",
                pubkey,
                Some("sbm-swarm-acme-dev"),
                Some("custom_psk".to_string()),
                Some(58888),
            )
            .unwrap();
        assert_eq!(acme.name, "acme-dev");
        assert_eq!(store.list().len(), 2);

        // 3. Switch network
        let switched = store.switch_network("acme-dev").unwrap();
        assert_eq!(switched.name, "acme-dev");
        assert_eq!(store.active_network, "acme-dev");
        assert_eq!(store.get_active().overlay_subnet, "10.42.0.0/16");

        // 4. Persistence reload
        let reloaded = NetworkStore::load_existing(&path).unwrap();
        assert_eq!(reloaded.active_network, "acme-dev");
        assert_eq!(reloaded.list().len(), 2);

        // 5. Deletion protection on active network
        let del_active_err = store.delete_network("acme-dev");
        assert!(del_active_err.is_err());

        // 6. Switch back to default and delete acme-dev
        store.switch_network("default").unwrap();
        assert!(store.delete_network("acme-dev").is_ok());
        assert_eq!(store.list().len(), 1);

        // 7. Deletion protection on default network
        let del_def_err = store.delete_network("default");
        assert!(del_def_err.is_err());
    }

    #[test]
    fn legacy_psks_migrate_only_after_private_sidecars_are_verified() {
        let dir = create_test_dir("psk-migration");
        let catalog_path = dir.join("networks.json");
        let mut store = NetworkStore::load_or_create_default(&catalog_path, "default-key").unwrap();
        store
            .create_network(
                "acme",
                "ACME",
                "10.241.0.0/16",
                "acme-key",
                None,
                Some("sensitive-acme-psk".to_string()),
                None,
            )
            .unwrap();
        assert!(fs::read_to_string(&catalog_path)
            .unwrap()
            .contains("sensitive-acme-psk"));

        assert_eq!(store.migrate_psks().unwrap(), 1);
        let catalog_after_migration = fs::read_to_string(&catalog_path).unwrap();
        assert!(!catalog_after_migration.contains("sensitive-acme-psk"));
        let paths = crate::state::MeshStatePaths::for_mesh_at(&dir, "acme").unwrap();
        assert_eq!(
            NetworkStore::read_private_psk(&paths.psk)
                .unwrap()
                .as_deref(),
            Some("sensitive-acme-psk")
        );
        let mut reloaded =
            NetworkStore::load_or_create_default(&catalog_path, "default-key").unwrap();
        assert_eq!(
            reloaded.networks["acme"].psk.as_deref(),
            Some("sensitive-acme-psk")
        );
        reloaded.switch_network("default").unwrap();
        assert!(!fs::read_to_string(&catalog_path)
            .unwrap()
            .contains("sensitive-acme-psk"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn conflicting_psk_sidecar_preserves_legacy_catalog_value() {
        let dir = create_test_dir("psk-conflict");
        let catalog_path = dir.join("networks.json");
        let mut store = NetworkStore::load_or_create_default(&catalog_path, "default-key").unwrap();
        store
            .create_network(
                "acme",
                "ACME",
                "10.241.0.0/16",
                "acme-key",
                None,
                Some("catalog-secret".to_string()),
                None,
            )
            .unwrap();
        let paths = crate::state::MeshStatePaths::for_mesh_at(&dir, "acme").unwrap();
        paths.ensure().unwrap();
        fs::write(&paths.psk, "different-secret").unwrap();

        assert!(store.migrate_psks().is_err());
        assert!(fs::read_to_string(&catalog_path)
            .unwrap()
            .contains("catalog-secret"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_vrf_subnet_isolation_and_cross_talk_defense() {
        let dir = create_test_dir("vrf");
        let path = dir.join("networks.json");
        let pubkey = "test_pubkey_vrf=";

        let mut store = NetworkStore::load_or_create_default(&path, pubkey).unwrap();
        store
            .create_network(
                "bank-prod",
                "Banking Production Network",
                "10.43.0.0/16",
                pubkey,
                None,
                None,
                None,
            )
            .unwrap();

        // Active is 'default' (10.240.0.0/16)
        let valid_default_ip: Ipv4Addr = "10.240.1.5".parse().unwrap();
        let bank_ip: Ipv4Addr = "10.43.0.99".parse().unwrap();
        let external_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

        // 1. IP in active subnet must pass
        assert!(store.validate_vrf_boundary(valid_default_ip).is_ok());

        // 2. IP in bank-prod must be detected as Cross-Talk Violation and rejected!
        let bank_err = store.validate_vrf_boundary(bank_ip).unwrap_err();
        assert!(bank_err.contains("VRF Isolation Violation"));
        assert!(bank_err.contains("bank-prod"));

        // 3. Foreign IP must be rejected
        let ext_err = store.validate_vrf_boundary(external_ip).unwrap_err();
        assert!(ext_err.contains("VRF Routing Error"));

        // 4. Switch to bank-prod
        store.switch_network("bank-prod").unwrap();
        assert!(store.validate_vrf_boundary(bank_ip).is_ok());
        let def_err = store.validate_vrf_boundary(valid_default_ip).unwrap_err();
        assert!(def_err.contains("VRF Isolation Violation"));
    }

    #[test]
    fn test_cidr_validation() {
        assert!(validate_cidr("10.0.0.0/8"));
        assert!(validate_cidr("192.168.1.0/24"));
        assert!(validate_cidr("10.42.0.0/16"));
        assert!(validate_cidr("0.0.0.0/0"));

        assert!(!validate_cidr("10.0.0.0/33"));
        assert!(!validate_cidr("not_an_ip/24"));
        assert!(!validate_cidr("10.0.0.0"));
        assert!(!validate_cidr(""));
    }
}
