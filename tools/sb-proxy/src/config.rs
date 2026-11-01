use sb_code::escape::{
    validate_domain, validate_target_port, EscapeSpace, EscapeSpaceStore, EscapeStatus,
};

/// Proxy configuration manager integrated with S&B's persistent EscapeSpaceStore.
pub struct ProxyConfig;

impl ProxyConfig {
    /// Loads all configured escape spaces / proxy routes.
    pub fn load_spaces() -> Vec<EscapeSpace> {
        let store = EscapeSpaceStore::load();
        store.spaces
    }

    /// Finds a space by domain or ID.
    pub fn find_space(query: &str) -> Option<EscapeSpace> {
        let q = query.trim().to_lowercase();
        let store = EscapeSpaceStore::load();
        store
            .spaces
            .into_iter()
            .find(|s| s.id == q || s.domain.to_lowercase() == q)
    }

    /// Adds a new escape space proxy route.
    pub fn add_route(
        domain: &str,
        target_port: u16,
        node_callsign: &str,
    ) -> Result<EscapeSpace, String> {
        validate_target_port(target_port)?;
        let valid_domain = validate_domain(domain)?;
        let mut store = EscapeSpaceStore::load();
        store.add(&valid_domain, target_port, node_callsign)
    }

    /// Adds a Mesh-Tunnel route: traffic arrives via `sb proxy link` over the encrypted Mesh Stealth tunnel.
    /// The VPS Sovereign Tunnel Hub (loopback:58910) handles connections; no local port is required on the VPS.
    pub fn add_tunnel_route(domain: &str, node_callsign: &str) -> Result<EscapeSpace, String> {
        let valid_domain = validate_domain(domain)?;
        let mut store = EscapeSpaceStore::load();
        store.add_mesh_tunnel(&valid_domain, node_callsign)
    }

    /// Adds a public static-site route backed by an explicitly selected directory.
    pub fn add_static_site(
        domain: &str,
        root: &std::path::Path,
        node_callsign: &str,
    ) -> Result<EscapeSpace, String> {
        let canonical_root = std::fs::canonicalize(root).map_err(|error| {
            format!(
                "Statisches Verzeichnis {} kann nicht aufgelöst werden: {error}",
                root.display()
            )
        })?;
        if !canonical_root.is_dir() {
            return Err(format!(
                "Statisches Verzeichnis ist kein Ordner: {}",
                canonical_root.display()
            ));
        }
        let valid_domain = validate_domain(domain)?;
        let mut store = EscapeSpaceStore::load();
        store.add_static_site(
            &valid_domain,
            node_callsign,
            &canonical_root.to_string_lossy(),
        )
    }

    /// Removes a route by ID or domain.
    pub fn remove_route(query: &str) -> Result<bool, String> {
        let q = query.trim().to_lowercase();
        let mut store = EscapeSpaceStore::load();
        let id_opt = store
            .spaces
            .iter()
            .find(|s| s.id == q || s.domain.to_lowercase() == q)
            .map(|s| s.id.clone());
        if let Some(id) = id_opt {
            store.remove(&id)
        } else {
            Err(format!(
                "Keine Route mit Kennung oder Domain '{}' gefunden",
                query
            ))
        }
    }

    /// Sets status of a route (Active / Paused).
    pub fn set_status(query: &str, active: bool) -> Result<EscapeStatus, String> {
        let q = query.trim().to_lowercase();
        let mut store = EscapeSpaceStore::load();
        let found = store
            .spaces
            .iter_mut()
            .find(|s| s.id == q || s.domain.to_lowercase() == q);
        if let Some(space) = found {
            space.status = if active {
                EscapeStatus::Active
            } else {
                EscapeStatus::Paused
            };
            let status_clone = space.status.clone();
            store.save()?;
            Ok(status_clone)
        } else {
            Err(format!(
                "Keine Route mit Kennung oder Domain '{}' gefunden",
                query
            ))
        }
    }

    /// Sets maintenance mode for a route.
    pub fn set_maintenance(
        query: &str,
        message: Option<String>,
        enable: bool,
    ) -> Result<EscapeStatus, String> {
        let mut store = EscapeSpaceStore::load();
        store.set_maintenance(query, message, enable)
    }

    /// Adds a temporary preview space with TTL in hours.
    pub fn add_preview(
        domain: &str,
        target_port: u16,
        node_callsign: &str,
        ttl_hours: u64,
    ) -> Result<EscapeSpace, String> {
        validate_target_port(target_port)?;
        let valid_domain = validate_domain(domain)?;
        let mut store = EscapeSpaceStore::load();
        store.add_preview(&valid_domain, target_port, node_callsign, ttl_hours)
    }

    /// Adds an alias domain to an existing route (e.g. www.meinedomain.de).
    pub fn add_alias(query: &str, alias: &str) -> Result<String, String> {
        let mut store = EscapeSpaceStore::load();
        store.add_alias(query, alias)
    }

    /// Switches the upstream target port of a route seamlessly (Blue-Green zero-downtime deployment).
    pub fn switch_port(query: &str, new_port: u16) -> Result<EscapeSpace, String> {
        validate_target_port(new_port)?;
        let q = query.trim().to_lowercase();
        let mut store = EscapeSpaceStore::load();
        let found = store
            .spaces
            .iter_mut()
            .find(|s| s.id == q || s.domain.to_lowercase() == q);
        if let Some(space) = found {
            if space.static_root.is_some() {
                return Err("Eine statische Route besitzt keinen Upstream-Port.".to_string());
            }
            space.target_port = new_port;
            let updated = space.clone();
            store.save()?;
            Ok(updated)
        } else {
            Err(format!(
                "Keine Route mit Kennung oder Domain '{}' gefunden",
                query
            ))
        }
    }

    /// Imports a custom PEM certificate and private key for a route.
    pub fn import_cert(query: &str, cert_path: &str, key_path: &str) -> Result<(), String> {
        let space = Self::find_space(query)
            .ok_or_else(|| format!("Keine Route mit Kennung oder Domain '{}' gefunden", query))?;
        crate::acme::import_custom_certificate(&space.domain, cert_path, key_path)
    }

    /// Returns the certificate and key paths for a domain (checking custom cert, then dev CA cert).
    pub fn find_certificate(domain: &str) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        if let Some(space) = Self::find_space(domain) {
            if let (Some(crt), Some(key)) = (space.custom_cert_path, space.custom_key_path) {
                let cp = std::path::PathBuf::from(crt);
                let kp = std::path::PathBuf::from(key);
                if cp.exists() && kp.exists() {
                    return Some((cp, kp));
                }
            }
        }
        crate::ca::DeveloperCa::find_dev_certificate(domain)
    }

    /// Lists certificate status and metadata for all configured routes.
    pub fn list_certificates() -> Vec<crate::acme::CertificateMetadata> {
        let spaces = Self::load_spaces();
        spaces
            .into_iter()
            .map(|s| {
                let dev_cert_opt = crate::ca::DeveloperCa::find_dev_certificate(&s.domain);
                let has_custom_cert = s.custom_cert_path.is_some();
                let is_custom = has_custom_cert || dev_cert_opt.is_some();
                let (custom_cert, custom_key) = if let Some((crt, key)) = &dev_cert_opt {
                    (
                        Some(crt.to_string_lossy().to_string()),
                        Some(key.to_string_lossy().to_string()),
                    )
                } else {
                    (s.custom_cert_path, s.custom_key_path)
                };

                let expires_at_opt = s
                    .cert_expires_at
                    .as_deref()
                    .and_then(|str_val| chrono::DateTime::parse_from_rfc3339(str_val).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc));
                let issuer = if has_custom_cert {
                    "Custom PEM Certificate".to_string()
                } else if dev_cert_opt.is_some() {
                    "S&B Developer CA (Local Zero-Warning)".to_string()
                } else if s.tls_enabled {
                    "Let's Encrypt (ACME Auto-TLS)".to_string()
                } else {
                    "Deaktiviert (Nur HTTP)".to_string()
                };

                crate::acme::CertificateMetadata {
                    domain: s.domain,
                    issuer,
                    expires_at: expires_at_opt,
                    custom_cert_path: custom_cert,
                    custom_key_path: custom_key,
                    is_custom,
                }
            })
            .collect()
    }
}
