use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustDomain {
    Public,
    Dev,
    Secret,
}

impl std::fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustDomain::Public => write!(f, "public"),
            TrustDomain::Dev => write!(f, "dev"),
            TrustDomain::Secret => write!(f, "secret"),
        }
    }
}

impl TrustDomain {
    pub fn for_mesh_name(mesh_name: &str) -> Self {
        let lower = mesh_name.to_ascii_lowercase();
        if lower.contains("public") || lower.contains("web") || lower.contains("dmz") {
            TrustDomain::Public
        } else if lower.contains("secret")
            || lower.contains("vault")
            || lower.contains("prod")
            || lower.contains("core")
        {
            TrustDomain::Secret
        } else {
            TrustDomain::Dev
        }
    }

    pub fn recommended_service_account(&self) -> &'static str {
        match self {
            TrustDomain::Public => "sb-public",
            TrustDomain::Dev => "sb-dev",
            TrustDomain::Secret => "sb-secret",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIsolationReport {
    pub mesh_name: String,
    pub trust_domain: TrustDomain,
    pub current_os_user: String,
    pub service_account_configured: Option<String>,
    pub is_dedicated_service_account: bool,
    pub shared_user_warning: Option<String>,
    pub file_permissions_secure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshStatePaths {
    pub root: PathBuf,
    pub identity: PathBuf,
    pub config: PathBuf,
    pub peers: PathBuf,
    pub runtime_status: PathBuf,
    pub rbac: PathBuf,
    pub tickets: PathBuf,
    pub subnet_routes: PathBuf,
    pub psk: PathBuf,
}

impl MeshStatePaths {
    pub fn for_mesh(mesh_name: &str) -> Result<Self, String> {
        Self::for_mesh_at(&crate::identity::default_data_dir()?, mesh_name)
    }

    pub fn for_mesh_at(base_dir: &Path, mesh_name: &str) -> Result<Self, String> {
        let mesh_name = normalize_mesh_name(mesh_name)?;
        let root = base_dir.join("instances").join(mesh_name);
        Ok(Self {
            identity: root.join("identity.json"),
            config: root.join("config.toml"),
            peers: root.join("peers.toml"),
            runtime_status: root.join(crate::runtime_status::RUNTIME_STATUS_FILE),
            rbac: root.join("rbac.json"),
            tickets: root.join("tickets"),
            subnet_routes: root.join("subnets.json"),
            psk: root.join("network.psk"),
            root,
        })
    }

    pub fn ensure(&self) -> Result<(), String> {
        // CVE-Threat: Path traversal or symlink redirection across mesh state directories.
        // Analysis: Canonical mesh names block traversal; existing and raced directory links fail closed.
        // Hardening: Check both parent and instance paths before/after creation; restrict Unix modes.
        let instances_dir = self
            .root
            .parent()
            .ok_or_else(|| "Mesh-State-Pfad besitzt kein Instanzverzeichnis".to_string())?;
        for path in [instances_dir, self.root.as_path()] {
            ensure_not_symlink(path)?;
        }
        std::fs::create_dir_all(instances_dir).map_err(|error| {
            format!("Mesh-State-Verzeichnis konnte nicht erstellt werden: {error}")
        })?;
        for path in [instances_dir, self.root.as_path()] {
            ensure_not_symlink(path)?;
        }
        std::fs::create_dir_all(&self.root).map_err(|error| {
            format!("Mesh-State-Verzeichnis konnte nicht erstellt werden: {error}")
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [instances_dir, self.root.as_path()] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                    |error| {
                        format!("Mesh-State-Verzeichnis konnte nicht geschützt werden: {error}")
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn legacy_paths(base_dir: &Path, mesh_name: &str) -> Result<Vec<PathBuf>, String> {
        let mesh_name = normalize_mesh_name(mesh_name)?;
        Ok(vec![
            base_dir.join("identity.json"),
            base_dir.join("config.toml"),
            base_dir.join("peers.toml"),
            base_dir.join("runtime-status.json"),
            base_dir.join("tenants").join(mesh_name).join("rbac.json"),
            base_dir
                .join("tenants")
                .join(mesh_name)
                .join("subnets.json"),
            base_dir.join("tickets").join(format!("{mesh_name}.json")),
        ])
    }
}

fn ensure_not_symlink(path: &Path) -> Result<(), String> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "Mesh-State-Verzeichnis darf kein symbolischer Link sein: {}",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "Mesh-State-Pfad konnte nicht geprüft werden ({}): {error}",
            path.display()
        )),
    }
}

pub fn normalize_mesh_name(mesh_name: &str) -> Result<&str, String> {
    let name = mesh_name.trim();
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !name.as_bytes()[0].is_ascii_lowercase() && !name.as_bytes()[0].is_ascii_digit()
        || name.ends_with('-')
    {
        return Err(
            "Mesh-Name muss 1-63 Zeichen aus Kleinbuchstaben, Ziffern und inneren Bindestrichen enthalten"
                .to_string(),
        );
    }
    Ok(name)
}

pub fn inspect_process_isolation(
    mesh_name: &str,
    base_dir: &Path,
) -> Result<ProcessIsolationReport, String> {
    let mesh_name = normalize_mesh_name(mesh_name)?;
    let trust_domain = TrustDomain::for_mesh_name(mesh_name);
    let current_os_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let service_account_configured = std::env::var("SB_MESH_ACCOUNT").ok();

    let expected_service_account = trust_domain.recommended_service_account();
    let is_dedicated_service_account = match &service_account_configured {
        Some(account) => account.eq_ignore_ascii_case(expected_service_account),
        None => current_os_user.eq_ignore_ascii_case(expected_service_account),
    };

    let mut shared_user_warning = None;
    if !is_dedicated_service_account {
        if trust_domain == TrustDomain::Public {
            if current_os_user.eq_ignore_ascii_case("root")
                || current_os_user.eq_ignore_ascii_case("Administrator")
            {
                shared_user_warning = Some(
                    "WARNUNG: Public-Mesh läuft als Superuser (root/Administrator). Sicherheitsrisiko: Für öffentliche Netze ist ein dediziertes Dienstkonto ('sb-public') zwingend geboten.".to_string(),
                );
            } else {
                shared_user_warning = Some(format!(
                    "HINWEIS: Public-Mesh läuft unter dem regulären Benutzerkonto '{}'. Multi-Mesh trennt Netzwerkverkehr logisch, bietet aber keine OS-Sicherheitsgrenze gegen lokale Prozesse desselben Nutzers. Empfohlenes OS-Dienstkonto: '{}'.",
                    current_os_user, expected_service_account
                ));
            }
        } else if trust_domain == TrustDomain::Secret {
            shared_user_warning = Some(format!(
                "HINWEIS: Secret-Mesh teilt sich das lokale Benutzerkonto '{}' mit anderen Prozessen. Zur strikten Isolation vor kompromittierten Entwicklungstools wird ein isoliertes Dienstkonto ('{}') empfohlen.",
                current_os_user, expected_service_account
            ));
        }
    }

    let paths = MeshStatePaths::for_mesh_at(base_dir, mesh_name)?;
    let file_permissions_secure = check_permissions_secure(&paths.root);

    Ok(ProcessIsolationReport {
        mesh_name: mesh_name.to_string(),
        trust_domain,
        current_os_user,
        service_account_configured,
        is_dedicated_service_account,
        shared_user_warning,
        file_permissions_secure,
    })
}

fn check_permissions_secure(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = path.metadata() {
            let mode = meta.permissions().mode();
            return (mode & 0o077) == 0;
        }
        false
    }
    #[cfg(not(unix))]
    {
        path.exists()
    }
}

pub fn validate_identity_isolation(
    current_mesh: &str,
    current_pubkey: &str,
    base_dir: &Path,
) -> Result<(), String> {
    let instances_dir = base_dir.join("instances");
    if !instances_dir.is_dir() {
        return Ok(());
    }

    let entries = match std::fs::read_dir(&instances_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        if dir_name.eq_ignore_ascii_case(current_mesh) {
            continue;
        }

        let other_identity_path = path.join("identity.json");
        if other_identity_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&other_identity_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(other_pubkey) =
                        json.get("wireguard_pubkey").and_then(|v| v.as_str())
                    {
                        if other_pubkey.trim() == current_pubkey.trim() {
                            return Err(format!(
                                "Identitätskollision / Sicherheitsverletzung: Mesh '{}' versucht denselben WireGuard-Schlüssel zu verwenden wie Mesh '{}'. Netz- und Identitätsisolation verletzt: Jedes Mesh muss zwingend ein eigenständiges Schlüsselpaar besitzen.",
                                current_mesh, dir_name
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerTable;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[test]
    fn mesh_state_paths_are_distinct_and_restart_stable() {
        let root = std::env::temp_dir().join(format!(
            "sb-mesh-state-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let alpha = MeshStatePaths::for_mesh_at(&root, "alpha-mesh").unwrap();
        let beta = MeshStatePaths::for_mesh_at(&root, "beta-mesh").unwrap();
        assert_ne!(alpha.root, beta.root);
        assert_ne!(alpha.identity, beta.identity);
        assert_ne!(alpha.peers, beta.peers);
        assert_eq!(
            alpha,
            MeshStatePaths::for_mesh_at(&root, "alpha-mesh").unwrap()
        );

        alpha.ensure().unwrap();
        assert!(alpha.root.is_dir());
        assert!(!beta.root.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mesh_state_paths_reject_path_traversal_and_noncanonical_names() {
        for invalid in [
            "",
            "../alpha",
            "Alpha",
            "alpha/beta",
            "alpha_",
            "-alpha",
            "alpha-",
        ] {
            assert!(MeshStatePaths::for_mesh_at(Path::new("root"), invalid).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn mesh_state_paths_reject_symlinked_instance_roots_before_writing() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "sb-mesh-state-symlink-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let outside = base.join("outside");
        let instances = base.join("instances");
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, &instances).unwrap();

        let paths = MeshStatePaths::for_mesh_at(&base, "alpha").unwrap();
        assert!(paths.ensure().is_err());
        assert!(!outside.join("alpha").exists());

        std::fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn separate_mesh_states_can_back_concurrent_transports() {
        let root = std::env::temp_dir().join(format!(
            "sb-mesh-concurrent-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let alpha = MeshStatePaths::for_mesh_at(&root, "alpha").unwrap();
        let beta = MeshStatePaths::for_mesh_at(&root, "beta").unwrap();
        alpha.ensure().unwrap();
        beta.ensure().unwrap();

        let alpha_identity =
            Arc::new(crate::identity::NodeIdentity::load_or_generate(&alpha.identity).unwrap());
        let beta_identity =
            Arc::new(crate::identity::NodeIdentity::load_or_generate(&beta.identity).unwrap());
        let alpha_peers = Arc::new(RwLock::new(
            PeerTable::load_from_file(&alpha.peers).unwrap(),
        ));
        let beta_peers = Arc::new(RwLock::new(PeerTable::load_from_file(&beta.peers).unwrap()));
        let alpha_port = free_udp_port();
        let beta_port = free_udp_port();
        assert_ne!(alpha_port, beta_port);

        let alpha_transport = crate::transport::MeshTransport::bind(
            "alpha",
            alpha_port,
            alpha_identity.clone(),
            alpha_peers.clone(),
            Arc::new(RwLock::new(false)),
        )
        .await
        .unwrap();
        let beta_transport = crate::transport::MeshTransport::bind(
            "beta",
            beta_port,
            beta_identity.clone(),
            beta_peers.clone(),
            Arc::new(RwLock::new(false)),
        )
        .await
        .unwrap();

        assert_ne!(
            alpha_transport.socket.local_addr().unwrap(),
            beta_transport.socket.local_addr().unwrap()
        );
        assert_eq!(alpha_transport.mesh_id(), "alpha");
        assert_eq!(beta_transport.mesh_id(), "beta");
        assert_ne!(alpha_identity.node_id, beta_identity.node_id);
        assert!(!Arc::ptr_eq(&alpha_peers, &beta_peers));
        assert!(alpha.runtime_status.parent().unwrap().exists());
        assert!(beta.runtime_status.parent().unwrap().exists());

        drop((alpha_transport, beta_transport));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn free_udp_port() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    }

    #[test]
    fn trust_domains_and_process_isolation_reporting() {
        assert_eq!(
            TrustDomain::for_mesh_name("public-mesh"),
            TrustDomain::Public
        );
        assert_eq!(
            TrustDomain::for_mesh_name("skulls-web"),
            TrustDomain::Public
        );
        assert_eq!(TrustDomain::for_mesh_name("dev-mesh"), TrustDomain::Dev);
        assert_eq!(TrustDomain::for_mesh_name("my-project"), TrustDomain::Dev);
        assert_eq!(
            TrustDomain::for_mesh_name("secret-mesh"),
            TrustDomain::Secret
        );
        assert_eq!(
            TrustDomain::for_mesh_name("vault-corp"),
            TrustDomain::Secret
        );

        assert_eq!(
            TrustDomain::Public.recommended_service_account(),
            "sb-public"
        );
        assert_eq!(TrustDomain::Dev.recommended_service_account(), "sb-dev");
        assert_eq!(
            TrustDomain::Secret.recommended_service_account(),
            "sb-secret"
        );

        let root = std::env::temp_dir().join(format!(
            "sb-mesh-isolation-rep-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let paths = MeshStatePaths::for_mesh_at(&root, "public-mesh").unwrap();
        paths.ensure().unwrap();

        let report = inspect_process_isolation("public-mesh", &root).unwrap();
        assert_eq!(report.trust_domain, TrustDomain::Public);
        assert_eq!(report.mesh_name, "public-mesh");
        assert!(!report.current_os_user.is_empty());
        assert!(report.shared_user_warning.is_some() || report.is_dedicated_service_account);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_mesh_identity_isolation_detects_key_reuse() {
        let root = std::env::temp_dir().join(format!(
            "sb-mesh-collision-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let alpha = MeshStatePaths::for_mesh_at(&root, "alpha-mesh").unwrap();
        let beta = MeshStatePaths::for_mesh_at(&root, "beta-mesh").unwrap();
        alpha.ensure().unwrap();
        beta.ensure().unwrap();

        let alpha_identity = crate::identity::NodeIdentity::generate();
        let beta_identity = crate::identity::NodeIdentity::generate();

        // Save alpha identity
        let alpha_json = crate::identity::IdentityJson {
            node_id: alpha_identity.node_id.clone(),
            wireguard_pubkey: alpha_identity.wireguard_pubkey.clone(),
            secret_key_base64: "test-secret-alpha".into(),
            pow_nonce: 0,
            created_at: chrono::Utc::now(),
        };
        std::fs::write(&alpha.identity, serde_json::to_string(&alpha_json).unwrap()).unwrap();

        // 1. Beta with DIFFERENT key passes
        assert!(
            validate_identity_isolation("beta-mesh", &beta_identity.wireguard_pubkey, &root)
                .is_ok()
        );

        // 2. Beta with SAME key as alpha is strictly rejected
        let collision_err =
            validate_identity_isolation("beta-mesh", &alpha_identity.wireguard_pubkey, &root)
                .unwrap_err();
        assert!(
            collision_err.contains("Sicherheitsverletzung")
                || collision_err.contains("Identitätskollision")
        );
        assert!(collision_err.contains("alpha-mesh"));

        let _ = std::fs::remove_dir_all(root);
    }
}
