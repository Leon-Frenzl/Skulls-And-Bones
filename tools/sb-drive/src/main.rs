use clap::{Parser, Subcommand};
use colored::Colorize;
use sb_drive::GhostEngine;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "sb-drive")]
#[command(
    about = "💀 S&B Sovereign Drive — Peer-Shared Mesh Storage & Ghost Launch Engine",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch an authorized immutable Mesh object version into cache and open it
    Open {
        /// Peer and stable object identifier (e.g. @nas:object:invoice-2026)
        target: String,
        /// Exact immutable object version to fetch
        #[arg(long)]
        version_id: String,
        /// Registered source mesh network name
        #[arg(short, long, default_value = "corp-mesh")]
        mesh: String,
        /// Authorized destination mesh containing the resource
        #[arg(long)]
        target_mesh: String,
        /// UDP address of the source mesh anchor pinned by the join ticket
        #[arg(long)]
        anchor: SocketAddr,
        /// Optional capability token JSON file
        #[arg(long)]
        token: Option<PathBuf>,
    },
    /// Serve ACL-protected object payloads to the local sb-node bridge
    Serve {
        /// Directory containing payloads registered in the object catalog
        #[arg(long)]
        root: PathBuf,
        /// Mesh whose catalog and RBAC store authorize this service
        #[arg(short, long)]
        mesh: String,
        /// Loopback-only listener address
        #[arg(long, default_value = "127.0.0.1:58833")]
        bind: SocketAddr,
        /// Object catalog path (defaults to ~/.sb-node/catalog/<mesh>/object-catalog.json)
        #[arg(long)]
        catalog: Option<PathBuf>,
        /// SB-MAP grant policy JSON; enables per-operation app grants on downloads
        #[arg(long)]
        grant_policy: Option<PathBuf>,
    },
    /// List cached files in the local ephemeral Ghost Cache
    Cache {
        /// Clear all cached files
        #[arg(long)]
        clear: bool,
    },
    /// Inspect NTFS-inspired ACLs on a remote mesh share
    Acl {
        /// Target share or path (e.g. @nas:/documents)
        target: String,
        /// Mesh network name
        #[arg(short, long, default_value = "corp-mesh")]
        mesh: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let engine = GhostEngine::new();

    match cli.command {
        Commands::Open {
            target,
            version_id,
            mesh,
            target_mesh,
            anchor,
            token,
        } => {
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════"
                    .bold()
                    .black()
            );
            println!(
                "  {} {} {}",
                "S&B SOVEREIGN DRIVE".cyan().bold(),
                "//".black().bold(),
                "GHOST LAUNCH ENGINE".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════"
                    .bold()
                    .black()
            );
            println!("  Ziel-Ressource: {}", target.bright_yellow().bold());
            println!(
                "  Quell-Mesh:     {} | Ziel-Mesh: {}",
                mesh.bright_cyan(),
                target_mesh.bright_cyan()
            );

            let (peer, resource_id) = if let Some((p, r)) = target.split_once(':') {
                (p, r)
            } else {
                eprintln!(
                    "  {} Ungültiges Format. Erwartet: @peer:object-id",
                    "✗".red().bold()
                );
                std::process::exit(1);
            };
            if !is_safe_peer_cache_key(peer)
                || sb_mesh::objects::MeshObjectId::new(resource_id.to_string()).is_err()
            {
                eprintln!(
                    "  {} Peer- oder Objekt-ID enthält unsichere Zeichen oder ist ungültig.",
                    "✗".red().bold()
                );
                std::process::exit(1);
            }
            if sb_mesh::objects::ObjectVersionId::new(version_id.clone()).is_err() {
                eprintln!("  {} Objektversion ist ungültig.", "✗".red().bold());
                std::process::exit(1);
            }
            let capability = match load_capability_token(token.as_deref()) {
                Ok(token) => token,
                Err(error) => {
                    eprintln!(
                        "  {} Token konnte nicht geladen werden: {error}",
                        "✗".red().bold()
                    );
                    std::process::exit(1);
                }
            };
            let identity = match sb_mesh::identity::NodeIdentity::load_registered_for_mesh(&mesh) {
                Ok(identity) => Arc::new(identity),
                Err(error) => {
                    eprintln!(
                        "  {} Mesh-Identität konnte nicht geladen werden: {error}",
                        "✗".red().bold()
                    );
                    std::process::exit(1);
                }
            };
            let client =
                match sb_mesh::client::MeshClient::connect(sb_mesh::client::MeshClientConfig {
                    mesh_name: mesh.clone(),
                    swarm_topic: format!("sbm-swarm-{mesh}"),
                    anchor_addr: anchor,
                    identity,
                    local_bind_port: None,
                })
                .await
                {
                    Ok(client) => client,
                    Err(error) => {
                        eprintln!(
                            "  {} Mesh-Verbindung fehlgeschlagen: {error}",
                            "✗".red().bold()
                        );
                        std::process::exit(1);
                    }
                };
            let destination = engine.cache.cache_path(
                peer,
                &format!("{}.bin", cache_object_key(resource_id, &version_id)),
            );
            match sb_drive::stream::download_from_mesh(
                &client,
                &target_mesh,
                resource_id,
                &version_id,
                &destination,
                capability,
                None,
            )
            .await
            {
                Ok(cached_path) => {
                    println!(
                        "  {} Autorisierter Inhalt verifiziert im Cache: {}",
                        "✓".bright_green().bold(),
                        cached_path.display().to_string().white()
                    );
                    if let Err(error) = sb_drive::HostLauncher::open_with_default_app(&cached_path)
                    {
                        eprintln!(
                            "  {} Datei geladen, aber Öffnen fehlgeschlagen: {error}",
                            "✗".red().bold()
                        );
                        std::process::exit(1);
                    }
                    println!("  {} Native Host-Anwendung gestartet!", "🚀".bright_green());
                }
                Err(error) => {
                    eprintln!(
                        "  {} Mesh-Download abgelehnt oder fehlgeschlagen: {error}",
                        "✗".bright_red().bold()
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Serve {
            root,
            mesh,
            bind,
            catalog,
            grant_policy,
        } => {
            let catalog_path = match catalog {
                Some(path) => path,
                None => match sb_drive::stream::default_catalog_path(&mesh) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Catalog path error: {error}");
                        std::process::exit(1);
                    }
                },
            };
            let policy = match grant_policy
                .map(|path| sb_drive::stream::AppGrantPolicy::from_config_file(&path))
                .transpose()
            {
                Ok(policy) => policy.map(std::sync::Arc::new),
                Err(error) => {
                    eprintln!("Grant policy error: {error}");
                    std::process::exit(1);
                }
            };
            if let Err(error) =
                sb_drive::stream::serve_with_policy(root, bind, mesh, catalog_path, policy).await
            {
                eprintln!("sb-drive serve failed: {error}");
                std::process::exit(1);
            }
        }
        Commands::Cache { clear } => {
            let cache_dir = dirs::home_dir()
                .map(|h| h.join(".sb-drive").join("cache"))
                .unwrap_or_else(|| PathBuf::from(".sb-drive-cache"));

            if clear {
                let _ = std::fs::remove_dir_all(&cache_dir);
                let _ = std::fs::create_dir_all(&cache_dir);
                println!(
                    "  {} Lokaler Ghost-Cache erfolgreich bereinigt.",
                    "✓".bright_green().bold()
                );
            } else {
                println!("{}", "═══ S&B GHOST CACHE ÜBERSICHT ═══".bold().cyan());
                println!("  Pfad: {}", cache_dir.display().to_string().yellow());
                if let Ok(entries) = std::fs::read_dir(&cache_dir) {
                    let mut count = 0;
                    for e in entries.flatten() {
                        count += 1;
                        println!("  • {}", e.file_name().to_string_lossy());
                    }

                    if count == 0 {
                        println!("  Keine gecachten Dateien vorhanden.");
                    }
                }
            }
        }
        Commands::Acl { target, mesh } => {
            println!(
                "{}",
                "═══ S&B RESOURCE NTFS-ACL INSPECTOR ═══".bold().cyan()
            );
            println!(
                "  Target: {} | Mesh: {}",
                target.bright_yellow(),
                mesh.bright_cyan()
            );
            let rbac = sb_mesh::rbac::MeshRbacStore::load_or_create(&mesh);
            if let Ok(store) = rbac {
                let clean_key = target.trim_start_matches('@').to_lowercase();
                if let Some(acl) = store.get_resource_acl(&clean_key) {
                    println!("  Vererbung aktiv: {}", acl.inherit_from_parent);
                    for ace in &acl.entries {
                        let t = match ace.ace_type {
                            sb_mesh::rbac::AceType::Allow => "ALLOW".bright_green().bold(),
                            sb_mesh::rbac::AceType::Deny => "DENY ".bright_red().bold(),
                        };
                        println!(
                            "  • [{}] {:<18} R:{} W:{} X:{} D:{}",
                            t,
                            ace.principal.yellow(),
                            ace.permissions.read,
                            ace.permissions.write,
                            ace.permissions.execute,
                            ace.permissions.delete
                        );
                    }
                } else {
                    println!(
                        "  Keine explizite ACL hinterlegt (Default-Deny Standardregel greift)."
                    );
                }
            }
        }
    }
}

fn load_capability_token(
    path: Option<&std::path::Path>,
) -> Result<Option<sb_mesh::acl::CapabilityToken>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect token file {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 16 * 1024 {
        return Err("Token file must be a regular, non-symlink file no larger than 16 KiB".into());
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("Cannot read token file {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("Invalid capability token in {}: {error}", path.display()))
}

fn is_safe_peer_cache_key(peer: &str) -> bool {
    let peer = peer.trim().trim_start_matches('@');
    !peer.is_empty()
        && peer != "."
        && peer != ".."
        && peer.len() <= 128
        && peer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn cache_object_key(resource_id: &str, resource_version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(resource_id.as_bytes());
    hasher.update([0]);
    hasher.update(resource_version.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
