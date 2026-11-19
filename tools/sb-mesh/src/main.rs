use base64::Engine;
use clap::Parser;
use colored::Colorize;
use sb_mesh::cli::{
    Cli, Commands, DnsCommands, GroupCommands, InviteCommands, NetworkCommands, PairCommands,
    PeerCommands, RbacCommands, RouteCommands, TicketCommands,
};
use sb_mesh::config::MeshConfig;
use sb_mesh::discovery::DiscoveryManager;
use sb_mesh::identity::{default_data_dir, NodeIdentity};
use sb_mesh::peer::{PeerConfig, PeerTable};
use sb_mesh::rbac::{MeshGroup, MeshInviteToken, MeshMember, MeshRbacStore, MeshRole};
use sb_mesh::runtime_status::{MeshRuntimeNetwork, MeshRuntimeStatus};
use sb_mesh::transport::MeshTransport;
use sb_mesh::tui::TuiApp;
use std::sync::Arc;
use tokio::sync::RwLock;

fn main() {
    // Piped output must stay free of ANSI escapes (NO_COLOR is honoured by `colored` itself).
    {
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            colored::control::set_override(false);
        }
    }
    // Ensure sufficient stack size (8MB) on Windows for debug builds containing large futures
    let builder = std::thread::Builder::new()
        .name("sb-mesh-main".into())
        .stack_size(8 * 1024 * 1024);

    let handler = builder
        .spawn(|| {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("Failed to initialize Tokio runtime: {}", e);
                    std::process::exit(1);
                }
            };

            rt.block_on(async {
                if let Err(e) = run().await {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            });
        })
        .expect("Failed to spawn main thread");

    let _ = handler.join();
}

fn load_runtime_networks(
    path: &std::path::Path,
    requested_mesh: &str,
) -> Result<(String, String, String, String, Vec<MeshRuntimeNetwork>), String> {
    if !path.exists() {
        return Err(format!("Mesh network catalog {:?} does not exist", path));
    }

    let content = std::fs::read_to_string(path)
        .map_err(|error| format!("Failed to read network configuration {:?}: {error}", path))?;
    let networks_file: sb_mesh::network::NetworksFile = serde_json::from_str(&content)
        .map_err(|error| format!("Invalid network configuration {:?}: {error}", path))?;
    if networks_file.networks.is_empty() {
        return Err(format!("Network configuration {:?} has no networks", path));
    }
    let active_name = requested_mesh.trim().to_ascii_lowercase();
    let selected = networks_file
        .networks
        .get(&active_name)
        .or_else(|| {
            networks_file
                .networks
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(&active_name))
                .map(|(_, network)| network)
        })
        .ok_or_else(|| format!("Active mesh '{}' is not present in {:?}", active_name, path))?;

    if selected.name != active_name {
        return Err(format!(
            "Network key '{}' does not match network name '{}' in {:?}",
            active_name, selected.name, path
        ));
    }

    let mut available_networks = Vec::with_capacity(networks_file.networks.len());
    for (key, network) in &networks_file.networks {
        if key.trim().is_empty() || network.name.trim().is_empty() {
            return Err(format!(
                "Network configuration {:?} contains an empty network name",
                path
            ));
        }
        if !key.eq_ignore_ascii_case(&network.name) {
            return Err(format!(
                "Network key '{}' does not match network name '{}' in {:?}",
                key, network.name, path
            ));
        }
        available_networks.push(MeshRuntimeNetwork {
            name: network.name.clone(),
            description: network.description.clone(),
            subnet: network.overlay_subnet.clone(),
            is_active: network.name.eq_ignore_ascii_case(&active_name),
        });
    }
    available_networks.sort_by(|left, right| left.name.cmp(&right.name));

    Ok((
        selected.name.clone(),
        selected.description.clone(),
        selected.overlay_subnet.clone(),
        selected.swarm_topic.clone(),
        available_networks,
    ))
}

fn resolve_mesh_name(
    networks_path: &std::path::Path,
    requested_mesh: Option<&str>,
) -> Result<String, String> {
    let content = std::fs::read_to_string(networks_path)
        .map_err(|error| format!("Mesh network catalog could not be read: {error}"))?;
    let networks: sb_mesh::network::NetworksFile = serde_json::from_str(&content)
        .map_err(|error| format!("Mesh network catalog is invalid: {error}"))?;
    let name = requested_mesh.unwrap_or(&networks.active_network);
    let name = sb_mesh::state::normalize_mesh_name(name)?.to_string();
    if !networks.networks.contains_key(&name) {
        return Err(format!(
            "Mesh '{}' is not registered; bootstrap or join it before starting a daemon",
            name
        ));
    }
    Ok(name)
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let data_dir = default_data_dir()?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;

    let networks_path = data_dir.join("networks.json");
    let active_mesh = if networks_path.exists() {
        resolve_mesh_name(&networks_path, None)?
    } else {
        "default".to_string()
    };
    let state_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, &active_mesh)?;
    state_paths.ensure()?;
    let config_path = state_paths.config.clone();
    let peers_path = state_paths.peers.clone();

    match cli.command {
        None | Some(Commands::Tui) => {
            let identity = Arc::new(NodeIdentity::load_or_generate_default()?);
            let config = MeshConfig::load_or_create(&config_path)?;
            let peer_table = Arc::new(RwLock::new(PeerTable::load_from_file(&peers_path)?));
            let air_gap = Arc::new(RwLock::new(config.air_gap_killswitch));

            let transport = MeshTransport::bind(
                &active_mesh,
                config.listen_port,
                identity.clone(),
                peer_table.clone(),
                air_gap.clone(),
            )
            .await
            .map_err(|e| format!("Transport init error: {}", e))?;

            let discovery = Arc::new(DiscoveryManager::new());
            if config.lan_discovery && !config.air_gap_killswitch {
                let _ = discovery.start_listener(identity.node_id.clone());
                let node_id = identity.node_id.clone();
                let pubkey = identity.wireguard_pubkey.clone();
                let port = config.listen_port;
                tokio::spawn(async move {
                    let _ = DiscoveryManager::broadcast_presence(&node_id, &pubkey, port).await;
                });
            }

            let mut app = TuiApp::new(identity, transport, peer_table, discovery, config.clone());
            app.run().await.map_err(|e| e.to_string())?;

            // Save config if it was modified
            let _ = config.save(&config_path);
        }

        Some(Commands::Daemon { port, anchor, mesh }) => {
            let mesh_name = resolve_mesh_name(&networks_path, mesh.as_deref())?;
            let daemon_paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, &mesh_name)?;
            daemon_paths.ensure()?;
            let legacy_paths = sb_mesh::state::MeshStatePaths::legacy_paths(&data_dir, &mesh_name)?;
            if legacy_paths.iter().any(|path| path.exists()) {
                eprintln!(
                    "Legacy shared Mesh-Dateien gefunden; sie werden für '{}' nicht gelesen, kopiert oder gelöscht. Gegenstellen müssen mit der neuen Mesh-Identität erneut gekoppelt werden.",
                    mesh_name
                );
            }
            let identity = Arc::new(NodeIdentity::load_registered_for_mesh(&mesh_name)?);
            let config = MeshConfig::load_or_create(&daemon_paths.config)?;
            let listen_port = port.unwrap_or(config.listen_port);
            let loaded_peers = PeerTable::load_from_file(&daemon_paths.peers)?;
            if !daemon_paths.peers.exists() {
                loaded_peers.save_to_file(&daemon_paths.peers)?;
            }
            let peer_table = Arc::new(RwLock::new(loaded_peers));
            let air_gap = Arc::new(RwLock::new(config.air_gap_killswitch));
            let (mesh_name, description, overlay_subnet, swarm_topic, available_networks) =
                load_runtime_networks(&networks_path, &mesh_name)?;

            let transport = MeshTransport::bind(
                &mesh_name,
                listen_port,
                identity.clone(),
                peer_table.clone(),
                air_gap.clone(),
            )
            .await
            .map_err(|e| format!("Daemon bind error: {}", e))?;

            let ipc_server = sb_mesh::ipc::IpcServer::new(
                identity.clone(),
                transport.clone(),
                peer_table.clone(),
                Arc::new(RwLock::new(config.clone())),
            );
            let _ipc_handle = ipc_server.start();

            let runtime_status_path = daemon_paths.runtime_status;
            let runtime_peers = peer_table.clone();
            let runtime_identity = identity.clone();
            let runtime_mesh_name = mesh_name.clone();
            let runtime_description = description.clone();
            let runtime_subnet = overlay_subnet.clone();
            let runtime_topic = swarm_topic.clone();
            let runtime_air_gap = air_gap.clone();
            let runtime_networks = available_networks.clone();
            let runtime_started_at = MeshRuntimeStatus::now_unix()?;
            tokio::spawn(async move {
                let mut last_error = None;
                loop {
                    let air_gap_killswitch = *runtime_air_gap.read().await;
                    let peer_table = runtime_peers.read().await;
                    let snapshot = MeshRuntimeStatus::from_live_state(
                        runtime_mesh_name.clone(),
                        runtime_description.clone(),
                        runtime_subnet.clone(),
                        runtime_topic.clone(),
                        runtime_identity.node_id.clone(),
                        runtime_identity.wireguard_pubkey.clone(),
                        listen_port,
                        air_gap_killswitch,
                        runtime_started_at,
                        &peer_table,
                        runtime_networks.clone(),
                    );
                    drop(peer_table);
                    let result =
                        snapshot.and_then(|snapshot| snapshot.write_atomic(&runtime_status_path));
                    match result {
                        Ok(()) => last_error = None,
                        Err(error) if last_error.as_deref() != Some(error.as_str()) => {
                            eprintln!("Mesh runtime status export failed: {error}");
                            last_error = Some(error);
                        }
                        Err(_) => {}
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            });

            let discovery = DiscoveryManager::new();
            if config.lan_discovery && !config.air_gap_killswitch {
                let _ = discovery.start_listener(identity.node_id.clone());
                let node_id = identity.node_id.clone();
                let pubkey = identity.wireguard_pubkey.clone();
                let p = listen_port;
                tokio::spawn(async move {
                    loop {
                        let _ = DiscoveryManager::broadcast_presence(&node_id, &pubkey, p).await;
                        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                    }
                });
            }

            println!(
                "{}",
                "═══════════════════════════════════════════════════════════".cyan()
            );
            if anchor {
                println!(
                    "{}",
                    "  SKULLS & BONES SOVEREIGN ANCHOR HUB (sb-mesh)"
                        .bold()
                        .bright_green()
                );
            } else {
                println!(
                    "{}",
                    "  SKULLS & BONES SOVEREIGN MESH DAEMON (sb-mesh)"
                        .bold()
                        .cyan()
                );
            }
            println!(
                "{}",
                "═══════════════════════════════════════════════════════════".cyan()
            );
            println!("  {} {}", "Node ID:".bold(), identity.node_id.green());
            println!(
                "  {} {}",
                "Public Key:".bold(),
                identity.wireguard_pubkey.yellow()
            );
            println!(
                "  {} {}",
                "Listen Port:".bold(),
                listen_port.to_string().magenta()
            );
            if anchor {
                println!(
                    "  {} {}",
                    "Anchor Mode:".bold(),
                    "ACTIVE (SBM-TEP Ticket Issuer & Rendezvous Broker)"
                        .bright_green()
                        .bold()
                );
                if let Some(ref m) = mesh {
                    println!("  {} {}", "Bound Mesh:".bold(), m.cyan().bold());
                }
            }
            println!(
                "  {} {}",
                "Air-Gap Killswitch:".bold(),
                if config.air_gap_killswitch {
                    "ACTIVE (Traffic blocked)".red().bold()
                } else {
                    "DISABLED (Normal operation)".green()
                }
            );
            let table = peer_table.read().await;
            println!(
                "  {} {}",
                "Configured Peers:".bold(),
                table.peers.len().to_string().cyan()
            );
            drop(table);
            println!(
                "{}",
                "───────────────────────────────────────────────────────────".dimmed()
            );
            if anchor {
                println!(
                    "  {} Anchor Hub aktiv. Nimmt SBM-TEP Tickets & P2P-Verbindungen entgegen.",
                    "●".bright_green().bold()
                );
            }
            println!("  Mesh daemon running in background. Press Ctrl+C to terminate.");

            tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
            println!("\nShutting down sb-mesh daemon gracefully...");
        }

        Some(Commands::Bootstrap {
            name,
            anchor,
            cidr,
            admin,
            headless,
        }) => {
            sb_mesh::bootstrap::run_bootstrap(sb_mesh::bootstrap::BootstrapOptions {
                name,
                anchor_endpoint: anchor,
                cidr,
                admin_name: admin,
                headless,
            })?;
        }

        Some(Commands::Service { sub }) => {
            sb_mesh::service::handle_service(sub)?;
        }

        Some(Commands::Status) => {
            let identity = NodeIdentity::load_or_generate_default()?;
            let config = MeshConfig::load_or_default(&config_path)?;
            let peer_table = PeerTable::load_from_file(&peers_path)?;

            println!("{}", "═══ S&B SOVEREIGN MESH NODE STATUS ═══".bold().cyan());
            println!("  {:<20} {}", "Node ID:", identity.node_id.green().bold());
            println!(
                "  {:<20} {}",
                "Public Key (WG):",
                identity.wireguard_pubkey.yellow()
            );
            println!(
                "  {:<20} {}",
                "Listen Port:",
                config.listen_port.to_string().white()
            );
            println!(
                "  {:<20} {}",
                "Air-Gap Killswitch:",
                if config.air_gap_killswitch {
                    "ENGAGED (Isolated)".red().bold()
                } else {
                    "DISENGAGED (Connected)".green()
                }
            );
            println!(
                "  {:<20} {}",
                "LAN Discovery:",
                if config.lan_discovery {
                    "ENABLED".green()
                } else {
                    "DISABLED".dimmed()
                }
            );
            println!(
                "  {:<20} {}",
                "Peers Configured:",
                peer_table.peers.len().to_string().cyan()
            );

            if let Ok(report) = sb_mesh::state::inspect_process_isolation(
                &resolve_mesh_name(&networks_path, None).unwrap_or_else(|_| "default".to_string()),
                &data_dir,
            ) {
                println!(
                    "  {:<20} {} (OS: {})",
                    "Trust Domain:",
                    report.trust_domain.to_string().cyan(),
                    if report.is_dedicated_service_account {
                        "Dienstkonto aktiv".green()
                    } else {
                        "Geteiltes Benutzerkonto".yellow()
                    }
                );
            }

            if !peer_table.peers.is_empty() {
                println!("\n{}", "── Configured Peers ──".dimmed());
                for peer in peer_table.list() {
                    let ep = peer.config.endpoint.as_deref().unwrap_or("Dynamic");
                    println!(
                        "  • {:<16} {:<14} {:<22} {}",
                        peer.config.callsign.bold(),
                        peer.config.node_id.cyan(),
                        ep.yellow(),
                        peer.config.public_key_base64.dimmed()
                    );
                }
            }
        }

        Some(Commands::Isolation { mesh, json }) => {
            let mesh_name = resolve_mesh_name(&networks_path, mesh.as_deref())?;
            let report = sb_mesh::state::inspect_process_isolation(&mesh_name, &data_dir)?;

            if json {
                let serialized = serde_json::to_string_pretty(&report)
                    .map_err(|e| format!("Failed to serialize isolation report: {e}"))?;
                println!("{}", serialized);
            } else {
                println!(
                    "{}",
                    "═══ S&B MESH PROZESS- & IDENTITÄTSISOLATION ═══"
                        .bold()
                        .cyan()
                );
                println!("  {:<24} {}", "Mesh-Name:", report.mesh_name.bold().green());
                println!(
                    "  {:<24} {}",
                    "Vertrauensdomäne:",
                    report.trust_domain.to_string().yellow().bold()
                );
                println!(
                    "  {:<24} {}",
                    "Aktueller OS-User:",
                    report.current_os_user.white()
                );
                println!(
                    "  {:<24} {}",
                    "Empfohlenes Dienstkonto:",
                    report.trust_domain.recommended_service_account().cyan()
                );
                println!(
                    "  {:<24} {}",
                    "Dediziertes Dienstkonto:",
                    if report.is_dedicated_service_account {
                        "JA (OS-Prozessgrenze aktiv)".green().bold()
                    } else {
                        "NEIN (Geteiltes Benutzerkonto)".yellow()
                    }
                );
                println!(
                    "  {:<24} {}",
                    "Dateirechte gesichert:",
                    if report.file_permissions_secure {
                        "JA (Verzeichnis geschützt)".green()
                    } else {
                        "PRÜFEN / OFFEN".red()
                    }
                );
                if let Some(ref warning) = report.shared_user_warning {
                    println!("\n  {} {}", "Hinweis/Warnung:".bold().yellow(), warning);
                }
                println!();
            }
        }

        Some(Commands::Peer { sub }) => match sub {
            PeerCommands::Add {
                callsign,
                public_key,
                endpoint,
                overlay_ip,
            } => {
                let mut table = PeerTable::load_from_file(&peers_path)?;
                let cfg = PeerConfig {
                    callsign: callsign.clone(),
                    node_id: format!("peer-{}", public_key.chars().take(8).collect::<String>()),
                    public_key_base64: public_key.clone(),
                    endpoint,
                    overlay_ip,
                    created_at: chrono::Utc::now(),
                };
                table.add_peer(cfg);
                table.save_to_file(&peers_path)?;
                println!(
                    "{} Peer '{}' ({}) successfully added.",
                    "✓".green().bold(),
                    callsign.bold(),
                    public_key.yellow()
                );
            }
            PeerCommands::List => {
                let table = PeerTable::load_from_file(&peers_path)?;
                let peers = table.list();
                if peers.is_empty() {
                    println!("{}", "No peers configured yet. Use 'sb-mesh peer add' or 'sb-mesh pair connect'.".dimmed());
                } else {
                    println!("{}", "Configured Sovereign Mesh Peers:".bold());
                    for p in peers {
                        println!(
                            "  • {:<18} {:<14} {:<22} IP: {}",
                            p.config.callsign.cyan().bold(),
                            p.config.node_id,
                            p.config.endpoint.as_deref().unwrap_or("none").yellow(),
                            p.config.overlay_ip.as_deref().unwrap_or("auto")
                        );
                    }
                }
            }
            PeerCommands::Remove { target } => {
                let mut table = PeerTable::load_from_file(&peers_path)?;
                let found_key = table.peers.iter().find_map(|(k, v)| {
                    if k == &target || v.config.callsign == target || v.config.node_id == target {
                        Some(k.clone())
                    } else {
                        None
                    }
                });

                if let Some(k) = found_key {
                    let removed = table.remove_peer(&k);
                    table.save_to_file(&peers_path)?;
                    println!(
                        "{} Removed peer: {}",
                        "✓".green().bold(),
                        removed.map(|r| r.config.callsign).unwrap_or(target)
                    );
                } else {
                    eprintln!("{} Peer not found: {}", "✗".red(), target);
                }
            }
        },

        Some(Commands::Pair { sub }) => match sub {
            PairCommands::Generate { endpoint, qr, ttl } => {
                let identity = NodeIdentity::load_or_generate_default()?;
                let ttl_opt = if ttl > 0 { Some(ttl) } else { None };
                let token = identity.generate_pairing_token_with_ttl(&endpoint, ttl_opt);
                println!("{}", "═══ S&B AIR-GAPPED PAIRING TOKEN ═══".bold().cyan());
                if ttl > 0 {
                    println!(
                        "  {} Gilt für {} Sekunden ({} Minuten)",
                        "⏳ TTL:".yellow().bold(),
                        ttl,
                        ttl / 60
                    );
                }
                println!("Share this token with the target device to establish a direct cryptographic link:\n");
                println!("  {}\n", token.green().bold());

                if qr {
                    match sb_mesh::identity::render_terminal_qr(&token) {
                        Ok(qr_str) => {
                            println!(
                                "{}",
                                "── Terminal QR-Code (Scan with camera/companion) ──".dimmed()
                            );
                            println!("{}\n", qr_str);
                        }
                        Err(e) => eprintln!("Failed to render QR code: {}", e),
                    }
                } else {
                    println!(
                        "{}",
                        "Tip: Run with '--qr' to display a high-density terminal QR code.\n"
                            .dimmed()
                    );
                }

                println!("{}", "On the remote machine, execute:".dimmed());
                println!("  sb-mesh pair connect <FRIENDLY_NAME> \"{}\"", token);
            }
            PairCommands::Connect { callsign, token } => {
                let (node_id, pubkey, endpoint) = NodeIdentity::parse_pairing_token(&token)
                    .map_err(|e| format!("Invalid pairing token: {}", e))?;

                let mut table = PeerTable::load_from_file(&peers_path)?;
                let cfg = PeerConfig {
                    callsign: callsign.clone(),
                    node_id,
                    public_key_base64: pubkey.clone(),
                    endpoint: Some(endpoint.clone()),
                    overlay_ip: None,
                    created_at: chrono::Utc::now(),
                };
                table.add_peer(cfg);
                table.save_to_file(&peers_path)?;

                println!("{}", "═══ DEVICE PAIRED SUCCESSFULLY ═══".bold().green());
                println!("  Callsign: {}", callsign.bold());
                println!("  Public Key: {}", pubkey.yellow());
                println!("  Endpoint: {}", endpoint.cyan());
            }
        },

        Some(Commands::Ping { target }) => {
            let identity = Arc::new(NodeIdentity::load_or_generate_default()?);
            let config = MeshConfig::load_or_default(&config_path)?;
            let peer_table = Arc::new(RwLock::new(PeerTable::load_from_file(&peers_path)?));
            let air_gap = Arc::new(RwLock::new(config.air_gap_killswitch));

            let table = peer_table.read().await;
            let peer_opt = table
                .peers
                .values()
                .find(|p| {
                    p.config.callsign == target
                        || p.config.node_id == target
                        || p.config.public_key_base64 == target
                })
                .cloned();
            drop(table);

            if let Some(peer) = peer_opt {
                let transport = MeshTransport::bind(
                    &active_mesh,
                    0, // ephemeral port for ping CLI
                    identity.clone(),
                    peer_table.clone(),
                    air_gap.clone(),
                )
                .await
                .map_err(|e| format!("Failed to bind ping socket: {}", e))?;

                println!(
                    "Sending cryptographic authenticated ping to '{}' at {:?}...",
                    peer.config.callsign.cyan(),
                    peer.parsed_endpoint
                );

                transport.send_ping(&peer.config.public_key_base64).await?;
                println!(
                    "{} Ping packet dispatched successfully.",
                    "✓".green().bold()
                );
            } else {
                eprintln!("{} Peer not found: {}", "✗".red(), target);
            }
        }

        Some(Commands::Airgap { action }) => {
            let mut config = MeshConfig::load_or_default(&config_path)?;
            let new_state = match action.to_lowercase().as_str() {
                "on" | "true" | "1" | "enable" => true,
                "off" | "false" | "0" | "disable" => false,
                "toggle" => !config.air_gap_killswitch,
                _ => {
                    println!(
                        "Air-Gap Killswitch is currently: {}",
                        if config.air_gap_killswitch {
                            "ENGAGED (Isolated)".red().bold()
                        } else {
                            "DISENGAGED (Online)".green()
                        }
                    );
                    return Ok(());
                }
            };

            config.air_gap_killswitch = new_state;
            config.save(&config_path)?;

            if new_state {
                println!(
                    "{} AIR-GAP KILLSWITCH ENGAGED! All inbound and outbound traffic is severed.",
                    "⚠".red().bold()
                );
            } else {
                println!(
                    "{} AIR-GAP KILLSWITCH DISENGAGED. Normal mesh networking restored.",
                    "✓".green().bold()
                );
            }
        }

        Some(Commands::Proxy { port, mesh }) => {
            let identity = NodeIdentity::load_or_generate_default()?;
            let networks_path = data_dir.join("networks.json");
            let net_store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_path,
                &identity.wireguard_pubkey,
            )?;
            let active_mesh_name = mesh.unwrap_or(net_store.active_network.clone());
            let mesh_identity = NodeIdentity::load_registered_for_mesh(&active_mesh_name)?;
            let ticket = sb_mesh::ticket::load_cached_ticket(&active_mesh_name).ok_or_else(|| {
                format!(
                    "No valid cached mesh ticket for '{}'; join the mesh and obtain administrator approval before starting the proxy",
                    active_mesh_name
                )
            })?;
            let proxy_paths =
                sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, &active_mesh_name)?;
            proxy_paths.ensure()?;
            let config = MeshConfig::load_or_create(&proxy_paths.config)?;

            println!("{}", "═══ S&B USER-SPACE SOCKS5 PROXY ═══".bold().cyan());
            println!("  Port: 127.0.0.1:{}", port);
            println!("  Mesh Tenant: {}", active_mesh_name.bright_yellow().bold());
            println!("  Status: Running (Zero kernel drivers / Zero Wintun)");
            if !config.advertised_subnets.is_empty() {
                println!("  Subnets Routed: {:?}", config.advertised_subnets);
            }
            if let Some(ref exit) = config.exit_node {
                println!("  Exit Node: {}", exit);
            }
            println!("  Configure any app (browser, curl, git, db clients) to use SOCKS5 proxy at 127.0.0.1:{}", port);
            println!("  Press Ctrl+C to terminate.");

            let peer_table = Arc::new(RwLock::new(PeerTable::load_from_file(&proxy_paths.peers)?));
            let resolver = Arc::new(sb_mesh::dns::SovereignResolver::new(peer_table));
            let mut subnet_router = sb_mesh::proxy::SubnetRouter::new();
            if let Some(ref exit) = config.exit_node {
                if let Ok(exit_ep) = exit.parse() {
                    subnet_router.set_exit_node(exit_ep);
                }
            }
            let proxy = sb_mesh::proxy::Socks5Server::new(port)
                .with_resolver(resolver)
                .with_subnet_router(Arc::new(RwLock::new(subnet_router)))
                .with_mesh_name(&active_mesh_name)?
                .with_mesh_ticket(&ticket, &active_mesh_name, &mesh_identity.node_id)?;
            proxy
                .run()
                .await
                .map_err(|e| format!("Proxy runtime error: {}", e))?;
        }

        Some(Commands::Tunnel { local, remote }) => {
            println!("{}", "═══ S&B P2P PORT-FORWARD TUNNEL ═══".bold().cyan());
            println!("  Listening: 127.0.0.1:{}", local);
            println!("  Destination: {}", remote);
            println!("  Status: Active through Sovereign Mesh tunnel");
            println!("  Press Ctrl+C to terminate.");

            let tunnel = std::sync::Arc::new(sb_mesh::proxy::PortForwardTunnel::new(local, remote));
            tunnel
                .start()
                .await
                .map_err(|e| format!("Tunnel runtime error: {}", e))?;
        }

        Some(Commands::Stealth {
            server,
            target_port,
            local_port,
            mesh,
            swarm,
            pubkey,
            idle_timeout,
            oneshot,
        }) => {
            let suite_cfg = sb_core::config::SuiteConfig::load();
            let server_str = server
                .or(suite_cfg.network.default_server.clone())
                .unwrap_or_else(|| format!("127.0.0.1:{}", suite_cfg.ports.mesh_udp));
            let local_port = local_port.unwrap_or(suite_cfg.ports.stealth_ssh);

            let catalog_identity = NodeIdentity::load_or_generate_default()?;
            let server_addr: std::net::SocketAddr = server_str
                .parse()
                .map_err(|e| format!("Ungültige Server-Adresse: {}", e))?;

            let networks_file = sb_core::paths::sb_mesh_dir().join("networks.json");
            let net_store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_file,
                &catalog_identity.wireguard_pubkey,
            );
            let active_mesh_name = mesh.unwrap_or_else(|| {
                net_store
                    .as_ref()
                    .map(|st| st.active_network.clone())
                    .unwrap_or_else(|_| "dev-mesh".to_string())
            });
            let identity =
                std::sync::Arc::new(NodeIdentity::load_registered_for_mesh(&active_mesh_name)?);
            let default_swarm = net_store
                .as_ref()
                .ok()
                .and_then(|store| store.networks.get(&active_mesh_name))
                .map(|network| network.swarm_topic.clone())
                .unwrap_or_else(|| "sbm-swarm-dev".to_string());

            let mut active_swarm = swarm.unwrap_or(default_swarm);
            let mut resolved_server_pk: Option<[u8; 32]> = None;

            if let Some(pk_str) = pubkey {
                let bytes = base64::prelude::BASE64_STANDARD
                    .decode(&pk_str)
                    .map_err(|e| format!("Ungültiger Pubkey: {}", e))?;
                if bytes.len() != 32 {
                    return Err("Pubkey muss 32 Bytes lang sein".to_string());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                resolved_server_pk = Some(arr);
            } else {
                let now = chrono::Utc::now().timestamp() as u64;
                // 1. Schneller Cache-Check: Gibt es ein noch gültiges Ticket?
                let cached_valid = sb_mesh::ticket::load_cached_ticket(&active_mesh_name)
                    .filter(|c| c.grant.valid_until > now);

                if let Some(cached) = cached_valid {
                    println!("  {} [SBM-TEP] Gültiges Session-Ticket geladen (Mesh '{}', Lease bis {} UTC)",
                        "✓".bright_green().bold(),
                        active_mesh_name.bright_cyan().bold(),
                        chrono::DateTime::from_timestamp(cached.grant.valid_until as i64, 0).map(|dt| dt.to_rfc3339()).unwrap_or_default()
                    );
                    if let Ok(bytes) =
                        base64::prelude::BASE64_STANDARD.decode(&cached.grant.server_pubkey)
                    {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            resolved_server_pk = Some(arr);
                        }
                    }
                    active_swarm = cached.grant.swarm_topic;
                } else {
                    // 2. Kein gültiges Ticket im Cache: Automatischer Pre-Auth Ticket Exchange Knock
                    println!("  {} [SBM-TEP] Klopfe an Server {} für Mesh '{}' (Automatischer Pre-Auth Key Exchange)...",
                        "🎟️".bright_yellow(), server_addr, active_mesh_name.bright_cyan());
                    match sb_mesh::ticket::request_ticket(
                        &server_addr.to_string(),
                        &identity,
                        &active_mesh_name,
                        std::time::Duration::from_secs(3),
                    )
                    .await
                    {
                        Ok(grant) => {
                            println!("  {} [SBM-TEP] Authentifiziert als '{}'! Server-Key automatisch ermittelt: {}",
                                "✓".bright_green().bold(),
                                grant.role.bright_cyan().bold(),
                                grant.server_pubkey.bright_yellow()
                            );
                            if suite_cfg.network.server_pubkey.as_deref()
                                != Some(&grant.server_pubkey)
                            {
                                let mut updated_cfg = suite_cfg.clone();
                                updated_cfg.network.server_pubkey =
                                    Some(grant.server_pubkey.clone());
                                let _ = updated_cfg.save();
                            }
                            if let Ok(bytes) =
                                base64::prelude::BASE64_STANDARD.decode(&grant.server_pubkey)
                            {
                                if bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    resolved_server_pk = Some(arr);
                                }
                            }
                            active_swarm = grant.swarm_topic;
                        }
                        Err(e) => {
                            if let Some(ref pk_str) = suite_cfg.network.server_pubkey {
                                println!("  {} [SBM-TEP] Ticket-Knock fehlgeschlagen ({}), nutze hinterlegten Key aus ~/.sb/config.toml.", "⚠".bright_yellow(), e);
                                if let Ok(bytes) = base64::prelude::BASE64_STANDARD.decode(pk_str) {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        resolved_server_pk = Some(arr);
                                    }
                                }
                            } else {
                                return Err(format!("Server-Key konnte weder per SBM-TEP noch aus ~/.sb/config.toml ermittelt werden: {}", e));
                            }
                        }
                    }
                }
            }

            let remote_pk_bytes =
                resolved_server_pk.unwrap_or_else(|| *identity.public_key.as_bytes());

            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════"
                    .bold()
                    .black()
            );
            println!(
                "  {} {} {}",
                "S&B SOVEREIGN MESH".cyan().bold(),
                "//".black().bold(),
                "STEALTH INGRESS TUNNEL".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════"
                    .bold()
                    .black()
            );
            println!(
                "  {:<24} {}",
                "Lokaler SSH-Endpunkt:".bold(),
                format!("127.0.0.1:{}", local_port).green().bold()
            );
            println!(
                "  {:<24} {}",
                "Mesh Server:",
                format!("{} (UDP {})", server_addr, suite_cfg.ports.mesh_udp).bright_yellow()
            );
            println!(
                "  {:<24} {}",
                "Mesh Netzwerk:",
                active_mesh_name.bright_cyan().bold()
            );
            println!(
                "  {:<24} {}",
                "Ziel-Dienst auf Server:",
                format!("127.0.0.1:{}", target_port).bright_white()
            );
            println!("  {:<24} {}", "Swarm Overlay Topic:", active_swarm.cyan());
            println!(
                "  {:<24} {}",
                "Server Public Key:",
                base64::prelude::BASE64_STANDARD
                    .encode(remote_pk_bytes)
                    .bright_yellow()
            );
            println!(
                "  {:<24} {}",
                "Verschlüsselung:",
                "ChaCha20-Poly1305 (Noise_IK Single-Port)".green()
            );
            println!(
                "  {:<24} {}",
                "WAN-Sicherheit:",
                "Port 22 im WAN 100% unsichtbar & geschützt"
                    .bright_green()
                    .bold()
            );
            let user = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "root".into());
            println!(
                "  {} Verbinde mit: {}",
                "►".bright_cyan(),
                format!("sb-ssh -p {} {}@127.0.0.1", local_port, user)
                    .bright_white()
                    .bold()
            );
            println!("  {} Drücke Ctrl+C zum Beenden.", "i".bright_black());
            println!();

            let client = sb_mesh::stream::StealthStreamClient::new(
                local_port,
                server_addr,
                target_port,
                &active_swarm,
                identity,
                remote_pk_bytes,
            )
            .with_idle_timeout(idle_timeout)
            .with_oneshot(oneshot);

            client
                .run()
                .await
                .map_err(|e| format!("Stealth Client Fehler: {}", e))?;
        }

        Some(Commands::Routes) => {
            let config = MeshConfig::load_or_default(&config_path)?;
            let peer_table = PeerTable::load_from_file(&peers_path)?;

            println!(
                "{}",
                "═══ S&B MULTI-HOP ROUTING & SUBNET STATUS ═══"
                    .bold()
                    .cyan()
            );
            println!(
                "  {:<25} {}",
                "Overlay Subnet:",
                config.overlay_subnet.yellow()
            );
            println!(
                "  {:<25} {}",
                "Advertised Subnets:",
                if config.advertised_subnets.is_empty() {
                    "None".dimmed()
                } else {
                    config.advertised_subnets.join(", ").green().bold()
                }
            );
            println!(
                "  {:<25} {}",
                "Exit Node Mode:",
                if config.is_exit_node {
                    "ACTIVE (Routing WAN Traffic)".green().bold()
                } else {
                    "Disabled".white()
                }
            );
            println!(
                "  {:<25} {}",
                "Active Exit Node:",
                config
                    .exit_node
                    .as_deref()
                    .unwrap_or("None (Direct LAN/Mesh)")
                    .cyan()
            );
            println!("\n  {}", "Connected Neighbor Hops:".bold());
            let list = peer_table.list();
            if list.is_empty() {
                println!("    {}", "No active peers in local table".dimmed());
            } else {
                for peer in list {
                    println!(
                        "    • {:<16} ID: {:<14} Hop: 1  RTT: {:<7} Status: {}",
                        peer.config.callsign.bold(),
                        peer.config.node_id.cyan(),
                        peer.rtt_ms
                            .map(|r| format!("{:.1}ms", r))
                            .unwrap_or_else(|| "--".to_string()),
                        peer.status.badge_text().green()
                    );
                }
            }
        }

        Some(Commands::Route { sub, mesh }) => {
            let catalog_identity = NodeIdentity::load_or_generate_default()?;
            let networks_path = data_dir.join("networks.json");
            let net_store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_path,
                &catalog_identity.wireguard_pubkey,
            )?;
            let target_mesh = mesh.unwrap_or(net_store.active_network.clone());

            let sub_cmd = sub.unwrap_or(RouteCommands::List {
                mesh: Some(target_mesh.clone()),
            });

            match sub_cmd {
                RouteCommands::List { mesh: m_opt } => {
                    let m = m_opt.unwrap_or(target_mesh);
                    NodeIdentity::load_registered_for_mesh(&m)?;
                    let store = sb_mesh::subnet_route::SubnetRouteStore::load_or_create(&m)?;

                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());
                    println!(
                        "  {} // {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "VPC SUBNET ROUTES & GATEWAYS".bold()
                    );
                    println!("  Mesh: {}", m.bright_yellow().bold());
                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());

                    let active = store.list_active();
                    if active.is_empty() {
                        println!(
                            "  {}",
                            "Keine aktiven Subnetz-Routen im Mesh registriert.".dimmed()
                        );
                        println!(
                            "  Tipp: Bewirb ein lokales VPC-Subnetz mit: {}",
                            format!("sb mesh route advertise 10.0.0.0/16 --mesh {}", m).yellow()
                        );
                    } else {
                        println!(
                            "  {:<20} {:<22} {:<24} {}",
                            "SUBNET CIDR".bold(),
                            "GATEWAY NODE".bold(),
                            "GATEWAY ENDPOINT".bold(),
                            "STATUS".bold()
                        );
                        println!("  {}", "─────────────────────────────────────────────────────────────────────────────".dimmed());
                        for r in active {
                            println!(
                                "  {:<20} {:<22} {:<24} {}",
                                r.cidr.bright_green().bold(),
                                r.gateway_node_id.cyan(),
                                r.gateway_endpoint.white(),
                                "● AKTIV".bright_green()
                            );
                        }
                    }
                    println!();
                }
                RouteCommands::Advertise {
                    cidr,
                    endpoint,
                    mesh: m_opt,
                } => {
                    let m = m_opt.unwrap_or(target_mesh);
                    let identity = NodeIdentity::load_registered_for_mesh(&m)?;
                    let mut store = sb_mesh::subnet_route::SubnetRouteStore::load_or_create(&m)?;
                    let ep = endpoint.unwrap_or_else(|| "127.0.0.1:58888".to_string());
                    let route = store.advertise(
                        &cidr,
                        &identity.node_id,
                        &identity.wireguard_pubkey,
                        &ep,
                    )?;

                    println!(
                        "  {} Subnetz-Route '{}' im Mesh '{}' erfolgreich beworben!",
                        "✓".bright_green().bold(),
                        route.cidr.bright_yellow().bold(),
                        m
                    );
                    println!("  {} Gateway Node ID: {}", "►".cyan(), identity.node_id);
                    println!(
                        "  {} Berechtigte Team-Mitglieder können jetzt VPC-Ziele erreichen:",
                        "►".green()
                    );
                    println!(
                        "    {}",
                        format!(
                            "sb mesh route forward --local-port 5432 --target {}:5432",
                            route.cidr.split('/').next().unwrap_or("10.0.0.1")
                        )
                        .white()
                    );
                }
                RouteCommands::Withdraw { cidr, mesh: m_opt } => {
                    let m = m_opt.unwrap_or(target_mesh);
                    let identity = NodeIdentity::load_registered_for_mesh(&m)?;
                    let mut store = sb_mesh::subnet_route::SubnetRouteStore::load_or_create(&m)?;
                    if store.withdraw(&cidr, &identity.wireguard_pubkey) {
                        println!(
                            "  {} Subnetz-Route '{}' aus Mesh '{}' zurückgezogen.",
                            "✓".bright_green(),
                            cidr,
                            m
                        );
                    } else {
                        eprintln!(
                            "  {} Keine aktive Subnetz-Route für '{}' gefunden.",
                            "✗".bright_red(),
                            cidr
                        );
                    }
                }
                RouteCommands::Forward {
                    local_port,
                    target,
                    mesh: m_opt,
                } => {
                    let m = m_opt.unwrap_or(target_mesh);
                    sb_mesh::subnet_route::run_vpc_forwarder(local_port, &target, &m).await?;
                }
                RouteCommands::Bridge { cidr, mesh: m_opt } => {
                    let m = m_opt.unwrap_or(target_mesh);
                    sb_mesh::subnet_route::run_vpc_bridge(&m, cidr.as_deref()).await?;
                }
            }
        }

        Some(Commands::Revoke { pubkey, reason }) => {
            let identity = NodeIdentity::load_or_generate_default()?;
            let mut peer_table = PeerTable::load_from_file(&peers_path)?;
            let mut gossip = sb_mesh::gossip::GossipEngine::new();

            let revocation_msg = sb_mesh::gossip::GossipEngine::create_revocation(
                &identity.node_id,
                &pubkey,
                &reason,
                1,
                vec![0x53, 0x42, 0x4D],
            );

            let _ = gossip.process_incoming(revocation_msg, Some(&mut peer_table));
            peer_table.save_to_file(&peers_path)?;

            println!(
                "{}",
                "═══ S&B P2P GOSSIP CRL KEY REVOCATION ═══".bold().red()
            );
            println!("  {:<20} {}", "Revoked Pubkey:", pubkey.yellow());
            println!("  {:<20} {}", "Reason:", reason.white());
            println!(
                "  {:<20} {}",
                "Local Eviction:",
                "SUCCESS (Removed from peers.toml)".green().bold()
            );
            println!(
                "  {:<20} {}",
                "Gossip Status:",
                "Disseminated across mesh swarm".cyan()
            );
        }

        Some(Commands::Share {
            port,
            label,
            host,
            ingress_port,
        }) => {
            let ingress = ingress_port.unwrap_or(port);
            let service_label = label.unwrap_or_else(|| format!("service-{}", port));

            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════"
                    .bold()
                    .black()
            );
            println!(
                "  {} {} {}",
                "S&B LOCAL DEVELOPMENT".cyan().bold(),
                "//".black().bold(),
                "LOOPBACK PORT FORWARD".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════"
                    .bold()
                    .black()
            );

            println!(
                "  {:<24} {}",
                "Lokaler Endpunkt:".bold(),
                format!("http://{}:{}", host, port).white().bold()
            );
            println!(
                "  {:<24} {}",
                "Lokaler Listener:".bold(),
                format!("127.0.0.1:{}", ingress).bright_yellow()
            );
            println!(
                "\n  {}",
                "Nur lokal erreichbar; kein authentisierter oder verschlüsselter Mesh-Ingress."
                    .yellow()
            );

            let server = std::sync::Arc::new(sb_mesh::proxy::MeshPortShareServer::new(
                host.clone(),
                port,
                ingress,
                service_label,
            ));

            if !server.check_local_service().await {
                println!(
                    "\n  {} Hinweis: Auf {}:{} wurde noch kein lauschender Dienst gefunden.",
                    "i".yellow(),
                    host,
                    port
                );
                println!(
                    "    Starte deinen lokalen Webserver/API (z.B. Vite, Next.js, FastAPI, Axum)."
                );
            } else {
                println!(
                    "\n  {} Lokaler Dienst auf {}:{} antwortet!",
                    "✓".green(),
                    host,
                    port
                );
            }

            println!(
                "\n  {} Lokaler Forward ist aktiv. Drücke {} zum Beenden.\n",
                "●".green().bold(),
                "[STRG + C]".bold()
            );
            server
                .start()
                .await
                .map_err(|e| format!("Port-Sharing Fehler: {}", e))?;
        }

        Some(Commands::Network { sub }) => {
            let identity = NodeIdentity::load_or_generate_default()?;
            let networks_path = data_dir.join("networks.json");
            let mut store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_path,
                &identity.wireguard_pubkey,
            )?;

            match sub {
                NetworkCommands::Create {
                    name,
                    subnet,
                    desc,
                    swarm,
                    psk,
                } => {
                    let mesh_name = name.trim().to_ascii_lowercase();
                    if store.networks.contains_key(&mesh_name) {
                        return Err(format!("Mesh '{}' existiert bereits.", mesh_name));
                    }
                    let mesh_paths =
                        sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, &mesh_name)?;
                    mesh_paths.ensure()?;
                    let legacy_paths =
                        sb_mesh::state::MeshStatePaths::legacy_paths(&data_dir, &mesh_name)?;
                    if legacy_paths.iter().any(|path| path.exists()) {
                        eprintln!(
                            "Legacy-Dateien für '{}' gefunden; sie werden nicht importiert oder gelöscht.",
                            mesh_name
                        );
                    }
                    let mesh_identity = NodeIdentity::load_or_generate(&mesh_paths.identity)?;
                    match store.create_network(
                        &name,
                        &desc,
                        &subnet,
                        &mesh_identity.wireguard_pubkey,
                        swarm.as_deref(),
                        psk,
                        None,
                    ) {
                        Ok(net) => {
                            if !mesh_paths.config.exists() {
                                MeshConfig::default().save(&mesh_paths.config)?;
                            } else {
                                MeshConfig::load_or_create(&mesh_paths.config)?;
                            }
                            if !mesh_paths.peers.exists() {
                                PeerTable::new().save_to_file(&mesh_paths.peers)?;
                            } else {
                                PeerTable::load_from_file(&mesh_paths.peers)?;
                            }
                            MeshRbacStore::load_or_create(&net.name)?;
                            println!(
                                "{}",
                                "═══ S&B MULTI-MESH OVERLAY ERSTELLT ═══".bold().cyan()
                            );
                            println!("  {:<20} {}", "Netzwerk-Name:", net.name.green().bold());
                            println!("  {:<20} {}", "Subnet CIDR:", net.overlay_subnet.yellow());
                            println!("  {:<20} {}", "Swarm Topic:", net.swarm_topic.magenta());
                            println!("  {:<20} {}", "Beschreibung:", net.description.white());
                            println!(
                                "\n  {} Umschalten mit: {}",
                                "Tipp:".dimmed(),
                                format!("sb-mesh network switch {}", net.name)
                                    .bold()
                                    .yellow()
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{} Fehler beim Erstellen des Netzwerks: {}",
                                "✗".red().bold(),
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                }
                NetworkCommands::List { json } => {
                    if json {
                        let items: Vec<_> = store
                            .list()
                            .iter()
                            .map(|n| {
                                serde_json::json!({
                                    "name": n.name,
                                    "subnet": n.overlay_subnet,
                                    "swarm_topic": n.swarm_topic,
                                    "active": n.name == store.active_network,
                                })
                            })
                            .collect();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&items).unwrap_or_default()
                        );
                        return Ok(());
                    }
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {} {} {}",
                        "S&B SOVEREIGN MULTI-MESH".cyan().bold(),
                        "//".black().bold(),
                        "OVERLAY NETWORKS".bold()
                    );
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {:<18} {:<18} {:<24} STATUS",
                        "NAME", "SUBNET", "SWARM TOPIC"
                    );
                    println!("  {}", "─".repeat(66).black());

                    let list = store.list();
                    for net in list {
                        let is_active = net.name == store.active_network;
                        let status_badge = if is_active {
                            "● AKTIV".bright_green().bold()
                        } else {
                            "○ BEREIT".bright_black()
                        };
                        let name_fmt = if is_active {
                            net.name.bright_white().bold()
                        } else {
                            net.name.normal()
                        };
                        println!(
                            "  {:<18} {:<18} {:<24} {}",
                            name_fmt,
                            net.overlay_subnet.yellow(),
                            net.swarm_topic.magenta(),
                            status_badge
                        );
                    }
                    println!();
                }
                NetworkCommands::Current => {
                    let active = store.get_active();
                    println!("{}", "═══ AKTIVES SOVEREIGN MESH OVERLAY ═══".bold().cyan());
                    println!("  {:<20} {}", "Name:", active.name.bright_white().bold());
                    println!(
                        "  {:<20} {}",
                        "Subnet CIDR:",
                        active.overlay_subnet.yellow().bold()
                    );
                    println!("  {:<20} {}", "Swarm Topic:", active.swarm_topic.magenta());
                    println!("  {:<20} {}", "Beschreibung:", active.description);
                    println!(
                        "  {:<20} {}",
                        "Listen Port:",
                        active.listen_port.to_string().cyan()
                    );
                    println!(
                        "  {:<20} {}",
                        "Public Key:",
                        active.wireguard_pubkey.yellow()
                    );
                    println!(
                        "  {:<20} {}",
                        "Erstellt am:",
                        active.created_at.bright_black()
                    );
                    println!(
                        "  {:<20} {}",
                        "Zuletzt aktiv:",
                        active.last_active_at.bright_black()
                    );
                }
                NetworkCommands::Switch { name } => match store.switch_network(&name) {
                    Ok(net) => {
                        println!(
                            "  {} Aktives Mesh-Overlay gewechselt zu '{}' [{}]",
                            "✓".green().bold(),
                            net.name.bright_white().bold(),
                            net.overlay_subnet.yellow()
                        );
                    }
                    Err(e) => {
                        eprintln!("{} {}", "✗".red().bold(), e);
                        std::process::exit(1);
                    }
                },
                NetworkCommands::Delete { name } => match store.delete_network(&name) {
                    Ok(()) => {
                        println!(
                            "  {} Mesh-Overlay '{}' erfolgreich gelöscht.",
                            "✓".green().bold(),
                            name
                        );
                    }
                    Err(e) => {
                        eprintln!("{} {}", "✗".red().bold(), e);
                        std::process::exit(1);
                    }
                },
                NetworkCommands::MigratePsks => {
                    let migrated = store.migrate_psks()?;
                    println!(
                        "  {} {} PSK(s) geprüft und in mesh-spezifische private Dateien verschoben.",
                        "✓".green().bold(),
                        migrated
                    );
                    if migrated == 0 {
                        println!("  Es waren keine Katalog-PSKs vorhanden.");
                    }
                }
            }
        }

        Some(Commands::Ticket { sub }) => {
            let catalog_identity = std::sync::Arc::new(NodeIdentity::load_or_generate_default()?);
            let suite_cfg = sb_core::config::SuiteConfig::load();
            let networks_file = sb_core::paths::sb_mesh_dir().join("networks.json");
            let net_store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_file,
                &catalog_identity.wireguard_pubkey,
            );
            let active_mesh_name = net_store
                .as_ref()
                .map(|st| st.active_network.clone())
                .unwrap_or_else(|_| "dev-mesh".to_string());

            match sub {
                TicketCommands::Request { mesh, server } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    let identity = NodeIdentity::load_registered_for_mesh(&target_mesh)?;
                    let target_server = server
                        .or(suite_cfg.network.default_server.clone())
                        .unwrap_or_else(|| format!("127.0.0.1:{}", suite_cfg.ports.mesh_udp));

                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {} {} {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "//".black().bold(),
                        "TICKET REQUEST (SBM-TEP)".bold()
                    );
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!("  {:<24} {}", "Server:", target_server.bright_yellow());
                    println!(
                        "  {:<24} {}",
                        "Ziel-Mesh:",
                        target_mesh.bright_cyan().bold()
                    );
                    println!(
                        "  {:<24} {} ({})",
                        "Eigene Identität:",
                        identity.node_id.bold(),
                        identity.wireguard_pubkey.yellow()
                    );
                    println!();
                    println!("  {} Sende Pre-Auth Knock...", "►".bright_cyan());

                    match sb_mesh::ticket::request_ticket(
                        &target_server,
                        &identity,
                        &target_mesh,
                        std::time::Duration::from_secs(5),
                    )
                    .await
                    {
                        Ok(grant) => {
                            println!(
                                "  {} Authentifizierung erfolgreich! Ticket erhalten.",
                                "✓".bright_green().bold()
                            );
                            println!(
                                "  {:<24} {}",
                                "Server Node ID:",
                                grant.server_node_id.bright_cyan()
                            );
                            println!(
                                "  {:<24} {}",
                                "Server Pubkey:",
                                grant.server_pubkey.bright_yellow()
                            );
                            println!(
                                "  {:<24} {}",
                                "Swarm Topic:",
                                grant.swarm_topic.bright_magenta()
                            );
                            println!(
                                "  {:<24} {}",
                                "Rolle im Mesh:",
                                grant.role.bright_green().bold()
                            );
                            if !grant.capabilities.is_empty() {
                                println!(
                                    "  {:<24} {}",
                                    "Capabilities:",
                                    grant.capabilities.join(", ").bright_white()
                                );
                            }
                            println!(
                                "  {:<24} {}",
                                "Gültig bis (Lease):",
                                chrono::DateTime::from_timestamp(grant.valid_until as i64, 0)
                                    .map(|dt| dt.to_rfc3339())
                                    .unwrap_or_default()
                                    .bright_white()
                                    .bold()
                            );
                            println!(
                                "  {:<24} {}",
                                "Session Ticket:",
                                grant.session_ticket.bright_black()
                            );

                            // Auto-Sync config.toml
                            if suite_cfg.network.server_pubkey.as_deref()
                                != Some(&grant.server_pubkey)
                            {
                                println!(
                                    "\n  {} Aktualisiere server_pubkey in ~/.sb/config.toml...",
                                    "🔄".bright_cyan()
                                );
                                let mut updated_cfg = suite_cfg.clone();
                                updated_cfg.network.server_pubkey = Some(grant.server_pubkey);
                                let _ = updated_cfg.save();
                                println!(
                                    "  {} ~/.sb/config.toml erfolgreich synchronisiert!",
                                    "✓".bright_green()
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "  {} Ticket-Anfrage abgewiesen oder fehlgeschlagen: {}",
                                "✗".bright_red().bold(),
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                }
                TicketCommands::Status { mesh } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {} {} {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "//".black().bold(),
                        "TICKET LEASE STATUS".bold()
                    );
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    match sb_mesh::ticket::load_cached_ticket(&target_mesh) {
                        Some(ticket) => {
                            let now = chrono::Utc::now().timestamp() as u64;
                            let remaining = ticket.grant.valid_until.saturating_sub(now);
                            println!("  {:<24} {}", "Mesh:", target_mesh.bright_cyan().bold());
                            println!("  {:<24} {}", "Server:", ticket.server_addr.bright_yellow());
                            println!(
                                "  {:<24} {}",
                                "Server Node ID:",
                                ticket.grant.server_node_id.bright_cyan()
                            );
                            println!(
                                "  {:<24} {}",
                                "Server Pubkey:",
                                ticket.grant.server_pubkey.bright_yellow()
                            );
                            println!(
                                "  {:<24} {}",
                                "Rolle im Mesh:",
                                ticket.grant.role.bright_green().bold()
                            );
                            if !ticket.grant.capabilities.is_empty() {
                                println!(
                                    "  {:<24} {}",
                                    "Capabilities:",
                                    ticket.grant.capabilities.join(", ").bright_white()
                                );
                            }
                            println!(
                                "  {:<24} {}",
                                "Status:",
                                if remaining > 0 {
                                    "GÜLTIG".bright_green().bold()
                                } else {
                                    "ABGELAUFEN".bright_red().bold()
                                }
                            );
                            println!(
                                "  {:<24} {} Minuten ({} Sekunden)",
                                "Restlaufzeit:",
                                remaining / 60,
                                remaining
                            );
                            println!(
                                "  {:<24} {}",
                                "Ablaufzeitpunkt:",
                                chrono::DateTime::from_timestamp(
                                    ticket.grant.valid_until as i64,
                                    0
                                )
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_default()
                            );
                        }
                        None => {
                            println!("  {:<24} {}", "Mesh:", target_mesh.bright_cyan().bold());
                            println!(
                                "  {:<24} {}",
                                "Status:",
                                "KEIN GÜLTIGES TICKET VORHANDEN".bright_yellow().bold()
                            );
                            println!(
                                "\n  {} Hole ein neues Ticket mit: {}",
                                "Tipp:".dimmed(),
                                format!("sb-mesh ticket request --mesh {}", target_mesh)
                                    .bright_yellow()
                                    .bold()
                            );
                        }
                    }
                }
            }
        }

        Some(Commands::Rbac { sub, ui, mesh }) => {
            let identity = std::sync::Arc::new(NodeIdentity::load_or_generate_default()?);
            let networks_file = sb_core::paths::sb_mesh_dir().join("networks.json");
            let net_store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_file,
                &identity.wireguard_pubkey,
            );
            let active_mesh_name = net_store
                .as_ref()
                .map(|st| st.active_network.clone())
                .unwrap_or_else(|_| "dev-mesh".to_string());

            if ui || sub.is_none() {
                let target_mesh = mesh.unwrap_or(active_mesh_name);
                let mut app = sb_mesh::rbac_tui::RbacTuiApp::new(Some(target_mesh));
                app.run().await.map_err(|e| e.to_string())?;
                return Ok(());
            }

            match sub.unwrap() {
                RbacCommands::Ui { mesh: sub_mesh } => {
                    let target_mesh = sub_mesh.or(mesh).unwrap_or(active_mesh_name);
                    let mut app = sb_mesh::rbac_tui::RbacTuiApp::new(Some(target_mesh));
                    app.run().await.map_err(|e| e.to_string())?;
                }

                RbacCommands::List { mesh: sub_mesh } => {
                    let target_mesh = sub_mesh
                        .or(mesh)
                        .unwrap_or_else(|| active_mesh_name.clone());
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {} {} {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "//".black().bold(),
                        format!("TENANT RBAC [{}]", target_mesh).bold()
                    );
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    let store = MeshRbacStore::load_or_create(&target_mesh)?;
                    let now = chrono::Utc::now().timestamp() as u64;

                    if store.members.is_empty() {
                        println!(
                            "  {} Keine Mitglieder im Mesh '{}' konfiguriert.",
                            "i".dimmed(),
                            target_mesh
                        );
                        println!("  {} Füge ein Mitglied hinzu mit: {}", "Tipp:".dimmed(), format!("sb-mesh rbac add --mesh {} --name <user> --pubkey <key> --role <role>", target_mesh).yellow());
                    } else {
                        println!(
                            "  {:<16} {:<10} {:<14} {:<10} CAPABILITIES",
                            "NAME", "ROLLE", "NODE ID", "STATUS"
                        );
                        println!("  {}", "─".repeat(70).dimmed());
                        for m in &store.members {
                            let status = if m.revoked {
                                "REVOKED".bright_red().bold()
                            } else if m.is_active(now) {
                                "AKTIV".bright_green()
                            } else {
                                "EXPIRED".bright_yellow()
                            };
                            let caps_summary = if m.capabilities.is_empty() {
                                "-".dimmed().to_string()
                            } else {
                                m.capabilities.join(", ")
                            };
                            println!(
                                "  {:<16} {:<10} {:<14} {:<10} {}",
                                m.name.bright_white().bold(),
                                m.role.badge().bright_cyan(),
                                m.node_id.dimmed(),
                                status,
                                caps_summary.bright_white()
                            );
                        }
                    }
                    println!();
                }

                RbacCommands::Pending { mesh: sub_mesh } => {
                    let target_mesh = sub_mesh
                        .or(mesh)
                        .unwrap_or_else(|| active_mesh_name.clone());
                    let store = MeshRbacStore::load_or_create(&target_mesh)?;
                    let pending: Vec<_> = store
                        .join_requests
                        .iter()
                        .filter(|request| {
                            request.status == sb_mesh::rbac::JoinRequestStatus::Pending
                        })
                        .collect();
                    if pending.is_empty() {
                        println!("Keine ausstehenden Beitrittsanfragen in '{}'.", target_mesh);
                    } else {
                        println!(
                            "{:<34} {:<18} {:<14} {:<12} CREATED",
                            "REQUEST ID", "NAME", "ROLE", "NODE ID"
                        );
                        for request in pending {
                            println!(
                                "{:<34} {:<18} {:<14} {:<12} {}",
                                request.request_id,
                                request.name,
                                request.role.as_str(),
                                request.node_id,
                                request.created_at
                            );
                        }
                    }
                }

                RbacCommands::Approve {
                    request_id,
                    mesh: sub_mesh,
                } => {
                    let target_mesh = sub_mesh
                        .or(mesh)
                        .unwrap_or_else(|| active_mesh_name.clone());
                    let actor = std::env::var("USERNAME")
                        .or_else(|_| std::env::var("USER"))
                        .map_err(|_| "Could not determine the local administrator identity")?;
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    if store.approve_join_request(&request_id, &actor)? {
                        store.save()?;
                        println!(
                            "Beitrittsanfrage '{}' genehmigt; Peer ist jetzt Mitglied von '{}'.",
                            request_id, target_mesh
                        );
                    } else {
                        eprintln!(
                            "Beitrittsanfrage '{}' wurde nicht gefunden oder ist nicht mehr ausstehend.",
                            request_id
                        );
                    }
                }

                RbacCommands::Deny {
                    request_id,
                    reason,
                    mesh: sub_mesh,
                } => {
                    let target_mesh = sub_mesh
                        .or(mesh)
                        .unwrap_or_else(|| active_mesh_name.clone());
                    let actor = std::env::var("USERNAME")
                        .or_else(|_| std::env::var("USER"))
                        .map_err(|_| "Could not determine the local administrator identity")?;
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    if store.deny_join_request(&request_id, &actor, &reason) {
                        store.save()?;
                        println!("Beitrittsanfrage '{}' abgelehnt.", request_id);
                    } else {
                        eprintln!(
                            "Beitrittsanfrage '{}' wurde nicht gefunden oder ist nicht mehr ausstehend.",
                            request_id
                        );
                    }
                }

                RbacCommands::Add {
                    name,
                    pubkey,
                    role,
                    caps,
                    mesh,
                } => {
                    let target_mesh = mesh.unwrap_or_else(|| active_mesh_name.clone());
                    let parsed_role = MeshRole::from_str(&role).ok_or_else(|| {
                        format!("Ungültige Rolle '{}'. Verfügbar: Admin, Developer, Operator, Consumer, Auditor", role)
                    })?;

                    let node_id = NodeIdentity::derive_node_id_from_pubkey(&pubkey);
                    let mut member =
                        MeshMember::new(&name, &pubkey, &node_id, &target_mesh, parsed_role);

                    if let Some(custom_caps) = caps {
                        member.capabilities = custom_caps
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }

                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    store.add_or_update(member.clone());
                    store.save()?;

                    println!(
                        "  {} Mitglied '{}' erfolgreich zum Mesh '{}' hinzugefügt!",
                        "✓".bright_green().bold(),
                        name,
                        target_mesh
                    );
                    println!("  {:<20} {}", "Rolle:", member.role.badge().bright_cyan());
                    println!("  {:<20} {}", "Node ID:", member.node_id.bright_yellow());
                    println!(
                        "  {:<20} {}",
                        "Capabilities:",
                        member.capabilities.join(", ").white()
                    );
                }

                RbacCommands::Revoke { name, reason, mesh } => {
                    let target_mesh = mesh.unwrap_or_else(|| active_mesh_name.clone());
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    if store.revoke(&name, &reason) {
                        store.save()?;
                        println!(
                            "  {} Mitglied '{}' aus Mesh '{}' revoziert (KRL Eviction aktiv).",
                            "✓".bright_red().bold(),
                            name,
                            target_mesh
                        );
                        println!("  {:<20} {}", "Grund:", reason);
                    } else {
                        eprintln!(
                            "  {} Mitglied '{}' im Mesh '{}' nicht gefunden.",
                            "✗".bright_red(),
                            name,
                            target_mesh
                        );
                    }
                }

                RbacCommands::Remove { name, mesh } => {
                    let target_mesh = mesh.unwrap_or_else(|| active_mesh_name.clone());
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    if store.remove(&name) {
                        store.save()?;
                        println!(
                            "  {} Mitglied '{}' vollständig aus Mesh '{}' entfernt.",
                            "✓".bright_green(),
                            name,
                            target_mesh
                        );
                    } else {
                        eprintln!(
                            "  {} Mitglied '{}' im Mesh '{}' nicht gefunden.",
                            "✗".bright_red(),
                            name,
                            target_mesh
                        );
                    }
                }

                RbacCommands::Audit { mesh, limit } => {
                    let target_mesh = mesh.unwrap_or_else(|| active_mesh_name.clone());
                    let store = MeshRbacStore::load_or_create(&target_mesh)?;

                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());
                    println!(
                        "  {} // {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "SECURITY AUDIT LOG".bold()
                    );
                    println!("  Mesh: {}", target_mesh.bright_yellow().bold());
                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());

                    if store.audit_log.is_empty() {
                        println!("  {}", "Keine Audit-Ereignisse protokolliert.".dimmed());
                    } else {
                        let count = store.audit_log.len();
                        let start = count.saturating_sub(limit);
                        println!(
                            "  {:<20} {:<18} {:<16} {:<20} {}",
                            "ZEITPUNKT".bold(),
                            "AKTION".bold(),
                            "AKTEUR".bold(),
                            "ZIEL".bold(),
                            "DETAILS".bold()
                        );
                        println!("  {}", "─────────────────────────────────────────────────────────────────────────────────────────────".dimmed());

                        for entry in &store.audit_log[start..] {
                            let dt = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| entry.timestamp.to_string());
                            let action_color = match entry.action.as_str() {
                                "member_revoked" | "invite_revoked" => entry.action.bright_red(),
                                "joined_via_invite" | "invite_created" => {
                                    entry.action.bright_green()
                                }
                                _ => entry.action.cyan(),
                            };
                            println!(
                                "  {:<20} {:<18} {:<16} {:<20} {}",
                                dt.dimmed(),
                                action_color,
                                entry.actor.yellow(),
                                entry.target.white(),
                                entry.details.dimmed()
                            );
                        }
                    }
                    println!();
                }
            }
        }

        Some(Commands::Join { invite }) => {
            let invite_details = MeshInviteToken::decode_uri(&invite)?;
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            if now >= invite_details.expires_at {
                return Err("Einladungs-Token ist abgelaufen.".to_string());
            }
            let network_store = match networks_path.symlink_metadata() {
                Ok(_) => Some(sb_mesh::network::NetworkStore::load_or_create_default(
                    &networks_path,
                    "",
                )?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(format!("Mesh-Katalog konnte nicht geprüft werden: {error}"))
                }
            };
            let join_paths =
                sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, &invite_details.mesh_name)?;
            join_paths.ensure()?;
            let identity = std::sync::Arc::new(
                if network_store
                    .as_ref()
                    .is_some_and(|store| store.networks.contains_key(&invite_details.mesh_name))
                {
                    NodeIdentity::load_registered_for_mesh(&invite_details.mesh_name)?
                } else {
                    NodeIdentity::load_or_generate(&join_paths.identity)?
                },
            );
            if !join_paths.config.exists() {
                MeshConfig::default().save(&join_paths.config)?;
            } else {
                MeshConfig::load_or_create(&join_paths.config)?;
            }
            if !join_paths.peers.exists() {
                PeerTable::new().save_to_file(&join_paths.peers)?;
            }
            println!(
                "{}",
                "═════════════════════════════════════════════════════════════════════════════"
                    .bold()
                    .cyan()
            );
            println!(
                "  {} // {}",
                "S&B SOVEREIGN MESH".cyan().bold(),
                "ONE-CLICK JOIN HANDSHAKE".bold()
            );
            println!(
                "{}",
                "═════════════════════════════════════════════════════════════════════════════"
                    .bold()
                    .cyan()
            );
            println!("  Löse Einladungs-Token auf...");

            match sb_mesh::ticket::join_with_invite(
                &invite,
                &identity,
                std::time::Duration::from_secs(5),
            )
            .await
            {
                Ok(grant) => {
                    if !sb_mesh::network::validate_cidr(&grant.overlay_subnet) {
                        return Err(
                            "Server hat kein gültiges Mesh-Subnetz im Ticket übermittelt."
                                .to_string(),
                        );
                    }
                    let mesh_name =
                        sb_mesh::state::normalize_mesh_name(&grant.granted_mesh)?.to_string();
                    let mut joined_networks =
                        network_store.unwrap_or_else(|| sb_mesh::network::NetworkStore {
                            path: networks_path.clone(),
                            active_network: mesh_name.clone(),
                            networks: std::collections::HashMap::new(),
                        });
                    if let Some(existing) = joined_networks.networks.get(&mesh_name) {
                        if existing.wireguard_pubkey != identity.wireguard_pubkey
                            || existing.overlay_subnet != grant.overlay_subnet
                            || existing.swarm_topic != grant.swarm_topic
                        {
                            return Err(format!(
                            "Lokale Mesh-Metadaten für '{}' weichen vom Invite ab; bitte Eintrag prüfen und erneut beitreten.",
                            mesh_name
                        ));
                        }
                    } else {
                        joined_networks.create_network(
                            &mesh_name,
                            &format!("Beigetretenes Sovereign Mesh ({mesh_name})"),
                            &grant.overlay_subnet,
                            &identity.wireguard_pubkey,
                            Some(&grant.swarm_topic),
                            None,
                            None,
                        )?;
                    }
                    joined_networks.switch_network(&mesh_name)?;
                    println!("\n  {} Erfolgreich beigetreten!", "✓".bright_green().bold());
                    println!(
                        "  {:<24} {}",
                        "Mesh-Netzwerk:",
                        grant.granted_mesh.bright_cyan().bold()
                    );
                    println!(
                        "  {:<24} {}",
                        "Server Node ID:",
                        grant.server_node_id.bright_yellow()
                    );
                    println!(
                        "  {:<24} {}",
                        "Server Public Key:",
                        grant.server_pubkey.dimmed()
                    );
                    println!("  {:<24} {}", "Rolle:", grant.role.bright_green().bold());
                    println!(
                        "  {:<24} {}",
                        "Capabilities:",
                        grant.capabilities.join(", ").white()
                    );
                    println!("  {:<24} {}", "Swarm Topic:", grant.swarm_topic.cyan());
                    println!(
                        "\n  {} Authentifiziertes Ticket lokal im Cache gesichert.",
                        "●".bright_cyan()
                    );
                    println!(
                        "  Verbinde dich jetzt mit: {}",
                        format!("sb stealth --mesh {}", grant.granted_mesh)
                            .bright_yellow()
                            .bold()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "\n  {} Fehler beim Beitreten: {}",
                        "✗".bright_red().bold(),
                        e
                    );
                    std::process::exit(1);
                }
            }
            println!();
        }

        Some(Commands::Invite { sub }) => {
            let identity = std::sync::Arc::new(NodeIdentity::load_or_generate_default()?);
            let networks_file = sb_core::paths::sb_mesh_dir().join("networks.json");
            let net_store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_file,
                &identity.wireguard_pubkey,
            );
            let active_mesh_name = net_store
                .as_ref()
                .map(|st| st.active_network.clone())
                .unwrap_or_else(|_| "dev-mesh".to_string());

            match sub {
                InviteCommands::Create {
                    name,
                    role,
                    groups,
                    ttl,
                    uses,
                    mesh,
                    print,
                } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    let identity = NodeIdentity::load_registered_for_mesh(&target_mesh)?;
                    let parsed_role = MeshRole::from_str(&role).ok_or_else(|| {
                        format!("Ungültige Rolle '{}'. Verfügbar: Admin, Developer, Operator, Consumer, Auditor", role)
                    })?;

                    let suite_cfg = sb_core::config::SuiteConfig::load();
                    let server_endpoint =
                        suite_cfg.network.default_server.clone().unwrap_or_else(|| {
                            format!(
                                "{}:58888",
                                suite_cfg
                                    .network
                                    .expected_node_ip
                                    .unwrap_or_else(|| "127.0.0.1".into())
                            )
                        });

                    let net = net_store
                        .as_ref()
                        .ok()
                        .and_then(|st| st.networks.get(&target_mesh))
                        .cloned();
                    let swarm_topic = net
                        .map(|n| n.swarm_topic)
                        .unwrap_or_else(|| format!("sbm-swarm-{}", target_mesh));

                    let group_list: Vec<String> = groups
                        .map(|g| {
                            g.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();
                    let now = chrono::Utc::now().timestamp() as u64;
                    let expires_at = now + (ttl * 3600);
                    let rand_id = format!("{:08x}", rand::random::<u32>());
                    let token_id = format!("inv-{}", rand_id);

                    let token = MeshInviteToken {
                        token_id: token_id.clone(),
                        mesh_name: target_mesh.clone(),
                        user_name: name.clone(),
                        role: parsed_role,
                        groups: group_list,
                        capabilities: parsed_role.default_capabilities(),
                        server_endpoint,
                        server_pubkey: identity.wireguard_pubkey.clone(),
                        swarm_topic,
                        created_at: now,
                        expires_at,
                        max_uses: uses,
                        current_uses: 0,
                        revoked: false,
                        signature: MeshInviteToken::new_secret(),
                    };

                    let uri = token.encode_uri();
                    let uri_file = token.write_uri_file(&uri)?;
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    store.add_invite(token.to_stored());
                    store.save()?;

                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());
                    println!(
                        "  {} // {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "EINLADUNGS-TOKEN ERSTELLT".bold()
                    );
                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());
                    println!("  {:<20} {}", "Token ID:".bold(), token_id.bright_yellow());
                    println!("  {:<20} {}", "Nutzer:".bold(), name.bright_white().bold());
                    println!(
                        "  {:<20} {}",
                        "Mesh-Netzwerk:".bold(),
                        target_mesh.bright_cyan().bold()
                    );
                    println!(
                        "  {:<20} {}",
                        "Rolle:".bold(),
                        parsed_role.badge().bright_green()
                    );
                    println!(
                        "  {:<20} {} Stunden",
                        "Gültig für:".bold(),
                        ttl.to_string().white()
                    );
                    println!(
                        "  {:<20} {}",
                        "Max. Nutzungen:".bold(),
                        if uses == 0 {
                            "Unbegrenzt".to_string()
                        } else {
                            uses.to_string()
                        }
                    );
                    if print {
                        println!(
                            "\n  {} Invite-URI (Bearer-Credential, nicht loggen!):",
                            "►".bright_green().bold()
                        );
                        println!("  {}\n", uri.bright_white().bold());
                    } else {
                        println!(
                            "\n  {} Invite-URI gespeichert (nur Besitzer lesbar): {}",
                            "►".bright_green().bold(),
                            uri_file.display().to_string().bright_white().bold()
                        );
                        println!("  (Mit --print auf stdout ausgeben.)\n");
                    }
                    println!("  Der Nutzer führt auf seiner Maschine einfach aus:");
                    println!("  {}\n", "sb-mesh join <invite-uri>".bright_yellow().bold());
                }

                InviteCommands::List { mesh } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    let store = MeshRbacStore::load_or_create(&target_mesh)?;

                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());
                    println!(
                        "  {} // {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "AKTIVE EINLADUNGS-TOKENS".bold()
                    );
                    println!("  Mesh: {}", target_mesh.bright_yellow().bold());
                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());

                    if store.invites.is_empty() {
                        println!("  {}", "Keine Einladungs-Tokens vorhanden.".dimmed());
                    } else {
                        let now = chrono::Utc::now().timestamp() as u64;
                        println!(
                            "  {:<14} {:<16} {:<12} {:<10} {:<18} {}",
                            "TOKEN ID".bold(),
                            "NUTZER".bold(),
                            "ROLLE".bold(),
                            "NUTZUNGEN".bold(),
                            "STATUS".bold(),
                            "ABLAUF".bold()
                        );
                        println!("  {}", "─────────────────────────────────────────────────────────────────────────────────────────────".dimmed());

                        for inv in &store.invites {
                            let status = if inv.revoked {
                                "REVOZIERT".bright_red().bold()
                            } else if now >= inv.expires_at {
                                "ABGELAUFEN".dimmed()
                            } else if inv.max_uses > 0 && inv.current_uses >= inv.max_uses {
                                "VERBRAUCHT".yellow()
                            } else {
                                "AKTIV".green().bold()
                            };

                            let exp_dt = chrono::DateTime::from_timestamp(inv.expires_at as i64, 0)
                                .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
                                .unwrap_or_else(|| inv.expires_at.to_string());

                            let uses_str = format!(
                                "{}/{}",
                                inv.current_uses,
                                if inv.max_uses == 0 {
                                    "∞".into()
                                } else {
                                    inv.max_uses.to_string()
                                }
                            );
                            println!(
                                "  {:<14} {:<16} {:<12} {:<10} {:<18} {}",
                                inv.token_id.yellow(),
                                inv.user_name.white().bold(),
                                inv.role.badge().cyan(),
                                uses_str,
                                status,
                                exp_dt.dimmed()
                            );
                        }
                    }
                    println!();
                }

                InviteCommands::Revoke { token, mesh } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    if store.revoke_invite(&token) {
                        store.save()?;
                        println!(
                            "  {} Einladungs-Token '{}' erfolgreich für Mesh '{}' revoziert.",
                            "✓".bright_red().bold(),
                            token,
                            target_mesh
                        );
                    } else {
                        eprintln!(
                            "  {} Einladungs-Token '{}' nicht gefunden.",
                            "✗".bright_red(),
                            token
                        );
                    }
                }
            }
        }

        Some(Commands::Group { sub }) => {
            let identity = std::sync::Arc::new(NodeIdentity::load_or_generate_default()?);
            let networks_file = sb_core::paths::sb_mesh_dir().join("networks.json");
            let net_store = sb_mesh::network::NetworkStore::load_or_create_default(
                &networks_file,
                &identity.wireguard_pubkey,
            );
            let active_mesh_name = net_store
                .as_ref()
                .map(|st| st.active_network.clone())
                .unwrap_or_else(|_| "dev-mesh".to_string());

            match sub {
                GroupCommands::List { mesh } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    let store = MeshRbacStore::load_or_create(&target_mesh)?;

                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());
                    println!(
                        "  {} // {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "ACTIVE DIRECTORY-STYLE GROUPS".bold()
                    );
                    println!("  Mesh: {}", target_mesh.bright_yellow().bold());
                    println!("{}", "═════════════════════════════════════════════════════════════════════════════".bold().cyan());

                    if store.groups.is_empty() {
                        println!("  {}", "Keine Gruppen definiert.".dimmed());
                    } else {
                        println!(
                            "  {:<20} {:<32} {}",
                            "GRUPPEN-NAME".bold(),
                            "BESCHREIBUNG".bold(),
                            "CAPABILITIES".bold()
                        );
                        println!("  {}", "─────────────────────────────────────────────────────────────────────────────────────────────".dimmed());

                        for g in &store.groups {
                            println!(
                                "  {:<20} {:<32} {}",
                                format!("@{}", g.name).bright_green().bold(),
                                g.description.dimmed(),
                                g.capabilities.join(", ").cyan()
                            );
                        }
                    }
                    println!();
                }

                GroupCommands::Add {
                    name,
                    desc,
                    caps,
                    mesh,
                } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    let cap_list: Vec<String> = caps
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    let group = MeshGroup::new(&name, &desc, cap_list);
                    store.add_or_update_group(group);
                    store.save()?;

                    println!(
                        "  {} Gruppe '@{}' erfolgreich im Mesh '{}' gespeichert!",
                        "✓".bright_green().bold(),
                        name,
                        target_mesh
                    );
                }

                GroupCommands::Remove { name, mesh } => {
                    let target_mesh = mesh.unwrap_or(active_mesh_name);
                    let mut store = MeshRbacStore::load_or_create(&target_mesh)?;
                    if store.remove_group(&name) {
                        store.save()?;
                        println!(
                            "  {} Gruppe '@{}' aus Mesh '{}' gelöscht.",
                            "✓".bright_green(),
                            name,
                            target_mesh
                        );
                    } else {
                        eprintln!("  {} Gruppe '@{}' nicht gefunden.", "✗".bright_red(), name);
                    }
                }
            }
        }

        Some(Commands::Dns { sub }) => {
            let cmd = sub.unwrap_or(DnsCommands::Status);
            match cmd {
                DnsCommands::Setup { ip } => {
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {} {} {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "//".black().bold(),
                        "MAGIC SPLIT-DNS OS INTEGRATION".bold()
                    );
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  Konfiguriere OS-weites Routing für '{}' Domain-Anfragen an '{}'...",
                        ".sbm".yellow().bold(),
                        ip.cyan()
                    );

                    match sb_dns::os_integration::OsIntegration::install_split_dns(&ip) {
                        Ok(msg) => {
                            println!("  {} {}", "✓".bright_green().bold(), msg.bright_green());
                            println!("  {} Domain-Namen im Mesh (z.B. node-xyz.sbm, service.sbm) werden nun transparent lokal aufgelöst.", "●".bright_cyan());
                        }
                        Err(err) => {
                            eprintln!(
                                "  {} Split-DNS Einrichtung fehlgeschlagen: {}",
                                "✗".bright_red().bold(),
                                err
                            );
                            #[cfg(target_os = "windows")]
                            {
                                eprintln!(
                                    "\n  {} Administrator-Rechte erforderlich:",
                                    "Tipp:".bright_yellow().bold()
                                );
                                eprintln!("    Starte PowerShell als Administrator und führe aus:");
                                eprintln!("    Add-DnsClientNrptRule -Namespace '.sbm' -NameServers '{}' -DisplayName 'Sovereign-SBM'", ip);
                            }
                            #[cfg(target_os = "linux")]
                            {
                                eprintln!(
                                    "\n  {} Root-Rechte erforderlich:",
                                    "Tipp:".bright_yellow().bold()
                                );
                                eprintln!("    sudo resolvectl domain <interface> ~sbm");
                                eprintln!("    sudo resolvectl dns <interface> {}", ip);
                            }
                        }
                    }
                    println!();
                }
                DnsCommands::Teardown => {
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {} {} {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "//".black().bold(),
                        "REMOVE SPLIT-DNS ROUTING".bold()
                    );
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    match sb_dns::os_integration::OsIntegration::uninstall_split_dns() {
                        Ok(msg) => {
                            println!("  {} {}", "✓".bright_green().bold(), msg.bright_green());
                        }
                        Err(err) => {
                            eprintln!(
                                "  {} Entfernen fehlgeschlagen: {}",
                                "✗".bright_red().bold(),
                                err
                            );
                        }
                    }
                    println!();
                }
                DnsCommands::Status => {
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    println!(
                        "  {} {} {}",
                        "S&B SOVEREIGN MESH".cyan().bold(),
                        "//".black().bold(),
                        "MAGIC SPLIT-DNS STATUS".bold()
                    );
                    println!(
                        "{}",
                        "══════════════════════════════════════════════════════════════════"
                            .bold()
                            .black()
                    );
                    let active = sb_dns::os_integration::OsIntegration::is_split_dns_active();
                    if active {
                        println!(
                            "  {:<24} {}",
                            "Split-DNS (.sbm):",
                            "AKTIV (OS leitet *.sbm transparent an Mesh DNS weiter)"
                                .bright_green()
                                .bold()
                        );
                    } else {
                        println!(
                            "  {:<24} {}",
                            "Split-DNS (.sbm):",
                            "INAKTIV (Keine OS-spezifische Richtlinie hinterlegt)".bright_yellow()
                        );
                        println!(
                            "\n  {} Aktiviere mit: {}",
                            "Tipp:".dimmed(),
                            "sb-mesh dns setup".bright_cyan().bold()
                        );
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}
