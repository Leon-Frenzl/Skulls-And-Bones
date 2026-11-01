use clap::Parser;
use colored::*;

mod cli;
mod cockpit;
mod commands;
mod context;
mod logger;
mod logs;
mod meta;
mod process_ledger;
mod quorum;
mod trace;

use cli::{
    Cli, Commands, DriveAction, EscapeAction, InviteAction, QuorumAction, ReleaseAction,
    ServerAction, WebAction,
};
use commands::config::handle_config;
use commands::context::{handle_context_cmd, handle_use_cmd};
use commands::daemon::run_daemon;
use commands::delegate::delegate_to;
use commands::doctor::{handle_completions, handle_doctor};
use commands::drive::{handle_drive_cat, handle_drive_get, handle_drive_ls, handle_drive_write};
use commands::env::handle_sb_env;
use commands::fleet::{
    handle_approve, handle_invite_client, handle_invite_list, handle_join, handle_revoke,
    handle_server_init, handle_server_list, handle_server_token,
};
use commands::init::handle_sb_init;
use commands::logs::handle_logs_cmd;
use commands::pkg::{
    cleanup_old_binary, handle_identity, handle_install_with_options, handle_uninstall,
    handle_update_with_options,
};
use commands::share::handle_share;
use commands::status::handle_status;

fn main() {
    const STACK_SIZE: usize = 8 * 1024 * 1024;
    let child = std::thread::Builder::new()
        .name("sb-main".to_string())
        .stack_size(STACK_SIZE)
        .spawn(real_main);

    match child {
        Ok(handle) => match handle.join() {
            Ok(()) => {}
            Err(e) => {
                std::panic::resume_unwind(e);
            }
        },
        Err(_) => {
            real_main();
        }
    }
}

fn real_main() {
    // Piped output must stay free of ANSI escapes (NO_COLOR is honoured by `colored` itself).
    {
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            colored::control::set_override(false);
        }
    }
    cleanup_old_binary();
    let _ = sb_core::config::SuiteConfig::prompt_first_run();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Status { json: true }) => {
            commands::status::handle_status_json();
        }
        Some(Commands::Status { json: false }) | None => {
            handle_status();
        }
        Some(Commands::Up { fix, json }) => {
            commands::up::handle_up(fix, json);
        }
        Some(Commands::Service { action, json }) => {
            commands::service::handle_service(action, json);
        }
        Some(Commands::Link {
            target,
            name,
            mesh,
            json,
        }) => {
            commands::link::handle_link(&target, name, mesh, json);
        }
        Some(Commands::Catalog { json }) => {
            if let Err(error) = commands::catalog::handle_catalog(json) {
                eprintln!("Suite-Produktinventar konnte nicht geladen werden: {error}");
                std::process::exit(1);
            }
        }
        Some(Commands::Ps) => {
            process_ledger::cmd_ps();
        }
        Some(Commands::Stop { target }) => {
            process_ledger::cmd_stop(target.as_deref());
        }
        Some(Commands::Lease { args }) => {
            let mut pass_args = vec!["lease".to_string()];
            pass_args.extend(args);
            delegate_to("key", "sb-key", &pass_args);
        }
        Some(Commands::Lock) => {
            delegate_to("key", "sb-key", &["lock".to_string()]);
        }
        Some(Commands::Key { args }) => {
            delegate_to("key", "sb-key", &args);
        }
        Some(Commands::Init { force, template }) => {
            handle_sb_init(force, template.as_deref());
        }
        Some(Commands::Run { env, command }) => {
            handle_sb_env(cli::EnvAction::Run { env, command });
        }
        Some(Commands::Env { action }) => {
            handle_sb_env(action);
        }
        Some(Commands::Doctor { fix, json }) => {
            handle_doctor(fix, json);
        }
        Some(Commands::Completions { shell }) => {
            handle_completions(shell);
        }
        Some(Commands::Share { port, name }) => {
            handle_share(port, name);
        }
        Some(Commands::Install {
            tools,
            force,
            allow_downgrade,
            from_dir,
            from_url,
            from_mesh,
        }) => {
            if let Err(error) = handle_install_with_options(
                &tools,
                force,
                allow_downgrade,
                from_dir,
                from_url,
                from_mesh,
            ) {
                eprintln!("Installation fehlgeschlagen: {error}");
                std::process::exit(1);
            }
        }
        Some(Commands::Uninstall { tools }) => {
            handle_uninstall(&tools);
        }
        Some(Commands::Update {
            tools,
            allow_downgrade,
            from_dir,
            from_url,
            from_mesh,
        }) => {
            if let Err(error) =
                handle_update_with_options(&tools, allow_downgrade, from_dir, from_url, from_mesh)
            {
                eprintln!("Update fehlgeschlagen: {error}");
                std::process::exit(1);
            }
        }
        Some(Commands::Release { action }) => match action {
            ReleaseAction::Pack {
                version,
                target,
                input_dir,
                output_dir,
                format,
            } => {
                if let Err(error) = commands::release::pack_release(
                    &version,
                    &target,
                    &input_dir,
                    &output_dir,
                    &format,
                ) {
                    eprintln!("Release-Packaging fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
            ReleaseAction::PackAll {
                version,
                target,
                input_dir,
                output_dir,
                format,
                key_file,
            } => {
                if let Err(error) = commands::release::pack_all_release(
                    &version,
                    target.as_deref(),
                    &input_dir,
                    &output_dir,
                    &format,
                    key_file.as_deref(),
                ) {
                    eprintln!("Suite-Release-Packaging fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
            ReleaseAction::Sign { manifest, key_file } => {
                if let Err(error) = commands::release::sign_release_manifest(&manifest, &key_file) {
                    eprintln!("Release-Signierung fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
            ReleaseAction::Verify { bin_dir, manifest } => {
                if let Err(error) = commands::release::verify_release_integrity(
                    bin_dir.as_deref(),
                    manifest.as_deref(),
                ) {
                    eprintln!("Release-Verifikation fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
            ReleaseAction::GenKey { output } => {
                if let Err(error) = commands::release::generate_release_keypair(&output) {
                    eprintln!("Schlüsselerzeugung fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
            ReleaseAction::VerifyKey { key_file } => {
                if let Err(error) = commands::release::verify_release_key(&key_file) {
                    eprintln!("Schlüsselprüfung fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
            ReleaseAction::Publish {
                manifest,
                key_file,
                mesh,
                namespace,
            } => {
                if let Err(error) = commands::release::publish_release_to_mesh(
                    &manifest,
                    key_file.as_deref(),
                    &mesh,
                    &namespace,
                ) {
                    eprintln!("Release-Veröffentlichung im Mesh fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
            ReleaseAction::Fetch {
                version,
                target,
                mesh,
                namespace,
                out_dir,
            } => {
                if let Err(error) = commands::release::fetch_release_from_mesh(
                    &version,
                    target.as_deref(),
                    &mesh,
                    &namespace,
                    &out_dir,
                ) {
                    eprintln!("Release-Abruf aus dem Mesh fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
        },
        Some(Commands::Identity) => {
            handle_identity();
        }
        Some(Commands::Ssh { args }) => {
            commands::ssh::handle_ssh(&args);
        }
        Some(Commands::Forge { args }) => {
            delegate_to("forge", "sb-forge", &args);
        }
        Some(Commands::Mesh { args }) => {
            delegate_to("mesh", "sb-mesh", &args);
        }
        Some(Commands::Cockpit {
            snapshot,
            poll_interval,
        }) => {
            if let Err(e) = cockpit::run_cockpit(snapshot, poll_interval) {
                eprintln!("Fehler beim Starten des Cockpits: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Vault { args }) => {
            if args.iter().any(|a| a == "--tui" || a == "-t") || which::which("sb-vault").is_err() {
                if let Err(e) = cockpit::run_cockpit(false, 1000) {
                    eprintln!("Fehler beim Starten des Cockpits: {}", e);
                    std::process::exit(1);
                }
            } else {
                delegate_to("vault", "sb-vault", &args);
            }
        }
        Some(Commands::Node { action }) => match action {
            Some(cli::NodeAction::Bootstrap(args)) => {
                if let Err(e) = commands::bootstrap::handle_node_bootstrap(args) {
                    eprintln!("Fehler beim Node-Bootstrap: {}", e);
                    std::process::exit(1);
                }
            }
            Some(cli::NodeAction::External(args)) => {
                delegate_to("node", "sb-node", &args);
            }
            None => {
                delegate_to("node", "sb-node", &[]);
            }
        },
        Some(Commands::Code { args }) => {
            delegate_to("code", "sb-code", &args);
        }
        Some(Commands::Proxy { args }) => {
            delegate_to("proxy", "sb-proxy", &args);
        }
        Some(Commands::Dns { args }) => {
            delegate_to("dns", "sb-dns", &args);
        }
        Some(Commands::Db { args }) => {
            delegate_to("db", "sb-db", &args);
        }
        Some(Commands::Ca { args }) => {
            delegate_to("ca", "sb-ca", &args);
        }
        Some(Commands::Auth { args }) => {
            delegate_to("auth", "sb-auth", &args);
        }
        Some(Commands::Publish { args }) => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            if cwd.join("tools").is_dir() && args.is_empty() {
                eprintln!(
                    "  {} {}\n  ► Das Monorepo 'Skulls-And-Bones' darf nicht als monolithischer Stream im Mesh liegen.\n  ► Veröffentliche stattdessen ein einzelnes Werkzeug:\n    • {}\n    • oder wechsle in den Ordner: {}",
                    "✗".bright_red().bold(),
                    "Monorepo-Schutz aktiv: Veröffentlichung blockiert.".bold(),
                    "sb publish <tool-name> (z.B. sb publish sb-ssh)".cyan(),
                    "cd tools/sb-ssh && sb publish".yellow()
                );
                std::process::exit(1);
            }
            let mut full_args = vec!["publish".to_string()];
            full_args.extend(args);
            delegate_to("code", "sb-code", &full_args);
        }
        Some(Commands::Subscribe { args }) => {
            if let Some(target) = args.first() {
                let target_lower = target.to_lowercase();
                if target_lower.contains("skulls-and-bones")
                    || target_lower.contains("workspace")
                    || target_lower == "suite"
                {
                    eprintln!(
                        "  {} {}\n  ► Das Monorepo liegt nicht im Mesh.\n  ► Alle Werkzeuge sind modular aufgebaut. Abonniere z.B.: {}",
                        "✗".bright_red().bold(),
                        "Monorepo-Schutz aktiv: Abonnieren nicht möglich.".bold(),
                        "sb subscribe sb-ssh".cyan()
                    );
                    std::process::exit(1);
                }
            }
            let mut full_args = vec!["subscribe".to_string()];
            full_args.extend(args);
            delegate_to("code", "sb-code", &full_args);
        }
        Some(Commands::Server { action }) => match action {
            ServerAction::Init {
                target,
                name,
                port,
                identity,
                password,
                user,
                dry_run,
            } => {
                handle_server_init(&target, name, port, identity, password, user, dry_run);
            }
            ServerAction::Token { name } => {
                handle_server_token(&name);
            }
            ServerAction::List => {
                handle_server_list();
            }
            ServerAction::Provision {
                host,
                login,
                admin,
                pubkey,
                port,
                meshes,
                binaries,
                print_script,
            } => {
                if let Err(e) = commands::provision::handle_server_provision(
                    &host,
                    &login,
                    &admin,
                    pubkey,
                    port,
                    meshes,
                    binaries,
                    print_script,
                ) {
                    eprintln!("  {} {}", "✗".bright_red().bold(), e);
                    std::process::exit(1);
                }
            }
        },
        Some(Commands::Invite { action }) => match action {
            InviteAction::Client { name, role, ttl } => {
                handle_invite_client(&name, &role, ttl);
            }
            InviteAction::List => {
                handle_invite_list();
            }
        },
        Some(Commands::Approve {
            request_id,
            approver,
        }) => {
            handle_approve(&request_id, approver.as_deref());
        }
        Some(Commands::Join { token, name }) => {
            handle_join(&token, name);
        }
        Some(Commands::Revoke { name, reason }) => {
            handle_revoke(&name, &reason);
        }
        Some(Commands::Escape { action }) => match action {
            EscapeAction::Share {
                port,
                domain,
                gateway,
            } => {
                let args = vec![
                    "escape".to_string(),
                    "share".to_string(),
                    port.to_string(),
                    "--as".to_string(),
                    domain,
                    "--gateway".to_string(),
                    gateway,
                ];
                delegate_to("code", "sb-code", &args);
            }
            EscapeAction::List => {
                let args = vec!["escape".to_string(), "list".to_string()];
                delegate_to("code", "sb-code", &args);
            }
            EscapeAction::Tunnel { space, enable } => {
                let mut args = vec!["escape".to_string(), "tunnel".to_string(), space];
                if enable {
                    args.push("--enable".to_string());
                }
                delegate_to("code", "sb-code", &args);
            }
        },
        Some(Commands::Web { action }) => match action {
            WebAction::Publish {
                domain,
                project_dir,
                port,
                node,
            } => {
                let runtime = tokio::runtime::Runtime::new()
                    .expect("Tokio-Runtime konnte nicht initialisiert werden");
                if let Err(error) =
                    runtime.block_on(commands::web::publish(&domain, &project_dir, port, &node))
                {
                    eprintln!("Web-Veröffentlichung fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
        },
        Some(Commands::Context { action }) => {
            handle_context_cmd(action);
        }
        Some(Commands::Use { name }) => {
            handle_use_cmd(&name);
        }
        Some(Commands::Logs {
            server,
            service,
            follow,
            lines,
            local,
        }) => {
            handle_logs_cmd(server, service, follow, lines, local);
        }
        Some(Commands::Trace {
            server,
            watch,
            interval,
        }) => {
            trace::run_trace(server, watch, interval);
        }
        Some(Commands::Quorum { action }) => match action {
            QuorumAction::List { all, category } => {
                quorum::handle_quorum_list(all, category.as_deref());
            }
            QuorumAction::Create {
                category,
                target,
                description,
                required,
                ttl,
                payload,
                initiator,
            } => {
                quorum::handle_quorum_create(
                    &category,
                    &target,
                    &description,
                    required,
                    ttl,
                    payload.as_deref(),
                    initiator.as_deref(),
                );
            }
            QuorumAction::Approve { id, approver } => {
                quorum::handle_quorum_approve(&id, approver.as_deref());
            }
            QuorumAction::Reject {
                id,
                reason,
                rejecter,
            } => {
                quorum::handle_quorum_reject(&id, reason.as_deref(), rejecter.as_deref());
            }
            QuorumAction::Show { id } => {
                quorum::handle_quorum_show(&id);
            }
            QuorumAction::Execute { id } => {
                quorum::handle_quorum_execute(&id);
            }
        },
        Some(Commands::Drive { action }) => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio runtime");
            rt.block_on(async {
                match action {
                    DriveAction::Serve {
                        root,
                        bind,
                        mesh,
                        catalog,
                        grant_policy,
                    } => {
                        let bind = match bind.parse() {
                            Ok(address) => address,
                            Err(error) => {
                                eprintln!("Ungültige sb-drive Bind-Adresse: {error}");
                                std::process::exit(2);
                            }
                        };
                        let catalog = match catalog {
                            Some(path) => path,
                            None => match sb_drive::stream::default_catalog_path(&mesh) {
                                Ok(path) => path,
                                Err(error) => {
                                    eprintln!("Ungültiger sb-drive Catalog-Pfad: {error}");
                                    std::process::exit(2);
                                }
                            },
                        };
                        let policy = match grant_policy
                            .map(|path| sb_drive::stream::AppGrantPolicy::from_config_file(&path))
                            .transpose()
                        {
                            Ok(policy) => policy.map(std::sync::Arc::new),
                            Err(error) => {
                                eprintln!("Ungültige Grant-Policy: {error}");
                                std::process::exit(2);
                            }
                        };
                        if let Err(error) =
                            sb_drive::stream::serve_with_policy(root, bind, mesh, catalog, policy)
                                .await
                        {
                            eprintln!("sb-drive Stream-Dienst fehlgeschlagen: {error}");
                            std::process::exit(1);
                        }
                    }
                    DriveAction::Ls { peer, path } => {
                        handle_drive_ls(&peer, path.as_deref()).await;
                    }
                    DriveAction::Cat { peer, path } => {
                        handle_drive_cat(&peer, &path).await;
                    }
                    DriveAction::Write {
                        peer,
                        path,
                        content,
                    } => {
                        handle_drive_write(&peer, &path, &content).await;
                    }
                    DriveAction::Get { peer, path } => {
                        handle_drive_get(&peer, &path).await;
                    }
                }
            });
        }
        Some(Commands::AppPublish { action }) => {
            let result = match action {
                cli::PublishAction::Keygen { out } => commands::publish::keygen(&out)
                    .map(|public| format!("Öffentlicher Publisher-Schlüssel: {public}")),
                cli::PublishAction::Pack {
                    manifest,
                    artifact,
                    key,
                    out,
                } => commands::publish::pack(&manifest, &artifact, &key, &out)
                    .map(|size| format!("Bundle geschrieben ({size})")),
                cli::PublishAction::Catalog {
                    bundle,
                    drive_root,
                    catalog,
                    trusted_publishers,
                    owner,
                    readers,
                } => commands::publish::publish_to_catalog(
                    &bundle,
                    &drive_root,
                    &catalog,
                    &trusted_publishers,
                    &owner,
                    &readers,
                )
                .map(|summary| format!("Im Mesh-Katalog veröffentlicht: {summary}")),
            };
            match result {
                Ok(message) => println!("{message}"),
                Err(error) => {
                    eprintln!("sb publish fehlgeschlagen: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Daemon { port, api, detach }) => {
            if detach {
                let daemon_port = port.unwrap_or(sb_core::ports::DEFAULT_DAEMON_API_PORT);
                let mut args = vec![
                    "daemon".to_string(),
                    "--port".to_string(),
                    daemon_port.to_string(),
                ];
                if api {
                    args.push("--api".to_string());
                }
                match process_ledger::ServiceSupervisor::new("daemon")
                    .with_bin("sb")
                    .with_args(args)
                    .with_port(daemon_port)
                    .with_log_file("daemon.log")
                    .spawn_and_track()
                {
                    Ok(p) => {
                        println!(
                            "  {} S&B Daemon erfolgreich im Hintergrund gestartet (PID {}, Port {}).",
                            "✓".bright_green().bold(),
                            p.pid.to_string().cyan(),
                            daemon_port
                        );
                        println!("  Überwachen mit: {}", "sb ps".bright_cyan());
                        println!("  Beenden mit:    {}", "sb stop daemon".bright_cyan());
                    }
                    Err(e) => {
                        eprintln!("Fehler beim Starten des Daemons: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                let rt =
                    tokio::runtime::Runtime::new().expect("Failed to initialize tokio runtime");
                if let Err(e) = rt.block_on(run_daemon(port, api)) {
                    eprintln!("Daemon error: {}", e);
                }
            }
        }
        Some(Commands::Config { action }) => {
            handle_config(action);
        }
    }
}

#[cfg(test)]
pub static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use crate::cli::{Cli, Commands, ReleaseAction};
    use crate::commands::env::parse_dotenv_content;
    use crate::commands::fleet::{
        build_pairing_token, compute_required_quorum, parse_pairing_token, TeamJoinRequest,
    };
    use crate::meta::{available_tools, resolve_tools};
    use clap::Parser;

    #[test]
    fn test_can_rename_running_exe() {
        let current_exe = std::env::current_exe().expect("must get current exe");
        let temp_name = current_exe.with_extension("tmp_test_rename");
        let _ = std::fs::remove_file(&temp_name);
        let res = std::fs::rename(&current_exe, &temp_name);
        println!("Rename result: {:?}", res);
        assert!(
            res.is_ok(),
            "Renaming running binary must succeed on Windows: {:?}",
            res
        );
        // Rename back!
        let res_back = std::fs::rename(&temp_name, &current_exe);
        assert!(
            res_back.is_ok(),
            "Renaming back must succeed: {:?}",
            res_back
        );
    }

    #[test]
    fn test_resolve_tools() {
        // Test "all"
        let (tools, cli) = resolve_tools(&["all".to_string()]).unwrap();
        assert_eq!(tools.len(), available_tools().len());
        assert!(cli);

        // Test specific tool
        let (tools, cli) = resolve_tools(&["drive".to_string()]).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].id, "drive");
        assert!(!cli);

        // Test sb-cli
        let (tools, cli) = resolve_tools(&["sb-cli".to_string()]).unwrap();
        assert_eq!(tools.len(), 0);
        assert!(cli);

        // Test unknown
        let err = resolve_tools(&["unknown_tool".to_string()]);
        assert!(err.is_err());
    }

    #[test]
    fn test_catalog_cli_is_available() {
        let parsed = Cli::try_parse_from(["sb", "catalog", "--json"]).unwrap();
        assert!(matches!(
            parsed.command,
            Some(Commands::Catalog { json: true })
        ));
    }

    #[test]
    fn test_release_pack_and_sign_cli_parsing() {
        let pack = Cli::try_parse_from([
            "sb",
            "release",
            "pack",
            "--version",
            "v1.2.3",
            "--target",
            "x86_64-unknown-linux-musl",
            "--input-dir",
            "target/release",
            "--format",
            "tar.gz",
        ])
        .unwrap();
        assert!(matches!(
            pack.command,
            Some(Commands::Release {
                action: ReleaseAction::Pack { .. }
            })
        ));

        let sign =
            Cli::try_parse_from(["sb", "release", "sign", "--key-file", "release.seed"]).unwrap();
        assert!(matches!(
            sign.command,
            Some(Commands::Release {
                action: ReleaseAction::Sign { .. }
            })
        ));

        let pack_all = Cli::try_parse_from([
            "sb",
            "release",
            "pack-all",
            "--version",
            "v1.2.3",
            "--key-file",
            "release.seed",
        ])
        .unwrap();
        assert!(matches!(
            pack_all.command,
            Some(Commands::Release {
                action: ReleaseAction::PackAll { .. }
            })
        ));

        let verify = Cli::try_parse_from(["sb", "release", "verify"]).unwrap();
        assert!(matches!(
            verify.command,
            Some(Commands::Release {
                action: ReleaseAction::Verify { .. }
            })
        ));

        let gen_key =
            Cli::try_parse_from(["sb", "release", "gen-key", "--output", "my_release.key"])
                .unwrap();
        assert!(matches!(
            gen_key.command,
            Some(Commands::Release {
                action: ReleaseAction::GenKey { .. }
            })
        ));

        let verify_key = Cli::try_parse_from([
            "sb",
            "release",
            "verify-key",
            "--key-file",
            "my_release.key",
        ])
        .unwrap();
        assert!(matches!(
            verify_key.command,
            Some(Commands::Release {
                action: ReleaseAction::VerifyKey { .. }
            })
        ));
    }

    #[test]
    fn test_install_and_update_cli_parsing() {
        use std::path::PathBuf;

        let install_dir = Cli::try_parse_from([
            "sb",
            "install",
            "mesh",
            "code",
            "--force",
            "--from-dir",
            "dist/releases",
        ])
        .unwrap();
        match install_dir.command {
            Some(Commands::Install {
                tools,
                force,
                allow_downgrade,
                from_dir,
                from_url,
                from_mesh,
            }) => {
                assert_eq!(tools, vec!["mesh".to_string(), "code".to_string()]);
                assert!(force);
                assert!(!allow_downgrade);
                assert_eq!(from_dir, Some(PathBuf::from("dist/releases")));
                assert_eq!(from_url, None);
                assert_eq!(from_mesh, None);
            }
            _ => panic!("Expected Install command"),
        }

        let update_url = Cli::try_parse_from([
            "sb",
            "update",
            "--allow-downgrade",
            "--from-url",
            "https://custom-mirror.org/bin",
        ])
        .unwrap();
        match update_url.command {
            Some(Commands::Update {
                tools,
                allow_downgrade,
                from_dir,
                from_url,
                from_mesh,
            }) => {
                assert!(tools.is_empty());
                assert!(allow_downgrade);
                assert_eq!(from_dir, None);
                assert_eq!(from_url.as_deref(), Some("https://custom-mirror.org/bin"));
                assert_eq!(from_mesh, None);
            }
            _ => panic!("Expected Update command"),
        }
    }

    #[test]
    fn test_compute_required_quorum() {
        // Initial state with 0 or 1 member -> single sponsor suffices
        assert_eq!(compute_required_quorum(0), 1);
        assert_eq!(compute_required_quorum(1), 1);

        // Team state with 2 or more members -> 4-Eyes Principle requires 2 approvals
        assert_eq!(compute_required_quorum(2), 2);
        assert_eq!(compute_required_quorum(5), 2);
        assert_eq!(compute_required_quorum(10), 2);
    }

    #[test]
    fn test_parse_pairing_token_roundtrip() {
        let token = "sbm-pair://sbm-zone123/invite?node=bob&ca=ssh-ed25519+AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey";
        let (swarm, node, ca) = parse_pairing_token(token).expect("Token must parse");
        assert_eq!(swarm, "sbm-zone123");
        assert_eq!(node, "bob");
        assert_eq!(ca, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey");
    }

    #[test]
    fn test_build_and_parse_base64_pairing_token() {
        let swarm = "sbm-test-swarm";
        let node = "web01";
        let ca = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleValidKey1234567890";
        let token = build_pairing_token(swarm, node, ca);
        assert!(!token.contains('?'));
        assert!(!token.contains('&'));
        assert!(!token.contains(' '));

        let (parsed_swarm, parsed_node, parsed_ca) =
            parse_pairing_token(&token).expect("Must parse Base64 token");
        assert_eq!(parsed_swarm, swarm);
        assert_eq!(parsed_node, node);
        assert_eq!(parsed_ca, ca);
    }

    #[test]
    fn test_team_request_quorum_transition() {
        let mut req = TeamJoinRequest {
            request_id: "req-test".to_string(),
            candidate_name: "bob".to_string(),
            role: "dev".to_string(),
            sponsor: "alice".to_string(),
            token: "sbm-pair://...".to_string(),
            created_at: "now".to_string(),
            expires_at: "future".to_string(),
            approvals: vec!["alice".to_string()],
            required_quorum: 2,
            status: "pending".to_string(),
        };

        // Initially pending (1/2 approvals)
        assert_eq!(req.status, "pending");
        assert_eq!(req.approvals.len(), 1);

        // Co-sponsor Charlie approves
        let approver = "charlie".to_string();
        if !req.approvals.contains(&approver) {
            req.approvals.push(approver);
            if req.approvals.len() >= req.required_quorum {
                req.status = "approved".to_string();
            }
        }

        // Now approved (2/2 approvals satisfied)
        assert_eq!(req.status, "approved");
        assert_eq!(req.approvals.len(), 2);
    }

    #[test]
    fn test_parse_dotenv_content() {
        let dotenv = r#"
# Kommentar am Anfang
DATABASE_URL=postgres://user:secret@localhost:5432/mydb
export API_KEY="sk_test_123456"
PORT=8080 # Inline-Kommentar
EMPTY_LINE=
QUOTED_SINGLE='some string with spaces'
MULTILINE="first\nsecond"
"#;
        let parsed = parse_dotenv_content(dotenv);
        assert_eq!(parsed.len(), 6); // DATABASE_URL, API_KEY, PORT, EMPTY_LINE, QUOTED_SINGLE, MULTILINE
        assert_eq!(
            parsed[0],
            (
                "DATABASE_URL".to_string(),
                "postgres://user:secret@localhost:5432/mydb".to_string()
            )
        );
        assert_eq!(
            parsed[1],
            ("API_KEY".to_string(), "sk_test_123456".to_string())
        );
        assert_eq!(parsed[2], ("PORT".to_string(), "8080".to_string()));
        assert_eq!(parsed[3], ("EMPTY_LINE".to_string(), "".to_string()));
        assert_eq!(
            parsed[4],
            (
                "QUOTED_SINGLE".to_string(),
                "some string with spaces".to_string()
            )
        );
        assert_eq!(
            parsed[5],
            ("MULTILINE".to_string(), "first\nsecond".to_string())
        );
    }

    #[test]
    fn test_sync_mesh_network_with_context() {
        let temp_dir =
            std::env::temp_dir().join(format!("sb_mesh_sync_test_{}", rand::random::<u32>()));
        let mesh_dir = temp_dir.join(".sb-mesh");
        let _ = std::fs::create_dir_all(&mesh_dir);
        let networks_path = mesh_dir.join("networks.json");

        let initial_json = r#"{
  "active_network": "default",
  "networks": {
    "default": {
      "name": "default",
      "description": "Standard",
      "swarm_topic": "sbm-swarm-default",
      "overlay_subnet": "10.240.0.0/16",
      "listen_port": 58888,
      "wireguard_pubkey": "key1=",
      "psk": null,
      "created_at": "2026-01-01T00:00:00Z",
      "last_active_at": "2026-01-01T00:00:00Z"
    },
    "acme-corp": {
      "name": "acme-corp",
      "description": "Acme Dev",
      "swarm_topic": "sbm-swarm-acme",
      "overlay_subnet": "10.42.0.0/16",
      "listen_port": 58888,
      "wireguard_pubkey": "key2=",
      "psk": null,
      "created_at": "2026-01-01T00:00:00Z",
      "last_active_at": "2026-01-01T00:00:00Z"
    }
  }
}"#;
        std::fs::write(&networks_path, initial_json).unwrap();

        // Mutate logic directly on path
        let content = std::fs::read_to_string(&networks_path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&content).unwrap();
        let context_name = "acme-corp";
        let target_info = if let Some(networks) = json.get("networks").and_then(|n| n.as_object()) {
            networks.get(context_name).map(|n| {
                (
                    context_name.to_string(),
                    n.get("overlay_subnet")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                )
            })
        } else {
            None
        };

        assert!(target_info.is_some());
        let (net_name, subnet) = target_info.unwrap();
        assert_eq!(net_name, "acme-corp");
        assert_eq!(subnet, "10.42.0.0/16");

        json["active_network"] = serde_json::Value::String(net_name);
        std::fs::write(&networks_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let updated_content = std::fs::read_to_string(&networks_path).unwrap();
        let updated_json: serde_json::Value = serde_json::from_str(&updated_content).unwrap();
        assert_eq!(updated_json["active_network"], "acme-corp");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_drive_and_daemon_cli_parsing() {
        use crate::cli::{Cli, Commands, DriveAction};
        use clap::Parser;

        let drive_cmd = Cli::try_parse_from(["sb", "drive", "ls", "local", "/tmp"]).unwrap();
        match drive_cmd.command {
            Some(Commands::Drive {
                action: DriveAction::Ls { peer, path },
            }) => {
                assert_eq!(peer, "local");
                assert_eq!(path.as_deref(), Some("/tmp"));
            }
            _ => panic!("Expected Drive Ls command"),
        }

        let daemon_cmd = Cli::try_parse_from(["sb", "daemon", "--port", "58999"]).unwrap();
        match daemon_cmd.command {
            Some(Commands::Daemon { port, api, detach }) => {
                assert_eq!(port, Some(58999));
                assert!(api);
                assert!(!detach);
            }
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_two_node_pairing_and_workspace_replication_e2e() {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp_root =
            std::env::temp_dir().join(format!("sb_e2e_drill_{}", rand::random::<u32>()));
        let node_a_dir = temp_root.join("node_a");
        let node_b_dir = temp_root.join("node_b");
        std::fs::create_dir_all(&node_a_dir).unwrap();
        std::fs::create_dir_all(&node_b_dir).unwrap();

        // 1. Setup Node A (Admin Swarm Leader)
        std::env::set_var("SB_HOME", node_a_dir.to_str().unwrap());
        std::env::set_var("SB_CALLSIGN", "sponsor-node-a");

        // Seed 2 initial team members on Node A so 4-eyes quorum (2 approvals) is strictly required
        let initial_members = vec![
            crate::commands::fleet::TeamMember {
                name: "sponsor-node-a".to_string(),
                role: "lead".to_string(),
                added_at: "2026-10-09T00:00:00Z".to_string(),
                approved_by: vec!["root".to_string()],
            },
            crate::commands::fleet::TeamMember {
                name: "co-admin-bob".to_string(),
                role: "admin".to_string(),
                added_at: "2026-10-09T00:00:00Z".to_string(),
                approved_by: vec!["root".to_string()],
            },
        ];
        crate::commands::fleet::save_team_members(&initial_members).unwrap();

        // 2. Node A issues invite for candidate "dev-alice"
        crate::commands::fleet::handle_invite_client("dev-alice", "dev", 60);

        let reqs_a = crate::commands::fleet::load_team_requests();
        assert_eq!(reqs_a.len(), 1, "Expected 1 join request on Node A");
        let invite_req = &reqs_a[0];
        assert_eq!(invite_req.candidate_name, "dev-alice");
        assert_eq!(invite_req.status, "pending");
        assert_eq!(invite_req.required_quorum, 2);
        assert_eq!(invite_req.approvals, vec!["sponsor-node-a"]);
        let req_id = invite_req.request_id.clone();
        let token = invite_req.token.clone();

        // 3. Candidate Alice on Node B attempts to join before 4-eyes approval
        std::env::set_var("SB_HOME", node_b_dir.to_str().unwrap());
        std::env::set_var("SB_CALLSIGN", "dev-alice");

        // Alice receives the token and pending request
        crate::commands::fleet::save_team_requests(&reqs_a).unwrap();
        crate::commands::fleet::handle_join(&token, Some("dev-alice".to_string()));

        let members_b_premature = crate::commands::fleet::load_team_members();
        assert!(
            members_b_premature.is_empty(),
            "Node B must NOT be admitted while 4-eyes approval is still pending"
        );

        // 4. Co-Admin Bob on Node A performs the 4-eyes approval
        std::env::set_var("SB_HOME", node_a_dir.to_str().unwrap());
        std::env::set_var("SB_CALLSIGN", "co-admin-bob");
        crate::commands::fleet::handle_approve(&req_id, Some("co-admin-bob"));

        let reqs_a_approved = crate::commands::fleet::load_team_requests();
        let approved_req = reqs_a_approved
            .iter()
            .find(|r| r.request_id == req_id)
            .unwrap();
        assert_eq!(approved_req.status, "approved");
        assert_eq!(approved_req.approvals.len(), 2);
        assert!(approved_req
            .approvals
            .contains(&"sponsor-node-a".to_string()));
        assert!(approved_req.approvals.contains(&"co-admin-bob".to_string()));

        // 5. Node B joins successfully after 4-eyes approval
        std::env::set_var("SB_HOME", node_b_dir.to_str().unwrap());
        std::env::set_var("SB_CALLSIGN", "dev-alice");
        crate::commands::fleet::save_team_requests(&reqs_a_approved).unwrap();
        crate::commands::fleet::handle_join(&token, Some("dev-alice".to_string()));

        let members_b_admitted = crate::commands::fleet::load_team_members();
        assert_eq!(members_b_admitted.len(), 1);
        assert_eq!(members_b_admitted[0].name, "dev-alice");
        assert_eq!(members_b_admitted[0].role, "dev");

        // 6. Dev-Workspace Synchronisation drill (Alice pushed, Node A replicates)
        let alice_repo = node_b_dir.join("workspaces").join("sb-core");
        std::fs::create_dir_all(alice_repo.join("src")).unwrap();
        std::fs::write(
            alice_repo.join("src").join("lib.rs"),
            "pub fn sovereign_code() -> &'static str { \"sovereign\" }\n",
        )
        .unwrap();

        // Alice initializes VCS and commits
        let mut alice_vcs = sb_code::vcs::VcsEngine::init(&alice_repo).unwrap();
        let alice_commit_id = alice_vcs
            .commit(
                "feat(core): initial sovereign code implementation",
                "dev-alice",
            )
            .unwrap();

        // Create DevWorkspacePolicy with Alice as authoritative writer
        let workspace_id = "dev/tools/sb-core";
        let policy = sb_code::dev_workspace::DevWorkspacePolicy::new(
            workspace_id,
            "sb-core",
            "dev-alice",
            vec!["sponsor-node-a".into()],
        )
        .unwrap();

        // Verify policy authorizations
        assert!(policy.authorize_write("dev-alice", None).is_ok());
        assert!(policy.authorize_read("sponsor-node-a", None).is_ok());

        // Unauthorized intruder (mallory) is strictly rejected
        assert!(policy
            .authorize_write("unauthorized-mallory", None)
            .is_err());
        assert!(policy.authorize_read("unauthorized-mallory", None).is_err());

        // Bundle export on Alice's node
        let bundle_bytes = alice_vcs.export_bundle("main", None).unwrap();
        assert!(!bundle_bytes.is_empty(), "Bundle bytes must not be empty");

        // Replicate / Import into Node A's repo
        let node_a_repo = node_a_dir.join("workspaces").join("sb-core");
        std::fs::create_dir_all(&node_a_repo).unwrap();
        let mut admin_vcs = sb_code::vcs::VcsEngine::init(&node_a_repo).unwrap();
        let sync_report = admin_vcs.import_bundle(&bundle_bytes, "main").unwrap();

        // Heads match perfectly across both nodes
        assert_eq!(sync_report.new_head, alice_commit_id.commit_id);

        // Checkout main branch on Node A to write files to disk
        admin_vcs.checkout("main").unwrap();
        let replicated_file = node_a_repo.join("src").join("lib.rs");
        assert!(
            replicated_file.is_file(),
            "Replicated file must exist in Node A"
        );
        let content = std::fs::read_to_string(replicated_file).unwrap();
        assert!(content.contains("sovereign_code"));

        // Cleanup
        std::env::remove_var("SB_HOME");
        std::env::remove_var("SB_CALLSIGN");
        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_quorum_hardening_rejects_self_approval_and_unauthorized_and_expired() {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use super::commands::fleet::{
            handle_approve, load_team_requests, save_team_members, save_team_requests,
            TeamJoinRequest, TeamMember,
        };

        let temp_root =
            std::env::temp_dir().join(format!("sb-hardening-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).unwrap();

        std::env::set_var("SB_HOME", &temp_root);
        std::env::set_var("SB_CALLSIGN", "alice");

        // 1. Setup authorized team members: alice and bob
        save_team_members(&[
            TeamMember {
                name: "alice".to_string(),
                role: "admin".to_string(),
                added_at: "2026-10-09T00:00:00Z".to_string(),
                approved_by: vec![],
            },
            TeamMember {
                name: "bob".to_string(),
                role: "admin".to_string(),
                added_at: "2026-10-09T00:00:00Z".to_string(),
                approved_by: vec![],
            },
        ])
        .unwrap();

        // 2. Setup a valid join request AND an expired request
        let valid_exp = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let past_exp = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        save_team_requests(&[
            TeamJoinRequest {
                request_id: "req-self-test".to_string(),
                candidate_name: "charlie".to_string(),
                role: "dev".to_string(),
                sponsor: "alice".to_string(),
                token: "sbm-pair://test".to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                expires_at: valid_exp,
                approvals: vec!["alice".to_string()],
                required_quorum: 2,
                status: "pending".to_string(),
            },
            TeamJoinRequest {
                request_id: "req-expired-test".to_string(),
                candidate_name: "dave".to_string(),
                role: "dev".to_string(),
                sponsor: "alice".to_string(),
                token: "sbm-pair://expired".to_string(),
                created_at: (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339(),
                expires_at: past_exp,
                approvals: vec!["alice".to_string()],
                required_quorum: 2,
                status: "pending".to_string(),
            },
        ])
        .unwrap();

        // Candidate charlie tries to self-approve -> must be rejected
        handle_approve("req-self-test", Some("charlie"));
        let reqs = load_team_requests();
        let charlie_req = reqs
            .iter()
            .find(|r| r.request_id == "req-self-test")
            .unwrap();
        assert_eq!(
            charlie_req.status, "pending",
            "Candidate must NOT self-approve"
        );
        assert_eq!(charlie_req.approvals.len(), 1);

        // Unauthorized outsider mallory tries to approve -> must be rejected
        handle_approve("req-self-test", Some("mallory"));
        let reqs = load_team_requests();
        let charlie_req = reqs
            .iter()
            .find(|r| r.request_id == "req-self-test")
            .unwrap();
        assert_eq!(
            charlie_req.status, "pending",
            "Unauthorized outsider must NOT approve"
        );
        assert_eq!(charlie_req.approvals.len(), 1);

        // Authorized bob tries to approve an expired request -> must be marked expired and rejected
        handle_approve("req-expired-test", Some("bob"));
        let reqs = load_team_requests();
        let expired_req = reqs
            .iter()
            .find(|r| r.request_id == "req-expired-test")
            .unwrap();
        assert_eq!(
            expired_req.status, "expired",
            "Expired request must be marked expired"
        );

        // Authorized co-admin bob approves valid request -> successfully transitions to approved
        handle_approve("req-self-test", Some("bob"));
        let reqs = load_team_requests();
        let target = reqs
            .iter()
            .find(|r| r.request_id == "req-self-test")
            .unwrap();
        assert_eq!(
            target.status, "approved",
            "Authorized co-admin must satisfy quorum"
        );
        assert_eq!(target.approvals.len(), 2);

        // Cleanup
        std::env::remove_var("SB_HOME");
        std::env::remove_var("SB_CALLSIGN");
        let _ = std::fs::remove_dir_all(&temp_root);
    }
}
