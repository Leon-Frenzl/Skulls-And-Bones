use clap::Parser;
use colored::*;

mod cli;
mod commands;
mod context;
mod logger;
mod logs;
mod meta;
mod process_ledger;

use cli::{Cli, Commands, ReleaseAction, ServerAction};
use commands::context::handle_context_cmd;
use commands::daemon::run_daemon;
use commands::delegate::delegate_to;
use commands::doctor::handle_doctor;
use commands::env::handle_sb_env;
use commands::fleet::{
    handle_domain_bootstrap, handle_join, handle_server_init, handle_server_list,
    handle_server_token,
};
use commands::logs::handle_logs_cmd;
use commands::pkg::{cleanup_old_binary, handle_update_with_options};
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
        } else {
            #[cfg(windows)]
            if colored::control::set_virtual_terminal(true).is_err() {
                colored::control::set_override(false);
            }
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
        Some(Commands::Run { env, command }) => {
            handle_sb_env(cli::EnvAction::Run { env, command });
        }
        Some(Commands::Env { action }) => {
            handle_sb_env(action);
        }
        Some(Commands::Doctor { fix, json }) => {
            handle_doctor(fix, json);
        }
        Some(Commands::Update {
            tools,
            allow_downgrade,
            from_dir,
            from_url,
            from_mesh,
            github,
            tag,
            server,
            from_workspace,
        }) => {
            let no_explicit_source = !github
                && tag.is_none()
                && server.is_none()
                && !from_workspace
                && tools.is_empty()
                && from_dir.is_none()
                && from_url.is_none()
                && from_mesh.is_none();
            let res = if let Some(srv) = server.as_deref() {
                commands::pkg::update_remote_server(srv)
            } else if from_workspace {
                commands::pkg::update_from_local_workspace(&tools)
            } else if no_explicit_source {
                match commands::pkg::try_local_stage_update() {
                    Ok(true) => Ok(()),
                    Ok(false) => commands::pkg::self_update_from_github(tag.as_deref()),
                    Err(e) => Err(e),
                }
            } else if github
                || (tools.is_empty()
                    && from_dir.is_none()
                    && from_url.is_none()
                    && from_mesh.is_none())
            {
                commands::pkg::self_update_from_github(tag.as_deref())
            } else {
                handle_update_with_options(&tools, allow_downgrade, from_dir, from_url, from_mesh)
            };
            if let Err(error) = res {
                sb_core::logfmt::error(
                    "ERR_SB_UPDATE",
                    "sb.pkg",
                    "Update failed",
                    &[("error", &error.to_string())],
                );
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
                    sb_core::logfmt::error(
                        "ERR_RELEASE_PACK",
                        "sb.release",
                        "Release packaging failed",
                        &[("error", &error.to_string())],
                    );
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
                    sb_core::logfmt::error(
                        "ERR_RELEASE_PACK_ALL",
                        "sb.release",
                        "Suite release packaging failed",
                        &[("error", &error.to_string())],
                    );
                    std::process::exit(1);
                }
            }
            ReleaseAction::Sign { manifest, key_file } => {
                if let Err(error) = commands::release::sign_release_manifest(&manifest, &key_file) {
                    sb_core::logfmt::error(
                        "ERR_RELEASE_SIGN",
                        "sb.release",
                        "Release signing failed",
                        &[("error", &error.to_string())],
                    );
                    std::process::exit(1);
                }
            }
            ReleaseAction::Verify { bin_dir, manifest } => {
                if let Err(error) = commands::release::verify_release_integrity(
                    bin_dir.as_deref(),
                    manifest.as_deref(),
                ) {
                    sb_core::logfmt::error(
                        "ERR_RELEASE_VERIFY",
                        "sb.release",
                        "Release verification failed",
                        &[("error", &error.to_string())],
                    );
                    std::process::exit(1);
                }
            }
            ReleaseAction::GenKey { output } => {
                if let Err(error) = commands::release::generate_release_keypair(&output) {
                    sb_core::logfmt::error(
                        "ERR_RELEASE_GENKEY",
                        "sb.release",
                        "Release key generation failed",
                        &[("error", &error.to_string())],
                    );
                    std::process::exit(1);
                }
            }
            ReleaseAction::VerifyKey { key_file } => {
                if let Err(error) = commands::release::verify_release_key(&key_file) {
                    sb_core::logfmt::error(
                        "ERR_RELEASE_VERIFYKEY",
                        "sb.release",
                        "Release key verification failed",
                        &[("error", &error.to_string())],
                    );
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
                    sb_core::logfmt::error(
                        "ERR_RELEASE_PUBLISH",
                        "sb.release",
                        "Release mesh publish failed",
                        &[("error", &error.to_string())],
                    );
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
                    sb_core::logfmt::error(
                        "ERR_RELEASE_FETCH",
                        "sb.release",
                        "Release mesh fetch failed",
                        &[("error", &error.to_string())],
                    );
                    std::process::exit(1);
                }
            }
        },
        Some(Commands::Ssh { args }) => {
            commands::ssh::handle_ssh(&args);
        }
        Some(Commands::Domain { args }) => {
            let mut full = vec!["domain".to_string()];
            full.extend(args);
            delegate_to("domain", "sb-node", &full);
        }
        Some(Commands::Policy { args }) => {
            let mut full = vec!["policy".to_string()];
            full.extend(args);
            delegate_to("policy", "sb-node", &full);
        }
        Some(Commands::Agent { args }) => {
            let mut full = vec!["service".to_string()];
            full.extend(args);
            delegate_to("agent", "sb-node", &full);
        }
        Some(Commands::User { args }) => {
            let mut full = vec!["user".to_string()];
            full.extend(args);
            delegate_to("user", "sb-node", &full);
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
                    sb_core::logfmt::error(
                        "ERR_SB_PROVISION",
                        "sb.server",
                        "Server provisioning failed",
                        &[("error", &e.to_string())],
                    );
                    std::process::exit(1);
                }
            }
            ServerAction::DcInit {
                target,
                domain,
                console_host,
                enroll_host,
                admin,
                password,
                proxy,
                tarball_url,
                dry_run,
            } => {
                commands::fleet::handle_server_dc_init(
                    target.as_deref(),
                    &domain,
                    console_host.as_deref(),
                    enroll_host.as_deref(),
                    &admin,
                    password.as_deref(),
                    &proxy,
                    tarball_url.as_deref(),
                    dry_run,
                );
            }
            ServerAction::Backup { target, out } => {
                commands::fleet::handle_server_backup(target.as_deref(), out.as_deref());
            }
            ServerAction::Restore { input, target } => {
                commands::fleet::handle_server_restore(&input, target.as_deref());
            }
        },
        Some(Commands::Join {
            target,
            name,
            dc,
            token,
            username,
            password,
            no_service,
            dry_run,
        }) => {
            if target.starts_with("sbm-pair://") {
                handle_join(&target, name);
            } else {
                handle_domain_bootstrap(
                    &target,
                    dc.as_deref(),
                    token.as_deref(),
                    username.as_deref(),
                    password.as_deref(),
                    no_service,
                    dry_run,
                );
            }
        }
        Some(Commands::Tunnel {
            machine,
            remote_port,
            local_port,
            dc,
        }) => {
            commands::fleet::handle_tunnel(
                &machine,
                remote_port,
                local_port.unwrap_or(remote_port),
                dc.as_deref(),
            );
        }
        Some(Commands::Context { action }) => {
            handle_context_cmd(action);
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
                        sb_core::logfmt::error(
                            "ERR_SB_DAEMON_START",
                            "sb.daemon",
                            "Failed to start daemon",
                            &[("error", &e.to_string())],
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                let rt =
                    tokio::runtime::Runtime::new().expect("Failed to initialize tokio runtime");
                if let Err(e) = rt.block_on(run_daemon(port, api)) {
                    sb_core::logfmt::error(
                        "ERR_SB_DAEMON",
                        "sb.daemon",
                        "Daemon exited with error",
                        &[("error", &e.to_string())],
                    );
                }
            }
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
        let (tools, cli) = resolve_tools(&["dns".to_string()]).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].id, "dns");
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
                ..
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
    fn test_daemon_cli_parsing() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
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
    fn test_tunnel_cli_parsing() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        let cmd =
            Cli::try_parse_from(["sb", "tunnel", "mach_abc", "3389", "--local-port", "13389"])
                .unwrap();
        match cmd.command {
            Some(Commands::Tunnel {
                machine,
                remote_port,
                local_port,
                dc,
            }) => {
                assert_eq!(machine, "mach_abc");
                assert_eq!(remote_port, 3389);
                assert_eq!(local_port, Some(13389));
                assert_eq!(dc, None);
            }
            _ => panic!("Expected Tunnel command"),
        }
    }

    #[test]
    fn test_quorum_hardening_rejects_self_approval_and_unauthorized_and_expired() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
