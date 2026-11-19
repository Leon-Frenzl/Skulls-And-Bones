use colored::*;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::process_ledger;

pub fn resolve_ssh_invocation(args: &[String]) -> (Vec<String>, bool) {
    let cfg = sb_core::config::SuiteConfig::load();
    let stealth_port = cfg.ports.stealth_ssh;
    let node_ip = cfg
        .network
        .expected_node_ip
        .clone()
        .unwrap_or_else(|| "192.0.2.1".to_string());

    let mut direct = false;
    let mut filtered_args = Vec::new();

    for arg in args {
        if arg == "--direct" {
            direct = true;
        } else {
            filtered_args.push(arg.clone());
        }
    }

    if direct {
        return (filtered_args, false);
    }

    // Check if user already specified an explicit port other than stealth_port
    let has_other_port = filtered_args
        .windows(2)
        .any(|w| (w[0] == "-p" || w[0] == "-P") && w[1] != stealth_port.to_string());
    if has_other_port {
        return (filtered_args, false);
    }

    // If no arguments provided: open interactive TUI with stealth tunnel ready
    if filtered_args.is_empty() {
        return (Vec::new(), true);
    }

    // Check if target is node server, hostname, alias or stealth keyword via TargetResolver
    let is_node_server = filtered_args.iter().any(|a| {
        a == &node_ip
            || a.ends_with(&format!("@{}", node_ip))
            || a.contains(&format!(":{}", stealth_port))
            || sb_core::TargetResolver::resolve(a).is_some_and(|s| {
                s.tags.contains(&"stealth".to_string())
                    || s.host == node_ip
                    || s.host == "127.0.0.1"
            })
    });

    if is_node_server {
        let mut final_args = Vec::new();
        let mut port_added = false;

        let mut i = 0;
        while i < filtered_args.len() {
            let arg = &filtered_args[i];
            if (arg == "-p" || arg == "-P") && i + 1 < filtered_args.len() {
                final_args.push(arg.clone());
                final_args.push(stealth_port.to_string());
                port_added = true;
                i += 2;
                continue;
            }

            if arg == "hostinger-node" || arg == "hostinger-prod" || arg == "hostinger-stealth" {
                final_args.push("hostinger-stealth".to_string());
            } else if arg == &node_ip || arg == "srv490042" || arg == "stealth" {
                final_args.push("root@127.0.0.1".to_string());
            } else if arg.contains('@') && (arg.ends_with(&node_ip) || arg.ends_with("srv490042")) {
                let user = arg.split('@').next().unwrap_or("root");
                final_args.push(format!("{}@127.0.0.1", user));
            } else {
                final_args.push(arg.clone());
            }
            i += 1;
        }

        if !port_added && !final_args.contains(&"hostinger-stealth".to_string()) {
            final_args.insert(0, stealth_port.to_string());
            final_args.insert(0, "-p".to_string());
        }

        (final_args, true)
    } else {
        // Foreign server or custom host: default directly to port 22
        (filtered_args, false)
    }
}

pub fn ensure_stealth_tunnel_if_needed() {
    let cfg = sb_core::config::SuiteConfig::load();
    let stealth_port = cfg.ports.stealth_ssh;

    let local_addr_str = format!("127.0.0.1:{}", stealth_port);
    if let Ok(addr) = local_addr_str.parse::<std::net::SocketAddr>() {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok() {
            return;
        }
    }

    println!(
        "  {} Starte lokalen Sovereign Stealth-Tunnel im Hintergrund...",
        "►".bright_cyan()
    );

    let mesh_server = cfg
        .network
        .default_server
        .unwrap_or_else(|| format!("127.0.0.1:{}", cfg.ports.mesh_udp));

    let stealth_args = [
        "stealth".to_string(),
        "--server".to_string(),
        mesh_server,
        "--target-port".to_string(),
        "22".to_string(),
        "--local-port".to_string(),
        stealth_port.to_string(),
        "--idle-timeout".to_string(),
        "120".to_string(),
    ];

    let _ = process_ledger::ServiceSupervisor::new("mesh-stealth")
        .with_bin("sb-mesh")
        .with_args(stealth_args)
        .with_port(stealth_port)
        .with_log_file("mesh-stealth.log")
        .spawn_and_track();

    if let Ok(addr) = local_addr_str.parse::<std::net::SocketAddr>() {
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(100));
            if TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok() {
                println!(
                    "  {} Stealth-Tunnel aktiv (UDP 58888 ➔ 127.0.0.1:{}).",
                    "✓".bright_green(),
                    stealth_port
                );
                return;
            }
        }
    }
}

pub fn delegate_to(tool_id: &str, binary: &str, args: &[String]) {
    let (final_args, _use_stealth) = if binary == "sb-ssh" {
        let (resolved_args, stealth_needed) = resolve_ssh_invocation(args);
        if stealth_needed {
            ensure_stealth_tunnel_if_needed();
        }
        (resolved_args, stealth_needed)
    } else {
        (args.to_vec(), false)
    };

    let is_detached = final_args.iter().any(|a| a == "--detach" || a == "-d");
    if is_detached {
        let filtered_args: Vec<String> = final_args
            .into_iter()
            .filter(|a| a != "--detach" && a != "-d")
            .collect();

        match process_ledger::ServiceSupervisor::new(tool_id)
            .with_bin(binary)
            .with_args(filtered_args)
            .spawn_and_track()
        {
            Ok(proc) => {
                let log_path = sb_core::paths::sb_run_dir().join(format!("{}.log", tool_id));
                println!(
                    "  {} Hintergrund-Dienst '{}' gestartet (PID {}, Log: {}).",
                    "✓".bright_green().bold(),
                    tool_id.bold(),
                    proc.pid.to_string().cyan(),
                    log_path.display().to_string().bright_black()
                );
                println!("  Überwachen mit: {}", "sb ps".bright_cyan());
                println!(
                    "  Beenden mit:    {}",
                    format!("sb stop {}", tool_id).bright_cyan()
                );
                return;
            }
            Err(e) => {
                sb_core::logfmt::error("ERR_DELEGATE_START", "sb.delegate", "Failed to start background service", &[("tool", tool_id), ("error", &e.to_string())]);
                std::process::exit(1);
            }
        }
    }

    let exe_name = if cfg!(windows) {
        format!("{}.exe", binary)
    } else {
        binary.to_string()
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut candidates = Vec::new();
    if let Ok(cur_exe) = std::env::current_exe() {
        if let Some(dir) = cur_exe.parent() {
            candidates.push(dir.join(&exe_name));
        }
    }
    candidates.push(crate::meta::get_sb_dir().join("bin").join(&exe_name));
    candidates.extend([
        cwd.join("target").join("release").join(&exe_name),
        cwd.join("target").join("debug").join(&exe_name),
        cwd.join("..")
            .join("target")
            .join("release")
            .join(&exe_name),
        cwd.join("..").join("target").join("debug").join(&exe_name),
        cwd.join("../..")
            .join("target")
            .join("release")
            .join(&exe_name),
        cwd.join("../..")
            .join("target")
            .join("debug")
            .join(&exe_name),
        cwd.join("tools")
            .join(binary)
            .join("target")
            .join("release")
            .join(&exe_name),
        cwd.join("tools")
            .join(binary)
            .join("target")
            .join("debug")
            .join(&exe_name),
    ]);
    let binary_path = candidates
        .iter()
        .find(|p| p.is_file())
        .cloned()
        .or_else(|| which::which(binary).ok())
        .or_else(|| {
            if binary == "sb-ssh" {
                which::which("ssh").ok()
            } else {
                None
            }
        });

    let binary_to_run = match binary_path {
        Some(p) => p,
        None => {
            if binary == "sb-ssh" {
                sb_core::logfmt::error("ERR_SSH_CLIENT_MISSING", "sb.delegate", "No SSH client found in PATH", &[("binary", binary)]);
            } else {
                sb_core::logfmt::error("ERR_TOOL_NOT_INSTALLED", "sb.delegate", "Tool is not installed", &[("binary", binary), ("tool", tool_id)]);
            }
            std::process::exit(1);
        }
    };

    let mut cmd = Command::new(binary_to_run);
    cmd.args(&final_args);
    let status = cmd.status();

    match status {
        Ok(s) => {
            std::process::exit(s.code().unwrap_or(0));
        }
        Err(e) => {
            sb_core::logfmt::error("ERR_DELEGATE_EXEC", "sb.delegate", "Failed to execute delegated tool", &[("binary", binary), ("error", &e.to_string())]);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_ssh_default_empty() {
        let (args, stealth) = resolve_ssh_invocation(&[]);
        assert!(stealth);
        assert!(args.is_empty());
    }

    #[test]
    fn test_resolve_ssh_alias() {
        let input = vec!["hostinger-node".to_string()];
        let (args, stealth) = resolve_ssh_invocation(&input);
        assert!(stealth);
        assert_eq!(args, vec!["hostinger-stealth"]);
    }

    #[test]
    fn test_resolve_ssh_node_ip() {
        let cfg_ip = sb_core::config::SuiteConfig::load()
            .network
            .expected_node_ip
            .unwrap_or_else(|| "192.0.2.1".to_string());
        let input = vec![format!("root@{cfg_ip}"), "uptime".to_string()];
        let (args, stealth) = resolve_ssh_invocation(&input);
        assert!(stealth);
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], "58822");
        assert_eq!(args[2], "root@127.0.0.1");
        assert_eq!(args[3], "uptime");
    }

    #[test]
    fn test_resolve_ssh_direct_flag() {
        let input = vec!["--direct".to_string(), "root@192.0.2.1".to_string()];
        let (args, stealth) = resolve_ssh_invocation(&input);
        assert!(!stealth);
        assert_eq!(args, vec!["root@192.0.2.1"]);
    }

    #[test]
    fn test_resolve_ssh_foreign_host() {
        let input = vec!["git@github.com".to_string()];
        let (args, stealth) = resolve_ssh_invocation(&input);
        assert!(!stealth);
        assert_eq!(args, vec!["git@github.com"]);
    }
}
