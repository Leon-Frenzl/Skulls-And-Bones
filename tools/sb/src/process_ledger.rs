use colored::*;

pub use sb_core::process::*;

fn format_duration(seconds: i64) -> String {
    if seconds < 0 {
        return "gerade eben".to_string();
    }
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

pub fn cmd_ps() {
    let ledger = modify_ledger(|ledger| {
        prune_dead(ledger);
        ledger.clone()
    });

    println!();
    println!(
        "{}",
        "  ╔═══════════════════════════════════════════════════════════════════════╗".bright_cyan()
    );
    println!(
        "{}",
        "  ║        SKULLS & BONES — ACTIVE BACKGROUND PROCESSES & TUNNELS         ║".bright_cyan()
    );
    println!(
        "{}",
        "  ╚═══════════════════════════════════════════════════════════════════════╝".bright_cyan()
    );
    println!();

    if ledger.processes.is_empty() {
        println!(
            "  {} Keine aktiven S&B Hintergrund-Dienste registriert.",
            "ℹ".bright_blue()
        );
        println!("  {} Tunnels werden automatisch on-demand gestartet (z. B. via 'sb ssh hostinger-stealth').", "→".dimmed());
        println!();
        return;
    }

    println!(
        "  {:<18} {:<8} {:<10} {:<14} {}",
        "SERVICE".bright_yellow().bold(),
        "PID".bright_yellow().bold(),
        "PORT".bright_yellow().bold(),
        "UPTIME".bright_yellow().bold(),
        "STATUS".bright_yellow().bold()
    );
    println!("  {}", "─".repeat(70).dimmed());

    let now = chrono::Utc::now().timestamp();
    for p in &ledger.processes {
        let uptime = format_duration(now - p.started_at);
        let port_str = p
            .port
            .map(|pt| pt.to_string())
            .unwrap_or_else(|| "—".to_string());

        let status_str = if let Some(pt) = p.port {
            if is_port_listening(pt) {
                format!("{} ONLINE (127.0.0.1:{})", "●".bright_green(), pt)
            } else {
                format!("{} WAITING / DETACHED", "◌".bright_yellow())
            }
        } else {
            format!("{} RUNNING", "●".bright_green())
        };

        println!(
            "  {:<18} {:<8} {:<10} {:<14} {}",
            p.name.bright_white().bold(),
            p.pid.to_string().cyan(),
            port_str.bright_cyan(),
            uptime.dimmed(),
            status_str
        );
    }

    println!();
    println!(
        "  {} Beenden mit: {}",
        "Tip:".dimmed(),
        "sb stop <name|pid|all>".bright_white()
    );
    println!();
}

pub fn cmd_stop(target: Option<&str>) {
    let target_str = target.unwrap_or("all").trim().to_string();

    modify_ledger(|ledger| {
        let _ = prune_dead(ledger);

        if ledger.processes.is_empty() {
            println!(
                "  {} Keine aktiven Hintergrund-Dienste zum Beenden gefunden.",
                "ℹ".bright_blue()
            );
            return;
        }

        if target_str.eq_ignore_ascii_case("all") {
            println!(
                "  {} Beende alle ({}) aktiven S&B Hintergrund-Dienste...",
                "►".bright_yellow(),
                ledger.processes.len()
            );
            let to_kill = ledger.processes.clone();
            for p in to_kill {
                print!("    Beende {} (PID {})... ", p.name.bright_white(), p.pid);
                if terminate_pid(p.pid) {
                    println!("{}", "✓ gestoppt".bright_green());
                } else {
                    println!("{}", "! nicht mehr aktiv".dimmed());
                }
            }
            ledger.processes.clear();
            println!(
                "  {} Alle Hintergrund-Dienste erfolgreich bereinigt.",
                "✓".bright_green()
            );
            return;
        }

        // Try match by PID
        if let Ok(pid) = target_str.parse::<u32>() {
            if let Some(pos) = ledger.processes.iter().position(|p| p.pid == pid) {
                let proc = ledger.processes.remove(pos);
                print!(
                    "  {} Beende {} (PID {})... ",
                    "►".bright_yellow(),
                    proc.name.bright_white(),
                    proc.pid
                );
                if terminate_pid(proc.pid) {
                    println!("{}", "✓ gestoppt".bright_green());
                } else {
                    println!("{}", "! Prozess war bereits beendet".dimmed());
                }
                return;
            }
        }

        // Match by name (case-insensitive substring or exact)
        let matching_indices: Vec<usize> = ledger
            .processes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.name.to_lowercase().contains(&target_str.to_lowercase()))
            .map(|(i, _)| i)
            .collect();

        if matching_indices.is_empty() {
            println!(
                "  {} Kein aktiver Dienst gefunden, der '{}' entspricht.",
                "✗".bright_red(),
                target_str
            );
            println!(
                "  Führe '{}' aus, um alle laufenden Dienste zu sehen.",
                "sb ps".bright_cyan()
            );
            return;
        }

        // Kill matched in reverse index order
        for idx in matching_indices.into_iter().rev() {
            let proc = ledger.processes.remove(idx);
            print!(
                "  {} Beende {} (PID {})... ",
                "►".bright_yellow(),
                proc.name.bright_white(),
                proc.pid
            );
            if terminate_pid(proc.pid) {
                println!("{}", "✓ gestoppt".bright_green());
            } else {
                println!("{}", "! nicht mehr aktiv".dimmed());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pid_alive() {
        let current_pid = std::process::id();
        assert!(is_pid_alive(current_pid));
        assert!(!is_pid_alive(999_999_999));
    }

    #[test]
    fn test_spawn_and_track() {
        let _env_guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut child = if cfg!(windows) {
            std::process::Command::new("powershell")
                .args(&["-Command", "Start-Sleep -Seconds 5"])
                .spawn()
                .expect("failed to spawn child")
        } else {
            std::process::Command::new("sleep")
                .args(["5"])
                .spawn()
                .expect("failed to spawn child")
        };
        let pid = child.id();
        assert!(is_pid_alive(pid), "Spawned PID {} should be alive", pid);
        assert!(
            terminate_pid(pid),
            "terminate_pid for PID {} should succeed",
            pid
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !is_pid_alive(pid),
            "PID {} should be dead after terminate",
            pid
        );
        let _ = child.wait();
    }

    #[test]
    fn test_service_supervisor_builder_lifecycle() {
        let _env_guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let svc_name = format!("test-sleep-svc-{}", std::process::id());
        let supervisor = if cfg!(windows) {
            ServiceSupervisor::new(&svc_name)
                .with_bin("powershell")
                .with_args(["-Command", "Start-Sleep -Seconds 5"])
        } else {
            ServiceSupervisor::new(&svc_name)
                .with_bin("sleep")
                .with_args(["5"])
        };

        let tracked = supervisor
            .spawn_and_track()
            .expect("failed to spawn via supervisor");
        assert!(is_pid_alive(tracked.pid));
        assert_eq!(tracked.name, svc_name);

        // Verify it was registered in ledger
        let ledger = load_ledger();
        assert!(ledger
            .processes
            .iter()
            .any(|p| p.name == svc_name && p.pid == tracked.pid));

        // Stop the service
        assert!(ServiceSupervisor::stop_by_name(&svc_name));
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!is_pid_alive(tracked.pid));
    }
}
