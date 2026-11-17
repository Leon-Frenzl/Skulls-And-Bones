//! Fleet Observability & Live Telemetry HUD (`sb trace`)
//! Echtzeit-Monitoring von CPU, RAM, Sockets, Watchdog-Leaks und
//! Edge-Proxy Fehlerraten über das Sovereign Mesh.

use colored::*;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub use sb_core::dto::{ProxyTelemetryDto, RemoteTelemetry};

/// Rendert einen ASCII-Prozentbalken
pub fn render_ascii_bar(percent: f32, width: usize) -> String {
    let clamped = percent.clamp(0.0, 100.0);
    let filled = ((clamped / 100.0) * width as f32).round() as usize;
    let empty = width.saturating_sub(filled);
    let bar_str = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
    if clamped < 60.0 {
        bar_str.bright_green().to_string()
    } else if clamped < 85.0 {
        bar_str.bright_yellow().to_string()
    } else {
        bar_str.bright_red().to_string()
    }
}

/// Formatiert Sekunden in lesbare Laufzeit
pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;
    let secs = seconds % 60;
    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else {
        format!("{}m {}s", mins, secs)
    }
}

/// Fragt die Live-Telemetrie vom lokalen S&B Proxy Loopback-IPC Socket (127.0.0.1:58900) ab
pub fn fetch_proxy_telemetry() -> Option<ProxyTelemetryDto> {
    let mut stream =
        TcpStream::connect_timeout(&"127.0.0.1:58900".parse().ok()?, Duration::from_millis(600))
            .ok()?;

    stream
        .set_read_timeout(Some(Duration::from_millis(600)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(600)))
        .ok()?;

    let req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).ok()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body).ok()
}

/// Fragt Remote-Telemetrie von einem Flottenknoten über OpenSSH (`~/.sb/ssh/ssh_config`) und `sb-node` ab
pub fn fetch_remote_telemetry(server_name: &str) -> Result<RemoteTelemetry, String> {
    let (ssh_bin, ssh_args) =
        sb_core::ssh_transport::build_ssh_exec_args(server_name, "sb-node telemetry --json")?;

    let output = Command::new(&ssh_bin)
        .args(&ssh_args)
        .output()
        .map_err(|e| format!("Konnte OpenSSH nicht starten: {}", e))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Telemetrie-Abruf fehlgeschlagen: {}",
            err_msg.trim()
        ));
    }

    serde_json::from_slice::<RemoteTelemetry>(&output.stdout)
        .map_err(|e| format!("Fehler beim Parsen der Telemetrie: {}", e))
}

/// Gibt einen einheitlichen Telemetrie-Bericht auf stdout aus
pub fn print_trace_dashboard(server: Option<&str>) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!(
        "  {} {} {}  {}",
        "S&B TELEMETRY & METRICS HUD".cyan().bold(),
        "//".black().bold(),
        if let Some(s) = server {
            s.to_uppercase()
        } else {
            "LOKALER KNOTEN".to_string()
        }
        .yellow()
        .bold(),
        format!("[{}]", timestamp).dimmed()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );

    if let Some(target_server) = server {
        // Remote Telemetry
        println!(
            "  📡 Frage Flottenknoten via Sovereign Mesh ab: {}",
            target_server.bright_cyan().bold()
        );
        match fetch_remote_telemetry(target_server) {
            Ok(tel) => {
                println!();
                println!(
                    "  ┌── {} ─────────────────────────────────────────────────────────────┐",
                    "HOST RESSOURCEN & GESUNDHEIT".bold()
                );
                println!(
                    "  │ CPU Auslastung:   [{}] {:>5.1}%",
                    render_ascii_bar(tel.cpu_usage_percent, 24),
                    tel.cpu_usage_percent
                );
                println!(
                    "  │ RAM Belegung:     [{}] {:>5.1}%  ({} MB / {} MB)",
                    render_ascii_bar(tel.mem_used_percent, 24),
                    tel.mem_used_percent,
                    tel.mem_used_mb,
                    tel.mem_total_mb
                );
                println!(
                    "  │ Uptime:           {}",
                    format_uptime(tel.uptime_seconds).bright_white()
                );
                println!(
                    "  │ Stealth-SSH:      {}",
                    if tel.stealth_ssh_active {
                        "🔒 AKTIV (Port 22 WAN-geschützt via Mesh)"
                            .bright_green()
                            .bold()
                    } else {
                        "⚠️ INAKTIV (Port 22 potentiell ungeschützt)".bright_yellow()
                    }
                );
                println!("  └──────────────────────────────────────────────────────────────────────────┘");

                println!();
                println!(
                    "  ┌── {} ─────────────────────────────────────────────────────────────┐",
                    "SOCKET WATCHDOG & PORT AUDIT".bold()
                );
                if tel.active_leaks_count == 0 {
                    println!(
                        "  │ {}",
                        "✔ Optimal geschützt: Keine unautorisierten 0.0.0.0 Binds gefunden."
                            .bright_green()
                            .bold()
                    );
                } else {
                    println!(
                        "  │ {}",
                        format!(
                            "🚨 ALARM: {} ungeschützte 0.0.0.0 Binds aufgetreten!",
                            tel.active_leaks_count
                        )
                        .bright_red()
                        .bold()
                    );
                }
                println!(
                    "  │ Swarm Domain:     {}",
                    format!("{}.sbm", tel.node_name).bright_cyan()
                );
                println!(
                    "  │ Cross-Mesh:       {}",
                    if tel.cross_mesh_active {
                        format!(
                            "🔒 AKTIV ({} Regeln / Default Deny)",
                            tel.cross_mesh_rules_count
                        )
                        .bright_green()
                        .bold()
                    } else {
                        "⚪ INAKTIV (Keine Regeln)".dimmed()
                    }
                );
                println!("  └──────────────────────────────────────────────────────────────────────────┘");
            }
            Err(e) => {
                println!();
                println!(
                    "  {} {}",
                    "✖ Fehler beim Telemetrie-Abruf:".bright_red().bold(),
                    e
                );
                println!("  {}", "Stelle sicher, dass der Server im Mesh erreichbar und sb-node installiert ist.".dimmed());
            }
        }
    } else {
        // Local Telemetry & Edge Proxy HUD
        let proxy_opt = fetch_proxy_telemetry();

        println!(
            "  ┌── {} ─────────────────────────────────────────────────────────────┐",
            "S&B EDGE PROXY (127.0.0.1:58900)".bold()
        );
        if let Some(proxy) = proxy_opt {
            let error_4xx_rate = if proxy.total_requests > 0 {
                (proxy.requests_4xx as f32 / proxy.total_requests as f32) * 100.0
            } else {
                0.0
            };
            let error_5xx_rate = if proxy.total_requests > 0 {
                (proxy.requests_5xx as f32 / proxy.total_requests as f32) * 100.0
            } else {
                0.0
            };

            println!(
                "  │ Status:           {}",
                "🟢 ONLINE".bright_green().bold()
            );
            println!(
                "  │ PID / Uptime:     {} / {}",
                proxy.pid,
                format_uptime(proxy.uptime_secs).bright_white()
            );
            println!(
                "  │ Aktive Spaces:    {} registrierte Domains",
                proxy.active_spaces_count.to_string().bright_cyan().bold()
            );
            println!(
                "  │ Anfragen Gesamt:  {}",
                proxy.total_requests.to_string().bright_white().bold()
            );
            println!(
                "  │ HTTP 2xx/3xx:     {}  ({})",
                proxy.requests_2xx.to_string().bright_green(),
                "Erfolgreich".dimmed()
            );
            println!(
                "  │ HTTP 4xx Fehler:  {}  ({:.1}% Quote, Rate-Limits: {})",
                proxy.requests_4xx.to_string().bright_yellow(),
                error_4xx_rate,
                proxy.rate_limited_count
            );
            println!(
                "  │ HTTP 5xx Fehler:  {}  ({:.1}% Quote)",
                if proxy.requests_5xx > 0 {
                    proxy.requests_5xx.to_string().bright_red().bold()
                } else {
                    proxy.requests_5xx.to_string().bright_green()
                },
                error_5xx_rate
            );
            println!(
                "  │ Upstream Latenz:  {:.1} ms (Ø Antwortzeit)",
                proxy.avg_latency_ms
            );
        } else {
            println!(
                "  │ Status:           {}",
                "⚪ OFFLINE / Inaktiv (sb proxy start)".dimmed()
            );
            println!("  │ IPC Socket:       127.0.0.1:58900 nicht erreichbar");
        }
        println!("  └──────────────────────────────────────────────────────────────────────────┘");

        println!();
        println!(
            "  ┌── {} ─────────────────────────────────────────────────────────────┐",
            "LOKALE SOVEREIGN ENVIRONMENT & AUDIT".bold()
        );
        let ctx_store = crate::context::ContextStore::new();
        let active_ctx = ctx_store.get_active();
        println!(
            "  │ Aktiver Context:  {}",
            active_ctx.name.bright_yellow().bold()
        );
        if let Some(target) = active_ctx.target_server {
            println!("  │ Context Target:   {}", target.bright_cyan());
        }
        if let Some(overlay) = active_ctx.mesh_swarm {
            println!("  │ Overlay Swarm:    {}", overlay.bright_magenta());
        }

        let lease_path = dirs::home_dir().map(|h| h.join(".sb").join("lease.json"));
        let lease_active = lease_path.map(|p| p.exists()).unwrap_or(false);
        println!(
            "  │ Ephemere Lease:   {}",
            if lease_active {
                "🟢 AKTIV IM RAM (8h TTL)".bright_green().bold()
            } else {
                "🔴 INAKTIV / GESPERRT ('sb lease')".bright_red()
            }
        );

        let cross_mesh_path =
            dirs::home_dir().map(|h| h.join(".sb-mesh").join("cross_mesh_rules.json"));
        let cross_mesh_count = cross_mesh_path.and_then(|p| {
            if p.exists() {
                std::fs::read_to_string(p).ok().and_then(|c| {
                    serde_json::from_str::<serde_json::Value>(&c)
                        .ok()
                        .and_then(|v| v.get("rules").and_then(|r| r.as_array()).map(|a| a.len()))
                })
            } else {
                None
            }
        });
        if let Some(count) = cross_mesh_count {
            println!(
                "  │ Cross-Mesh:       {}",
                if count > 0 {
                    format!("🟢 AKTIV ({} Regeln / Default Deny)", count)
                        .bright_green()
                        .bold()
                } else {
                    "⚪ BEREIT (0 Regeln)".dimmed()
                }
            );
        }

        println!("  └──────────────────────────────────────────────────────────────────────────┘");
    }

    println!();
}

/// Startet den Live-Trace Befehl (optional mit kontinuierlichem Redraw)
pub fn run_trace(server: Option<String>, watch: bool, interval: u64) {
    if !watch {
        print_trace_dashboard(server.as_deref());
        return;
    }

    let interval_duration = Duration::from_secs(interval.max(1));

    loop {
        // ANSI clear screen + cursor to top-left
        print!("\x1B[2J\x1B[1;1H");
        let _ = io::stdout().flush();

        print_trace_dashboard(server.as_deref());
        println!(
            "  {}",
            format!(
                "Drücke Ctrl+C zum Beenden | Aktualisierung alle {}s",
                interval
            )
            .dimmed()
        );

        thread::sleep(interval_duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_ascii_bar_bounds() {
        let bar_0 = render_ascii_bar(0.0, 10);
        assert!(bar_0.contains("░░░░░░░░░░"));

        let bar_50 = render_ascii_bar(50.0, 10);
        assert!(bar_50.contains("█████░░░░░"));

        let bar_100 = render_ascii_bar(100.0, 10);
        assert!(bar_100.contains("██████████"));
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(45), "0m 45s");
        assert_eq!(format_uptime(3665), "1h 1m 5s");
        assert_eq!(format_uptime(90060), "1d 1h 1m");
    }
}
