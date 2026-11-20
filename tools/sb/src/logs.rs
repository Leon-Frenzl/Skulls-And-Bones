//! Fleet Observability & Live Log Streaming (`sb logs`)
//! Echtzeit-Log-Streaming entfernter Server und lokaler Dienste mit
//! Smart Crash Inspector (Erkennung von Rust Panics, Python Tracebacks, Node.js Rejections).

use colored::*;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// Schweregrad einer protokollierten Zeile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSeverity {
    Panic,
    Traceback,
    Error,
    Warning,
    Success,
    Info,
    Standard,
}

impl LogSeverity {
    pub fn badge(&self) -> &'static str {
        match self {
            LogSeverity::Panic => "💥 PANIC",
            LogSeverity::Traceback => "🐍 TRACEBACK",
            LogSeverity::Error => "✖ ERROR",
            LogSeverity::Warning => "▲ WARN",
            LogSeverity::Success => "✔ OK",
            LogSeverity::Info => "ℹ INFO",
            LogSeverity::Standard => "  LOG",
        }
    }
}

/// Smart Crash Inspector & Stack Trace Decoder
pub struct CrashInspector;

impl CrashInspector {
    /// Prüft, ob ein Textblock einen bekannten Crash oder Panic enthält
    pub fn inspect(line: &str) -> Option<String> {
        let trimmed = line.trim();

        // 1. Rust Panic
        if trimmed.contains("panicked at")
            || trimmed.starts_with("thread '") && trimmed.contains("panicked")
        {
            let detail = if let Some(idx) = trimmed.find("panicked at") {
                &trimmed[idx..]
            } else {
                trimmed
            };
            return Some(format!(
                "{}\n  {} {}\n  {} {}",
                "┌─── 🚨 RUST PANIC DETECTED ──────────────────────────────────────────────┐"
                    .bright_red()
                    .bold(),
                "Ursache:".bold(),
                detail.bright_yellow(),
                "Hinweis:".dimmed(),
                "Prüfe Stack-Trace und unwrap()/expect() Aufrufe.".dimmed()
            ));
        }

        // 2. Python Traceback
        if trimmed.starts_with("Traceback (most recent call last):") {
            return Some(format!(
                "{}\n  {} {}",
                "┌─── 🐍 PYTHON UNHANDLED EXCEPTION ────────────────────────────────────────┐"
                    .bright_red()
                    .bold(),
                "Status: ".bold(),
                "Kritischer Laufzeitfehler im Python-Prozess.".bright_yellow()
            ));
        }

        // 3. Node.js Unhandled Rejection
        if trimmed.contains("UnhandledPromiseRejection")
            || trimmed.contains("UnhandledPromiseRejectionWarning")
        {
            return Some(format!(
                "{}\n  {} {}",
                "┌─── ⚡ NODE.JS UNHANDLED REJECTION ───────────────────────────────────────┐"
                    .bright_yellow()
                    .bold(),
                "Status: ".bold(),
                "Nicht abgefangener Promise-Fehler in Node.js Event-Loop.".white()
            ));
        }

        // 4. Linux Kernel OOM Killer
        if trimmed.contains("Out of memory: Kill process") || trimmed.contains("invoked oom-killer")
        {
            return Some(format!(
                "{}\n  {} {}",
                "┌─── 💀 LINUX OOM KILLER INVOKED ─────────────────────────────────────────┐"
                    .bright_red()
                    .bold(),
                "Alarm:  ".bold(),
                "Prozess wurde vom Kernel wegen Speichermangel getötet!"
                    .bright_red()
                    .bold()
            ));
        }

        None
    }

    /// Gibt Typ und Details eines erkannten Crashes zurück (für TUI/Cockpit-Banners)
    #[allow(dead_code)]
    pub fn inspect_type(line: &str) -> Option<(&'static str, String)> {
        let trimmed = line.trim();
        if trimmed.contains("panicked at")
            || (trimmed.starts_with("thread '") && trimmed.contains("panicked"))
        {
            let detail = if let Some(idx) = trimmed.find("panicked at") {
                &trimmed[idx..]
            } else {
                trimmed
            };
            return Some(("RUST PANIC", detail.to_string()));
        }
        if trimmed.starts_with("Traceback (most recent call last):") {
            return Some((
                "PYTHON TRACEBACK",
                "Kritischer Laufzeitfehler im Python-Prozess".to_string(),
            ));
        }
        if trimmed.contains("UnhandledPromiseRejection")
            || trimmed.contains("UnhandledPromiseRejectionWarning")
        {
            return Some((
                "NODE.JS REJECTION",
                "Nicht abgefangener Promise-Fehler in Event-Loop".to_string(),
            ));
        }
        if trimmed.contains("Out of memory: Kill process") || trimmed.contains("invoked oom-killer")
        {
            return Some((
                "LINUX OOM KILLER",
                "Prozess wurde vom Kernel wegen Speichermangel getötet!".to_string(),
            ));
        }
        None
    }
}

/// Liest die letzten N Zeilen der lokalen Logs aus
#[allow(dead_code)]
pub fn fetch_recent_logs(lines: usize) -> Vec<String> {
    crate::logger::read_recent_log_lines(None, lines)
}

/// Klassifiziert und formatiert eine einzelne Log-Zeile mit Smart Highlighting
pub fn format_log_line(line: &str) -> (LogSeverity, String) {
    let lower = line.to_lowercase();

    // Priorität 1: Panics & Crashes
    if line.contains("panicked at") || line.contains("PANIC") {
        return (LogSeverity::Panic, line.bright_red().bold().to_string());
    }

    if line.starts_with("Traceback (most recent call last):")
        || line.trim_start().starts_with("File \"") && line.contains("line ")
    {
        return (LogSeverity::Traceback, line.bright_magenta().to_string());
    }

    // Priorität 2: Typische Fehler und HTTP 5xx
    if lower.contains("error")
        || lower.contains("fatal")
        || lower.contains("failed")
        || lower.contains("exception")
        || line.contains(" 500 ")
        || line.contains(" 502 ")
        || line.contains(" 503 ")
        || line.contains(" 504 ")
        || lower.contains("connection refused")
    {
        return (LogSeverity::Error, line.bright_red().to_string());
    }

    // Priorität 3: Warnings & HTTP 4xx
    if lower.contains("warn")
        || line.contains(" 404 ")
        || line.contains(" 403 ")
        || line.contains(" 401 ")
    {
        return (LogSeverity::Warning, line.bright_yellow().to_string());
    }

    // Priorität 4: Success & Health
    if lower.contains("started")
        || lower.contains("healthy")
        || lower.contains("ready")
        || line.contains(" 200 ")
    {
        return (LogSeverity::Success, line.bright_green().to_string());
    }

    // Priorität 5: Info
    if lower.contains("info") {
        return (LogSeverity::Info, line.normal().to_string());
    }

    (LogSeverity::Standard, line.dimmed().to_string())
}

/// Server-Verbindungsdaten aus servers.toml (konsolidiert auf sb_core::ServerConfig)
#[allow(unused_imports)]
pub use sb_core::ServerConfig as ServerTarget;

/// Löst einen Servernamen über den kanonischen TargetResolver auf
#[allow(dead_code)]
pub fn resolve_server(name: &str) -> Option<sb_core::ServerConfig> {
    sb_core::TargetResolver::resolve(name)
}

/// Streamt lokale S&B-Audit- und Tool-Logs
pub fn stream_local_logs(lines: usize) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!(
        "  {} {} {}",
        "S&B SOVEREIGN LOGS".cyan().bold(),
        "//".black().bold(),
        "LOKALER KNOTEN & AUDIT".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );

    let recent = crate::logger::read_recent_log_lines(None, lines);
    if recent.is_empty() {
        println!(
            "  {}",
            "Keine lokalen Log-Einträge in ~/.sb/logs/ vorhanden.".dimmed()
        );
        return;
    }

    for raw_line in recent {
        if let Some(crash_box) = CrashInspector::inspect(&raw_line) {
            println!("\n{}\n", crash_box);
        }
        let (sev, formatted) = format_log_line(&raw_line);
        let badge = match sev {
            LogSeverity::Panic => sev.badge().bright_red().bold(),
            LogSeverity::Traceback => sev.badge().bright_magenta().bold(),
            LogSeverity::Error => sev.badge().bright_red(),
            LogSeverity::Warning => sev.badge().bright_yellow(),
            LogSeverity::Success => sev.badge().bright_green(),
            LogSeverity::Info => sev.badge().bright_blue(),
            LogSeverity::Standard => sev.badge().bright_black(),
        };
        println!("  [{}] {}", badge, formatted);
    }
    println!();
}

/// Streamt Live-Logs eines entfernten Servers über SSH/Mesh
#[allow(dead_code)]
pub fn stream_remote_logs(
    server_name: &str,
    service: Option<&str>,
    lines: usize,
    follow: bool,
) -> Result<(), String> {
    let target = sb_core::TargetResolver::resolve_node_or_default(Some(server_name))
        .unwrap_or_else(|| sb_core::ServerConfig {
            name: server_name.to_string(),
            host: if server_name.contains('.') {
                server_name.to_string()
            } else {
                format!("{}.sbm", server_name)
            },
            port: 22,
            user: "root".to_string(),
            tags: Vec::new(),
            description: None,
        });
    stream_remote_logs_to_target(&target, service, lines, follow)
}

/// Streamt Live-Logs für eine direkt übergebene ServerConfig
pub fn stream_remote_logs_to_target(
    target: &sb_core::ServerConfig,
    service: Option<&str>,
    lines: usize,
    follow: bool,
) -> Result<(), String> {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!(
        "  {} {} {} {}",
        "S&B LIVE LOG STREAM".cyan().bold(),
        "//".black().bold(),
        target.name.bright_white().bold(),
        if let Some(s) = service {
            format!("[{}]", s)
        } else {
            "[SYSTEM]".to_string()
        }
        .bright_yellow()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!(
        "  {:<18} {}",
        "Zielserver:".bold(),
        format!("{}:{}", target.ssh_destination(), target.port).bright_white()
    );
    println!(
        "  {:<18} {}",
        "Modus:".bold(),
        if follow {
            "Live Stream (-f)"
        } else {
            "Snapshot"
        }
        .bright_green()
    );
    println!("  {:<18} {}\n", "Zeilen:".bold(), lines.to_string().cyan());

    // Generiere das Remote-Kommando
    let remote_cmd = if let Some(svc) = service {
        if follow {
            format!("journalctl -u {} -n {} -f --no-pager 2>/dev/null || docker logs -f --tail {} {} 2>/dev/null || tail -n {} -f /var/log/{}.log 2>/dev/null", svc, lines, lines, svc, lines, svc)
        } else {
            format!("journalctl -u {} -n {} --no-pager 2>/dev/null || docker logs --tail {} {} 2>/dev/null || tail -n {} /var/log/{}.log 2>/dev/null", svc, lines, lines, svc, lines, svc)
        }
    } else {
        if follow {
            format!("journalctl -n {} -f --no-pager 2>/dev/null || tail -n {} -f /var/log/syslog 2>/dev/null || tail -n {} -f /var/log/messages 2>/dev/null", lines, lines, lines)
        } else {
            format!("journalctl -n {} --no-pager 2>/dev/null || tail -n {} /var/log/syslog 2>/dev/null || tail -n {} /var/log/messages 2>/dev/null", lines, lines, lines)
        }
    };

    // Starte OpenSSH mit ~/.sb/ssh/ssh_config
    let ssh_bin = sb_core::BinaryResolver::resolve_ssh()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ssh".to_string());
    let cfg_path = sb_core::ssh_transport::ensure_sovereign_ssh_config()
        .unwrap_or_else(|_| sb_core::paths::sb_ssh_dir().join("ssh_config"));
    let mut child = Command::new(&ssh_bin)
        .args([
            "-F",
            &cfg_path.to_string_lossy(),
            "-p",
            &target.port.to_string(),
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            &target.ssh_destination(),
            &remote_cmd,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "Konnte SSH-Verbindung zu '{}' nicht aufbauen: {}",
                target.host, e
            )
        })?;

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(crash_box) = CrashInspector::inspect(&line) {
                println!("\n{}\n", crash_box);
            }
            let (sev, formatted) = format_log_line(&line);
            let badge = match sev {
                LogSeverity::Panic => sev.badge().bright_red().bold(),
                LogSeverity::Traceback => sev.badge().bright_magenta().bold(),
                LogSeverity::Error => sev.badge().bright_red(),
                LogSeverity::Warning => sev.badge().bright_yellow(),
                LogSeverity::Success => sev.badge().bright_green(),
                LogSeverity::Info => sev.badge().bright_blue(),
                LogSeverity::Standard => sev.badge().bright_black(),
            };
            println!("  [{}] {}", badge, formatted);
        }
    }

    let _ = child.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_line_classification() {
        let (sev_err, _) =
            format_log_line("2026-09-23 12:00:00 [ERROR] Database connection failed");
        assert_eq!(sev_err, LogSeverity::Error);

        let (sev_warn, _) = format_log_line("2026-09-23 12:00:01 [WARN] High memory consumption");
        assert_eq!(sev_warn, LogSeverity::Warning);

        let (sev_succ, _) =
            format_log_line("2026-09-23 12:00:02 [INFO] Server started on 0.0.0.0:8080");
        assert_eq!(sev_succ, LogSeverity::Success);

        let (sev_http, _) =
            format_log_line("GET /api/v1/checkout HTTP/1.1 500 Internal Server Error");
        assert_eq!(sev_http, LogSeverity::Error);

        let (sev_std, _) = format_log_line("Processing batch job #42");
        assert_eq!(sev_std, LogSeverity::Standard);
    }

    #[test]
    fn test_rust_panic_detection() {
        let panic_line = "thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/main.rs:42:15";
        let inspected = CrashInspector::inspect(panic_line);
        assert!(inspected.is_some());
        let report = inspected.unwrap();
        assert!(report.contains("RUST PANIC DETECTED"));
        assert!(report.contains("Option::unwrap()"));
    }

    #[test]
    fn test_python_traceback_detection() {
        let tb_line = "Traceback (most recent call last):";
        let inspected = CrashInspector::inspect(tb_line);
        assert!(inspected.is_some());
        let report = inspected.unwrap();
        assert!(report.contains("PYTHON UNHANDLED EXCEPTION"));
    }

    #[test]
    fn test_nodejs_unhandled_rejection_detection() {
        let node_err =
            "(node:1234) UnhandledPromiseRejectionWarning: Unhandled promise rejection: TypeError";
        let inspected = CrashInspector::inspect(node_err);
        assert!(inspected.is_some());
        let report = inspected.unwrap();
        assert!(report.contains("NODE.JS UNHANDLED REJECTION"));
    }

    #[test]
    fn test_oom_killer_detection() {
        let oom_line = "kernel: [12345.67] Out of memory: Kill process 5678 (node) score 950 or sacrifice child";
        let inspected = CrashInspector::inspect(oom_line);
        assert!(inspected.is_some());
        let report = inspected.unwrap();
        assert!(report.contains("LINUX OOM KILLER INVOKED"));
    }

    #[test]
    fn test_resolve_server_via_target_resolver() {
        let target = resolve_server("10.0.0.42");
        assert!(target.is_some());
        let t = target.unwrap();
        assert_eq!(t.host, "10.0.0.42");
        assert_eq!(t.port, 22);
        assert_eq!(t.user, "root");

        let target_user = resolve_server("admin@myhost.org");
        assert!(target_user.is_some());
        let tu = target_user.unwrap();
        assert_eq!(tu.host, "myhost.org");
        assert_eq!(tu.user, "admin");
        assert_eq!(tu.ssh_destination(), "admin@myhost.org");
    }
}
