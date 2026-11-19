use colored::*;
use std::process::Command;

use crate::commands::delegate::delegate_to;

#[derive(serde::Deserialize, Debug)]
pub struct DevPortEntry {
    pub port: u16,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
}

pub fn detect_active_dev_ports() -> Vec<DevPortEntry> {
    if let Ok(output) = Command::new("sb-ports").args(["list", "--json"]).output() {
        if output.status.success() {
            if let Ok(entries) = serde_json::from_slice::<Vec<DevPortEntry>>(&output.stdout) {
                let system_names = [
                    "svchost.exe",
                    "system",
                    "lsass.exe",
                    "wininit.exe",
                    "steam.exe",
                    "services.exe",
                    "spoolsv.exe",
                    "agy.exe",
                    "code.exe",
                    "registry",
                    "smss.exe",
                    "csrss.exe",
                ];
                let dev_candidates: Vec<DevPortEntry> = entries
                    .into_iter()
                    .filter(|e| {
                        if e.port < 1024 {
                            return false;
                        }
                        if let Some(ref name) = e.process_name {
                            let lower = name.to_lowercase();
                            if system_names.iter().any(|s| lower.contains(s)) {
                                return false;
                            }
                        }
                        let is_web = e.category.as_deref() == Some("Web") || e.category.as_deref() == Some("WebServer");
                        let common_port = matches!(e.port, 3000..=3010 | 5173..=5180 | 8000 | 8080 | 8081 | 4200 | 8888 | 9000);
                        let dev_proc = e.process_name.as_ref().map(|n| {
                            let l = n.to_lowercase();
                            l.contains("node") || l.contains("vite") || l.contains("python")
                                || l.contains("cargo") || l.contains("uvicorn") || l.contains("flask")
                                || l.contains("deno") || l.contains("bun") || l.contains("next")
                        }).unwrap_or(false);

                        is_web || common_port || dev_proc
                    })
                    .collect();

                return dev_candidates;
            }
        }
    }
    Vec::new()
}

pub fn handle_share(port: Option<u16>, name: Option<String>) {
    let target_port = match port {
        Some(p) => p,
        None => {
            println!(
                "  {} Suche nach aktiven lokalen Entwicklungs-Servern via sb-ports...",
                "🔍".cyan()
            );
            let candidates = detect_active_dev_ports();
            if candidates.is_empty() {
                sb_core::logfmt::error(
                    "SHARE_NO_DEV_SERVER",
                    "sb::share",
                    "Kein aktiver Entwicklungs-Server auf Standard-Ports gefunden",
                    &[],
                );
                println!(
                    "  💡 Bitte gib den Port explizit an: {}",
                    "sb share <PORT>".bright_yellow()
                );
                println!(
                    "     Beispiel: {}",
                    "sb share 3000 --name preview-app".bright_cyan()
                );
                return;
            } else if candidates.len() == 1 {
                let candidate = &candidates[0];
                let proc_desc = candidate
                    .process_name
                    .as_deref()
                    .unwrap_or("Unbekannter Prozess");
                println!(
                    "  {} Gefunden: {} auf Port {} (PID {:?})",
                    "✓".green().bold(),
                    proc_desc.bold(),
                    candidate.port.to_string().bright_yellow().bold(),
                    candidate.pid.unwrap_or(0)
                );
                candidate.port
            } else {
                println!(
                    "\n  {} Mehrere aktive Entwicklungs-Dienste gefunden:",
                    "⚡".yellow().bold()
                );
                for (idx, c) in candidates.iter().enumerate() {
                    let proc_desc = c.process_name.as_deref().unwrap_or("Prozess");
                    println!(
                        "    [{}] Port {:<5} ➔ {} (PID {:?})",
                        idx + 1,
                        c.port.to_string().bright_yellow().bold(),
                        proc_desc.bold(),
                        c.pid.unwrap_or(0)
                    );
                }
                println!(
                    "\n  Wähle automatisch Port {} (erster gefundener Webdienst).",
                    candidates[0].port.to_string().bright_yellow().bold()
                );
                println!("  (Tipp: Für einen anderen Port nutze: sb share <port>)\n");
                candidates[0].port
            }
        }
    };

    let mut args = vec!["share".to_string(), target_port.to_string()];
    if let Some(lbl) = name {
        args.push("--label".to_string());
        args.push(lbl);
    }
    delegate_to("mesh", "sb-mesh", &args);
}
