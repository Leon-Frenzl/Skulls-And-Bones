use colored::*;
use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::session::get_active_callsign;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressEndpoint {
    pub port: u16,
    pub process_name: String,
    pub pid: Option<u32>,
    pub mesh_url: String,
    pub category: String,
}

#[derive(Deserialize, Debug)]
struct PortsListEntry {
    port: u16,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    process_name: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
}

/// Detects locally active web development servers and derives their Sovereign Mesh Ingress URLs.
pub fn detect_ingress_endpoints() -> Vec<IngressEndpoint> {
    let mut endpoints = Vec::new();
    let callsign = get_active_callsign();

    // Query sb-ports for active listening sockets
    if let Ok(output) = Command::new("sb-ports").args(["list", "--json"]).output() {
        if output.status.success() {
            if let Ok(entries) = serde_json::from_slice::<Vec<PortsListEntry>>(&output.stdout) {
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

                for e in entries {
                    if e.port < 1024 {
                        continue;
                    }
                    if let Some(ref name) = e.process_name {
                        let lower = name.to_lowercase();
                        if system_names.iter().any(|s| lower.contains(s)) {
                            continue;
                        }
                    }

                    let is_web = e.category.as_deref() == Some("Web")
                        || e.category.as_deref() == Some("WebServer");
                    let common_port = matches!(e.port, 3000..=3010 | 5173..=5180 | 8000 | 8080 | 8081 | 4200 | 8888 | 9000);
                    let dev_proc = e
                        .process_name
                        .as_ref()
                        .map(|n| {
                            let l = n.to_lowercase();
                            l.contains("node")
                                || l.contains("vite")
                                || l.contains("python")
                                || l.contains("cargo")
                                || l.contains("uvicorn")
                                || l.contains("flask")
                                || l.contains("deno")
                                || l.contains("bun")
                                || l.contains("next")
                        })
                        .unwrap_or(false);

                    if is_web || common_port || dev_proc {
                        let proc_name = e.process_name.unwrap_or_else(|| "dev-server".to_string());
                        let mesh_url = format!("http://{}.sbm:{}", callsign, e.port);
                        endpoints.push(IngressEndpoint {
                            port: e.port,
                            process_name: proc_name,
                            pid: e.pid,
                            mesh_url,
                            category: e.category.unwrap_or_else(|| "DevServer".to_string()),
                        });
                    }
                }
            }
        }
    }

    endpoints
}

/// Formats and displays active Dev Ingress endpoints in the CLI.
pub fn print_ingress_report(endpoints: &[IngressEndpoint]) {
    println!(
        "{}",
        "── S&B Sovereign Dev Ingress (sb-ports ↔ sb-mesh) ──"
            .bold()
            .cyan()
    );
    if endpoints.is_empty() {
        println!(
            "  {} Kein aktiver lokaler Entwicklungs-Server auf Standard-Ports erkannt.",
            "○".dimmed()
        );
        println!("  Tipp: Starte deine App (z.B. 'npm run dev' oder 'cargo run').");
        println!("  Sobald ein Port geöffnet wird, erzeugt sb-code automatisch eine Mesh-URL.\n");
    } else {
        println!(
            "  {} Aktive lokale Dev-Server im Mesh bereitgestellt:\n",
            "✔".green()
        );
        for ep in endpoints {
            let pid_str = ep.pid.map(|p| format!(" (PID {})", p)).unwrap_or_default();
            println!(
                "  {} Port {:<5} ➔  {}  {}{}",
                "🌐".cyan(),
                ep.port.to_string().bold().yellow(),
                ep.mesh_url.bold().green(),
                ep.process_name.white(),
                pid_str.dimmed()
            );
        }
        println!();
        println!(
            "  {} Peers im Swarm können diese URLs direkt in ihrem Browser aufrufen,",
            "ℹ".cyan()
        );
        println!(
            "    solange sie über 'sb-mesh' verbunden sind (100% Ende-zu-Ende verschlüsselt).\n"
        );
    }
}
