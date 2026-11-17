use colored::*;
use sb_core::config::SuiteConfig;

use crate::cli::ConfigAction;

pub fn handle_config(action: Option<ConfigAction>) {
    match action {
        None | Some(ConfigAction::Get { key: None }) => {
            print_full_config();
        }
        Some(ConfigAction::Get { key: Some(k) }) => {
            let cfg = SuiteConfig::load();
            if let Some(val) = cfg.get_value(&k) {
                println!("{}", val);
            } else {
                eprintln!(
                    "{} Unbekannter Konfigurations-Schlüssel '{}'",
                    "FEHLER:".bright_red().bold(),
                    k
                );
                std::process::exit(1);
            }
        }
        Some(ConfigAction::Set { key, value }) => {
            let mut cfg = SuiteConfig::load();
            match cfg.set_value(&key, &value) {
                Ok(()) => {
                    println!(
                        "{} {} = {}",
                        "✓ Konfiguration aktualisiert:".bright_green().bold(),
                        key.bright_cyan().bold(),
                        value.bright_yellow()
                    );
                    println!(
                        "  Gespeichert in: {}",
                        SuiteConfig::config_path()
                            .display()
                            .to_string()
                            .bright_black()
                    );
                }
                Err(err) => {
                    eprintln!("{} {}", "FEHLER:".bright_red().bold(), err);
                    std::process::exit(1);
                }
            }
        }
        Some(ConfigAction::Path) => {
            println!("{}", SuiteConfig::config_path().display());
        }
    }
}

fn print_full_config() {
    let cfg = SuiteConfig::load();
    let path = SuiteConfig::config_path();

    println!(
        "\n{}",
        "⚙️  S&B SUITE — ZENTRALE KONFIGURATION"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────────────".bright_black()
    );
    println!("  Pfad: {}\n", path.display().to_string().bright_black());

    println!("  {}", "[PORTS]".bright_yellow().bold());
    println!(
        "    {:<26} {:<8} {}",
        "ports.mesh_udp",
        cfg.ports.mesh_udp.to_string().cyan(),
        "# P2P WireGuard Overlay UDP Port".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "ports.proxy_ipc",
        cfg.ports.proxy_ipc.to_string().cyan(),
        "# Reverse-Proxy Telemetrie IPC".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "ports.proxy_http",
        cfg.ports.proxy_http.to_string().cyan(),
        "# HTTP-01 ACME Challenge & Redirect".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "ports.proxy_https",
        cfg.ports.proxy_https.to_string().cyan(),
        "# Edge TLS Gateway Port".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "ports.tunnel_hub",
        cfg.ports.tunnel_hub.to_string().cyan(),
        "# Ephemeral Port-Forward Tunnel Hub".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "ports.mesh_ipc",
        cfg.ports.mesh_ipc.to_string().cyan(),
        "# Daemon Management Socket".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "ports.stealth_ssh",
        cfg.ports.stealth_ssh.to_string().cyan(),
        "# Lokaler Stealth-SSH Loopback Port".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "ports.default_dev_target",
        cfg.ports.default_dev_target.to_string().cyan(),
        "# Standard Dev Server Port (Next/Vite)".bright_black()
    );

    println!("\n  {}", "[NETWORK]".bright_yellow().bold());
    println!(
        "    {:<26} {:<8} {}",
        "network.default_server",
        cfg.network
            .default_server
            .as_deref()
            .unwrap_or("<nicht gesetzt>")
            .cyan(),
        "# Flotten-Server Endpunkt".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "network.expected_node_ip",
        cfg.network
            .expected_node_ip
            .as_deref()
            .unwrap_or("<nicht gesetzt>")
            .cyan(),
        "# Erwartete öffentliche Node IP".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "network.connect_timeout_ms",
        format!("{}ms", cfg.network.connect_timeout_ms).cyan(),
        "# Socket Verbindungs-Timeout".bright_black()
    );

    println!("\n  {}", "[SECURITY]".bright_yellow().bold());
    println!(
        "    {:<26} {:<8} {}",
        "security.airgap_default",
        cfg.security.airgap_default.to_string().cyan(),
        "# Standard Airgap-Isolierung".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "security.lease_duration_secs",
        format!("{}s", cfg.security.lease_duration_secs).cyan(),
        "# Flüchtige Ephemeral Lease Dauer".bright_black()
    );
    println!(
        "    {:<26} {:<8} {}",
        "security.secret_engine",
        cfg.security.secret_engine.cyan(),
        "# Secret Storage Backend".bright_black()
    );

    println!("\n  {}", "TIPP: Werte anpassen mit:".bright_black());
    println!("    sb config set ports.stealth_ssh 58823");
    println!("    sb config set network.default_server 10.0.0.1:58888\n");
}
