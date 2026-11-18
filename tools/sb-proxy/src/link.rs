//! sb-proxy link — Sovereign Mesh Tunnel Link (Cloudflare Tunnel / ngrok Killer)
//!
//! Runs on the **developer's machine**: connects outbound via the encrypted
//! sb-mesh Stealth tunnel (UDP ChaCha20-Poly1305 / Noise_IK) to the VPS
//! Sovereign Tunnel Hub (loopback:58910), then proxies all traffic to a local
//! service port.  Zero inbound WAN ports required on either side.
//!
//! # Architecture
//!
//! ```text
//! Internet ──► VPS:443 (sb-proxy HTTPS/TLS) ──► TunnelHub:127.0.0.1:58910
//!                                                        │  OPEN_STREAM cmd
//!                                              ◄─────────┘  (via control channel)
//! Dev Machine: sb proxy link ──► Stealth UDP ──► decrypts ──► 127.0.0.1:58910
//!                                                              ──► localhost:<port>
//! ```
//!
//! Usage (plaintext):
//!
//! ```text
//! sb proxy link myapp.skulls-and-bones.org 3000
//! sb proxy link myapp.example.com 8080 --node hostinger-node --callsign my-laptop
//! ```

use crate::escape::SovereignTunnelClient;
use colored::Colorize;
use std::process::Command as StdCommand;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Local port used to forward VPS:58910 via Stealth tunnel.
/// Must not conflict with common dev ports or other mesh ports.
pub const MESH_TUNNEL_HUB_FORWARD_PORT: u16 = 58912;

/// Runs the developer-side Sovereign Mesh Tunnel Link.
///
/// # Steps
/// 1. Spawn `sb-mesh stealth --target-port 58910 --local-port 58912` in background
/// 2. Wait for loopback:58912 to become ready (≤5s)
/// 3. Connect `SovereignTunnelClient` to `127.0.0.1:58912`
/// 4. Block until Ctrl+C
pub async fn run_escape_link(
    domain: &str,
    local_port: u16,
    callsign: &str,
    node: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let hub_port = MESH_TUNNEL_HUB_FORWARD_PORT;

    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!(
        "  {} {} {}",
        "S&B SOVEREIGN PROXY".cyan().bold(),
        "//".black().bold(),
        "MESH TUNNEL LINK".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!("  {:<24} {}", "Domain:".bold(), domain.cyan().bold());
    println!(
        "  {:<24} {}",
        "Lokaler Dienst:".bold(),
        format!("127.0.0.1:{}", local_port).green().bold()
    );
    println!("  {:<24} {}", "Callsign:".bold(), callsign.white());
    println!(
        "  {:<24} {}",
        "Mesh-Verbindung:".bold(),
        format!("Node '{}' via Stealth UDP", node).bright_yellow()
    );
    println!(
        "  {:<24} {}",
        "Verschlüsselung:".bold(),
        "ChaCha20-Poly1305 (Noise_IK) — Zero WAN Ports".green()
    );
    println!(
        "  {:<24} {}",
        "Tunnel Hub Forward:".bold(),
        format!("127.0.0.1:{} → VPS:127.0.0.1:58910", hub_port).bright_white()
    );
    println!();

    // --- Step 1: Start sb-mesh stealth to forward VPS:58910 → local:58912 ---
    println!(
        "  {} Starte verschlüsselten Mesh-Stealth-Tunnel zur VPS ...",
        "⚡".yellow()
    );

    let sb_mesh_bin = resolve_sb_mesh_binary();
    let mut stealth_child = StdCommand::new(&sb_mesh_bin)
        .args([
            "stealth",
            "--target-port", "58910",
            "--local-port", &hub_port.to_string(),
            "--idle-timeout", "0", // disabled: sb proxy link manages lifecycle
        ])
        .spawn()
        .map_err(|e| format!("Konnte sb-mesh nicht starten ('{}'): {}. Stelle sicher, dass sb-mesh installiert und im PATH ist.", sb_mesh_bin, e))?;

    // --- Step 2: Wait for loopback port to be ready (up to 5s) ---
    let ready = wait_for_port_open("127.0.0.1", hub_port, Duration::from_secs(5)).await;
    if !ready {
        let _ = stealth_child.kill();
        return Err(format!(
            "Stealth-Tunnel konnte nicht innerhalb von 5s gestartet werden (127.0.0.1:{}). \
             Prüfe 'sb-mesh stealth' und die VPS-Erreichbarkeit.",
            hub_port
        )
        .into());
    }
    println!(
        "  {} Stealth-Tunnel bereit auf 127.0.0.1:{}",
        "✓".green().bold(),
        hub_port
    );

    // --- Step 3: Connect SovereignTunnelClient via the tunnel ---
    let gateway_addr = format!("127.0.0.1:{}", hub_port);
    let client = match SovereignTunnelClient::new(domain, local_port, &gateway_addr, callsign) {
        Ok(client) => client,
        Err(error) => {
            let _ = stealth_child.kill();
            let _ = stealth_child.wait();
            return Err(format!("Tunnel-Client-Fehler: {}", error).into());
        }
    };

    println!("  {} Registriere Tunnel für '{}' ...", "●".cyan(), domain);
    println!();
    println!(
        "  {} Tunnel aktiv! HTTPS-Anfragen an {} werden zu {} weitergeleitet.",
        "✓".green().bold(),
        domain.cyan().bold(),
        format!("127.0.0.1:{}", local_port).green().bold()
    );
    println!(
        "  {} Drücke {} zum Beenden.",
        "i".bright_black(),
        "[Strg+C]".bold()
    );
    println!();

    let running = client.running.clone();
    let running_for_ctrlc = running.clone();

    // Ctrl+C handler: stop tunnel client gracefully
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("\n  {} Tunnel wird beendet...", "⏹".yellow());
        running_for_ctrlc.store(false, Ordering::SeqCst);
    });

    // Run until stopped
    let result = client.run().await;

    // Clean up stealth child
    let _ = stealth_child.kill();
    let _ = stealth_child.wait();
    running.store(false, Ordering::SeqCst);

    result.map_err(|e| format!("Tunnel-Verbindung getrennt: {}", e).into())
}

/// Returns the path to `sb-mesh` via central BinaryResolver.
fn resolve_sb_mesh_binary() -> String {
    sb_core::BinaryResolver::resolve_mesh()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| sb_core::BinaryResolver::exe_name("sb-mesh"))
}

/// Polls TCP port until it accepts connections or timeout expires.
async fn wait_for_port_open(host: &str, port: u16, timeout: Duration) -> bool {
    let addr = format!("{}:{}", host, port);
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Returns a machine-derived callsign for this developer node.
/// Uses `USERNAME` / `USER` env var + hostname.
pub fn default_callsign() -> String {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "dev".into());
    let host = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "laptop".into());
    // sanitize: only ascii alphanumeric and hyphens, max 48 chars
    let raw = format!("{}-{}", user, host);
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(48)
        .collect();
    if clean.is_empty() {
        "dev-node".to_string()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_callsign_is_valid() {
        let cs = default_callsign();
        assert!(!cs.is_empty());
        assert!(cs.len() <= 48);
        assert!(cs.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn test_mesh_tunnel_hub_port_not_protected() {
        // The forward port must not be a mesh or system protected port
        assert_ne!(MESH_TUNNEL_HUB_FORWARD_PORT, 22);
        assert_ne!(MESH_TUNNEL_HUB_FORWARD_PORT, 58888);
        assert_ne!(MESH_TUNNEL_HUB_FORWARD_PORT, 58910);
        assert!(MESH_TUNNEL_HUB_FORWARD_PORT > 1024);
    }

    #[tokio::test]
    async fn test_wait_for_port_timeout_on_closed_port() {
        // Port 59999 should not be open -> timeout
        let result = wait_for_port_open("127.0.0.1", 59999, Duration::from_millis(200)).await;
        assert!(!result, "Expected timeout on closed port");
    }

    #[tokio::test]
    async fn test_wait_for_port_succeeds_when_open() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = wait_for_port_open("127.0.0.1", port, Duration::from_secs(1)).await;
        assert!(result, "Expected success on open port");
    }
}
