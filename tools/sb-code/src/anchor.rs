use colored::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorInfo {
    pub callsign: String,
    pub node_id: String,
    pub overlay_ip: Option<String>,
    pub endpoint: Option<String>,
    pub is_anchor: bool,
    pub source: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
struct MeshIpcRequest {
    action: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MeshIpcResponse {
    status: String,
    #[serde(default)]
    data: serde_json::Value,
}

/// Discovers available Seeding Anchors in the S&B Mesh.
pub async fn find_seeding_anchors() -> Vec<AnchorInfo> {
    let mut anchors = Vec::new();

    // 1. Try to query local sb-mesh IPC on 127.0.0.1:58890
    if let Ok(mesh_peers) = query_mesh_ipc_peers().await {
        for peer in mesh_peers {
            if is_anchor_candidate(&peer.callsign) {
                anchors.push(AnchorInfo {
                    callsign: peer.callsign,
                    node_id: peer.node_id,
                    overlay_ip: peer.overlay_ip,
                    endpoint: peer.endpoint,
                    is_anchor: true,
                    source: "sb-mesh Swarm".to_string(),
                });
            }
        }
    }

    // 2. Check local sb-node configuration or active service
    if let Some(local_node) = check_local_sb_node() {
        if !anchors.iter().any(|a| a.callsign == local_node.callsign) {
            anchors.push(local_node);
        }
    }

    // 3. Check fleet team servers from ~/.sb/team_servers.toml
    for fleet_node in check_fleet_team_servers() {
        if !anchors.iter().any(|a| a.callsign == fleet_node.callsign) {
            anchors.push(fleet_node);
        }
    }

    anchors
}

fn check_fleet_team_servers() -> Vec<AnchorInfo> {
    let mut fleet = Vec::new();
    if let Some(home) = dirs::home_dir() {
        let servers_path = home.join(".sb").join("team_servers.toml");
        if servers_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&servers_path) {
                if let Ok(val) = content.parse::<toml::Value>() {
                    if let Some(servers) = val.get("servers").and_then(|s| s.as_array()) {
                        for s in servers {
                            let name = s.get("name").and_then(|n| n.as_str()).unwrap_or_default();
                            let host = s.get("host").and_then(|h| h.as_str()).unwrap_or_default();
                            let tags = s
                                .get("tags")
                                .and_then(|t| t.as_array())
                                .map(|arr| {
                                    arr.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>()
                                })
                                .unwrap_or_default();

                            let is_anchor = tags.contains(&"anchor")
                                || tags.contains(&"seeder")
                                || tags.contains(&"sb-node")
                                || is_anchor_candidate(name);

                            if is_anchor && !name.is_empty() {
                                fleet.push(AnchorInfo {
                                    callsign: name.to_string(),
                                    node_id: format!("fleet-{}", name),
                                    overlay_ip: Some(host.to_string()),
                                    endpoint: Some(format!("{}:58888", host)),
                                    is_anchor: true,
                                    source: "S&B Fleet Server".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    fleet
}

fn is_anchor_candidate(callsign: &str) -> bool {
    let lower = callsign.to_lowercase();
    lower.starts_with("node-")
        || lower.starts_with("srv-")
        || lower.starts_with("anchor-")
        || lower.ends_with("-node")
        || lower.ends_with("-anchor")
        || lower.contains("anchor")
        || lower.contains("server")
}

#[derive(Debug, Deserialize)]
struct PeerSummaryRaw {
    callsign: String,
    node_id: String,
    endpoint: Option<String>,
    overlay_ip: Option<String>,
}

async fn query_mesh_ipc_peers() -> Result<Vec<PeerSummaryRaw>, String> {
    let addr: SocketAddr = "127.0.0.1:58890".parse().map_err(|e| format!("{}", e))?;
    let stream = tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr))
        .await
        .map_err(|_| "Timeout connecting to sb-mesh IPC".to_string())?
        .map_err(|e| format!("Cannot connect to sb-mesh: {}", e))?;

    let (mut reader, mut writer) = stream.into_split();

    let req = serde_json::json!({
        "action": "ListPeers"
    });
    let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;

    writer
        .write_all(&req_bytes)
        .await
        .map_err(|e| e.to_string())?;
    writer.shutdown().await.map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .map_err(|e| e.to_string())?;

    let resp: MeshIpcResponse = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
    if resp.status == "Ok" {
        let peers: Vec<PeerSummaryRaw> = serde_json::from_value(resp.data).unwrap_or_default();
        Ok(peers)
    } else {
        Err("Mesh IPC returned error".to_string())
    }
}

fn check_local_sb_node() -> Option<AnchorInfo> {
    let mut config_paths = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(program_data) = std::env::var("ProgramData") {
            config_paths.push(
                PathBuf::from(program_data)
                    .join("sb-node")
                    .join("node.json"),
            );
        }
    }
    if let Some(home) = dirs::home_dir() {
        config_paths.push(home.join(".sb-node").join("node.json"));
    }

    for path in config_paths {
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                    let node_name = v
                        .get("node_name")
                        .and_then(|s| s.as_str())
                        .unwrap_or("sb-node-local");
                    return Some(AnchorInfo {
                        callsign: node_name.to_string(),
                        node_id: "local-daemon".to_string(),
                        overlay_ip: Some("127.0.0.1".to_string()),
                        endpoint: Some(format!(
                            "127.0.0.1:{}",
                            v.get("mesh_port").and_then(|p| p.as_u64()).unwrap_or(58888)
                        )),
                        is_anchor: true,
                        source: "Local sb-node Agent".to_string(),
                    });
                }
            }
        }
    }

    None
}

/// Emits the rich CLI status report for Seeding Anchors.
/// Returns true if at least one anchor is active, false otherwise.
pub fn print_anchor_status_report(anchors: &[AnchorInfo]) -> bool {
    if !anchors.is_empty() {
        println!(
            "{}",
            "── Seeding Anchors (Persistenz-Garantie) ──".bold().cyan()
        );
        for a in anchors {
            let ip_str = a.overlay_ip.as_deref().unwrap_or("Mesh-Overlay");
            println!(
                "  {} {} '{}' ({}) via {}",
                "⚓".green(),
                "Seeding Anchor aktiv:".bold().green(),
                a.callsign.bold().white(),
                ip_str.yellow(),
                a.source.cyan()
            );
        }
        println!(
            "  {} Projekt wird persistent im Mesh vorgehalten (24/7 Verfügbarkeit gesichert).\n",
            "✔".green()
        );
        true
    } else {
        println!(
            "{}",
            "────────────────────────────────────────────────────────────────────────".yellow()
        );
        println!(
            "  {} {}",
            "⚠️".bold().yellow(),
            "KEIN SEEDING ANCHOR (sb-node) IM MESH ERKANNT!"
                .bold()
                .yellow()
        );
        println!(
            "{}",
            "────────────────────────────────────────────────────────────────────────".yellow()
        );
        println!();
        println!(
            "  {} {}",
            "ℹ".bold().cyan(),
            "Was ist ein Seeding Anchor?".bold().white()
        );
        println!(
            "    Ein Seeding Anchor ist ein dedizierter, ständig erreichbarer Knoten\n    (z. B. ein Server, VPS oder Raspberry Pi mit '{}').\n    Er hält den Code im Mesh 24/7 persistent vor, sodass Teammitglieder dein\n    Projekt auch dann 'subscriben' können, wenn dein Laptop zugeklappt oder offline ist.",
            "sb-node".bold().yellow()
        );
        println!();
        println!(
            "  {} {}",
            "💡".bold().cyan(),
            "Wie startest du einen Seeding Anchor?".bold().white()
        );
        println!(
            "    1. Auf deinem Server:  {}",
            "sb node init && sb node start --anchor".bold().green()
        );
        println!(
            "    2. Oder lokal testen:  {}",
            "sb node start".bold().green()
        );
        println!();
        println!(
            "  {} {}",
            "⚡".bold().magenta(),
            "Fallback in flüchtigen P2P-Modus:".bold().magenta()
        );
        println!(
            "    Das Projekt wird veröffentlicht, ist aber {} solange dieser\n    Rechner aktiv im Mesh online bleibt.",
            "NUR VERFÜGBAR,".bold().red()
        );
        println!(
            "{}",
            "────────────────────────────────────────────────────────────────────────\n".yellow()
        );
        false
    }
}
