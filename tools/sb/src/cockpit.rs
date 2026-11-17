//! Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`)
//!
//! Interactive Ratatui Terminal User Interface and Headless Snapshot Engine
//! for live daemon health, WireGuard mesh peers, and audit/access telemetry.
//!
//! Standards & Security Compliance:
//! - ECMA-48 / ISO/IEC 6429: Control functions and ANSI sequence sanitization (CWE-150 / CWE-116).
//! - ISO 8601 / RFC 3339: UTC timestamp representations.
//! - CWE-754: Global panic hook ensuring terminal restoration on abnormal exit.
//! - CWE-400: Decoupled background polling with bounded socket timeouts (<=150ms).
//! - CWE-403: Redaction of private credentials and keys in snapshot dumps.

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Stdout, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::time::{Duration, Instant};

pub use sb_core::mesh_ipc::PeerSummaryPayload;

// ==============================================================================
// 1. DATA MODELS & TELEMETRY CONTRACTS
// ==============================================================================

/// Health status badge for active daemons
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Online,
    Degraded,
    Offline,
}

impl HealthStatus {
    pub fn badge(&self) -> (&'static str, Color) {
        match self {
            HealthStatus::Online => ("● ONLINE", Color::Green),
            HealthStatus::Degraded => ("▲ DEGRADED", Color::Yellow),
            HealthStatus::Offline => ("✖ OFFLINE", Color::Red),
        }
    }

    pub fn text_badge(&self) -> &'static str {
        match self {
            HealthStatus::Online => "[ONLINE]",
            HealthStatus::Degraded => "[DEGRADED]",
            HealthStatus::Offline => "[OFFLINE]",
        }
    }
}

/// Telemetry status of an individual core daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonHealth {
    pub name: String,
    pub role: String,
    pub port_info: String,
    pub status: HealthStatus,
    pub latency_ms: Option<u64>,
    pub details: String,
}

/// Structured audit and access event for the bottom HUD panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub source: String,
    pub severity: String,
    pub message: String,
}

/// Complete telemetry snapshot of the Fleet HUD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CockpitSnapshot {
    pub callsign: String,
    pub swarm_status: String,
    pub utc_time: String,
    pub lease_status: String,
    pub lease_remaining: String,
    pub daemons: Vec<DaemonHealth>,
    pub peers: Vec<PeerSummaryPayload>,
    pub audit_events: Vec<AuditEvent>,
    pub detected_crashes: Vec<String>,
    pub pending_quorum: usize,
}

// ==============================================================================
// 2. SECURITY HARDENING: ANSI SANITIZER & PANIC HOOK
// ==============================================================================

/**
 * Sanitizes strings from untrusted sources to prevent ANSI escape sequence injection.
 *
 * SECURITY AUDIT:
 * - Dynamic Threat Vector: Untrusted external strings (remote peer callsigns, DNS record names,
 *   unfiltered audit log entries) can inject ANSI escape sequences (CSI, OSC, cursor positioning)
 *   to hijack the terminal emulator display, overwrite borders, or spoof green status badges.
 * - CVE / CWE Mapping: CWE-150 (Improper Neutralization of Escape, Meta, or Control Sequences),
 *   CWE-116 (Improper Output Neutralization).
 * - Likelihood & Exploitability: High (Score: 8/10) when displaying names supplied by remote mesh peers.
 * - Applied Mitigation: Strip all C0 control characters (0x00..=0x1F except tab and newline),
 *   DEL (0x7F), C1 control characters (0x80..=0x9F), and 7-bit/8-bit ANSI escape sequences.
 *
 * Conforms to ECMA-48 (5th Edition, June 1991) §5.4 (CSI) and §5.5 (OSC), and ISO/IEC 6429.
 */
pub fn sanitize_tui_string(input: &str) -> String {
    let mut clean = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ANSI escape sequence start
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: ESC [ ... [0x40..=0x7E]
                    chars.next();
                    while let Some(seq_char) = chars.next() {
                        if (0x40..=0x7E).contains(&(seq_char as u32)) {
                            break;
                        }
                    }
                    continue;
                } else if next == ']' {
                    // OSC sequence: ESC ] ... (ST \x1b\ or BEL \x07)
                    chars.next();
                    while let Some(seq_char) = chars.next() {
                        if seq_char == '\x07' || seq_char == '\x1b' {
                            if seq_char == '\x1b' && chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                    continue;
                } else if next == '(' || next == ')' || next == '*' || next == '+' {
                    chars.next();
                    chars.next();
                    continue;
                } else {
                    chars.next();
                    continue;
                }
            }
            continue;
        }

        // Handle tabs and newlines
        if c == '\t' {
            clean.push(' ');
            continue;
        }
        if c == '\n' {
            clean.push('\n');
            continue;
        }

        // Filter out C0 control characters (0x00..=0x1F)
        if (c as u32) < 0x20 {
            continue;
        }

        // Filter out DEL (0x7F) and C1 control characters (0x80..=0x9F)
        if (0x7F..=0x9F).contains(&(c as u32)) {
            continue;
        }

        clean.push(c);
    }

    clean
}

/**
 * Installs a global panic hook ensuring the terminal is always restored to standard mode
 * even if a panic occurs inside the Ratatui event loop or render pipeline.
 *
 * SECURITY AUDIT:
 * - Dynamic Threat Vector: An unhandled panic while the terminal is in raw mode, hidden cursor,
 *   and alternate screen leaves the user's terminal emulator bricked (un-echoed keystrokes, missing cursor).
 * - CVE / CWE Mapping: CWE-754 (Improper Check for Unusual or Exceptional Conditions).
 * - Likelihood & Exploitability: High (Score: 7/10) during unexpected terminal resizing or drawing panics.
 * - Applied Mitigation: Global std::panic::set_hook resets raw mode, disables mouse capture,
 *   leaves alternate screen, and restores cursor visibility before delegating to default panic handler.
 */
fn setup_terminal_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = crossterm::execute!(
            stdout,
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show
        );
        default_hook(panic_info);
    }));
}

// ==============================================================================
// 3. TELEMETRY PROBING ENGINE (CWE-400 DEFENSE WITH BOUNDED TIMEOUTS)
// ==============================================================================

const SOCKET_PROBE_TIMEOUT: Duration = Duration::from_millis(150);

/// Probes the local `sb-node` daemon status and port bindings
fn probe_node_daemon(timeout: Duration) -> DaemonHealth {
    let start = Instant::now();
    let api_addr: SocketAddr = match "127.0.0.1:58905".parse() {
        Ok(a) => a,
        Err(_) => {
            return DaemonHealth {
                name: "sb-node".to_string(),
                role: "Server Agent & Relay".to_string(),
                port_info: "UDP 58888".to_string(),
                status: HealthStatus::Offline,
                latency_ms: None,
                details: "Ungültige Loopback-Adresse".to_string(),
            };
        }
    };

    let api_connected = TcpStream::connect_timeout(&api_addr, timeout).is_ok();
    let rtt = if api_connected {
        Some(start.elapsed().as_millis() as u64)
    } else {
        None
    };

    // Process ledger & systemd verification
    let ledger = sb_core::process::load_ledger();
    let tracked = ledger
        .processes
        .iter()
        .find(|p| p.name == "sb-node" || p.command.contains("sb-node"));
    let pid_alive = tracked
        .map(|p| sb_core::process::is_pid_alive(p.pid))
        .unwrap_or(false)
        || crate::commands::service::is_systemd_unit_active("sb-node");

    if api_connected {
        DaemonHealth {
            name: "sb-node".to_string(),
            role: "Server Agent & Relay".to_string(),
            port_info: "UDP 58888 :58905".to_string(),
            status: HealthStatus::Online,
            latency_ms: rtt,
            details: "Loopback API :58905 aktiv, UDP 58888 Dispatcher bereit".to_string(),
        }
    } else if pid_alive {
        let pid_str = tracked
            .map(|p| format!("PID {} aktiv", p.pid))
            .unwrap_or_else(|| "Systemd aktiv".to_string());
        DaemonHealth {
            name: "sb-node".to_string(),
            role: "Server Agent & Relay".to_string(),
            port_info: "UDP 58888".to_string(),
            status: HealthStatus::Online,
            latency_ms: None,
            details: format!("{}, UDP 58888 Dispatcher aktiv", pid_str),
        }
    } else {
        DaemonHealth {
            name: "sb-node".to_string(),
            role: "Server Agent & Relay".to_string(),
            port_info: "UDP 58888".to_string(),
            status: HealthStatus::Offline,
            latency_ms: None,
            details: "Daemon inaktiv (UDP 58888 / TCP 58905 nicht erreichbar)".to_string(),
        }
    }
}

/// Probes the local `sb-mesh` daemon over TCP IPC (Port 58890)
fn probe_mesh_daemon(timeout: Duration) -> (DaemonHealth, Vec<PeerSummaryPayload>) {
    let start = Instant::now();
    let sock_addr: SocketAddr = "127.0.0.1:58890".parse().unwrap();

    let mut stream = match TcpStream::connect_timeout(&sock_addr, timeout) {
        Ok(s) => s,
        Err(_) => {
            let offline_peers = load_offline_peers();
            let ledger = sb_core::process::load_ledger();
            let pid_alive = ledger
                .processes
                .iter()
                .any(|p| p.name == "sb-mesh" && sb_core::process::is_pid_alive(p.pid));

            let status = if pid_alive {
                HealthStatus::Degraded
            } else {
                HealthStatus::Offline
            };
            let details = if pid_alive {
                "Prozess läuft, IPC-Port 58890 blockiert".to_string()
            } else {
                "Daemon inaktiv (TCP 58890 nicht erreichbar)".to_string()
            };

            return (
                DaemonHealth {
                    name: "sb-mesh".to_string(),
                    role: "WireGuard Overlay Mesh".to_string(),
                    port_info: "TCP 58890".to_string(),
                    status,
                    latency_ms: None,
                    details,
                },
                offline_peers,
            );
        }
    };

    let rtt = start.elapsed().as_millis() as u64;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut details = "IPC aktiv (WireGuard Noise_IK)".to_string();
    if stream.write_all(b"{\"action\":\"GetStatus\"}\n").is_ok() {
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = stream.read(&mut buf) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&buf[..n]) {
                if let Some(data) = val.get("data") {
                    let peers_count = data.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let air_gap = data
                        .get("air_gap_killswitch")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    details = format!(
                        "Peers: {}, Air-Gap: {}, UDP 51820",
                        peers_count,
                        if air_gap { "ON" } else { "OFF" }
                    );
                }
            }
        }
    }

    // Query ListPeers
    let mut peers = Vec::new();
    if let Ok(mut pstream) = TcpStream::connect_timeout(&sock_addr, timeout) {
        let _ = pstream.set_read_timeout(Some(timeout));
        let _ = pstream.set_write_timeout(Some(timeout));
        if pstream.write_all(b"{\"action\":\"ListPeers\"}\n").is_ok() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            while let Ok(n) = pstream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
            }
            if let Ok(resp) = serde_json::from_slice::<sb_core::mesh_ipc::IpcResponse>(&buf) {
                if let sb_core::mesh_ipc::IpcResponse::Ok(sb_core::mesh_ipc::IpcPayload::Peers(p)) =
                    resp
                {
                    peers = p;
                }
            }
        }
    }

    if peers.is_empty() {
        peers = load_offline_peers();
    }

    (
        DaemonHealth {
            name: "sb-mesh".to_string(),
            role: "WireGuard Overlay Mesh".to_string(),
            port_info: "TCP 58890".to_string(),
            status: HealthStatus::Online,
            latency_ms: Some(rtt),
            details,
        },
        peers,
    )
}

/// Probes the local `sb-proxy` HTTP loopback endpoint (Port 58900)
fn probe_proxy_daemon(timeout: Duration) -> DaemonHealth {
    let start = Instant::now();
    let sock_addr: SocketAddr = "127.0.0.1:58900".parse().unwrap();

    let mut stream = match TcpStream::connect_timeout(&sock_addr, timeout) {
        Ok(s) => s,
        Err(_) => {
            let ledger = sb_core::process::load_ledger();
            let pid_alive = ledger
                .processes
                .iter()
                .any(|p| p.name == "sb-proxy" && sb_core::process::is_pid_alive(p.pid));

            let status = if pid_alive {
                HealthStatus::Degraded
            } else {
                HealthStatus::Offline
            };
            let details = if pid_alive {
                "Prozess läuft, HTTP 58900 blockiert".to_string()
            } else {
                "Gateway inaktiv (TCP 58900 nicht erreichbar)".to_string()
            };

            return DaemonHealth {
                name: "sb-proxy".to_string(),
                role: "Edge Gateway & TLS".to_string(),
                port_info: "TCP 58900".to_string(),
                status,
                latency_ms: None,
                details,
            };
        }
    };

    let rtt = start.elapsed().as_millis() as u64;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let req = "GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let mut details = "HTTP 200 OK (Edge Gateway & On-Demand TLS aktiv)".to_string();

    if stream.write_all(req.as_bytes()).is_ok() {
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = stream.read(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if let Some(body_start) = resp.find("\r\n\r\n") {
                let body = &resp[body_start + 4..];
                if let Ok(dto) =
                    serde_json::from_str::<sb_core::dto::ProxyTelemetryDto>(body.trim())
                {
                    details = format!(
                        "PID {}, Reqs: {} (4xx:{}, 5xx:{}), Latency: {:.1}ms",
                        dto.pid,
                        dto.total_requests,
                        dto.requests_4xx,
                        dto.requests_5xx,
                        dto.avg_latency_ms
                    );
                }
            }
        }
    }

    DaemonHealth {
        name: "sb-proxy".to_string(),
        role: "Edge Gateway & TLS".to_string(),
        port_info: "TCP 58900".to_string(),
        status: HealthStatus::Online,
        latency_ms: Some(rtt),
        details,
    }
}

/// Probes the local `sb-dns` split-horizon resolver (Port 58853 / 53)
fn probe_dns_daemon(timeout: Duration) -> DaemonHealth {
    let start = Instant::now();
    let addr_58853: SocketAddr = "127.0.0.1:58853".parse().unwrap();
    let addr_53: SocketAddr = "127.0.0.1:53".parse().unwrap();

    let (connected, rtt, port) = match TcpStream::connect_timeout(&addr_58853, timeout) {
        Ok(_) => (true, Some(start.elapsed().as_millis() as u64), 58853),
        Err(_) => match TcpStream::connect_timeout(&addr_53, timeout) {
            Ok(_) => (true, Some(start.elapsed().as_millis() as u64), 53),
            Err(_) => (false, None, 0),
        },
    };

    if connected {
        DaemonHealth {
            name: "sb-dns".to_string(),
            role: "Split-Horizon DNS".to_string(),
            port_info: if port == 53 {
                ":53 (Root)".to_string()
            } else {
                ":58853".to_string()
            },
            status: HealthStatus::Online,
            latency_ms: rtt,
            details: format!("Port {} aktiv (.sbm, .mesh Split-Horizon Resolver)", port),
        }
    } else {
        let ledger = sb_core::process::load_ledger();
        let pid_alive = ledger
            .processes
            .iter()
            .any(|p| p.name == "sb-dns" && sb_core::process::is_pid_alive(p.pid));

        let status = if pid_alive {
            HealthStatus::Degraded
        } else {
            HealthStatus::Offline
        };
        let details = if pid_alive {
            "Prozess aktiv, DNS-Ports blockiert".to_string()
        } else {
            "Resolver inaktiv (Ports 58853 / 53 nicht erreichbar)".to_string()
        };

        DaemonHealth {
            name: "sb-dns".to_string(),
            role: "Split-Horizon DNS".to_string(),
            port_info: ":58853 / :53".to_string(),
            status,
            latency_ms: None,
            details,
        }
    }
}

/// Fallback peer loader from local configuration files
fn load_offline_peers() -> Vec<PeerSummaryPayload> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

    // 1. Try ~/.sb-mesh/peers.toml
    let peers_file = home.join(".sb-mesh").join("peers.toml");
    if peers_file.is_file() {
        if let Ok(content) = std::fs::read_to_string(&peers_file) {
            if let Ok(val) = toml::from_str::<toml::Value>(&content) {
                if let Some(arr) = val.get("peers").and_then(|p| p.as_array()) {
                    let mut list = Vec::new();
                    for item in arr {
                        let callsign = item
                            .get("callsign")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let node_id = item
                            .get("node_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-")
                            .to_string();
                        let pubkey = item
                            .get("public_key")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-")
                            .to_string();
                        let endpoint = item
                            .get("endpoint")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let overlay_ip = item
                            .get("overlay_ip")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        list.push(PeerSummaryPayload {
                            callsign,
                            node_id,
                            public_key_base64: pubkey,
                            endpoint,
                            overlay_ip,
                            status: "SAVED".to_string(),
                            rtt_ms: None,
                            bytes_sent: 0,
                            bytes_recv: 0,
                            zk_attested: false,
                        });
                    }
                    if !list.is_empty() {
                        return list;
                    }
                }
            }
        }
    }

    // 2. Fallback to registered servers in ~/.sb/servers.toml
    let servers = sb_core::TargetResolver::load_servers();
    servers
        .into_iter()
        .map(|s| PeerSummaryPayload {
            callsign: s.name.clone(),
            node_id: format!("sbm-{}", s.host.replace(['.', ':'], "-")),
            public_key_base64: "ConfiguredHost".to_string(),
            endpoint: Some(format!("{}:{}", s.host, s.port)),
            overlay_ip: Some(format!("{}.sbm", s.name)),
            status: "STANDBY".to_string(),
            rtt_ms: None,
            bytes_sent: 0,
            bytes_recv: 0,
            zk_attested: false,
        })
        .collect()
}

/// Loads recent audit, session, and error logs with bounded memory usage (CWE-400)
fn load_audit_events(limit: usize) -> (Vec<AuditEvent>, Vec<String>) {
    let mut events = Vec::new();
    let mut detected_crashes = Vec::new();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

    // 1. Read sessions.jsonl
    let sessions_path = home.join(".sb").join("audit").join("sessions.jsonl");
    if sessions_path.is_file() {
        if let Ok(file) = std::fs::File::open(&sessions_path) {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
            for line in lines.into_iter().rev().take(limit) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    let ts = v
                        .get("timestamp")
                        .and_then(|t| t.as_str())
                        .unwrap_or("-")
                        .to_string();
                    let target = v
                        .get("target")
                        .or_else(|| v.get("host"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("ssh");
                    let user = v.get("user").and_then(|u| u.as_str()).unwrap_or("admin");
                    let action = v
                        .get("action")
                        .and_then(|a| a.as_str())
                        .unwrap_or("session");

                    events.push(AuditEvent {
                        timestamp: ts,
                        source: "AUDIT".to_string(),
                        severity: "INFO".to_string(),
                        message: format!("Session {} by user {} on {}", action, user, target),
                    });
                }
            }
        }
    }

    // 2. Read errors.jsonl
    let errors_path = home.join(".sb").join("logs").join("errors.jsonl");
    if errors_path.is_file() {
        if let Ok(file) = std::fs::File::open(&errors_path) {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
            for line in lines.into_iter().rev().take(limit) {
                if let Ok(rec) = serde_json::from_str::<crate::logger::ErrorRecord>(&line) {
                    events.push(AuditEvent {
                        timestamp: rec.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                        source: rec.tool,
                        severity: rec.level,
                        message: rec.message,
                    });
                }
            }
        }
    }

    // 3. Fallback: Read recent lines from ~/.sb/logs/
    if events.is_empty() {
        let raw_logs = crate::logs::fetch_recent_logs(limit);
        for l in raw_logs {
            let (sev, _) = crate::logs::format_log_line(&l);
            if let Some((kind, detail)) = crate::logs::CrashInspector::inspect_type(&l) {
                detected_crashes.push(format!("{}: {}", kind, detail));
            }
            events.push(AuditEvent {
                timestamp: chrono::Utc::now()
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
                source: "LOG".to_string(),
                severity: sev.badge().to_string(),
                message: l,
            });
        }
    } else {
        // Inspect loaded messages for crashes
        for ev in &events {
            if let Some((kind, detail)) = crate::logs::CrashInspector::inspect_type(&ev.message) {
                detected_crashes.push(format!("{}: {}", kind, detail));
            }
        }
    }

    events.truncate(limit);
    (events, detected_crashes)
}

/// Formats raw byte counts into human-readable strings (B, KB, MB, GB)
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

impl CockpitSnapshot {
    /// Collects the complete live telemetry snapshot from local daemons, sockets, and logs.
    pub fn collect() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

        // 1. Callsign & Local Mesh Identity
        let mesh_id_path = home.join(".sb-mesh").join("identity.json");
        let mut callsign = "sbm-local".to_string();
        let mut has_mesh_identity = false;
        if mesh_id_path.exists() {
            if let Ok(c) = std::fs::read_to_string(&mesh_id_path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&c) {
                    if let Some(id) = val.get("node_id").and_then(|v| v.as_str()) {
                        callsign = id.to_string();
                        has_mesh_identity = true;
                    }
                }
            }
        }

        // 2. Ephemeral RAM Lease Status (Unified sb-key lease.token + legacy lease.json fallback)
        let mut lease_status = "INAKTIV / GESPERRT".to_string();
        let mut lease_remaining = "Führe 'sb up' oder 'sb lease' aus".to_string();

        if let Some(active_lease) = sb_key::get_lease_status() {
            if let Some(rem) = active_lease.remaining_duration() {
                let total_secs = rem.num_seconds().max(0);
                let h = total_secs / 3600;
                let m = (total_secs % 3600) / 60;
                let s = total_secs % 60;
                lease_status = "AKTIV (RAM)".to_string();
                lease_remaining = format!("{:02}h {:02}m {:02}s", h, m, s);
            }
        } else {
            let lease_path = sb_core::paths::sb_home().join("lease.json");
            if lease_path.exists() {
                if let Ok(data) = std::fs::read_to_string(&lease_path) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                        if let Some(exp_str) = v.get("expires_at").and_then(|e| e.as_str()) {
                            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(exp_str)
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                            {
                                let now = chrono::Utc::now();
                                if exp > now {
                                    let rem = exp - now;
                                    let total_secs = rem.num_seconds();
                                    let h = total_secs / 3600;
                                    let m = (total_secs % 3600) / 60;
                                    let s = total_secs % 60;
                                    lease_status = "AKTIV (RAM)".to_string();
                                    lease_remaining = format!("{:02}h {:02}m {:02}s", h, m, s);
                                } else {
                                    lease_status = "ABGELAUFEN".to_string();
                                    lease_remaining = "00h 00m 00s".to_string();
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Probe Daemons & Collect Peers
        let node_health = probe_node_daemon(SOCKET_PROBE_TIMEOUT);
        let (mesh_health, peers) = probe_mesh_daemon(SOCKET_PROBE_TIMEOUT);
        let proxy_health = probe_proxy_daemon(SOCKET_PROBE_TIMEOUT);
        let dns_health = probe_dns_daemon(SOCKET_PROBE_TIMEOUT);

        let swarm_status = if mesh_health.status == HealthStatus::Online {
            "ONLINE (WireGuard)".to_string()
        } else if has_mesh_identity {
            "STANDBY (Overlay)".to_string()
        } else {
            "ISOLATED".to_string()
        };

        let daemons = vec![node_health, mesh_health, proxy_health, dns_health];

        // 4. Audit & Access Logs
        let (audit_events, detected_crashes) = load_audit_events(30);

        // 5. Current UTC Time (ISO 8601 / RFC 3339)
        let utc_time = chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();

        let pending_quorum = crate::quorum::get_pending_count();

        Self {
            callsign,
            swarm_status,
            utc_time,
            lease_status,
            lease_remaining,
            daemons,
            peers,
            audit_events,
            detected_crashes,
            pending_quorum,
        }
    }
}

// ==============================================================================
// 4. HEADLESS SNAPSHOT RENDERER (CI/CD & SCRIPT VERIFICATION)
// ==============================================================================

/**
 * Renders the complete HUD panels as formatted plain-text to standard output or buffer.
 *
 * SECURITY AUDIT:
 * - Dynamic Threat Vector: Untrusted external strings in telemetry dumps (malicious peer names,
 *   crafted log entries, multi-byte UTF-8 IDs) may corrupt automated CI log pipelines or cause slice panics.
 * - CVE / CWE Mapping: CWE-150 (ANSI injection), CWE-403 (Exposure of Sensitive Information),
 *   CWE-248 / CWE-754 / CWE-125 (UTF-8 char-boundary slicing panic).
 * - Likelihood & Exploitability: Low (Score: 2/10) in automated execution; High (8/10) crash vector if multi-byte node_id is received.
 * - Applied Mitigation: Enforce sanitize_tui_string on all variable outputs, char-boundary-safe slicing with .chars().take(14); exclude private keys.
 *
 * Conforms to ISO 8601, ISO/IEC 10646 (Unicode UTF-8), and VT100 / ECMA-48 text formatting.
 */
pub fn render_snapshot<W: Write>(snapshot: &CockpitSnapshot, out: &mut W) -> std::io::Result<()> {
    writeln!(
        out,
        "╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗"
    )?;
    writeln!(
        out,
        "║ SKULLS & BONES // FLEET COCKPIT HUD [SNAPSHOT]                                                       ║"
    )?;
    writeln!(
        out,
        "╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝"
    )?;
    let quorum_str = if snapshot.pending_quorum > 0 {
        format!(
            " | Quorum: {} pending ('sb quorum')",
            snapshot.pending_quorum
        )
    } else {
        String::new()
    };
    writeln!(
        out,
        " Callsign: {:<16} Swarm: {:<18} Time: {:<24} Lease: {} ({}){}",
        sanitize_tui_string(&snapshot.callsign),
        snapshot.swarm_status,
        snapshot.utc_time,
        snapshot.lease_status,
        snapshot.lease_remaining,
        quorum_str
    )?;

    writeln!(out, "\n[ACTIVE DAEMONS & LIVE HEALTH]")?;
    for d in &snapshot.daemons {
        let badge = d.status.text_badge();
        let rtt = d
            .latency_ms
            .map(|ms| format!("{}ms", ms))
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            out,
            "  • {:<10} {:<12} {:<18} RTT: {:<6} {}",
            d.name,
            badge,
            d.port_info,
            rtt,
            sanitize_tui_string(&d.details)
        )?;
    }

    writeln!(
        out,
        "\n[WIREGUARD MESH PEERS] ({} peers registered)",
        snapshot.peers.len()
    )?;
    writeln!(
        out,
        "  {:<16} {:<16} {:<18} {:<8} {:<18} STATUS",
        "CALLSIGN", "NODE ID", "OVERLAY IP", "RTT", "TX / RX"
    )?;
    if snapshot.peers.is_empty() {
        writeln!(out, "  (No active WireGuard peers detected)")?;
    } else {
        for p in &snapshot.peers {
            let rtt = p
                .rtt_ms
                .map(|r| format!("{:.0}ms", r))
                .unwrap_or_else(|| "-".to_string());
            let traffic = format!(
                "{} / {}",
                format_bytes(p.bytes_sent),
                format_bytes(p.bytes_recv)
            );
            let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
            writeln!(
                out,
                "  {:<16} {:<16} {:<18} {:<8} {:<18} {}",
                sanitize_tui_string(&p.callsign),
                short_id,
                sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
                rtt,
                traffic,
                p.status
            )?;
        }
    }

    writeln!(
        out,
        "\n[RECENT AUDIT & ACCESS LOGS] ({} events)",
        snapshot.audit_events.len()
    )?;
    if snapshot.audit_events.is_empty() {
        writeln!(out, "  (No audit or error events recorded)")?;
    } else {
        for a in snapshot.audit_events.iter().take(8) {
            writeln!(
                out,
                "  [{}] [{:<8}] [{:<6}] {}",
                a.timestamp,
                sanitize_tui_string(&a.source),
                a.severity,
                sanitize_tui_string(&a.message)
            )?;
        }
    }

    if !snapshot.detected_crashes.is_empty() {
        writeln!(out, "\n[CRASH DETECTOR ALERTS]")?;
        for c in &snapshot.detected_crashes {
            writeln!(out, "  ✖ {}", sanitize_tui_string(c))?;
        }
    }

    writeln!(
        out,
        "\n Controls: [Tab] Panel [j/k] Select [s] Start/Stop [l] Lease [x] Lock [f] Auto-Fix [r] Refresh [q] Quit"
    )?;
    writeln!(
        out,
        "════════════════════════════════════════════════════════════════════════════════════════════════════════"
    )?;
    Ok(())
}

// ==============================================================================
// 5. INTERACTIVE RATATUI TUI RENDERING
// ==============================================================================

fn render_header(f: &mut Frame, snap: &CockpitSnapshot, area: Rect) {
    let swarm_color =
        if snap.swarm_status.contains("ACTIVE") || snap.swarm_status.contains("ONLINE") {
            Color::Green
        } else {
            Color::Yellow
        };
    let lease_color = if snap.lease_status.contains("AKTIV") {
        Color::Green
    } else {
        Color::Red
    };

    let mut header_spans = vec![
        Span::styled(
            " Callsign: ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<14} ", sanitize_tui_string(&snap.callsign)),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Swarm: ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<16} ", snap.swarm_status),
            Style::default()
                .fg(swarm_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("UTC: ", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("{:<20} ", snap.utc_time),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled("RAM Lease: ", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("{} ({})", snap.lease_status, snap.lease_remaining),
            Style::default()
                .fg(lease_color)
                .add_modifier(Modifier::BOLD),
        ),
    ];

    if snap.pending_quorum > 0 {
        header_spans.push(Span::styled(
            format!(" | [!] {} QUORUM PENDING", snap.pending_quorum),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let line = Line::from(header_spans);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" SKULLS & BONES // SOVEREIGN OPERATOR COCKPIT & FLEET HUD ")
        .title_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    let p = Paragraph::new(line).block(block);
    f.render_widget(p, area);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CockpitFocusPanel {
    Daemons,
    Peers,
    Audit,
}

impl CockpitFocusPanel {
    fn next(self) -> Self {
        match self {
            CockpitFocusPanel::Daemons => CockpitFocusPanel::Peers,
            CockpitFocusPanel::Peers => CockpitFocusPanel::Audit,
            CockpitFocusPanel::Audit => CockpitFocusPanel::Daemons,
        }
    }
}

fn render_daemons_panel(
    f: &mut Frame,
    snap: &CockpitSnapshot,
    area: Rect,
    selected: usize,
    focused: bool,
) {
    let rows: Vec<Row> = snap
        .daemons
        .iter()
        .enumerate()
        .map(|(idx, d)| {
            let (badge, color) = d.status.badge();
            let rtt_str = d
                .latency_ms
                .map(|m| format!("{}ms", m))
                .unwrap_or_else(|| "-".to_string());
            let base_style = if focused && idx == selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                match d.status {
                    HealthStatus::Online => Style::default().fg(Color::White),
                    HealthStatus::Degraded => Style::default().fg(color),
                    HealthStatus::Offline => Style::default().fg(Color::DarkGray),
                }
            };
            Row::new(vec![
                d.name.to_string(),
                badge.to_string(),
                d.port_info.to_string(),
                rtt_str,
                sanitize_tui_string(&d.details),
            ])
            .style(base_style)
        })
        .collect();

    let border_color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(10), // DAEMON
            Constraint::Length(12), // STATUS
            Constraint::Length(16), // PORT
            Constraint::Length(7),  // RTT
            Constraint::Min(10),    // DETAILS
        ],
    )
    .header(
        Row::new(vec![
            "DAEMON",
            "STATUS",
            "PORT / ROLE",
            "RTT",
            "RUNTIME DETAILS",
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(" [TOP-LEFT: ACTIVE DAEMONS & LIVE HEALTH] ")
            .title_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
    );

    f.render_widget(table, area);
}

/**
 * Renders the WireGuard mesh peers table in the cockpit HUD.
 *
 * SECURITY AUDIT:
 * - Dynamic Threat Vector: Untrusted peer metadata (node_id with multi-byte unicode or ANSI escape codes)
 *   could cause slice panics (CWE-248) or terminal escape injection (CWE-150 / CWE-116).
 * - CVE / CWE Mapping: CWE-150 / CWE-116 (Improper Output Neutralization), CWE-248 / CWE-754 / CWE-125 (UTF-8 char-boundary slicing panic).
 * - Likelihood & Exploitability: High (Score: 8/10) if an untrusted peer announces crafted metadata.
 * - Applied Mitigation: Neutralize ANSI escape sequences with sanitize_tui_string() and perform char-boundary-safe slicing via .chars().take(14).
 *
 * Conforms to ISO/IEC 10646 (Unicode UTF-8) and VT100 / ECMA-48 terminal control sequence handling.
 */
fn render_mesh_peers_panel(f: &mut Frame, snap: &CockpitSnapshot, area: Rect, selected: usize) {
    let rows: Vec<Row> = if snap.peers.is_empty() {
        vec![Row::new(vec![
            "(No WireGuard peers registered in mesh)".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ])
        .style(Style::default().fg(Color::DarkGray))]
    } else {
        snap.peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let style = if i == selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
                let rtt = p
                    .rtt_ms
                    .map(|r| format!("{:.0}ms", r))
                    .unwrap_or_else(|| "-".to_string());
                let traffic = format!(
                    "{} / {}",
                    format_bytes(p.bytes_sent),
                    format_bytes(p.bytes_recv)
                );
                let status_badge = if p.status == "ONLINE" {
                    "● ONLINE"
                } else if p.status == "STANDBY" {
                    "▲ STANDBY"
                } else {
                    "✖ OFFLINE"
                };

                Row::new(vec![
                    sanitize_tui_string(&p.callsign),
                    short_id,
                    sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
                    status_badge.to_string(),
                    rtt,
                    traffic,
                ])
                .style(style)
            })
            .collect()
    };

    let title = format!(" [TOP-RIGHT: WIREGUARD MESH PEERS ({})] ", snap.peers.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(14), // CALLSIGN
            Constraint::Length(15), // NODE ID
            Constraint::Length(15), // OVERLAY IP
            Constraint::Length(11), // STATUS
            Constraint::Length(7),  // RTT
            Constraint::Min(14),    // TX / RX
        ],
    )
    .header(
        Row::new(vec![
            "CALLSIGN",
            "NODE ID",
            "OVERLAY IP",
            "STATUS",
            "RTT",
            "TX / RX",
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
    );

    f.render_widget(table, area);
}

fn render_audit_panel(f: &mut Frame, snap: &CockpitSnapshot, area: Rect) {
    let has_crashes = !snap.detected_crashes.is_empty();
    let border_color = if has_crashes {
        Color::Red
    } else {
        Color::Green
    };

    let mut lines = Vec::new();
    if has_crashes {
        for c in snap.detected_crashes.iter().take(2) {
            lines.push(Line::from(vec![
                Span::styled(
                    "  🚨 CRASH DETECTED: ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    sanitize_tui_string(c),
                    Style::default()
                        .fg(Color::LightRed)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
    }

    if snap.audit_events.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (Keine Audit- oder Fehler-Ereignisse protokolliert)",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for ev in snap.audit_events.iter().take(6) {
            let sev_color = match ev.severity.to_uppercase().as_str() {
                s if s.contains("PANIC") || s.contains("CRASH") || s.contains("ERROR") => {
                    Color::Red
                }
                s if s.contains("WARN") => Color::Yellow,
                s if s.contains("OK") || s.contains("SUCCESS") => Color::Green,
                _ => Color::Cyan,
            };

            lines.push(Line::from(vec![
                Span::styled(
                    format!("  [{}] ", ev.timestamp),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("[{:<7}] ", sanitize_tui_string(&ev.source)),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{:<6}] ", ev.severity),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    sanitize_tui_string(&ev.message),
                    Style::default().fg(Color::White),
                ),
            ]));
        }
    }

    let title = format!(
        " [BOTTOM: RECENT AUDIT & ACCESS EVENTS ({})] ",
        snap.audit_events.len()
    );
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(title)
            .title_style(
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            ),
    );

    f.render_widget(p, area);
}

fn render_footer(f: &mut Frame, _snap: &CockpitSnapshot, area: Rect, toast_msg: Option<&str>) {
    let mut spans = vec![
        Span::styled(
            " [Tab] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Panel "),
        Span::styled(
            "[j/k] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Select "),
        Span::styled(
            "[s] ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Start/Stop "),
        Span::styled(
            "[l] ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Lease "),
        Span::styled(
            "[x] ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw("Lock "),
        Span::styled(
            "[f] ",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Auto-Fix "),
        Span::styled(
            "[r] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Refresh "),
        Span::styled(
            "[q] ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Quit"),
    ];

    if let Some(msg) = toast_msg {
        spans.push(Span::raw("  | "));
        spans.push(Span::styled(
            sanitize_tui_string(msg),
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let footer_text = Line::from(spans);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" INTERACTIVE OPERATOR CONTROLS ")
        .title_style(Style::default().fg(Color::DarkGray));

    let p = Paragraph::new(footer_text).block(block);
    f.render_widget(p, area);
}

fn ui(
    f: &mut Frame,
    snap: &CockpitSnapshot,
    focus: CockpitFocusPanel,
    selected_daemon: usize,
    selected_peer: usize,
    toast_msg: Option<&str>,
) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header: Callsign, Swarm Status, System Time, Lease
            Constraint::Percentage(55), // Middle Row: Daemons (Left) & WireGuard Peers (Right)
            Constraint::Min(8),    // Bottom Row: Recent Audit & Access Events
            Constraint::Length(3), // Footer: Shortcuts, Status & Controls
        ])
        .split(f.area());

    render_header(f, snap, main_layout[0]);

    let middle_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(42), // Top-Left: Active Daemons Status & Live Health
            Constraint::Percentage(58), // Top-Right: WireGuard Mesh Peers Table
        ])
        .split(main_layout[1]);

    render_daemons_panel(
        f,
        snap,
        middle_split[0],
        selected_daemon,
        focus == CockpitFocusPanel::Daemons,
    );
    render_mesh_peers_panel(f, snap, middle_split[1], selected_peer);
    render_audit_panel(f, snap, main_layout[2]);
    render_footer(f, snap, main_layout[3], toast_msg);
}

// ==============================================================================
// 6. MAIN COCKPIT RUNNER & EVENT LOOP
// ==============================================================================

/// Starts or stops a selected S&B core daemon non-blockingly from the interactive TUI.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Arbitrary command execution if untrusted daemon names are passed to a shell.
/// - CVE / CWE Mapping: CWE-78 (Improper Neutralization of Special Elements used in an OS Command).
/// - Likelihood & Exploitability: Low (1/10).
/// - Applied Mitigation: Strictly allowlists the 4 canonical S&B daemon binary names (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`) and invokes `std::process::Command` directly without `sh -c`.
fn toggle_selected_daemon(daemon: &DaemonHealth) -> String {
    let bin = match daemon.name.as_str() {
        "sb-node" | "sb-mesh" | "sb-proxy" | "sb-dns" => daemon.name.as_str(),
        _ => return format!("Unbekannter Daemon '{}'", daemon.name),
    };

    if daemon.status == HealthStatus::Online {
        if crate::commands::service::is_systemd_available() {
            let _ = std::process::Command::new("systemctl")
                .args(["stop", &format!("{}.service", bin)])
                .status();
        }
        crate::process_ledger::cmd_stop(Some(bin));
        format!("Daemon '{}' gestoppt", bin)
    } else {
        let _ = crate::commands::service::ensure_service_prerequisites();
        if crate::commands::service::is_systemd_available()
            && std::path::Path::new(&format!("/etc/systemd/system/{}.service", bin)).exists()
        {
            if std::process::Command::new("systemctl")
                .args(["restart", &format!("{}.service", bin)])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return format!("Daemon '{}' via systemd gestartet", bin);
            }
        }
        let mut cmd = std::process::Command::new(bin);
        match bin {
            "sb-node" => {
                cmd.args(["daemon", "--port", "58888"]);
            }
            "sb-mesh" => {
                cmd.args(["daemon", "--port", "51820"]);
            }
            "sb-proxy" => {
                cmd.args([
                    "start",
                    "--http-bind",
                    "127.0.0.1:58080",
                    "--bind",
                    "127.0.0.1:58443",
                ]);
            }
            "sb-dns" => {
                cmd.args(["serve", "--bind", "127.0.0.1:58853"]);
            }
            _ => {}
        }
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        match cmd.spawn() {
            Ok(child) => {
                sb_core::process::register_process(
                    bin,
                    child.id(),
                    None,
                    &format!("{} (cockpit)", bin),
                );
                format!("Daemon '{}' gestartet (PID {})", bin, child.id())
            }
            Err(e) => format!("Start von '{}' fehlgeschlagen: {}", bin, e),
        }
    }
}

/// Interactive UI event loop
fn run_interactive_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    snapshot_state: &Arc<RwLock<CockpitSnapshot>>,
) -> io::Result<()> {
    let mut focus = CockpitFocusPanel::Daemons;
    let mut selected_daemon = 0usize;
    let mut selected_peer = 0usize;
    let mut last_toast: Option<String> = None;

    loop {
        // Read current snapshot from RAM (fast read, < 0.1ms)
        let snap = {
            let lock = snapshot_state.read().unwrap();
            lock.clone()
        };

        terminal.draw(|f| {
            ui(
                f,
                &snap,
                focus,
                selected_daemon,
                selected_peer,
                last_toast.as_deref(),
            )
        })?;

        // 50ms non-blocking poll for responsive keystrokes
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(());
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Tab => {
                        focus = focus.next();
                    }
                    KeyCode::Char('r') => {
                        let fresh = CockpitSnapshot::collect();
                        if let Ok(mut lock) = snapshot_state.write() {
                            *lock = fresh;
                        }
                        last_toast = Some("HUD aktualisiert".to_string());
                    }
                    KeyCode::Char('l') => {
                        let shared_id = crate::meta::SovereignIdentity::load_or_create();
                        if sb_key::inspect_identity(None).is_err() {
                            let _ = sb_key::init_identity(Some(shared_id.callsign), None, false);
                        }
                        match sb_key::mint_lease(None, 8) {
                            Ok(lease) => {
                                last_toast =
                                    Some(format!("8h RAM-Lease geprägt ({})", lease.lease_id));
                            }
                            Err(e) => {
                                last_toast = Some(format!("Lease-Fehler: {}", e));
                            }
                        }
                        let fresh = CockpitSnapshot::collect();
                        if let Ok(mut lock) = snapshot_state.write() {
                            *lock = fresh;
                        }
                    }
                    KeyCode::Char('x') => {
                        match sb_key::lock_lease() {
                            Ok(()) => {
                                last_toast =
                                    Some("RAM-Lease gesperrt & vernichtet (zeroize)".to_string());
                            }
                            Err(e) => {
                                last_toast = Some(format!("Lock-Fehler: {}", e));
                            }
                        }
                        let fresh = CockpitSnapshot::collect();
                        if let Ok(mut lock) = snapshot_state.write() {
                            *lock = fresh;
                        }
                    }
                    KeyCode::Char('f') => {
                        let shared_id = crate::meta::SovereignIdentity::load_or_create();
                        if sb_key::inspect_identity(None).is_err() {
                            let _ = sb_key::init_identity(Some(shared_id.callsign), None, false);
                        }
                        let _ = sb_ca::init_all(false);
                        if sb_key::get_lease_status().is_none() {
                            let _ = sb_key::mint_lease(None, 8);
                        }
                        let fresh = CockpitSnapshot::collect();
                        if let Ok(mut lock) = snapshot_state.write() {
                            *lock = fresh;
                        }
                        last_toast =
                            Some("Auto-Fix (Identity + Dual-CA + 8h Lease) ausgeführt".to_string());
                    }
                    KeyCode::Char('s') => {
                        if let Some(d) = snap.daemons.get(selected_daemon) {
                            let msg = toggle_selected_daemon(d);
                            last_toast = Some(msg);
                            let fresh = CockpitSnapshot::collect();
                            if let Ok(mut lock) = snapshot_state.write() {
                                *lock = fresh;
                            }
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => match focus {
                        CockpitFocusPanel::Daemons => {
                            if selected_daemon > 0 {
                                selected_daemon -= 1;
                            }
                        }
                        CockpitFocusPanel::Peers | CockpitFocusPanel::Audit => {
                            if selected_peer > 0 {
                                selected_peer -= 1;
                            }
                        }
                    },
                    KeyCode::Down | KeyCode::Char('j') => match focus {
                        CockpitFocusPanel::Daemons => {
                            if !snap.daemons.is_empty() && selected_daemon + 1 < snap.daemons.len()
                            {
                                selected_daemon += 1;
                            }
                        }
                        CockpitFocusPanel::Peers | CockpitFocusPanel::Audit => {
                            if !snap.peers.is_empty() && selected_peer + 1 < snap.peers.len() {
                                selected_peer += 1;
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}

/**
 * Primary entry point for `sb cockpit` and `sb hud`.
 *
 * Supports both interactive terminal mode (Ratatui TUI) and headless snapshot mode (`--snapshot`).
 */
pub fn run_cockpit(
    snapshot: bool,
    poll_interval_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let poll_interval = Duration::from_millis(poll_interval_ms.max(100));

    // 1. Initial snapshot collection
    let initial_snapshot = CockpitSnapshot::collect();

    if snapshot {
        // Headless snapshot mode: dump to stdout and exit with code 0 without terminal initialization
        let mut stdout = std::io::stdout();
        render_snapshot(&initial_snapshot, &mut stdout)?;
        return Ok(());
    }

    // 2. Interactive TUI Mode:
    // Install panic hook for terminal state safety (CWE-754)
    setup_terminal_panic_hook();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        crossterm::cursor::Hide
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Shared thread-safe snapshot
    let snapshot_state = Arc::new(RwLock::new(initial_snapshot));
    let running = Arc::new(AtomicBool::new(true));

    // Spawn background poller decoupled from UI event loop (CWE-400)
    let poller_snapshot = Arc::clone(&snapshot_state);
    let poller_running = Arc::clone(&running);
    let poller_handle = std::thread::Builder::new()
        .name("cockpit-telemetry-poller".to_string())
        .spawn(move || {
            while poller_running.load(Ordering::Relaxed) {
                std::thread::sleep(poll_interval);
                if !poller_running.load(Ordering::Relaxed) {
                    break;
                }
                let fresh = CockpitSnapshot::collect();
                if let Ok(mut lock) = poller_snapshot.write() {
                    *lock = fresh;
                }
            }
        })?;

    // Run interactive event loop
    let res = run_interactive_loop(&mut terminal, &snapshot_state);

    // Stop background poller
    running.store(false, Ordering::Relaxed);
    let _ = poller_handle.join();

    // Teardown terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        crossterm::cursor::Show
    )?;

    res.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

// ==============================================================================
// 7. BACKWARDS COMPATIBILITY WRAPPER (COCKPIT APP)
// ==============================================================================

#[allow(dead_code)]
pub struct CockpitApp {
    pub selected_tab: usize,
    pub status_message: String,
    pub snapshot: CockpitSnapshot,
    pub last_refresh: Instant,
}

#[allow(dead_code)]
impl CockpitApp {
    pub fn new() -> Self {
        Self {
            selected_tab: 0,
            status_message: "Bereit. [q] Beenden, [r] Aktualisieren, [↑/↓] Peer wählen".to_string(),
            snapshot: CockpitSnapshot::collect(),
            last_refresh: Instant::now(),
        }
    }

    pub fn reload_data(&mut self) {
        self.snapshot = CockpitSnapshot::collect();
        self.last_refresh = Instant::now();
        self.status_message = "Daten aktualisiert.".to_string();
    }
}

impl Default for CockpitApp {
    fn default() -> Self {
        Self::new()
    }
}

// ==============================================================================
// 8. UNIT TESTS
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cockpit_app_initialization() {
        let app = CockpitApp::new();
        assert_eq!(app.selected_tab, 0);
        assert!(!app.status_message.is_empty());
        assert!(!app.snapshot.daemons.is_empty());
    }

    #[test]
    fn test_cockpit_tab_switching() {
        let mut app = CockpitApp::new();
        app.selected_tab = 1;
        assert_eq!(app.selected_tab, 1);
        app.selected_tab = (app.selected_tab + 1) % 5;
        assert_eq!(app.selected_tab, 2);
        app.selected_tab = 4;
        app.selected_tab = (app.selected_tab + 1) % 5;
        assert_eq!(app.selected_tab, 0);
    }

    #[test]
    fn test_sanitize_tui_string_csi_escape() {
        let dirty = "\x1b[31;1mRED_ALERT\x1b[0m";
        let clean = sanitize_tui_string(dirty);
        assert_eq!(clean, "RED_ALERT");
    }

    #[test]
    fn test_sanitize_tui_string_osc_escape() {
        let dirty = "\x1b]0;Evil Window Title\x07CleanPeerName";
        let clean = sanitize_tui_string(dirty);
        assert_eq!(clean, "CleanPeerName");

        let dirty2 = "\x1b]0;Title\x1b\\AnotherPeer";
        let clean2 = sanitize_tui_string(dirty2);
        assert_eq!(clean2, "AnotherPeer");
    }

    #[test]
    fn test_sanitize_tui_string_control_characters() {
        let dirty = "callsign\x00\x01\x08malicious\x7f\u{0080}\u{009f}";
        let clean = sanitize_tui_string(dirty);
        assert_eq!(clean, "callsignmalicious");

        // Tab converts to space, newline is preserved
        let formatted = "item1\titem2\nitem3";
        let clean_fmt = sanitize_tui_string(formatted);
        assert_eq!(clean_fmt, "item1 item2\nitem3");
    }

    #[test]
    fn test_sanitize_tui_string_preserves_valid_unicode() {
        let valid = "srv-prod-01 (145.223.83.235) — Öresund 🚀";
        let clean = sanitize_tui_string(valid);
        assert_eq!(clean, valid);
    }

    #[test]
    fn test_health_status_badges() {
        let online = HealthStatus::Online;
        let degraded = HealthStatus::Degraded;
        let offline = HealthStatus::Offline;

        assert_eq!(online.text_badge(), "[ONLINE]");
        assert_eq!(degraded.text_badge(), "[DEGRADED]");
        assert_eq!(offline.text_badge(), "[OFFLINE]");

        let (b_on, c_on) = online.badge();
        assert_eq!(b_on, "● ONLINE");
        assert_eq!(c_on, Color::Green);

        let (b_deg, c_deg) = degraded.badge();
        assert_eq!(b_deg, "▲ DEGRADED");
        assert_eq!(c_deg, Color::Yellow);

        let (b_off, c_off) = offline.badge();
        assert_eq!(b_off, "✖ OFFLINE");
        assert_eq!(c_off, Color::Red);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_render_snapshot_output() {
        let snapshot = CockpitSnapshot {
            callsign: "test-node-01".to_string(),
            swarm_status: "ONLINE (WireGuard)".to_string(),
            utc_time: "2026-10-28 02:00:00 UTC".to_string(),
            lease_status: "AKTIV (RAM)".to_string(),
            lease_remaining: "07h 45m 12s".to_string(),
            daemons: vec![
                DaemonHealth {
                    name: "sb-node".to_string(),
                    role: "Server Agent".to_string(),
                    port_info: "UDP 58888".to_string(),
                    status: HealthStatus::Online,
                    latency_ms: Some(1),
                    details: "Ready".to_string(),
                },
                DaemonHealth {
                    name: "sb-mesh".to_string(),
                    role: "WireGuard Mesh".to_string(),
                    port_info: "TCP 58890".to_string(),
                    status: HealthStatus::Online,
                    latency_ms: Some(2),
                    details: "Peers: 1".to_string(),
                },
            ],
            peers: vec![PeerSummaryPayload {
                callsign: "peer-remote".to_string(),
                node_id: "sbm-14522383235".to_string(),
                public_key_base64: "AAAAC3...".to_string(),
                endpoint: Some("145.223.83.235:51820".to_string()),
                overlay_ip: Some("10.240.0.1".to_string()),
                status: "ONLINE".to_string(),
                rtt_ms: Some(15.0),
                bytes_sent: 1048576,
                bytes_recv: 524288,
                zk_attested: true,
            }],
            audit_events: vec![AuditEvent {
                timestamp: "2026-10-28 01:55:00 UTC".to_string(),
                source: "AUDIT".to_string(),
                severity: "INFO".to_string(),
                message: "Test audit record".to_string(),
            }],
            detected_crashes: vec![],
            pending_quorum: 0,
        };

        let mut buf = Vec::new();
        render_snapshot(&snapshot, &mut buf).expect("render_snapshot failed");
        let output = String::from_utf8(buf).expect("UTF-8 decoding failed");

        assert!(output.contains("SKULLS & BONES // FLEET COCKPIT HUD [SNAPSHOT]"));
        assert!(output.contains("test-node-01"));
        assert!(output.contains("ONLINE (WireGuard)"));
        assert!(output.contains("AKTIV (RAM)"));
        assert!(output.contains("[ACTIVE DAEMONS & LIVE HEALTH]"));
        assert!(output.contains("sb-node"));
        assert!(output.contains("[ONLINE]"));
        assert!(output.contains("[WIREGUARD MESH PEERS]"));
        assert!(output.contains("peer-remote"));
        assert!(output.contains("10.240.0.1"));
        assert!(output.contains("15ms"));
        assert!(output.contains("[RECENT AUDIT & ACCESS LOGS]"));
        assert!(output.contains("Test audit record"));
    }

    #[test]
    fn test_cockpit_snapshot_collection_structure() {
        let snapshot = CockpitSnapshot::collect();
        assert!(!snapshot.callsign.is_empty());
        assert!(!snapshot.utc_time.is_empty());
        assert_eq!(snapshot.daemons.len(), 4);
        assert_eq!(snapshot.daemons[0].name, "sb-node");
        assert_eq!(snapshot.daemons[1].name, "sb-mesh");
        assert_eq!(snapshot.daemons[2].name, "sb-proxy");
        assert_eq!(snapshot.daemons[3].name, "sb-dns");
    }

    #[test]
    fn test_adversarial_ansi_sanitization_comprehensive() {
        // 1. CSI complex color, style, and attribute injection
        let csi_payload = "\x1b[38;2;255;0;0;1;4mINJECTED_RED\x1b[0m";
        assert_eq!(sanitize_tui_string(csi_payload), "INJECTED_RED");

        // 2. CSI terminal control, cursor repositioning and clear screen
        let csi_control = "\x1b[2J\x1b[H\x1b[10;10H\x1b[?25lCLEAR_AND_HIDE\x1b[?25h";
        assert_eq!(sanitize_tui_string(csi_control), "CLEAR_AND_HIDE");

        // 3. CSI Device Status Report & Private modes
        let csi_dsr = "\x1b[5n\x1b[6nSTATUS_PROBE";
        assert_eq!(sanitize_tui_string(csi_dsr), "STATUS_PROBE");

        // 4. OSC Window title hijacking (both BEL and ST terminators)
        let osc_bel = "\x1b]0;MALICIOUS_TITLE\x07PeerCallsign";
        assert_eq!(sanitize_tui_string(osc_bel), "PeerCallsign");
        let osc_st = "\x1b]2;MALICIOUS_TITLE\x1b\\PeerCallsign";
        assert_eq!(sanitize_tui_string(osc_st), "PeerCallsign");

        // 5. OSC 52 Clipboard injection attack
        let osc_clip = "\x1b]52;c;d2hvYW1p\x07SafeDisplay";
        assert_eq!(sanitize_tui_string(osc_clip), "SafeDisplay");

        // 6. OSC 8 Hyperlink injection attack
        let osc_link = "\x1b]8;;http://evil.com/phish\x1b\\PhishText\x1b]8;;\x1b\\";
        assert_eq!(sanitize_tui_string(osc_link), "PhishText");

        // 7. Truncated and unterminated escape sequences
        assert_eq!(sanitize_tui_string("trailing\x1b"), "trailing");
        assert_eq!(sanitize_tui_string("trailing_csi\x1b["), "trailing_csi");
        assert_eq!(
            sanitize_tui_string("trailing_osc\x1b]0;never_ends"),
            "trailing_osc"
        );
        assert_eq!(sanitize_tui_string("\x1b\x1b\x1b"), "");

        // 8. C0 control character suite (0x00 to 0x1F)
        let mut c0_all = String::new();
        for b in 0u8..=0x1F {
            c0_all.push(b as char);
        }
        let sanitized_c0 = sanitize_tui_string(&c0_all);
        assert_eq!(sanitized_c0, " \n"); // Only tab (space) and newline preserved

        // 9. C1 control characters (0x80..=0x9F) and DEL (0x7F)
        let c1_chars: String = (0x7Fu8..=0x9Fu8).map(|b| b as char).collect();
        assert_eq!(sanitize_tui_string(&c1_chars), "");

        // 10. Valid Unicode preservation (Emojis, German Umlauts, accented characters, CJK)
        let rich_unicode = "Node-01 — Übergrößen-Server mit S&B 🛡️ & 🚀 in München, Köln & Zürich (日本語 / Русский)";
        assert_eq!(sanitize_tui_string(rich_unicode), rich_unicode);
    }

    #[test]
    fn test_adversarial_socket_probe_timeouts() {
        // Connect to a blackhole or unresponsive listener with 150ms timeout
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let sock_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        let start = Instant::now();
        let stream = TcpStream::connect_timeout(&sock_addr, Duration::from_millis(150));
        let elapsed = start.elapsed();

        assert!(stream.is_ok());
        // Verify timeout parameter behaves as expected and socket probes return promptly
        assert!(elapsed < Duration::from_millis(200));

        // Connect to unallocated port
        let dead_addr: SocketAddr = "127.0.0.1:59998".parse().unwrap();
        let start_dead = Instant::now();
        let _ = TcpStream::connect_timeout(&dead_addr, Duration::from_millis(150));
        let elapsed_dead = start_dead.elapsed();
        // Operating system RST or timeout must be <= 300ms
        assert!(elapsed_dead < Duration::from_millis(300));
    }

    #[test]
    fn test_panic_hook_registration_safety() {
        // Calling setup_terminal_panic_hook should not panic or fail
        setup_terminal_panic_hook();
        // Calling it a second time should also safely chain
        setup_terminal_panic_hook();
    }

    #[test]
    fn test_peer_node_id_utf8_char_boundary_slicing_reproduction() {
        // Empirical verification: peer node_id with multi-byte unicode and ANSI escape sequences
        // must be safely sanitized and sliced along char boundaries without panic.
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let malicious_peer = PeerSummaryPayload {
                callsign: "\x1b[31;1madversary\x1b[0m".to_string(),
                // 's','b','m','-' (4 bytes) + 'ö','ä','ü','ß' (8 bytes = 12 total) + '🦀' (4 bytes: 12..16) + 'f','o','o'
                // Byte 14 is inside '🦀' (bytes 12..16)
                node_id: "\x1b[32msbm-öäüß🦀foo\x1b[0m".to_string(),
                public_key_base64: "AAAAC3NzaC...".to_string(),
                endpoint: None,
                overlay_ip: Some("\x1b]0;hacked\x0710.42.0.99".to_string()),
                status: "ONLINE".to_string(),
                rtt_ms: None,
                bytes_sent: 0,
                bytes_recv: 0,
                zk_attested: false,
            };

            let snapshot = CockpitSnapshot {
                callsign: "test".to_string(),
                swarm_status: "TEST".to_string(),
                utc_time: "2026-10-28".to_string(),
                lease_status: "TEST".to_string(),
                lease_remaining: "TEST".to_string(),
                daemons: vec![],
                peers: vec![malicious_peer],
                audit_events: vec![],
                detected_crashes: vec![],
                pending_quorum: 0,
            };

            let mut out = Vec::new();
            let res = render_snapshot(&snapshot, &mut out);
            assert!(res.is_ok(), "render_snapshot should return Ok(())");
            let out_str = String::from_utf8(out).expect("valid utf8 output");
            // Injected ANSI sequences must be stripped
            assert!(!out_str.contains("\x1b["));
            assert!(!out_str.contains("\x1b]"));
            assert!(!out_str.contains("hacked"));
            // Sanitized components must appear intact
            assert!(out_str.contains("adversary"));
            assert!(out_str.contains("10.42.0.99"));
            // Short id should be 12 unicode chars of sanitized "sbm-öäüß🦀foo"
            assert!(out_str.contains("sbm-öäüß🦀foo"));

            // Also verify Ratatui TUI panel rendering does not panic with multi-byte UTF-8
            let backend = ratatui::backend::TestBackend::new(120, 30);
            let mut terminal = ratatui::Terminal::new(backend).unwrap();
            let draw_res = terminal.draw(|f| {
                render_mesh_peers_panel(f, &snapshot, f.area(), 0);
            });
            assert!(
                draw_res.is_ok(),
                "TUI render_mesh_peers_panel should draw without panic"
            );
        }));

        assert!(
            panic_result.is_ok(),
            "render_snapshot and render_mesh_peers_panel must succeed without panic on UTF-8 node_id slicing and ANSI strings"
        );
    }
}
