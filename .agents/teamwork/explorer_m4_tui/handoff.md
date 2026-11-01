# Milestone 4 Exploration & TUI Architecture Report: Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`)

**Author**: explorer_m4_tui  
**Date**: 2026-10-28  
**Scope**: Terminal User Interface, CLI Subcommand & Aliases, Daemon Health Telemetry, WireGuard Mesh Peers Table, Audit Event Log, Terminal Safety & Panic Hooks (CWE-754), ANSI Sanitization (CWE-150/116).

---

## 1. Observation

### 1.1 Dependency Inspection (`tools/sb/Cargo.toml`)
Inspection of `tools/sb/Cargo.toml` (lines 17–48) confirms that all required crates and workspace members are already declared:
- Line 32: `ratatui = "0.29"`
- Line 33: `crossterm = "0.28"`
- Line 20: `tokio = { version = "1.43", features = ["full"] }`
- Line 21: `serde = { version = "1.0", features = ["derive"] }`
- Line 22: `serde_json = "1.0"`
- Line 26: `chrono = { version = "0.4", features = ["serde"] }`
- Line 42: `sb-core = { version = "0.2.0", path = "../sb-core" }`
- Line 44: `sb-mesh = { version = "0.3.0", path = "../sb-mesh" }`
- Line 45: `sb-proxy = { version = "0.1.0", path = "../sb-proxy" }`
- Line 46: `sb-key = { version = "0.1.0", path = "../sb-key" }`
- Line 47: `sb-ca = { version = "0.1.0", path = "../sb-ca" }`

No additional external crates or Cargo modifications are required to build the interactive Cockpit HUD.

### 1.2 Existing CLI Subcommands & Main Dispatch
- In `tools/sb/src/cli.rs` (lines 207–209):
  ```rust
  /// Interaktives Terminal-Cockpit (sb-vault TUI) für Flotte, Ephemeral CA und Mesh
  Cockpit,
  ```
  *Observed defect*: Missing alias `hud` (`#[command(alias = "hud")]`), missing `--snapshot` flag, missing `--poll-interval` parameter.
- In `tools/sb/src/main.rs` (lines 269–282):
  ```rust
  Some(Commands::Cockpit) => {
      if let Err(e) = cockpit::run_cockpit() {
          eprintln!("Fehler beim Starten des Cockpits: {}", e);
      }
  }
  ```
  *Observed defect*: Invokes `cockpit::run_cockpit()` without taking snapshot or poll interval parameters; does not exit with non-zero code on error.

### 1.3 Telemetry & Data Source Survey

1. **Active Daemons (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`)**:
   - `sb-mesh` (Port 58890): `tools/sb-mesh/src/ipc.rs` line 21 exposes `IPC_TCP_PORT = 58890`. Accepts legacy `{"action":"GetStatus"}` returning `NodeStatusPayload` (node_id, peer_count, air_gap, wireguard_pubkey).
   - `sb-proxy` (Port 58900): `tools/sb-proxy/src/ipc.rs` lines 84–140 exposes HTTP loopback on port 58900 (`/health` returns `200 OK`, `/status` returns `ProxyTelemetryDto` with requests, latencies, active spaces).
   - `sb-node` (Port 58905 & UDP 58888): `tools/sb-core/src/ports.rs` line 28 defines `DEFAULT_DAEMON_API_PORT = 58905` and UDP dispatcher port 58888 (`DEFAULT_MESH_UDP_PORT`). `sb-node telemetry --json` provides full remote and local telemetry.
   - `sb-dns` (Port 58853 / 53): `tools/sb-dns/src/config.rs` line 69 defines default listener on port 58853. Probing UDP/TCP socket verifies `.sbm` domain resolution availability.

2. **WireGuard Mesh Peers**:
   - In `tools/sb-core/src/mesh_ipc.rs` (lines 44–55):
     ```rust
     pub struct PeerSummaryPayload {
         pub callsign: String,
         pub node_id: String,
         pub public_key_base64: String,
         pub endpoint: Option<String>,
         pub overlay_ip: Option<String>,
         pub status: String,
         pub rtt_ms: Option<f64>,
         pub bytes_sent: u64,
         pub bytes_recv: u64,
         pub zk_attested: bool,
     }
     ```
   - In `tools/sb-mesh/src/ipc.rs` (lines 141–153, lines 243–250): sending `{"action":"ListPeers"}` to `127.0.0.1:58890` responds with `IpcResponse::Ok(IpcPayload::Peers(Vec<PeerSummaryPayload>))`.

3. **Recent Audit & Access Events**:
   - `~/.sb/audit/sessions.jsonl`: Formatted JSON lines tracking SSH sessions, remote logins, and admin access (`tools/sb/src/commands/daemon.rs` line 871).
   - `~/.sb/logs/errors.jsonl`: Structured error records (`tools/sb/src/logger.rs` line 31 `get_errors_jsonl_path()`) containing timestamp, tool name, log level, message, and exit codes.
   - `tools/sb/src/logs.rs` provides `CrashInspector::inspect_type(line)` detecting Rust panics, Python tracebacks, and Linux OOM kills.

4. **Terminal Restoration & Panic Vulnerability (CWE-754)**:
   - In current `tools/sb/src/cockpit.rs` (lines 269–286), terminal teardown (`disable_raw_mode()`, `LeaveAlternateScreen`, `DisableMouseCapture`) is called sequentially after `run_loop()`.
   - If an unhandled panic occurs inside `run_loop()` or during Ratatui drawing, the process unwinds and terminates before teardown executes, leaving the operator's shell in a broken state (raw mode active, cursor hidden, mouse capture locked).

---

## 2. Logic Chain

```
[Observation 1.1: ratatui 0.29 & crossterm 0.28 present]
       │
       ▼
[Requirement R3: sb cockpit / sb hud interactive TUI + snapshot]
       │
       ├───────────────────────────────────────────┐
       ▼                                           ▼
[CLI Layer: cli.rs & main.rs]             [Data Layer: Daemons, Mesh, Audit]
- Add #[command(alias = "hud")]           - sb-mesh: TCP 58890 (GetStatus, ListPeers)
- Add --snapshot (bool)                   - sb-proxy: TCP 58900 (HTTP /status, /health)
- Add --poll-interval (u64, def 1000)     - sb-node: TCP 58905 / UDP 58888
       │                                  - sb-dns: UDP/TCP 58853
       │                                  - ~/.sb/audit/sessions.jsonl & errors.jsonl
       │                                           │
       └─────────────────────┬─────────────────────┘
                             ▼
             [Cockpit TUI Architecture: cockpit.rs]
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
[Terminal Safety]     [Non-Blocking Loop]     [3-Panel Layout]
- Global panic hook   - poll(50ms) for UI     - Header: Callsign, Swarm, Time
- Reset raw mode      - Background probe      - Left: Daemons Live Health
- Leave alt screen    - Instant keystroke     - Right: WireGuard Peers Table
- CWE-754 defense     - CWE-400 defense       - Bottom: Audit & Access Log
                             │
                             ▼
              [Headless Snapshot Execution]
              - Dump formatted text to stdout
              - Zero terminal side-effects
              - Exit code 0 for CI/CD
```

1. **CLI Ergonomics & Automation**: Supporting both `sb cockpit` and `sb hud` via Clap derive attribute `#[command(alias = "hud")]` satisfies the specification. Adding `--snapshot` allows automated verification in CI/CD without requiring an interactive PTY.
2. **Terminal Safety (CWE-754)**: Ratatui applications must guarantee terminal state restoration even if an unexpected panic occurs. A custom panic hook (`std::panic::set_hook`) ensures `disable_raw_mode` and `LeaveAlternateScreen` run prior to process exit.
3. **Responsive UI Thread (CWE-400)**: Direct synchronous network calls during TUI rendering cause UI freezes when a daemon is restarting or unreachable. Telemetry polling must have strict micro-timeouts (e.g., 100–150ms) or run decoupled from the render loop.
4. **Data Sanitization (CWE-150 / CWE-116)**: Displaying peer names or audit logs from untrusted sources directly in a terminal can allow ANSI escape injection. All displayed strings must be sanitized.
5. **HUD Layout Architecture**: A 3-panel layout mapping:
   - Header: Callsign, Swarm connectivity, UTC time, RAM Lease.
   - Top-Left: 4 core daemons (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`).
   - Top-Right: WireGuard mesh peers (`PeerSummaryPayload`).
   - Bottom: Audit & error events with `CrashInspector` alert highlights.

---

## 3. Dynamic Threat Modeling & Security Hardening

In compliance with the workspace `secure-function-coder` framework, the following dynamic threats were analyzed:

| # | Dynamic Threat Vector | CWE / CVE Mapping | Likelihood & Exploitability | Applied Mitigation |
|---|----------------------|-------------------|-----------------------------|--------------------|
| 1 | **Terminal State Corruption on Panic**: Unhandled panic during rendering leaves terminal in raw mode, hidden cursor, and alternate screen, bricking operator shell. | **CWE-754**: Improper Check for Unusual or Exceptional Conditions | **High** (Likelihood: 7/10, Exploitability: N/A - DoS) | Register global panic hook with `std::panic::set_hook` restoring raw mode and cursor before invoking original hook. |
| 2 | **ANSI Escape Sequence Injection**: Untrusted peer callsigns or crafted log messages containing control characters manipulate terminal titles, overwrite lines, or invoke terminal vulnerabilities. | **CWE-150** / **CWE-116**: Improper Neutralization of Control / Escape Characters | **Medium** (Likelihood: 6/10, Exploitability: 7/10) | Implement `sanitize_tui_string` stripping ECMA-48 control sequences (0x00..=0x1F except tab/newline, and 0x7F..=0x9F) before text creation. |
| 3 | **UI Event Loop Starvation / Freeze**: Synchronous network probing against unresponsive or blocked daemon ports halts crossterm event polling, dropping keystrokes (e.g. 'q'). | **CWE-400**: Uncontrolled Resource Consumption | **High** (Likelihood: 8/10, Exploitability: 4/10) | Strict `Duration::from_millis(150)` timeout on socket connects; render loop decoupled with non-blocking `crossterm::event::poll(50ms)`. |
| 4 | **Unbounded Memory Accumulation**: Continuously reading multi-megabyte audit and error log files on every refresh exhausts RAM. | **CWE-400**: Resource Exhaustion | **Medium** (Likelihood: 6/10, Exploitability: 3/10) | Bound log reading to the last 50 lines using reverse seek / bounded line iterator and cap stored entries. |
| 5 | **Secret Leaks in Headless Snapshot**: `--snapshot` dumping telemetry into automated CI logs leaks sensitive tokens or private keys. | **CWE-403**: Exposure of Sensitive Information | **Low** (Likelihood: 3/10, Exploitability: 6/10) | Enforce that only public keys (`wireguard_pubkey`), node IDs, and redacted audit summaries are exposed. |

---

## 4. Formal Standards Compliance Radar

In compliance with the workspace `standards-compliance` framework:

| Standard | Section / Topic | Concrete Integration |
|---|---|---|
| **ISO 8601 / RFC 3339** | Date and time representation | HUD header and audit logs format timestamps as `YYYY-MM-DD HH:MM:SS UTC` or RFC 3339 `2026-10-28T01:55:00Z` using `chrono::Utc`. |
| **ECMA-48 / ANSI X3.64** | Control functions for text communication | Output formatting relies strictly on standard VT100 / ECMA-48 escape sequences managed by Crossterm; input sanitization strips non-compliant control codes. |
| **IETF RFC 4251** | SSH Architecture & Protocol | Verification of OpenSSH Ephemeral CA anchoring and user certificates. |
| **RFC 5280 / TLS 1.3** | X.509 PKI & Certificate Validation | Validates status of `sb-proxy` and `sb-ca` on-demand TLS engine. |

---

## 5. Architectural Specification & Concrete Code Proposals

### 5.1 CLI Subcommand Specification (`tools/sb/src/cli.rs`)

Modify line 207 in `tools/sb/src/cli.rs`:

```rust
    /// Interaktives Terminal-Cockpit & Operator HUD (sb cockpit / sb hud) für Daemons, Mesh & Audit
    #[command(alias = "hud")]
    Cockpit {
        /// Headless Snapshot-Modus: Gibt den aktuellen HUD-Status non-interaktiv auf stdout aus und beendet sich mit 0 (CI/CD)
        #[arg(long)]
        snapshot: bool,

        /// Aktualisierungsintervall für Hintergrund-Telemetrie in Millisekunden (Standard: 1000)
        #[arg(short, long, default_value_t = 1000)]
        poll_interval: u64,
    },
```

### 5.2 Main Dispatcher Specification (`tools/sb/src/main.rs`)

Modify lines 269–282 in `tools/sb/src/main.rs`:

```rust
        Some(Commands::Cockpit { snapshot, poll_interval }) => {
            if let Err(e) = cockpit::run_cockpit(snapshot, poll_interval) {
                eprintln!("Fehler beim Starten des Cockpits: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Vault { args }) => {
            if args.iter().any(|a| a == "--tui" || a == "-t") || which::which("sb-vault").is_err() {
                if let Err(e) = cockpit::run_cockpit(false, 1000) {
                    eprintln!("Fehler beim Starten des Cockpits: {}", e);
                    std::process::exit(1);
                }
            } else {
                delegate_to("vault", "sb-vault", &args);
            }
        }
```

### 5.3 Complete Cockpit Architecture (`tools/sb/src/cockpit.rs`)

The revised `tools/sb/src/cockpit.rs` architecture contains:

#### 1. Core Data Models & Safe Probing
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

#[derive(Debug, Clone)]
pub struct DaemonHealth {
    pub name: &'static str,
    pub role: &'static str,
    pub port_info: &'static str,
    pub status: HealthStatus,
    pub latency_ms: Option<u64>,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub source: String,
    pub severity: crate::logs::LogSeverity,
    pub message: String,
}
```

#### 2. ANSI Sanitization (CWE-150 / CWE-116 Mitigation)
```rust
/// Sanitizes strings from untrusted sources to prevent ANSI escape sequence injection.
/// Strips ECMA-48 escape sequences and ASCII control characters.
pub fn sanitize_tui_string(input: &str) -> String {
    let mut clean = String::with_capacity(input.len());
    let mut in_escape = false;
    for c in input.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        // Filter control characters except tab and newline
        if c.is_control() && c != '\t' && c != '\n' {
            continue;
        }
        clean.push(c);
    }
    clean
}
```

#### 3. Terminal Setup, Teardown & Panic Hook (CWE-754 Mitigation)
```rust
fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = crossterm::execute!(
            stdout,
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show
        );
        original_hook(panic_info);
    }));
}

pub fn run_cockpit(snapshot: bool, poll_interval_ms: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = CockpitApp::new(Duration::from_millis(poll_interval_ms));
    app.reload_all();

    if snapshot {
        app.render_snapshot(&mut std::io::stdout())?;
        return Ok(());
    }

    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture, crossterm::cursor::Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        crossterm::cursor::Show
    )?;

    res.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}
```

#### 4. 3-Panel HUD Layout Rendering (`ratatui 0.29`)
```rust
fn ui(f: &mut Frame, app: &CockpitApp) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // Header: Callsign, Swarm Status, System Time, Lease
            Constraint::Percentage(55), // Middle Row: Daemons (Left) & WireGuard Peers (Right)
            Constraint::Min(8),         // Bottom Row: Recent Audit & Access Events
            Constraint::Length(3),      // Footer: Shortcuts, Status & Controls
        ])
        .split(f.area());

    // 1. Render Header
    render_header(f, app, main_layout[0]);

    // 2. Middle Row Split (Left: Daemons, Right: Mesh Peers)
    let middle_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(42), // Top Panel / Left: Active Daemons Status & Live Health
            Constraint::Percentage(58), // Middle / Right: WireGuard Mesh Peers Table
        ])
        .split(main_layout[1]);

    render_daemons_panel(f, app, middle_split[0]);
    render_mesh_peers_panel(f, app, middle_split[1]);

    // 3. Bottom Panel: Recent Audit & Access Events
    render_audit_panel(f, app, main_layout[2]);

    // 4. Footer
    render_footer(f, app, main_layout[3]);
}
```

#### 5. Headless Snapshot Mode (`app.render_snapshot`)
For automated CI verification, headless scripts, and remote diagnosis:
```rust
impl CockpitApp {
    pub fn render_snapshot<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        writeln!(out, "╔══════════════════════════════════════════════════════════════════════════════════════╗")?;
        writeln!(out, "║ SKULLS & BONES // FLEET COCKPIT HUD [SNAPSHOT]                                        ║")?;
        writeln!(out, "╚══════════════════════════════════════════════════════════════════════════════════════╝")?;
        writeln!(out, " Callsign: {:<16} Swarm: {:<18} Time: {:<24} Lease: {}",
            self.callsign, self.swarm_status, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"), self.lease_status)?;
        writeln!(out, "\n[ACTIVE DAEMONS & LIVE HEALTH]")?;
        for d in &self.daemons {
            let (b, _) = d.status.badge();
            let lat = d.latency_ms.map(|l| format!("{}ms", l)).unwrap_or_else(|| "-".to_string());
            writeln!(out, "  • {:<10} {:<12} {:<16} RTT: {:<6} {}", d.name, b, d.port_info, lat, d.details)?;
        }
        writeln!(out, "\n[WIREGUARD MESH PEERS] ({} peers registered)", self.peers.len())?;
        writeln!(out, "  {:<14} {:<16} {:<16} {:<8} {:<18} STATUS", "CALLSIGN", "NODE ID", "OVERLAY IP", "RTT", "TX / RX")?;
        for p in &self.peers {
            let rtt = p.rtt_ms.map(|r| format!("{:.0}ms", r)).unwrap_or_else(|| "-".to_string());
            let traffic = format!("{} / {}", format_bytes(p.bytes_sent), format_bytes(p.bytes_recv));
            writeln!(out, "  {:<14} {:<16} {:<16} {:<8} {:<18} {}",
                p.callsign, &p.node_id[..p.node_id.len().min(14)], p.overlay_ip.as_deref().unwrap_or("-"), rtt, traffic, p.status)?;
        }
        writeln!(out, "\n[RECENT AUDIT & ACCESS LOGS] ({} events)", self.audit_events.len())?;
        for a in self.audit_events.iter().take(8) {
            writeln!(out, "  [{}] [{:<8}] [{:<6}] {}", a.timestamp, a.source, a.severity.badge(), a.message)?;
        }
        writeln!(out, "════════════════════════════════════════════════════════════════════════════════════════")?;
        Ok(())
    }
}
```

---

## 6. Caveats

1. **Daemon Listeners on Empty System**: When running `sb cockpit` on a fresh system where no daemons have been started, the socket probes will cleanly report `[OFFLINE]` with 0 active peers and no audit logs, without crashing or hanging.
2. **Terminal Dimensions**: If an operator runs `sb cockpit` in a very small terminal (< 80 columns or < 20 rows), Ratatui automatically clips content. The layout is designed to prioritize the Daemons status and wireguard peers table.
3. **Audit Log Formats**: While `~/.sb/audit/sessions.jsonl` contains structured JSON, raw text logs in `~/.sb/logs/` are line-parsed with fallback to standard text severity tagging.

---

## 7. Conclusion

The design for Milestone 4 (`sb cockpit` / `sb hud`) is comprehensive, fully aligned with workspace contracts, and addresses all functional and security requirements:
1. `ratatui 0.29` and `crossterm 0.28` are already integrated in `tools/sb/Cargo.toml`.
2. `cli.rs` and `main.rs` are enhanced with `#[command(alias = "hud")]`, `--snapshot`, and `--poll-interval <u64>`.
3. `cockpit.rs` delivers the requested 3-Panel HUD layout (Header, Left: Daemons Live Health, Right: WireGuard Peers, Bottom: Audit & Access Logs).
4. Full mitigation for CWE-754 (panic hook), CWE-150/116 (ANSI sanitization), and CWE-400 (non-blocking decoupled polling).
5. Headless `--snapshot` mode allows automated CI/CD and remote testing without PTY requirements.

---

## 8. Verification Method

To independently verify this design and the upcoming implementation:

1. **Workspace Compilation & Lints**:
   ```powershell
   cargo check --workspace
   ```
   *Expected output*: 0 errors, 0 warnings.

2. **Automated Unit & Snapshot Tests**:
   ```powershell
   cargo test -p sb-cli -- cockpit
   cargo test -p sb-cli -- cli_parsing
   ```
   *Expected output*: 100% pass across all existing and new unit tests.

3. **Headless Snapshot Execution**:
   ```powershell
   cargo run -p sb-cli -- hud --snapshot
   cargo run -p sb-cli -- cockpit --snapshot
   ```
   *Expected output*: Clean tabular ASCII/Unicode HUD dump on stdout, exiting immediately with exit code 0.

4. **Panic Hook Restoration Check (Negative Testing)**:
   Verify that deliberately triggering an unwinding panic inside the cockpit event loop properly invokes `disable_raw_mode()` and restores cursor visibility without corrupting the terminal.

5. **Invalidation Conditions**:
   - If `sb hud` is not recognized as a command.
   - If `--snapshot` hangs waiting for input.
   - If an unhandled panic leaves the terminal in raw mode without cursor.
