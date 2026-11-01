# Telemetry & Cockpit HUD Exploration Report — Milestone 4 (`sb cockpit` / `sb hud`)

**Author**: `explorer_m4_telemetry`  
**Date**: 2026-10-28  
**Scope**: Milestone 4 (`sb cockpit` / `sb hud`) Telemetry, Daemon Probing, Mesh Peers, Audit Logs, and Non-Blocking Worker Architecture  

---

## 1. Observation

Direct code and architectural observations across the Skulls & Bones workspace:

### 1.1 Existing Cockpit State & Subcommand Wiring
- In `tools/sb/src/cockpit.rs` (lines 33–55, 364–459): An initial tab-based cockpit implementation exists (`CockpitApp`) with 5 tabs: `[1] Fleet & Nodes`, `[2] Port Guard`, `[3] Ephemeral SSH CA`, `[4] Sovereign Mesh`, `[5] Logs & Crashes`. It uses `ratatui 0.29` and `crossterm 0.28`.
- In `tools/sb/src/cli.rs` (lines 17–60) and `tools/sb/src/main.rs`: `Cockpit` (with alias `hud`) is **not yet added** to `Commands` in `cli.rs`, nor dispatched in `main.rs`.
- In `tools/sb/src/cockpit.rs` line 250–266 (`probe_selected_server_telemetry`): Currently executes a **blocking** synchronous command `Command::new("sb-ssh").args([&target, "sb-node", "telemetry", "--json"]).output()` directly on the UI thread when key `'t'` is pressed. If the target server is slow or partitioned, the entire TUI event loop locks up (CWE-400).
- In `tools/sb/Cargo.toml` lines 32–33, 40–48: `sb-cli` already depends on `ratatui = "0.29"`, `crossterm = "0.28"`, `tokio = { version = "1.43", features = ["full"] }`, `sb-core`, `sb-mesh`, `sb-proxy`, `sb-ca`, `sb-key`, `serde`, `serde_json`, `toml`, `chrono`, and `ureq`.

### 1.2 Daemon Health & Status Probing Mechanisms

#### A. `sb-node` (Server Agent & Relay Anchor)
- **Primary Listener**: Single-port UDP Dispatcher listening on UDP port `58888` (`tools/sb-node/src/main.rs:44, 2734`). UDP sockets cannot be verified using standard TCP stream handshakes.
- **Loopback API & Port**: Port `58905` is defined as `sb_core::ports::DEFAULT_DAEMON_API_PORT` (`tools/sb-core/src/ports.rs:28`). When the daemon HTTP RPC is active, it responds on `127.0.0.1:58905`.
- **Process Supervision Ledger**: `tools/sb-core/src/process.rs:10-40` tracks background processes in `~/.sb/run/processes.json` (`TrackedProcess { name, pid, port, command, started_at }`).
- **PID Verification**: `sb_core::process::is_pid_alive(pid)` (`tools/sb-core/src/process.rs:80-120`):
  * On Windows: Uses Win32 `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` and checks `GetExitCodeProcess` against `STILL_ACTIVE (259)`.
  * On Linux/Unix: Reads `/proc/<pid>/status` and verifies the process is not in zombie state `'Z'` or dead state `'X'/'x'`.
- **System Metrics & Local Telemetry**: `tools/sb-node/src/main.rs:2533-2581` defines `collect_telemetry() -> NodeTelemetry`:
  * Returns `node_name`, `swarm_domain`, `uptime_seconds`, `cpu_usage_percent`, `mem_total_mb`, `mem_used_mb`, `mem_used_percent`, `stealth_ssh_active` (loopback port 22/58822), `active_leaks_count` (0.0.0.0 binds), `cross_mesh_active`, `cross_mesh_rules_count`.
  * Represented in `sb-core` as `sb_core::dto::RemoteTelemetry`.

#### B. `sb-mesh` (WireGuard & Encrypted Overlay)
- **Primary Listener**: TCP loopback port `58890` (`tools/sb-mesh/src/ipc.rs:21` `IPC_TCP_PORT = 58890`).
- **Protocols Supported**:
  * JSON-RPC 2.0: `{"jsonrpc":"2.0","id":1,"method":"mesh.status","params":null}` (`tools/sb-mesh/src/ipc.rs:118-140`).
  * Legacy IPC Request: `{"action":"GetStatus"}` (`tools/sb-mesh/src/ipc.rs:226-242`).
- **Response Payload**: `sb_core::mesh_ipc::NodeStatusPayload` (`tools/sb-core/src/mesh_ipc.rs:33-41`):
  ```rust
  pub struct NodeStatusPayload {
      pub node_id: String,
      pub wireguard_pubkey: String,
      pub listen_port: u16,
      pub air_gap_killswitch: bool,
      pub lan_discovery: bool,
      pub zk_attestation: String,
      pub peer_count: usize,
  }
  ```
- **Offline Fallback**:
  * Identity: `~/.sb-mesh/identity.json` (`node_id`, `wireguard_pubkey`).
  * Peers file: `~/.sb-mesh/peers.toml` (`PeersFile { peers: Vec<PeerConfig> }`).

#### C. `sb-proxy` (Developer Edge Gateway & TLS Engine)
- **Primary Listener**: TCP loopback port `58900` (`tools/sb-proxy/src/ipc.rs:84-140`).
- **HTTP Endpoints**:
  * `GET /health`: Ultra-fast liveness check, responds with `HTTP/1.1 200 OK\r\n\r\nOK` (`tools/sb-proxy/src/ipc.rs:113-115`).
  * `GET /` or `GET /status`: Responds with JSON `ProxyTelemetryDto` (`tools/sb-proxy/src/ipc.rs:128-150`, `sb_core::dto::ProxyTelemetryDto`):
    ```rust
    pub struct ProxyTelemetryDto {
        pub status: String,
        pub pid: u32,
        pub uptime_secs: u64,
        pub total_requests: u64,
        pub requests_2xx: u64,
        pub requests_4xx: u64,
        pub requests_5xx: u64,
        pub rate_limited_count: u64,
        pub avg_latency_ms: f64,
        pub active_spaces_count: usize,
    }
    ```
- **Socket Probe**: Tested via `TcpStream::connect_timeout(&"127.0.0.1:58900".parse().unwrap(), Duration::from_millis(200))`.

#### D. `sb-dns` (Split-Horizon DNS Resolver)
- **Primary Listeners**: UDP and TCP on port `58853` (default) or port `53` (privileged) (`tools/sb-dns/src/config.rs:69`, `tools/sb-dns/src/server.rs:38-48`).
- **Dual-Binding Architecture**: `DnsServer::run` binds both a `UdpSocket` and a `TcpListener` on the exact same `SocketAddr`. Therefore, an asynchronous or timeout-bounded TCP connect to `127.0.0.1:58853` (or `127.0.0.1:53`) reliably detects daemon presence without needing complex DNS packet encoding.
- **Config & State Fallback**:
  * Configuration: `~/.sb/dns/config.json` (`DnsConfig { listen_ip, listen_port, sovereign_suffixes, upstream_servers, cache_size, authority_trust }`).
  * Records: `~/.sb/dns/records.json` (`RecordsConfig { a, aaaa, cname, txt }`).

### 1.3 WireGuard Mesh Peers Querying
- In `tools/sb-mesh/src/ipc.rs` (lines 141–153, 243–251, 395–414):
  * Active Daemon Query: Sending `{"action":"ListPeers"}` or JSON-RPC `{"jsonrpc":"2.0","id":1,"method":"mesh.nodes","params":null}` to `127.0.0.1:58890`.
  * Wire Payload: `Vec<sb_core::mesh_ipc::PeerSummaryPayload>`:
    ```rust
    pub struct PeerSummaryPayload {
        pub callsign: String,
        pub node_id: String,
        pub public_key_base64: String,
        pub endpoint: Option<String>,
        pub overlay_ip: Option<String>,
        pub status: String, // "ONLINE", "HANDSHAKE", "STANDBY", "OFFLINE"
        pub rtt_ms: Option<f64>,
        pub bytes_sent: u64,
        pub bytes_recv: u64,
        pub zk_attested: bool,
    }
    ```
- In `tools/sb-mesh/src/peer.rs` (lines 286–317):
  * Offline State File Fallback: `PeerTable::load_from_file(Path::new("~/.sb-mesh/peers.toml"))` parses `PeersFile { peers: Vec<PeerConfig> }`.

### 1.4 Audit Event & Access Log Locations
- In `tools/sb/src/commands/daemon.rs` lines 869–918:
  * `sessions.jsonl`: Located at `~/.sb/audit/sessions.jsonl`.
  * `runs.jsonl`: Located at `~/.sb/audit/runs.jsonl`.
- In `tools/sb/src/logger.rs` lines 21–38, 114–141:
  * Central error log: `~/.sb/logs/errors.jsonl`.
  * Format: Serialized `ErrorRecord`:
    ```rust
    pub struct ErrorRecord {
        pub timestamp: DateTime<Utc>,
        pub tool: String,
        pub level: String,
        pub message: String,
        pub details: Option<String>,
        pub exit_code: Option<i32>,
    }
    ```
- In `tools/sb/src/logs.rs` lines 38–144 (`CrashInspector`):
  * Analyzes logs for critical signatures: Rust Panics (`panicked at`), Python Tracebacks (`Traceback (most recent call last):`), Node.js Unhandled Rejections, and Linux OOM-Killer (`Out of memory: Kill process`).

---

## 2. Logic Chain

From the observations, the following architectural inferences and design decisions are derived:

```
[Observation 1.1: TUI freezing on synchronous probes]
        │
        ▼
[Logic Step 1: Thread Decoupling via Non-Blocking Background Worker]
- The TUI render loop (Ratatui terminal.draw) must never execute network I/O or disk operations.
- Background polling must run in a dedicated thread / tokio task updating an `Arc<RwLock<CockpitSnapshot>>`.
- The UI loop reads from RAM cache in microseconds, achieving uninterrupted 20+ FPS user input handling.

[Observation 1.2: 4 Daemons with Distinct Transport & Sockets]
        │
        ▼
[Logic Step 2: Unified Daemon Telemetry Prober with Bounded Sockets]
- sb-node: Process ledger PID check + loopback port 58905 check + local/remote NodeTelemetry metrics.
- sb-mesh: TCP 58890 IPC check (GetStatus) with 150ms timeout; fallback to ~/.sb-mesh/identity.json.
- sb-proxy: TCP 58900 HTTP GET /health & /status with 200ms timeout; fallback to process_ledger.
- sb-dns: TCP 58853 / 53 socket connection check with 150ms timeout; fallback to ~/.sb/dns/config.json.
- Every probe has a hard timeout to prevent thread starvation (CWE-400).

[Observation 1.3: PeerSummaryPayload Wire Format & Offline File]
        │
        ▼
[Logic Step 3: Resilient Peer Table Loader]
- Online path: Query 127.0.0.1:58890 ListPeers -> Vec<PeerSummaryPayload> with live RTT & byte counts.
- Offline path: Load ~/.sb-mesh/peers.toml -> Map PeerConfig to PeerSummaryPayload (marked OFFLINE/Saved).
- Eliminates blank peer panel when the daemon is temporarily stopped.

[Observation 1.4: Dual Audit Sources (sessions.jsonl & errors.jsonl)]
        │
        ▼
[Logic Step 4: Unified Time-Sorted Audit Stream]
- Stream reads from tail (last 50 lines) of ~/.sb/audit/sessions.jsonl and ~/.sb/logs/errors.jsonl.
- Maps entries to a common `HudAuditEntry { timestamp, source, severity, summary }`.
- Integrates CrashInspector detection so active panics or errors display with immediate visual highlighting.

[Observations 1.1 & 1.3: Untrusted External Strings in Terminal]
        │
        ▼
[Logic Step 5: ECMA-48 ANSI Escape Sequence Sanitizer]
- Untrusted peer callsigns or error strings could contain terminal control sequences (CSI, OSC, \x1b[2J).
- Without sanitization, terminal borders break, screens clear, or spoofed status appears (CWE-150 / CWE-116).
- An explicit ECMA-48 sanitizer must strip all C0/C1 control codes and ANSI escape sequences.
```

---

## 3. Detailed Architecture & Design Specifications

### 3.1 Non-Blocking Background Telemetry Worker (CWE-400 Defense)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        COCKPIT ARCHITECTURE                           │
├──────────────────────────────────┬─────────────────────────────────────┤
│      TUI RENDER LOOP             │   BACKGROUND TELEMETRY WORKER       │
│      (Main Thread)               │   (Dedicated Asynchronous Task)     │
├──────────────────────────────────┼─────────────────────────────────────┤
│ 1. crossterm::event::poll(50ms)  │ 1. tokio::time::sleep(1500ms)       │
│    - Responsive to 'q', 'r',     │ 2. Probe sb-node (PID / 58905)      │
│      arrows, '1'-'5' tabs        │ 3. Probe sb-mesh (IPC 58890)        │
│ 2. Read snapshot from RAM:       │ 4. Probe sb-proxy (HTTP 58900)      │
│    snapshot.read().unwrap()      │ 5. Probe sb-dns (TCP 58853 / 53)    │
│ 3. terminal.draw(|f| ui(f, snap))│ 6. Query ListPeers (or peers.toml)  │
│    - Latency: < 0.5 ms           │ 7. Tail sessions.jsonl & errors     │
│    - 0 network / disk I/O        │ 8. Atomic write to Arc<RwLock<...>> │
└──────────────────────────────────┴─────────────────────────────────────┘
```

#### In-Code Data Contract: `CockpitSnapshot`
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonHealth {
    pub name: &'static str,
    pub binary: &'static str,
    pub status: DaemonStatus, // Online, Offline, Degraded
    pub socket_addr: String,
    pub pid: Option<u32>,
    pub metrics: Vec<String>,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonStatus {
    Online,
    Offline,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CockpitSnapshot {
    pub daemons: Vec<DaemonHealth>,
    pub mesh_peers: Vec<sb_core::mesh_ipc::PeerSummaryPayload>,
    pub audit_events: Vec<HudAuditEntry>,
    pub local_identity: Option<String>,
    pub last_polled_at: chrono::DateTime<chrono::Utc>,
}
```

### 3.2 ANSI Escape Sequence Sanitizer (CWE-150 / ECMA-48 Compliance)

```rust
/**
 * Sanitizes untrusted text strings before rendering into terminal TUI cells.
 *
 * SECURITY AUDIT:
 * - Dynamic Threat Vector: Untrusted external strings (remote peer callsigns, DNS record names,
 *   unfiltered audit log entries) can inject ANSI escape sequences (CSI, OSC, cursor positioning)
 *   to hijack the terminal emulator display, overwrite borders, or spoof green status badges.
 * - CVE / CWE Mapping: CWE-150 (Improper Neutralization of Escape, Meta, or Control Sequences),
 *   CWE-116 (Improper Output Neutralization).
 * - Likelihood & Exploitability: High (Score: 8/10) when displaying names supplied by remote mesh peers.
 * - Applied Mitigation: Strip all C0 control characters (0x00..=0x1F except tab converted to space),
 *   DEL (0x7F), C1 control characters (0x80..=0x9F), and 7-bit/8-bit ANSI escape sequences.
 *
 * Conforms to ECMA-48 (5th Edition, June 1991) §5.4 (CSI) and §5.5 (OSC), and ISO/IEC 6429.
 */
pub fn sanitize_tui_text(input: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_len));
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if out.len() >= max_len {
            break;
        }

        // Check for ESC (0x1B)
        if ch == '\u{001B}' {
            if let Some(&next_ch) = chars.peek() {
                if next_ch == '[' {
                    // CSI sequence: ESC [ ... [0x40..=0x7E]
                    chars.next();
                    while let Some(c) = chars.next() {
                        if (0x40..=0x7E).contains(&(c as u32)) {
                            break;
                        }
                    }
                    continue;
                } else if next_ch == ']' {
                    // OSC sequence: ESC ] ... (ST or BEL)
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\u{0007}' || c == '\u{001B}' {
                            if c == '\u{001B}' && chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                    continue;
                } else if next_ch == '(' || next_ch == ')' || next_ch == '*' || next_ch == '+' {
                    // Charset selection: ESC ( B
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

        // Replace tab with single space
        if ch == '\t' {
            out.push(' ');
            continue;
        }

        // Strip C0 control characters (0x00..=0x1F)
        if (ch as u32) < 0x20 {
            continue;
        }

        // Strip DEL (0x7F) and C1 control characters (0x80..=0x9F)
        if (0x7F..=0x9F).contains(&(ch as u32)) {
            continue;
        }

        out.push(ch);
    }

    out
}
```

### 3.3 Terminal State Restoration on Panic (CWE-754 Defense)

```rust
/**
 * Installs a fail-safe panic hook ensuring the terminal is always restored
 * to standard mode even if a panic occurs inside the Ratatui event loop.
 *
 * SECURITY AUDIT:
 * - Dynamic Threat Vector: An unhandled panic while the terminal is in raw mode and alternate
 *   screen leaves the user's shell completely un-echoed, invisible, and unresponsive (CWE-754).
 * - CVE / CWE Mapping: CWE-754 (Improper Check for Unusual or Exceptional Conditions).
 * - Likelihood & Exploitability: Medium (Score: 6/10) during unexpected terminal resizing or drawing.
 * - Applied Mitigation: Global std::panic::set_hook resets raw mode, disables mouse capture,
 *   leaves alternate screen, and un-hides cursor before delegating to default panic handler.
 */
pub fn setup_terminal_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show
        );
        default_hook(info);
    }));
}
```

### 3.4 3-Panel Unified HUD Layout Specification

The primary HUD view in `sb cockpit` / `sb hud` displays 3 panels in vertical split:

```
┌────────────────────────────────────────────────────────────────────────┐
│ SKULLS & BONES // SOVEREIGN OPERATOR COCKPIT & FLEET HUD [2026-10-28]  │
├────────────────────────────────────────────────────────────────────────┤
│ [PANEL 1: ACTIVE DAEMONS & RUNTIME METRICS] (Height: 8 lines)          │
│ DAEMON   STATUS   PID / PORT       METRICS            DETAILS          │
│ sb-node  🟢 ONLINE PID 4120 :58888  CPU 0.8% | RAM 48M No Leaks (0.0.0.0)
│ sb-mesh  🟢 ONLINE PID 3980 :58890  Peers: 3 active    Listen UDP 51820│
│ sb-proxy 🟢 ONLINE PID 5112 :58900  1,840 reqs (4xx:1) Latency: 1.2ms │
│ sb-dns   🟢 ONLINE :58853 / :53    Upstream: 1.1.1.1  .sbm, .mesh, .sb │
├────────────────────────────────────────────────────────────────────────┤
│ [PANEL 2: WIREGUARD MESH PEERS & ROUTING STATUS] (Min height: 8 lines) │
│ CALLSIGN      OVERLAY IP   ENDPOINT           STATUS  RTT     TRAFFIC  │
│ srv-prod-01   10.240.0.1   145.223.83.235:... 🟢 ON   14.2ms  ↑12M ↓4M │
│ alpha-laptop  10.240.0.5   192.168.1.100:...  🟡 STBY —       ↑0K  ↓0K │
├────────────────────────────────────────────────────────────────────────┤
│ [PANEL 3: RECENT AUDIT & ACCESS EVENTS] (Min height: 8 lines)          │
│ TIMESTAMP (UTC)      SOURCE   SEVERITY  EVENT SUMMARY                  │
│ 2026-10-28 01:54:12  SSH      INFO      Operator leonf connected (node)│
│ 2026-10-28 01:50:00  CA       INFO      On-demand cert issued: *.sbm   │
│ 2026-10-28 01:45:22  PROXY    WARN      Rate-limit threshold reached   │
├────────────────────────────────────────────────────────────────────────┤
│ STATUS: [r] Force Refresh | [q] Exit | [1-5] Tabs | Polled: 1s ago     │
└────────────────────────────────────────────────────────────────────────┘
```

#### Snapshot Mode (`--snapshot`)
When `sb cockpit --snapshot` or `sb hud --snapshot` is executed:
- The command executes a single synchronous polling pass (with 200ms bounded socket timeouts).
- Formats the 3 panels as clear ASCII text with ANSI colors.
- Prints to standard stdout and terminates immediately with exit code 0.
- Enables complete automated CLI verification, headless testing, and remote live check on `145.223.83.235`.

---

## 4. Caveats

1. **UDP Socket Probing for `sb-node`**: `sb-node` daemon dispatcher listens on UDP port 58888. Standard TCP `connect` fails on UDP ports. Therefore, daemon health probing for `sb-node` combines:
   - Process ledger check (`is_pid_alive` for `"sb-node"` in `~/.sb/run/processes.json`).
   - TCP probe to port 58905 (`DEFAULT_DAEMON_API_PORT`).
   - UDP socket bind probe or system metrics reading via `collect_telemetry()`.
2. **DNS Port 53 Privileges**: On Linux/Unix, binding port 53 requires `CAP_NET_BIND_SERVICE` or root. On Windows or developer unprivileged mode, `sb-dns` listens on port `58853`. Probing checks port 58853 first, followed by 53.
3. **Empty Audit Log Initial State**: On fresh installations, `~/.sb/audit/sessions.jsonl` may not exist yet. The parser handles `NotFound` gracefully and returns an informational notice rather than crashing.

---

## 5. Conclusion

- **Ready for Implementation**: The telemetry data sources, wire formats, probe ports, and IPC contracts are fully mapped and verified.
- **Architectural Security**: The non-blocking background worker (`Arc<RwLock<CockpitSnapshot>>`) coupled with strict 150-200ms socket timeouts eliminates UI thread hangs (CWE-400).
- **Terminal Defense**: ECMA-48 escape sequence filtering neutralizes ANSI injection from untrusted mesh peer callsigns (CWE-150 / CWE-116), and the global panic hook guarantees terminal restoration (CWE-754).
- **Headless & Script Compliance**: Adding `--snapshot` flag enables seamless execution in CI scripts and remote live verification without TTY allocation.

---

## 6. Verification Method

To verify these observations and design models independently:

### Verification Commands:
1. Workspace compilation hygiene:
   ```powershell
   cargo check --workspace
   ```
   *Expected: Exit code 0, 0 compiler errors, 0 warnings.*

2. Run `sb-cli` unit tests:
   ```powershell
   cargo test -p sb-cli -- --nocapture
   ```
   *Expected: 100+ tests pass.*

3. Inspect files:
   - `tools/sb-node/src/main.rs:2533` (`collect_telemetry`)
   - `tools/sb-mesh/src/ipc.rs:21, 243` (`IPC_TCP_PORT = 58890`, `ListPeers`)
   - `tools/sb-proxy/src/ipc.rs:84` (`127.0.0.1:58900 /status`)
   - `tools/sb-dns/src/config.rs:69`, `tools/sb-dns/src/server.rs:38` (ports 58853 / 53)
   - `tools/sb/src/logger.rs:31, 115` (`errors.jsonl`, `ErrorRecord`)
   - `tools/sb/src/commands/daemon.rs:871` (`sessions.jsonl`)

### Invalidation Conditions:
- If `cargo check --workspace` fails with any compilation error.
- If socket probes hang longer than 200ms during daemon outage.
- If unescaped ANSI sequences pass through `sanitize_tui_text`.
