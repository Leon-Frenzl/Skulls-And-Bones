# Handoff Report: Survey of Operator Cockpit & Fleet HUD (R3) and Remote Target Live Verification (R4)

**Working Directory**: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_cockpit_remote`  
**Date**: 2026-10-27  
**Subagent**: Explorer (`explorer_survey_cockpit_remote`)  
**Parent**: Orchestrator 2 (`60991008-ad8c-4620-be18-d84298ed02f0`)  

---

## 1. Observation

### 1.1 `sb` CLI Architecture & Command Structure
- **Crate Definition**: Located at `tools/sb/Cargo.toml`. Package name: `sb-cli` (v0.2.1), binary name `sb` (`src/main.rs`).
  - Lines 32–33 in `tools/sb/Cargo.toml`:
    ```toml
    ratatui = "0.29"
    crossterm = "0.28"
    ```
- **Command Dispatcher**: In `tools/sb/src/cli.rs` (lines 207–208):
  ```rust
  /// Interaktives Terminal-Cockpit (sb-vault TUI) für Flotte, Ephemeral CA und Mesh
  Cockpit,
  ```
  In `tools/sb/src/main.rs` (lines 269–273):
  ```rust
  Some(Commands::Cockpit) => {
      if let Err(e) = cockpit::run_cockpit() {
          eprintln!("Fehler beim Starten des Cockpits: {}", e);
      }
  }
  ```
  - **Defect/Gap**: There is currently no `hud` subcommand or `#[command(alias = "hud")]` attribute on `Cockpit`. Invoking `sb hud` currently fails as unrecognized command.
- **Process Management & Background Tracking**:
  - `tools/sb/src/process_ledger.rs` (lines 19–85) and `tools/sb-core/src/process.rs` (lines 1–260) maintain `~/.sb/run/process_ledger.json` storing active background daemons (`name`, `pid`, `port`, `started_at`, `status`).

---

### 1.2 Daemon Status, Health, and Metrics APIs

#### 1. `sb-node` (Headless Server Daemon & Ingress Watchdog)
- **Code Reference**: `tools/sb-node/src/main.rs` (lines 2533–2581, 2660–2666).
- **Interface**:
  - CLI command: `sb-node telemetry --json` executes `collect_telemetry() -> NodeTelemetry`.
  - Serialized JSON Payload:
    ```json
    {
      "node_name": "srv490042",
      "swarm_domain": "srv490042.sbm",
      "uptime_seconds": 84120,
      "cpu_usage_percent": 12.5,
      "mem_total_mb": 7936,
      "mem_used_mb": 668,
      "mem_used_percent": 8.4,
      "stealth_ssh_active": true,
      "active_leaks_count": 0,
      "cross_mesh_active": false,
      "cross_mesh_rules_count": 0
    }
    ```
  - Metrics Source: `/proc/uptime`, `/proc/meminfo`, `/proc/loadavg` on Linux (`read_system_metrics()`, lines 2584–2632).
  - Loopback RPC: `tools/sb-core/src/ports.rs` line 28 defines `DEFAULT_DAEMON_API_PORT = 58905` for HTTP JSON-RPC via `DaemonClient` (`tools/sb-core/src/daemon_client.rs`).
  - Remote Ingress Query: `tools/sb/src/cockpit.rs` (line 250) and `tools/sb/src/trace.rs` (lines 69–91) query remote nodes via:
    `sb-ssh <server>.sbm sb-node telemetry --json`

#### 2. `sb-mesh` (Sovereign WireGuard Noise_IK Transport & Routing)
- **Code Reference**: `tools/sb-mesh/src/ipc.rs` (lines 20–250), `tools/sb-mesh/src/peer.rs` (lines 83–110), `tools/sb-mesh/src/routing.rs` (lines 9–62).
- **Interface**:
  - Universal TCP loopback IPC on `127.0.0.1:58890` (`IPC_TCP_PORT` in `tools/sb-mesh/src/ipc.rs:21`).
  - Supported Protocol: Dual-mode (JSON-RPC 2.0 and Legacy JSON action packets).
  - Queries & Payloads:
    - `{"action":"GetStatus"}` / `mesh.status` -> `NodeStatusPayload`:
      ```json
      {
        "node_id": "sbm-2dd0d6c6",
        "wireguard_pubkey": "Hk...",
        "listen_port": 58888,
        "air_gap_killswitch": false,
        "lan_discovery": true,
        "zk_attestation": "ACTIVE (Phase 2 / 0-Leak)",
        "peer_count": 3
      }
      ```
    - `{"action":"ListPeers"}` / `mesh.nodes` -> `Vec<PeerSummaryPayload>`:
      ```json
      [
        {
          "callsign": "hostinger-node",
          "node_id": "sbm-14522383",
          "public_key_base64": "AbC12...",
          "endpoint": "145.223.83.235:58888",
          "overlay_ip": "10.42.0.2",
          "status": "ONLINE",
          "rtt_ms": 23.4,
          "bytes_sent": 1048576,
          "bytes_recv": 2097152,
          "zk_attested": true
        }
      ]
      ```
  - Multi-hop Routing State (`tools/sb-mesh/src/routing.rs:11`):
    `RouteEntry` tracks `destination_node_id`, `next_hop_node_id`, `next_hop_endpoint`, `metric`, `hop_count`, `seq_no`, and expiry.

#### 3. `sb-proxy` (Pure-Rust Edge Gateway & Reverse Proxy)
- **Code Reference**: `tools/sb-proxy/src/ipc.rs` (lines 8–150), `tools/sb/src/trace.rs` (lines 45–66).
- **Interface**:
  - Local HTTP Loopback Server on `127.0.0.1:58900` (`DEFAULT_PROXY_IPC_PORT`).
  - Endpoints:
    - `GET /health` -> HTTP 200 OK (`OK`)
    - `GET /` or `GET /status` -> JSON `ProxyTelemetryDto`:
      ```json
      {
        "status": "online",
        "pid": 14022,
        "uptime_secs": 3600,
        "total_requests": 1420,
        "requests_2xx": 1410,
        "requests_4xx": 8,
        "requests_5xx": 2,
        "rate_limited_count": 0,
        "avg_latency_ms": 2.4,
        "active_spaces_count": 3
      }
      ```

#### 4. `sb-dns` (Sovereign Split-DNS Resolver & Authority)
- **Code Reference**: `tools/sb-dns/src/main.rs` (lines 287–345), `tools/sb-dns/src/client.rs`.
- **Interface**:
  - Standard DNS Port 53 (UDP/TCP) with fallback to Port 58853.
  - Query health via `sb_dns::client::query_server(target, query)`.
  - Process & configuration status via `sb-dns status` inspecting local records and OS Split-DNS integration (`Windows NRPT` / `Linux systemd-resolved`).

---

### 1.3 Audit & Access Event Log Storage
- **Code Reference**: `tools/sb/src/logger.rs` (lines 22–85), `tools/sb/src/commands/daemon.rs` (lines 869–920), `tools/sb-core/src/rpc.rs` (lines 36–37).
- **Central Storage Locations**:
  1. `~/.sb/audit/sessions.jsonl`: SSH/terminal sessions, audited operator, duration, recorded `.cast` asciinema sessions.
  2. `~/.sb/audit/runs.jsonl`: Automated RPC and job runs.
  3. `~/.sb/logs/errors.jsonl`: Structured error records (`ErrorRecord` with timestamp, tool, message, details, exit code).
  4. `~/.sb/logs/<tool>.log`: Per-tool human-readable execution and warning stream.
- **RPC Streaming Methods**: `audit.list` and `audit.recording` exposed via loopback daemon RPC.

---

### 1.4 Existing TUI Architecture (`cockpit.rs`) Deficiencies
- **File**: `tools/sb/src/cockpit.rs` (1,127 lines, 40 KB).
- **Current Behavior**:
  - Displays 5 tabs: `[1] Fleet & Nodes`, `[2] Port Guard`, `[3] Ephemeral SSH CA`, `[4] Sovereign Mesh`, `[5] Logs & Crashes`.
- **Defects Identified**:
  1. **Missing Unified HUD Overview**: No single pane summarizing the 4 active daemons (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`) with live CPU, RAM, ports, and health metrics simultaneously.
  2. **Missing WireGuard Mesh Peers Table**: Tab 4 renders identity and cross-mesh rules, but does not fetch or display the live `PeerSummaryPayload` table (`callsign`, `endpoint`, `overlay_ip`, `rtt_ms`, `rx/tx bytes`, `zk_attested`) from `sb-mesh` IPC.
  3. **Missing Audit / Access Log Table**: Tab 5 shows raw crash alerts and tool log lines, but lacks structured access/audit events from `~/.sb/audit/sessions.jsonl`.
  4. **UI Event Loop Freezing (CWE-400)**: At `cockpit.rs:250`:
     ```rust
     if let Ok(output) = Command::new("sb-ssh")
         .args([&target, "sb-node", "telemetry", "--json"])
         .output()
     ```
     This synchronous call blocks the crossterm event loop for ~1.5s per keypress `[t]`!
  5. **Missing Terminal Panic Hook (CWE-754)**: If any thread panics during rendering, the terminal is left in raw mode with cursor hidden and mouse capture active, breaking the operator's shell.

---

### 1.5 Remote Target Verification (`145.223.83.235`)
- **Direct Probe Execution**:
  - `Test-NetConnection -ComputerName 145.223.83.235 -Port 22`: `TcpTestSucceeded : True` (Port 22 is open and listening).
  - `sb-ssh info root@145.223.83.235`:
    - Uptime: `23 hours, 20 minutes`
    - CPU Load: `0.05 (1m)  0.01 (5m)  0.00 (15m)  [OPTIMAL]`
    - Memory: `8.4% (0.65 GB / 7.75 GB)`
    - Disk: `25.7% (24.6 GB / 95.8 GB)`
  - Environment Command `uname -a; cat /etc/os-release`:
    - Kernel: `Linux srv490042 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`
    - OS: `Ubuntu 26.04.1 LTS`
    - Rust Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo 1.99.1`
    - Systemd: `/usr/bin/systemctl` active.
    - S&B Binaries in `/root/.cargo/bin/`: `sb`, `sb-mesh`, `sb-node`, `sb-auth`, `sb-code`, `sb-db`, `sb-dns`, `sb-drive`, `sb-forge`, `sb-key`, `sb-proxy`.
- **Existing Remote Verification Scripts**:
  - `/root/verify_all.sh` exists on the server!
    - Runs binary version checks across 11 core tools.
    - Verifies `sb-mesh status` and `network list`.
    - Verifies `sb-node start/telemetry/stop` lifecycle.
    - Verifies `sb status`, `sb ps`, `sb catalog`.
    - Verifies `sb-key`, `sb-db`, `sb-dns`, `sb-forge`, `sb-proxy`.
  - Executed `/root/verify_all.sh` live on `145.223.83.235`: Result: **Exit Code 0 (ALL VERIFICATIONS COMPLETED SUCCESSFULLY)**.
  - Executed `/root/.cargo/bin/sb doctor` live on `145.223.83.235`: Result: **Exit Code 0 (13/13 Checks Passed, Alle Systemprüfungen Bestanden)**.
  - Executed `cargo check --workspace` in `/root/teamwork_projects/skulls_and_bones_test` on `145.223.83.235`: Result: **Exit Code 0 in 21.25s (0 errors, 0 warnings)**.

---

### 1.6 Local Workspace Hygiene & Gate Status
- **Local `cargo check --workspace`**:
  - Result: `Finished dev profile [unoptimized + debuginfo] target(s) in 0.56s` (Exit Code 0, 0 compiler errors, 0 warnings).
- **Local `cargo test -p sb-cli`**:
  - Result: `83 passed; 0 failed; 0 ignored; finished in 7.24s` (Exit Code 0).
- **Local `cargo test --workspace --no-run`**:
  - Result: Built all test suites across all 14 workspace crates in 35.14s (Exit Code 0, 0 warnings).

---

## 2. Logic Chain

1. **R3 Requirements Mapping**:
   - The user request explicitly demands:
     - Live status and metrics of active daemons (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`).
     - WireGuard mesh peers and routing status.
     - Recent audit and access events.
     - Launchable via `sb cockpit` or `sb hud`.
   - **Step 1**: In `tools/sb/src/cli.rs`, `Cockpit` is currently the only enum variant. Adding `#[command(alias = "hud")]` immediately fulfills the CLI invocation requirement without code duplication.
   - **Step 2**: The current `cockpit.rs` architecture already has `ratatui` (0.29) and `crossterm` (0.28). However, its tabs are isolated and lack the three explicit components requested in R3.
   - **Step 3**: Designing a primary "Unified HUD" view (or tab 0) that renders a 3-way split:
     1. Daemon Status Table (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`) with live CPU/RAM/port/metrics.
     2. WireGuard Mesh Peers Table (`callsign`, `endpoint`, `overlay_ip`, `status`, `rtt`, `rx/tx`, `zk_attestation`).
     3. Audit and Access Event Log (`timestamp`, `user`, `action`, `resource`, `status`).
   - **Step 4**: To eliminate the ~1.5s UI freezes observed during `sb-ssh` execution, data collection must be decoupled from rendering. A background `tokio` worker or background thread updates an `Arc<RwLock<CockpitData>>`, allowing `terminal.draw()` to render at 60 FPS purely from memory.
   - **Step 5**: To satisfy enterprise resilience and ECMA-48 terminal requirements, a panic hook must be installed on startup (`std::panic::set_hook`) to reset raw mode, restore alternate screens, and show the cursor before the panic message is printed.

2. **R4 Requirements Mapping**:
   - The user request requires deploying and verifying the toolchain on `145.223.83.235`, confirming zero failures on `verify_all.sh` and `sb doctor`.
   - **Step 1**: Probing confirmed `root@145.223.83.235` has Port 22 open and accepts SSH connections cleanly via `sb-ssh`.
   - **Step 2**: Ubuntu 26.04 LTS x86_64 has `rustc 1.99.1`, `cargo 1.99.1`, and `systemctl`.
   - **Step 3**: The test workspace `/root/teamwork_projects/skulls_and_bones_test` is already in place on the remote server and currently passes `cargo check --workspace` cleanly.
   - **Step 4**: When `sb-ca` (R1) and `sb node bootstrap` (R2) are implemented, `sb-ca` must be deployed to `/root/.cargo/bin/sb-ca`, and `/root/verify_all.sh` must be updated to check `sb-ca --version` and verify certificate validation.
   - **Step 5**: Once M1–M4 are deployed, running `verify_all.sh` and `sb doctor` remotely will guarantee gate closure.

---

## 3. Dynamic Threat Modeling & Standards Compliance

### 3.1 Dynamic Threat Modeling

| Threat Vector | Industry Classification | Likelihood & Score | Trigger Conditions | Applied Mitigation |
|---|---|---|---|---|
| **Terminal Escape Injection** | CWE-150 / ECMA-48 escape injection (CVE-2003-0063 / CVE-2022-24765) | Medium (Score 6/10) | Untrusted peer callsigns, HTTP proxy URLs, or audit usernames containing ANSI control sequences (`\x1b]52;...`) rendered directly in TUI. | Sanitize all dynamic string inputs before rendering in Ratatui spans (`c.is_ascii_control() && c != '\t' && c != '\n'`). Strip OSC and CSI control codes. |
| **Event Loop Blocking / Denial of Service** | CWE-400 / Uncontrolled Resource Consumption | High (Score 8/10) | Synchronous `Command::output("sb-ssh")` or blocking TCP sockets inside the crossterm event loop. | Asynchronous background polling via `tokio::spawn` with timeouts (150ms IPC, 1500ms SSH). UI thread only reads cached state. |
| **Terminal State Corruption on Panic** | CWE-754 / Improper Check for Unusual Conditions | High (Score 7/10) | Unhandled panic during rendering leaving terminal in raw mode, mouse captured, cursor hidden. | Install global panic hook (`std::panic::set_hook`) that invokes `disable_raw_mode()`, `LeaveAlternateScreen`, `DisableMouseCapture`, and `show_cursor()`. |
| **Credential Exposure in CLI Args** | CWE-214 / CWE-522 Plaintext Secrets in Process Args | High (Score 8/10) | Passing remote root password `aKjn?KN@2t&G'2Bs` via CLI arguments visible in `/proc/<pid>/cmdline`. | Use SSH key / CA certificate authentication. For initial bootstrap, supply credentials via stdin pipe or `SB_BOOTSTRAP_PASSWORD` env var and zeroize memory buffers immediately. |

### 3.2 Standards Compliance Radar

| Standard | Section / Clause | Application in Cockpit & Remote Verification |
|---|---|---|
| **ECMA-48 / ANSI X3.64** | §5.4 (Control Sequences), §6 (Device Control) | TUI Alternate Screen (`\x1b[?1049h`), Raw mode, cursor handling, and input sanitization. |
| **IETF RFC 4251 / RFC 4252** | The Secure Shell (SSH) Protocol Architecture & Authentication | Ephemeral Ed25519 user certificates and host verification for remote execution on `145.223.83.235`. |
| **IETF RFC 5280 / RFC 8446** | X.509 PKI & TLS 1.3 | Verification of `*.sbm` certificate issuance in `sb-proxy` and display of TLS metrics in the HUD. |
| **POSIX.1-2017** | System Interfaces / `/proc` filesystem | Metric collection (`uptime`, `meminfo`, `loadavg`) across Linux server nodes. |

---

## 4. Cockpit & Fleet HUD (`sb cockpit` / `sb hud`) Architecture Design

### 4.1 CLI Command Signature
In `tools/sb/src/cli.rs`:
```rust
/// Interaktives Operator Cockpit & Fleet HUD für Daemons, Ephemeral CA, Mesh & Audits
#[command(alias = "hud")]
Cockpit {
    /// Startet im Non-Interactive Snapshot-Modus (gibt HUD-Zustand als JSON oder Text aus)
    #[arg(short, long)]
    snapshot: bool,
    /// Aktualisierungs-Intervall in Sekunden (Standard: 2s)
    #[arg(short, long, default_value = "2")]
    interval: u64,
},
```

### 4.2 Terminal Lifecycle & Panic Safety
In `tools/sb/src/cockpit.rs`:
```rust
pub fn run_cockpit() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Install panic hook for terminal restoration
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show
        );
        original_hook(panic_info);
    }));

    // 2. Initialize terminal
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen, crossterm::event::EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    // 3. Run event loop with background worker
    let mut app = CockpitApp::new();
    let res = run_loop(&mut terminal, &mut app);

    // 4. Clean shutdown
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture,
        crossterm::cursor::Show
    )?;

    if let Err(err) = res {
        eprintln!("Cockpit error: {:?}", err);
    }
    Ok(())
}
```

### 4.3 Visual HUD Layout Wireframe
```
┌── SKULLS & BONES // OPERATOR COCKPIT & FLEET HUD v0.2.1 ─────────────────────────────────────────────┐
│ [1] Fleet HUD   [2] Nodes Telemetry   [3] WireGuard Mesh   [4] Ephemeral CA   [5] Audit Trail        │
├──────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ── ACTIVE DAEMONS & SERVICE TELEMETRY ───────────────────────────────────────────────────────────── │
│ DAEMON   STATUS   PORT / ENDPOINT    UPTIME       CPU / RAM       METRICS / STATUS                   │
│ sb-node  ● ONLINE 127.0.0.1:58905    23h 20m      0.1% / 68MB     Stealth SSH active (0 Leaks)       │
│ sb-mesh  ● ONLINE 127.0.0.1:58890    23h 20m      0.2% / 42MB     3 Peers · Noise_IK UDP 58888       │
│ sb-proxy ● ONLINE 127.0.0.1:58900    23h 18m      0.3% / 35MB     1420 reqs (2.4ms avg) · TLS On-Dem │
│ sb-dns   ● ONLINE 127.0.0.1:53       23h 20m      0.0% / 18MB     3 Records · Split-DNS Active       │
├──────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ── WIREGUARD MESH PEERS & MULTI-HOP ROUTING ──────────────────────────────────────────────────────── │
│ CALLSIGN         NODE ID        ENDPOINT             OVERLAY IP  STATUS    RTT    TX / RX    ATTEST  │
│ hostinger-node   sbm-14522383   145.223.83.235:58888 10.42.0.2   ● ONLINE  23ms   1.2M/2.4M  ✔ ZK-OK │
│ dev-laptop       sbm-89ab12cd   192.168.1.45:58888   10.42.0.3   ● ONLINE   2ms   520K/810K  ✔ ZK-OK │
│ backup-anchor    sbm-ef345678   [Relay via Node 1]   10.42.0.4   ◌ STANDBY  --    0B / 0B    ○ NONE  │
├──────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ── RECENT AUDIT & ACCESS EVENTS ─────────────────────────────────────────────────────────────────── │
│ [2026-10-27 19:58:28] root@145.223.83.235: SSH Health Probe executed (Exit: 0, RTT: 1.4s)          │
│ [2026-10-27 19:58:36] root@145.223.83.235: Telemetry Query /proc/loadavg (Load: 0.05)              │
│ [2026-10-27 19:59:02] root@145.223.83.235: verify_all.sh batch verification PASSED (11 tools OK)    │
│ [2026-10-27 20:00:03] local-daemon: Ephemeral certificate generated (Validity: 8h, Ed25519)         │
├──────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ STATUS: Normalbetrieb | Aktualisiert vor 1s | [Tab/1-5] Tabs [j/k] Scroll [r] Refresh [t] Probe [q] Q│
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Remote Target Deployment & Verification Protocol (`145.223.83.235`)

### 5.1 Remote Server Verified State
- Target Host: `145.223.83.235`
- User: `root`
- SSH Auth: Verified working via `sb-ssh` / OpenSSH key.
- Architecture: `x86_64` (Ubuntu 26.04.1 LTS).
- Systemd: Fully supported.
- Workspace on Host: `/root/teamwork_projects/skulls_and_bones_test`.

### 5.2 Verification Pipeline Sequence (for Milestones M1–M5)
1. **Local Build & Package**:
   `cargo build --release -p sb-ca -p sb -p sb-proxy -p sb-node`
2. **Deploy to Target**:
   Use SFTP / `sb-ssh push` to transfer binaries to `/root/.cargo/bin/` or synchronize the workspace in `/root/teamwork_projects/skulls_and_bones_test`.
3. **Remote Gate Checks**:
   - `sb doctor` on remote host must exit 0.
   - `/root/verify_all.sh` on remote host must exit 0 (with `sb-ca` added to the binary check loop).
   - In `/root/teamwork_projects/skulls_and_bones_test`:
     - `cargo check --workspace` must exit 0 with 0 warnings.
     - `cargo test --workspace` must pass 100%.

---

## 6. Caveats

- **Network Latency during SSH Probing**: Direct SSH command execution to `145.223.83.235` has an RTT of ~1400–1500ms from the Windows testing host. Cockpit must never execute remote SSH calls synchronously on the UI event thread.
- **Port 58822 Stealth Ingress**: Port 58822 is closed/filtered directly from WAN, as designed by the stealth SSH architecture. WAN SSH connections must target Port 22 unless tunneling over the sovereign WireGuard mesh.
- **Root Password Handling**: Initial bootstrap supports password `aKjn?KN@2t&G'2Bs`, but subsequent verifications must use short-lived Ed25519 certificates to eliminate static password risks.

---

## 7. Conclusion

Requirements R3 (`sb cockpit` / `sb hud`) and R4 (Live verification on `145.223.83.235`) are fully validated as technically feasible and architecturally aligned with the existing codebase:
1. `ratatui` (0.29) and `crossterm` (0.28) are already present in `tools/sb/Cargo.toml`.
2. All 4 daemons (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`) expose clean, existing status/metrics interfaces over loopback sockets and CLI subcommands.
3. Adding `#[command(alias = "hud")]` and a unified 3-panel HUD layout to `tools/sb/src/cockpit.rs` alongside non-blocking async background polling and terminal panic hooks will satisfy Requirement R3 with zero breaking changes.
4. Target server `145.223.83.235` is online, reachable, has OpenSSH on port 22, has Rust 1.99.1 installed, and currently passes both `verify_all.sh`, `sb doctor`, and `cargo check --workspace` cleanly.

---

## 8. Verification Method

To independently verify all claims made in this report:

1. **Verify Local Workspace Compilation**:
   ```powershell
   cargo check --workspace
   cargo test -p sb-cli
   cargo test --workspace --no-run
   ```
   *Expected*: Exit code 0, 0 errors, 0 warnings.

2. **Verify Remote Server Reachability & Health**:
   ```powershell
   sb-ssh info root@145.223.83.235
   ```
   *Expected*: Successful connection, rendering server metrics (CPU, RAM, Uptime).

3. **Verify Remote Script & Doctor Status**:
   ```powershell
   sb-ssh root@145.223.83.235 "/root/verify_all.sh"
   sb-ssh root@145.223.83.235 "/root/.cargo/bin/sb doctor"
   ```
   *Expected*: Exit code 0 on both scripts.

4. **Verify Remote Workspace Compilation**:
   ```powershell
   sb-ssh root@145.223.83.235 "cd /root/teamwork_projects/skulls_and_bones_test && cargo check --workspace"
   ```
   *Expected*: Exit code 0 with 0 errors and 0 warnings.
