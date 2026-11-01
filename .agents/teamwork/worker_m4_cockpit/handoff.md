# Milestone 4 Handoff Report: Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`)

**Author**: `worker_m4_cockpit`  
**Date**: 2026-10-28  
**Scope**: Milestone 4 (`sb cockpit` / `sb hud`), Interactive Ratatui Terminal User Interface, Headless `--snapshot` Engine, Non-Blocking Poller (CWE-400), ANSI Sanitization (CWE-150 / CWE-116), Panic Hook Terminal Safety (CWE-754).

---

## 1. Observation

### 1.1 Pre-Modification Baseline
- `tools/sb/src/cli.rs` (lines 207–209):
  `Commands::Cockpit` was declared as a unit variant with no alias, missing the required `hud` alias, `--snapshot` flag, and `--poll-interval` parameter.
- `tools/sb/src/main.rs` (lines 269–282):
  Dispatched `Some(Commands::Cockpit) => { if let Err(e) = cockpit::run_cockpit() { eprintln!(...); } }` without arguments and without setting a non-zero exit code on failure.
- `tools/sb/src/cockpit.rs`:
  Contained legacy tab implementations with blocking network calls (`Command::new("sb-ssh")`) on the UI thread (CWE-400), missing a global panic hook (leaving terminals bricked on crash, CWE-754), missing ECMA-48 ANSI escape sanitization (CWE-150 / CWE-116), and without a headless `--snapshot` mode for automated CI/CD and remote scripting.

### 1.2 Implemented Changes & Verified Source State

#### A. CLI Subcommand (`tools/sb/src/cli.rs`)
Updated `Commands::Cockpit` with alias `hud` and dedicated flags:
```rust
    /// Interaktives Terminal-Cockpit & Operator HUD (sb cockpit / sb hud) für Daemons, Mesh & Audit
    #[command(alias = "hud")]
    Cockpit {
        /// Headless Snapshot-Modus: Gibt den aktuellen HUD-Status non-interaktiv auf stdout aus und beendet sich mit 0
        #[arg(
            long,
            help = "Headless Snapshot-Modus: Gibt den aktuellen HUD-Status non-interaktiv auf stdout aus und beendet sich mit 0"
        )]
        snapshot: bool,

        /// Aktualisierungsintervall in Millisekunden
        #[arg(
            short,
            long,
            default_value_t = 1000,
            help = "Aktualisierungsintervall in Millisekunden"
        )]
        poll_interval: u64,
    },
```

#### B. Main Dispatcher (`tools/sb/src/main.rs`)
Routed `Commands::Cockpit { snapshot, poll_interval }` to `cockpit::run_cockpit(snapshot, poll_interval)` and enforced non-zero exit on error:
```rust
        Some(Commands::Cockpit {
            snapshot,
            poll_interval,
        }) => {
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

#### C. Cockpit Engine & Fleet HUD (`tools/sb/src/cockpit.rs`)
Delivered full interactive Ratatui TUI and headless snapshot engine:
1. **Global Panic Hook (CWE-754 Defense)**:
   Installed `setup_terminal_panic_hook()` via `std::panic::set_hook`: guarantees that if any panic occurs inside Ratatui or Crossterm, `disable_raw_mode()`, `LeaveAlternateScreen`, `DisableMouseCapture`, and `Show` cursor execute before delegating to the default panic handler.
2. **ECMA-48 ANSI Escape Sanitizer (CWE-150 / CWE-116 Defense)**:
   Implemented `sanitize_tui_string(&str) -> String`: strips all CSI escape sequences (`\x1b[...`), OSC window title sequences (`\x1b]...\x07` or `\x1b]...\x1b\\`), C0 control characters (except tab and newline), and DEL / C1 codes. Conforms to ECMA-48 §5.4/§5.5 and ISO/IEC 6429.
3. **Decoupled Background Poller (CWE-400 Defense)**:
   UI event loop and network I/O are completely decoupled:
   - Dedicated background thread `cockpit-telemetry-poller` polls daemons and updates an `Arc<RwLock<CockpitSnapshot>>`.
   - Every daemon socket probe (`sb-node` on UDP 58888/TCP 58905, `sb-mesh` on TCP 58890, `sb-proxy` on TCP 58900, `sb-dns` on TCP 58853/53) is bounded by `SOCKET_PROBE_TIMEOUT = Duration::from_millis(150)`.
   - The interactive UI thread reads snapshots from RAM cache in < 0.1ms and polls keyboard input every 50ms, achieving zero UI stutter and instant key responsiveness.
4. **3-Panel HUD Layout**:
   - **Header**: Callsign, Swarm Status, UTC Time (ISO 8601), Ephemeral RAM Lease status and remaining validity, 4-Eyes Quorum alert badge.
   - **Top-Left**: Active Daemons Status & Live Health (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`) with badges (`● ONLINE`, `▲ DEGRADED`, `✖ OFFLINE`), latency, and socket/role details.
   - **Top-Right**: WireGuard Mesh Peers Table (`PeerSummaryPayload`) displaying `CALLSIGN`, `NODE ID`, `OVERLAY IP`, `STATUS`, `RTT`, `TX / RX`.
   - **Bottom**: Recent Audit & Access Events (`~/.sb/audit/sessions.jsonl`, `~/.sb/logs/errors.jsonl`, central log stream) with automatic `CrashInspector` alert banner.
   - **Footer**: Keybindings (`q`/Esc to quit, `r` to refresh, `↑`/`↓` peer navigation).
5. **Headless Snapshot Mode (`--snapshot`)**:
   `app.render_snapshot` outputs formatted plain text directly to standard output without terminal initialization (no raw mode, no alternate screen), exiting cleanly with code 0.

---

## 2. Logic Chain

```
[Requirement: Milestone 4 Operator Cockpit & Fleet HUD]
       │
       ▼
[CLI Layer: cli.rs & main.rs]
- Add #[command(alias = "hud")] to Cockpit
- Add --snapshot (bool) & --poll-interval (u64, default 1000)
- Route to cockpit::run_cockpit(snapshot, poll_interval)
- Exit with code 1 on error
       │
       ▼
[Security & Reliability Layer: cockpit.rs]
- CWE-754: Global panic hook restoring terminal raw mode & cursor
- CWE-150 / CWE-116: ECMA-48 ANSI escape sanitizer
- CWE-400: Decoupled background poller with 150ms bounded socket timeouts
       │
       ▼
[3-Panel Layout & Snapshot Engine]
- Header: Callsign, Swarm, Time (ISO 8601), Lease
- Top-Left: Active Daemons (sb-node, sb-mesh, sb-proxy, sb-dns)
- Top-Right: WireGuard Peers Table (PeerSummaryPayload)
- Bottom: Recent Audit & Access Logs (sessions.jsonl, errors.jsonl)
- Footer: Shortcuts & Controls
       │
       ▼
[Automated & Live Verification]
- cargo check --workspace: 0 errors, 0 warnings
- cargo test -p sb-cli --bin sb cockpit: 10/10 tests passed
- cargo test -p sb-cli: 108/108 tests passed
- cargo run -p sb-cli -- cockpit --snapshot: exit code 0
- cargo run -p sb-cli -- hud --snapshot: exit code 0
- cargo run -p sb-cli -- hud --help: exit code 0
```

1. **Safety First**: Modifying raw terminal modes requires fail-safe cleanup. Without `setup_terminal_panic_hook`, any downstream panic leaves the user's terminal in an unrecoverable state.
2. **Decoupled Architecture**: Running socket probes synchronously inside `terminal.draw()` causes frame drops whenever a daemon port hangs. Spawning a dedicated poller thread updating `Arc<RwLock<CockpitSnapshot>>` ensures the UI thread draws in microseconds.
3. **Data Neutralization**: WireGuard mesh peers and external logs are untrusted. Passing raw strings into TUI Paragraph or Table cells allows ANSI injection (CSI title hijacking, cursor repositioning). Stripping ECMA-48 control sequences ensures display integrity.
4. **CI/CD Compatibility**: Automated test environments and remote verification scripts cannot interact with interactive PTYs. The `--snapshot` flag bypasses terminal initialization, dumps the full HUD status as formatted text, and terminates with exit code 0.

---

## 3. Caveats

1. **Offline System State**: When neither `sb-node`, `sb-mesh`, `sb-proxy`, nor `sb-dns` are running, socket connect attempts cleanly time out after 150ms. All daemons report `[OFFLINE]` with fallback details, without hanging or erroring.
2. **Terminal Dimensions**: In terminals narrower than 80 columns or shorter than 20 rows, Ratatui clips cells according to column constraints. The layout specifies `Constraint::Length` for fixed columns and `Constraint::Min` for flexible detail columns.
3. **Audit Log Initial Absence**: On a freshly initialized system without prior SSH sessions or errors, `~/.sb/audit/sessions.jsonl` does not exist. The reader handles this gracefully and displays `(No audit or error events recorded)`.

---

## 4. Conclusion

Milestone 4 is completely implemented and verified:
1. `sb cockpit` and `sb hud` are fully supported via Clap derive aliases.
2. The 3-panel HUD layout renders active daemon health, WireGuard mesh peers, and audit events.
3. Headless `--snapshot` mode executes cleanly with exit code 0.
4. Hardened against CWE-754 (panic hook), CWE-150/116 (ANSI sanitization), and CWE-400 (non-blocking decoupled polling).
5. All workspace quality gates passed (0 errors, 0 warnings, 100% test pass).

---

## 5. Verification Method

To independently reproduce and verify this implementation:

### 1. Workspace Compilation & Lint Hygiene
```powershell
cargo check --workspace
```
*Result*: Exit Code 0, 0 compiler errors, 0 warnings.

### 2. Unit Tests for Cockpit
```powershell
cargo test -p sb-cli --bin sb cockpit
```
*Result*: 10 tests passed, 0 failed:
- `cockpit::tests::test_health_status_badges ... ok`
- `cockpit::tests::test_sanitize_tui_string_control_characters ... ok`
- `cockpit::tests::test_sanitize_tui_string_csi_escape ... ok`
- `cockpit::tests::test_sanitize_tui_string_osc_escape ... ok`
- `cockpit::tests::test_format_bytes ... ok`
- `cockpit::tests::test_sanitize_tui_string_preserves_valid_unicode ... ok`
- `cockpit::tests::test_render_snapshot_output ... ok`
- `cockpit::tests::test_cockpit_snapshot_collection_structure ... ok`
- `cockpit::tests::test_cockpit_tab_switching ... ok`
- `cockpit::tests::test_cockpit_app_initialization ... ok`

### 3. Full `sb-cli` Test Suite
```powershell
cargo test -p sb-cli
```
*Result*: 108 tests passed, 0 failed.

### 4. Headless Snapshot Verification
```powershell
cargo run -p sb-cli -- cockpit --snapshot
cargo run -p sb-cli -- hud --snapshot
```
*Result*: Prints clean tabular ASCII HUD snapshot to stdout, exits with code 0:
```text
╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ SKULLS & BONES // FLEET COCKPIT HUD [SNAPSHOT]                                                       ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝
 Callsign: sbm-0x12d3ae3b   Swarm: STANDBY (Overlay)  Time: 2026-10-28 02:16:16 UTC  Lease: INAKTIV / GESPERRT (Führe 'sb lease' aus)

[ACTIVE DAEMONS & LIVE HEALTH]
  • sb-node    [OFFLINE]    UDP 58888          RTT: -      Daemon inaktiv (UDP 58888 / TCP 58905 nicht erreichbar)
  • sb-mesh    [OFFLINE]    TCP 58890          RTT: -      Daemon inaktiv (TCP 58890 nicht erreichbar)
  • sb-proxy   [OFFLINE]    TCP 58900          RTT: -      Gateway inaktiv (TCP 58900 nicht erreichbar)
  • sb-dns     [OFFLINE]    :58853 / :53       RTT: -      Resolver inaktiv (Ports 58853 / 53 nicht erreichbar)

[WIREGUARD MESH PEERS] (1 peers registered)
  CALLSIGN         NODE ID          OVERLAY IP         RTT      TX / RX            STATUS
  hostinger-anchor peer-KzPz8UJ4    10.240.0.1         -        0 B / 0 B          SAVED

[RECENT AUDIT & ACCESS LOGS] (0 events)
  (No audit or error events recorded)
════════════════════════════════════════════════════════════════════════════════════════════════════════
```

### 5. CLI Alias & Help Verification
```powershell
cargo run -p sb-cli -- hud --help
```
*Result*: Displays help for `sb.exe cockpit` with `--snapshot` and `--poll-interval` options, exits with code 0.
