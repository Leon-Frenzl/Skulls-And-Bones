# Milestone 4 Conformance & Quality Review Report: Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`)

**Author**: `reviewer_m4_conformance`  
**Date**: 2026-10-28  
**Scope**: Verification of Milestone 4 (`sb cockpit` / `sb hud`), Requirement R3 conformance, Ratatui TUI implementation, headless `--snapshot` mode, adversarial integrity assessment, and workspace quality gates.  
**Verdict**: **`APPROVE`**

---

## 1. Observation

Direct inspection of code, configuration files, and execution outputs revealed the following facts:

### 1.1 CLI Interface & Aliases (`tools/sb/src/cli.rs`)
In `tools/sb/src/cli.rs` (lines 207–225):
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
- **Observation**: `#[command(alias = "hud")]` is correctly registered on `Commands::Cockpit`.
- The `--snapshot` boolean flag and `--poll-interval` parameter (`default_value_t = 1000`) are properly exposed.

### 1.2 Main Dispatcher (`tools/sb/src/main.rs`)
In `tools/sb/src/main.rs` (lines 269–277):
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
```
- **Observation**: Dispatches `Commands::Cockpit` to `cockpit::run_cockpit(snapshot, poll_interval)`.
- If an error occurs, it prints the error and terminates with exit code 1. On success, it exits cleanly with code 0.
- Legacy `sb vault --tui` (lines 278–285) backwards compatibility is preserved.

### 1.3 Cockpit Architecture & Security Defenses (`tools/sb/src/cockpit.rs`)
1. **Global Panic Hook (CWE-754 Defense)** (lines 201–214):
   Installs `setup_terminal_panic_hook()` via `std::panic::set_hook`. Guarantees `disable_raw_mode()`, `LeaveAlternateScreen`, `DisableMouseCapture`, and `cursor::Show` are executed before delegating to the default panic handler.
2. **ECMA-48 ANSI Escape Sanitizer (CWE-150 / CWE-116 Defense)** (lines 122–187):
   `sanitize_tui_string(&str) -> String` neutralizes CSI sequences (`\x1b[...`), OSC sequences (`\x1b]...\x07`), C0 control chars (preserving tab as space and newline), and C1/DEL codes. Conforms to ECMA-48 §5.4/§5.5 and ISO/IEC 6429.
3. **Decoupled Background Poller (CWE-400 Defense)** (lines 1432–1448):
   Network probing runs in background thread `cockpit-telemetry-poller`, caching results in `Arc<RwLock<CockpitSnapshot>>`.
   Socket probes enforce `SOCKET_PROBE_TIMEOUT = Duration::from_millis(150)`.
   Interactive UI loop polls keyboard events with a 50ms timeout, ensuring instantaneous UI responsiveness.
4. **3-Panel HUD Layout** (lines 1312–1337):
   - **Header**: Callsign, Swarm Status, UTC Time (ISO 8601), Ephemeral RAM Lease status, Quorum alert.
   - **Top-Left Panel**: Active Daemons Status (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`) with badges (`● ONLINE`, `▲ DEGRADED`, `✖ OFFLINE`), latency, and socket info.
   - **Top-Right Panel**: WireGuard Mesh Peers Table (`PeerSummaryPayload`) displaying `CALLSIGN`, `NODE ID`, `OVERLAY IP`, `STATUS`, `RTT`, `TX / RX`.
   - **Bottom Panel**: Recent Audit & Access Events (`sessions.jsonl`, `errors.jsonl`, log stream) with crash detector alert banner.
   - **Footer Panel**: Keybindings (`q`/Esc to quit, `r` to refresh, `↑`/`↓` peer navigation).
5. **Headless Snapshot Mode** (lines 825–948):
   `render_snapshot()` writes formatted ASCII HUD snapshot directly to `std::io::stdout()`, bypassing terminal raw mode initialization and exiting cleanly with code 0.

### 1.4 Independent Command Execution Results
1. `cargo check --workspace`:
   - Output: `Finished dev profile [unoptimized + debuginfo] target(s) in 0.56s`
   - Exit code: 0 (0 compiler errors, 0 warnings).
2. `cargo test -p sb-cli --bin sb cockpit`:
   - Output: `running 10 tests ... test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 98 filtered out; finished in 0.78s`
   - Exit code: 0.
3. `cargo test -p sb-cli`:
   - Output: `running 108 tests ... test result: ok. 108 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.62s`
   - Exit code: 0.
4. `cargo run -p sb-cli -- cockpit --snapshot`:
   - Output: Tabular ASCII HUD snapshot rendered to stdout.
   - Exit code: 0.
5. `cargo run -p sb-cli -- hud --snapshot`:
   - Output: Identical tabular ASCII HUD snapshot rendered via `hud` alias.
   - Exit code: 0.
6. `cargo run -p sb-cli -- hud --help`:
   - Output: Displays options `--snapshot` and `-p, --poll-interval <POLL_INTERVAL>`.
   - Exit code: 0.
7. `cargo test -p sb-ca`:
   - Output: `7 passed` (adversarial unit tests) + `4 passed` (E2E SSH CA) + `4 passed` (E2E X.509 CA) = 15 tests passed, 0 failed.
   - Exit code: 0.
8. `cargo test --workspace`:
   - Output: 100% passed across all workspace crates (`sb`, `sb-ca`, `sb-core`, `sb-mesh`, `sb-proxy`, `sb-dns`, etc.).
   - Exit code: 0.

---

## 2. Logic Chain

```
[Requirement R3: Operator Cockpit & Fleet HUD]
       │
       ├─► Conformance: Live Daemons (sb-node, sb-mesh, sb-proxy, sb-dns),
       │                WireGuard Mesh Peers, Audit & Access Events,
       │                CLI aliases (`sb cockpit` / `sb hud`),
       │                Headless `--snapshot` mode
       │
       ├─► Integrity Check: Genuine network probes (TcpStream with 150ms timeout),
       │                    genuine IPC deserialization, genuine process ledger validation.
       │                    Zero hardcoded test facades or fabricated results.
       │
       ├─► Security Hardening:
       │    - CWE-150 / CWE-116: ECMA-48 ANSI sanitizer prevents terminal hijack.
       │    - CWE-754: Panic hook restores terminal state if draw/resize panics.
       │    - CWE-400: Decoupled poller thread eliminates UI event loop freeze.
       │    - CWE-403: Sensitive credentials and keys redacted from telemetry.
       │
       └─► Automated Verification:
            - `cargo check --workspace` -> 0 errors / 0 warnings
            - `cargo test -p sb-cli --bin sb cockpit` -> 10/10 PASS
            - `cargo test -p sb-cli` -> 108/108 PASS
            - `cargo run -p sb-cli -- cockpit --snapshot` -> EXIT 0
            - `cargo run -p sb-cli -- hud --snapshot` -> EXIT 0
            - `cargo run -p sb-cli -- hud --help` -> EXIT 0
            - Full workspace test suite -> 100% PASS
```

1. **R3 Conformance Verified**: All four specified daemons are probed with fallback to the local process ledger; WireGuard mesh peers table renders real peer summary payloads with bandwidth counters and RTT; recent audit and error records are parsed and scanned for crashes; and both command aliases (`sb cockpit` and `sb hud`) invoke the unified cockpit runner.
2. **Adversarial Integrity Confirmed**: No hardcoded dummy strings or cheat facades exist in `cockpit.rs`. Sockets, files, and process tables are queried dynamically.
3. **Robust Non-Interactive Behavior**: Headless `--snapshot` mode bypasses crossterm raw-mode terminal initialization completely, making it ideal for CI/CD runners, automated scripts, and remote monitoring without PTY requirements.
4. **Crash Safety Guaranteed**: The panic hook protects the operator's terminal emulator from corruption in all panic scenarios.

---

## 3. Findings

### Minor Finding 1 (Performance / Memory Optimization)
- **Location**: `tools/sb/src/cockpit.rs:620` and `tools/sb/src/cockpit.rs:659`
- **Issue**: `load_audit_events()` reads all lines of `sessions.jsonl` and `errors.jsonl` into a heap-allocated `Vec<String>` before calling `.rev().take(limit)`.
- **Impact**: On developer workstations and servers where log files are rotated, this is negligible. However, if a node's `sessions.jsonl` grows to hundreds of megabytes without rotation, reading all lines at each poll cycle could introduce avoidable memory spikes.
- **Suggestion**: For future maintenance, consider reading the last N lines using a reverse byte-seeking buffer or standard file tailing.
- **Status**: Non-blocking. Does not affect functional correctness or stability under normal operating conditions.

---

## 4. Caveats

1. **Terminal Hardware Constraints**: Ratatui requires at least ~80 columns by 20 lines to display all three panels without truncation. In extremely small terminals, table columns will be constrained or clipped per Ratatui layout rules.
2. **Initial Clean State**: On a brand new node without prior SSH connections or error incidents, `sessions.jsonl` and `errors.jsonl` are absent. The engine handles this cleanly by displaying `(No audit or error events recorded)`.

---

## 5. Conclusion

**Verdict: `APPROVE`**

The Milestone 4 implementation (`sb cockpit` / `sb hud`) satisfies Requirement R3 in its entirety. The codebase is well-structured, follows Rust best practices, adheres to mandatory Dynamic Security & Threat Modeling guidelines, complies with ECMA-48 and ISO 8601 standards, and passes all compilation checks and automated tests with zero errors.

---

## 6. Verification Method

To independently reproduce the review verification:

```powershell
# 1. Compiler hygiene across workspace
cargo check --workspace

# 2. Cockpit unit tests
cargo test -p sb-cli --bin sb cockpit

# 3. Full CLI test suite
cargo test -p sb-cli

# 4. Headless snapshot verification (cockpit and hud alias)
cargo run -p sb-cli -- cockpit --snapshot
cargo run -p sb-cli -- hud --snapshot

# 5. CLI help verification
cargo run -p sb-cli -- hud --help

# 6. Full workspace test suite
cargo test --workspace
```
Invalidation conditions: Any compilation error or warning, test failure, failure to print snapshot output, non-zero exit code on snapshot execution, or terminal freeze.
