## 2026-10-28T02:04:25Z
You are worker_m4_cockpit.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m4_cockpit
Workspace root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Mandatory input reports to read first:
1. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
2. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\PROJECT.md
3. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m4_tui\handoff.md
4. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m4_telemetry\handoff.md

Write ownership:
You exclusively own:
- `tools/sb/src/cockpit.rs`
- `tools/sb/src/cli.rs`
- `tools/sb/src/main.rs`

Your tasks:
Implement Milestone 4: Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`):
1. In `tools/sb/src/cli.rs`:
   - Enhance `Commands::Cockpit` with `#[command(alias = "hud")]`.
   - Add flags:
     * `snapshot: bool` (`#[arg(long, help = "Headless Snapshot-Modus: Gibt den aktuellen HUD-Status non-interaktiv auf stdout aus und beendet sich mit 0")]`).
     * `poll_interval: u64` (`#[arg(short, long, default_value_t = 1000, help = "Aktualisierungsintervall in Millisekunden")]`).
2. In `tools/sb/src/main.rs`:
   - Route `Commands::Cockpit { snapshot, poll_interval }` to `cockpit::run_cockpit(snapshot, poll_interval)`.
   - Ensure errors exit with non-zero code.
3. In `tools/sb/src/cockpit.rs`:
   - Implement the complete interactive Ratatui TUI and snapshot engine:
     * Terminal setup & teardown using Crossterm and Ratatui.
     * Global panic hook (`std::panic::set_hook`) to guarantee `disable_raw_mode()` and `LeaveAlternateScreen` on panic (CWE-754).
     * Non-blocking background polling with 150ms socket timeouts decoupled from UI event loop (CWE-400).
     * ANSI escape sequence sanitization for untrusted peer callsigns and error strings (CWE-150 / CWE-116).
     * 3-Panel HUD layout:
       - Header: Callsign, Swarm status, UTC time, RAM Lease.
       - Top-Left: Active daemons status & live health (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`).
       - Top-Right: WireGuard mesh peers table (`PeerSummaryPayload`).
       - Bottom: Recent audit & access events (`~/.sb/audit/sessions.jsonl`, `~/.sb/logs/errors.jsonl`).
       - Footer: Controls & Keybindings ('q'/Esc to quit, 'r' to refresh, tab/arrows).
     * Headless `--snapshot` mode: Formatted text dump of the HUD panels to stdout without terminal side-effects, exiting with code 0.
4. Unit Tests in `tools/sb/src/cockpit.rs`:
   - Add unit tests verifying ANSI sanitization, data model parsing, and snapshot output generation.
5. Verification:
   - Run `cargo check --workspace` (0 errors, 0 warnings).
   - Run `cargo test -p sb-cli --bin sb cockpit`.
   - Run `cargo test -p sb-cli`.
   - Run `cargo run -p sb-cli -- cockpit --snapshot`.
   - Run `cargo run -p sb-cli -- hud --snapshot`.
   - Run `cargo run -p sb-cli -- hud --help`.
6. Deliver full handoff report at `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m4_cockpit\handoff.md`.
7. Send a completion message via send_message to orchestrator_3.
