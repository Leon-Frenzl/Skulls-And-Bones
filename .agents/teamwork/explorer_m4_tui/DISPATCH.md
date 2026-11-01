## 2026-10-28T01:54:46Z

You are explorer_m4_tui.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m4_tui
Workspace root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones

Mandatory inputs to read first:
1. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
2. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\PROJECT.md

Your role & tasks:
Investigate and design the interactive Terminal User Interface for Milestone 4 (`sb cockpit` / `sb hud`):
1. Inspect `tools/sb/Cargo.toml` dependencies:
   - Check available versions of `ratatui` (0.29) and `crossterm` (0.28).
2. Inspect `tools/sb/src/cli.rs` and `tools/sb/src/main.rs`:
   - Design CLI subcommand: `Cockpit` with alias `hud` (`#[command(alias = "hud")]`).
   - Include options such as `--snapshot` (headless non-interactive dump for automated verification and CI/CD), `--poll-interval <u64>`, etc.
3. Design TUI architecture in `tools/sb/src/cockpit.rs` (or `tools/sb/src/commands/cockpit.rs`):
   - Terminal setup / teardown (alternate screen, raw mode, mouse capture, hide cursor).
   - Global panic hook (`std::panic::set_hook`) to guarantee terminal restoration (disable raw mode, leave alternate screen) if a panic occurs (CWE-754).
   - Non-blocking event loop (key handling: 'q'/Esc to quit, 'r' to refresh, tab/arrows for navigation).
   - 3-Panel HUD layout rendering:
     * Header: Callsign, Swarm status, system time.
     * Top Panel / Left: Active daemons status & live health (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`).
     * Middle / Right: WireGuard mesh peers table.
     * Bottom Panel: Recent audit & access events.
4. Deliver a comprehensive exploration report at `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m4_tui\handoff.md`.
5. Send a completion message via send_message to orchestrator_3.
