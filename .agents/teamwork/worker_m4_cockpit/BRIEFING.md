# BRIEFING — 2026-10-28T02:17:00Z

## Mission
Implement Milestone 4: Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`) with Ratatui TUI, 3-panel layout, headless `--snapshot`, decoupled polling, ANSI sanitization, and terminal panic safety.

## 🔒 My Identity
- Archetype: implementer, qa, specialist
- Roles: implementer, qa, specialist
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m4_cockpit
- Original parent: cc783d5e-4bd0-4308-8ca7-5252a7088535
- Milestone: M4 (Operator Cockpit & Fleet HUD)

## 🔒 Key Constraints
- Exclusively own and modify:
  * `tools/sb/src/cockpit.rs`
  * `tools/sb/src/cli.rs`
  * `tools/sb/src/main.rs`
- Do not touch files outside ownership unless instructed.
- All code must pass `cargo check --workspace` (0 errors, 0 warnings).
- `cargo test -p sb-cli` and `cargo test -p sb-cli --bin sb cockpit` must pass 100%.
- Both interactive cockpit and headless `--snapshot` mode must be implemented.
- ANSI escape sequence sanitization (CWE-150 / CWE-116).
- Global panic hook restoring terminal state (CWE-754).
- Decoupled polling with bounded socket timeouts (CWE-400).
- Deliver handoff.md and notify parent via `send_message`.

## Current Parent
- Conversation ID: cc783d5e-4bd0-4308-8ca7-5252a7088535
- Updated: 2026-10-28T02:17:00Z

## Task Summary
- **What to build**: Full interactive Ratatui TUI + headless snapshot engine for `sb cockpit` and `sb hud`, displaying active daemons (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`), WireGuard mesh peers (`PeerSummaryPayload`), and recent audit logs (`sessions.jsonl`, `errors.jsonl`).
- **Success criteria**:
  1. `Commands::Cockpit` with alias `hud`, `--snapshot`, `--poll-interval` in `cli.rs`. [DONE]
  2. Main routing to `cockpit::run_cockpit(snapshot, poll_interval)` with non-zero exit on error in `main.rs`. [DONE]
  3. Interactive TUI with 3-panel layout, header, footer, background non-blocking polling, panic hook, ANSI sanitization in `cockpit.rs`. [DONE]
  4. Headless `--snapshot` mode with clean stdout dump and exit code 0. [DONE]
  5. Comprehensive unit tests covering sanitization, models, snapshot rendering. [DONE]
  6. Clean `cargo check --workspace` (0 errors, 0 warnings) and tests pass 100%. [DONE]
- **Interface contracts**: PROJECT.md § Interface Contracts
- **Code layout**: PROJECT.md § Code Layout

## Key Decisions Made
- `cli.rs`: Added `#[command(alias = "hud")]` and `--snapshot`, `--poll-interval` flags to `Commands::Cockpit`.
- `main.rs`: Routed `Commands::Cockpit { snapshot, poll_interval }` to `cockpit::run_cockpit(snapshot, poll_interval)` with `std::process::exit(1)` on error.
- `cockpit.rs`:
  * Decoupled background polling worker thread with `Arc<RwLock<CockpitSnapshot>>` and `Duration::from_millis(150)` socket probe timeouts (CWE-400).
  * Global panic hook (`std::panic::set_hook`) restoring raw mode and cursor on crash (CWE-754).
  * ANSI sanitization engine `sanitize_tui_string` stripping ECMA-48 escape sequences and control characters (CWE-150 / CWE-116).
  * 3-panel HUD layout: Header, Top-Left (Daemons Live Health), Top-Right (WireGuard Mesh Peers), Bottom (Recent Audit & Access Events), Footer (Controls).
  * Headless `--snapshot` mode formatted text dump to stdout without terminal initialization, exiting with code 0.

## Artifact Index
- `.agents/teamwork/worker_m4_cockpit/DISPATCH.md` — Orchestrator assignment
- `.agents/teamwork/worker_m4_cockpit/progress.md` — Liveness & step heartbeat
- `.agents/teamwork/worker_m4_cockpit/BRIEFING.md` — Working memory & constraints
- `.agents/teamwork/worker_m4_cockpit/handoff.md` — Final deliverable report
- `tools/sb/src/cli.rs` — Enhanced CLI with alias hud, --snapshot, --poll-interval
- `tools/sb/src/main.rs` — Main router for Cockpit with non-zero error exit
- `tools/sb/src/cockpit.rs` — Interactive Ratatui HUD and headless snapshot engine

## Change Tracker
- **Files modified**:
  * `tools/sb/src/cli.rs`: added alias hud, --snapshot, --poll-interval
  * `tools/sb/src/main.rs`: updated Cockpit dispatch with parameters and exit(1) on error
  * `tools/sb/src/cockpit.rs`: full interactive TUI and snapshot engine implementation
- **Build status**: `cargo check --workspace` PASSED (0 errors, 0 warnings).
- **Pending issues**: None.

## Quality Status
- **Build/test result**:
  * `cargo check --workspace` (0 errors, 0 warnings)
  * `cargo test -p sb-cli --bin sb cockpit` (10/10 passed)
  * `cargo test -p sb-cli` (108/108 passed)
  * `cargo run -p sb-cli -- cockpit --snapshot` (exit code 0)
  * `cargo run -p sb-cli -- hud --snapshot` (exit code 0)
  * `cargo run -p sb-cli -- hud --help` (exit code 0)
- **Lint status**: 0 warnings.
- **Tests added/modified**: 8 new unit tests in `cockpit.rs` (ANSI sanitization, format bytes, health badges, snapshot render, snapshot collection structure).

## Loaded Skills
- **Source**: C:\Users\leonf\.gemini\config\skills\secure-function-coder\SKILL.md
  - **Local copy**: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m4_cockpit\skills\secure-function-coder.md
  - **Core methodology**: First-principles dynamic threat modeling, CWE mapping, and active code hardening.
- **Source**: C:\Users\leonf\.gemini\config\skills\standards-compliance\SKILL.md
  - **Local copy**: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m4_cockpit\skills\standards-compliance.md
  - **Core methodology**: Formal standards evaluation (ISO 8601, ECMA-48, RFC 4251, RFC 5280) and citation in code.
