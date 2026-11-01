# BRIEFING — 2026-10-28T02:03:00Z

## Mission
Investigate and design the interactive Terminal User Interface for Milestone 4 (`sb cockpit` / `sb hud`).

## 🔒 My Identity
- Archetype: explorer
- Roles: explorer, tui-architect
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m4_tui
- Original parent: cc783d5e-4bd0-4308-8ca7-5252a7088535
- Milestone: Milestone 4 (sb cockpit / sb hud interactive TUI)

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Dynamic Security & Threat Modeling (CWE-754 panic restoration, CWE-116 terminal escape injection, CWE-400 resource exhaustion in event loop)
- Standards Compliance (ANSI/VT100 escape codes, ISO 8601 timestamps, POSIX/Windows terminal handling)
- Layout compliance: source code in tools/sb, only metadata in .agents/teamwork/

## Current Parent
- Conversation ID: cc783d5e-4bd0-4308-8ca7-5252a7088535
- Updated: 2026-10-28T02:03:00Z

## Investigation State
- **Explored paths**:
  - `tools/sb/Cargo.toml`: Confirmed `ratatui 0.29`, `crossterm 0.28`, `tokio 1.43` present
  - `tools/sb/src/cli.rs`: Examined line 208 `Commands::Cockpit`
  - `tools/sb/src/main.rs`: Examined line 269 dispatch to `cockpit::run_cockpit()`
  - `tools/sb/src/cockpit.rs`: Analyzed current 5-tab cockpit structure (1127 lines)
  - `tools/sb-core/src/mesh_ipc.rs`: Inspected `PeerSummaryPayload` and `IpcRequest::ListPeers`
  - `tools/sb-mesh/src/ipc.rs`: Inspected loopback TCP listener on port 58890
  - `tools/sb-proxy/src/ipc.rs`: Inspected loopback HTTP listener on port 58900 (`/status`, `/health`)
  - `tools/sb-node/src/main.rs`: Inspected telemetry on port 58905 & UDP 58888
  - `tools/sb-dns/src/config.rs`: Inspected split-dns listener on port 58853
  - `tools/sb/src/logs.rs` & `logger.rs`: Inspected `errors.jsonl`, `sessions.jsonl`, `CrashInspector`
- **Key findings**:
  - `PeerSummaryPayload` in `sb-core` has all WireGuard peer metrics ready for HUD table rendering.
  - All 4 core daemons have deterministic loopback probe endpoints with minimal latency.
  - Adding `#[command(alias = "hud")]` and `--snapshot`, `--poll-interval` directly fulfills R3.
  - Threat modeling identified 4 critical failure modes: CWE-754 terminal corruption on panic, CWE-150/116 ANSI injection, CWE-400 event loop starvation, CWE-400 unbounded log memory.
- **Unexplored areas**: None for M4 exploration scope.

## Key Decisions Made
- Architecture decision: Implement panic hook with `std::panic::set_hook` to guarantee terminal restoration (CWE-754).
- Architecture decision: Implement `sanitize_tui_string` stripping ANSI sequences and control characters (CWE-150/116).
- Architecture decision: Support `--snapshot` flag rendering complete HUD state to stdout with exit code 0 for CI/CD and automated verification.
- Architecture decision: 3-Panel HUD layout: Top/Left Daemons Health, Middle/Right WireGuard Peers Table, Bottom Audit & Access Events.

## Artifact Index
- DISPATCH.md — incoming dispatch instructions
- BRIEFING.md — persistent working memory
- progress.md — liveness heartbeat
- handoff.md — final exploration report
