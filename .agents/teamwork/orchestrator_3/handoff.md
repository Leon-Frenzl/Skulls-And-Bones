# Soft Handoff: Project Orchestrator (Generation 3 -> Generation 4)

## Milestone State
| Milestone | Status | Key Deliverables & Evidence |
|---|---|---|
| **Phase 0: Step 0 Survey** | **DONE** | 3 parallel Explorers surveyed PKI/TLS (`sb-ca`), remote provisioning (`sb node bootstrap`), and TUI/remote verification (`sb cockpit`, server `145.223.83.235`). Findings consolidated in `PROJECT.md` and `TEST_INFRA.md`. |
| **Milestone 1: `sb-ca` PKI Engine Crate** | **DONE** | Fully implemented, remediated, and verified: `tools/sb-ca` (library `sb_ca` + binary `sb-ca`). OpenSSH Ed25519 (RFC 4251, `PROTOCOL.certkeys`) and X.509 ECDSA P-256 (RFC 5280 / TLS 1.3 RFC 8446 with mTLS ServerAuth/ClientAuth). Fixed defective 32-byte raw base64 key in `fleet.rs`. Windows ACL lockdown (`IsInherited: False`), `INDEX_MUTEX` and atomic file rename. 100% test pass: `sb-ca` (21/21), `sb-core` (39/39), `sb-cli` (85/85), workspace check 0 errors/0 warnings. Auditor verdict: **CLEAN**, Reviewers & Challengers: **APPROVE**. |
| **Milestone 2: `sb-proxy` On-Demand TLS Integration** | **DONE** | Fully integrated `sb-ca` into `DynamicSniResolver` in `tools/sb-proxy/src/proxy.rs` with in-memory `RwLock<HashMap<String, Arc<CertifiedKey>>>` cache. Automatic TLS issuance gate for `*.sbm`, `*.mesh`, `.local`, `localhost`, and active registered routes. Auditor verdict: **CLEAN**, Reviewers & Challengers: **APPROVE**. |
| **Milestone 3: `sb node bootstrap` Remote Provisioning** | **DONE** | Fully implemented, hardened, and verified in `tools/sb/src/commands/bootstrap.rs`, `cli.rs`, `main.rs`, and `Cargo.toml`. 6-phase remote onboarding pipeline using `sb-ssh` as transport. Password propagation via `SB_SSH_PASSWORD` with `Drop` memory zeroization and `[REDACTED]` debug masking. Custom SFTP port passing (`-p <port>` before `push`) with error keyword scanning and `test -s` verification. Strict parameter sanitization and injection allowlists (`--mesh`, `--ca-key`, `--mesh-token`, `--admin`, target). Transactional SSHD drop-in configuration with pre-flight `sshd -t` baseline test, backup snapshot handling regular and dangling symlinks `([ -e ] || [ -L ])`, and `rollback.sh` unlinking destination files before restore to eliminate GNU `cp` dangling symlink failures (CWE-404, CWE-59, CWE-459). Systemd `sb-node.service` with CIS Linux Benchmark Level 2 sandboxing and `-` prefix on `ReadWritePaths`. Post-onboarding daemon restart (`systemctl restart sb-node`). 15/15 unit tests pass in `commands::bootstrap`, 100/100 tests pass in `sb-cli`, 100% pass across full workspace, 0 errors and 0 warnings on `cargo check --workspace`. Dry-run verified (exit code 0). 9 live empirical permutations verified on `145.223.83.235` (100% pass). Auditor verdict: **CLEAN**, Reviewers & Challengers: **APPROVE**. |
| **Milestone 4: `sb cockpit` / `sb hud` Interactive TUI** | **PLANNED** | Survey complete. Ratatui TUI 3-panel HUD layout and non-blocking async event loop designed. Ready for Milestone 4 sub-orchestrator / worker dispatch. |
| **Milestone 5: Remote Target Live Verification on `145.223.83.235` & Final Gate** | **PLANNED** | Target credentials verified (`145.223.83.235`, root / `aKjn?KN@2t&G'2Bs`, Ubuntu 26.04 LTS, rustc 1.99.1, verify_all.sh exit 0, sb doctor exit 0). Deploy updated binaries, update verify_all.sh for sb-ca, verify zero errors/warnings across full workspace locally and remotely. |

## Active Subagents
- None. All 17 subagents spawned by Generation 3 have delivered their handoffs and completed cleanly.

## Pending Decisions & Key Context
1. **Milestone 4 Implementation Scope (`tools/sb/src/cockpit.rs` and `cli.rs`)**:
   - `ratatui` (version 0.29) and `crossterm` (version 0.28) are already dependencies in `tools/sb/Cargo.toml`.
   - Implement `tools/sb/src/cockpit.rs` containing the 3-panel interactive terminal UI:
     * Panel 1: Active daemons status & live metrics (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`).
     * Panel 2: WireGuard mesh peers and routing status (`PeerSummaryPayload`).
     * Panel 3: Recent audit and access events (`sessions.jsonl`, `errors.jsonl`).
   - CLI command in `tools/sb/src/cli.rs`:
     `Cockpit` subcommand with `#[command(alias = "hud")]`.
     Add optional `--snapshot` non-interactive flag for headless script verification.
   - Fault tolerance & safety:
     * Non-blocking async background polling to eliminate UI event loop freeze (CWE-400).
     * Global panic hook (`std::panic::set_hook`) to restore terminal state (leave alternate screen, show cursor) on panic (CWE-754).
     * ANSI escape sequence sanitization for peer callsigns/data (CWE-150 / ECMA-48).
   - Wire routing in `tools/sb/src/main.rs` to invoke `commands::cockpit::run_cockpit(...)`.

2. **Milestone 5 Live Remote Deployment Scope**:
   - Remote target: `145.223.83.235` (root / `aKjn?KN@2t&G'2Bs`).
   - Transfer updated workspace or release binaries (`sb`, `sb-node`, `sb-mesh`, `sb-proxy`, `sb-ca`, `sb-dns`, etc.).
   - Execute `/root/verify_all.sh` (augment with `sb-ca` check if needed) and `/root/.cargo/bin/sb doctor` with exit code 0.
   - Run `cargo check --workspace` (0 errors, 0 warnings) and `cargo test --workspace` (100% pass) locally and remotely.
   - Run Forensic Integrity Audit for final victory sign-off.

## Remaining Work for Successor (Orchestrator Generation 4)
1. **Execute Milestone 4 (`sb cockpit` / `sb hud`)**:
   - Spawn Worker (or Explorer first if needed) to implement `tools/sb/src/cockpit.rs`, wire `cli.rs` and `main.rs`.
   - Run gate review (2 Reviewers, 2 Challengers, 1 Forensic Integrity Auditor).
   - Close Gate 4.
2. **Execute Milestone 5 (Remote Target Live Verification & Workspace Quality Gate)**:
   - Deploy toolchain to `145.223.83.235` and run `/root/verify_all.sh` and `sb doctor` with exit code 0.
   - Ensure local and remote `cargo check --workspace` (0 errors, 0 warnings) and `cargo test --workspace` (100% pass).
   - Run Forensic Integrity Audit for final victory verification.
   - Close Gate 5.
3. **Deliver Final Human Victory Report**:
   - Deliver final handoff report in `handoff.md` and communicate completion to parent `f389185d-ae30-45ff-ae98-dd6d697ec25f`.

## Key Artifacts
- User request: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md`
- Master project index: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\PROJECT.md`
- Quality gate tracker: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\GATE_STATUS.md`
- Working memory: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\BRIEFING.md`
- Progress checkpoint: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\progress.md`
