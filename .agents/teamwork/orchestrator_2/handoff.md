# Soft Handoff: Project Orchestrator (Generation 1 -> Generation 2)

## Milestone State
| Milestone | Status | Key Deliverables & Evidence |
|---|---|---|
| **Phase 0: Step 0 Survey** | **DONE** | 3 parallel Explorers surveyed PKI/TLS (`sb-ca`), remote provisioning (`sb node bootstrap`), and TUI/remote verification (`sb cockpit`, server `145.223.83.235`). Findings consolidated in `PROJECT.md` and `TEST_INFRA.md`. |
| **Milestone 1: `sb-ca` PKI Engine Crate** | **DONE** | Fully implemented, remediated, and verified: `tools/sb-ca` (library `sb_ca` + binary `sb-ca`). OpenSSH Ed25519 (RFC 4251, `PROTOCOL.certkeys`) and X.509 ECDSA P-256 (RFC 5280 / TLS 1.3 RFC 8446 with mTLS ServerAuth/ClientAuth). Fixed defective 32-byte raw base64 key in `fleet.rs`. Windows ACL lockdown (`IsInherited: False`), `INDEX_MUTEX` and atomic file rename, wildcard fix (`*.*.sbm` avoided), IPv6 colon sanitization (`::1` -> `__1.crt`), `IssuedCertPair` redacted Debug and Zeroize. All tests pass 100%: `sb-ca` (21/21), `sb-core` (39/39), `sb-cli` (85/85), workspace check 0 errors/0 warnings. Auditor verdict: **CLEAN**, Reviewers & Challengers: **APPROVE**. |
| **Milestone 2: `sb-proxy` On-Demand TLS Integration** | **IN_PROGRESS** | Interface contract `sb_ca::x509::get_or_issue_on_demand` verified. Ready for Worker dispatch to enhance `DynamicSniResolver` in `tools/sb-proxy/src/proxy.rs` with in-memory RAM cache and automatic minting for `.sbm` and `.mesh`. |
| **Milestone 3: `sb node bootstrap` Remote Provisioning** | **PLANNED** | Survey complete. Architecture and 6-phase pipeline designed (`sb-ssh` / SFTP transport, `/etc/ssh/sshd_config.d/99-sb-ca.conf`, `TrustedUserCAKeys`, systemd `sb-node.service`). |
| **Milestone 4: `sb cockpit` / `sb hud` Interactive TUI** | **PLANNED** | Survey complete. Ratatui TUI 3-panel HUD layout and non-blocking async event loop designed. |
| **Milestone 5: Remote Target Live Verification on `145.223.83.235` & Final Gate** | **PLANNED** | Remote environment verified (`145.223.83.235`, root / `aKjn?KN@2t&G'2Bs`, Ubuntu 26.04 LTS, rustc 1.99.1, verify_all.sh exit 0, sb doctor exit 0). Deploy updated binaries, update verify_all.sh for sb-ca, verify zero errors/warnings across full workspace. |

## Active Subagents
- None. All 18 subagents from Generation 1 have completed their handoffs and retired cleanly.

## Pending Decisions & Context
- `product-inventory.json` registers `ca` with `"maturity": "integrated"`. In Milestone 5, when final workspace packaging and live verification on `145.223.83.235` succeed, its release evidence can be formally populated.
- `tools/sb-proxy/Cargo.toml` should add dependency `sb-ca = { path = "../sb-ca" }`.
- `tools/sb-proxy/src/proxy.rs`: `DynamicSniResolver` should hold an in-memory `cert_cache: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>`. On incoming SNI, check RAM cache first (instant return); if miss and domain ends with `.sbm`, `.mesh`, `.local`, or matches route, call `sb_ca::x509::get_or_issue_on_demand`, convert PEM to `CertifiedKey`, insert into RAM cache, and return.

## Remaining Work for Successor
1. **Execute Milestone 2 (`sb-proxy` On-Demand TLS Integration)**:
   - Dispatch Worker M2 to add `sb-ca` dependency in `tools/sb-proxy/Cargo.toml` and update `DynamicSniResolver` in `tools/sb-proxy/src/proxy.rs`.
   - Dispatch Reviewers, Challengers, and Forensic Auditor for M2.
   - Close M2 Gate.
2. **Execute Milestone 3 (`sb node bootstrap`)**:
   - Dispatch Worker M3 to implement `sb node bootstrap <user@host>` in `tools/sb/src/cli.rs` and `commands/bootstrap.rs` using `sb-ssh` / SFTP.
   - Dispatch Reviewers, Challengers, and Forensic Auditor for M3.
   - Close M3 Gate.
3. **Execute Milestone 4 (`sb cockpit` / `sb hud`)**:
   - Dispatch Worker M4 to add alias `hud` to `Cockpit` and implement the 3-panel HUD layout with async background polling and panic hook.
   - Dispatch Reviewers, Challengers, and Forensic Auditor for M4.
   - Close M4 Gate.
4. **Execute Milestone 5 (Remote Target Live Verification on `145.223.83.235` & Quality Gate)**:
   - Deploy `sb-ca` and updated binaries to `145.223.83.235`.
   - Remotely execute `/root/verify_all.sh` and `/root/.cargo/bin/sb doctor` with exit code 0.
   - Ensure local and remote `cargo check --workspace` (0 errors, 0 warnings) and `cargo test --workspace` (100% pass).
   - Forensic Auditor final victory check.
   - Deliver final handoff and report to user.

## Key Artifacts
- User request: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md`
- Master project index: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md`
- E2E Test infrastructure: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\TEST_INFRA.md`
- Quality gate tracker: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\GATE_STATUS.md`
- Working memory: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\BRIEFING.md`
- Progress checkpoint: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\progress.md`
