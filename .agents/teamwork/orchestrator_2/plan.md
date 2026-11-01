# Plan: PKI, Remote Bootstrapping, Operator Cockpit, and Live Target Verification

## Objective
Implement `sb-ca` (OpenSSH & X.509 dual-mode PKI engine), integrate on-demand TLS into `sb-proxy`, implement `sb node bootstrap` via `sb-ssh` for remote Linux provisioning, build `sb cockpit` interactive TUI, verify locally (100% tests passing, zero warnings), and perform live deployment and verification on server `145.223.83.235`.

## Phases & Milestones

### Phase 0: Survey & Architecture (Step 0)
- Dispatch 3 parallel Explorers to examine:
  1. `sb-ca` & PKI / TLS requirements, existing cryptography crates/conventions, OpenSSH RFC 4251, X.509 RFC 5280, and `sb-proxy` architecture.
  2. `sb-ssh`, SFTP, remote provisioning, sshd `TrustedUserCAKeys`, systemd setup for `sb-node`, and wireguard mesh registration.
  3. CLI commands in `sb` (`sb cockpit`/`sb hud`, `sb node bootstrap`), `ratatui` or TUI integration, daemon metrics, and server `145.223.83.235` environment (`verify_all.sh`, `sb doctor`).
- Consolidate findings into `PROJECT.md` with Feature Inventory and Interface Contracts.

### Phase 1: Test Infrastructure & Implementation Milestones
- Spawn E2E Testing Orchestrator / Test Writer for `TEST_INFRA.md` covering Tiers 1-4.
- Milestone 1 (M1): `sb-ca` PKI Crate (OpenSSH Ed25519 certs + X.509 TLS 1.3 certs for `*.sbm`, `*.mesh`).
- Milestone 2 (M2): `sb-proxy` On-Demand TLS Certificate Generation and Caching.
- Milestone 3 (M3): `sb node bootstrap <user@host>` via `sb-ssh` and SFTP.
- Milestone 4 (M4): `sb cockpit` / `sb hud` ratatui TUI Dashboard.
- Milestone 5 (M5): Local Workspace Hygiene (`cargo check --workspace`, `cargo test --workspace`) and Live Remote Verification on `145.223.83.235`.

### Phase 2: Quality Gates, Forensic Audit & Final Handoff
- Full iteration loop per milestone: Explorer -> Worker -> Reviewers (2) -> Challengers (2) -> Forensic Auditor -> Gate.
- Final remote target execution: `verify_all.sh` and `sb doctor` on `145.223.83.235`.
