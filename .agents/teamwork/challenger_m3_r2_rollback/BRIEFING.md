# BRIEFING — 2026-10-28T01:38:00Z

## Mission
Empirically and adversarially challenge the SSHD backup and rollback fixes implemented by worker_m3_remediation.

## 🔒 My Identity
- Archetype: empirical-challenger
- Roles: critic, specialist
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m3_r2_rollback
- Original parent: cc783d5e-4bd0-4308-8ca7-5252a7088535
- Milestone: M3 (remediation verification round 2)
- Instance: 1 of 1

## 🔒 Key Constraints
- Review-only — do NOT modify implementation code
- Empirical verification: write and run tests/scripts directly, never trust unverified assertions
- Focus on SSHD backup (`99-sb-ca.conf`, `99-sbm.conf`), rollback (`rollback.sh`), systemd unit `ReadWritePaths`, and `cargo test -p sb-cli --bin sb commands::bootstrap`

## Current Parent
- Conversation ID: cc783d5e-4bd0-4308-8ca7-5252a7088535
- Updated: not yet

## Review Scope
- **Files reviewed**:
  - `tools/sb/src/commands/bootstrap.rs`
- **Interface contracts**: `ORIGINAL_REQUEST.md`, `orchestrator_3/PROJECT.md`, `worker_m3_remediation/handoff.md`
- **Review criteria**: correctness, empirical validation of edge cases, symlink handling, short-circuit behavior, data loss risks, standards & security compliance

## Attack Surface
- **Hypotheses tested**:
  1. Does `rollback.sh` restore pre-existing `99-sbm.conf` when `99-sb-ca.conf` did not pre-exist? (Result: FAILED — GNU cp fails on dangling symlink, triggers `|| rm -f`, resulting in permanent data loss).
  2. Does `rollback.sh` restore pre-existing files when BOTH `99-sb-ca.conf` and `99-sbm.conf` pre-existed? (Result: FAILED — `cp -a` follows the existing symlink `99-sbm.conf`, overwriting `99-sb-ca.conf` with `99-sbm.conf` content, corrupting the target and leaking the symlink).
  3. Does systemd unit `ReadWritePaths` prevent `status=226/NAMESPACE` when user home directory does not exist? (Result: PASSED — `-` prefix verified empirically on Linux via `systemd-run`).
  4. Do bootstrap unit tests pass? (Result: PASSED — 15/15 passed).
- **Vulnerabilities found**:
  - Critical Data Loss / Destination Symlink Overwrite Bug in `rollback.sh` (CWE-404, CWE-459, CWE-59).
- **Untested angles**:
  - None within M3 rollback scope.

## Key Decisions Made
- Executed empirical tests on live Linux target `145.223.83.235` (Ubuntu kernel 7.0.0-38-generic, OpenSSH 10.2p1, GNU coreutils 9.4).
- Verified empirical failure of `rollback.sh` and developed verified mitigation.
- Rendered definitive verdict: `REQUEST_CHANGES`.

## Artifact Index
- DISPATCH.md — Dispatch log
- BRIEFING.md — Working memory and context
- progress.md — Liveness heartbeat and step tracking
- handoff.md — Final hard handoff report with verdict
