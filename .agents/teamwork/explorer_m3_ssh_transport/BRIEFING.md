# BRIEFING — 2026-10-27T22:18:45Z

## Mission
Investigate SSH transport, remote execution, SFTP staging, and authentication patterns for `sb node bootstrap` in `tools/sb`.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigator, synthesizer
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m3_ssh_transport
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: M3

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Do NOT modify source code
- Write only to .agents/teamwork/explorer_m3_ssh_transport
- Adhere to dynamic security threat modeling (CWE/CVE) and standards compliance (RFC 4251, 4254, etc.)
- Produce 5-component handoff report in handoff.md

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: not yet

## Investigation State
- **Explored paths**: `~/.cargo/bin/sb-ssh.exe`, `~/.sb-ssh/`, `tools/sb/src/commands/{provision.rs, fleet.rs, mod.rs}`, `tools/sb-core/src/binary_resolver.rs`, live target `145.223.83.235:22`.
- **Key findings**:
  1. `sb-ssh.exe` exists in `~/.cargo/bin` (and aliased as `ssh.exe`). No system `scp` or `sftp` exists on this Windows host.
  2. `sb-ssh push` provides pure-Rust SFTP upload, but has a CRITICAL bug: on failure it writes error to STDERR but exits with code 0!
  3. `sb-ssh` command execution accepts compound shell strings directly as arguments, but does not support piped stdin streaming (`bash -s`).
  4. Authentication: `sb-ssh` uses sovereign key/cert auth (`-i <key>` or `~/.ssh/id_ed25519` / `~/.sb-ssh/id_ephemeral`). It has NO interactive password prompt. Live target `145.223.83.235` accepts our local `~/.ssh/id_ed25519` key directly for root login.
  5. Remote staging & execution pattern verified live: `mkdir -m 0700 /tmp/.sb-staging-<uuid>` -> `sb-ssh push` -> `sha256sum verify` -> `bash execution` -> `rm -rf cleanup`.
- **Unexplored areas**: None. All 4 objectives investigated and verified live.

## Key Decisions Made
- Recommend staged script execution instead of stdin streaming to bypass `sb-ssh` stdin limitations.
- Require dual-verification of `sb-ssh push`: check exit code + inspect stderr for `Upload-Fehler` + verify remote sha256.

## Artifact Index
- DISPATCH.md — Incoming task dispatch
- BRIEFING.md — Working memory and identity
- progress.md — Heartbeat and status
- handoff.md — Final 5-component handoff report
