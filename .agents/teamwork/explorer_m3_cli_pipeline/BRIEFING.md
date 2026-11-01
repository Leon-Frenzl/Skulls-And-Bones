# BRIEFING — 2026-10-27T22:13:35Z

## Mission
Investigate CLI structure in `tools/sb/src/cli.rs` and `tools/sb/src/commands/` for implementing `sb node bootstrap` pipeline orchestration.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigation, synthesis
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m3_cli_pipeline
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: M3 (`sb node bootstrap` CLI pipeline)

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Do NOT modify source code

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: not yet

## Investigation State
- **Explored paths**:
  - `tools/sb/src/cli.rs`: Command hierarchy and `Node` subcommand definition
  - `tools/sb/src/main.rs`: Dispatching patterns and delegation
  - `tools/sb/src/commands/fleet.rs`: `handle_server_init` and token generation
  - `tools/sb/src/commands/provision.rs`: `handle_server_provision` and shell script generation
  - `tools/sb/src/commands/mod.rs`: Module registrations
  - `tools/sb-ca/src/lib.rs` & `tools/sb-ca/src/ssh/`: `sb_ca::ssh::ca_public_key_openssh`
  - `tools/sb-core/src/binary_resolver.rs`: Resolver for `sb-ssh`, `sb-mesh`, `sb-node`
  - `sb-ssh` binary: Verified `sb-ssh push` and command execution
- **Key findings**:
  - `Node` subcommand currently delegates all args blindly via `delegate_to("node", "sb-node", &args)`.
  - Refactoring `Node` into `NodeAction` with `Bootstrap` variant and `#[command(external_subcommand)] External(Vec<String>)` preserves 100% backward compatibility for existing `sb node <daemon|status|...>` calls while providing full typed Clap CLI parsing for `sb node bootstrap`.
  - Required CLI flags (`--port`, `--key`, `--password`, `--admin`, `--ca-key`, `--mesh-token`, `--mesh`, `--binaries`, `--force`, `--dry-run`) are mapped to clean Rust types and validated against CWE-78 command injection.
  - Planned 6-phase pipeline orchestration for `tools/sb/src/commands/bootstrap.rs` integrates `SshTransport` (`sb-ssh` with `ssh`/`scp` fallback), SHA256 integrity checks, atomic rollback for `sshd -t` and `visudo -cf`, systemd sandboxed service, and mesh onboarding.
- **Unexplored areas**: None for M3 architecture. Ready for implementer.

## Key Decisions Made
- Architecture decision: Place `NodeAction` in `cli.rs` with `Bootstrap` and `External` variants.
- Place pipeline orchestration in `tools/sb/src/commands/bootstrap.rs` registered in `tools/sb/src/commands/mod.rs`.
- Add `sb-ca = { version = "0.1.0", path = "../sb-ca" }` dependency to `tools/sb/Cargo.toml`.

## Artifact Index
- `handoff.md` — Complete 5-component handoff report and recommended implementation plan
- `progress.md` — Liveness and execution heartbeat
- `DISPATCH.md` — Incoming dispatch message record
