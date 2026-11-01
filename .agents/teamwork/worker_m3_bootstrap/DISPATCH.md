## 2026-10-27T22:20:25Z
You are worker_m3_bootstrap.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m3_bootstrap

Read ORIGINAL_REQUEST.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
Read PROJECT.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md
Read Explorer handoff reports at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m3_cli_pipeline\handoff.md
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m3_ssh_transport\handoff.md
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m3_sshd_systemd\handoff.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

File write ownership:
You own `tools/sb/Cargo.toml`, `tools/sb/src/cli.rs`, `tools/sb/src/main.rs`, `tools/sb/src/commands/mod.rs`, and `tools/sb/src/commands/bootstrap.rs`.

Your Objectives:
1. `tools/sb/Cargo.toml`: Add `sb-ca = { version = "0.1.0", path = "../sb-ca" }`.
2. `tools/sb/src/cli.rs`:
   - Add `pub enum NodeAction` with `Bootstrap(BootstrapArgs)` and `#[command(external_subcommand)] External(Vec<String>)`.
   - Define `BootstrapArgs` with all required flags (`target`, `--port`, `--key`, `--password`, `--admin`, `--ca-key`, `--mesh-token`, `--mesh`, `--binaries`, `--force`, `--dry-run`).
   - Update `Commands::Node { #[command(subcommand)] action: Option<NodeAction> }` preserving 100% backward compatibility for existing `sb node <...>` calls.
3. `tools/sb/src/commands/mod.rs`:
   - Add `pub mod bootstrap;`.
4. `tools/sb/src/commands/bootstrap.rs`:
   - Implement the complete 6-Phase Provisioning Pipeline:
     * Phase 1: Pre-flight probe (OS Linux, arch, root/sudo, disk space, existing services).
     * Phase 2: Staging upload & SHA-256 integrity check (UUID directory in `/tmp/.sb-staging-<uuid>/`, mode 0700, upload runner script & binary via `sb-ssh push`, mitigate `sb-ssh push` exit code 0 defect by checking stderr and verifying remote existence).
     * Phase 3: OpenSSH Swarm-CA anchoring & rollback (`/etc/ssh/trusted_user_ca_keys`, `/etc/ssh/sshd_config.d/99-sb-ca.conf`, transactional pre-validation via `sshd -t`, auto-rollback on failure, graceful reload).
     * Phase 4: Dedicated admin user creation (`sbadmin` user, `/etc/sudoers.d/90-sb-sbadmin` pre-validated via `visudo -cf`, mode 0440).
     * Phase 5: Sandboxed systemd service deployment (`/etc/systemd/system/sb-node.service` with `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, enable and start service, verify UDP 58888 listener).
     * Phase 6: Mesh onboarding (`sudo -u sbadmin /usr/local/bin/sb-node init --token <token>`, vault registration).
   - Implement `--dry-run` to output full execution plan and generated configs without remote modifications.
   - Implement comprehensive unit tests verifying CLI parsing, argument validation, script generation, and rollback logic.
   - Add dynamic security threat modeling comments and standards citations (RFC 4251, RFC 4252, RFC 8709, PROTOCOL.certkeys, POSIX.1-2017).
5. `tools/sb/src/main.rs`:
   - Route `Commands::Node { action }`: If `Some(NodeAction::Bootstrap(args))`, call `commands::bootstrap::handle_node_bootstrap(args)`. If `Some(NodeAction::External(args))`, call `delegate_to("node", "sb-node", &args)`. If `None`, call `delegate_to("node", "sb-node", &[])`.
6. Verification:
   - Run `cargo check --workspace` (verify 0 compiler errors, 0 compiler warnings).
   - Run `cargo test -p sb-cli` (verify all tests pass).
   - Run `cargo test -p sb-ca` and `cargo test -p sb-proxy` (verify 0 regressions).
   - Run dry-run test: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run`.
7. Document all changes and test outputs in `handoff.md` and send completion message to caller.
