# BRIEFING — 2026-10-27T21:01:45Z

## Mission
Survey and investigate Requirement R2: Automated Remote Server Bootstrapping (`sb node bootstrap <user@host>`), analyzing `sb-ssh`, `sb-node`, Linux bootstrapping automation, CLI integration, and dynamic threat modeling.

## 🔒 My Identity
- Archetype: Explorer
- Roles: Read-only investigation, codebase surveying, threat modeling, architecture analysis, synthesis
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_bootstrap
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: Requirement R2 Survey & Architecture

## 🔒 Key Constraints
- Read-only investigation — do NOT implement code changes in the project tree directly
- Output structured 5-component handoff report to `handoff.md`
- Maintain liveness heartbeat via `progress.md`
- Apply User Global Rules (Dynamic Threat Modeling & In-Code Security Comments, Standards Compliance Radar, Critical Thinking)

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: 2026-10-27T21:01:45Z

## Investigation State
- **Explored paths**:
  - `tools/sb/src/commands/provision.rs` (`generate_provision_script`, `handle_server_provision`)
  - `tools/sb/src/commands/fleet.rs` (`handle_server_init`, `get_or_detect_ca_pubkey`, `build_pairing_token`, `register_server_in_vault`)
  - `tools/sb/src/commands/delegate.rs` (`resolve_ssh_invocation`, `delegate_to`)
  - `tools/sb/src/cli.rs` (`Commands::Node`, `Commands::Server`, `ServerAction`)
  - `tools/sb-node/src/main.rs` (`run_daemon`, `handle_init`, `handle_revoke`, `open_rbac_db`)
  - `tools/sb-core/src/binary_resolver.rs` (`BinaryResolver::resolve_ssh`)
  - `tools/sb-core/src/paths.rs` (`sb_ssh_dir`, `servers_config_path`, `sb_ca_dir`)
  - `tools/sb-drive/src/peer_fs.rs` (SSH command & pipe transfer patterns)
  - `~/.cargo/bin/sb-ssh.exe` (Discovered binary: capabilities `push`, `pull`, `exec`, `connect`, `server-init`, `cert`, built with `russh_sftp`)
  - `~/.sb-ssh/` (`ca_key.pub`, `id_ephemeral-cert.pub`, `servers.toml`)
  - `docs/DEV_SERVER_SETUP.md`, `docs/SOVEREIGN_FLEET_ARCHITECTURE.md`, `docs/ARCHITECTURE.md`
- **Key findings**:
  1. `sb-ssh` binary is installed in `~/.cargo/bin/sb-ssh.exe` (v0.1.0) and contains native SFTP (`push`/`pull` via `russh_sftp`), remote command execution (`exec`), and certificate generation (`cert`).
  2. `BinaryResolver::resolve_ssh()` in `sb-core` resolves `sb-ssh` first, falling back to OpenSSH `ssh` / `ssh.exe`.
  3. `sb-node` runs a multi-tenant relay daemon (`sb-node daemon --port 58888`), uses `~/.sb-mesh/networks.json` and `~/.sb-mesh/identity.json` or `/etc/sb/identity.json`.
  4. Remote bootstrapping currently has two partial implementations: `sb server provision` (spawns ssh/scp for systemd unit & binaries) and `sb server init` (spawns ssh for user creation & sshd drop-in `99-sbm.conf`).
  5. Architecture for `sb node bootstrap <user@host>` cleanly unifies these: zero-touch onboarding via `sb-ssh`, SFTP binary deployment, `/etc/ssh/sshd_config.d/99-sb-ca.conf` anchoring with atomic rollback on `sshd -t` validation failure, unprivileged hardened `sb-node.service` via systemd, and mesh pairing token registration.
- **Unexplored areas**: None for R2 survey scope. Ready for handoff synthesis.

## Key Decisions Made
- Architected `sb node bootstrap <user@host>` as a unified, idempotent orchestration engine supporting both `sb-ssh` (native SFTP push & exec) and OpenSSH fallback.
- Formulated 5 dynamic threat models with CWE mappings, scores (1-10), and concrete hardening mitigations following User Global Rule 1.
- Identified relevant IEEE/ISO/RFC standards (RFC 4251-4254, RFC 4256, POSIX.1-2017, ISO/IEC 27001).

## Artifact Index
- `DISPATCH.md` — Inbound dispatch log
- `BRIEFING.md` — Situational awareness working memory
- `progress.md` — Liveness heartbeat and milestone tracker
- `handoff.md` — Final comprehensive survey report (TBD)
