# BRIEFING — 2026-10-27T22:15:30Z

## Mission
Investigate sshd CA configuration, systemd service setup, and security rollback for `sb node bootstrap` in Milestone 3, producing an architectural design and handoff report.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigator, analyzer, synthesizer
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m3_sshd_systemd
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: M3 (Node Bootstrap & SSH CA Integration)

## 🔒 Key Constraints
- Read-only investigation — do NOT modify source code
- Standards compliance (RFC 4251, PROTOCOL.certkeys, POSIX, systemd security standards)
- Threat modeling on every critical function/step (CWE mapping, risk score, hardening)
- Deliver self-contained handoff.md with 5 components (Observation, Logic Chain, Caveats, Conclusion, Verification Method)
- Communicate via send_message to caller 60991008-ad8c-4620-be18-d84298ed02f0

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: 2026-10-27T22:15:30Z

## Investigation State
- **Explored paths**:
  - `tools/sb-ca/src/ssh/`: Root CA key generation, `ca_public_key_openssh()`, RFC 4251 / PROTOCOL.certkeys export.
  - `tools/sb/src/commands/fleet.rs`: `build_pairing_token()`, `parse_pairing_token()`, legacy `server init` script payload.
  - `tools/sb/src/commands/provision.rs`: `generate_provision_script()`, systemd unit generation, pubkey validation.
  - `tools/sb-node/src/main.rs`: `handle_init(token)`, SinglePortDispatcher UDP 58888 listener, `handle_revoke(name)` expecting `/etc/ssh/sshd_config.d/99-sbm.conf`.
  - `docs/DEV_SERVER_SETUP.md`: Server target environment, Ubuntu LTS, systemd sandboxing.
- **Key findings**:
  1. `sb_ca::ssh::ca_public_key_openssh()` provides wire-format Ed25519 public key line for `/etc/ssh/trusted_user_ca_keys`.
  2. Legacy code used `99-sbm.conf`, but prompt specifies `99-sb-ca.conf`. Creating a symlink `99-sbm.conf -> 99-sb-ca.conf` ensures backwards-compatibility with `sb-node revoke` which writes to `99-sbm.conf`.
  3. Pre-flight `sshd -t` test + atomic staging directory snapshot prevents permanent VPS lockout. Graceful `reload` (SIGHUP) must be used rather than `restart`.
  4. Sudoers file `/etc/sudoers.d/90-sb-$ADMIN` must be pre-validated via `visudo -cf` on a temporary file before atomic move with mode `0440`.
  5. `sb-node.service` runs unprivileged as `User=sbadmin` with strict sandboxing (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=...`, `CapabilityBoundingSet=`).
  6. `sb-node init --token <token>` must be run under `sudo -u sbadmin` to prevent permission corruption in `~/.sb` and `~/.sb-mesh`.
- **Unexplored areas**: None for M3 sshd/systemd scope; ready to formulate handoff report.

## Key Decisions Made
- Architecture follows 4 modular blocks: (1) CA Anchoring, (2) Safety Rollback, (3) Sandboxed systemd & Admin User, (4) Mesh Onboarding.
- Full compatibility bridge for `99-sb-ca.conf` and `99-sbm.conf`.
- SIGHUP reload with automatic restore on `sshd -t` failure.
- In-code threat models covering CWE-78, CWE-269, CWE-276, CWE-440, CWE-755, and CWE-250.

## Artifact Index
- DISPATCH.md — incoming instructions
- progress.md — liveness heartbeat
- BRIEFING.md — working memory
- handoff.md — comprehensive 5-component handoff report
