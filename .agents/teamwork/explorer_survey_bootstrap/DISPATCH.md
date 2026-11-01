## 2026-10-27T19:51:45Z
Sender: 60991008-ad8c-4620-be18-d84298ed02f0
Priority: MESSAGE_PRIORITY_HIGH

You are an Explorer subagent for the Skulls-And-Bones project.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_bootstrap
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

Mission: Survey and investigate Requirement R2:
Automated Remote Server Bootstrapping (`sb node bootstrap <user@host>`).

Please perform an in-depth codebase and architecture survey covering:
1. `tools/sb-ssh`: Investigate current capabilities, client APIs, authentication mechanisms (password, key, agent, cert), SFTP file transfer capabilities, remote command execution, and session management.
2. `tools/sb-node`: What is the architecture of `sb-node`? Where are its config files, systemd unit files, runtime state, and CLI commands? How does a node register with the mesh?
3. Remote SSH & Linux Bootstrapping:
   - How to connect to a fresh Linux target via `sb-ssh`.
   - How to deploy `sb-node` binary and initial config via SFTP.
   - How to configure `/etc/ssh/sshd_config` with `TrustedUserCAKeys` and deploy `sb-ca`'s SSH CA public key safely (atomic write, validation, `systemctl reload sshd` / `service ssh reload`).
   - How to install and start `sb-node.service` via systemd.
   - How to handle permissions, idempotency, failure rollback, and sudo/root privileges.
4. CLI Integration: How `sb node bootstrap` should be integrated into the `sb` CLI (clap commands, flags like `--key`, `--port`, `--ca-key`, `--mesh-token`, `--force`, `--dry-run`).
5. Dynamic Threat Modeling & Security Hardening: Apply the user's mandatory rule for dynamic threat modeling (remote execution injection, credential leakage, SFTP path traversal, sshd lockout prevention, privilege escalation risks).

Output Requirements:
- Maintain your heartbeat in `progress.md` with `Last visited: [timestamp]`.
- Write your comprehensive, evidence-based survey and recommendations report to `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_bootstrap\handoff.md`.
- When finished, send a message to parent (60991008-ad8c-4620-be18-d84298ed02f0) with `send_message`.
