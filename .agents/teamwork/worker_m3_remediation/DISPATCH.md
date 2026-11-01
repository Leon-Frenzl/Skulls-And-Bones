## 2026-10-28T01:21:27Z
You are worker_m3_remediation.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m3_remediation
Workspace root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Mandatory input reports to read:
1. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
2. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\PROJECT.md
3. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\reviewer_m3_conformance_gen3\handoff.md
4. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\reviewer_m3_security_gen3\handoff.md
5. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m3_rollback_gen3\handoff.md

Write ownership:
You exclusively own: `tools/sb/src/commands/bootstrap.rs`.

Your tasks:
Remediate all issues identified during Milestone 3 Gate Iteration 1:
1. **Password Propagation to `sb-ssh`**:
   - In `SshTarget`, store `pub password: Option<String>`. Ensure password memory is zeroized or sanitized where appropriate.
   - In `SshTransport::exec` and `SshTransport::upload`, when password is present, pass `cmd.env("SB_SSH_PASSWORD", pwd)`.
2. **SFTP Upload Port Flag**:
   - In `SshTransport::upload`, pass `cmd.args(["-p", &self.target.port.to_string()])` before `push`.
3. **Shell Metacharacter Validation & Sanitization**:
   - In `resolve_ca_public_key`, verify that the key does NOT contain single quotes (`'`) or newlines (`\n`, `\r`), and that all characters conform to RFC 4251 base64 / OpenSSH characters (`[a-zA-Z0-9+/=@.-_ ]`).
   - In `resolve_pairing_token`, verify that user-provided token does NOT contain single quotes (`'`) or newlines, and conforms to valid pairing token format (`sbm-pair://...`).
   - In `handle_node_bootstrap`, validate each mesh name in `args.mesh` against `is_valid_nodename(m)` (alphanumeric, hyphen, underscore, 1..63 chars) and reject injection strings.
4. **SSHD 99-sbm.conf Backup & Rollback Fix**:
   - In backup creation, back up both `99-sb-ca.conf` and `99-sbm.conf`:
     `[ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf "${BACKUP_DIR}/" || true`
     `[ -e /etc/ssh/sshd_config.d/99-sbm.conf ] && cp -a /etc/ssh/sshd_config.d/99-sbm.conf "${BACKUP_DIR}/" || true`
   - In `rollback.sh`, avoid short-circuit data loss or symlink leak:
     `[ -e "$B/99-sb-ca.conf" ] && cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf || rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf`
     `[ -e "$B/99-sbm.conf" ] && cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf || rm -f /etc/ssh/sshd_config.d/99-sbm.conf`
5. **Systemd Unit Hardening**:
   - In `generate_systemd_service`, prefix dynamic user paths with `-`:
     `ReadWritePaths=-/home/{admin_user}/.sb-mesh -/home/{admin_user}/.sb /run /tmp`
6. **Daemon Lifecycle Order**:
   - In `generate_runner_script`, after Phase 6 executes `sb-node init --token`, restart the daemon (`systemctl restart sb-node || true`) so it runs with the initialized swarm configuration.
7. **Comprehensive Unit Tests**:
   - Add unit tests in `commands/bootstrap.rs` covering rejection of invalid `--mesh`, invalid `--ca-key`, and invalid `--mesh-token`, as well as testing the new backup/rollback script and systemd unit strings.
8. **Verification**:
   - Run `cargo check --workspace` (0 errors, 0 warnings).
   - Run `cargo test -p sb-cli --bin sb commands::bootstrap`.
   - Run `cargo test -p sb-cli`.
   - Run `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run`.
9. Deliver full handoff report at `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m3_remediation\handoff.md`.
10. Send a completion message via send_message to orchestrator_3.
