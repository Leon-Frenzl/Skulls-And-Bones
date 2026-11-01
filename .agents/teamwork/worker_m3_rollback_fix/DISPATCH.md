## 2026-10-28T01:39:54Z
You are worker_m3_rollback_fix.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m3_rollback_fix
Workspace root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Mandatory input reports to read:
1. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
2. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\PROJECT.md
3. C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m3_r2_rollback\handoff.md

Write ownership:
You exclusively own: `tools/sb/src/commands/bootstrap.rs`.

Your task:
Apply the exact rollback hardening in `tools/sb/src/commands/bootstrap.rs`:
1. In backup snapshot creation (lines ~687-690):
   ```bash
   ([ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] || [ -L /etc/ssh/sshd_config.d/99-sb-ca.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf "${BACKUP_DIR}/" || true
   ([ -e /etc/ssh/sshd_config.d/99-sbm.conf ] || [ -L /etc/ssh/sshd_config.d/99-sbm.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sbm.conf "${BACKUP_DIR}/" || true
   ```
2. In `rollback.sh` (lines ~699-700):
   Explicitly remove existing destination drop-in symlinks before copying from `$B/`:
   ```bash
   rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf
   if [ -e "$B/99-sb-ca.conf" ] || [ -L "$B/99-sb-ca.conf" ]; then
       cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf
   fi
   rm -f /etc/ssh/sshd_config.d/99-sbm.conf
   if [ -e "$B/99-sbm.conf" ] || [ -L "$B/99-sbm.conf" ]; then
       cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf
   fi
   ```
3. Update unit test `test_generate_runner_script_contains_rollback_and_visudo` in `tools/sb/src/commands/bootstrap.rs` to match the updated rollback and backup syntax.
4. Run verification commands:
   - `cargo check --workspace` (0 errors, 0 warnings).
   - `cargo test -p sb-cli --bin sb commands::bootstrap`.
   - `cargo test -p sb-cli`.
5. Deliver handoff report at `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m3_rollback_fix\handoff.md`.
6. Send a completion message via send_message to orchestrator_3.
