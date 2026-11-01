## 2026-10-27T22:08:37Z
You are explorer_m3_sshd_systemd.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m3_sshd_systemd
Read ORIGINAL_REQUEST.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
Read PROJECT.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md

Objective:
Investigate sshd CA configuration, systemd service setup, and security rollback for `sb node bootstrap`:
1. Design `/etc/ssh/trusted_user_ca_keys` and `/etc/ssh/sshd_config.d/99-sb-ca.conf` configuration using OpenSSH CA key from `sb-ca`.
2. Design safety rollback mechanism (`sshd -t` pre-validation before reloading `sshd`, auto-restoring backup on syntax error without dropping current session).
3. Design sandboxed systemd service `/etc/systemd/system/sb-node.service` and admin user creation (`sbadmin` with `visudo -cf`).
4. Design mesh onboarding step (`sb-node init --token <token>`).
Write your findings and recommended plan in handoff.md and send completion message to caller. Do NOT modify source code.
