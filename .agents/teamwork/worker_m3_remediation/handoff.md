# Handoff Report: Milestone 3 Gate Remediation (`sb node bootstrap`)

**Author:** `worker_m3_remediation` (implementer, qa, specialist)  
**Parent / Caller:** `orchestrator_3` (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Scope:** Milestone 3 Provisioning Pipeline Remediation (`tools/sb/src/commands/bootstrap.rs`)  
**Date:** 2026-10-28T01:32:00Z  
**Verdict:** **RESOLVED / READY FOR RE-EVALUATION**

---

## 1. Observation

Direct observations from source inspection, compilation, test execution, and adversarial verification:

### 1.1 Remediation Actions in `tools/sb/src/commands/bootstrap.rs`

1. **Password Storage, Redaction, and Propagation (Finding 1 / CWE-684 / CWE-532)**:
   - In `SshTarget` (lines 33–64):
     Added `pub password: Option<String>`.
     Implemented `Drop for SshTarget` executing `pwd.zeroize()` on drop.
     Implemented custom `std::fmt::Debug for SshTarget` redacting cleartext password to `[REDACTED]`.
     Updated `SshTarget::parse` to take `password: Option<String>`.
   - In `SshTransport::exec` (lines 191–193) and `SshTransport::upload` (lines 235–237):
     ```rust
     if let Some(ref pwd) = self.target.password {
         cmd.env("SB_SSH_PASSWORD", pwd);
     }
     ```
     Password is now securely exported to the child process environment for `sb-ssh`.
   - In `handle_node_bootstrap` (line 881):
     `defer_zeroize(&mut args.password);` zeroizes the CLI argument memory immediately after constructing `target`.

2. **SFTP Upload Port Flag (Finding 2 / CWE-20)**:
   - In `SshTransport::upload` (line 229):
     Added `cmd.args(["-p", &self.target.port.to_string()]);` prior to `push`.
     Both `exec` and `upload` now target the identical, operator-configured port.

3. **Shell Metacharacter Validation & Sanitization (Finding 3 / SEC-1, SEC-2, SEC-3 / CWE-78 / CWE-116)**:
   - In `resolve_ca_public_key` (lines 388–424):
     Enforces prefix `ssh-ed25519 AAA` (RFC 4251 wire format).
     Explicitly rejects newlines (`\n`, `\r`) and quotes (`'`, `"`).
     Restricts all characters to base64 / OpenSSH charset: `c.is_ascii_alphanumeric() || " +/=@.-_".contains(c)`.
     Validates both user-supplied arguments and internally resolved Swarm-CA keys.
   - In `resolve_pairing_token` (lines 440–484):
     Changed signature to `Result<String, String>`.
     Explicitly rejects `'`, `"`, `\n`, `\r`.
     Enforces schema prefix `sbm-pair://` and validates payload charset against `[a-zA-Z0-9+/=-_]`.
     Validates structure via `crate::commands::fleet::parse_pairing_token`.
   - In `handle_node_bootstrap` (lines 855–863) and `generate_runner_script` (lines 639–642):
     Validates every mesh name in `args.mesh` against `is_valid_nodename(m)` (`[a-zA-Z0-9_-]{1,63}`).
     Rejects unescaped quotes, semicolons, and spaces immediately with error exit code 1.

4. **SSHD 99-sbm.conf Backup & Rollback Fix (Finding 4 / BUG-M3-01 / BUG-M3-02 / CWE-404 / CWE-459)**:
   - In backup snapshot creation (lines 687–690):
     ```bash
     [ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf "${BACKUP_DIR}/" || true
     [ -e /etc/ssh/sshd_config.d/99-sbm.conf ] && cp -a /etc/ssh/sshd_config.d/99-sbm.conf "${BACKUP_DIR}/" || true
     ```
     Uses `[ -e ]` to support both regular files and symlinks.
   - In `rollback.sh` (lines 699–700):
     ```bash
     [ -e "$B/99-sb-ca.conf" ] && cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf || rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf
     [ -e "$B/99-sbm.conf" ] && cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf || rm -f /etc/ssh/sshd_config.d/99-sbm.conf
     ```
     Eliminates short-circuiting: restores `99-sbm.conf` if pre-existing (preventing eviction list data loss), and removes `99-sbm.conf` if created during bootstrap (preventing symlink leak).

5. **Systemd Unit Hardening (Finding 5 / BUG-M3-04)**:
   - In `generate_systemd_service` (line 578):
     Updated to:
     `ReadWritePaths=-/home/{admin_user}/.sb-mesh -/home/{admin_user}/.sb /run /tmp`
     Prefixing dynamic user paths with `-` prevents systemd startup failure (`status=226/NAMESPACE`) if user directories are created asynchronously or missing.

6. **Daemon Lifecycle Order (Finding 6)**:
   - In `generate_runner_script` Phase 6 (lines 823–826):
     ```bash
     if [ -x /usr/local/bin/sb-node ]; then
         sudo -u "$ADMIN" /usr/local/bin/sb-node init --token '{pairing_token}'
         systemctl restart sb-node 2>/dev/null || true
     fi
     ```
     After initializing credentials and callsign via `sb-node init`, restarts `sb-node.service` so the daemon runs with full swarm connectivity.

### 1.2 Verification Outputs

1. **Compilation (`cargo check --workspace`)**:
   ```text
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.65s
   0 compiler errors, 0 compiler warnings.
   ```

2. **Bootstrap Unit Tests (`cargo test -p sb-cli --bin sb commands::bootstrap`)**:
   ```text
   running 15 tests
   test commands::bootstrap::tests::test_admin_username_validation ... ok
   test commands::bootstrap::tests::test_generate_sudoers_entry ... ok
   test commands::bootstrap::tests::test_generate_sshd_ca_config ... ok
   test commands::bootstrap::tests::test_generate_systemd_service ... ok
   test commands::bootstrap::tests::test_resolve_ca_public_key_format_validation ... ok
   test commands::bootstrap::tests::test_ssh_target_parsing_rejects_injection ... ok
   test commands::bootstrap::tests::test_generate_runner_script_contains_rollback_and_visudo ... ok
   test commands::bootstrap::tests::test_ssh_target_parsing_valid ... ok
   test commands::bootstrap::tests::test_ssh_target_password_redaction_and_zeroize ... ok
   test commands::bootstrap::tests::test_resolve_pairing_token_validation ... ok
   test commands::bootstrap::tests::test_cli_backward_compatibility_node_external ... ok
   test commands::bootstrap::tests::test_cli_backward_compatibility_node_empty ... ok
   test commands::bootstrap::tests::test_cli_parsing_node_bootstrap_dry_run ... ok
   test commands::bootstrap::tests::test_cli_parsing_node_bootstrap_with_flags ... ok
   test commands::bootstrap::tests::test_mesh_name_validation ... ok

   test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 85 filtered out; finished in 0.01s
   ```

3. **Workspace Suite (`cargo test -p sb-cli`)**:
   ```text
   test result: ok. 100 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.78s
   ```

4. **Dry-Run Simulation**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
   Output: Exit code 0, complete 6-phase plan rendered with Swarm-CA key, pairing token, and valid parameters.

5. **Adversarial Injection CLI Verification**:
   - Mesh injection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m 'dev"; rm -rf /; echo "' --dry-run`  
     -> Exit code 1: `Fehler beim Node-Bootstrap: Ungültiger Mesh-Name: 'dev; rm -rf /; echo ' (nur a-z, 0-9, _, - bis max. 63 Zeichen)`
   - CA Key injection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA'; id; echo '" --dry-run`  
     -> Exit code 1: `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen oder Zeilenumbrüche (RFC 4251 / OpenSSH Format erforderlich).`
   - Token injection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://abc'; id; echo '" --dry-run`  
     -> Exit code 1: `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Enthält unzulässige Metazeichen oder Zeilenumbrüche.`

---

## 2. Logic Chain

1. **Premise 1 (Credential Flow to Transport Subprocess)**:
   `sb-ssh` relies on the `SB_SSH_PASSWORD` environment variable to authenticate without interactive terminal prompts. By adding `password` to `SshTarget`, passing `cmd.env("SB_SSH_PASSWORD", pwd)` in both `exec` and `upload`, and zeroizing password memory on Drop, headless password authentication to fresh Linux VPS instances functions seamlessly while adhering to credential hygiene (CWE-316, CWE-532).

2. **Premise 2 (Consistent Transport Port Resolution)**:
   Passing `-p <port>` to `sb-ssh push` ensures that SFTP upload connects to the identical non-standard SSH port as `exec`, preventing connection timeouts or refused connections on port 22.

3. **Premise 3 (Trust Boundary Invariant in Script Templating)**:
   All values interpolated into `runner.sh` (`--ca-key`, `--mesh-token`, `--mesh`) are untrusted inputs crossing into a root shell execution context. Validating character allow-lists and schema prefixes before script generation eliminates command injection (CWE-78 / CWE-116).

4. **Premise 4 (Non-Destructive and Leak-Free Rollback)**:
   By backing up `99-sbm.conf` and handling both `99-sb-ca.conf` and `99-sbm.conf` independently via `[ -e ]` without short-circuiting, pre-existing configuration (e.g. `DenyUsers` eviction lists) is preserved on failure, and created symlinks are destroyed if the transaction aborts.

5. **Premise 5 (Service Sandboxing Resilience and Lifecycle Consistency)**:
   Prefixing `ReadWritePaths=` with `-` protects systemd against `status=226/NAMESPACE` startup crashes if paths do not yet exist. Restarting the daemon after `sb-node init --token` guarantees that the service runs with bound swarm credentials.

6. **Conclusion**:
   All 6 functional, security, and rollback issues identified across all three reviewer reports have been fully resolved with zero regressions.

---

## 3. Caveats

- Live deployment against `145.223.83.235` was not run during this remediation step, as live target verification is assigned to Milestone 5 in `PROJECT.md`.
- No other caveats.

---

## 4. Conclusion

All defects and vulnerability vectors identified during Milestone 3 Gate Iteration 1 have been completely remediated in `tools/sb/src/commands/bootstrap.rs`:
- Password propagation and redaction: **RESOLVED**
- SFTP upload custom port: **RESOLVED**
- Shell injection in `--mesh`, `--ca-key`, and `--mesh-token`: **RESOLVED**
- SSHD `99-sbm.conf` backup and rollback: **RESOLVED**
- Systemd `ReadWritePaths` namespace hardening: **RESOLVED**
- Daemon restart post-onboarding: **RESOLVED**
- Comprehensive unit tests: **15/15 PASS (100/100 in suite)**
- Clean workspace: **0 errors, 0 warnings**

**Verdict: RESOLVED / READY FOR RE-EVALUATION**

---

## 5. Verification Method

To independently verify the remediations:

1. **Clean Workspace Check**:
   ```powershell
   cargo check --workspace
   ```
   *Expected outcome*: 0 errors, 0 warnings.

2. **Run Bootstrap Unit Tests**:
   ```powershell
   cargo test -p sb-cli --bin sb commands::bootstrap
   ```
   *Expected outcome*: 15 passed, 0 failed.

3. **Run Full `sb-cli` Suite**:
   ```powershell
   cargo test -p sb-cli
   ```
   *Expected outcome*: 100 passed, 0 failed.

4. **Dry-Run Simulation**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
   *Expected outcome*: Exit code 0 with full 6-phase plan.

5. **Adversarial Injection Checks**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m 'dev"; rm -rf /; echo "' --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA'; id; echo '" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://abc'; id; echo '" --dry-run
   ```
   *Expected outcome*: Each command exits with code 1 and a descriptive rejection message.
