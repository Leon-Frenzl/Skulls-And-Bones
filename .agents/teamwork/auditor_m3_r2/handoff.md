# Forensic Audit Report: Milestone 3 Remediation (`sb node bootstrap`)

**Work Product**: `tools/sb/src/commands/bootstrap.rs`  
**Profile**: General Project  
**Integrity Mode**: Development (from `ORIGINAL_REQUEST.md` lines 8 & 42)  
**Auditor**: `auditor_m3_r2` (forensic_auditor)  
**Parent / Caller**: `orchestrator_3` (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Verdict**: **CLEAN**

---

### Phase Results
- **Hardcoded test results**: **PASS** — Zero hardcoded test outputs or fake comparison mocks detected.
- **Facade implementations**: **PASS** — All functions implement genuine parsing, validation, cryptographic hashing, and process execution logic.
- **Pre-populated artifact detection**: **PASS** — No fake verification artifacts or pre-generated test logs exist in the repository.
- **Build and compilation check**: **PASS** — `cargo check --workspace --all-targets` completed cleanly with 0 errors and 0 warnings.
- **Unit test execution**: **PASS** — 15/15 unit tests in `commands::bootstrap` passed (100% pass rate in `sb-cli` suite of 100 tests).
- **Workspace test suite execution**: **PASS** — `cargo test --workspace` passed 100% across all crates with exit code 0.
- **Behavioral & Adversarial Verification**: **PASS** — Dry-run simulation and 5 injection attack vectors verified empirically.

---

## 1. Observation

Direct empirical observations from source analysis, compiler output, test execution, and runtime command testing:

### 1.1 Source Code Inspection (`tools/sb/src/commands/bootstrap.rs`)
1. **Password Redaction, Zeroization, and Child Environment Propagation**:
   - Lines 33–64: `SshTarget` contains `pub password: Option<String>`.
   - Lines 41–47: `Drop for SshTarget` invokes `pwd.zeroize()`.
   - Lines 49–62: `std::fmt::Debug for SshTarget` masks password with `[REDACTED]`.
   - Lines 172–174: In `SshTransport::exec`:
     ```rust
     if let Some(ref pwd) = self.target.password {
         cmd.env("SB_SSH_PASSWORD", pwd);
     }
     ```
   - Lines 213–215: In `SshTransport::upload`:
     ```rust
     if let Some(ref pwd) = self.target.password {
         cmd.env("SB_SSH_PASSWORD", pwd);
     }
     ```
   - Lines 864 & 1047–1051: `defer_zeroize(&mut args.password);` zeroizes CLI argument memory directly after target construction.

2. **Transport SFTP Upload Port Consistency**:
   - Lines 209: In `SshTransport::upload`:
     ```rust
     cmd.args(["-p", &self.target.port.to_string()]);
     ```
     Guarantees that `upload` targets the exact operator-configured port as `exec`.

3. **Input Validation and Metacharacter Sanitization**:
   - Lines 356–371 (`resolve_ca_public_key`): Enforces prefix `ssh-ed25519 AAA` (RFC 4251 wire format), forbids `'`, `"`, `\n`, `\r`, and restricts character set to `c.is_ascii_alphanumeric() || " +/=@.-_".contains(c)`.
   - Lines 409–437 (`resolve_pairing_token`): Requires `sbm-pair://` prefix, forbids `'`, `"`, `\n`, `\r`, restricts characters to base64 charset, and verifies token decoding via `crate::commands::fleet::parse_pairing_token`.
   - Lines 834–840 & 611–613: Mesh identifiers validated via `is_valid_nodename(m)` (`[a-zA-Z0-9_-]{1,63}`). Rejects spaces, quotes, and command separators.
   - Lines 333–342 (`validate_admin_username`): Rejects "root" (case-insensitive) and validates POSIX usernames up to 32 characters (`is_valid_username`).

4. **SSHD 99-sbm.conf Backup & Transactional Rollback**:
   - Lines 659–665:
     ```bash
     [ -f /etc/ssh/trusted_user_ca_keys ] && cp -a /etc/ssh/trusted_user_ca_keys "${BACKUP_DIR}/" || true
     [ -f /etc/ssh/revoked_keys ] && cp -a /etc/ssh/revoked_keys "${BACKUP_DIR}/" || true
     [ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf "${BACKUP_DIR}/" || true
     [ -e /etc/ssh/sshd_config.d/99-sbm.conf ] && cp -a /etc/ssh/sshd_config.d/99-sbm.conf "${BACKUP_DIR}/" || true
     [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ] && cp -a /etc/ssh/sshd_config.d/50-cloud-init.conf "${BACKUP_DIR}/" || true
     cp -a /etc/ssh/sshd_config "${BACKUP_DIR}/"
     ```
     Uses `[ -e ]` to support both regular files and symlinks.
   - Lines 666–678 (`rollback.sh`):
     ```bash
     [ -e "$B/99-sb-ca.conf" ] && cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf || rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf
     [ -e "$B/99-sbm.conf" ] && cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf || rm -f /etc/ssh/sshd_config.d/99-sbm.conf
     ```
     Both drop-ins are handled independently without short-circuiting: restores if pre-existing, deletes if created by bootstrap.

5. **Systemd Namespace Hardening**:
   - Line 549:
     ```ini
     ReadWritePaths=-/home/{admin_user}/.sb-mesh -/home/{admin_user}/.sb /run /tmp
     ```
     Prefixing with `-` informs systemd to ignore missing directories gracefully, preventing `status=226/NAMESPACE` startup crashes.

6. **Daemon Lifecycle Order**:
   - Lines 802–805 (Phase 6):
     ```bash
     if [ -x /usr/local/bin/sb-node ]; then
         sudo -u "$ADMIN" /usr/local/bin/sb-node init --token '{pairing_token}'
         systemctl restart sb-node 2>/dev/null || true
     fi
     ```
     Restarts `sb-node.service` post-initialization so the daemon adopts the freshly anchored credentials.

---

### 1.2 Tool Execution and Verification Outputs

1. **Compiler Workspace Check**:
   - Command: `cargo check --workspace --all-targets`
   - Result:
     ```text
     Checking sb-cli v0.2.1 (C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\tools\sb)
     Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.59s
     Exit Code: 0
     0 compiler errors, 0 compiler warnings.
     ```

2. **Bootstrap Unit Tests**:
   - Command: `cargo test -p sb-cli --bin sb commands::bootstrap`
   - Result:
     ```text
     running 15 tests
     test commands::bootstrap::tests::test_admin_username_validation ... ok
     test commands::bootstrap::tests::test_generate_sudoers_entry ... ok
     test commands::bootstrap::tests::test_generate_sshd_ca_config ... ok
     test commands::bootstrap::tests::test_generate_systemd_service ... ok
     test commands::bootstrap::tests::test_resolve_ca_public_key_format_validation ... ok
     test commands::bootstrap::tests::test_generate_runner_script_contains_rollback_and_visudo ... ok
     test commands::bootstrap::tests::test_ssh_target_parsing_rejects_injection ... ok
     test commands::bootstrap::tests::test_ssh_target_parsing_valid ... ok
     test commands::bootstrap::tests::test_ssh_target_password_redaction_and_zeroize ... ok
     test commands::bootstrap::tests::test_resolve_pairing_token_validation ... ok
     test commands::bootstrap::tests::test_cli_backward_compatibility_node_empty ... ok
     test commands::bootstrap::tests::test_cli_backward_compatibility_node_external ... ok
     test commands::bootstrap::tests::test_cli_parsing_node_bootstrap_dry_run ... ok
     test commands::bootstrap::tests::test_cli_parsing_node_bootstrap_with_flags ... ok
     test commands::bootstrap::tests::test_mesh_name_validation ... ok

     test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 85 filtered out; finished in 0.01s
     Exit Code: 0
     ```

3. **Full `sb-cli` Crate Test Suite**:
   - Command: `cargo test -p sb-cli`
   - Result:
     ```text
     test result: ok. 100 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.44s
     Exit Code: 0
     ```

4. **Workspace Wide Test Suite**:
   - Command: `cargo test --workspace`
   - Result:
     ```text
     All member crate test targets (sb-app-contract, sb-app-protocol, sb-auth, sb-ca, sb-code, sb-core, sb-db, sb-dns, sb-drive, sb-key, sb-mesh, sb-proxy, sb-cli) passed 100%.
     Exit Code: 0
     ```

5. **Dry-Run Simulation**:
   - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run`
   - Result:
     ```text
     Finished `dev` profile in 0.47s
     Exit Code: 0
     Output rendered full 6-phase execution plan:
     Target: root@145.223.83.235
     Port: 22
     Admin User: sbadmin
     Node Callsign: hostinger-node
     Mesh Domain: hostinger-node.sbm
     Swarm CA Key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAjA51B9II/eOjzTSPZz0YGYltunV5Tznfshdp4519Oh sovereign-swarm-ca@local
     Pairing Token: sbm-pair://eyJjYV9wdWJsaWNfa...
     ✓ Dry-run completed successfully. No remote changes were made.
     ```

6. **Adversarial Injection Stress-Tests**:
   - Mesh Injection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m 'dev"; rm -rf /; echo "' --dry-run`
     -> Exit Code: 1
     -> Output: `Fehler beim Node-Bootstrap: Ungültiger Mesh-Name: 'dev; rm -rf /; echo ' (nur a-z, 0-9, _, - bis max. 63 Zeichen)`
   - CA Key Injection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA'; id; echo '" --dry-run`
     -> Exit Code: 1
     -> Output: `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen oder Zeilenumbrüche (RFC 4251 / OpenSSH Format erforderlich).`
   - Pairing Token Injection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://abc'; id; echo '" --dry-run`
     -> Exit Code: 1
     -> Output: `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Enthält unzulässige Metazeichen oder Zeilenumbrüche.`
   - Admin Root Rejection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin root --dry-run`
     -> Exit Code: 1
     -> Output: `Fehler beim Node-Bootstrap: Der dedizierte Admin-Benutzer darf nicht 'root' sein (Least-Privilege-Prinzip).`
   - Target User Injection: `cargo run -p sb-cli -- node bootstrap "root; id@145.223.83.235" --dry-run`
     -> Exit Code: 1
     -> Output: `Fehler beim Node-Bootstrap: Ungültiger Initial-Benutzername: 'root; id'`
   - Port 0 Rejection: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -p 0 --dry-run`
     -> Exit Code: 1
     -> Output: `Fehler beim Node-Bootstrap: Ungültiger SSH-Port: 0`

---

## 2. Logic Chain

1. **Integrity Mode Conformance**:
   `ORIGINAL_REQUEST.md` (lines 8 & 42) explicitly defines `Integrity mode: development`. Under Development Mode, the forensic rules prohibit hardcoded outputs, fake mocks, facades, and fabricated artifacts. Code reuse and external tool delegation for auxiliary tasks are permitted.
2. **Authenticity of Implementation**:
   Source code review confirms that `tools/sb/src/commands/bootstrap.rs` contains zero stubs, zero dummy return constants, and zero mock files. Every function implements genuine cryptographic validation, input sanitation, bash script generation, or process management.
3. **Remediation Verification**:
   - *Password Propagation & Sanitization*: Handled via `Option<String>`, zeroized on `Drop` and in CLI parsing (`defer_zeroize`), masked as `[REDACTED]` in `Debug`, and forwarded cleanly to child process environment `SB_SSH_PASSWORD`.
   - *SFTP Upload Port*: Propagates `-p <port>` explicitly to `sb-ssh push`.
   - *Command Injection Prevention*: Strict allowlists and schema enforcement on all parameters (`--mesh`, `--ca-key`, `--mesh-token`, `--admin`, target) eliminate shell metacharacter injection.
   - *SSHD Rollback*: Uses `[ -e ]` and avoids short-circuiting, ensuring both `99-sb-ca.conf` and `99-sbm.conf` are safely backed up and restored/pruned.
   - *Systemd Hardening*: Prefixes `ReadWritePaths` with `-` to eliminate namespace startup failures.
   - *Daemon Restart*: Re-triggers `systemctl restart sb-node` following `sb-node init --token`.
4. **Empirical Quality Gate Status**:
   `cargo check --workspace --all-targets` verified 0 errors and 0 warnings. `cargo test --workspace` and `cargo test -p sb-cli` passed 100%. All adversarial injections fail closed.
5. **Conclusion**:
   The work product satisfies all forensic integrity checks and acceptance criteria.

---

## 3. Caveats

- Live deployment against `145.223.83.235` was not executed during this local forensic audit, as live target deployment is assigned to Milestone 5 in `PROJECT.md`.
- No other caveats.

---

## 4. Conclusion

The remediated Milestone 3 implementation in `tools/sb/src/commands/bootstrap.rs` is **genuine, robust, and clean of integrity violations**. All 6 reported findings from iteration 1 have been completely resolved with authentic logic and thorough unit test coverage.

**Forensic Verdict**: **CLEAN**

---

## 5. Verification Method

To independently reproduce this verification:

1. **Verify Workspace Cleanliness (0 errors, 0 warnings)**:
   ```powershell
   cargo check --workspace --all-targets
   ```
2. **Execute Bootstrap Unit Tests**:
   ```powershell
   cargo test -p sb-cli --bin sb commands::bootstrap
   ```
3. **Execute Full CLI Test Suite**:
   ```powershell
   cargo test -p sb-cli
   ```
4. **Execute Workspace Test Suite**:
   ```powershell
   cargo test --workspace
   ```
5. **Execute Dry-Run Simulation**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
6. **Execute Adversarial Stress-Tests**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m 'dev"; rm -rf /; echo "' --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA'; id; echo '" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://abc'; id; echo '" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin root --dry-run
   cargo run -p sb-cli -- node bootstrap "root; id@145.223.83.235" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -p 0 --dry-run
   ```
