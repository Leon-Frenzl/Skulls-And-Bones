# Adversarial Security Review & Handoff Report: Milestone 3 (`sb node bootstrap`)

**Reviewer:** `reviewer_m3_security_gen3` (reviewer, critic)  
**Parent / Caller:** `orchestrator_3` (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Scope:** Milestone 3 Provisioning Pipeline (`tools/sb/src/commands/bootstrap.rs`, `tools/sb/src/cli.rs`, `tools/sb/src/main.rs`)  
**Date:** 2026-10-28T01:20:00Z  
**Verdict:** `REQUEST_CHANGES`

---

## Review Summary

**Verdict**: `REQUEST_CHANGES`

While the core provisioning architecture, SSHD transactional safety, systemd sandboxing, and SFTP defect mitigation demonstrate genuine engineering and strict standards compliance (zero integrity violations or facades detected), an adversarial code audit discovered **three command injection / argument injection vulnerabilities (CWE-78 / CWE-20)** in the remote root runner script generation. Specifically, unvalidated CLI arguments passed to `--mesh`, `--ca-key`, and `--mesh-token` can break out of string quotation in the dynamically generated `/tmp/.sb-staging-*/runner.sh` script, leading to arbitrary remote command execution as root.

Remediation is straightforward and concrete code patches are provided below.

---

## 1. Observation

Direct observations from source inspection, compilation, test execution, and adversarial analysis:

### 1.1 Integrity & Facade Verification
1. **Source Inspection (`tools/sb/src/commands/bootstrap.rs`, lines 1–1147)**:
   - Full 1,147 lines of functional Rust code.
   - Genuine execution logic: child processes invoked via `std::process::Command`, real cryptographic operations via `sha2::Sha256` and `hex`, genuine staging directory generation via `rand::random::<u128>()` with mode 0700.
   - Tests (lines 958–1146): 12 unit tests exercising parsing, validation, injection rejection, sshd config formatting, systemd unit generation, rollback script generation, and Clap dispatch.
   - **Result**: No hardcoded test stubs, no facade implementations, no shortcuts, no fabricated verification logs. **INTEGRITY CHECK PASSED (NO VIOLATION)**.

### 1.2 Build & Test Verification
1. **Compilation**:
   ```powershell
   cargo check --workspace
   ```
   *Result*: `Finished dev profile [unoptimized + debuginfo] target(s) in 0.60s` (0 errors, 0 warnings).

2. **Target Test Execution**:
   ```powershell
   cargo test -p sb-cli --bin sb commands::bootstrap
   ```
   *Result*: `12 passed; 0 failed; 0 ignored; 0 measured; 85 filtered out; finished in 0.01s`.
   *(Note: The command suggested in the dispatch and worker handoff was `cargo test -p sb-cli --lib commands::bootstrap`, which returns `error: no library targets found in package 'sb-cli'` because `sb-cli` defines only `[[bin]] name = "sb"` in `tools/sb/Cargo.toml`)*.

3. **Workspace Full Test Suite (`sb-cli`)**:
   ```powershell
   cargo test -p sb-cli
   ```
   *Result*: `97 passed; 0 failed; 0 ignored; 0 measured; finished in 6.68s`.

4. **Dry-Run Simulation**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
   *Result*: Exit code 0, outputs structured 6-phase execution plan and configurations without making remote mutations.

### 1.3 SSHD Transactional Safety & Rollback Verification
1. **Initial Baseline Probe (`bootstrap.rs:560-564`)**:
   ```bash
   if ! sshd -t >/dev/null 2>&1; then
       echo "[SB-ERROR] Pre-existing SSHD configuration is invalid! Aborting to prevent lockout." >&2
       sshd -t
       exit 1
   fi
   ```
   Fails closed prior to modifying any configuration files.

2. **Atomic Backup & Rollback Script (`bootstrap.rs:574-596`)**:
   - `BACKUP_DIR="/etc/ssh/.sb-backup-${TX_ID}"` with mode 0700.
   - Backs up: `trusted_user_ca_keys`, `revoked_keys`, `99-sb-ca.conf`, `50-cloud-init.conf`, and `sshd_config`.
   - `rollback.sh` restores original files, removes drop-ins if they were absent, and issues SIGHUP reload (`systemctl reload ssh || systemctl reload sshd || service ssh reload || service sshd reload`).
   - Active shell trap: `trap '... sh "${BACKUP_DIR}/rollback.sh"; rm -rf "${BACKUP_DIR}"; exit 1' ERR INT TERM`.

3. **Pre-Validation & SIGHUP Reload (`bootstrap.rs:632-644`)**:
   - Drops in `/etc/ssh/sshd_config.d/99-sb-ca.conf` and creates eviction link `/etc/ssh/sshd_config.d/99-sbm.conf`.
   - Pre-validation check: `if ! sshd -t; then sh "${BACKUP_DIR}/rollback.sh"; rm -rf "${BACKUP_DIR}"; exit 1; fi`.
   - SIGHUP reload semantics (`systemctl reload ssh || systemctl reload sshd`). Ensures existing SSH sessions remain open without connection drop.

### 1.4 Dedicated Admin User & Sudoers Hardening Verification
1. **Root Rejection (`bootstrap.rs:296-306`)**:
   `validate_admin_username` rejects "root" (case-insensitive) and validates `is_valid_username` (`[a-zA-Z0-9_-]{1,32}`).
2. **Sudoers Staging & visudo Validation (`bootstrap.rs:669-683`)**:
   - Staged to `/etc/sudoers.d/90-sb-${ADMIN}.tmp.$$` with mode 0440.
   - Validated via `visudo -cf "$SUDOERS_TMP"`.
   - Atomic replacement via `mv -f "$SUDOERS_TMP" "$SUDOERS_FILE"` with mode 0440.
3. **Break-Glass Key Preservation (`bootstrap.rs:662-666`)**:
   Preserves `/root/.ssh/authorized_keys` to `/home/$ADMIN/.ssh/authorized_keys` (mode 0600) only if empty or missing.

### 1.5 Systemd Sandboxing Verification (`bootstrap.rs:425-475`)
1. Adheres to CIS Linux Benchmark Level 2 / BSI IT-Grundschutz SYS.1.1:
   - `User={admin_user}`, `Group={admin_user}`, `WorkingDirectory=/home/{admin_user}`.
   - `NoNewPrivileges=yes`.
   - `ProtectSystem=strict`.
   - `ProtectHome=read-only`.
   - `PrivateTmp=yes`, `PrivateDevices=yes`.
   - `CapabilityBoundingSet=` (drops all capabilities; port 58888 is unprivileged >= 1024).
   - `AmbientCapabilities=`.
   - `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`.
   - `RestrictSUIDSGID=yes`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`.
   - `ReadWritePaths=/home/{admin_user}/.sb-mesh /home/{admin_user}/.sb /run /tmp`.

### 1.6 SFTP Defect Compensation Verification (`bootstrap.rs:160-240`)
1. Mitigates `sb-ssh push` exit code 0 defect:
   - Evaluates process status `!output.status.success()`.
   - Scans stderr for error keywords: `"Upload-Fehler"`, `"Fehler"`, `"failed"`.
   - Independent remote existence probe: `self.exec(&format!("test -s '{remote_path}'"))`.
   - Cryptographic verification (`upload_and_verify`): Computes local `Sha256`, runs remote `sha256sum '{remote_path}' | awk '{print $1}'`, and asserts bitwise equality.

### 1.7 Adversarial Vulnerability Findings (Shell Injection Vectors)
1. **Vulnerability SEC-1 (`bootstrap.rs:531-537`)**:
   ```rust
   for m in &meshes {
       mesh_cmds.push_str(&format!(
           "if [ -x /usr/local/bin/sb-mesh ]; then\n\
            \x20   sudo -u \"{admin_user}\" /usr/local/bin/sb-mesh bootstrap --headless -n \"{m}\" -a \"127.0.0.1:58888\" 2>/dev/null || true\n\
            fi\n"
       ));
   }
   ```
   `args.mesh` is taken directly from CLI flag `--mesh` without validating each element against `is_valid_nodename(m)`. If an operator or automated caller supplies `--mesh 'dev" || touch /tmp/pwned || echo "'`, the unescaped double quotes allow arbitrary root command execution when `bash runner.sh` executes.

2. **Vulnerability SEC-2 (`bootstrap.rs:320-326`, `bootstrap.rs:617-619`)**:
   ```rust
   pub fn resolve_ca_public_key(ca_key_arg: Option<&str>) -> Result<String, String> {
       if let Some(key) = ca_key_arg {
           let trimmed = key.trim();
           if !trimmed.starts_with("ssh-ed25519 AAA") {
               return Err("Ungültiger Swarm-CA Key: Muss mit 'ssh-ed25519 AAA' beginnen (RFC 4251 Wire Format).".to_string());
           }
           return Ok(trimmed.to_string());
       }
   ...
   ```
   And in `generate_runner_script`:
   ```bash
   if ! grep -qxF '{ca_pubkey}' /etc/ssh/trusted_user_ca_keys 2>/dev/null; then
       echo '{ca_pubkey}' >> /etc/ssh/trusted_user_ca_keys
   fi
   ```
   `resolve_ca_public_key` only checks `starts_with("ssh-ed25519 AAA")`. It does not check for single quotes `'`, newlines `\n`, or illegal characters. An attacker providing `--ca-key "ssh-ed25519 AAA'; id; echo '"` escapes the single quotes in the bash script and executes commands as root.

3. **Vulnerability SEC-3 (`bootstrap.rs:361-367`, `bootstrap.rs:720`)**:
   ```rust
   pub fn resolve_pairing_token(token_arg: Option<&str>, node_name: &str, ca_pubkey: &str) -> String {
       if let Some(token) = token_arg {
           token.trim().to_string()
       } else { ... }
   }
   ```
   And in `generate_runner_script`:
   ```bash
   if [ -x /usr/local/bin/sb-node ]; then
       sudo -u "$ADMIN" /usr/local/bin/sb-node init --token '{pairing_token}'
   fi
   ```
   `token_arg` from CLI `--mesh-token` has zero character or structure validation. If it contains `'` (e.g. `sbm-pair://...'; reboot; echo '`), it breaks out of the argument boundary in the remote script.

---

## 2. Logic Chain

1. **Premise 1 (Integrity & Core Correctness)**:
   Observations 1.1–1.6 demonstrate that `worker_m3_bootstrap` implemented the required 6-phase bootstrapping pipeline thoroughly, including backward compatibility, atomic SSHD rollback, sudoers staging via `visudo -cf`, systemd sandboxing, and SFTP defect mitigation. All 12 new unit tests and 97 suite tests pass.
2. **Premise 2 (Trust Boundaries in Remote Script Generation)**:
   The provisioning architecture writes a shell script (`runner.sh`) that is executed remotely with root privileges (`bash runner.sh`). Under dynamic threat modeling (CWE-78 / CWE-20), all values interpolated into this template must be treated as untrusted data crossing a trust boundary.
3. **Premise 3 (Command Injection Blast Radius)**:
   While `args.admin` is strictly validated (`is_valid_username`), Observation 1.7 proves that `args.mesh`, `args.ca_key`, and `args.mesh_token` are not sanitized or whitelisted before interpolation into shell execution contexts. Because the script executes as root, any breakout allows arbitrary command execution on the target server.
4. **Conclusion**:
   The implementation is 95% complete and of high quality, but contains three actionable command injection vulnerabilities that must be hardened before this pipeline can be approved for live target deployment in Milestone 5.

---

## 3. Findings & Required Changes

### [Major / Security] SEC-1: OS Command Injection via Unvalidated `--mesh` Parameter
- **What**: Shell metacharacters in `--mesh` execute arbitrary commands during Phase 6 runner script execution.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, lines 531–537 and line 759.
- **Why**: `args.mesh` is not validated against `is_valid_nodename`. It is interpolated inside double quotes: `sudo -u "{admin_user}" /usr/local/bin/sb-mesh bootstrap --headless -n "{m}"`.
- **CWE / CVE**: CWE-78 (OS Command Injection), CWE-88 (Improper Neutralization of Argument Delimiters).
- **Likelihood & Impact**: High (7/10). Execution as root.
- **Remediation**:
  In `tools/sb/src/commands/bootstrap.rs` inside `handle_node_bootstrap`:
  ```rust
  for m in &args.mesh {
      if !is_valid_nodename(m) {
          return Err(format!(
              "Ungültiger Mesh-Name: '{m}' (nur a-z, 0-9, _, - bis max. 63 Zeichen)"
          ));
      }
  }
  ```

### [Major / Security] SEC-2: Shell Injection via Incompletely Validated `--ca-key`
- **What**: Swarm-CA public key argument only verifies prefix `ssh-ed25519 AAA`, allowing single quotes and newlines.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, lines 319–326 and 617–619.
- **Why**: Key is interpolated into `echo '{ca_pubkey}' >> /etc/ssh/trusted_user_ca_keys` and `grep -qxF '{ca_pubkey}'`. Single quotes escape the string literal.
- **CWE / CVE**: CWE-78 (OS Command Injection), CWE-20 (Improper Input Validation).
- **Likelihood & Impact**: High (8/10). Execution as root.
- **Remediation**:
  In `tools/sb/src/commands/bootstrap.rs` update `resolve_ca_public_key`:
  ```rust
  pub fn resolve_ca_public_key(ca_key_arg: Option<&str>) -> Result<String, String> {
      if let Some(key) = ca_key_arg {
          let trimmed = key.trim();
          if !trimmed.starts_with("ssh-ed25519 AAA") {
              return Err("Ungültiger Swarm-CA Key: Muss mit 'ssh-ed25519 AAA' beginnen (RFC 4251 Wire Format).".to_string());
          }
          if trimmed.contains('\n') || trimmed.contains('\r') || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || " +/=@.-_".contains(c)) {
              return Err("Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen oder Zeilenumbrüche (RFC 4251 / OpenSSH Format erforderlich).".to_string());
          }
          return Ok(trimmed.to_string());
      }
  ```

### [Major / Security] SEC-3: Shell Breakout via Unvalidated `--mesh-token`
- **What**: CLI `--mesh-token` string is interpolated directly into `sudo -u "$ADMIN" /usr/local/bin/sb-node init --token '{pairing_token}'` without format validation.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, lines 361–367 and 720.
- **Why**: Single quotes in token allow command breakout.
- **CWE / CVE**: CWE-78 (OS Command Injection).
- **Likelihood & Impact**: Medium (6/10). Execution as root.
- **Remediation**:
  In `tools/sb/src/commands/bootstrap.rs` update `resolve_pairing_token` to return `Result<String, String>` (or validate in `handle_node_bootstrap`):
  ```rust
  pub fn resolve_pairing_token(token_arg: Option<&str>, node_name: &str, ca_pubkey: &str) -> Result<String, String> {
      if let Some(token) = token_arg {
          let clean = token.trim();
          if !clean.starts_with("sbm-pair://") || !clean["sbm-pair://".len()..].chars().all(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(c)) {
              return Err("Ungültiges Pairing-Token: Format muss 'sbm-pair://<base64>' entsprechen.".to_string());
          }
          Ok(clean.to_string())
      } else {
          Ok(crate::commands::fleet::build_pairing_token("sbm-swarm-default", node_name, ca_pubkey))
      }
  }
  ```

### [Minor / Quality] MIN-1: Misleading Test Target Flag in Documentation
- **What**: Documentation states `cargo test -p sb-cli --lib commands::bootstrap`, which fails with `error: no library targets found in package 'sb-cli'`.
- **Where**: `worker_m3_bootstrap/handoff.md` (Verification Method) & instructions.
- **Suggestion**: Use `cargo test -p sb-cli --bin sb commands::bootstrap` or `cargo test -p sb-cli commands::bootstrap`.

### [Minor / Quality] MIN-2: Immediate Password Zeroization
- **What**: Comment in line 765 says `// Zeroize cleartext password on return`, but `defer_zeroize(&mut args.password)` is invoked synchronously at line 766.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, line 765–766.
- **Suggestion**: While zeroizing cleartext credentials immediately upon entry is good defense-in-depth, update the comment or use a scope drop guard if deferred zeroization was intended.

---

## 4. Verified Claims Matrix

| Claim from Worker M3 | Verification Method | Result | Notes |
|---|---|---|---|
| Zero integrity violations / honest implementation | AST and full source inspection of `bootstrap.rs` | **PASS** | Real implementations, genuine error handling and tests |
| Clean workspace check (`cargo check --workspace`) | Executed `cargo check --workspace` in project root | **PASS** | 0 errors, 0 warnings (0.60s) |
| Bootstrap unit tests pass | `cargo test -p sb-cli --bin sb commands::bootstrap` | **PASS** | 12/12 passed (0.01s) |
| Full `sb-cli` suite passes | `cargo test -p sb-cli` | **PASS** | 97/97 passed (6.68s) |
| SSHD baseline check | Inspected lines 560–564 in `bootstrap.rs` | **PASS** | `sshd -t` fail-closed probe |
| SSHD atomic backup & rollback | Inspected lines 574–596, 632–638 | **PASS** | Mode 0700 backup, rollback.sh, ERR trap |
| SSHD SIGHUP reload semantics | Inspected line 641 in `bootstrap.rs` | **PASS** | `systemctl reload ssh \|\| systemctl reload sshd` |
| Dedicated admin user rejects root | Inspected line 297, tested `validate_admin_username` | **PASS** | Rejects "root" and "ROOT" |
| Sudoers safe staging & `visudo -cf` | Inspected lines 669–683, tested in unit test | **PASS** | Mode 0440 staging, visudo check |
| Systemd sandboxing directives | Inspected lines 425–475, tested in unit test | **PASS** | Full CIS Level 2 directives verified |
| SFTP exit-code-0 defect compensation | Inspected lines 189–205, 220–239 | **PASS** | Stderr scan + `test -s` + SHA256 sum |
| Zero command injection in runner templates | Adversarial parameter tracing | **FAIL** | SEC-1, SEC-2, SEC-3 discovered |

---

## 5. Caveats

- **Remote Target Server Execution (`145.223.83.235`)**: As designated in `PROJECT.md`, live execution against `145.223.83.235` was not performed during this review turn, only local dry-run simulation and unit test validation. Live target verification is scheduled for Milestone 5.
- **No other caveats**: The codebase compiles cleanly, all existing tests pass without regressions.

---

## 6. Conclusion & Recommendation

**Verdict**: `REQUEST_CHANGES`

The Milestone 3 implementation by `worker_m3_bootstrap` is well-architected, robustly structured, and free of any integrity violations or deceptive stubs. However, because `sb node bootstrap` is designed for remote bare-metal provisioning as root, hardening against shell injection vectors (SEC-1, SEC-2, SEC-3) is critical prior to live deployment.

Once `worker_m3_bootstrap` incorporates the three input validation checks and adds corresponding unit tests, Milestone 3 will be ready for immediate approval.

---

## 7. Verification Method for Rework

To verify the remediated code:

1. **Verify Workspace Clean Check**:
   ```powershell
   cargo check --workspace
   ```
   *Expected outcome*: 0 errors, 0 warnings.

2. **Verify Bootstrap Test Suite with Injection Tests**:
   ```powershell
   cargo test -p sb-cli --bin sb commands::bootstrap
   ```
   *Expected outcome*: All unit tests pass, including new tests verifying rejection of malicious `--mesh`, `--ca-key`, and `--mesh-token` arguments.

3. **Verify Dry-Run Simulation**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
   *Expected outcome*: Exit code 0, complete execution plan rendered cleanly.
