# Empirical Challenge Report: Milestone 3 — SSHD Backup & Rollback Symlink Hardening (Round 3)

**Author:** `challenger_m3_r3_rollback` (critic, specialist)  
**Target:** `orchestrator_3` (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Scope:** `tools/sb/src/commands/bootstrap.rs` (SSHD backup snapshot creation, `rollback.sh` execution, GNU coreutils symlink resilience, unit test coverage)  
**Date:** 2026-10-28T01:51:00Z  
**Verdict:** **`APPROVE`**

---

## 1. Observation

Direct empirical observations obtained from static analysis of `tools/sb/src/commands/bootstrap.rs`, execution of the full local Cargo workspace verification suites, and empirical test harnesses executed directly on live Linux target server `145.223.83.235` (Ubuntu kernel 7.0.0-38-generic x86_64, GNU coreutils 9.7, Bash 5.3.9, OpenSSH 10.2p1):

### 1.1 Implementation in `tools/sb/src/commands/bootstrap.rs`

1. **Backup Snapshot Creation (Lines 661–662)**:
   ```bash
   ([ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] || [ -L /etc/ssh/sshd_config.d/99-sb-ca.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf "${BACKUP_DIR}/" || true
   ([ -e /etc/ssh/sshd_config.d/99-sbm.conf ] || [ -L /etc/ssh/sshd_config.d/99-sbm.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sbm.conf "${BACKUP_DIR}/" || true
   ```
   - In contrast to the legacy `[ -e ]` check which evaluated to false on dangling symlinks, the compound check `([ -e <file> ] || [ -L <file> ])` captures regular files, active symlinks, and dangling symlinks alike.
   - Using `cp -a` preserves the symlink itself (via `--no-dereference`) into `${BACKUP_DIR}/`.

2. **Rollback Restoration Logic in `rollback.sh` (Lines 672–679)**:
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
   - Prior to copying from `$B/`, the destination file `/etc/ssh/sshd_config.d/99-sb-ca.conf` and `/etc/ssh/sshd_config.d/99-sbm.conf` is explicitly unlinked via `rm -f`.
   - The conditional restoration `if [ -e "$B/..." ] || [ -L "$B/..." ]` ensures that regular files, valid symlinks, and dangling symlinks in backup are safely copied back without encountering destination collisions, dangling symlink write blocks, or symlink traversal.
   - If a file did not exist prior to bootstrap, it is not present in `$B/`, leaving the destination unlinked and clean.

3. **In-Code Security Threat Documentation (Lines 574–581)**:
   ```rust
   /**
    * SECURITY AUDIT:
    * - Dynamic Threat Vector: Mid-execution network disconnect, syntax error leaving host permanently inaccessible, command injection via unescaped variables, or data loss during rollback (dangling symlink or symlink traversal corrupting target).
    * - CVE / CWE Mapping: CWE-440 (Expected Behavior Violation), CWE-755 (Improper Handling of Exceptional Conditions), CWE-78 (OS Command Injection), CWE-404 / CWE-284 (Improper Resource Shutdown or Release), CWE-59 / CWE-459 (Symlink Traversal and Incomplete Cleanup).
    * - Likelihood & Exploitability: High (8/10).
    *   * Threat Condition: SSH daemon fails to start with new configuration, or rollback encounters destination symlink leading to GNU cp failure and deletion of existing 99-sbm.conf.
    * - Applied Mitigation: Pre-flight `sshd -t` baseline test, atomic transaction snapshot in `/etc/ssh/.sb-backup-*` backing up both `99-sb-ca.conf` and `99-sbm.conf` via `([ -e ] || [ -L ])`, rollback unlinking destination symlinks before restoring to eliminate dangling symlink failures and traversal corruption, `visudo -cf` verification, graceful SIGHUP reload, and post-onboarding daemon restart.
    * - Standards Compliance: POSIX.1-2017, IETF RFC 4251, CIS Linux Benchmark Level 2.
    */
   ```

4. **Unit Test Updates in `tools/sb/src/commands/bootstrap.rs` (Lines 1189–1198)**:
   - `test_generate_runner_script_contains_rollback_and_visudo` asserts:
     ```rust
     assert!(script.contains("([ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] || [ -L /etc/ssh/sshd_config.d/99-sb-ca.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf"));
     assert!(script.contains("([ -e /etc/ssh/sshd_config.d/99-sbm.conf ] || [ -L /etc/ssh/sshd_config.d/99-sbm.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sbm.conf"));
     assert!(script.contains("rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf"));
     assert!(script.contains("if [ -e \"$B/99-sb-ca.conf\" ] || [ -L \"$B/99-sb-ca.conf\" ]; then"));
     assert!(script.contains("cp -a \"$B/99-sb-ca.conf\" /etc/ssh/sshd_config.d/99-sb-ca.conf"));
     assert!(script.contains("rm -f /etc/ssh/sshd_config.d/99-sbm.conf"));
     assert!(script.contains("if [ -e \"$B/99-sbm.conf\" ] || [ -L \"$B/99-sbm.conf\" ]; then"));
     assert!(script.contains("cp -a \"$B/99-sbm.conf\" /etc/ssh/sshd_config.d/99-sbm.conf"));
     ```

### 1.2 Empirical Stress-Test Execution on Live Target Server `145.223.83.235`

An empirical test harness (`test_rollback_empirical.sh`) was uploaded to and executed on the production target `145.223.83.235` via `sb-ssh` to test all permutations of initial drop-in configurations under real Linux GNU coreutils 9.7 and kernel 7.0:

```text
======================================================================
EMPIRICAL TEST SUITE: SSHD BACKUP & ROLLBACK HARDENING
Target Host: srv490042 (Linux srv490042 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026 x86_64 GNU/Linux)
GNU coreutils cp: cp (GNU coreutils) 9.7
Bash version: 5.3.9(1)-release
======================================================================
Running [Test: Clean slate (no prior drop-ins)] ... PASSED
Running [Test: Only 99-sbm.conf pre-existed (Scenario A data-loss trap)] ... PASSED
Running [Test: Only 99-sb-ca.conf pre-existed] ... PASSED
Running [Test: Both regular files pre-existed (Scenario B symlink corruption trap)] ... PASSED
Running [Test: 99-sbm.conf pre-existed as external symlink] ... PASSED
Running [Test: 99-sbm.conf pre-existed as DANGLING symlink] ... PASSED
Running [Test: 99-sb-ca.conf pre-existed as DANGLING symlink] ... PASSED
Running [Test: Both pre-existed as DANGLING symlinks] ... PASSED
Running [Test: Idempotence verification] ... PASSED
======================================================================
SUMMARY: Passed: 9, Failed: 0
======================================================================
```

Key empirical findings from the 9 test permutations:
1. **Scenario A (Data Loss Trap - Only `99-sbm.conf` pre-existed)**:
   - When provisioning created the symlink `99-sbm.conf -> 99-sb-ca.conf` and rollback removed `99-sb-ca.conf`, the destination `99-sbm.conf` became a dangling symlink.
   - `rm -f /etc/ssh/sshd_config.d/99-sbm.conf` successfully unlinked the dangling symlink.
   - `cp -a "$B/99-sbm.conf" ...` restored the original regular file cleanly with exact content `ORIGINAL_SBM_CONTENT`.
   - GNU coreutils error `cp: not writing through dangling symlink` was completely eliminated (Exit code 0).
2. **Scenario B (Symlink Traversal Trap - Both regular files pre-existed)**:
   - When provisioning created `99-sbm.conf -> 99-sb-ca.conf`, `rm -f /etc/ssh/sshd_config.d/99-sbm.conf` unlinked the symlink prior to restoration.
   - `cp -a "$B/99-sbm.conf" ...` restored `99-sbm.conf` as an independent regular file without following or writing into `99-sb-ca.conf`.
   - Both files retained their respective distinct contents (`ORIGINAL_SB_CA_CONTENT_4` and `ORIGINAL_SBM_CONTENT_4`) with 0 bytes corrupted.
3. **Dangling Symlink Preservation (Cases 6, 7, 8)**:
   - `([ -e ] || [ -L ])` successfully backed up pre-existing dangling symlinks.
   - `if [ -e ] || [ -L ]` and `cp -a` faithfully restored dangling symlinks with their target paths intact.

### 1.3 Local Cargo Verification Suites

1. `cargo test -p sb-cli --bin sb commands::bootstrap`:
   ```text
   running 15 tests
   test commands::bootstrap::tests::test_admin_username_validation ... ok
   test commands::bootstrap::tests::test_generate_systemd_service ... ok
   test commands::bootstrap::tests::test_generate_sshd_ca_config ... ok
   test commands::bootstrap::tests::test_resolve_ca_public_key_format_validation ... ok
   test commands::bootstrap::tests::test_ssh_target_parsing_rejects_injection ... ok
   test commands::bootstrap::tests::test_ssh_target_password_redaction_and_zeroize ... ok
   test commands::bootstrap::tests::test_generate_runner_script_contains_rollback_and_visudo ... ok
   test commands::bootstrap::tests::test_generate_sudoers_entry ... ok
   test commands::bootstrap::tests::test_ssh_target_parsing_valid ... ok
   test commands::bootstrap::tests::test_resolve_pairing_token_validation ... ok
   test commands::bootstrap::tests::test_cli_backward_compatibility_node_external ... ok
   test commands::bootstrap::tests::test_cli_backward_compatibility_node_empty ... ok
   test commands::bootstrap::tests::test_cli_parsing_node_bootstrap_dry_run ... ok
   test commands::bootstrap::tests::test_cli_parsing_node_bootstrap_with_flags ... ok
   test commands::bootstrap::tests::test_mesh_name_validation ... ok

   test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 85 filtered out; finished in 0.01s
   ```

2. `cargo check --workspace`:
   ```text
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.57s
   ```
   (0 compiler errors, 0 warnings).

3. `cargo test --workspace`:
   ```text
   All workspace crates passed cleanly (Exit Code 0).
   ```

---

## 2. Logic Chain

1. **Elimination of GNU `cp` Dangling Symlink Error (Addressing Question 1a)**:
   - *Observation 1.1.2 & 1.2.1*: In `rollback.sh`, `rm -f /etc/ssh/sshd_config.d/99-sbm.conf` executes immediately before `cp -a "$B/99-sbm.conf" ...`.
   - *Logic*: Because `rm -f` unlinks the inode at `/etc/ssh/sshd_config.d/99-sbm.conf`, the destination is non-existent at the moment `cp -a` is invoked. Therefore, GNU `cp` will never encounter an existing dangling symlink at the destination path.
   - *Result*: The verbatim error `cp: not writing through dangling symlink` is impossible under this sequencing, and the backed-up file is restored with 100% fidelity without triggering deletion.

2. **Elimination of Symlink Dereference and Target Overwrite (Addressing Question 1b)**:
   - *Observation 1.1.2 & 1.2.2*: During bootstrap, `99-sbm.conf` is created as a symlink pointing to `99-sb-ca.conf`.
   - *Logic*: If `99-sbm.conf` were not unlinked before copying, `cp -a "$B/99-sbm.conf" ...` would dereference the existing symlink and overwrite the content of `99-sb-ca.conf`. Because `rm -f /etc/ssh/sshd_config.d/99-sbm.conf` unlinks the symlink first, `cp -a` creates a brand new regular file or symlink as stored in `$B/99-sbm.conf`.
   - *Result*: `99-sb-ca.conf` is never overwritten by `99-sbm.conf`, and `99-sbm.conf` is restored as an independent regular file (or its original symlink).

3. **Completeness of Backup and Restoration via `[ -e ] || [ -L ]` (Addressing Question 2)**:
   - *Observation 1.1.1 & 1.2.3*: POSIX `[ -e ]` evaluates the target of a symlink; if the symlink is dangling (target missing), `[ -e ]` returns false. POSIX `[ -L ]` (and `[ -h ]`) evaluates the file itself without resolving its target; if the file is a symbolic link (active or dangling), `[ -L ]` returns true.
   - *Logic*: The expression `([ -e <file> ] || [ -L <file> ])` evaluates to true for:
     1. Regular files (`[ -e ]` is true).
     2. Valid symlinks (`[ -e ]` is true, `[ -L ]` is true).
     3. Dangling symlinks (`[ -e ]` is false, `[ -L ]` is true).
     4. Missing files (`[ -e ]` is false, `[ -L ]` is false).
   - In both backup creation and rollback restoration, this expression guarantees complete coverage across all 4 file states.
   - *Result*: Pre-existing dangling symlinks are never dropped from backup and are restored identically upon rollback.

4. **Workspace Hygiene & Test Suite Integrity**:
   - *Observation 1.3*: Unit tests specific to `commands::bootstrap` passed 15/15, `cargo check --workspace` showed 0 warnings/errors, and `cargo test --workspace` passed 100%.
   - *Result*: The changes introduced no regressions and meet all acceptance criteria.

---

## 3. Caveats

- **POSIX `[ -L ]` availability**: POSIX.1-2017 specifies `test -L` and `test -h` as standard test operators for symbolic links supported by all compliant shells (bash, dash, ash, zsh, ksh). Supported across all Linux distributions.
- **No other caveats**: The fix was validated empirically on the target production server and locally across full workspace check/test commands.

---

## 4. Conclusion

Verdict: **`APPROVE`**

The SSHD backup snapshot and transactional rollback logic in `tools/sb/src/commands/bootstrap.rs` is fully hardened, verified, and complete:
1. `rollback.sh` unlinks destination files with `rm -f` prior to restoring from backup, which completely eliminates GNU `cp` dangling symlink aborts and symlink traversal target corruption.
2. Backup snapshot creation uses `([ -e ] || [ -L ])`, ensuring complete backup and restoration of regular files, valid symlinks, and dangling symlinks.
3. All unit tests, workspace checks, and 9 empirical stress test cases pass with zero errors and zero warnings.

Milestone M3 SSHD rollback hardening is formally approved to proceed.

---

## 5. Verification Method

To independently reproduce this verification:

1. **Live Empirical Test Matrix on `145.223.83.235`**:
   ```bash
   sb-ssh.exe push root@145.223.83.235 .agents/teamwork/challenger_m3_r3_rollback/test_rollback_empirical.sh /tmp/test_rollback_empirical.sh
   sb-ssh.exe -p 22 root@145.223.83.235 "bash /tmp/test_rollback_empirical.sh; rm -f /tmp/test_rollback_empirical.sh"
   ```
   Expectation: `SUMMARY: Passed: 9, Failed: 0`.

2. **Bootstrap Unit Tests**:
   ```powershell
   cargo test -p sb-cli --bin sb commands::bootstrap
   ```
   Expectation: `test result: ok. 15 passed; 0 failed`.

3. **Workspace Check**:
   ```powershell
   cargo check --workspace
   ```
   Expectation: 0 errors, 0 warnings.
