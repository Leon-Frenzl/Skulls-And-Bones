# Empirical Challenge Report: Milestone 3 — SSHD Backup, Rollback & Systemd Verification (Round 2)

**Author:** `challenger_m3_r2_rollback` (critic, specialist)  
**Target:** `orchestrator_3` (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Scope:** Milestone M3 Gate Remediation / Requirement R2 (`tools/sb/src/commands/bootstrap.rs` SSHD backup, `rollback.sh`, systemd `ReadWritePaths`, unit tests)  
**Date:** 2026-10-28T01:39:00Z  
**Verdict:** **`REQUEST_CHANGES`**

---

## 1. Observation

Direct empirical observations obtained from static analysis of `tools/sb/src/commands/bootstrap.rs`, Cargo test suites, and empirical test harnesses executed directly on live Linux target server `145.223.83.235` (Ubuntu kernel 7.0.0-38-generic x86_64, OpenSSH 10.2p1, GNU coreutils 9.4):

### 1.1 SSHD Backup and Rollback Logic in `tools/sb/src/commands/bootstrap.rs`

1. **Backup Phase (Lines 661–662)**:
   ```bash
   [ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf "${BACKUP_DIR}/" || true
   [ -e /etc/ssh/sshd_config.d/99-sbm.conf ] && cp -a /etc/ssh/sshd_config.d/99-sbm.conf "${BACKUP_DIR}/" || true
   ```
   - Uses `[ -e ]`. If `99-sbm.conf` is a regular file or an active symlink, it is copied into `${BACKUP_DIR}/`.
   - If `99-sbm.conf` is a dangling symlink, `[ -e ]` evaluates to false (exit code 1) under POSIX / GNU `test`, meaning a pre-existing dangling symlink is not backed up unless `[ -L ]` or `[ -h ]` is included.

2. **Rollback Script Logic (Lines 672–673)**:
   ```bash
   [ -e "$B/99-sb-ca.conf" ] && cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf || rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf
   [ -e "$B/99-sbm.conf" ] && cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf || rm -f /etc/ssh/sshd_config.d/99-sbm.conf
   ```

3. **Provisioning Drop-In Creation (Lines 711–712)**:
   ```bash
   mv /etc/ssh/sshd_config.d/99-sb-ca.conf.tmp /etc/ssh/sshd_config.d/99-sb-ca.conf
   ln -sf /etc/ssh/sshd_config.d/99-sb-ca.conf /etc/ssh/sshd_config.d/99-sbm.conf
   ```
   This creates `/etc/ssh/sshd_config.d/99-sbm.conf` as a symbolic link pointing to `/etc/ssh/sshd_config.d/99-sb-ca.conf`.

4. **Empirical Reproduction of Failure Scenario A (Pre-existing `99-sbm.conf`, no pre-existing `99-sb-ca.conf`)**:
   - Initial state: `/etc/ssh/sshd_config.d/99-sbm.conf` exists containing `DenyUsers eviluser` (e.g. from `sb-node evict`). No `99-sb-ca.conf` exists.
   - Backup succeeds and copies `99-sbm.conf` into `$B/99-sbm.conf`.
   - Provisioning executes lines 711–712, creating the symlink `99-sbm.conf -> 99-sb-ca.conf`.
   - Rollback is triggered on error:
     - Line 672: `$B/99-sb-ca.conf` does not exist, so line 672 executes `rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf`.
     - At this point, `/etc/ssh/sshd_config.d/99-sbm.conf` is now a **dangling symlink**.
     - Line 673: `[ -e "$B/99-sbm.conf" ]` evaluates to true because `$B/99-sbm.conf` exists in backup.
     - The shell executes `cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf`.
     - **Verbatim Error on Live Linux Target**:
       ```text
       cp: not writing through dangling symlink '/etc/ssh/sshd_config.d/99-sbm.conf'
       ```
     - GNU `cp` exits with code 1.
     - Because `cp -a` returned non-zero, the shell executes the `||` branch:
       `rm -f /etc/ssh/sshd_config.d/99-sbm.conf`!
     - **Empirical State After Rollback**:
       ```text
       === Contents of sshd_config.d ===
       total 0
       DATA LOSS CONFIRMED: 99-sbm.conf is MISSING!
       ```
     - `${BACKUP_DIR}` is deleted by line 681 (`rm -rf "${BACKUP_DIR}"`).
     - **Result**: The pre-existing `99-sbm.conf` eviction configuration is **permanently destroyed**.

5. **Empirical Reproduction of Failure Scenario B (Both `99-sb-ca.conf` and `99-sbm.conf` pre-existed)**:
   - Initial state:
     `/etc/ssh/sshd_config.d/99-sb-ca.conf` = `ORIGINAL CA`
     `/etc/ssh/sshd_config.d/99-sbm.conf` = `ORIGINAL SBM`
   - Backup captures both files.
   - Provisioning replaces `99-sb-ca.conf` and creates symlink `99-sbm.conf -> 99-sb-ca.conf`.
   - Rollback executes:
     - Line 672: `cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf` restores `ORIGINAL CA`.
     - Line 673: `cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf` runs.
     - Because destination `99-sbm.conf` is an existing symbolic link pointing to `99-sb-ca.conf`, `cp -a` follows the symlink and overwrites the target (`99-sb-ca.conf`) with `ORIGINAL SBM`!
     - **Empirical State After Rollback**:
       ```text
       === Results in Case 4 ===
       total 4
       -rw-r--r-- 1 root root 13 Oct 28 01:37 99-sb-ca.conf
       lrwxrwxrwx 1 root root 47 Oct 28 01:37 99-sbm.conf -> /etc/ssh/sshd_config.d/99-sb-ca.conf
       99-sb-ca.conf content: ORIGINAL SBM
       99-sbm.conf is link? YES
       99-sbm.conf content: ORIGINAL SBM
       ```
     - **Result**: `99-sb-ca.conf` is corrupted and overwritten with `99-sbm.conf` data, and `99-sbm.conf` remains a leaked symlink instead of being restored as a regular file.

### 1.2 Systemd Unit `ReadWritePaths` Directive

1. In `tools/sb/src/commands/bootstrap.rs`, line 549:
   ```ini
   ReadWritePaths=-/home/{admin_user}/.sb-mesh -/home/{admin_user}/.sb /run /tmp
   ```
2. Verified in unit test `test_generate_systemd_service` (line 1150).
3. **Live Systemd Verification on `145.223.83.235`**:
   - `systemd-analyze verify`: Exit Code 0.
   - Live execution via `systemd-run`:
     - With `-` prefix (`ReadWritePaths=-/home/nonexistent_user/.sb`):
       ```text
       Main processes terminated with: code=exited, status=0/SUCCESS
       With hyphen: 0
       ```
     - Without `-` prefix (`ReadWritePaths=/home/nonexistent_user/.sb`):
       ```text
       Main processes terminated with: code=exited, status=226/NAMESPACE
       Without hyphen: 226
       ```
   - **Result**: The `-` prefix on dynamic user paths successfully prevents `status=226/NAMESPACE` startup crashes.

### 1.3 Test Suite Execution

1. Command:
   `cargo test -p sb-cli --bin sb commands::bootstrap`
   - Output: `15 passed; 0 failed; 0 ignored; 0 measured; 85 filtered out; finished in 0.01s`.
2. Command:
   `cargo test -p sb-cli`
   - Output: `100 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.03s`.
3. Note: The existing unit test `test_generate_runner_script_contains_rollback_and_visudo` passed because it only asserts substring presence (`assert!(script.contains("[ -e \"$B/99-sbm.conf\" ] && cp -a ..."))`), without executing the generated script under GNU `cp` with existing symlinks.

---

## 2. Logic Chain

1. **Premise 1 (Destination Symlink Semantics under GNU `cp -a`)**:
   In POSIX and GNU coreutils, `cp -a src dst` handles an existing `dst` that is a symlink as follows:
   - If `dst` is a dangling symlink: `cp` fails with `cp: not writing through dangling symlink`.
   - If `dst` points to an existing file: `cp` dereferences `dst` and writes into the file `dst` points to, leaving `dst` as a symlink.
2. **Premise 2 (State of `99-sbm.conf` During Bootstrap)**:
   In Phase 3 of `bootstrap.rs`, lines 711–712 create `/etc/ssh/sshd_config.d/99-sbm.conf` as a symlink pointing to `/etc/ssh/sshd_config.d/99-sb-ca.conf`. Therefore, whenever `rollback.sh` is invoked, `99-sbm.conf` is guaranteed to be a symlink.
3. **Premise 3 (Dangling Symlink Trigger in Scenario A)**:
   In `rollback.sh`:
   `[ -e "$B/99-sb-ca.conf" ] && cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf || rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf`
   `[ -e "$B/99-sbm.conf" ] && cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf || rm -f /etc/ssh/sshd_config.d/99-sbm.conf`
   When `99-sb-ca.conf` did not exist prior to bootstrap, line 1 removes `99-sb-ca.conf`. This immediately turns `99-sbm.conf` into a dangling symlink.
   When line 2 attempts `cp -a "$B/99-sbm.conf" ...`, `cp` fails on the dangling symlink. The `|| rm -f` fallback executes and deletes `99-sbm.conf`.
   *Conclusion A*: The pre-existing file in `$B/99-sbm.conf` is never restored, and the target file is deleted, causing complete data loss (CWE-404).
4. **Premise 4 (Symlink Dereference & Target Corruption in Scenario B)**:
   When both files pre-existed, line 1 restores `99-sb-ca.conf`.
   Line 2 runs `cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf`.
   Because destination `99-sbm.conf` is a symlink pointing to `99-sb-ca.conf`, `cp` writes the data of `99-sbm.conf` into `99-sb-ca.conf`.
   *Conclusion B*: `99-sb-ca.conf` is corrupted, and `99-sbm.conf` remains a leaked symlink (CWE-59, CWE-459).
5. **Mitigation Invariant**:
   To safely restore files from backup when the destination may be a symlink created during the aborted transaction, `rollback.sh` must explicitly remove the destination (`rm -f`) BEFORE copying the file from `$B/`:
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
   Empirical testing of this mitigation on `145.223.83.235` confirmed 5/5 passing tests across all possible initial states.

---

## 3. Caveats

- **Systemd Unit `ReadWritePaths`**: Fully verified and validated on Linux. No issues found.
- **Unit test coverage**: `cargo test -p sb-cli --bin sb commands::bootstrap` passes 15/15, but unit test assertions in `test_generate_runner_script_contains_rollback_and_visudo` need to be updated to match the corrected rollback commands once applied.
- **No other caveats**: All observations were directly reproduced and confirmed on the target production Linux environment.

---

## 4. Conclusion

Verdict: **`REQUEST_CHANGES`**

While the Systemd unit `ReadWritePaths` fix is fully verified and correct, the SSHD `rollback.sh` implementation contains an active, critical data loss and file corruption flaw on any standard Linux target whenever `99-sbm.conf` pre-existed.

### Required Changes in `tools/sb/src/commands/bootstrap.rs`:

1. **Harden `rollback.sh` generation (lines 672–673)**:
   Replace:
   ```bash
   [ -e "$B/99-sb-ca.conf" ] && cp -a "$B/99-sb-ca.conf" /etc/ssh/sshd_config.d/99-sb-ca.conf || rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf
   [ -e "$B/99-sbm.conf" ] && cp -a "$B/99-sbm.conf" /etc/ssh/sshd_config.d/99-sbm.conf || rm -f /etc/ssh/sshd_config.d/99-sbm.conf
   ```
   With:
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

2. **Harden Backup Snapshot Creation (lines 661–662)**:
   Support pre-existing symlinks (even if dangling) during backup:
   ```bash
   ([ -e /etc/ssh/sshd_config.d/99-sb-ca.conf ] || [ -L /etc/ssh/sshd_config.d/99-sb-ca.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sb-ca.conf "${BACKUP_DIR}/" || true
   ([ -e /etc/ssh/sshd_config.d/99-sbm.conf ] || [ -L /etc/ssh/sshd_config.d/99-sbm.conf ]) && cp -a /etc/ssh/sshd_config.d/99-sbm.conf "${BACKUP_DIR}/" || true
   ```

3. **Update Unit Test Assertions**:
   In `test_generate_runner_script_contains_rollback_and_visudo` (lines 1187–1188), update the expected assertions to match the unlinking and restoration pattern.

---

## 5. Verification Method

To independently verify the flaw and validate the proposed fix:

1. **Empirical Reproduction of Data Loss Flaw**:
   Execute on any Linux host or remote target `145.223.83.235`:
   ```bash
   TMP=$(mktemp -d)
   mkdir -p "$TMP/sshd_config.d" "$TMP/backup"
   echo "DenyUsers eviluser" > "$TMP/sshd_config.d/99-sbm.conf"
   
   # Backup
   [ -e "$TMP/sshd_config.d/99-sb-ca.conf" ] && cp -a "$TMP/sshd_config.d/99-sb-ca.conf" "$TMP/backup/" || true
   [ -e "$TMP/sshd_config.d/99-sbm.conf" ] && cp -a "$TMP/sshd_config.d/99-sbm.conf" "$TMP/backup/" || true
   
   # Provisioning
   echo "CA CONFIG" > "$TMP/sshd_config.d/99-sb-ca.conf"
   ln -sf "$TMP/sshd_config.d/99-sb-ca.conf" "$TMP/sshd_config.d/99-sbm.conf"
   
   # Current rollback logic
   B="$TMP/backup"
   [ -e "$B/99-sb-ca.conf" ] && cp -a "$B/99-sb-ca.conf" "$TMP/sshd_config.d/99-sb-ca.conf" || rm -f "$TMP/sshd_config.d/99-sb-ca.conf"
   [ -e "$B/99-sbm.conf" ] && cp -a "$B/99-sbm.conf" "$TMP/sshd_config.d/99-sbm.conf" || rm -f "$TMP/sshd_config.d/99-sbm.conf"
   
   # Check result:
   [ ! -f "$TMP/sshd_config.d/99-sbm.conf" ] && echo "FAIL: 99-sbm.conf was deleted! DATA LOSS CONFIRMED!"
   rm -rf "$TMP"
   ```

2. **Empirical Verification of Corrected Logic**:
   Run the test with the proposed fix:
   ```bash
   TMP=$(mktemp -d)
   mkdir -p "$TMP/sshd_config.d" "$TMP/backup"
   echo "DenyUsers eviluser" > "$TMP/sshd_config.d/99-sbm.conf"
   
   ([ -e "$TMP/sshd_config.d/99-sbm.conf" ] || [ -L "$TMP/sshd_config.d/99-sbm.conf" ]) && cp -a "$TMP/sshd_config.d/99-sbm.conf" "$TMP/backup/" || true
   
   echo "CA CONFIG" > "$TMP/sshd_config.d/99-sb-ca.conf"
   ln -sf "$TMP/sshd_config.d/99-sb-ca.conf" "$TMP/sshd_config.d/99-sbm.conf"
   
   B="$TMP/backup"
   rm -f "$TMP/sshd_config.d/99-sb-ca.conf"
   if [ -e "$B/99-sb-ca.conf" ] || [ -L "$B/99-sb-ca.conf" ]; then
       cp -a "$B/99-sb-ca.conf" "$TMP/sshd_config.d/99-sb-ca.conf"
   fi
   rm -f "$TMP/sshd_config.d/99-sbm.conf"
   if [ -e "$B/99-sbm.conf" ] || [ -L "$B/99-sbm.conf" ]; then
       cp -a "$B/99-sbm.conf" "$TMP/sshd_config.d/99-sbm.conf"
   fi
   
   [ -f "$TMP/sshd_config.d/99-sbm.conf" ] && echo "PASS: 99-sbm.conf restored successfully!"
   rm -rf "$TMP"
   ```

3. **Cargo Unit Test Suite**:
   ```powershell
   cargo test -p sb-cli --bin sb commands::bootstrap
   ```
