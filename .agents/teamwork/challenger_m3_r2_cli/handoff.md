# Handoff Report: Milestone 3 CLI Remediation & Injection Verification

**Author:** `challenger_m3_r2_cli` (critic, specialist, empirical challenger)  
**Parent / Caller:** `orchestrator_3` (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Scope:** CLI Argument Parsing, Input Validation, Injection Rejection, and Backward Compatibility for `sb node bootstrap`  
**Date:** 2026-10-28T01:36:00Z  
**Verdict:** **APPROVE**

---

## 1. Observation

All tests were directly executed via command line in the workspace root `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones`.

### 1.1 Mandated Injection Vector Rejection (Exit Code 1)

1. **Mesh Name Injection Vector**:
   - **Command**:
     ```powershell
     cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m 'dev"; rm -rf /; echo "' --dry-run
     ```
   - **Verbatim Output**:
     ```text
     Fehler beim Node-Bootstrap: Ungültiger Mesh-Name: 'dev; rm -rf /; echo ' (nur a-z, 0-9, _, - bis max. 63 Zeichen)
     error: process didn't exit successfully: `target\debug\sb.exe node bootstrap root@145.223.83.235 -m "dev; rm -rf /; echo " --dry-run` (exit code: 1)
     ```
   - **Observed Exit Code**: `1`

2. **Swarm-CA Key Injection Vector**:
   - **Command**:
     ```powershell
     cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key 'ssh-ed25519 AAA''; id; echo ''' --dry-run
     ```
   - **Verbatim Output**:
     ```text
     Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen oder Zeilenumbrüche (RFC 4251 / OpenSSH Format erforderlich).
     error: process didn't exit successfully: `target\debug\sb.exe node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA'; id; echo '" --dry-run` (exit code: 1)
     ```
   - **Observed Exit Code**: `1`

3. **Mesh Pairing Token Injection Vector**:
   - **Command**:
     ```powershell
     cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token 'sbm-pair://abc''; id; echo ''' --dry-run
     ```
   - **Verbatim Output**:
     ```text
     Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Enthält unzulässige Metazeichen oder Zeilenumbrüche.
     error: process didn't exit successfully: `target\debug\sb.exe node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://abc'; id; echo '" --dry-run` (exit code: 1)
     ```
   - **Observed Exit Code**: `1`

---

### 1.2 Mandated Valid Dry-Run Verification (Exit Code 0)

- **Command**:
  ```powershell
  cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
  ```
- **Verbatim Output**:
  ```text
  ════════════════════════════════════════════════════════════════════════════════
    ► SKULLS & BONES — NODE BOOTSTRAP EXECUTION PLAN [DRY-RUN SIMULATION]
  ════════════════════════════════════════════════════════════════════════════════
    Target:                  root@145.223.83.235
    Port:                    22
    Admin User:              sbadmin
    Node Callsign:           hostinger-node
    Mesh Domain:             hostinger-node.sbm
    Mesh Networks:           dev
    Swarm CA Key:            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAjA51B9II/eOjzTSPZz0YGYltunV5Tznfshdp4519Oh sovereign-swarm-ca@local
    Pairing Token:           sbm-pair://eyJjYV9wdWJsaWNfa2V5Ijoic3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUFqQTUxQjlJSS9lT2p6VFNQWnowWUdZbHR1blY1VHpuZnNoZHA0NTE5T2ggc292ZXJlaWduLXN3YXJtLWNhQGxvY2FsIiwiZW5kcG9pbnQiOm51bGwsImV4cGlyZXNfYXQiOm51bGwsIm5vZGVfbmFtZSI6Imhvc3Rpbmdlci1ub2RlIiwic3dhcm1fbmFtZSI6InNibS1zd2FybS1kZWZhdWx0In0=

  --- Phase 1: Pre-Flight Probe ---
    [Plan] Probe target host OS (Linux), CPU architecture, UID, and disk space.
    [Plan] Test pre-existing sshd configuration with `sshd -t` (fail-closed if broken).

  --- Phase 2: Staging Upload & SHA-256 Integrity Verification ---
    [Plan] Create isolated staging directory: /tmp/.sb-staging-<uuid> (POSIX mode 0700).
    [Plan] Upload runner script and binaries via SFTP with SHA-256 checksum verification.

  --- Phase 3: OpenSSH Swarm-CA Anchoring & Rollback ---
    [Plan] Create transaction snapshot in /etc/ssh/.sb-backup-<timestamp>_$$/
    [Plan] Safely disable /etc/ssh/sshd_config.d/50-cloud-init.conf (preserve original settings).
    [Plan] Append Swarm-CA public key to /etc/ssh/trusted_user_ca_keys (0644).
    [Plan] Deploy /etc/ssh/sshd_config.d/99-sb-ca.conf with RFC 4251 & PROTOCOL.certkeys trust settings.
    [Plan] Validate configuration via `sshd -t` (auto-rollback on syntax failure).
    [Plan] Graceful SIGHUP reload of ssh daemon (`systemctl reload ssh || systemctl reload sshd`).

  --- Phase 4: Dedicated Admin User & Sudoers Hardening ---
    [Plan] Create unprivileged admin user 'sbadmin' with home directory and .ssh layout.
    [Plan] Copy authorized keys from root for break-glass access.
    [Plan] Stage /etc/sudoers.d/90-sb-sbadmin.tmp (POSIX mode 0440).
    [Plan] Pre-validate sudoers syntax via `visudo -cf` before activating.

  --- Phase 5: Sandboxed Systemd Service Deployment ---
    [Plan] Deploy /etc/systemd/system/sb-node.service with CIS Benchmark Level 2 sandboxing.
    [Plan] Reload systemd daemon, enable and restart sb-node service.
    [Plan] Verify active service state and UDP port 58888 dispatcher binding.

  --- Phase 6: Mesh Onboarding & Vault Registration ---
    [Plan] Execute `sudo -u sbadmin /usr/local/bin/sb-node init --token <token>`.
    [Plan] Register target server in local vault (~/.sb/servers.toml).
  ════════════════════════════════════════════════════════════════════════════════
    ✓ Dry-run completed successfully. No remote changes were made.
  ```
- **Observed Exit Code**: `0`

---

### 1.3 Backward Compatibility Verification

1. **`sb node` default delegation**:
   - **Command**: `cargo run -p sb-cli -- node`
   - **Observed**: Transparently delegates to `sb-node` (via `delegate_to("node", "sb-node", &[])`) rendering the local node HUD:
     ```text
     ══════════════════════════════════════════════════════════════════
       SKULLS & BONES // SB-NODE FLOTTENKNOTEN STATUS
     ══════════════════════════════════════════════════════════════════
       Knoten-Identität:        desktop-33ar5nl
       Overlay-Adresse:         desktop-33ar5nl.sbm
       Status:                  BEREIT / MULTI-TENANT ANCHOR
       Hintergrunddienst:       STOPPED
     ```
   - **Observed Exit Code**: `0`

2. **`sb node --help`**:
   - **Command**: `cargo run -p sb-cli -- node --help`
   - **Observed**: Shows subcommand help for `node` including `bootstrap` and `help`.
   - **Observed Exit Code**: `0`

3. **`sb node daemon --help`**:
   - **Command**: `cargo run -p sb-cli -- node daemon --help`
   - **Observed**: Transparently delegates to `sb-node.exe daemon --help` (via `External` subcommand delegation):
     ```text
     Startet den Multi-Tenant Headless Daemon (Port 58888 Single-Port Dispatcher & Relays)

     Usage: sb-node.exe daemon [OPTIONS]

     Options:
       -p, --port <PORT>      Port für den Single-Port UDP Dispatcher (Standard: 58888) [default: 58888]
       -c, --config <CONFIG>  Pfad zur networks.json (optional)
       -h, --help             Print help
     ```
   - **Observed Exit Code**: `0`

---

### 1.4 Additional Adversarial Stress Tests

The following empirical attack vectors were executed against `sb node bootstrap`:

| Vector Category | Command / Payload Tested | Expected | Actual Output / Exit Code | Pass? |
|---|---|---|---|---|
| **Target User Injection** | `cargo run -p sb-cli -- node bootstrap 'root; id@145.223.83.235' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Initial-Benutzername: 'root; id'` (Exit 1) | PASS |
| **Target Host Injection** | `cargo run -p sb-cli -- node bootstrap 'root@145.223.83.235; rm -rf /' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Hostname oder IP-Adresse: '145.223.83.235; rm -rf /'` (Exit 1) | PASS |
| **Admin Least-Privilege** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin root --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Der dedizierte Admin-Benutzer darf nicht 'root' sein (Least-Privilege-Prinzip).` (Exit 1) | PASS |
| **Admin Shell Injection** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin 'sbadmin; id' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Admin-Benutzername: 'sbadmin; id' (nur a-z, 0-9, _, - bis max. 32 Zeichen)` (Exit 1) | PASS |
| **Admin Command Substitution** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin 'sbadmin$(whoami)' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Admin-Benutzername: 'sbadmin$(whoami)'` (Exit 1) | PASS |
| **Admin Max Length (36 chars)** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin abcdefghijklmnopqrstuvwxyz0123456789 --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Admin-Benutzername: 'abcdefghijklmnopqrstuvwxyz0123456789'` (Exit 1) | PASS |
| **Port Boundary (Port 0)** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -p 0 --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger SSH-Port: 0` (Exit 1) | PASS |
| **CA-Key Non-Ed25519** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-rsa AAA..." --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Muss mit 'ssh-ed25519 AAA' beginnen (RFC 4251 Wire Format).` (Exit 1) | PASS |
| **CA-Key Backtick Sub** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key 'ssh-ed25519 AAA`whoami`' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen...` (Exit 1) | PASS |
| **CA-Key Semicolon** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key 'ssh-ed25519 AAA; id;' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen...` (Exit 1) | PASS |
| **CA-Key Double Quote** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key 'ssh-ed25519 AAA\"foo\"' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen...` (Exit 1) | PASS |
| **CA-Key Newline Injection** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA`nTrustedUserCAKeys /evil" --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen oder Zeilenumbrüche...` (Exit 1) | PASS |
| **Mesh Token Empty Base64** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token 'sbm-pair://' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Format muss 'sbm-pair://<base64>' entsprechen.` (Exit 1) | PASS |
| **Mesh Token Invalid Chars** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token 'sbm-pair://not_valid_base64!@#' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Format muss 'sbm-pair://<base64>' entsprechen.` (Exit 1) | PASS |
| **Mesh Token Semicolon** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token 'sbm-pair://abc;rm -rf /' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Format muss 'sbm-pair://<base64>' entsprechen.` (Exit 1) | PASS |
| **Mesh Token Wrong Schema** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token 'http://not-sbm-pair' --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Format muss mit 'sbm-pair://' beginnen.` (Exit 1) | PASS |
| **Mesh Token Newline** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://abc`nid" --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Enthält unzulässige Metazeichen oder Zeilenumbrüche.` (Exit 1) | PASS |
| **Mesh Name Length (64 chars)** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m <64-chars> --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Mesh-Name: '...' (nur a-z, 0-9, _, - bis max. 63 Zeichen)` (Exit 1) | PASS |
| **Multi-Mesh Malicious Element**| `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m dev -m "stage; reboot" --dry-run` | Exit 1 | `Fehler beim Node-Bootstrap: Ungültiger Mesh-Name: 'stage; reboot' (nur a-z, 0-9, _, - bis max. 63 Zeichen)` (Exit 1) | PASS |
| **Password Credential Leak** | `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --password "SuperSecretP@ssw0rd!" --dry-run` | Password not logged, exit 0 | Output inspected: string `SuperSecretP@ssw0rd!` does not appear in stdout or stderr. | PASS |

---

### 1.5 Test Suites Execution

1. **Bootstrap Module Unit Tests**:
   - `cargo test -p sb-cli --bin sb commands::bootstrap` -> **15 passed, 0 failed**.
2. **`sb-cli` Full Test Suite**:
   - `cargo test -p sb-cli` -> **100 passed, 0 failed**.
3. **Workspace Compilation**:
   - `cargo check --workspace` -> **0 compiler errors, 0 warnings**.

---

## 2. Logic Chain

1. **Observation 1.1** proves that all three mandated injection vectors (`-m`, `--ca-key`, `--mesh-token`) are intercepted prior to any remote command execution, formatting, or transport dispatch. The errors originate in `handle_node_bootstrap` (`tools/sb/src/commands/bootstrap.rs:824-862`) and bubble to `tools/sb/src/main.rs:287`, which prints to `stderr` and executes `std::process::exit(1)`.
2. **Observation 1.2** proves that valid arguments generate a complete, valid 6-phase execution plan in dry-run mode and terminate cleanly with exit code `0`.
3. **Observation 1.3** proves that backwards compatibility is strictly preserved: invoking `sb node` displays node HUD status, `sb node --help` details subcommands, and invoking `sb node daemon --help` (or any other subcommand) forwards arguments directly to the underlying `sb-node` binary via the `External` clap subcommand.
4. **Observation 1.4** demonstrates through 20 distinct empirical stress tests that input validation is comprehensive across all parameters (target, admin, port, ca-key, mesh-token, mesh names, password redaction). All malicious payloads are rejected with exit code `1` and descriptive messages without leaking internal traces or credentials.
5. **Observation 1.5** confirms that all 100 tests in `sb-cli` pass without regressions and compiler checks report zero warnings or errors.
6. Therefore, the CLI argument parsing and injection rejection mechanisms for Milestone 3 satisfy all security, functional, and compatibility requirements.

---

## 3. Caveats

- Live network deployment against VPS `145.223.83.235` was not executed as part of this CLI challenge; per `PROJECT.md`, live server deployment and end-to-end verification are scheduled for Milestone 5.
- No other caveats.

---

## 4. Conclusion

The CLI argument parsing and injection rejection implementation in `sb node bootstrap` is robust, secure, and fully backward-compatible. All mandated vectors, additional edge cases, and backward compatibility paths have been empirically tested and verified.

**Verdict: APPROVE**

---

## 5. Verification Method

To independently reproduce and verify this assessment:

1. **Run mandated injection rejection checks**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 -m 'dev"; rm -rf /; echo "' --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key 'ssh-ed25519 AAA''; id; echo ''' --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token 'sbm-pair://abc''; id; echo ''' --dry-run
   ```
   *Verification criterion*: Each exits with status code `1`.

2. **Run valid dry-run check**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
   *Verification criterion*: Exits with status code `0` and renders the 6-phase bootstrap plan.

3. **Run backward compatibility checks**:
   ```powershell
   cargo run -p sb-cli -- node
   cargo run -p sb-cli -- node --help
   cargo run -p sb-cli -- node daemon --help
   ```
   *Verification criterion*: Each exits with status code `0`.

4. **Run test suites**:
   ```powershell
   cargo check --workspace
   cargo test -p sb-cli --bin sb commands::bootstrap
   cargo test -p sb-cli
   ```
   *Verification criterion*: 0 compiler warnings/errors, 15/15 bootstrap tests passed, 100/100 `sb-cli` tests passed.
