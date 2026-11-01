# Challenger Verification Report: Milestone 3 — CLI Argument Parsing, Dry-Run Execution & Security Hardening

**Author:** `challenger_m3_r3_cli` (critic, specialist)  
**Target:** `orchestrator_3` (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Scope:** CLI Argument Parsing, Backward Compatibility, Dry-Run Execution, and Injection Resistance (`tools/sb/src/cli.rs`, `tools/sb/src/main.rs`, `tools/sb/src/commands/bootstrap.rs`)  
**Date:** 2026-10-28T01:53:00Z  
**Type:** Hard Handoff (Task Complete)  
**Verdict:** **`APPROVE`**

---

## 1. Observation

1. **Backward Compatibility Testing**:
   - Command: `cargo run -p sb-cli -- node`
     - Result: Exited with code `0`.
     - Output:
       ```text
       ══════════════════════════════════════════════════════════════════
         SKULLS & BONES // SB-NODE FLOTTENKNOTEN STATUS
       ══════════════════════════════════════════════════════════════════
         Knoten-Identität:        desktop-33ar5nl
         Overlay-Adresse:         desktop-33ar5nl.sbm
         Status:                  BEREIT / MULTI-TENANT ANCHOR
         Hintergrunddienst:       STOPPED
         Dispatcher Port:         58888 (UDP Single-Port)
         Socket-Sicherheit:       0 Leaks
       ```
     - Verification: In `tools/sb/src/main.rs` (lines 283–296), `Commands::Node { action: None }` correctly delegates to `commands::delegate::delegate_to("node", "sb-node", &[])`.
   - Command: `cargo run -p sb-cli -- node --help`
     - Result: Exited with code `0`.
     - Output displayed subcommand help:
       ```text
       Delegiert an S&B Server Agent (sb-node) — Headless Daemon & Port Watchdog, oder führt Node-Bootstrap aus

       Usage: sb.exe node [COMMAND]

       Commands:
         bootstrap  1-Befehl Remote Server Provisioning via SSH & Swarm-CA
         help       Print this message or the help of the given subcommand(s)
       ```
   - Command: `cargo run -p sb-cli -- node daemon --help`
     - Result: Exited with code `0`.
     - Output:
       ```text
       Startet den Multi-Tenant Headless Daemon (Port 58888 Single-Port Dispatcher & Relays)

       Usage: sb-node.exe daemon [OPTIONS]

       Options:
         -p, --port <PORT>      Port für den Single-Port UDP Dispatcher (Standard: 58888) [default: 58888]
         -c, --config <CONFIG>  Pfad zur networks.json (optional)
         -h, --help             Print help
       ```
     - Verification: In `tools/sb/src/cli.rs` (lines 938–946), `NodeAction::External(Vec<String>)` with `#[command(external_subcommand)]` captures all unmapped subcommands and flags and transparently invokes `sb-node`.

2. **Dry-Run Execution Verification**:
   - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run`
     - Result: Exited with code `0`.
     - Verbatim Output:
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
     - Verification: No network requests, SSH sockets, or remote commands were initiated.

3. **Injection and Adversarial Stress-Testing**:
   Each adversarial attack vector was executed against the binary and evaluated:
   - Target Semicolon Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap "root@145.223.83.235;reboot" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Hostname oder IP-Adresse: '145.223.83.235;reboot'` (Exit code: `1`).
   - Target Pipe Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap "root@145.223.83.235|reboot" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Hostname oder IP-Adresse: '145.223.83.235|reboot'` (Exit code: `1`).
   - Target Ampersand Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap "root@145.223.83.235&&reboot" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Hostname oder IP-Adresse: '145.223.83.235&&reboot'` (Exit code: `1`).
   - Target Subshell Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap 'root@145.223.83.235$(whoami)' --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Hostname oder IP-Adresse: '145.223.83.235$(whoami)'` (Exit code: `1`).
   - Target Username Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap 'user;reboot@145.223.83.235' --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Initial-Benutzername: 'user;reboot'` (Exit code: `1`).
   - Admin Parameter Command Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin "sbadmin;reboot" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Admin-Benutzername: 'sbadmin;reboot' (nur a-z, 0-9, _, - bis max. 32 Zeichen)` (Exit code: `1`).
   - Admin Parameter Root Assignment (Least-Privilege Enforcement):
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin root --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Der dedizierte Admin-Benutzer darf nicht 'root' sein (Least-Privilege-Prinzip).` (Exit code: `1`).
   - Admin Parameter Subshell Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin 'user$(id)' --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Admin-Benutzername: 'user$(id)' (nur a-z, 0-9, _, - bis max. 32 Zeichen)` (Exit code: `1`).
   - Mesh Name Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh "dev;reboot" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Mesh-Name: 'dev;reboot' (nur a-z, 0-9, _, - bis max. 63 Zeichen)` (Exit code: `1`).
   - Swarm CA Key Semicolon Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA;rm -rf /" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen oder Zeilenumbrüche (RFC 4251 / OpenSSH Format erforderlich).` (Exit code: `1`).
   - Swarm CA Key Quote Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA'rm -rf /" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Enthält unzulässige Zeichen oder Zeilenumbrüche (RFC 4251 / OpenSSH Format erforderlich).` (Exit code: `1`).
   - Swarm CA Key Invalid Prefix:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key invalid-prefix --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Swarm-CA Key: Muss mit 'ssh-ed25519 AAA' beginnen (RFC 4251 Wire Format).` (Exit code: `1`).
   - Mesh Token Subshell Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token 'sbm-pair://$(id)' --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Format muss 'sbm-pair://<base64>' entsprechen.` (Exit code: `1`).
   - Mesh Token Semicolon Injection:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://abc;reboot" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Format muss 'sbm-pair://<base64>' entsprechen.` (Exit code: `1`).
   - Mesh Token Invalid Scheme:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "invalid-scheme" --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiges Pairing-Token: Format muss mit 'sbm-pair://' beginnen.` (Exit code: `1`).
   - Boundary Check - Port 0:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --port 0 --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger SSH-Port: 0` (Exit code: `1`).
   - Boundary Check - Whitespace Target:
     - Command: `cargo run -p sb-cli -- node bootstrap "   " --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Zielserver darf nicht leer sein.` (Exit code: `1`).
   - Boundary Check - Whitespace Admin:
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin "   " --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Admin-Benutzername: '   ' (nur a-z, 0-9, _, - bis max. 32 Zeichen)` (Exit code: `1`).
   - Boundary Check - Overlong Admin Username (>32 chars):
     - Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin a_very_long_username_exceeding_thirty_two_chars --dry-run`
     - Output: `Fehler beim Node-Bootstrap: Ungültiger Admin-Benutzername: 'a_very_long_username_exceeding_thirty_two_chars' (nur a-z, 0-9, _, - bis max. 32 Zeichen)` (Exit code: `1`).

4. **Automated Test Suites**:
   - `cargo test -p sb-cli`: `test result: ok. 100 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.90s`.
   - `cargo test -p sb-ca`: `test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out` (including adversarial security, e2e_ssh_ca, and e2e_x509_ca).
   - `cargo check --workspace`: Finished with `0 errors, 0 warnings`.
   - `cargo test --workspace`: 100% pass across all workspace crates (`finished in 20.51s`).

---

## 2. Logic Chain

1. **Backward Compatibility Preservation**:
   - Prior to Milestone 3, `sb node` commands delegated transparently to `sb-node`.
   - In `tools/sb/src/cli.rs`, `Commands::Node` has `action: Option<NodeAction>`. When no action is given (`sb node`), line 294 of `main.rs` dispatches `delegate_to("node", "sb-node", &[])`, which was empirically demonstrated in Observation 1 to print the expected `sb-node` status HUD with exit code 0.
   - For subcommands other than `bootstrap` (such as `daemon --help`), `NodeAction::External(Vec<String>)` forwards all arguments unmodified to `sb-node` (line 291 of `main.rs`), which Observation 1 proved outputs the `sb-node.exe daemon` help with exit code 0.
   - Therefore, backward compatibility is fully intact and regression-free.

2. **Dry-Run Determinism & Safety**:
   - In `tools/sb/src/commands/bootstrap.rs` (lines 872–931), when `args.dry_run == true`, the function renders the structured 6-phase provisioning plan and immediately returns `Ok(())` without instantiating `SshTransport` or dispatching any subprocesses.
   - Observation 2 proved that running `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run` exited cleanly with code 0 and displayed the full configuration, resolving the Swarm CA key and pairing token locally.

3. **Input Sanitization & Injection Defense**:
   - All input parameters (`target`, `admin`, `mesh`, `ca_key`, `mesh_token`, `port`) pass through strict validation gates before any phase executes:
     - `SshTarget::parse` enforces regex allow-lists on user (`[a-zA-Z0-9_-]`, max 32 chars) and host (`[a-zA-Z0-9.-:]`, max 253 chars), rejecting shell metacharacters and port 0.
     - `validate_admin_username` prevents privilege escalation by rejecting `"root"` and enforcing alphanumeric charset and 32-character limits.
     - `resolve_ca_public_key` enforces RFC 4251 wire format prefix `ssh-ed25519 AAA` and rejects quotes, newlines, and non-OpenSSH characters.
     - `resolve_pairing_token` strictly validates `sbm-pair://` URI scheme and base64 character set.
     - `mesh` names are validated against `is_valid_nodename` (max 63 chars, alphanumeric + `-` + `_`).
   - Observation 3 empirically verified across 18 distinct attack vectors that all malicious inputs are rejected with exit code 1 (or 2 for clap syntax constraints), preventing command injection, privilege escalation, and format poisoning.

4. **Workspace Stability**:
   - Observation 4 verified that all 100 tests in `sb-cli`, all security tests in `sb-ca`, and all tests across the entire cargo workspace pass with zero compiler warnings and zero failures.

---

## 3. Caveats

- No caveats. All tasks assigned to this role were executed empirically in the live workspace.

---

## 4. Conclusion

The CLI argument parsing, backward compatibility delegation, dry-run simulation, and security boundary defenses of `sb node bootstrap` in `sb-cli` are robust, mathematically sound, and empirically verified. All 4 verification criteria outlined in the dispatch message have been met with zero regressions and zero failures.

**Final Verdict:** **`APPROVE`**

---

## 5. Verification Method

To independently reproduce the empirical findings of this report:

1. **Verify Backward Compatibility**:
   ```powershell
   cargo run -p sb-cli -- node
   cargo run -p sb-cli -- node --help
   cargo run -p sb-cli -- node daemon --help
   ```
   *Expected:* All three commands exit with code `0`.

2. **Verify Dry-Run Execution**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
   *Expected:* Exits with code `0`, displays 6-phase plan, makes no remote changes.

3. **Verify Injection Prevention**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap "root@145.223.83.235;reboot" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin "sbadmin;reboot" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --admin root --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh "dev;reboot" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --ca-key "ssh-ed25519 AAA;rm -rf /" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --mesh-token "sbm-pair://$(id)" --dry-run
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --port 0 --dry-run
   ```
   *Expected:* Every command fails closed and exits with code `1`.

4. **Verify Test Suites**:
   ```powershell
   cargo check --workspace
   cargo test -p sb-cli
   cargo test --workspace
   ```
   *Expected:* 0 compiler warnings/errors, 100% test pass rate.
