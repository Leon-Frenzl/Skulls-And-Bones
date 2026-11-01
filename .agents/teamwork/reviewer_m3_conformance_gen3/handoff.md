# Handoff Report: Milestone 3 Conformance & Adversarial Review (`sb node bootstrap`)

**Author:** `reviewer_m3_conformance_gen3` (reviewer, critic)  
**Target:** Orchestrator (`cc783d5e-4bd0-4308-8ca7-5252a7088535`)  
**Scope:** Milestone 3 / Requirement R2 (`sb node bootstrap` Conformance, Security & Backward Compatibility)  
**Date:** 2026-10-28T01:22:00Z  
**Verdict:** **REQUEST_CHANGES**

---

## Review Summary

**Verdict**: **REQUEST_CHANGES**

The Milestone 3 implementation establishes an impressive, well-structured 6-phase architecture with backward compatibility, CIS Linux Benchmark Level 2 sandboxing, transactional SSHD pre-validation, and rollback capabilities. However, adversarial scrutiny and code auditing revealed **two functional defects** and **one security vulnerability** that prevent production readiness:
1. **Critical Functionality Bug**: `--password` parameter is accepted and zeroized in `handle_node_bootstrap`, but is **never passed** to `sb-ssh` (via `cmd.env("SB_SSH_PASSWORD", ...)` or `std::env::set_var("SB_SSH_PASSWORD", ...)`), causing password-authenticated bootstrapping against fresh servers to fail completely.
2. **Major Transport Bug**: `SshTransport::upload` omits the `-p <port>` argument, causing SFTP binary and runner script uploads to attempt port 22 and fail whenever a non-standard SSH port (`--port`) is specified.
3. **Major Security Vulnerability (CWE-78 / CWE-116)**: Shell script templating in `generate_runner_script` fails to sanitize or character-bound `--ca-key`, `--mesh-token`, and `--mesh` parameters against single-quotes, double-quotes, or newlines, exposing the remote root execution environment to command injection.
4. **Minor Lifecycle Issue**: Phase 5 starts `sb-node.service` *before* Phase 6 executes `sb-node init --token`, and never restarts the service after onboarding, leaving the running daemon uninitialized with swarm credentials.
5. **Minor Usability Issue**: `--force` CLI flag is accepted by `BootstrapArgs` but never inspected or utilized in the provisioning logic.

---

## 1. Observation

Direct observations from the local codebase, build tools, tests, and execution outputs:

### 1.1 Compilation and Test Suite Verification
1. **`cargo check --workspace`**:
   Command: `cargo check --workspace`
   Result: Exit code 0, 0 compiler errors, 0 compiler warnings (duration: 2.37s).
2. **`cargo test -p sb-cli`**:
   Command: `cargo test -p sb-cli`
   Result: Exit code 0, 97 passed, 0 failed, finished in 6.53s.
   Includes passing tests in `commands::bootstrap::tests`:
   - `test_ssh_target_parsing_valid` (ok)
   - `test_ssh_target_parsing_rejects_injection` (ok)
   - `test_admin_username_validation` (ok)
   - `test_generate_sshd_ca_config` (ok)
   - `test_generate_systemd_service` (ok)
   - `test_generate_sudoers_entry` (ok)
   - `test_generate_runner_script_contains_rollback_and_visudo` (ok)
   - `test_cli_parsing_node_bootstrap_dry_run` (ok)
   - `test_cli_parsing_node_bootstrap_with_flags` (ok)
   - `test_cli_backward_compatibility_node_external` (ok)
   - `test_cli_backward_compatibility_node_empty` (ok)
   - `test_resolve_ca_public_key_format_validation` (ok)
3. **Dry-Run Execution**:
   Command: `cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run`
   Result: Exit code 0. Displays full 6-phase plan and artifacts without remote mutations.

### 1.2 CLI and Backward Compatibility Verification
4. **`tools/sb/src/cli.rs`**:
   - Lines 211–214:
     ```rust
     Node {
         #[command(subcommand)]
         action: Option<NodeAction>,
     },
     ```
   - Lines 938–992:
     `NodeAction` enum correctly defines `Bootstrap(BootstrapArgs)` and `#[command(external_subcommand)] External(Vec<String>)`.
     `BootstrapArgs` declares all required flags: `target`, `--port`, `--key`, `--password`, `--admin`, `--ca-key`, `--mesh-token`, `--mesh`, `--binaries`, `--force`, `--dry-run`.
5. **`tools/sb/src/main.rs`**:
   - Lines 283–296:
     ```rust
     Some(Commands::Node { action }) => match action {
         Some(cli::NodeAction::Bootstrap(args)) => {
             if let Err(e) = commands::bootstrap::handle_node_bootstrap(args) {
                 eprintln!("Fehler beim Node-Bootstrap: {}", e);
                 std::process::exit(1);
             }
         }
         Some(cli::NodeAction::External(args)) => {
             delegate_to("node", "sb-node", &args);
         }
         None => {
             delegate_to("node", "sb-node", &[]);
         }
     },
     ```
   - Independent verification confirms that `sb node` alone, `sb node --help`, and `sb node daemon ...` transparently delegate to `sb-node`.

### 1.3 Code Inspection & Defect Observations
6. **Password Ignored**:
   In `tools/sb/src/commands/bootstrap.rs`:
   - Line 766: `defer_zeroize(&mut args.password);`
   - In `SshTarget`: `password` is omitted from fields (lines 32–38).
   - In `SshTransport::new`: no password received or saved (lines 114–123).
   - In `SshTransport::exec` (lines 136–157) and `SshTransport::upload` (lines 170–207): neither `cmd.env("SB_SSH_PASSWORD", ...)` nor `std::env::set_var("SB_SSH_PASSWORD", ...)` is called.
   - Contrast with `tools/sb/src/commands/fleet.rs:554-556`:
     ```rust
     if let Some(ref pwd) = password_opt {
         std::env::set_var("SB_SSH_PASSWORD", pwd);
     }
     ```
   - `args.password` is never passed to `sb-ssh`.

7. **Missing Port in SFTP Upload**:
   In `tools/sb/src/commands/bootstrap.rs`:
   - `SshTransport::exec` (lines 137–138):
     ```rust
     let mut cmd = Command::new(&self.ssh_bin);
     cmd.args(["-p", &self.target.port.to_string()]);
     ```
   - `SshTransport::upload` (lines 175–183):
     ```rust
     let mut cmd = Command::new(&self.ssh_bin);
     if let Some(ref id) = self.target.identity {
         cmd.args(["-i", &id.to_string_lossy()]);
     }
     cmd.arg("push");
     cmd.arg(self.target.target_string());
     cmd.arg(local_path);
     cmd.arg(remote_path);
     ```
   - The `-p` port parameter is completely omitted before or after `push`. Testing `sb-ssh -p <PORT> push` confirmed that `sb-ssh` requires `-p` as an option before `push` to target non-standard ports.

8. **Script Injection in Runner Generation**:
   In `tools/sb/src/commands/bootstrap.rs`:
   - Lines 320–326:
     ```rust
     if let Some(key) = ca_key_arg {
         let trimmed = key.trim();
         if !trimmed.starts_with("ssh-ed25519 AAA") {
             return Err("Ungültiger Swarm-CA Key: Muss mit 'ssh-ed25519 AAA' beginnen (RFC 4251 Wire Format).".to_string());
         }
         return Ok(trimmed.to_string());
     }
     ```
     Does not check for `'`, `"`, `\n`, or `\r`.
   - Lines 361–367:
     ```rust
     pub fn resolve_pairing_token(token_arg: Option<&str>, node_name: &str, ca_pubkey: &str) -> String {
         if let Some(token) = token_arg {
             token.trim().to_string()
         } else {
             crate::commands::fleet::build_pairing_token("sbm-swarm-default", node_name, ca_pubkey)
         }
     }
     ```
     Does not call `parse_pairing_token` or check for `'`, `"`, `\n`, or `\r`.
   - Lines 531–538:
     ```rust
     let mut mesh_cmds = String::new();
     for m in &meshes {
         mesh_cmds.push_str(&format!(
             "if [ -x /usr/local/bin/sb-mesh ]; then\n\
              \x20   sudo -u \"{admin_user}\" /usr/local/bin/sb-mesh bootstrap --headless -n \"{m}\" -a \"127.0.0.1:58888\" 2>/dev/null || true\n\
              fi\n"
         ));
     }
     ```
     `m` is unvalidated and directly interpolated inside double quotes into the bash runner script.
   - Contrast with `tools/sb/src/commands/fleet.rs:498` and `fleet.rs:506`:
     ```rust
     if ca_key.is_empty() || ca_key.contains('\n') || ca_key.contains('\r') || ca_key.contains('\'') { ... }
     if token.contains('\'') || token.contains('\n') || token.contains('\r') { ... }
     ```

9. **Daemon Lifecycle Order**:
   In `generate_runner_script` (lines 695–723):
   - Phase 5 restarts `sb-node.service` (`systemctl restart sb-node`) and probes UDP 58888.
   - Phase 6 follows Phase 5 and executes `sudo -u "$ADMIN" /usr/local/bin/sb-node init --token '{pairing_token}'`.
   - No subsequent `systemctl restart sb-node` is issued after `init`.

10. **Dead Flag `--force`**:
    `args.force` is declared in `BootstrapArgs` (line 987) but never accessed in `bootstrap.rs`.

---

## 2. Logic Chain

1. **Premise 1 (Authenticity and Authentication Feasibility)**:
   Requirement R2 specifies: "Authenticate via standard OpenSSH credentials to fresh Linux hosts." On bare-metal and fresh VPS instances (such as `145.223.83.235` initialized with root password `aKjn?KN@2t&G'2Bs`), operators rely on `--password` for the initial connect. By Observation 6, `args.password` is never delivered to `sb-ssh` or set in the environment. Therefore, any attempt to bootstrap using `--password` will fail authentication immediately.

2. **Premise 2 (Transport Integrity Across Non-Default Ports)**:
   Observation 7 demonstrates that `SshTransport::upload` omits `-p <port>`. If an operator specifies `-p 2222`, `exec` connects to 2222, but `upload` connects to port 22. This causes an immediate failure during Phase 2 (file not uploaded or connection refused) whenever a custom port is used.

3. **Premise 3 (Remote Execution Boundary Security)**:
   Observation 8 demonstrates that user-provided `--ca-key`, `--mesh-token`, and `--mesh` parameters are interpolated directly into a bash script executed as root. While `admin_user`, `target.user`, and `target.host` are strictly validated, these three parameters lack boundary assertions against shell delimiters (`'`, `"`, `\n`). This constitutes a CWE-78 / CWE-116 vulnerability.

4. **Premise 4 (Service Initialization Consistency)**:
   Observation 9 demonstrates that `sb-node.service` is started before `sb-node init --token` is executed, and is not restarted afterwards. In `fleet.rs:577`, `sb-node init` is executed first, followed by `systemctl restart sb-node`. Starting the service prior to initialization risks running the daemon without its bound swarm credentials.

5. **Conclusion**:
   While the core workspace builds and unit tests pass, the three defects in authentication, upload transport, and script templating directly undermine the reliability and security of `sb node bootstrap`. Therefore, changes must be requested and resolved before approval.

---

## 3. Detailed Findings

### [Critical] Finding 1: SSH Password Parameter `--password` Is Discarded (CWE-684)

- **What**: The `--password <PASSWORD>` CLI parameter is received and zeroized on return, but never passed to `sb-ssh` or set in the child process execution environment.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, lines 136–157 (`SshTransport::exec`), lines 170–207 (`SshTransport::upload`), and lines 766–767 (`handle_node_bootstrap`).
- **Why**: `sb-ssh` reads authentication passwords from the `SB_SSH_PASSWORD` environment variable (as shown in `fleet.rs:555`). Without passing `cmd.env("SB_SSH_PASSWORD", pwd)` or setting `std::env::set_var("SB_SSH_PASSWORD", pwd)`, password-based remote onboarding to fresh Linux VPS hosts (e.g. `root@145.223.83.235`) fails with an authentication error.
- **Suggestion**:
  1. Add `pub password: Option<String>` to `SshTarget` and `SshTransport`.
  2. In `SshTransport::exec` and `SshTransport::upload`, if password is present, pass `.env("SB_SSH_PASSWORD", pwd)` to the child `Command`.
  3. Ensure that when `args.password` is extracted into `SshTarget`, it remains protected and zeroized on drop.

---

### [Major] Finding 2: `SshTransport::upload` Drops the Port Parameter (CWE-20)

- **What**: `SshTransport::upload` omits the SSH port argument `-p <port>` when executing `sb-ssh push`.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, line 175.
- **Why**: `exec` passes `cmd.args(["-p", &self.target.port.to_string()])`, but `upload` omits it. If `--port <port>` is specified (e.g. `--port 2222`), `upload` will attempt to connect to port 22, causing SFTP staging upload to fail on hosts with hardened SSH ports.
- **Suggestion**:
  In `SshTransport::upload`, pass `cmd.args(["-p", &self.target.port.to_string()]);` prior to `push`.

---

### [Major] Finding 3: Shell Metacharacter Injection in Runner Script (CWE-78 / CWE-116)

- **What**: Runner script templating in `generate_runner_script` interpolates `ca_pubkey`, `pairing_token`, and `mesh` names without sanitizing or rejecting single quotes, double quotes, and newlines.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, lines 320–326 (`resolve_ca_public_key`), lines 361–367 (`resolve_pairing_token`), and lines 531–538 (`mesh` iteration).
- **Why**:
  - `resolve_ca_public_key` only checks `starts_with("ssh-ed25519 AAA")`. A payload like `ssh-ed25519 AAA...'; reboot; '` breaks out of `echo '{ca_pubkey}' >> ...`.
  - `resolve_pairing_token` does not validate `token_arg`. A token containing `'` breaks out of `'--token '{pairing_token}'`.
  - `args.mesh` elements are interpolated into `"-n \"{m}\""`. A value containing `" ; evil_cmd ; #` achieves root command execution.
- **Suggestion**:
  1. In `resolve_ca_public_key`: Enforce that the key contains no newlines (`\n`, `\r`) or single-quotes (`'`), and strictly validate standard OpenSSH public key characters (`[a-zA-Z0-9+/=@._ -]`).
  2. In `resolve_pairing_token`: If `token_arg` is provided, validate via `crate::commands::fleet::parse_pairing_token` or verify it contains no `'`, `"`, `\n`, `\r`.
  3. For each mesh in `args.mesh`: Validate with `is_valid_nodename(m)` or restrict to alphanumeric, hyphen, underscore.

---

### [Minor] Finding 4: Phase 5 / Phase 6 Daemon Startup Ordering

- **What**: Phase 5 starts and probes `sb-node.service` before Phase 6 runs `sb-node init --token`.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, lines 695–723.
- **Why**: `sb-node init --token` binds the server identity and generates swarm configuration. Starting the daemon before initialization means the daemon boots up uninitialized, and without a subsequent reload/restart in Phase 6, may not activate swarm communications.
- **Suggestion**:
  Either run `sb-node init --token` before enabling/starting `sb-node.service`, or add `systemctl restart sb-node` after Phase 6 completes onboarding (identical to `fleet.rs:577`).

---

### [Minor] Finding 5: CLI Flag `--force` Is Unused Dead Code

- **What**: `--force` (`-f`) is declared on `BootstrapArgs` but never inspected in `bootstrap.rs`.
- **Where**: `tools/sb/src/commands/bootstrap.rs`, line 739.
- **Why**: Operators specifying `--force` expect destructive overwrite of existing accounts or configurations, but the flag currently has no effect.
- **Suggestion**:
  Either hook `--force` into decision branches (e.g. recreating user, resetting `.sb` directory, or overwriting drop-ins unconditionally), or document its scope.

---

## 4. Adversarial Challenge & Stress-Testing

### Challenge 1: SSH Port Divergence
- **Scenario**: Operator runs `sb node bootstrap user@target.host -p 2222`.
- **Observed Behavior**: `probe` succeeds on port 2222; `create_staging_dir` succeeds on port 2222; then `upload` executes `sb-ssh push user@target.host /tmp/...` without `-p 2222` and attempts port 22.
- **Result**: Connection refused / timeout on port 22.
- **Status**: **CONFIRMED DEFECT**.

### Challenge 2: Headless Password Bootstrapping
- **Scenario**: Operator runs `sb node bootstrap root@145.223.83.235 --password "aKjn?KN@2t&G'2Bs"`.
- **Observed Behavior**: Password is never exported to `SB_SSH_PASSWORD`. `sb-ssh` attempts public key auth, fails, and prompts for interactive input or aborts.
- **Result**: Automated bootstrap fails on password-only machines.
- **Status**: **CONFIRMED DEFECT**.

### Challenge 3: Malicious Mesh Identifier Injection
- **Scenario**: Operator runs `sb node bootstrap root@host -m 'dev"; rm -rf /tmp/test; echo "'`.
- **Observed Behavior**: Runner script generates:
  `sudo -u "sbadmin" /usr/local/bin/sb-mesh bootstrap --headless -n "dev"; rm -rf /tmp/test; echo "" -a "127.0.0.1:58888"`.
- **Result**: Arbitrary shell command `rm -rf /tmp/test` executes as root on the target host.
- **Status**: **CONFIRMED VULNERABILITY**.

---

## 5. Verified Claims

- `cargo check --workspace` completes with 0 errors and 0 warnings: **PASS** (verified: 2.37s).
- `cargo test -p sb-cli` passes 97/97 tests: **PASS** (verified: 6.53s).
- Backward compatibility for `sb node`, `sb node --help`, and `sb node daemon ...`: **PASS** (verified).
- Dry-run simulation prints execution plan without remote mutations: **PASS** (verified: exit code 0).
- Integrity check (no hardcoded test results, facade implementations, or bypassed work): **PASS** (verified: genuine implementation).

---

## 6. Caveats

- Live remote execution against `145.223.83.235` was not performed during this review turn, as live target deployment is explicitly assigned to Milestone 5 in `PROJECT.md`.
- No other caveats.

---

## 7. Conclusion

Milestone 3's foundation is structurally solid, but due to **Finding 1 (Password not propagated)**, **Finding 2 (Port dropped in upload)**, and **Finding 3 (Command injection in runner script)**, the implementation cannot be approved for live production deployment in its current state.

**Verdict: REQUEST_CHANGES**

Once the implementer addresses Findings 1, 2, and 3, Milestone 3 will be fully compliant with Requirement R2 and ready for live verification.

---

## 8. Verification Method

To verify these findings:
1. **Verify Password Drop**:
   Inspect `tools/sb/src/commands/bootstrap.rs` lines 765–770 and search for any reference to `SB_SSH_PASSWORD` or `cmd.env`. Confirm neither exists.
2. **Verify Missing Port in Upload**:
   Inspect `tools/sb/src/commands/bootstrap.rs` line 175 (`SshTransport::upload`). Compare with line 137 (`SshTransport::exec`) and observe the absence of `cmd.args(["-p", ...])`.
3. **Verify Runner Script Injection**:
   Generate runner script with a mesh name containing `"` or a CA key containing `'`. Inspect the generated bash string and observe unescaped command injection.
