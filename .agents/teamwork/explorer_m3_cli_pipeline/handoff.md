# Handoff Report: `sb node bootstrap` CLI & Pipeline Orchestration Architecture

**Author**: `explorer_m3_cli_pipeline`  
**Date**: 2026-10-27T22:15:00Z  
**Target Milestone**: M3 (`sb node bootstrap` Remote Server Provisioning)  
**Status**: Completed (Read-only Investigation)

---

## 1. Observation

Direct observations from the local codebase, binary probes, and architecture contracts:

1. **Current `Node` Subcommand Structure in `tools/sb/src/cli.rs` (lines 211–214)**:
   ```rust
   /// Delegiert an S&B Server Agent (sb-node) — Headless Daemon & Port Watchdog
   Node {
       #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
       args: Vec<String>,
   },
   ```
   In `tools/sb/src/main.rs` (lines 283–285):
   ```rust
   Some(Commands::Node { args }) => {
       delegate_to("node", "sb-node", &args);
   }
   ```
   Any arguments passed to `sb node` are forwarded unconditionally via `delegate_to` to the `sb-node` executable. There are currently no typed subcommands or flag parsers under `sb node`.

2. **Existing Subcommand Action Pattern in `tools/sb/src/cli.rs`**:
   Existing subcommands with nested actions (`Server`, `Release`, `Drive`, `Env`, `Context`, `Config`) use dedicated enums:
   - Line 261–264: `Commands::Server { #[command(subcommand)] action: ServerAction }`
   - Line 869–936: `pub enum ServerAction` with variants `Init`, `Token`, `List`, `Provision`.
   - `commands/fleet.rs:413`: `pub fn handle_server_init(target, name_opt, port, identity, password_opt, user_opt, dry_run)`
   - `commands/provision.rs:211`: `pub fn handle_server_provision(host, user, admin, pubkey_file, port, meshes, binaries, print_script)`

3. **Dependencies in `tools/sb/Cargo.toml` (lines 40–47)**:
   ```toml
   sb-code = { version = "0.1.0", path = "../sb-code" }
   sb-app-contract = { path = "../sb-app-contract" }
   sb-core = { version = "0.2.0", path = "../sb-core" }
   sb-drive = { version = "0.2.0", path = "../sb-drive" }
   sb-mesh = { version = "0.3.0", path = "../sb-mesh" }
   sb-proxy = { version = "0.1.0", path = "../sb-proxy" }
   sb-key = { version = "0.1.0", path = "../sb-key" }
   zeroize = "1.8"
   ```
   `sb-ca` is not yet listed as a dependency in `tools/sb/Cargo.toml`.

4. **`sb-ca` Library API in `tools/sb-ca/src/lib.rs` & `tools/sb-ca/src/ssh/mod.rs`**:
   - `tools/sb-ca/Cargo.toml` exposes library `sb_ca` (`[lib] name = "sb_ca"`).
   - `sb_ca::ssh::ca_public_key_openssh() -> Result<String, CaError>` returns the standard OpenSSH wire format public key (`ssh-ed25519 AAAAC3... sovereign-swarm-ca@local`) suitable for `/etc/ssh/trusted_user_ca_keys`.
   - `sb_ca::SshCa::init_ca(force: bool) -> Result<SshCaStatus, CaError>` initializes the root CA keypair if missing.

5. **`sb-ssh` Binary Availability & SFTP Capabilities**:
   - `where.exe sb-ssh` returned `C:\Users\leonf\.cargo\bin\sb-ssh.exe` (Exit Code 0).
   - `sb-ssh push --help` output:
     `Usage: sb-ssh.exe push <TARGET> <LOCAL_PATH> [REMOTE_PATH]`
   - `sb-ssh` command execution:
     `sb-ssh.exe [OPTIONS] [TARGET] [COMMAND_ARGS]...`
     Supports `-p <PORT>`, `-i <IDENTITY_FILE>`, `-l <LOGIN_USER>`, `-o <OPTIONS>`, and `SB_SSH_PASSWORD` environment variable.
   - `sb_core::BinaryResolver::resolve_ssh()` (in `tools/sb-core/src/binary_resolver.rs:93`) resolves `sb-ssh` or falls back to system `ssh`.

6. **Target Machine & Inventory (`PROJECT.md` / `ORIGINAL_REQUEST.md`)**:
   - Target server: `145.223.83.235` (root / `aKjn?KN@2t&G'2Bs`).
   - Node agent listens on UDP port `58888` (`SinglePortDispatcher`).
   - Default admin user name: `sbadmin`.

---

## 2. Logic Chain

From the observations above, we deduce the following structural and design requirements:

1. **Seamless CLI Parsing Without Breaking Existing Delegation**:
   - Observation 1 shows that `sb node` previously passed all tokens to `sb-node`.
   - If we define `pub enum NodeAction` in `tools/sb/src/cli.rs` with:
     ```rust
     #[derive(Subcommand, Debug, Clone)]
     pub enum NodeAction {
         Bootstrap { ... },
         #[command(external_subcommand)]
         External(Vec<String>),
     }
     ```
     and update `Commands::Node`:
     ```rust
     Node {
         #[command(subcommand)]
         action: Option<NodeAction>,
     }
     ```
   - Then:
     - `sb node bootstrap <user@host> [flags...]` matches `NodeAction::Bootstrap`.
     - `sb node daemon`, `sb node status`, `sb node init`, etc., match `NodeAction::External(...)` and are forwarded via `delegate_to("node", "sb-node", &args)`.
     - `sb node` (no arguments) has `action: None` and forwards empty arguments to `sb-node` (displaying `sb-node` help).
   - This achieves 100% backward compatibility with zero regressions for existing `sb-node` commands while providing first-class typed Clap CLI parsing for `sb node bootstrap`.

2. **Flag Mapping & Strict Sanitization (CWE-78 Prevention)**:
   - Observation 2 and the requirements identify 11 CLI flags:
     - `target: String` (positional): Split into `[user@]host`. Validated with `is_valid_username` and `is_valid_host`. Default user `root`.
     - `--port <u16>` (`-p`): Default `22`. Validated range `1..=65535`.
     - `--key <PathBuf>` (`-k`, alias `--identity`, `-i`): Private key for initial connection.
     - `--password <String>`: Cleartext password for initial connection, zeroized via `zeroize::Zeroize` after use.
     - `--admin <String>` (`-a`): Default `"sbadmin"`. Validated with `is_valid_username` (must not be `"root"`).
     - `--ca-key <String>`: Explicit path or inline key. If omitted, fetched directly from `sb_ca::ssh::ca_public_key_openssh()`. Validated against RFC 4251 (`ssh-ed25519 AAA...`).
     - `--mesh-token <String>`: Explicit pairing token. If omitted, generated using `fleet::build_pairing_token`.
     - `--mesh <String>` (`-m`): Repeated mesh network names (default `vec!["dev".into()]`). Validated with `is_valid_nodename`.
     - `--binaries <PathBuf>` (`-b`): Local directory with pre-compiled Linux binaries (`sb-node`, `sb-mesh`).
     - `--force` (`-f`): Overwrite existing files/configs.
     - `--dry-run` (`-n`): Simulate and output generated configs without remote execution.

3. **Crate Dependency Addition**:
   - Observation 3 & 4 show `tools/sb` needs `sb-ca` to retrieve the OpenSSH Swarm-CA public key directly via Rust API instead of shelling out.
   - Adding `sb-ca = { version = "0.1.0", path = "../sb-ca" }` to `tools/sb/Cargo.toml` provides direct, type-safe access to `sb_ca::ssh::ca_public_key_openssh()`.

4. **Transport Layer Abstraction (`SshTransport`)**:
   - Observation 5 confirms `sb-ssh` provides `push` for file uploads and direct command execution, while `BinaryResolver` provides fallback to `ssh` / `scp`.
   - `SshTransport` encapsulates:
     - Command execution: `sb-ssh -p <port> [-i <key>] <user>@<host> "<command>"` (with `SB_SSH_PASSWORD` in environment if password provided), falling back to `ssh -p <port> -o StrictHostKeyChecking=accept-new [-i <key>] <user>@<host> "<command>"`.
     - Binary/file upload: `sb-ssh push <user>@<host> <local_file> <remote_path>`, falling back to `scp -P <port> -o StrictHostKeyChecking=accept-new <local_file> <user>@<host>:<remote_path>`.

5. **6-Phase Pipeline Orchestration in `tools/sb/src/commands/bootstrap.rs`**:
   - **Phase 1: Pre-Flight Probe**:
     - Remote check: `uname -s` (must be `Linux`), `uname -m`, `id -u` (must be root or sudoer), disk space.
     - Check existing `sb-node` installation and `sshd_config.d` state.
   - **Phase 2: SFTP Binary Upload & Integrity Check**:
     - Create staging: `mkdir -m 0700 -p /tmp/sb-bootstrap-staging`.
     - Upload binaries (`sb-node`, `sb-mesh` if available).
     - Compute SHA-256 locally, verify remote `sha256sum /tmp/sb-bootstrap-staging/*` matches. (CWE-353 mitigation).
     - Install: `install -m 0755 -o root -g root /tmp/sb-bootstrap-staging/sb-node /usr/local/bin/sb-node`.
     - Clean staging: `rm -rf /tmp/sb-bootstrap-staging`.
   - **Phase 3: OpenSSH Swarm-CA Anchoring & Rollback (CWE-754 / CWE-284 mitigation)**:
     - Install CA public key: `/etc/ssh/trusted_user_ca_keys` (mode `0644`).
     - Install drop-in: `/etc/ssh/sshd_config.d/99-sb-ca.conf`:
       ```text
       # === SKULLS & BONES SWARM CA BEGIN ===
       TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
       RevokedKeys /etc/ssh/revoked_keys
       PasswordAuthentication no
       KbdInteractiveAuthentication no
       PermitRootLogin prohibit-password
       PubkeyAuthentication yes
       # === SKULLS & BONES SWARM CA END ===
       ```
     - Transactional validation: Run `sshd -t`.
       - If `sshd -t` fails: Immediately `rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf` and abort without reload.
       - If `sshd -t` succeeds: `systemctl reload sshd || systemctl reload ssh`.
   - **Phase 4: Dedicated Unprivileged Admin User & Sudoers Hardening**:
     - Create user: `id -u <admin> || adduser --disabled-password --gecos '' <admin>`.
     - Write temporary sudoers: `/etc/sudoers.d/90-sb-<admin>.tmp` (`<admin> ALL=(ALL) NOPASSWD:ALL`).
     - Validate via `visudo -cf /etc/sudoers.d/90-sb-<admin>.tmp`.
     - If valid: `mv /etc/sudoers.d/90-sb-<admin>.tmp /etc/sudoers.d/90-sb-<admin>` and `chmod 0440`.
   - **Phase 5: Systemd Service Sandboxing (`sb-node.service`)**:
     - Deploy `/etc/systemd/system/sb-node.service` with strict sandboxing:
       `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `RestrictSUIDSGID=yes`, `RestrictNamespaces=yes`.
     - Writable paths: `/root/.sb /root/.sb-node /root/.sb-mesh /var/log /tmp`.
     - Run `systemctl daemon-reload && systemctl enable --now sb-node`.
     - Verify active daemon and UDP 58888 socket binding (`ss -ulpn | grep 58888`).
   - **Phase 6: Mesh Onboarding & Vault Registration**:
     - Execute `sb-node init --token '<token>'`.
     - For each mesh: `sb-mesh bootstrap --headless -n '<mesh>' -a '127.0.0.1:58888' || true`.
     - Register server in local vault (`~/.sb/vault/servers.json` or `register_server_in_vault`).
     - Display success HUD with mesh domain (`<node>.sbm`) and connection instructions (`sb ssh <node>.sbm`).

---

## 3. Caveats

1. **Non-Root Initial Login**: If the initial SSH login user is not `root` (e.g. `ubuntu` or `debian`), remote commands must be prefixed with `sudo`. The pre-flight probe must detect whether `id -u` is 0 or if passwordless/prompted sudo is required.
2. **Missing Local Linux Binaries in Development**: If the operator runs `sb node bootstrap` on Windows without `--binaries` and without prior cross-compilation (`cargo build --target x86_64-unknown-linux-musl`), local binary upload cannot proceed unless binaries are present in a distribution folder or downloaded. The pipeline must provide a clear error message instructing the user to supply `--binaries <path>` or run `sb release fetch / pack`.
3. **No Caveats on Other Components**: No source code was modified during this investigation.

---

## 4. Conclusion & Recommended Implementation Plan

The CLI architecture and pipeline orchestration for `sb node bootstrap` are fully mapped and ready for implementation.

### Recommended Implementation Steps:
1. **`tools/sb/Cargo.toml`**: Add `sb-ca = { version = "0.1.0", path = "../sb-ca" }`.
2. **`tools/sb/src/cli.rs`**:
   - Add `pub enum NodeAction` with `Bootstrap` and `#[command(external_subcommand)] External(Vec<String>)`.
   - Update `Commands::Node` to take `#[command(subcommand)] action: Option<NodeAction>`.
3. **`tools/sb/src/commands/mod.rs`**:
   - Add `pub mod bootstrap;`.
4. **`tools/sb/src/commands/bootstrap.rs`**:
   - Implement `BootstrapArgs`, `BootstrapError`, `SshTransport`, and `handle_node_bootstrap`.
   - Implement the 6-phase pipeline with rollback, `sshd -t`, and `visudo -cf`.
   - Implement `dry_run` mode formatting.
   - Include unit tests for target parsing, script generation, and validation.
5. **`tools/sb/src/main.rs`**:
   - Wire `Commands::Node { action }` to dispatch `NodeAction::Bootstrap` to `commands::bootstrap::handle_node_bootstrap(args)` and `NodeAction::External(args)` / `None` to `delegate_to("node", "sb-node", &args)`.

---

## 5. Verification Method

To independently verify the implementation once coded:

1. **Workspace Compilation & Check**:
   ```powershell
   cargo check --workspace
   ```
   *Expected outcome*: 0 errors, 0 warnings.

2. **Unit Tests in `sb`**:
   ```powershell
   cargo test -p sb-cli --lib commands::bootstrap
   ```
   *Expected outcome*: 100% passing tests verifying target parsing, command injection defense, and sshd/sudoers script generation.

3. **Dry-Run CLI Execution**:
   ```powershell
   cargo run -p sb-cli -- node bootstrap root@145.223.83.235 --dry-run
   ```
   *Expected outcome*: Prints full validated bootstrap execution plan, generated `99-sb-ca.conf`, `sb-node.service`, and command sequence without making network requests. Exit code 0.

4. **Delegation Compatibility Check**:
   ```powershell
   cargo run -p sb-cli -- node --help
   ```
   *Expected outcome*: Shows `bootstrap` as a subcommand while allowing `sb node daemon`, `sb node status`, etc., to pass through.
