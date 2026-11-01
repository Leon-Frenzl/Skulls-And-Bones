# Handoff Report: Requirement R2 — Automated Remote Server Bootstrapping Survey & Architecture

**Author:** Explorer Subagent (`explorer_survey_bootstrap`)  
**Target:** Orchestrator (`60991008-ad8c-4620-be18-d84298ed02f0`)  
**Scope:** Survey and technical architecture for `sb node bootstrap <user@host>` (Requirement R2)  
**Date:** 2026-10-27  

---

## 1. Observation

### 1.1 Discovery of Existing SSH Implementations and Binaries
1. **`sb-ssh` Binary Discovery**:
   - Running `Get-ChildItem -Path "$env:USERPROFILE\.cargo\bin" -Filter "*ssh*"` revealed:
     `C:\Users\leonf\.cargo\bin\sb-ssh.exe` (Version 0.1.0, 8,347,136 bytes).
   - Executing `sb-ssh.exe --help` confirms built-in commands:
     - `push <TARGET> <LOCAL_PATH> [REMOTE_PATH]` — native SFTP upload.
     - `pull <TARGET> <REMOTE_PATH> [LOCAL_PATH]` — native SFTP download.
     - `exec [OPTIONS] <COMMAND_TO_RUN>` — non-interactive remote execution.
     - `connect [OPTIONS] <TARGET>` — direct SSH connection.
     - `cert` — ephemeral OpenSSH certificate issuance.
     - `server-init` — outputs 1-click OpenSSH CA configuration instructions.
     - `status` — displays OAuth and SSH Certificate Authority status.
   - Binary string inspection confirmed symbols for `russh` and `russh_sftp`, establishing that `sb-ssh.exe` possesses a native pure-Rust SSH transport and SFTP engine.

2. **Resolution Mechanism in `sb-core`**:
   - File: `tools/sb-core/src/binary_resolver.rs` (lines 92–97):
     ```rust
     /// Resolves `sb-ssh` binary, or falls back to system `ssh`.
     pub fn resolve_ssh() -> Option<PathBuf> {
         Self::resolve_binary("sb-ssh")
             .or_else(|| which::which("ssh").ok())
             .or_else(|| which::which("ssh.exe").ok())
     }
     ```
   - File: `tools/sb/src/commands/delegate.rs` (lines 248–255):
     ```rust
     .or_else(|| {
         if binary == "sb-ssh" {
             which::which("ssh").ok()
         } else {
             None
         }
     });
     ```

3. **Current Fragmented Provisioning Commands in `sb`**:
   - `tools/sb/src/commands/provision.rs` (`sb server provision <host>`):
     - Uses `find_openssh("ssh.exe")` / `find_openssh("scp.exe")` (lines 259–280).
     - Uploads files via OpenSSH `scp` to `/tmp/sb-provision-bin/` (lines 296–304).
     - Installs hardened systemd unit `/etc/systemd/system/sb-node.service` (lines 166–183) with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`.
     - Validates public key syntax via `validate_pubkey` (lines 71–91).
   - `tools/sb/src/commands/fleet.rs` (`sb server init <target>`):
     - Resolves target host and user, builds pairing token via `build_pairing_token` (lines 197–204).
     - Generates remote shell payload:
       ```bash
       mkdir -p /etc/ssh /etc/ssh/sshd_config.d;
       echo '{ca_key}' > /etc/ssh/trusted_user_ca_keys;
       printf '... TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys ...' > /etc/ssh/sshd_config.d/99-sbm.conf;
       sshd -t && systemctl reload sshd;
       sb-node init --token '{token}' && systemctl restart sb-node;
       ```
     - Spawns `ssh_cmd = Command::new(ssh_bin)` (line 544).

### 1.2 Architecture of `sb-node`
1. **Source & Structure**:
   - Location: `tools/sb-node/` (Crate `sb-node` v0.1.0).
   - Entry point: `tools/sb-node/src/main.rs` (5,174 lines), with modules `catalog_membership.rs` and `catalog_sync.rs`.
   - Dependencies: `sb-core`, `sb-mesh`, `sb-db`, `sb-code`, `tokio`, `clap`, `ed25519-dalek`, `x25519-dalek`.
2. **Runtime Configuration & Files**:
   - Identity: `~/.sb-mesh/identity.json` or `/etc/sb/identity.json` (lines 2801–2820). Contains `node_id` and `wireguard_pubkey`.
   - Network Store: `~/.sb-mesh/networks.json` loaded via `sb_mesh::network::NetworkStore` (lines 2824–2832).
   - RBAC Store: `~/.sb/mesh_rbac.sbdb` or `/etc/sb/mesh_rbac.sbdb` (lines 3879–3890).
   - PID & Sockets: `~/.sb/run/` or `/run/`; binds multi-tenant Single-Port Dispatcher to UDP `0.0.0.0:58888`.
3. **CLI Commands**:
   - `Daemon`, `Start`, `Stop`, `Telemetry`, `Init { token }`, `Revoke { name, reason }`, `Status`, `Member`, `Setup`, `Route`, `Catalog`.
   - Currently, `sb-node` does not have a `bootstrap` subcommand; `sb-node init --token <token>` is the server-side initialization command.

### 1.3 Documentation Evidence & Server Environment
- `docs/DEV_SERVER_SETUP.md` (lines 50–75 and 125–150):
  - Target server environment: Ubuntu LTS, fresh VPS, initial access as `root` or admin.
  - SSH hardening standard: `/etc/ssh/sshd_config.d/` drop-in files, `sshd -t` validation before reload, `systemctl reload ssh || systemctl reload sshd`.
  - Service hardening: `User=sbadmin`, strict sandboxing (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`).
  - Target server specified in user request: `145.223.83.235` (root / `aKjn?KN@2t&G'2Bs`).

---

## 2. Logic Chain

1. **Premise 1**: The user request explicitly demands Requirement R2:
   `sb node bootstrap <user@host>` orchestrating zero-touch remote onboarding using `sb-ssh` as the transport layer.
2. **Premise 2**: In the existing codebase, remote onboarding is split between `sb server provision` (which uses system `ssh`/`scp` for binary push & systemd setup) and `sb server init` (which uses `ssh` for OpenSSH CA drop-in & pairing token). Neither is accessible via `sb node bootstrap`, and neither leverages `sb-ssh push` for SFTP.
3. **Premise 3**: `sb-ssh.exe` already exists in `~/.cargo/bin` and provides native `sb-ssh push` (SFTP powered by `russh_sftp`) and `sb-ssh <target> <command>` (remote execution). `sb-core::BinaryResolver::resolve_ssh()` is capable of detecting `sb-ssh` and falling back to OpenSSH `ssh`.
4. **Premise 4**: For resilience in diverse environments (whether `sb-ssh` is installed or standard OpenSSH is present), the transport layer should implement an `SshTransport` abstraction:
   - Priority 1: `sb-ssh` native CLI (`push` via SFTP, `exec` / direct command execution).
   - Priority 2: Standard OpenSSH fallback (`scp` / `sftp -b` and `ssh`).
5. **Premise 5**: Modifying `/etc/ssh/sshd_config` or `/etc/ssh/sshd_config.d/` carries severe lockout risks if syntax errors occur or if password authentication is disabled before CA authentication is proven. Therefore, atomic configuration with pre-validation (`sshd -t`) and automated rollback is mandatory.
6. **Premise 6**: In accordance with User Global Rule 1, all bootstrap orchestration methods must incorporate formal dynamic threat modeling with explicit headers (Dynamic Threat Vector, CVE/CWE Mapping, Likelihood & Exploitability rating 1–10, and Applied Mitigations).
7. **Conclusion**: `sb node bootstrap` must be implemented in `tools/sb/src/commands/bootstrap.rs`, wired into `tools/sb/src/cli.rs` under `Node`, and execute an idempotent 6-phase pipeline utilizing `sb-ssh` / SFTP, atomic sshd CA anchoring, systemd unit provisioning, and mesh onboarding.

---

## 3. Caveats

1. **`tools/sb-ssh` Crate Status**:
   - `sb-ssh` is currently an external pre-compiled binary (`v0.1.0`) located in `~/.cargo/bin/sb-ssh.exe`, having been consolidated out of the core workspace as an external satellite.
   - It is not a workspace crate in `Cargo.toml`. The bootstrap implementation must treat `sb-ssh` as an executable transport provider resolved via `sb_core::BinaryResolver::resolve_ssh()`, with seamless fallback to system `ssh`/`scp`/`sftp`.
2. **Cloud-Init & Vendor SSH Overrides**:
   - Cloud providers (e.g., Hetzner, AWS, Hostinger) frequently place files like `/etc/ssh/sshd_config.d/50-cloud-init.conf` that re-enable `PasswordAuthentication yes` or conflict with `TrustedUserCAKeys`.
   - The bootstrap engine must cleanly neutralize or override cloud-init files with a higher-priority lexical sort name (e.g. `99-sb-ca.conf`).
3. **Target Server Architecture**:
   - Pre-compiled binaries deployed via SFTP must match the target architecture (`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`).
   - The bootstrapping workflow must probe the target's architecture (`uname -m`) before transferring binaries.

---

## 4. Conclusion & Technical Architecture

### 4.1 CLI Interface Design (`sb node bootstrap`)

In `tools/sb/src/cli.rs`, update the `Node` command to support explicit subcommands while retaining delegation for all other commands:

```rust
#[derive(Subcommand, Debug, Clone)]
pub enum NodeAction {
    /// Zero-touch remote Linux server onboarding via sb-ssh & SFTP
    Bootstrap {
        /// Target server (user@host or host, default user: root)
        target: String,

        /// SSH port for the initial connection (default: 22)
        #[arg(short, long, default_value = "22")]
        port: u16,

        /// SSH private key file for initial connection
        #[arg(short = 'i', long = "key")]
        key: Option<PathBuf>,

        /// Initial SSH password (if password authentication is needed)
        #[arg(long)]
        password: Option<String>,

        /// Admin user to create on the target (default: sbadmin)
        #[arg(short, long, default_value = "sbadmin")]
        admin: String,

        /// OpenSSH CA public key from sb-ca to anchor in TrustedUserCAKeys
        #[arg(long = "ca-key")]
        ca_key: Option<String>,

        /// Pairing token for mesh registration
        #[arg(long = "mesh-token")]
        mesh_token: Option<String>,

        /// Name of the mesh network to join or bootstrap
        #[arg(long, default_value = "default")]
        mesh: String,

        /// Directory containing prebuilt Linux binaries to deploy via SFTP
        #[arg(long)]
        binaries: Option<PathBuf>,

        /// Force re-bootstrapping even if already configured
        #[arg(short, long)]
        force: bool,

        /// Dry-run mode: display actions and scripts without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Any other command delegated directly to sb-node binary
    #[command(external_subcommand)]
    External(Vec<String>),
}
```

### 4.2 The 6-Phase Bootstrapping Pipeline

```
[ Phase 1: Pre-Flight & Probe ]
   │  • Resolve target user@host and port
   │  • Detect sb-ssh vs OpenSSH via BinaryResolver
   │  • Probe remote: uname -sm, id -u, detect dist (Debian/Ubuntu/RHEL/Alpine)
   ▼
[ Phase 2: Binary Deployment via SFTP ]
   │  • Locate target-compatible sb-node (and companion) binaries
   │  • Create remote staging directory (/tmp/sb-bootstrap-<uuid>/)
   │  • Transfer binaries via `sb-ssh push` (or sftp fallback)
   │  • Verify remote sha256sum and atomic install to /usr/local/bin/sb-node (0755 root:root)
   ▼
[ Phase 3: OpenSSH Swarm-CA Anchoring & Hardening ]
   │  • Resolve CA pubkey from sb-ca (e.g. ~/.sb/ca/ca_key.pub)
   │  • Write /etc/ssh/trusted_user_ca_keys (0644 root:root)
   │  • Deploy drop-in: /etc/ssh/sshd_config.d/99-sb-ca.conf
   │  • CRITICAL: Run `sshd -t`; if fail -> automatic rollback & abort
   │  • Graceful reload: `systemctl reload sshd || service ssh reload`
   ▼
[ Phase 4: Dedicated Admin User & Privilege Boundary ]
   │  • Create unprivileged service/admin user (default: `sbadmin`)
   │  • Install sudoers entry: `/etc/sudoers.d/90-sb-sbadmin` (validated via `visudo -cf`)
   │  • Prepare user directory structure: ~/.sb-mesh, ~/.sb, ~/.sb-node (0700 sbadmin:sbadmin)
   ▼
[ Phase 5: Systemd Unit Installation & Service Supervision ]
   │  • Write hardened `/etc/systemd/system/sb-node.service`
   │  • Apply sandboxing: NoNewPrivileges, ProtectSystem=strict, ProtectHome=read-only, PrivateTmp
   │  • `systemctl daemon-reload && systemctl enable --now sb-node`
   │  • Verify active status: `systemctl is-active sb-node` & UDP 58888 listener
   ▼
[ Phase 6: Mesh Onboarding & Vault Registration ]
   │  • Generate or parse `sbm-pair://` pairing token
   │  • Execute: `sudo -u sbadmin sb-node init --token <token>`
   │  • Register node in local client `~/.sb/servers.toml` via `TargetResolver`
   │  • Report success: `✓ Server <node>.sbm onboarded. Connect: sb ssh <node>.sbm`
```

### 4.3 SSHD Configuration Drop-In Specification

File: `/etc/ssh/sshd_config.d/99-sb-ca.conf`
```text
# ==============================================================================
# SKULLS & BONES SOVEREIGN SWARM CA TRUST CONFIGURATION
# Generated by sb node bootstrap — DO NOT EDIT MANUALLY
# ==============================================================================
TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
RevokedKeys /etc/ssh/revoked_keys
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Hardening (fail-safe for unattended nodes)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
```

**SSHD Reload & Rollback Sequence:**
```bash
if sshd -t; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null
    echo "SSHD_RELOAD_SUCCESS"
else
    rm -f /etc/ssh/sshd_config.d/99-sb-ca.conf
    echo "SSHD_SYNTAX_ERROR_ROLLED_BACK"
    exit 1
fi
```

### 4.4 Dynamic Threat Modeling Matrix (User Global Rule 1 Compliance)

```rust
// =============================================================================
// THREAT MODEL AUDIT 1: Remote Execution / Shell Injection
// Dynamic Threat Vector: Shell command injection through maliciously crafted target,
//                        username, or mesh-token arguments interpolated into remote execution.
// CVE / CWE Mapping: CWE-78: Improper Neutralization of Special Elements used in an OS Command
// Likelihood & Exploitability: High (Score: 8/10). Triggered when untrusted inputs pass to remote shell.
// Applied Mitigation: Strict alphanumeric allow-list regex validation (`[a-zA-Z0-9_.-]+`) on all
//                     usernames, hostnames, and mesh names; binary execution with structured argument
//                     vectors; payload streamed via stdin (`bash -s`) with no unescaped interpolation.
// =============================================================================

// =============================================================================
// THREAT MODEL AUDIT 2: Credential & Private Key Leakage
// Dynamic Threat Vector: Exposure of SSH passwords, private keys, or CA signing keys
//                        via command-line arguments in `ps aux` or unmasked logs.
// CVE / CWE Mapping: CWE-214: Invocation of Process Using Visible Sensitive Information
// Likelihood & Exploitability: High (Score: 7/10). Passwords or keys in process argv are visible system-wide.
// Applied Mitigation: Passwords supplied via environment variables (`SB_SSH_PASSWORD`) or piped stdin;
//                     CA private key NEVER leaves local client; sensitive fields scrubbed in logs;
//                     in-memory secrets protected with `zeroize::Zeroize`.
// =============================================================================

// =============================================================================
// THREAT MODEL AUDIT 3: SFTP Path Traversal & Arbitrary Overwrite
// Dynamic Threat Vector: Path traversal (`../`) or symlink race conditions during SFTP
//                        file upload to `/tmp`, allowing arbitrary file modification.
// CVE / CWE Mapping: CWE-22: Path Traversal / CWE-59: Link Following
// Likelihood & Exploitability: Medium (Score: 6/10). Shared `/tmp` directories subject to symlink hijacking.
// Applied Mitigation: Upload into isolated, freshly created directory with mode 0700 (`/tmp/sb-boot-<uuid>/`);
//                     validate destination filename has no `/` or `..`; verify SHA-256 integrity hash
//                     of uploaded binary prior to invoking `install -m 0755` into `/usr/local/bin/`.
// =============================================================================

// =============================================================================
// THREAT MODEL AUDIT 4: Operator Lockout via Faulty SSHD Configuration
// Dynamic Threat Vector: Corrupted `sshd_config.d` drop-in or premature password disablement
//                        causing sshd daemon rejection or crash, severing remote administrative access.
// CVE / CWE Mapping: CWE-440: Expected Behavior Violation / CWE-755: Improper Handling of Exceptional Conditions
// Likelihood & Exploitability: High (Score: 8/10). A broken sshd configuration permanently isolates remote VPS.
// Applied Mitigation: Automated pre-flight validation via `sshd -t`; immediate file deletion rollback
//                     if `sshd -t` returns non-zero; non-destructive graceful SIGHUP reload (`systemctl reload`);
//                     retention of admin SSH key in `authorized_keys` alongside CA trust.
// =============================================================================

// =============================================================================
// THREAT MODEL AUDIT 5: Privilege Escalation & Service Hijacking
// Dynamic Threat Vector: Compromise of UDP 58888 Single-Port Dispatcher yielding root access
//                        if daemon executes as superuser.
// CVE / CWE Mapping: CWE-250: Execution with Unnecessary Privileges / CWE-269: Improper Privilege Management
// Likelihood & Exploitability: Medium (Score: 5/10). Publicly exposed network ports are primary attack surfaces.
// Applied Mitigation: Daemon runs strictly as unprivileged `User=sbadmin`; comprehensive systemd sandboxing
//                     (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`,
//                     empty `CapabilityBoundingSet=`, native syscall architecture lock).
// =============================================================================
```

### 4.5 Standards Compliance Radar
| Standard | Specification Title | Application in `sb node bootstrap` |
|---|---|---|
| **RFC 4251** | The Secure Shell (SSH) Protocol Architecture | Overall transport layer and security model |
| **RFC 4252** | SSH Authentication Protocol | Publickey & password authentication handling |
| **RFC 4254** | SSH Connection Protocol | Channel multiplexing and remote command `exec` |
| **OpenSSH PROTOCOL.certkeys** | OpenSSH Certificate Format | `ssh-ed25519-cert-v01@openssh.com` validation & principals |
| **IETF draft-ietf-secsh-filexfer** | SSH File Transfer Protocol (SFTP v3) | Binary upload via `sb-ssh push` and SFTP subsystem |
| **POSIX.1-2017** | Standard File Modes & System Interfaces | File permissions (`0755`, `0644`, `0440`), atomic renames |
| **ISO/IEC 27001 / BSI IT-Grundschutz** | Operations Security (OPS.1.1.4, SYS.1.1) | Zero-trust bootstrapping, least privilege, auditability |

---

## 5. Verification Method

To independently verify this survey and subsequent implementation:

1. **Verify `sb-ssh` Discovery & SFTP Capabilities**:
   ```powershell
   & "$env:USERPROFILE\.cargo\bin\sb-ssh.exe" --help
   & "$env:USERPROFILE\.cargo\bin\sb-ssh.exe" push --help
   & "$env:USERPROFILE\.cargo\bin\sb-ssh.exe" server-init
   ```
   *Expected Result*: Output lists `push` (SFTP), `exec`, `connect`, `server-init`, and `status`.

2. **Verify System `BinaryResolver` Resolution**:
   Run unit tests in `tools/sb-core`:
   ```powershell
   cargo test -p sb-core -- binary_resolver
   ```
   *Expected Result*: `test_exe_name_handling` and binary resolution pass 100%.

3. **Verify Existing Provisioning Logic Tests in `tools/sb`**:
   ```powershell
   cargo test -p sb-cli -- provision
   ```
   *Expected Result*: `script_is_hardened_and_ordered` and `pubkey_validation_rejects_injection` pass.

4. **Verify Dry-Run Bootstrapping Execution**:
   Once implemented in `tools/sb`:
   ```powershell
   sb node bootstrap root@145.223.83.235 --dry-run
   ```
   *Expected Result*: Validates arguments, displays the 6-phase plan and remote script payload without making network calls.

5. **Live Target Verification (Milestone 5 / Server `145.223.83.235`)**:
   ```powershell
   sb node bootstrap root@145.223.83.235 --port 22 --password "aKjn?KN@2t&G'2Bs"
   ```
   *Verification Checks on Remote Host*:
   - `test -f /usr/local/bin/sb-node` (Binary installed)
   - `grep -q "TrustedUserCAKeys" /etc/ssh/sshd_config.d/99-sb-ca.conf` (CA anchored)
   - `systemctl is-active sb-node` (Service active)
   - `ss -ulpn | grep 58888` (Single-Port Dispatcher listening)
   - `sb ssh hostinger-node.sbm "sb-node status"` (Zero-touch CA certificate login operational)
