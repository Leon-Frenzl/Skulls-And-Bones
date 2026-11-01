# Project: Skulls & Bones — PKI, Node Bootstrap, Cockpit & Remote Live Verification

## Architecture
- **Workspace**: Rust 2021 edition workspace with member crates (`sb`, `sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`, `sb-ca`, etc.).
- **New PKI Crate (`tools/sb-ca`)**:
  - Fully implemented independent library (`sb_ca`) and standalone binary CLI (`sb-ca`).
  - OpenSSH CA Engine (`sb_ca::ssh`): RFC 4251, `PROTOCOL.certkeys`, Ed25519 user & host certificates using `ssh-key 0.6.7`.
  - X.509 CA Engine (`sb_ca::x509`): RFC 5280 / TLS 1.3, ECDSA P-256 Root CA and leaf certs for mesh domains (`*.sbm`, `*.mesh`), mTLS with `ServerAuth` and `ClientAuth` EKUs using `rcgen 0.14`.
  - Concurrency & Persistence: `INDEX_MUTEX`, `ROOT_INIT_MUTEX`, atomic temporary file rename (`fs::rename`), self-healing disk inspection fallback via `x509-parser`.
  - Security Hardening: Windows `icacls` user-exclusive Full Control (`IsInherited: False`), POSIX 0o600 on Unix, memory zeroization and redacted Debug for `IssuedCertPair`.
- **On-Demand TLS in `sb-proxy`**:
  - Integrated `sb-ca` into `DynamicSniResolver` in `tools/sb-proxy/src/proxy.rs`.
  - High-performance in-memory cache `Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>`.
  - Eligibility gate for mesh domains (`.sbm`, `.mesh`, `.local`, `localhost`) and active routes.
  - Rate-limited dynamic generation and disk persistence in `~/.sb/ca/certs/`.
- **Remote Server Bootstrapping (`sb node bootstrap`)**:
  - Subcommand in `sb` CLI: `sb node bootstrap <user@host>` with options (`--port`, `--key`, `--password`, `--admin`, `--ca-key`, `--mesh-token`, `--mesh`, `--binaries`, `--force`, `--dry-run`).
  - Transport Layer: `SshTransport` utilizing `sb-ssh` (`sb-ssh.exe push` for SFTP and command execution) with fallback to OpenSSH `ssh`/`scp`. Passes `-p <port>` before `push` and exports `SB_SSH_PASSWORD`. Zeroizes credentials on Drop.
  - 6-Phase Pipeline: Pre-flight probe -> SFTP binary upload -> OpenSSH Swarm-CA anchoring (`/etc/ssh/sshd_config.d/99-sb-ca.conf` with `sshd -t` validation & symlink-safe rollback) -> Dedicated unprivileged admin `sbadmin` with sudoers (`visudo -cf`) -> Systemd service `sb-node.service` with CIS Level 2 sandboxing (`ReadWritePaths=-...`) -> Mesh onboarding (`sb-node init --token <token>` followed by daemon restart).
- **Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`)**:
  - Unified interactive TUI in `tools/sb/src/cockpit.rs` using `ratatui 0.29` and `crossterm 0.28`.
  - Subcommand `Cockpit` with alias `hud` in `tools/sb/src/cli.rs`.
  - 3-Panel HUD layout: Active Daemons status & metrics (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`), WireGuard Mesh Peers table (`PeerSummaryPayload`), Recent Audit & Access events (`sessions.jsonl`, `errors.jsonl`).
  - Asynchronous background polling to eliminate UI event loop freeze (CWE-400), global panic hook (`std::panic::set_hook`) to restore terminal state (CWE-754), and ANSI escape sequence sanitization (CWE-150 / ECMA-48).
- **Remote Target Live Verification on `145.223.83.235`**:
  - Live deployment of updated toolchain and `sb-ca` binary to server `145.223.83.235` (root / `aKjn?KN@2t&G'2Bs`).
  - Remote execution of `/root/verify_all.sh` (augmented for `sb-ca`) and `/root/.cargo/bin/sb doctor` -> Exit Code 0.
  - Full workspace compliance: `cargo check --workspace` (0 errors, 0 warnings) and `cargo test --workspace` (100% pass) locally and remotely.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | `sb-ca` crate scaffold & manifest | Create `tools/sb-ca` crate, add to workspace `Cargo.toml` and `product-inventory.json` | M1 | R1 |
| 2 | OpenSSH Ed25519 CA Engine | Issue user and host certificates conforming to RFC 4251 and `PROTOCOL.certkeys` using `ssh-key 0.6.7` | M1 | R1 |
| 3 | Fix `fleet.rs` OpenSSH Key Defect | Replace invalid 32-byte raw base64 key with RFC 4251 wire format `ssh-ed25519 AAAAC3...` | M1 | R1 / Survey |
| 4 | X.509 mTLS & Mesh CA Engine | Issue ECDSA P-256 Root CA and leaf certificates with SANs for `*.sbm`, `*.mesh` with ServerAuth/ClientAuth EKUs using `rcgen 0.14` | M1 | R1 |
| 5 | `sb-ca` CLI commands | `sb-ca init`, `sb-ca ssh issue-user`, `sb-ca ssh issue-host`, `sb-ca x509 issue`, `sb-ca install-root` | M1 | R1 |
| 6 | `sb-proxy` On-Demand TLS Engine | Enhance `DynamicSniResolver` with in-memory `RwLock<HashMap<String, Arc<CertifiedKey>>>` cache | M2 | R1 |
| 7 | `sb-proxy` Dynamic Issuance Gate | Auto-generate valid TLS certs on incoming SNI for `.sbm`, `.mesh`, and registered routes without manual setup | M2 | R1 |
| 8 | `sb node bootstrap` CLI Subcommand | Implement `sb node bootstrap <user@host>` in `tools/sb/src/cli.rs` and `commands/bootstrap.rs` | M3 | R2 |
| 9 | SFTP Transport & Deployment | Deploy `sb-node` binary and config via `sb-ssh push` into staging directory with SHA256 integrity verification | M3 | R2 |
| 10 | SSHD CA Anchoring & Rollback | Deploy `/etc/ssh/sshd_config.d/99-sb-ca.conf` with `TrustedUserCAKeys`, pre-validate via `sshd -t`, auto-rollback on failure | M3 | R2 |
| 11 | Systemd & Mesh Onboarding | Configure sandboxed `sb-node.service`, verify UDP 58888 listener, onboard with pairing token | M3 | R2 |
| 12 | `sb cockpit` & `sb hud` Command | Add `#[command(alias = "hud")]` to `Cockpit` in `tools/sb/src/cli.rs` | M4 | R3 |
| 13 | Unified HUD Layout | Implement 3-panel TUI: Daemons Status (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`), Mesh Peers Table, Audit Event Log | M4 | R3 |
| 14 | Cockpit Non-Blocking Polling & Safety | Background async worker for metrics, global panic hook for terminal restoration, ANSI escape sanitization | M4 | R3 |
| 15 | Local Quality Gate Compliance | `cargo check --workspace` 0 errors/0 warnings, `cargo test --workspace` 100% pass | M5 | Acceptance |
| 16 | Remote Target Live Deployment | Deploy `sb-ca` and updated binaries to `145.223.83.235` | M5 | R4 |
| 17 | Remote Live Script Verification | Execute `/root/verify_all.sh` and `/root/.cargo/bin/sb doctor` on `145.223.83.235` with Exit Code 0 | M5 | R4 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | `sb-ca` PKI Engine Crate | Crate `tools/sb-ca` (lib + CLI): OpenSSH Ed25519 (RFC 4251) & X.509 (RFC 5280 / TLS 1.3), `fleet.rs` fix | None | DONE |
| M2 | `sb-proxy` On-Demand TLS Integration | In-memory cached `DynamicSniResolver`, auto-issuance gate for `*.sbm`, `*.mesh` | M1 | DONE |
| M3 | `sb node bootstrap` Remote Provisioning | CLI subcommand, `sb-ssh` / SFTP transport, sshd CA anchoring & rollback, systemd supervision | M1 | DONE |
| M4 | `sb cockpit` / `sb hud` Operator HUD | Interactive Ratatui TUI dashboard, 3-panel HUD, async polling, terminal panic safety | None | DONE |
| M5 | Remote Target Live Verification & Final Gate | Workspace check/test 100%, deploy & live verify on `145.223.83.235` (`verify_all.sh`, `sb doctor`) | M1, M2, M3, M4 | IN_PROGRESS |

## Interface Contracts

### `sb_ca` ↔ `sb-proxy`
- `sb_ca::x509::get_or_issue_on_demand(domain: &str) -> Result<IssuedCertPair, CaError>`
- `IssuedCertPair { cert_pem: String, key_pem: String, cert_der: Vec<u8>, key_der: Vec<u8> }`
- Resolves within <2ms using ECDSA P-256 (`rcgen 0.14`), thread-safe, atomic disk persistence.

### `sb_ca` ↔ `sb node bootstrap`
- `sb_ca::ssh::ca_public_key_openssh() -> Result<String, CaError>`
- Returns wire-format `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... sovereign-swarm-ca@local` for `/etc/ssh/trusted_user_ca_keys`.
- `sb_ca::ssh::issue_user_certificate(pubkey: &str, key_id: &str, principals: &[String], ttl_seconds: u64, serial: Option<u64>) -> Result<String, CaError>`
- Returns standard OpenSSH certificate `ssh-ed25519-cert-v01@openssh.com ...`.

### `sb` CLI ↔ Operator Cockpit
- `sb cockpit` or `sb hud` launches `tools/sb/src/cockpit.rs::run_cockpit()`.
- Supports optional `--snapshot` non-interactive flag for headless scripts.
- Telemetry query interfaces:
  - `sb-node`: Loopback HTTP RPC port 58905 or `sb-node telemetry --json`.
  - `sb-mesh`: TCP loopback port 58890 (`GetStatus`, `ListPeers`).
  - `sb-proxy`: HTTP loopback port 58900 (`/status`).
  - `sb-dns`: Port 53 / 58853 status probe.
  - Audit logs: `~/.sb/audit/sessions.jsonl`, `~/.sb/logs/errors.jsonl`.

## Code Layout
- `tools/sb-ca/`: Crate root for PKI engine (lib + bin)
- `tools/sb-proxy/`: Reverse proxy, modified `src/proxy.rs` (DynamicSniResolver)
- `tools/sb/src/commands/bootstrap.rs`: Node bootstrapping logic
- `tools/sb/src/cockpit.rs`: Operator cockpit & HUD TUI
- `tools/sb/src/cli.rs`: Command line parser updates
- `product-inventory.json`: Workspace tool inventory update
