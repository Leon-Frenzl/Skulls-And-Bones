## 2026-10-27T20:05:14Z
You are the Worker subagent implementing Milestone 1 (M1): `sb-ca` Unified PKI Engine Crate.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m1_ca
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Project Scope Document: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md
- Survey Architecture Report: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_ca\handoff.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

File Write Ownership (EXCLUSIVELY):
- `tools/sb-ca/` (entire directory: Cargo.toml, README.md, src/, tests/)
- `Cargo.toml` (add `"tools/sb-ca"` to workspace `members`)
- `product-inventory.json` (add `sb-ca` entry)
- `tools/sb/src/commands/fleet.rs` (fix the 32-byte raw public key base64 defect to OpenSSH RFC 4251 wire format)

Requirements & Technical Architecture for Milestone 1:
1. Read `ORIGINAL_REQUEST.md`, `PROJECT.md`, and `explorer_survey_ca/handoff.md` thoroughly before writing code.
2. Create `tools/sb-ca` as both a reusable Rust library (`sb_ca`) and a CLI tool (`sb-ca`).
   - Use `ssh-key = "0.6.7"` (already cached in local cargo registry) with `ed25519` feature for OpenSSH certificate generation and signing.
   - Use `rcgen = "0.14"` (already in workspace) for X.509 certificate generation.
   - Use `zeroize = "1.8"` for sensitive private key material in memory.
   - Use `thiserror` / `anyhow` for errors.
3. OpenSSH CA Engine (`sb_ca::ssh`):
   - Generate and manage Ed25519 Root CA keypair in `~/.sb/ca/ssh/ca_key` with strict permissions (0600 on Unix, user ACL on Windows) and zeroization.
   - Export public key formatted in RFC 4251 wire format (`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... sovereign-swarm-ca@local`).
   - Issue user certificates (`issue_user_certificate`): `ssh-key 0.6.7` `Builder`, random nonce, serial number, valid_after (backdated 60s for clock drift), valid_before (default TTL 1h, max 8h), principals, `CertType::User`, sign with CA key.
   - Issue host certificates (`issue_host_certificate`): `CertType::Host`, hostname principal.
   - Output standard OpenSSH certificate strings (`ssh-ed25519-cert-v01@openssh.com ...`).
4. Fix `fleet.rs`:
   - In `tools/sb/src/commands/fleet.rs`, fix the defective 32-byte base64 encoding (`simple_base64_encode(verifying_key.as_bytes())`) to use standard OpenSSH wire format `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...` conforming to RFC 4251.
5. X.509 CA Engine (`sb_ca::x509`):
   - Generate and manage self-signed ECDSA P-256 Root CA (`rcgen 0.14`) in `~/.sb/ca/root_ca.crt` and `root_ca.key` (mode 0600).
   - Issue leaf certificates (`issue_leaf_certificate`): SANs for mesh domains (`*.sbm`, `*.mesh`, explicit hostnames, localhost, 127.0.0.1), Extended Key Usages including `ServerAuth` (OID 1.3.6.1.5.5.7.3.1) and `ClientAuth` (OID 1.3.6.1.5.5.7.3.2) for mTLS.
   - Export fullchain PEM, leaf cert PEM, private key PEM, and DER bytes.
   - Provide `get_or_issue_on_demand(domain)` helper that checks cache/disk and dynamically mints if needed.
   - OS trust store integration (`certutil` on Windows, `trust anchor` on Linux, `security` on macOS).
6. CLI Binary (`sb-ca`):
   - Subcommands: `init`, `ssh issue-user`, `ssh issue-host`, `x509 issue`, `install-root`, `status`.
7. Tests:
   - Comprehensive unit and integration tests in `tools/sb-ca/tests/e2e_ssh_ca.rs` and `e2e_x509_ca.rs`.
   - Verify OpenSSH certificate roundtrip and structure.
   - Verify X.509 certificate generation, SAN extensions, and mTLS EKUs.
8. User Global Rules (MANDATORY):
   - Dynamic Security & Threat Modeling: Document threat models in function headers (Threat Vector, CWE Mapping, Likelihood 1-10, Applied Mitigation).
   - Standards Compliance: Cite RFC 4251, PROTOCOL.certkeys, RFC 5280, TLS 1.3 RFC 8446 in code.
9. Verification:
   - Run `cargo check --workspace` to ensure 0 errors and 0 warnings.
   - Run `cargo test -p sb-ca` and `cargo test -p sb-cli` to verify all tests pass 100%.

Output Requirements:
- Update `progress.md` in your working directory with timestamps.
- Write your completion report to `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m1_ca\handoff.md` with:
  - Observation & files modified/created.
  - Logic Chain & implementation details.
  - Test verification commands executed and raw outputs.
- Send a completion message back to parent (60991008-ad8c-4620-be18-d84298ed02f0).
