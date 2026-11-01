## 2026-10-27T20:48:44Z
You are Worker subagent `worker_m1_remediation` implementing the Milestone 1 remediation fixes.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m1_remediation
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Gate Feedback Document: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\GATE_STATUS.md
- Remediation Specs:
  - Security Spec: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_security\handoff.md
  - X.509 Spec: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_x509\handoff.md
  - OpenSSH Spec: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_ssh\handoff.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

File Write Boundaries (Exclusively):
- `product-inventory.json`
- `tools/sb-core/src/catalog.rs`
- `tools/sb-ca/Cargo.toml`
- `tools/sb-ca/src/paths.rs`
- `tools/sb-ca/src/x509/store.rs`
- `tools/sb-ca/src/x509/leaf.rs`
- `tools/sb-ca/src/x509/root.rs`
- `tools/sb-ca/src/ssh/cert.rs`
- `tools/sb-ca/src/ssh/key.rs`
- `tools/sb-ca/src/ssh/mod.rs`
- `tools/sb-ca/src/main.rs`
- `tools/sb-ca/tests/adversarial_x509.rs`
- `tools/sb-ca/tests/adversarial_ssh_probe.rs`
- `tools/sb-ca/tests/e2e_ssh_ca.rs`
- `tools/sb-ca/tests/e2e_x509_ca.rs`

Implementation Tasks (Read the 3 remediation handoff specs for exact code lines):
1. `product-inventory.json`:
   - Change `ca` entry `"maturity": "integrated"`.
   - Set `"release_evidence": []`.
   - In `tools/sb-core/src/catalog.rs`, ensure `Maturity` enum supports serde deserialize for `"integrated"` (or alias), and update test `test_load_product_inventory` if it checks total product count (now 15).
2. Windows ACL & File Hardening (`tools/sb-ca/src/paths.rs`):
   - In `ensure_private_permissions`, call `icacls <path> /inheritance:r /grant:r "%USERNAME%:(F)"` on Windows to eliminate inheritance and grant exclusive access to the current user.
   - On Unix, enforce 0o600.
3. Concurrency & Atomic Index Persistence (`tools/sb-ca/src/x509/store.rs`):
   - Add `pub static INDEX_MUTEX: Mutex<()> = Mutex::new(());`.
   - In `DevCertIndex::save()`, write to a unique temporary file (`.index.json.<pid>.<rand>.tmp`) and atomically rename over `index.json`.
   - In `DevCertIndex::upsert()`, lock `INDEX_MUTEX`, reload disk state, update, and atomically save.
   - Implement custom `fmt::Debug` for `IssuedCertPair` that redacts `key_pem` and `key_der` (`[REDACTED PRIVATE KEY]`), and implement `Drop` with `Zeroize` for memory hygiene.
4. Wildcard Prefixing & Disk Fallback (`tools/sb-ca/src/x509/leaf.rs`):
   - In `domain_to_safe_filename`: replace colons `:` with `_` to prevent Windows OS error 123 with IPv6 addresses (`::1`).
   - In `get_or_issue_on_demand`: if `clean.starts_with('*')`, do NOT prepend `*.` (fixing the double-prefixing `*.*.sbm` bug).
   - Add disk fallback in `get_or_issue_on_demand`: if `leaf_crt_path` and `leaf_key_path` exist on disk but `index.find` missed an entry, inspect validity with `x509-parser`, self-heal the index entry via `upsert`, and return the cached certificate.
5. Root CA Split-Brain Protection (`tools/sb-ca/src/x509/root.rs`):
   - Add `static ROOT_INIT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());` in `init_root_ca`.
6. OpenSSH CA Principal Trimming & Lifetimes (`tools/sb-ca/src/ssh/cert.rs`):
   - Update `validate_principal` to return `Result<&str, CaError>` (trimmed slice).
   - In `issue_user_certificate` and `issue_host_certificate`, pass the trimmed slice to `builder.valid_principal(...)` and `builder.key_id(...)`.
   - Add `pub const MAX_HOST_CERT_TTL_SECONDS: u64 = 90 * 86400;` and enforce it in `issue_host_certificate`.
7. Decouple Filesystem from `parse_public_key` (`tools/sb-ca/src/ssh/key.rs` & `tools/sb-ca/src/main.rs`):
   - Remove file reading from library `parse_public_key`, making it a pure in-memory string parser.
   - Add `resolve_public_key_arg` to `src/main.rs` for CLI path reading.
8. Dependencies & Tests:
   - Move `x509-parser` to `[dependencies]` in `tools/sb-ca/Cargo.toml`.
   - Update assertions in `tests/adversarial_x509.rs` and `tests/adversarial_ssh_probe.rs` per the remediation specs so that all test probes pass cleanly.
   - Add standardized `SECURITY AUDIT:` docstring headers to all modified functions per User Global Rule 1.

Verification Commands:
- `cargo check --workspace` (0 errors, 0 warnings)
- `cargo test -p sb-ca`
- `cargo test -p sb-ca --test adversarial_x509`
- `cargo test -p sb-ca --test adversarial_ssh_probe`
- `cargo test -p sb-cli`
- `cargo test -p sb-core`
