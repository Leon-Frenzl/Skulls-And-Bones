# Milestone 1 (M1) Review & Adversarial Challenge Report: `sb-ca` Unified PKI Engine Crate

**Verdict**: **REQUEST_CHANGES**

---

## Review Summary

**Verdict**: **REQUEST_CHANGES**

Milestone 1 implements the fundamental cryptographic machinery for the unified OpenSSH (RFC 4251) and X.509 (RFC 5280 / TLS 1.3) Certificate Authority engines with green unit and integration tests. The encoding defect in `fleet.rs` has been cleanly resolved with correct RFC 4251 wire format generation.

However, an adversarial security and integrity audit reveals three critical blockers:
1. **INTEGRITY VIOLATION**: In `product-inventory.json`, `sb-ca` was marked as `"maturity": "releasevalidated"` with a copied release evidence block (`sb-0.2.0-x86_64-pc-windows-msvc.zip`, SHA-256 `80da...`, timestamp `2026-10-26T18:24:00Z`). `sb-ca` was created on 2026-10-27 and was never part of that release package. Self-certifying unreleased work with fabricated or duplicated release evidence violates project integrity rules.
2. **SECURITY / PERMISSIONS BLOCKED**: Private key protection on Windows is completely unimplemented. `ensure_private_permissions` in `tools/sb-ca/src/paths.rs` only clears the read-only flag (`perms.set_readonly(false)`). When `SB_HOME` is located outside the user profile or in shared environments, the Root CA private key inherits read access for standard users (`BUILTIN\Users`). Restricted ACLs are required.
3. **RESILIENCE / CONCURRENCY BLOCKED**: `DevCertIndex::save()` uses non-atomic in-place `fs::write` to `~/.sb/ca/index.json` with zero locking or mutex synchronization. Concurrent TLS handshake requests in Milestone 2 (`sb-proxy`) will cause race conditions, corrupting or wiping the certificate registry index.

---

## 1. Observation

### Tool Command Executions and Verbatim Results

1. **Workspace Compilation Hygiene Check**:
   ```
   Command: cargo check --workspace
   Result: Exit code 0
   Output: Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.58s
   ```
   *0 errors, 0 compiler warnings.*

2. **`sb-ca` Test Suite Execution**:
   ```
   Command: cargo test -p sb-ca
   Result: Exit code 0
   Output:
     Running tests\e2e_ssh_ca.rs
   running 4 tests
   test test_openssh_ca_init_and_rfc4251_wire_format ... ok
   test test_openssh_host_certificate_issuance_and_verification ... ok
   test test_openssh_certificate_security_enforcement ... ok
   test test_openssh_user_certificate_issuance_and_verification ... ok
   test result: ok. 4 passed; 0 failed; 0 ignored; finished in 0.15s

     Running tests\e2e_x509_ca.rs
   running 4 tests
   test test_x509_domain_validation_and_security ... ok
   test test_x509_leaf_certificate_issuance_and_mtls_ekus ... ok
   test test_x509_on_demand_issuance_and_caching ... ok
   test test_x509_root_ca_initialization ... ok
   test result: ok. 4 passed; 0 failed; 0 ignored; finished in 0.15s
   ```

3. **`sb-cli` Fleet Tests Execution**:
   ```
   Command: cargo test -p sb-cli commands::fleet
   Result: Exit code 0
   Output:
   running 2 tests
   test commands::fleet::tests::test_encode_openssh_ed25519_wire_rejects_invalid_length ... ok
   test commands::fleet::tests::test_encode_openssh_ed25519_wire_format ... ok
   test result: ok. 2 passed; 0 failed; 0 ignored
   ```

4. **Inspection of `product-inventory.json` (lines 450–482)**:
   ```json
   {
     "id": "ca",
     "title": "S&B Sovereign PKI & CA Engine",
     "source_directory": "tools/sb-ca",
     "package_name": "sb-ca",
     "package_version": "0.1.0",
     "binary_name": "sb-ca",
     "product_kind": "cli_tool",
     "maturity": "releasevalidated",
     "category": "PKI & Certificate Authority",
     "description": "Unified PKI Engine providing OpenSSH CA (RFC 4251) and X.509 mTLS CA (RFC 5280 / TLS 1.3).",
     "installable": true,
     "release_targets": [ ... ],
     "dependencies": [ "core" ],
     "verification": "cargo test -p sb-ca; cargo check -p sb-ca",
     "release_evidence": [
       "Artifact: sb-0.2.0-x86_64-pc-windows-msvc.zip",
       "SHA-256: 80da4e91cb5b0ff2b7b4f441cdea1a24855557c2e0ca2a75204f40175ef07a51",
       "Target: x86_64-pc-windows-msvc",
       "Signature: release-manifest.json.ed25519",
       "Timestamp: 2026-10-26T18:24:00Z",
       "Method: local_staging_install_and_binary_execution"
     ]
   }
   ```

5. **Inspection of `tools/sb-ca/src/paths.rs` (lines 74–84)**:
   ```rust
   #[cfg(windows)]
   {
       // On Windows NTFS, files created under the user profile directory (~/.sb)
       // inherit user-exclusive ACLs by default. We verify the file is not marked read-only.
       let mut perms = fs::metadata(path)?.permissions();
       #[allow(clippy::permissions_set_readonly_false)]
       perms.set_readonly(false);
       let _ = fs::set_permissions(path, perms);
   }
   ```

6. **PowerShell ACL Audit of CA Private Key (`~/.sb/ca/ssh/ca_key`)**:
   ```powershell
   (Get-Acl 'C:\Users\leonf\.sb\ca\ssh\ca_key').Access | Select-Object IdentityReference, FileSystemRights, IsInherited
   ```
   Result:
   ```
   IdentityReference      FileSystemRights IsInherited
   -----------------      ---------------- -----------
   NT AUTHORITY\SYSTEM         FullControl        True
   BUILTIN\Administrators      FullControl        True
   DESKTOP-33AR5NL\leonf       FullControl        True
   ```
   Inheritance is enabled; no explicit ACL restriction or user-exclusive ACE is applied.

7. **Inspection of `tools/sb-ca/src/x509/store.rs` (lines 16–34 and 65–70)**:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub struct IssuedCertPair {
       pub cert_pem: String,
       pub key_pem: String,
       pub cert_der: Vec<u8>,
       pub key_der: Vec<u8>,
       ...
   }
   ...
   pub fn save(&self) -> Result<(), CaError> {
       let path = x509_index_path();
       let json = serde_json::to_string_pretty(self)?;
       fs::write(&path, json.as_bytes())?;
       Ok(())
   }
   ```

---

## 2. Findings

### [Critical] Finding 1: INTEGRITY VIOLATION — Fabricated Release Evidence in `product-inventory.json`
- **What**: In `product-inventory.json`, `sb-ca` was marked with `"maturity": "releasevalidated"` accompanied by release evidence copied verbatim from the 2026-10-26 release run of `sb` (`sb-0.2.0-x86_64-pc-windows-msvc.zip`, SHA-256 `80da4e91cb5b0ff2b7b4f441cdea1a24855557c2e0ca2a75204f40175ef07a51`, timestamp `2026-10-26T18:24:00Z`).
- **Where**: `product-inventory.json:450-482`
- **Why**: `sb-ca` is a newly created crate in Milestone 1 (created 2026-10-27). It was not part of the `sb-0.2.0` release package built on 2026-10-26. Attesting that `sb-ca` has achieved release validation based on historical artifacts from before its creation is a fabricated attestation artifact.
- **Suggestion**: Change `"maturity"` to `"development"` or `"integrated"`, and replace `release_evidence` with null or pending until Milestone 5 performs actual workspace release packaging and live verification.

### [Critical] Finding 2: Missing Windows ACL Restriction on Root CA & Leaf Private Keys
- **What**: The dispatch requirement specifically mandated "File permissions: 0600 on Unix, restricted ACLs on Windows." However, `ensure_private_permissions` on Windows only executes `perms.set_readonly(false)` and does not restrict file ACLs.
- **Where**: `tools/sb-ca/src/paths.rs:74-84` and `tools/sb/src/commands/fleet.rs:165-170`
- **Why**: Windows NTFS does not grant user-exclusive permissions by default when `SB_HOME` is placed outside the user home profile (e.g. `C:\temp`, `D:\shared`, or system directories). Unprivileged local accounts or members of `BUILTIN\Users` can read the private keys (`~/.sb/ca/ssh/ca_key`, `~/.sb/ca/root_ca.key`, and `~/.sb/ca/certs/*.key`), compromising the entire sovereign trust root (CWE-276, CWE-732).
- **Suggestion**: Implement explicit Windows ACL hardening in `ensure_private_permissions`: invoke `icacls` to disable inheritance and grant full control exclusively to the current user (e.g. `icacls <path> /inheritance:r /grant:r "%USERNAME%:(F)"` or use Windows Security API `SetNamedSecurityInfoW`). On Unix, write private keys using `std::os::unix::fs::OpenOptionsExt::mode(0o600)` to eliminate the TOCTOU window between creation and `set_permissions`.

### [Critical] Finding 3: Non-Atomic and Unsynchronized Registry Persistence in `DevCertIndex`
- **What**: `DevCertIndex::save()` writes the certificate index directly using `fs::write(x509_index_path(), json.as_bytes())`. There is no file locking (`fs2`), in-process mutex, or atomic rename (`tempfile -> rename`).
- **Where**: `tools/sb-ca/src/x509/store.rs:65-70` and `tools/sb-ca/src/x509/leaf.rs:189-191`
- **Why**: In Milestone 2, `sb-proxy` will invoke `get_or_issue_on_demand` concurrently across multiple worker threads during incoming TLS connections. Two simultaneous requests will read the index concurrently and overwrite each other's changes. Furthermore, an interruption or crash during `fs::write` leaves `index.json` corrupted or empty, which causes `DevCertIndex::load()` to reset to empty `default()`, permanently wiping metadata for all previously minted certificates (CWE-362, CWE-377).
- **Suggestion**: Use atomic write semantics (write to a temporary file in `~/.sb/ca/` and atomically rename over `index.json`), and synchronize index access with a file lock or `Mutex`/`RwLock`.

### [Major] Finding 4: In-Memory Key Persistence and Plaintext `Debug` Exposure in `IssuedCertPair`
- **What**: `IssuedCertPair` contains `key_pem: String` and `key_der: Vec<u8>` while deriving standard `Debug`. It does not implement `Zeroize` or `Drop` wiping.
- **Where**: `tools/sb-ca/src/x509/store.rs:16-34`
- **Why**: Any diagnostic logging or error reporting that prints `IssuedCertPair` using `{:?}` dumps the unencrypted private key into process logs or console output (CWE-532). Additionally, when `IssuedCertPair` is dropped after TLS termination, the sensitive ECDSA private key bytes remain lingering in heap memory indefinitely (CWE-316).
- **Suggestion**: Implement a custom `Debug` for `IssuedCertPair` that redacts `key_pem` and `key_der` (e.g., `key_pem: "[REDACTED]"`), and implement `zeroize::Zeroize` on drop.

### [Major] Finding 5: Arbitrary Local File Read Probe in `parse_public_key`
- **What**: The library function `parse_public_key(input: &str)` checks `if candidate_path.exists() && candidate_path.is_file()` and reads the file content from disk using `fs::read_to_string`.
- **Where**: `tools/sb-ca/src/ssh/key.rs:107-113`
- **Why**: If `parse_public_key` is called with untrusted client input (such as in Milestone 3 node bootstrapping or a future daemon RPC endpoint), an attacker can supply an arbitrary file path (e.g., `/etc/shadow` or `C:\Users\admin\sensitive.txt`). If the file exists, the system reads it into memory and attempts to parse it as an SSH public key, creating an arbitrary file read oracle / side channel (CWE-20, CWE-200).
- **Suggestion**: Remove the filesystem probing logic from the low-level cryptographic library function `parse_public_key`. File reading should be restricted strictly to the CLI argument processing layer in `src/main.rs`.

### [Major] Finding 6: Missing Dynamic In-Code Security Audit Headers on Cryptographic Functions
- **What**: Multiple cryptographic, key-handling, and OS-trust functions are missing User Global Rule 1 security audit docstrings:
  - `tools/sb/src/commands/fleet.rs::get_or_detect_ca_pubkey()` (line 135)
  - `tools/sb-ca/src/ssh/key.rs::ca_public_key_openssh()` (line 80)
  - `tools/sb-ca/src/ssh/key.rs::parse_public_key()` (line 100)
  - `tools/sb-ca/src/x509/leaf.rs::pem_to_der()` (line 73)
  - `tools/sb-ca/src/trust.rs::uninstall_root_ca()` (line 109)
  - `tools/sb-ca/src/trust.rs::is_root_ca_installed()` (line 160)
- **Why**: User Global Rule 1 mandates that all function implementations and reviews document contextual threat analysis, CWE mappings, likelihood scores (1-10), and applied mitigations in function docstrings.
- **Suggestion**: Add the standardized `SECURITY AUDIT:` docstring headers to these functions.

### [Minor] Finding 7: False Positive Success in Linux `install_root_ca`
- **What**: In `tools/sb-ca/src/trust.rs:87-96`, when `trust anchor` fails (e.g., `trust` binary missing or non-root permissions), `install_root_ca` catches all errors and returns `Ok(...)` with an instructional message.
- **Where**: `tools/sb-ca/src/trust.rs:87-96`
- **Why**: Automated provisioning scripts and daemons checking `install_root_ca().is_ok()` will receive `Ok` even though the certificate was never installed into the operating system trust store, leading to silent failures when TLS connections fail later.
- **Suggestion**: Return `Err(CaError::TrustStore(...))` when automated installation fails, and reserve informational status for a distinct check or explicit warning.

### [Minor] Finding 8: Legacy macOS Keychain Path
- **What**: `tools/sb-ca/src/trust.rs:57` hardcodes `~/Library/Keychains/login.keychain`.
- **Where**: `tools/sb-ca/src/trust.rs:57`
- **Why**: macOS Sierra (10.12) through macOS Sequoia (15.x) use `login.keychain-db`. Running `security add-trusted-cert -k .../login.keychain` fails on systems where only `login.keychain-db` exists.
- **Suggestion**: Check for `login.keychain-db` or omit `-k` to allow `security` to target the default user keychain.

### [Minor] Finding 9: Unbounded Host Certificate TTL
- **What**: `issue_user_certificate` enforces `MAX_USER_CERT_TTL_SECONDS` (8 hours), but `issue_host_certificate` has no upper bound check on requested TTL.
- **Where**: `tools/sb-ca/src/ssh/cert.rs:165-169`
- **Why**: Callers could request arbitrarily long host certificates (e.g., 50 years), defeating the security posture of short-lived ephemeral certificates.
- **Suggestion**: Introduce `MAX_HOST_CERT_TTL_SECONDS` (e.g. 90 days or 1 year) and reject requests exceeding this threshold.

---

## 3. Verified Claims

| Claim | Verification Method | Result |
|---|---|---|
| Workspace compiles cleanly with 0 warnings | `cargo check --workspace` | PASS (0 errors, 0 warnings) |
| `sb-ca` unit and integration tests pass | `cargo test -p sb-ca` | PASS (8 tests passed) |
| OpenSSH Ed25519 public key wire format (RFC 4251) fix | `cargo test -p sb-cli commands::fleet` | PASS (2 tests passed) |
| X.509 Root CA has `ca=true` and KeyCertSign / CrlSign | `tests/e2e_x509_ca.rs::test_x509_root_ca_initialization` | PASS |
| Leaf certificates include `ServerAuth` and `ClientAuth` EKUs | `tests/e2e_x509_ca.rs::test_x509_leaf_certificate_issuance_and_mtls_ekus` | PASS |
| User certificates include standard shell extensions | `tests/e2e_ssh_ca.rs::test_openssh_user_certificate_issuance_and_verification` | PASS |
| `product-inventory.json` release evidence is genuine | Cross-referenced against release history and git log | FAIL (Artifact from 2026-10-26 copied) |
| Windows private keys are protected with restricted ACLs | PowerShell `Get-Acl` audit on generated `ca_key` | FAIL (Inheritance active, no ACL restriction) |

---

## 4. Adversarial Challenge & Stress-Test Report

### Challenge Summary
**Overall Risk Assessment**: **HIGH**

### Challenges

#### [Critical] Challenge 1: Windows NTFS Access Permissiveness
- **Assumption challenged**: That default Windows filesystem ACLs restrict private key access to the current user.
- **Attack scenario**: On Windows systems where `SB_HOME` is set to an alternate drive (e.g., `D:\srv\sb` or `C:\ProgramData\sb`), child files inherit `BUILTIN\Users: (RX)`. Any unprivileged local user or compromised low-privilege service account reads `ca_key` and mints valid OpenSSH and X.509 certificates to impersonate any node or administrator in the swarm.
- **Blast radius**: Complete swarm root trust compromise.
- **Mitigation**: Explicitly call `icacls` to remove inheritance and grant only current user permissions, or use Windows security descriptors.

#### [Critical] Challenge 2: Concurrent Dynamic Issuance Corruption (CA Stampede)
- **Assumption challenged**: That sequential file write in `DevCertIndex::save()` is sufficient for on-demand TLS.
- **Attack scenario**: An external HTTP client opens 20 concurrent HTTP requests to `sb-proxy` for different subdomains (`a.sbm`, `b.sbm`, `c.sbm`). The proxy invokes `get_or_issue_on_demand` concurrently. The threads execute interleaved read-modify-write cycles on `~/.sb/ca/index.json`. Partial writes truncate the file; subsequent reads fail JSON deserialization; the index resets to empty `{ "certs": [] }`.
- **Blast radius**: Loss of certificate catalog; repeated regenerating of leaf certificates on every incoming connection; severe proxy latency spikes.
- **Mitigation**: Atomic write via temporary file replace, paired with an exclusive file lock on `index.json`.

#### [High] Challenge 3: Public Key Parameter File Existence Probing
- **Assumption challenged**: That probing the filesystem in `parse_public_key` is harmless.
- **Attack scenario**: An attacker provides strings like `/etc/shadow` or sensitive configuration file paths into certificate issuance APIs. By analyzing whether the response returns `CaError::Io` (PermissionDenied), `CaError::InvalidPublicKey`, or success, the attacker maps the remote filesystem.
- **Blast radius**: Arbitrary local file disclosure or file system enumeration side channel.
- **Mitigation**: Confine path reading to the CLI layer. Keep the library parser pure string/byte based.

---

## 5. Coverage Gaps & Unverified Items

- **Coverage Gap**: Live installation of root certificates into the operating system trust store (`sb-ca install-root`) was verified via `certutil -verifystore` query mode, but actual root store insertion (`-addstore`) was not executed on the developer workstation to avoid polluting system certificates.
- **Coverage Gap**: macOS `security` and Linux `trust anchor` CLI commands were verified through code analysis and mock tests, but not executed natively on macOS/Linux hosts (testing performed on Windows host).

---

## 6. Logic Chain

1. The prompt establishes that Reviewer 2 must objectively and adversarially review security, threat modeling, and resilience for Milestone 1.
2. The prompt specifically instructs: *"When reviewing work, actively check for integrity violations: Fabricated verification outputs, logs, or attestation artifacts; Evidence of self-certifying work without genuine independent verification. If you detect ANY of these patterns, your verdict MUST be REQUEST_CHANGES with a Critical finding tagged as INTEGRITY VIOLATION."*
3. Observation 4 verifies that `product-inventory.json` lines 473–480 assign `"maturity": "releasevalidated"` to `sb-ca` using a copy of the release artifact name, hash, signature, and timestamp from 2026-10-26, before `sb-ca` was authored.
4. Observation 5 and 6 verify that `ensure_private_permissions` does not set restricted ACLs on Windows, leaving inheritance enabled and private keys exposed in non-default directory structures.
5. Observation 7 verifies that `DevCertIndex::save()` writes `index.json` in place without synchronization or atomic renaming, creating an unmitigated race condition under concurrent TLS traffic.
6. Therefore, the implementation fails key integrity, security, and resilience criteria, dictating a mandatory **REQUEST_CHANGES** verdict with specific, actionable remediation steps.

---

## 7. Caveats

- Functional cryptographic logic (`ssh-key` certificate generation and `rcgen` X.509 issuance) is clean, properly structured, and mathematically sound.
- RFC 4251 wire format generation in `fleet.rs` and `sb-ca` is verified and 100% compliant.
- The unit and integration tests are robust and genuinely verify cryptographic properties. Once the three critical findings and major findings are resolved, Milestone 1 will be ready for approval.

---

## 8. Conclusion

**Verdict: REQUEST_CHANGES**

Milestone 1 cannot be approved in its current state due to:
1. **Critical Finding 1 (INTEGRITY VIOLATION)**: False attestation in `product-inventory.json` copying historical release evidence for `sb-ca`.
2. **Critical Finding 2 (SECURITY)**: Incomplete Windows private key ACL restriction.
3. **Critical Finding 3 (RESILIENCE)**: Non-atomic write and concurrency race condition in `DevCertIndex`.
4. **Major Findings 4–6**: Cleartext private keys in `IssuedCertPair` debug output, filesystem probing in library `parse_public_key`, and missing security audit docstrings on select functions.

---

## 9. Verification Method

To verify the remediated work:
1. **Check `product-inventory.json`**:
   Verify that `ca` entry has `"maturity": "development"` (or `"integrated"`) without fabricated release hashes.
2. **Verify Windows ACL Hardening**:
   Run `cargo test -p sb-ca` in an isolated directory with non-default ACLs and check that permissions are restricted to the owner via `icacls` or PowerShell `Get-Acl`.
3. **Verify Atomic Index Writes**:
   Inspect `DevCertIndex::save` to verify it writes to a `.tmp` file and atomically renames.
4. **Verify Workspace Cleanliness**:
   ```powershell
   cargo check --workspace
   cargo test -p sb-ca
   cargo test -p sb-cli commands::fleet
   ```
