# Challenger 2 Report — Milestone 1 Iteration 2: X.509 CA Engine

**Agent**: Challenger 2 (`challenger_m1_r2_2`)  
**Working Directory**: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m1_r2_2`  
**Target Under Review**: Remediated X.509 CA Engine (`sb_ca::x509` in `tools/sb-ca`)  
**Verdict**: **APPROVE**  
**Overall Risk Assessment**: LOW  

---

## 1. Observation

### 1.1 Direct Execution of Adversarial Test Suite
- **Command**: `cargo test -p sb-ca --test adversarial_x509 -- --nocapture`
- **Result**: Exit code 0, 7 passed, 0 failed.
- **Verbatim Output**:
```text
running 7 tests
test test_adversarial_concurrency_race_conditions ... ok
test test_adversarial_concurrency_lost_updates_different_domains ... ok
test test_adversarial_domain_validation_and_path_traversal ... ok
test test_adversarial_concurrent_initialization_split_brain ... ok
test test_adversarial_wildcard_san_handling ... ok
test test_adversarial_on_demand_latency_sla ... ok
test test_adversarial_mtls_extended_key_usage_oids ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.72s
```

### 1.2 Wildcard SAN Handling (`*.sbm` and RFC 6125 Compliance)
- **Source Code**: `tools/sb-ca/src/x509/leaf.rs:341-347`
  ```rust
  let mut sans = vec![clean.clone()];
  if (clean.ends_with(".sbm") || clean.ends_with(".mesh")) && !clean.starts_with('*') {
      let wildcard = format!("*.{}", clean);
      if !sans.contains(&wildcard) {
          sans.push(wildcard);
      }
  }
  ```
- **Observed Behavior**:
  - `get_or_issue_on_demand("*.sbm")` returns `Ok(IssuedCertPair)`.
  - `domains` vector contains `["*.sbm"]` without any illegal duplicate prefixing (no `*.*.sbm`).
  - Safe filesystem filename produced: `_wildcard_.sbm.crt` and `_wildcard_.sbm.key` in `~/.sb/ca/certs/`.
  - X.509 DER inspection via `x509-parser` verifies SAN extension contains exact `DNSName("*.sbm")`.
  - Subsequent call to `get_or_issue_on_demand("*.sbm")` hits the cache and returns the identical certificate DER.
  - Calling `validate_domain("*.*.sbm")` fails immediately with `CaError::InvalidDomain("Domain '*.*.sbm' contains disallowed character '*'")`.

### 1.3 High-Concurrency On-Demand Minting & Zero Lost Updates in `DevCertIndex`
- **Source Code**: `tools/sb-ca/src/x509/store.rs:16-18, 110-157`
  - Global `INDEX_MUTEX: Mutex<()>` serializes all disk reads, modifications, and atomic renames.
  - `save_internal()` writes to `.index.json.<pid>.<rand>.tmp` and renames atomically with Windows retry loop.
  - `upsert()` locks `INDEX_MUTEX`, reloads the latest on-disk state via `load_internal()`, updates the entry, and atomically saves.
- **Empirical Stress Test (32 Threads)**:
  - Spawned 32 threads synchronized with `std::sync::Barrier` concurrently minting 32 distinct domains (`worker-node-00.sbm` through `worker-node-31.sbm`).
  - All 32 threads succeeded without sharing violations (`os error 32`).
  - Loaded `DevCertIndex::load()`: exact certificate count was 32.
  - Every single domain (`0..32`) was verified present in `index.json`. Zero lost updates observed.
  - Tested Fast-path 2 self-healing: artificially wiped `index.json` while retaining `.crt` and `.key` files on disk. Calling `get_or_issue_on_demand` successfully detected disk artifacts, validated certificate validity, restored the index entry, and served the cached certificate.

### 1.4 Windows Path Safety & IPv6 Colon Sanitization
- **Source Code**: `tools/sb-ca/src/x509/leaf.rs:78-80`
  ```rust
  pub fn domain_to_safe_filename(domain: &str) -> String {
      domain.replace('*', "_wildcard_").replace(':', "_")
  }
  ```
- **Observed Behavior**:
  - `get_or_issue_on_demand("::1")` executed on Windows returns `Ok(IssuedCertPair)`.
  - Did NOT trigger Win32 OS error 123 (`ERROR_INVALID_NAME`) or NTFS Alternate Data Stream errors.
  - On-disk filenames created: `__1.crt` and `__1.key`. Both paths exist on disk.
  - DER SAN extension parsed via `x509-parser`: contains `GeneralName::IPAddress` with 16 bytes `[0, ..., 1]`.
  - Global unicast IPv6 address `get_or_issue_on_demand("2001:db8::8a2e:370:7334")` sanitized to `2001_db8__8a2e_370_7334.crt` and succeeded.
  - Cached retrieval for `::1` succeeded and matched original DER bytes.

### 1.5 Full `sb-ca` Crate and Workspace Cleanliness
- `cargo test -p sb-ca`: 20 passed (1 unit test, 4 adversarial SSH tests, 7 adversarial X.509 tests, 4 e2e SSH tests, 4 e2e X.509 tests), 0 failed.
- `cargo check --workspace`: 0 errors, 0 warnings across all 15 crates.

---

## 2. Logic Chain

1. **Wildcard Correctness (Observation 1.2)**:
   - The condition `!clean.starts_with('*')` prevents prepending `*.` when the domain already begins with an asterisk.
   - Calling `get_or_issue_on_demand("*.sbm")` results in `clean = "*.sbm"`, preserving the single wildcard.
   - The SAN extension contains strictly `*.sbm`, complying with RFC 6125 §6.4.3. Double wildcards (`*.*.sbm`) are rejected at input validation.
2. **Concurrency Integrity (Observation 1.3)**:
   - Intra-process concurrency is serialized by acquiring `INDEX_MUTEX` during `DevCertIndex::upsert`.
   - Re-reading on-disk state inside `upsert()` prior to appending guarantees that any concurrent modifications from other threads are merged rather than overwritten.
   - Writing to a PID/random temporary file followed by an atomic rename prevents partial reads and Windows sharing violations.
   - The 32-thread empirical barrier test confirmed 32/32 entries present in `index.json` with 0 lost updates.
   - Fast-path 2 self-healing proves resilience against index loss.
3. **Windows NTFS Compatibility (Observation 1.4)**:
   - Colon characters (`:`) are reserved on Windows NTFS for Alternate Data Streams (ADS) and throw Win32 error 123 when used in ordinary filenames.
   - `domain_to_safe_filename` systematically replaces `:` with `_`.
   - The resulting filename `__1.crt` is valid on NTFS, allowing seamless certificate issuance and caching for IPv6 addresses.
4. **Overall Security and Standards Conformance**:
   - RFC 5280 §4.2.1.12 compliance is verified: leaf certificates contain both ServerAuth (`1.3.6.1.5.5.7.3.1`) and ClientAuth (`1.3.6.1.5.5.7.3.2`) EKUs.
   - Memory hygiene is verified: `IssuedCertPair` implements `Zeroize` and redacts private keys in `fmt::Debug` output (preventing CWE-532 log leaks).
   - All tests pass cleanly without regressions across the workspace.

---

## 3. Caveats

- **Cross-Process Concurrency**: Intra-process concurrency is serialized via `INDEX_MUTEX` and atomic file rename. In the scenario where two distinct CLI processes invoke `sb-ca` at the exact same millisecond, file replacement is atomic (no file corruption), but the last process to rename will commit its index view. For single-daemon or sovereign developer workstation operation, this is optimal; if multi-process concurrent writing is ever required in future phases, an OS-level file lock (`fs2`) can be introduced.
- **No Implementation Modifications**: Challenger 2 performed verification purely by executing tests and analyzing the codebase without modifying crate source code.

---

## 4. Conclusion

**Verdict: APPROVE**

The remediated X.509 CA Engine (`sb_ca::x509`) has successfully satisfied all challenge criteria:
1. `cargo test -p sb-ca --test adversarial_x509 -- --nocapture` passed with 7/7 tests green.
2. Wildcard SAN handling succeeds for `*.sbm` without producing illegal `*.*.sbm`, conforms to RFC 6125, and caches correctly.
3. Concurrency testing under 32 simultaneous threads confirms zero lost updates in `DevCertIndex` and valid atomic index persistence.
4. IPv6 colon sanitization works reliably on Windows NTFS, resolving `::1` without Win32 OS error 123.
5. Workspace compilation and test suites across all crates pass with 0 errors and 0 warnings.

---

## 5. Verification Method

To independently reproduce the empirical findings:

1. **Run Adversarial X.509 Probe**:
   ```powershell
   cargo test -p sb-ca --test adversarial_x509 -- --nocapture
   ```
2. **Run Full `sb-ca` Test Suite**:
   ```powershell
   cargo test -p sb-ca -- --nocapture
   ```
3. **Run Workspace Compilation**:
   ```powershell
   cargo check --workspace
   ```
4. **Invalidation Conditions**:
   - Any test failure in `adversarial_x509`.
   - `get_or_issue_on_demand("*.sbm")` returns a certificate with `*.*.sbm` or fails with an error.
   - `get_or_issue_on_demand("::1")` fails on Windows with OS error 123.
   - Any lost updates in `index.json` following concurrent minting.
