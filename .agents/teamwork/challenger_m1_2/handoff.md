# Adversarial Verification Report: `sb-ca::x509` Engine

**Verdict**: **`REQUEST_CHANGES`** (Action Required before M2 integration)

---

## 1. Observation

Direct empirical evidence was gathered by creating and running the automated adversarial integration test suite in `tools/sb-ca/tests/adversarial_x509.rs`.

Command executed:
```bash
cargo test -p sb-ca --test adversarial_x509 -- --nocapture
```

### Observation 1.1: Broken Wildcard Issuance in `get_or_issue_on_demand` (Critical)
- **Source Code (`tools/sb-ca/src/x509/leaf.rs:252-260`)**:
  ```rust
  let mut sans = vec![clean.clone()];
  if clean.ends_with(".sbm") || clean.ends_with(".mesh") {
      let wildcard = format!("*.{}", clean);
      if !sans.contains(&wildcard) {
          sans.push(wildcard);
      }
  }

  issue_leaf_certificate(&sans, DEFAULT_LEAF_CERT_TTL_DAYS)
  ```
- **Observed Test Execution**:
  Calling `get_or_issue_on_demand("*.sbm")`, `get_or_issue_on_demand("*.mesh")`, or `get_or_issue_on_demand("*.node1.sbm")` on a clean system produces the following error:
  ```text
  >>> Fresh get_or_issue_on_demand('*.sbm') result: Err(InvalidDomain("Domain '*.*.sbm' contains disallowed character '*'"))
  >>> Fresh get_or_issue_on_demand('*.mesh') result: Err(InvalidDomain("Domain '*.*.mesh' contains disallowed character '*'"))
  >>> Fresh get_or_issue_on_demand('*.node1.sbm') result: Err(InvalidDomain("Domain '*.*.node1.sbm' contains disallowed character '*'"))
  ```
- **Defect Mechanism**:
  When `clean` is `"*.sbm"`, `clean.ends_with(".sbm")` is `true`. The code unconditionally prefixes `*.`, producing `*.*.sbm`. `issue_leaf_certificate` validates all SANs via `validate_domain("*.*.sbm")`, which strips the first `*.` leaving `*.sbm`, detects `*`, and returns `Err(CaError::InvalidDomain("Domain '*.*.sbm' contains disallowed character '*'"))`.

### Observation 1.2: Unsynchronized `DevCertIndex` Lost Updates (CWE-362) & Cache Bypass (High)
- **Source Code (`tools/sb-ca/src/x509/leaf.rs:189-191`, `tools/sb-ca/src/x509/store.rs:65-77`)**:
  ```rust
  let mut index = DevCertIndex::load();
  let _ = index.upsert(meta);
  ```
  `index.upsert()` loads `index.json`, modifies the in-memory array, and calls `fs::write(&path, json.as_bytes())`. There is no process mutex, file lock, or atomic rename.
- **Observed Test Execution (`test_adversarial_concurrency_lost_updates_different_domains`)**:
  10 concurrent threads called `get_or_issue_on_demand` for 10 distinct domains (`concurrent-peer-0.sbm` through `concurrent-peer-9.sbm`).
  ```text
  >>> Distinct mints: 10 successes, 0 errors
  >>> DevCertIndex total cert count after 10 distinct mints: 2 (expected: 10)
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-0.sbm' is MISSING from index.json!
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-2.sbm' is MISSING from index.json!
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-3.sbm' is MISSING from index.json!
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-4.sbm' is MISSING from index.json!
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-5.sbm' is MISSING from index.json!
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-6.sbm' is MISSING from index.json!
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-7.sbm' is MISSING from index.json!
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-9.sbm' is MISSING from index.json!
  CONFIRMED BUG 2: DevCertIndex lost 8 updates due to unsynchronized concurrent index.json writes (CWE-362)!
  >>> Re-fetch latency for lost domain: 3.2586ms
  CONFIRMED CONSEQUENCE: Lost index entry caused full CA re-minting instead of cache hit! Cache bypass defect verified.
  ```
- **Defect Mechanism**:
  80% of concurrently issued certificates were wiped from `index.json`. Because lines 224-225 require `index.find(&clean)` to match before returning cached certificates, all 8 lost domains permanently bypass the fast disk cache. Subsequent requests re-mint a brand new private key and certificate on every request (3.26ms vs 0.55ms). Furthermore, `X509Ca::list_certificates()` and `sb-ca x509 list` omit the issued certificates.

### Observation 1.3: Unescaped Colons in Windows Filename (Medium)
- **Source Code (`tools/sb-ca/src/x509/leaf.rs:56`, `leaf.rs:68-70`, `leaf.rs:163`)**:
  `validate_domain` permits `:` (`ch != ':'`).
  `domain_to_safe_filename` only replaces `*`: `domain.replace('*', "_wildcard_")`.
- **Observed Test Execution (`test_adversarial_domain_validation_and_path_traversal`)**:
  ```text
  validate_domain('::1') result: Ok("::1")
  get_or_issue_on_demand('::1') result: Err(Io(Os { code: 123, kind: InvalidFilename, message: "The filename, directory name, or volume label syntax is incorrect." }))
  ```
- **Defect Mechanism**:
  Windows NTFS rejects `::1.crt` with OS error 123. For domains with port numbers (e.g. `node:8080`), NTFS creates Alternate Data Streams (`node:8080.crt`), violating RFC 5280 §4.2.1.6 (DNS names must not include port numbers) and RFC 6125.

### Observation 1.4: Verified Robust Features
1. **mTLS Extended Key Usage OIDs (`test_adversarial_mtls_extended_key_usage_oids`)**:
   - `x509-parser` confirmed the presence of `ExtendedKeyUsage` (OID 2.5.29.37) containing both:
     - `ServerAuth` (OID 1.3.6.1.5.5.7.3.1)
     - `ClientAuth` (OID 1.3.6.1.5.5.7.3.2)
   - `KeyUsage` contains both `digitalSignature` and `keyEncipherment`.
   - `BasicConstraints` confirms `ca: false`.
2. **Security & Input Validation Gate (`test_adversarial_domain_validation_and_path_traversal`)**:
   - Path traversal (`../`, `../../etc/shadow`, `..\\..\\windows\\system32`, `foo/bar`, `foo\\bar`): Blocked.
   - Control chars and null bytes (`\0`, `\n`, `\r`, `\t`): Blocked.
   - Shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``, `'`, `"`): Blocked.
   - Max length boundary: 253 characters accepted; 254 characters rejected.
   - Empty/whitespace/dot strings (`""`, `"   "`, `"."`, `".."`): Blocked.
3. **Latency SLA Compliance (`test_adversarial_on_demand_latency_sla`)**:
   - Initial mint latency: **2.81ms** (Target: <5ms SLA -> **PASSED**).
   - Cached retrieval latency (100 runs):
     - `min`: 531.6 µs
     - `p50`: 551.6 µs
     - `p95`: 970.0 µs
     - `p99`: 5.78 ms (due to Windows NTFS file system cache flush)
     - `avg`: 665.0 µs
     (Target: microsecond / sub-millisecond retrieval -> **PASSED**).

---

## 2. Logic Chain

1. **Step 1 (Wildcard Handling)**:
   The M1 prompt explicitly specifies: *"Test SAN wildcard handling (`*.sbm`, `*.mesh`)... Verify whether any edge case can cause a panic, corruption, or invalid certificate emission."*
   `get_or_issue_on_demand` is the primary interface for `sb-proxy` DynamicSniResolver. When a client connects asking for `*.sbm` or `*.mesh`, `get_or_issue_on_demand` unconditionally executes `format!("*.{}", clean)`.
   Because `clean` is already `*.sbm`, this produces `*.*.sbm`.
   `issue_leaf_certificate` enforces `validate_domain` on all SANs.
   `validate_domain("*.*.sbm")` strips `*.` leaving `*.sbm`, detects `*`, and aborts with `InvalidDomain`.
   Therefore, on-demand resolution of wildcard domains fails 100% of the time.

2. **Step 2 (Concurrency & Lost Updates)**:
   The M1 prompt specifies: *"Test concurrent calls: verify race conditions when multiple threads request the same unissued domain simultaneously."*
   When distinct mesh services or nodes connect simultaneously, multiple threads call `get_or_issue_on_demand` in parallel.
   Because `DevCertIndex::load()` and `DevCertIndex::save()` perform uncoordinated read-modify-writes directly on `~/.sb/ca/index.json`, concurrent saves overwrite each other.
   Empirical testing with 10 threads demonstrated that 8 of 10 updates were destroyed.
   Because the caching fast-path (`leaf.rs:224-225`) strictly checks `if let Some(meta) = index.find(&clean)`, any domain lost from `index.json` can NEVER hit the cache. Subsequent requests re-mint new certificates on every call, taking ~3.26ms and defeating the caching architecture.

3. **Step 3 (Platform Resilience on Windows)**:
   `validate_domain` permits `:` to allow ports or IPv6 addresses.
   `domain_to_safe_filename` does not translate `:` into a filesystem-safe character (such as `_`).
   On Windows NTFS, filenames containing colons either trigger `os error 123 (InvalidFilename)` or generate NTFS Alternate Data Streams.

---

## 3. Caveats

- **Direct Issuance Workaround**:
  Calling `sb_ca::x509::issue_leaf_certificate(&["*.sbm".into(), "*.mesh".into()], 90)` directly works because callers specify SANs explicitly without triggering `get_or_issue_on_demand`'s wildcard concatenation logic. However, since `get_or_issue_on_demand` is the required interface contract for Milestone 2 (`sb-proxy`), the bug in `get_or_issue_on_demand` is blocking.
- **Single-Threaded Use**:
  In strictly serialized environments where only one process/thread calls `sb-ca` at any given time and no wildcards are requested via `get_or_issue_on_demand`, the engine performs within specifications.

---

## 4. Conclusion & Required Changes

**Verdict**: **`REQUEST_CHANGES`**

Before Milestone 1 can be approved and Milestone 2 (`sb-proxy`) can rely on `sb_ca::x509`, the worker must apply the following targeted fixes:

1. **Fix Wildcard Concatenation in `tools/sb-ca/src/x509/leaf.rs:252-259`**:
   Only generate a subdomain wildcard if `clean` does NOT already start with `*` or `*.`:
   ```rust
   let mut sans = vec![clean.clone()];
   if (clean.ends_with(".sbm") || clean.ends_with(".mesh")) && !clean.starts_with('*') {
       let wildcard = format!("*.{}", clean);
       if !sans.contains(&wildcard) {
           sans.push(wildcard);
       }
   }
   ```
2. **Fix `DevCertIndex` Lost Updates (CWE-362)**:
   Add process-level synchronization (e.g., `static INDEX_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());`) around `DevCertIndex::load()`, mutation, and `save()`, or make cache resolution check the disk (`leaf_crt_path.exists() && leaf_key_path.exists()`) directly without hard-requiring `index.find(&clean)` if metadata is absent.
3. **Sanitize Colons in `domain_to_safe_filename` and Domain Validation**:
   Disallow `:` in `validate_domain` for DNS names (per RFC 5280 / RFC 6125), or replace `:` with `_` in `domain_to_safe_filename` so IPv6 addresses do not cause Windows OS error 123.

---

## 5. Verification Method

To verify these findings and confirm any subsequent fixes:

```bash
# 1. Run the entire test suite including the adversarial probes
cargo test -p sb-ca --test adversarial_x509 -- --nocapture

# 2. Specifically verify wildcard fix
cargo test -p sb-ca --test adversarial_x509 test_adversarial_wildcard_san_handling -- --nocapture

# 3. Specifically verify concurrency fix
cargo test -p sb-ca --test adversarial_x509 test_adversarial_concurrency_lost_updates_different_domains -- --nocapture
```

The test file `tools/sb-ca/tests/adversarial_x509.rs` remains in place as an automated regression guard.
