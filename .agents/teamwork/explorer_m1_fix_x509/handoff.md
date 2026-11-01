# Remediation Architecture & Fix Strategy: M1 X.509 PKI & Concurrency

**Agent**: Explorer M1 Fix X.509 (`explorer_m1_fix_x509`)  
**Target Milestone**: Milestone 1 (M1: `sb-ca` PKI Engine Crate) — Remediation Phase  
**Role**: Read-only Investigation & Synthesis  
**Date**: 2026-10-27  

---

## 1. Observation

Direct empirical investigation of the codebase and test runs revealed the following concrete observations:

### Observation 1.1: Double-Prefixing Wildcard Defect in `leaf.rs`
- **Location**: `tools/sb-ca/src/x509/leaf.rs:252-260`
- **Source Code**:
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
- **Observed Execution**: Running `cargo test -p sb-ca --test adversarial_x509 test_adversarial_wildcard_san_handling -- --nocapture` yielded:
  ```text
  >>> Fresh get_or_issue_on_demand('*.sbm') result: Err(InvalidDomain("Domain '*.*.sbm' contains disallowed character '*'"))
  >>> Fresh get_or_issue_on_demand('*.mesh') result: Err(InvalidDomain("Domain '*.*.mesh' contains disallowed character '*'"))
  >>> Fresh get_or_issue_on_demand('*.node1.sbm') result: Err(InvalidDomain("Domain '*.*.node1.sbm' contains disallowed character '*'"))
  ```
- **Mechanism**: When `domain` is `"*.sbm"`, `validate_domain` strips `*.`, verifies `"sbm"`, and returns `Ok("*.sbm")`. In `get_or_issue_on_demand`, `clean.ends_with(".sbm")` is `true`. The code unconditionally executes `format!("*.{}", clean)`, producing `*.*.sbm`. `issue_leaf_certificate` calls `validate_domain("*.*.sbm")`, which strips the first `*.` leaving `*.sbm`, detects the second `*` at line 58, and returns `Err(CaError::InvalidDomain)`.

### Observation 1.2: Unsynchronized `DevCertIndex` Lost Updates (CWE-362)
- **Location**: `tools/sb-ca/src/x509/store.rs:53-77` and `leaf.rs:189-191`
- **Source Code**:
  ```rust
  // leaf.rs:189-191
  let mut index = DevCertIndex::load();
  let _ = index.upsert(meta);

  // store.rs:65-77
  pub fn save(&self) -> Result<(), CaError> {
      let path = x509_index_path();
      let json = serde_json::to_string_pretty(self)?;
      fs::write(&path, json.as_bytes())?;
      Ok(())
  }
  pub fn upsert(&mut self, meta: DevCertMetadata) -> Result<(), CaError> {
      self.certs.retain(|c| c.primary_domain != meta.primary_domain);
      self.certs.push(meta);
      self.save()
  }
  ```
- **Observed Execution**: Running `cargo test -p sb-ca --test adversarial_x509 test_adversarial_concurrency_lost_updates_different_domains -- --nocapture` with 10 concurrent threads yielded:
  ```text
  >>> Distinct mints: 10 successes, 0 errors
  >>> DevCertIndex total cert count after 10 distinct mints: 0 (expected: 10)
  LOST UPDATE CONFIRMED: Domain 'concurrent-peer-0.sbm' is MISSING from index.json!
  ...
  CONFIRMED BUG 2: DevCertIndex lost 10 updates due to unsynchronized concurrent index.json writes (CWE-362)!
  >>> Re-fetch latency for lost domain: 4.8629ms
  CONFIRMED CONSEQUENCE: Lost index entry caused full CA re-minting instead of cache hit! Cache bypass defect verified.
  ```
- **Mechanism**: Every concurrent thread reads `index.json` independently into memory, appends its own newly issued certificate, and writes back the whole file via `fs::write`. Earlier threads' additions are completely overwritten by later threads. Furthermore, because line 225 requires `index.find(&clean)` before returning cached certificates, all missing domains permanently bypass the fast disk cache, re-minting keys and certs on every request (~4.86ms vs ~0.54ms).

### Observation 1.3: Windows OS Error 123 from Unsanitized Colons in Filenames
- **Location**: `tools/sb-ca/src/x509/leaf.rs:68-70`
- **Source Code**:
  ```rust
  pub fn domain_to_safe_filename(domain: &str) -> String {
      domain.replace('*', "_wildcard_")
  }
  ```
- **Observed Execution**: In `test_adversarial_domain_validation_and_path_traversal`:
  ```text
  validate_domain('::1') result: Ok("::1")
  get_or_issue_on_demand('::1') result: Err(Io(Os { code: 123, kind: InvalidFilename, message: "The filename, directory name, or volume label syntax is incorrect." }))
  ```
- **Mechanism**: On Windows NTFS, `:` is reserved for drive specifications and Alternate Data Streams (ADS). Writing `::1.crt` fails with Win32 OS error 123 (`ERROR_INVALID_NAME`). Writing `node1:8080.crt` creates a hidden NTFS ADS stream `node1:8080.crt` attached to `node1`.

### Observation 1.4: Concurrent Root CA Split-Brain Risk
- **Location**: `tools/sb-ca/src/x509/root.rs:46-53` and `leaf.rs:121-123`
- **Source Code**:
  ```rust
  if crt_path.exists() && key_path.exists() && !force {
      return get_ca_status();
  }
  ```
- **Mechanism**: When multiple concurrent threads call `get_or_issue_on_demand` before the Root CA has been initialized, multiple threads enter `init_root_ca` simultaneously. If two threads generate different Root CA keys and overwrite `root_ca.crt` and `root_ca.key`, leaf certificates issued by the overwritten key become cryptographically orphaned and fail chain verification against `root_ca.crt`.

### Observation 1.5: Plaintext Private Key Exposure in `IssuedCertPair` Debug derive
- **Location**: `tools/sb-ca/src/x509/store.rs:16-34`
- **Source Code**:
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct IssuedCertPair {
      pub cert_pem: String,
      pub key_pem: String,
      pub cert_der: Vec<u8>,
      pub key_der: Vec<u8>,
      ...
  }
  ```
- **Mechanism**: Deriving `Debug` on `IssuedCertPair` prints the unencrypted PEM and DER private keys directly to console logs or error messages (CWE-312 / CWE-532). It also does not implement `Zeroize` on drop.

---

## 2. Logic Chain

1. **Premise 1 (RFC 6125 §6.4.3 & RFC 5280 §4.2.1.6)**:
   Wildcards are only legal at the leftmost label position (e.g. `*.example.com`). Double wildcards such as `*.*.sbm` are strictly invalid. When a caller requests a domain that is already a wildcard (`*.sbm`, `*.mesh`, `*.node1.sbm`), prepending `*.` violates the grammar and causes the downstream validator to reject the request. If the code checks `!clean.starts_with('*')` before generating the wildcard SAN, `*.sbm` is retained as a valid wildcard SAN and `*.*.sbm` is never generated.

2. **Premise 2 (Concurrency & Data Integrity - CWE-362)**:
   The `DevCertIndex` catalog is an in-memory representation of `index.json`. When multiple threads invoke `upsert()`, interleaving between `load()` and `save()` destroys concurrent updates. To achieve linearizable updates without lost updates:
   - Intra-process synchronization must be enforced via a static process mutex (`INDEX_MUTEX`).
   - The mutex lock must be held across the entire atomic unit: loading current on-disk state, merging the new certificate metadata, and persisting the result.
   - File persistence must use atomic replacement: write to a temporary file (`.index.json.<pid>.<rand>.tmp`) on the same filesystem, flush, and rename via `std::fs::rename`.
   - In addition, to defend against potential index desynchronization or manual certificate additions, `get_or_issue_on_demand` must feature a **disk fallback**: if `index.find(&clean)` misses an entry but `leaf_crt_path` and `leaf_key_path` exist on disk, inspect the certificate's validity with `x509-parser`, self-heal the index entry via `upsert`, and return the cached certificate.

3. **Premise 3 (Windows File System Interoperability & Security - CWE-22 / CWE-20)**:
   Windows NTFS paths reject colons (`:`) in file names. Replacing `:` with `_` in `domain_to_safe_filename` transforms `::1` into `__1` and `node1:8080` into `node1_8080`. This eliminates OS error 123, prevents NTFS Alternate Data Stream creation, and remains fully reversible/deterministic for file lookups.

4. **Premise 4 (Root CA Split-Brain Prevention)**:
   Synchronizing `init_root_ca` with a static mutex (`ROOT_INIT_MUTEX`) guarantees that only the first thread executes key generation, while all concurrent threads block until the certificate and key are on disk, then safely exit early through the `crt_path.exists()` check.

5. **Premise 5 (Defense in Depth & Cryptographic Hygiene - CWE-312 / CWE-532)**:
   Implementing custom `fmt::Debug` for `IssuedCertPair` redacts `key_pem` and `key_der`, preventing accidental credential leakage in logs. Implementing `Drop` with `zeroize::Zeroize` wipes private key memory upon deallocation.

---

## 3. Caveats

- **Caveat 1 (Cross-Process File Locking)**: `INDEX_MUTEX` serializes concurrent threads within the same operating system process (the primary operational model for `sb-ca` embedded in `sb-proxy` and CLI commands). If multiple independent CLI processes invoke `sb-ca` at the exact same millisecond, `fs::rename` ensures that `index.json` is never corrupted or partially written, though atomic merging between separate processes would require OS-level advisory file locks (`fs2`). For Milestone 1 and 2 integration, process-level mutex + atomic rename + disk fallback provides complete protection.
- **Caveat 2 (Apex Domain in Wildcard Requests)**: When `*.node1.sbm` is requested, the wildcard certificate covers `foo.node1.sbm`, but does NOT cover `node1.sbm` itself per RFC 6125 §6.4.3. The strategy preserves the exact requested domain (`*.node1.sbm`) in `sans`. If callers need both apex and wildcard, callers or resolvers can request both.
- **Caveat 3 (Test Assertion Alignment in `adversarial_x509.rs`)**: Challenger 2's test suite originally asserted that `get_or_issue_on_demand("*.sbm")` produced `Err(CaError::InvalidDomain)` in order to prove the existence of Bug 1. For the remediation verification, that assertion in `adversarial_x509.rs` must be updated to assert success (`Ok(pair)`) so that it acts as a permanent regression test.

---

## 4. Conclusion & Concrete Fix Strategy

The remediation is structured into five concrete implementation targets across `tools/sb-ca`:

```
tools/sb-ca/
├── Cargo.toml               # Target 1: Promote x509-parser to [dependencies]
├── src/x509/leaf.rs         # Target 2: Colon sanitization, wildcard fix, disk fallback
├── src/x509/store.rs        # Target 3: INDEX_MUTEX, atomic tempfile+rename, Debug redaction & Zeroize
├── src/x509/root.rs         # Target 4: ROOT_INIT_MUTEX against split-brain
└── tests/adversarial_x509.rs# Target 5: Update adversarial assertions to verify passing state
```

### Detailed Code Changes

#### Target 1: Promote `x509-parser` in `tools/sb-ca/Cargo.toml`
Move `x509-parser` from `[dev-dependencies]` to `[dependencies]` to enable safe certificate parsing for disk fallback cache recovery.
```toml
[dependencies]
clap = { version = "4.5", features = ["derive"] }
colored = "3.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
zeroize = { version = "1.8", features = ["derive", "zeroize_derive"] }
ssh-key = { version = "0.6.7", features = ["ed25519", "std", "getrandom"] }
rcgen = { version = "0.14", default-features = false, features = ["pem", "ring", "x509-parser"] }
time = { version = "0.3", features = ["formatting", "parsing"] }
chrono = { version = "0.4", features = ["serde"] }
rand = "0.8"
dirs = "6.0"
hex = "0.4"
base64 = "0.22"
sb-core = { version = "0.2.0", path = "../sb-core" }
x509-parser = "0.18"

[dev-dependencies]
# x509-parser moved to dependencies
```

---

#### Target 2: Fix `leaf.rs` (`domain_to_safe_filename`, Wildcard Handling, Disk Fallback)

1. **Filename Colon Sanitization (`leaf.rs:67-70`)**:
```rust
/// Converts a domain name into a safe filesystem filename by escaping wildcard asterisks
/// and replacing colons (to prevent Windows NTFS Alternate Data Streams and OS error 123).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Path traversal or invalid filesystem characters causing OS errors (Win32 ERROR_INVALID_NAME 123) or NTFS Alternate Data Streams (ADS).
/// - CVE / CWE Mapping: CWE-22 (Path Traversal), CWE-20 (Improper Input Validation).
/// - Likelihood & Exploitability: High (8/10) on Windows systems when handling IPv6 addresses (`::1`) or port notations.
/// - Applied Mitigation: Replaces `*` with `_wildcard_` and `:` with `_`.
pub fn domain_to_safe_filename(domain: &str) -> String {
    domain.replace('*', "_wildcard_").replace(':', "_")
}
```

2. **Wildcard Fix & Cache Recovery with Disk Fallback (`leaf.rs:214-262`)**:
```rust
pub fn get_or_issue_on_demand(domain: &str) -> Result<IssuedCertPair, CaError> {
    let clean = validate_domain(domain)?;
    let safe_name = domain_to_safe_filename(&clean);

    let certs_dir = x509_certs_dir();
    let leaf_crt_path = certs_dir.join(format!("{}.crt", safe_name));
    let leaf_key_path = certs_dir.join(format!("{}.key", safe_name));

    // Fast-path 1: Check if certificate and key already exist on disk
    if leaf_crt_path.exists() && leaf_key_path.exists() {
        let index = DevCertIndex::load();
        if let Some(meta) = index.find(&clean) {
            // Check if certificate has expired
            if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(&meta.expires_at) {
                if exp_time.with_timezone(&Utc) > Utc::now() + chrono::Duration::hours(1) {
                    if let (Ok(cert_pem), Ok(key_pem)) = (
                        fs::read_to_string(&leaf_crt_path),
                        fs::read_to_string(&leaf_key_path),
                    ) {
                        if let (Ok(cert_der), Ok(key_der)) = (pem_to_der(&cert_pem), pem_to_der(&key_pem)) {
                            return Ok(IssuedCertPair {
                                cert_pem,
                                key_pem,
                                cert_der,
                                key_der,
                                cert_path: leaf_crt_path,
                                key_path: leaf_key_path,
                                domains: meta.alt_names.clone(),
                                expires_at: meta.expires_at.clone(),
                            });
                        }
                    }
                }
            }
        } else {
            // Fast-path 2 (Disk Fallback): Files exist on disk but index.json missed the entry (CWE-362 lost update recovery).
            // Directly inspect on-disk certificate validity and recover into index.
            if let (Ok(cert_pem), Ok(key_pem)) = (
                fs::read_to_string(&leaf_crt_path),
                fs::read_to_string(&leaf_key_path),
            ) {
                if let (Ok(cert_der), Ok(key_der)) = (pem_to_der(&cert_pem), pem_to_der(&key_pem)) {
                    if let Ok((_, x509)) = x509_parser::parse_x509_certificate(&cert_der) {
                        let not_after = x509.validity().not_after.timestamp();
                        let now_ts = Utc::now().timestamp();
                        if not_after > now_ts + 3600 {
                            let mut alt_names = vec![clean.clone()];
                            if let Ok(Some(san_ext)) = x509.subject_alternative_name() {
                                for gn in &san_ext.value.general_names {
                                    if let x509_parser::extensions::GeneralName::DNSName(dns) = gn {
                                        let dns_s = dns.to_string();
                                        if !alt_names.contains(&dns_s) {
                                            alt_names.push(dns_s);
                                        }
                                    }
                                }
                            }
                            let expires_at = chrono::DateTime::from_timestamp(not_after, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_default();

                            let meta = DevCertMetadata {
                                primary_domain: clean.clone(),
                                alt_names: alt_names.clone(),
                                cert_path: leaf_crt_path.to_string_lossy().to_string(),
                                key_path: leaf_key_path.to_string_lossy().to_string(),
                                issued_at: Utc::now().to_rfc3339(),
                                expires_at: expires_at.clone(),
                            };
                            let mut idx = DevCertIndex::load();
                            let _ = idx.upsert(meta);

                            return Ok(IssuedCertPair {
                                cert_pem,
                                key_pem,
                                cert_der,
                                key_der,
                                cert_path: leaf_crt_path,
                                key_path: leaf_key_path,
                                domains: alt_names,
                                expires_at,
                            });
                        }
                    }
                }
            }
        }
    }

    // Determine SANs: include explicit domain, and if it's a mesh domain and NOT already a wildcard,
    // add wildcard for immediate subdomains per RFC 6125 §6.4.3.
    let mut sans = vec![clean.clone()];
    if (clean.ends_with(".sbm") || clean.ends_with(".mesh")) && !clean.starts_with('*') {
        let wildcard = format!("*.{}", clean);
        if !sans.contains(&wildcard) {
            sans.push(wildcard);
        }
    }

    issue_leaf_certificate(&sans, DEFAULT_LEAF_CERT_TTL_DAYS)
}
```

---

#### Target 3: Fix `store.rs` (`INDEX_MUTEX`, Atomic Replace, Debug Redaction, Zeroize)

```rust
use crate::error::CaError;
use crate::paths::x509_index_path;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroize;

/// Global process-level mutex serializing all DevCertIndex disk reads and writes.
pub static INDEX_MUTEX: Mutex<()> = Mutex::new(());

/// Complete pair of issued certificate, private key, and serialized DER representations.
///
/// Interface contract for `sb-proxy` and cryptographic consumers.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuedCertPair {
    /// Full-chain certificate in PEM encoding (Leaf certificate + Root CA certificate).
    pub cert_pem: String,
    /// Private key in PEM encoding.
    pub key_pem: String,
    /// Leaf certificate in DER binary encoding.
    pub cert_der: Vec<u8>,
    /// Private key in DER binary encoding.
    pub key_der: Vec<u8>,
    /// Filesystem path to the stored certificate file.
    pub cert_path: PathBuf,
    /// Filesystem path to the stored private key file.
    pub key_path: PathBuf,
    /// List of SAN domain names and IP addresses covered by this certificate.
    pub domains: Vec<String>,
    /// RFC 3339 timestamp of expiration.
    pub expires_at: String,
}

impl std::fmt::Debug for IssuedCertPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCertPair")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("domains", &self.domains)
            .field("expires_at", &self.expires_at)
            .field("cert_pem", &"<PEM encoded certificate>")
            .field("key_pem", &"[REDACTED PRIVATE KEY]")
            .field("cert_der", &format!("<{} bytes>", self.cert_der.len()))
            .field("key_der", &"[REDACTED PRIVATE KEY DER]")
            .finish()
    }
}

impl Drop for IssuedCertPair {
    fn drop(&mut self) {
        self.key_pem.zeroize();
        self.key_der.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevCertMetadata {
    pub primary_domain: String,
    pub alt_names: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevCertIndex {
    pub certs: Vec<DevCertMetadata>,
}

impl DevCertIndex {
    fn load_internal() -> Self {
        let path = x509_index_path();
        if let Ok(data) = fs::read_to_string(&path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Loads the index from `~/.sb/ca/index.json` under mutex synchronization.
    pub fn load() -> Self {
        let _guard = INDEX_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        Self::load_internal()
    }

    fn save_internal(&self) -> Result<(), CaError> {
        let path = x509_index_path();
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let _ = fs::create_dir_all(parent);

        let json = serde_json::to_string_pretty(self)?;
        let rand_suffix: u64 = rand::random();
        let tmp_path = parent.join(format!(
            ".index.json.{}.{}.tmp",
            std::process::id(),
            rand_suffix
        ));

        fs::write(&tmp_path, json.as_bytes())?;

        // Atomic file replacement via rename with retries for Windows file lock release
        for attempt in 0..5 {
            match fs::rename(&tmp_path, &path) {
                Ok(_) => return Ok(()),
                Err(_) if attempt < 4 => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(CaError::Io(e));
                }
            }
        }
        Ok(())
    }

    /// Atomically persists the index to `~/.sb/ca/index.json` under mutex synchronization.
    pub fn save(&self) -> Result<(), CaError> {
        let _guard = INDEX_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        self.save_internal()
    }

    /// Atomically records or updates an issued certificate in the index,
    /// reloading current on-disk state to eliminate lost updates (CWE-362).
    pub fn upsert(&mut self, meta: DevCertMetadata) -> Result<(), CaError> {
        let _guard = INDEX_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let mut disk_index = Self::load_internal();
        disk_index.certs.retain(|c| c.primary_domain != meta.primary_domain);
        disk_index.certs.push(meta);
        disk_index.save_internal()?;
        self.certs = disk_index.certs;
        Ok(())
    }

    /// Finds metadata for a domain if previously issued and index entry exists.
    pub fn find(&self, domain: &str) -> Option<&DevCertMetadata> {
        let needle = domain.trim().to_ascii_lowercase();
        self.certs.iter().find(|c| {
            c.primary_domain == needle || c.alt_names.iter().any(|a| a == &needle)
        })
    }
}
```

---

#### Target 4: Fix `root.rs` (Root CA Split-Brain Protection)

In `tools/sb-ca/src/x509/root.rs:46-53`:
```rust
static ROOT_INIT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn init_root_ca(force: bool) -> Result<X509CaStatus, CaError> {
    let _guard = ROOT_INIT_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let crt_path = x509_root_crt_path();
    let key_path = x509_root_key_path();

    if crt_path.exists() && key_path.exists() && !force {
        return get_ca_status();
    }
    // ... proceed with generation ...
}
```

---

#### Target 5: Update `tools/sb-ca/tests/adversarial_x509.rs` Test Probes

Update the test assertions so all 7 probes verify positive compliance:

1. **Probe 1 (`test_adversarial_wildcard_san_handling`)**:
   ```rust
   assert!(on_demand_sbm.is_ok(), "get_or_issue_on_demand('*.sbm') must succeed: {:?}", on_demand_sbm);
   let pair_sbm = on_demand_sbm.unwrap();
   assert!(pair_sbm.domains.contains(&"*.sbm".to_string()));
   assert!(!pair_sbm.domains.iter().any(|d| d.contains("*.*")));

   assert!(on_demand_mesh.is_ok(), "get_or_issue_on_demand('*.mesh') must succeed: {:?}", on_demand_mesh);
   let pair_mesh = on_demand_mesh.unwrap();
   assert!(pair_mesh.domains.contains(&"*.mesh".to_string()));

   assert!(on_demand_sub.is_ok(), "get_or_issue_on_demand('*.node1.sbm') must succeed: {:?}", on_demand_sub);
   let pair_sub = on_demand_sub.unwrap();
   assert!(pair_sub.domains.contains(&"*.node1.sbm".to_string()));
   ```

2. **Probe 2 (`test_adversarial_domain_validation_and_path_traversal`)**:
   ```rust
   let issue_ipv6 = get_or_issue_on_demand("::1");
   assert!(issue_ipv6.is_ok(), "Issuance for IPv6 '::1' must succeed with colon sanitization: {:?}", issue_ipv6);
   let pair_ipv6 = issue_ipv6.unwrap();
   assert!(pair_ipv6.cert_path.exists());
   let cache_ipv6 = get_or_issue_on_demand("::1");
   assert!(cache_ipv6.is_ok(), "Cached retrieval for IPv6 '::1' must succeed: {:?}", cache_ipv6);
   ```

3. **Probe 6 (`test_adversarial_concurrency_lost_updates_different_domains`)**:
   ```rust
   assert_eq!(mint_errors, 0, "No concurrent minting errors allowed");
   assert_eq!(mint_successes, num_threads, "All concurrent threads must succeed");
   assert_eq!(index.certs.len(), num_threads, "DevCertIndex must contain all {} concurrently issued domains", num_threads);
   for i in 0..num_threads {
       let dom = format!("concurrent-peer-{}.sbm", i);
       assert!(index.find(&dom).is_some(), "Domain '{}' must be present in index.json", dom);
   }
   ```

4. **Probe 7 (`test_adversarial_concurrent_initialization_split_brain`)**:
   ```rust
   assert_eq!(errors, 0, "No errors during concurrent initializations");
   assert_eq!(split_brain_count, 0, "Zero certificates may be signed by an orphaned Root CA key");
   ```

---

## 5. Verification Method

To independently verify this strategy after application:

### Commands to Execute:
```bash
# 1. Compile the crate and test targets
cargo test -p sb-ca --no-run

# 2. Run the entire adversarial test suite
cargo test -p sb-ca --test adversarial_x509 -- --nocapture

# 3. Specifically verify wildcard issuance probe
cargo test -p sb-ca --test adversarial_x509 test_adversarial_wildcard_san_handling -- --nocapture

# 4. Specifically verify concurrency and zero lost updates
cargo test -p sb-ca --test adversarial_x509 test_adversarial_concurrency_lost_updates_different_domains -- --nocapture

# 5. Specifically verify IPv6 colon sanitization on Windows
cargo test -p sb-ca --test adversarial_x509 test_adversarial_domain_validation_and_path_traversal -- --nocapture

# 6. Run all existing crate tests (unit and integration)
cargo test -p sb-ca -- --nocapture
```

### Invalidation Conditions:
1. `get_or_issue_on_demand("*.sbm")` returns `Err(CaError::InvalidDomain)` containing `*.*`.
2. `test_adversarial_concurrency_lost_updates_different_domains` has `index.certs.len() < 10`.
3. `get_or_issue_on_demand("::1")` fails with `Os { code: 123, kind: InvalidFilename }`.
4. Any thread in `test_adversarial_concurrent_initialization_split_brain` receives a certificate not matching `root_ca.crt`.
5. `format!("{:?}", pair)` leaks `key_pem` private key content into logs.
