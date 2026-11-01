# Forensic Audit Report & Handoff: Milestone 2 Iteration 2

**Milestone**: M2 `sb-proxy` On-Demand TLS Integration  
**Auditor**: `auditor_m2_r2`  
**Date**: 2026-10-27T22:02:30Z  
**Verdict**: **CLEAN**

---

## Forensic Audit Report

**Work Product**: Milestone 2 Iteration 2 (`tools/sb-proxy/src/proxy.rs`, `tools/sb-proxy/tests/`, `~/.sb/ca/certs/`, `~/.sb/ca/index.json`)  
**Profile**: General Project (Development Mode)  
**Verdict**: **CLEAN**

### Phase Results
- **Phase 1: Source Code Analysis**: PASS — No hardcoded test results, mocks, facade implementations, or bypasses.
- **Phase 2: Cryptographic & RAM Caching Verification**: PASS — Authentic ECDSA P-256 issuance via `sb-ca` / `rcgen 0.14`, `Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>` sub-microsecond caching with pointer equality (`Arc::ptr_eq`).
- **Phase 3: Disk & Index Hygiene**: PASS — 0 spurious files in `~/.sb/ca/certs/` matching `^\.sbm|__1|_wildcard_|foo_bar`, 0 malformed entries in `~/.sb/ca/index.json`.
- **Phase 4: Independent Build & Test Execution**: PASS — `cargo check --tests --workspace` (0 errors, 0 warnings), `cargo test -p sb-proxy` (58/58 passed), `cargo test -p sb-ca` (15/15 passed), `cargo test -p sb-cli` (85/85 passed).
- **Phase 5: Adversarial Matrix Verification**: PASS — 0 mismatches across all 23 adversarial test vectors in `test_adversarial_sni_resolution_matrix`.

---

## 1. Observation

### 1.1 Source Code Verification in `tools/sb-proxy/src/proxy.rs`
1. **RFC 6066 §3 / RFC 1035 Pre-validation in `resolve_for_server_name`** (`tools/sb-proxy/src/proxy.rs:280-306`):
   ```rust
   pub fn resolve_for_server_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
       let name_clean = server_name.trim_end_matches('.').to_ascii_lowercase();
       // RFC 6066 §3 / RFC 1035 fail-closed pre-validation:
       // Do not query RAM cache or filesystem for structurally invalid SNIs
       if name_clean.is_empty()
           || name_clean.len() > 253
           || name_clean.contains('*')
           || name_clean.contains(':')
           || name_clean.contains('[')
           || name_clean.contains(']')
           || name_clean.contains('/')
           || name_clean.contains('\\')
           || name_clean.contains('\0')
           || name_clean.contains("..")
           || name_clean.starts_with('.')
           || name_clean.chars().any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
           || !name_clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
       {
           return self.fallback_cert.clone();
       }

       for label in name_clean.split('.') {
           if label.is_empty() || label.len() > 63 {
               return self.fallback_cert.clone();
           }
       }
   ```
2. **RAM Caching Fast-Path & Dynamic Issuance** (`tools/sb-proxy/src/proxy.rs:307-343`):
   ```rust
       // Fast-Path 1: In-memory RAM cache (sub-microsecond lookup)
       if let Ok(cache) = self.cert_cache.read() {
           if let Some(cert) = cache.get(&name_clean) {
               return Some(cert.clone());
           }
       }
       ...
       // Fast-Path 4: On-Demand TLS Issuance with Eligibility Gate
       if self.is_eligible_for_on_demand(&name_clean) {
           match sb_ca::x509::get_or_issue_on_demand(&name_clean) {
               Ok(pair) => {
                   match certified_key_from_pem(&pair.cert_pem, &pair.key_pem)
                       .or_else(|_| load_certified_key(&pair.cert_path, &pair.key_path))
                   {
                       Ok(cert) => {
                           if let Ok(mut cache) = self.cert_cache.write() {
                               cache.insert(name_clean.clone(), cert.clone());
                           }
                           return Some(cert);
                       }
   ```

### 1.2 Disk and Index Hygiene Empirical Verification
1. **On-Disk Certificates Check** (`~/.sb/ca/certs`):
   ```powershell
   Get-ChildItem -Path "$env:USERPROFILE\.sb\ca\certs" | Where-Object { $_.Name -match '^\.sbm|__1|_wildcard_|foo_bar' } | Measure-Object
   ```
   *Output*:
   ```text
   Count    : 0
   ```
2. **On-Disk Leading Dot / Asterisk / Colon Search**:
   ```powershell
   Get-ChildItem -Path "$env:USERPROFILE\.sb\ca\certs" | Where-Object { $_.Name -match '^[._]|\*|:' } | Measure-Object
   ```
   *Output*:
   ```text
   Count    : 0
   ```
3. **Index Hygiene Check** (`~/.sb/ca/index.json`):
   ```powershell
   (Get-Content -Path "$env:USERPROFILE\.sb\ca\index.json" | ConvertFrom-Json).certs | Where-Object { $_.primary_domain -match '^\.sbm|__1|\*|foo:bar|::1' } | Measure-Object
   ```
   *Output*:
   ```text
   Count    : 0
   ```
   Total valid certs registered in index: 597.

### 1.3 Independent Build & Test Execution
1. **Cargo Workspace Check**:
   ```powershell
   cargo check --tests --workspace
   ```
   *Output*:
   ```text
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.01s
   ```
   Exit Code: 0 (0 errors, 0 warnings).

2. **Adversarial Eligibility Matrix Battery**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture
   ```
   *Output*:
   ```text
   === ADVERSARIAL MATRIX EXECUTION ===
   [Trailing dots] input='valid-trailing.sbm.' => eligible=true, resolved=true, minted=true, expected_eligible=true
   [Trailing dots] input='...' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Trailing dots] input='.' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Trailing dots / bare TLD] input='.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Trailing dots / bare TLD] input='.sbm.' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Wildcards] input='*.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Wildcards] input='*.*.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Wildcards] input='*' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Wildcards] input='foo.*.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Extreme length 254] input='aaa...aaa.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Path traversal] input='../../etc/passwd' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Path traversal] input='..\..\windows\system32' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Path traversal] input='../../../etc/shadow.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [IPv6 literal] input='[::1]' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [IPv6 literal] input='::1' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Colon / Port] input='domain.sbm:8080' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Colon / Port] input='foo:bar.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Colon / IPv6] input='::1.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Null byte] input='domain evil.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Non-ASCII] input='日本語.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Control chars] input='domain\r\n.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Public domain] input='google.com' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Public domain] input='evil.org.sbm.evil.com' => eligible=false, resolved=false, minted=false, expected_eligible=false
   === TOTAL MISMATCH FINDINGS: 0 ===
   test test_adversarial_sni_resolution_matrix ... ok
   test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.96s
   ```

3. **`sb-proxy` Full Test Suite**:
   ```powershell
   cargo test -p sb-proxy
   ```
   *Output*:
   - Unit tests (`src/lib.rs`): 42 passed, 0 failed.
   - Adversarial eligibility tests (`tests/adversarial_eligibility.rs`): 7 passed, 0 failed.
   - Integration tests (`tests/on_demand_tls_integration.rs`): 4 passed, 0 failed (including live TLS 1.3 loopback handshake).
   - Concurrency stress tests (`tests/sni_concurrency_stress.rs`): 5 passed, 0 failed (including 60-thread stampede, 64-thread contention with 32,000 lookups, 100 distinct domain resolution, precision latency benchmark, and mixed read/write workloads).
   Total: 58 passed; 0 failed; finished in 8.63s.

4. **Regression Verification Across Workspace**:
   - `cargo test -p sb-ca`: 15 passed, 0 failed (7 adversarial + 4 e2e ssh + 4 e2e x509).
   - `cargo test -p sb-cli`: 85 passed, 0 failed.

---

## 2. Logic Chain

1. **Authentication vs Mocks**:
   - The test suites do not rely on pre-fabricated certs or hardcoded domain responses; rather, they mint fresh ECDSA P-256 certificates with unique UUIDs (`uuid::Uuid::new_v4().simple()`), sign them via the Developer Root CA, parse them through `rustls_pemfile` and `ring`, and assert memory identity via `Arc::ptr_eq`.
   - The end-to-end integration test runs an actual `TcpListener` and `TcpStream` exchanging TLS 1.3 `PING`/`PONG` frames verified against Root CA trust anchors.
2. **Early Fail-Closed Protection (RFC 6066 §3 / RFC 1035 §2.3.4)**:
   - By validating FQDN length (<= 253), label length (1..=63), non-ASCII prohibition, wildcard rejection, colon/IPv6 literal exclusion, and control character blocking at the very start of `resolve_for_server_name`, any malformed SNI immediately exits with `self.fallback_cert.clone()` without incurring RAM lock acquisition, route scanning, or disk inspection.
3. **Hygiene Verification**:
   - Inspection of `~/.sb/ca/certs` and `~/.sb/ca/index.json` confirmed that the 8 spurious files and 4 invalid index entries previously identified have been completely eliminated. Test runs generate certificates in isolated temp dirs or under legitimate UUID-tagged `.sbm` domains without polluting the persistent CA registry with wildcard or malformed artifacts.
4. **Conclusion Derivation**:
   - All acceptance criteria specified in `DISPATCH.md` and `PROJECT.md` (M2) have been satisfied. No integrity violations, hardcoded test results, facade implementations, or bypasses exist.

---

## 3. Caveats

- **Scope**: Audit is focused strictly on Milestone 2 Iteration 2 (`sb-proxy` on-demand TLS integration, eligibility gates, and CA interactions). Milestone 3 (`sb node bootstrap`), Milestone 4 (`sb cockpit`), and Milestone 5 (`145.223.83.235` remote live deployment) are distinct milestones to be executed and audited in subsequent phases.
- No other caveats.

---

## 4. Conclusion

- **Verdict**: **CLEAN**
- All 5 audit dimensions (Source Code Analysis, Cryptographic Operations, RAM Caching, Disk/Index Hygiene, and Test Battery Execution) passed with 100% compliance.
- Milestone 2 is complete, verified, and ready for transition to Milestone 3 (`sb node bootstrap`).

---

## 5. Verification Method

To independently reproduce the audit findings:
1. `cargo check --tests --workspace`
2. `cargo test -p sb-proxy`
3. `cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture`
4. `Get-ChildItem -Path "$env:USERPROFILE\.sb\ca\certs" | Where-Object { $_.Name -match '^\.sbm|__1|_wildcard_|foo_bar' } | Measure-Object`
5. `(Get-Content -Path "$env:USERPROFILE\.sb\ca\index.json" | ConvertFrom-Json).certs | Where-Object { $_.primary_domain -match '^\.sbm|__1|\*|foo:bar|::1' } | Measure-Object`
