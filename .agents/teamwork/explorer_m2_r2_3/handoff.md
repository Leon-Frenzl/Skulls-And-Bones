# Test Suite Compatibility & Test Harness Investigation Report

**Milestone**: M2 Round 2 `sb-proxy` On-Demand TLS Integration  
**Component**: `tools/sb-proxy/tests/` & `tools/sb-proxy/src/proxy.rs` (`DynamicSniResolver`)  
**Investigator**: `explorer_m2_r2_3`  
**Verdict**: **COMPATIBLE / GO FOR IMPLEMENTATION**

---

## 1. Observation

### 1.1 Test Suite Inventory in `tools/sb-proxy`
Inspection of `tools/sb-proxy/` and execution of `cargo test -p sb-proxy` confirms a total of **58 passing tests**:
- **`src/lib.rs` (Unit tests)**: 42 tests passed.
  - Includes `proxy::tests::accepts_dns_names_and_rejects_ip_or_malformed_names` (lines 1610–1617) which already explicitly asserts `assert!(!is_acme_dns_name("*.example.com"));`.
  - Includes `proxy::tests::test_dynamic_sni_resolver_on_demand_and_ram_cache` (lines 1531–1556) using `unit-node-{uuid}.sbm`.
  - Includes `proxy::tests::test_dynamic_sni_resolver_ineligible_domains_rejected` (lines 1558–1571) asserting rejection of `evil-attacker.com`, `../../etc/shadow`, and `bad\node.sbm`.
  - Includes `proxy::tests::test_dynamic_sni_resolver_active_route_without_custom_cert` (lines 1573–1607) using `mesh-svc-{uuid}.local`.
- **`tests/on_demand_tls_integration.rs`**: 4 tests passed.
  - `test_on_demand_tls_resolution_and_in_memory_caching` (lines 31–68) using `on-demand-test-{uuid}.sbm`.
  - `test_ineligible_domains_do_not_trigger_on_demand_generation` (lines 70–92) asserting rejection of `arbitrary-attacker-{uuid}.com`, `../../etc/shadow`, `attack\0domain.sbm`, `..\\windows\\system32`.
  - `test_active_route_dynamic_tls_issuance` (lines 94–136) using `cluster-service-{uuid}.local` and `cluster-alias-{uuid}.local`.
  - `test_e2e_tls13_handshake_with_on_demand_sni_resolution` (lines 138–215) using `live-handshake-{uuid}.mesh`.
- **`tests/sni_concurrency_stress.rs`**: 5 tests passed.
  - `test_cache_stampede_single_domain_60_threads` (lines 25–133) using `stampede-resilience-{uuid}.sbm`.
  - `test_pointer_equality_under_heavy_contention` (lines 136–210) using `contention-pool-{i}-{uuid}.mesh`.
  - `test_concurrent_resolution_100_distinct_domains` (lines 213–283) using `domain-{i:03}-{uuid}.sbm`.
  - `test_latency_benchmarking_minting_vs_cache_hit` (lines 286–358) using `latency-bench-{uuid}.mesh`.
  - `test_mixed_reads_writes_and_stampede` (lines 361–467) using `established-{1,2,3}-{uuid}.{sbm,mesh,local}` and `stampede-target-{uuid}.sbm`.
- **`tests/adversarial_eligibility.rs`**: 7 tests passed (all pass as Rust tests, but `test_adversarial_sni_resolution_matrix` logs 9 mismatch diagnostics).
  - `test_adversarial_extreme_lengths` (lines 99–136)
  - `test_adversarial_ipv6_colons_null_and_non_ascii` (lines 182–240)
  - `test_adversarial_sni_resolution_matrix` (lines 288–356)
  - `test_adversarial_path_traversals` (lines 139–179)
  - `test_adversarial_ineligible_public_domains` (lines 242–285)
  - `test_adversarial_trailing_dots` (lines 26–64)
  - `test_adversarial_wildcards` (lines 67–96)

### 1.2 Current Adversarial Matrix Execution
Execution command:
```powershell
cargo test -p sb-proxy --test adversarial_eligibility test_adversarial_sni_resolution_matrix -- --nocapture
```
Verbatim execution output:
```text
=== ADVERSARIAL MATRIX EXECUTION ===
[Trailing dots] input='valid-trailing.sbm.' => eligible=true, resolved=true, minted=true, expected_eligible=true
[Trailing dots] input='...' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Trailing dots] input='.' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Trailing dots / bare TLD] input='.sbm' => eligible=true, resolved=true, minted=true, expected_eligible=false
[Trailing dots / bare TLD] input='.sbm.' => eligible=true, resolved=true, minted=true, expected_eligible=false
[Wildcards] input='*.sbm' => eligible=true, resolved=true, minted=true, expected_eligible=false
[Wildcards] input='*.*.sbm' => eligible=true, resolved=false, minted=false, expected_eligible=false
[Wildcards] input='*' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Wildcards] input='foo.*.sbm' => eligible=true, resolved=false, minted=false, expected_eligible=false
[Extreme length 254] input='aaaaaaaa...sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Path traversal] input='../../etc/passwd' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Path traversal] input='..\..\windows\system32' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Path traversal] input='../../../etc/shadow.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
[IPv6 literal] input='[::1]' => eligible=false, resolved=false, minted=false, expected_eligible=false
[IPv6 literal] input='::1' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Colon / Port] input='domain.sbm:8080' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Colon / Port] input='foo:bar.sbm' => eligible=true, resolved=true, minted=true, expected_eligible=false
[Colon / IPv6] input='::1.sbm' => eligible=true, resolved=true, minted=true, expected_eligible=false
[Null byte] input='domain evil.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Non-ASCII] input='日本語.sbm' => eligible=true, resolved=false, minted=false, expected_eligible=false
[Control chars] input='domain\r\n.sbm' => eligible=true, resolved=false, minted=false, expected_eligible=false
[Public domain] input='google.com' => eligible=false, resolved=false, minted=false, expected_eligible=false
[Public domain] input='evil.org.sbm.evil.com' => eligible=false, resolved=false, minted=false, expected_eligible=false
=== TOTAL MISMATCH FINDINGS: 9 ===
```

### 1.3 Pre-existing On-Disk Spurious Certificates
Investigation of `C:\Users\leonf\.sb\ca\certs` revealed that 4 spurious certificate and key pairs were minted during previous test runs before the eligibility gate fix was identified:
- `.sbm.crt` and `.sbm.key` (from bare TLD `.sbm`)
- `_wildcard_.sbm.crt` and `_wildcard_.sbm.key` (from wildcard SNI `*.sbm`)
- `__1.sbm.crt` and `__1.sbm.key` (from IPv6 colon `::1.sbm`)
- `foo_bar.sbm.crt` and `foo_bar.sbm.key` (from colon `foo:bar.sbm`)

In `tools/sb-proxy/src/proxy.rs` (lines 245–251):
```rust
        // Fast-Path 3: Check on-disk S&B CA certs
        if let Some(cert) = self.check_disk_certs(&name_clean) {
            if let Ok(mut cache) = self.cert_cache.write() {
                cache.insert(name_clean.clone(), cert.clone());
            }
            return Some(cert);
        }
```
Because Fast-Path 3 checks on-disk certificates via `DeveloperCa::find_dev_certificate(&name_clean)` *before* Fast-Path 4 (`is_eligible_for_on_demand`), calling `resolve_for_server_name("*.sbm")` when `_wildcard_.sbm.crt` exists on disk will resolve the certificate from disk unless either:
1. `resolve_for_server_name` rejects RFC 6066 §3 violations before disk inspection, and/or
2. Spurious artifacts in `~/.sb/ca/certs/` are removed.

---

## 2. Logic Chain

### 2.1 Verification of Matrix Mismatch Reduction: 9 -> 0
The proposed fix replaces lines 133–170 of `tools/sb-proxy/src/proxy.rs` with:
```rust
    pub fn is_eligible_for_on_demand(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        // RFC 1035: FQDN max 253 octets; cannot be empty
        if d.is_empty() || d.len() > 253 {
            return false;
        }

        // RFC 6066 §3: Hostname is not a wildcard, no path traversal, no colons/ports/IPv6 brackets,
        // no null bytes, no whitespace or control characters
        if d.contains('/')
            || d.contains('\\')
            || d.contains('\0')
            || d.contains("..")
            || d.contains('*')
            || d.contains(':')
            || d.contains('[')
            || d.contains(']')
            || d.chars().any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return false;
        }

        // Must not start with a dot (e.g. bare ".sbm" or ".mesh" without host label)
        if d.starts_with('.') {
            return false;
        }

        // Hostname labels must consist solely of valid ASCII alphanumeric, hyphen, underscore, and dots
        if !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
            return false;
        }

        // Sanctioned mesh / sovereign local domain suffixes and localhost/loopback
        if d.ends_with(".sbm")
            || d.ends_with(".mesh")
            || d.ends_with(".local")
            || d == "localhost"
            || d == "127.0.0.1"
        {
            return true;
        }

        // Active routes in EscapeSpaceStore
        if let Ok(store) = self.routes.read() {
            for space in &store.spaces {
                if space.status == EscapeStatus::Active {
                    let matches_primary = space.domain.eq_ignore_ascii_case(&d);
                    let matches_alias = space
                        .aliases
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(&d));
                    if (matches_primary || matches_alias) && space.custom_cert_path.is_none() {
                        return true;
                    }
                }
            }
        }

        false
    }
```

Evaluating all 23 test matrix cases against this logic:
1. `valid-trailing.sbm.`: `d` = `"valid-trailing.sbm"`. Length 18, ASCII valid, ends with `.sbm` -> `is_eligible = true` (matches `expected = true`).
2. `...`: `d` = `""`. `d.is_empty()` -> `false` (matches `expected = false`).
3. `.`: `d` = `""`. `d.is_empty()` -> `false` (matches `expected = false`).
4. `.sbm`: `d.starts_with('.')` -> `false` (matches `expected = false`). **FIXED: was true**.
5. `.sbm.`: `d.starts_with('.')` -> `false` (matches `expected = false`). **FIXED: was true**.
6. `*.sbm`: `d.contains('*')` -> `false` (matches `expected = false`). **FIXED: was true**.
7. `*.*.sbm`: `d.contains('*')` -> `false` (matches `expected = false`). **FIXED: was true**.
8. `*`: `d.contains('*')` -> `false` (matches `expected = false`).
9. `foo.*.sbm`: `d.contains('*')` -> `false` (matches `expected = false`). **FIXED: was true**.
10. Length 254: `d.len() > 253` -> `false` (matches `expected = false`).
11. `../../etc/passwd`: `d.contains('/') || d.contains("..")` -> `false` (matches `expected = false`).
12. `..\..\windows\system32`: `d.contains('\\') || d.contains("..")` -> `false` (matches `expected = false`).
13. `../../../etc/shadow.sbm`: `d.contains('/') || d.contains("..")` -> `false` (matches `expected = false`).
14. `[::1]`: `d.contains('[') || d.contains(':')` -> `false` (matches `expected = false`).
15. `::1`: `d.contains(':')` -> `false` (matches `expected = false`).
16. `domain.sbm:8080`: `d.contains(':')` -> `false` (matches `expected = false`).
17. `foo:bar.sbm`: `d.contains(':')` -> `false` (matches `expected = false`). **FIXED: was true**.
18. `::1.sbm`: `d.contains(':')` -> `false` (matches `expected = false`). **FIXED: was true**.
19. `domain\0evil.sbm`: `d.contains('\0')` -> `false` (matches `expected = false`).
20. `日本語.sbm`: Non-ASCII characters rejected by `!d.chars().all(...)` -> `false` (matches `expected = false`). **FIXED: was true**.
21. `domain\r\n.sbm`: `c.is_ascii_control()` -> `false` (matches `expected = false`). **FIXED: was true**.
22. `google.com`: Not sanctioned suffix, not in active routes -> `false` (matches `expected = false`).
23. `evil.org.sbm.evil.com`: Not sanctioned suffix -> `false` (matches `expected = false`).

**Conclusion on Matrix**: All 23 test inputs produce `actual == expected`. Mismatches drop from **9 to 0**.

### 2.2 Compatibility with Existing 46+ Tests (All 58 Tests)
- **Unit tests (42)**: No test queries `.sbm`, `*.sbm`, or invalid inputs expecting on-demand issuance. All tests using `DynamicSniResolver` use legitimate FQDNs (`unit-node-{uuid}.sbm`, `mesh-svc-{uuid}.local`) which only contain ASCII alphanumeric characters, hyphens, and standard sanctioned suffixes (`.sbm`, `.local`). These continue to pass without regression.
- **Integration tests (4)**: All tests in `tests/on_demand_tls_integration.rs` use valid UUID-based FQDNs (`on-demand-test-{uuid}.sbm`, `cluster-service-{uuid}.local`, `live-handshake-{uuid}.mesh`). Negative test cases (`../../etc/shadow`, `attack\0domain.sbm`) explicitly assert `None`. These continue to pass without regression.
- **Stress tests (5)**: All tests in `tests/sni_concurrency_stress.rs` use clean UUID-based FQDNs. These continue to pass without regression.

### 2.3 Evaluation of Wildcard SNI in Existing Tests
A comprehensive search across the workspace (`tools/`) confirmed:
1. **No test anywhere in the workspace relies on wildcard SNI resolution**:
   - TLS Server Name Indication (RFC 6066 §3) explicitly prohibits wildcards in the `HostName` extension.
   - `proxy::tests::accepts_dns_names_and_rejects_ip_or_malformed_names` already confirms `!is_acme_dns_name("*.example.com")`.
   - `EscapeSpaceStore` performs exact string matching (`eq_ignore_ascii_case`), not wildcard routing.
   - `sb-node` explicitly rejects wildcard routes (`route_config_rejects_permissive_or_wildcard_policy`).
2. **Wildcards in `sb-ca`**:
   - `sb-ca` supports wildcard certificates in Subject Alternative Names (SANs) conforming to RFC 5280 / RFC 6125 §6.4.3 (`*.sbm`, `*.mesh`).
   - Leaf certs issued for `app.sbm` automatically include `*.sbm` in their SANs so clients can validate subdomains.
   - This is purely an X.509 PKI certificate attribute. The incoming TLS client SNI is always the specific FQDN (e.g., `app.sbm`), never `*.sbm`.
3. **Tests in `adversarial_eligibility.rs` that touch wildcards**:
   - `test_adversarial_wildcards`: Currently prints diagnostics for `*.sbm` instead of asserting rejection because the previous gate allowed it.
   - `test_adversarial_sni_resolution_matrix`: Lists `("*.sbm", "Wildcards", false)` and logged a mismatch because the previous gate returned `true`.

---

## 3. Caveats

1. **Pre-existing Disk Artifacts**: The spurious files `.sbm.crt`, `_wildcard_.sbm.crt`, `__1.sbm.crt`, and `foo_bar.sbm.crt` present in `C:\Users\leonf\.sb\ca\certs\` will cause `check_disk_certs` to return `Some(cert)` if `resolve_for_server_name` is called directly with those strings, unless:
   - Those 4 spurious files are deleted from `C:\Users\leonf\.sb\ca\certs\`, AND/OR
   - `resolve_for_server_name` performs RFC 6066 §3 input validation at its entry point before checking on-disk certs.
2. **Adversarial Test Assertions**: In `tools/sb-proxy/tests/adversarial_eligibility.rs`, `test_adversarial_sni_resolution_matrix` currently only prints mismatches without an `assert_eq!(findings.len(), 0)`. To prevent future regressions, an explicit assertion must be added.

---

## 4. Conclusion & Required Next Steps

### Actionable Plan for `worker_m2_proxy`

1. **Apply Eligibility Gate Hardening in `tools/sb-proxy/src/proxy.rs`**:
   Replace `is_eligible_for_on_demand` with the hardened RFC 6066 / RFC 1035 implementation.
2. **Harden `resolve_for_server_name` Entry Point in `tools/sb-proxy/src/proxy.rs`**:
   Add an RFC 6066 §3 check at the start of `resolve_for_server_name` so that invalid SNI syntax (wildcards `*`, control characters, colons `:`, path separators) returns `self.fallback_cert.clone()` immediately without querying on-disk or route caches:
   ```rust
   if name_clean.is_empty()
       || name_clean.len() > 253
       || name_clean.contains('*')
       || name_clean.contains(':')
       || name_clean.contains('/')
       || name_clean.contains('\\')
       || name_clean.contains('\0')
       || name_clean.starts_with('.')
   {
       return self.fallback_cert.clone();
   }
   ```
3. **Purge Spurious Test Artifacts**:
   Delete `.sbm.crt`, `.sbm.key`, `_wildcard_.sbm.crt`, `_wildcard_.sbm.key`, `__1.sbm.crt`, `__1.sbm.key`, `foo_bar.sbm.crt`, `foo_bar.sbm.key` from `C:\Users\leonf\.sb\ca\certs\`.
4. **Adapt `tools/sb-proxy/tests/adversarial_eligibility.rs`**:
   - In `test_adversarial_wildcards`: Add assertions for `*.sbm`:
     ```rust
     assert!(!resolver.is_eligible_for_on_demand(wildcard_sbm));
     assert!(wildcard_res.is_none());
     ```
   - In `test_adversarial_trailing_dots`: Add assertions for `.sbm` and `.sbm.`:
     ```rust
     assert!(!resolver.is_eligible_for_on_demand(".sbm"));
     assert!(dot_sbm_res.is_none());
     ```
   - In `test_adversarial_sni_resolution_matrix`: Add the zero-mismatch assertion at the end of the test:
     ```rust
     assert_eq!(findings.len(), 0, "Expected 0 adversarial matrix mismatches, found {}", findings.len());
     ```

---

## 5. Verification Method

Once changes are applied by `worker_m2_proxy`, independently verify via:

1. **Adversarial SNI Resolution Matrix**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility test_adversarial_sni_resolution_matrix -- --nocapture
   ```
   *Expected Output*: `=== TOTAL MISMATCH FINDINGS: 0 ===` and test exits 0.

2. **Full Adversarial Battery**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture
   ```
   *Expected Output*: All 7 tests pass with 0 warnings.

3. **Full `sb-proxy` Test Suite**:
   ```powershell
   cargo test -p sb-proxy
   ```
   *Expected Output*: All 58 tests pass (`42 in lib.rs`, `4 in on_demand_tls_integration.rs`, `5 in sni_concurrency_stress.rs`, `7 in adversarial_eligibility.rs`).

4. **Disk Hygiene Verification**:
   ```powershell
   Get-ChildItem -Path C:\Users\leonf\.sb\ca\certs\ | Where-Object { $_.Name -like "*wildcard*" -or $_.Name -like ".sbm*" -or $_.Name -like "__1*" -or $_.Name -like "foo_bar*" }
   ```
   *Expected Output*: 0 files returned.
