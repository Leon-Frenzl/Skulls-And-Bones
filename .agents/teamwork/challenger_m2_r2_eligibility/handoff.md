# Adversarial Re-Test Report: M2 R2 Domain Eligibility Gate & SNI Resolution

**Agent**: `challenger_m2_r2_eligibility`  
**Working Directory**: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m2_r2_eligibility`  
**Milestone**: M2 `sb-proxy` On-Demand TLS Integration  
**Date**: 2026-10-27T22:01:45Z  
**Verdict**: **APPROVE**

---

## 1. Observation

### 1.1 Empirical Test Execution & Results
1. Executed `cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture`:
   - Command exited with code `0` in `0.66s`.
   - All 7 test cases passed cleanly:
     - `test_adversarial_extreme_lengths`: ok
     - `test_adversarial_ipv6_colons_null_and_non_ascii`: ok
     - `test_adversarial_ineligible_public_domains`: ok
     - `test_adversarial_path_traversals`: ok
     - `test_adversarial_sni_resolution_matrix`: ok
     - `test_adversarial_trailing_dots`: ok
     - `test_adversarial_wildcards`: ok
2. Verbatim output from `test_adversarial_sni_resolution_matrix`:
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
   [Extreme length 254] input='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Path traversal] input='../../etc/passwd' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Path traversal] input='..\..\windows\system32' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Path traversal] input='../../../etc/shadow.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [IPv6 literal] input='[::1]' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [IPv6 literal] input='::1' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Colon / Port] input='domain.sbm:8080' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Colon / Port] input='foo:bar.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Colon / IPv6] input='::1.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Null byte] input='domain\0evil.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Non-ASCII] input='日本語.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Control chars] input='domain\r\n.sbm' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Public domain] input='google.com' => eligible=false, resolved=false, minted=false, expected_eligible=false
   [Public domain] input='evil.org.sbm.evil.com' => eligible=false, resolved=false, minted=false, expected_eligible=false
   === TOTAL MISMATCH FINDINGS: 0 ===
   ```

### 1.2 Disk & CA Index Hygiene Verification
1. Audited `C:\Users\leonf\.sb\ca\certs\` for spurious certificate files:
   - Evaluated regex: `^\.|\*|__1|foo_bar|:|/|\\|\s|_wildcard_` across all 4,312 certificate files on disk.
   - Count of offending files: **0**.
   - Verified that prior spurious files (`.sbm.crt`, `.sbm.key`, `_wildcard_.sbm.crt`, `_wildcard_.sbm.key`, `__1.sbm.crt`, `__1.sbm.key`, `foo_bar.sbm.crt`, `foo_bar.sbm.key`) remain completely absent.
2. Audited `C:\Users\leonf\.sb\ca\index.json`:
   - Evaluated regex: `^\.sbm|__1|\*|foo:bar|::1` across all registered entries.
   - Count of offending index entries: **0**.

### 1.3 Suite & Workspace Health
1. `cargo test -p sb-proxy`: 58 passed, 0 failed (unit, adversarial, integration, concurrency stress).
2. `cargo test -p sb-ca`: 15 passed, 0 failed (adversarial, e2e ssh ca, e2e x509 ca).
3. `cargo check --workspace`: 0 errors, 0 warnings (finished in 0.67s).

---

## 2. Logic Chain

1. **Gate Architecture in `tools/sb-proxy/src/proxy.rs`**:
   - `is_eligible_for_on_demand` (lines 154–220) enforces 4 rigorous validation tiers:
     - *Tier 1 (RFC 1035 §2.3.4)*: presentation length `1..=253` octets.
     - *Tier 2 (RFC 6066 §3)*: rejects `*`, `:`, `[`, `]`, `/`, `\`, `\0`, `..`, whitespace, and control chars.
     - *Tier 3 (RFC 1035 §2.3.1 / RFC 1123 §2.1)*: rejects leading dots, validates ASCII alphanumeric + `-` + `_`, validates each label is `1..=63` octets.
     - *Tier 4 (Sovereign scope)*: ensures domain ends with `.sbm`, `.mesh`, `.local`, or matches `localhost`, `127.0.0.1`, or active uncertified routes in `EscapeSpaceStore`.
   - `resolve_for_server_name` (lines 280–305) introduces an early fail-closed pre-validation filter prior to RAM cache read, custom route lookup, or filesystem inspection.
2. **Elimination of CA Stampede & Resource Contention**:
   - Because structurally invalid or adversarial inputs are rejected before Fast-Paths 1, 2, 3, or 4, they never acquire read/write locks on `cert_cache`, never access disk paths via `DeveloperCa::find_dev_certificate`, and never invoke `sb_ca::x509::get_or_issue_on_demand`.
3. **Prevention of Spurious Disk Generation**:
   - Any malicious SNI (e.g. `*.sbm`, `::1.sbm`, `foo:bar.sbm`) is prevented from reaching `sb-ca` leaf certificate generation. Consequently, no spurious `.sbm.crt` or wildcard cert files can be written to `~/.sb/ca/certs/`.
4. **Empirical Correlation**:
   - The adversarial test battery explicitly tests all 23 scenarios. Every single invalid scenario resulted in `is_eligible=false`, `resolved=false`, and `minted=false`, directly matching `expected_eligible=false`.
   - Total mismatch findings reached exactly 0.

---

## 3. Caveats

- **Permitted Underscores**: While RFC 952/1123 restricts standard internet hostnames to hyphen and alphanumeric characters, Skulls & Bones sovereign mesh domain syntax intentionally permits underscores (`_`) within labels (e.g., `service_worker.sbm`).
- **Loopback Dev Exemption**: While RFC 6066 §3 forbids literal IP addresses in SNI, `localhost` and `127.0.0.1` are intentionally whitelisted to permit local loopback proxy testing.
- **Punycode Requirement**: Non-ASCII Unicode (such as `日本語.sbm`) is strictly rejected at the SNI level in compliance with RFC 6066 §3. Internationalized domain names must arrive pre-encoded as ASCII Punycode (`xn--...`).
- No other caveats.

---

## 4. Conclusion

The domain eligibility gate and SNI resolution pipeline in `sb-proxy` are robust, standards-compliant, and hardened against CWE-400 (Resource Exhaustion / CA Stampede), CWE-295 (Improper Certificate Validation), CWE-22 (Path Traversal), and CWE-20 (Improper Input Validation).

Empirical verification confirms:
- `test_adversarial_sni_resolution_matrix` achieves **TOTAL MISMATCH FINDINGS: 0**.
- Zero spurious certificate files or index entries exist in `~/.sb/ca/certs/` or `~/.sb/ca/index.json`.
- The full workspace compile and test suite remain 100% green.

Verdict: **APPROVE**.

---

## 5. Verification Method

To independently verify this verdict:

1. **Run Adversarial Eligibility Test**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture
   ```
   *Expected*: 7 passed; 0 failed; outputs `=== TOTAL MISMATCH FINDINGS: 0 ===`.

2. **Verify Disk Certificate File Hygiene**:
   ```powershell
   Get-ChildItem -Path "C:\Users\leonf\.sb\ca\certs" | Where-Object { 
       $base = $_.Name -replace '\.(crt|key|pem)$', ''
       $base -match '^\.|\*|__1|foo_bar|:|/|\\|\s|_wildcard_'
   } | Measure-Object
   ```
   *Expected*: `Count: 0`.

3. **Verify CA Index Hygiene**:
   ```powershell
   (Get-Content -Path "C:\Users\leonf\.sb\ca\index.json" | ConvertFrom-Json).certs | Where-Object { 
       $_.primary_domain -match '^\.sbm|__1|\*|foo:bar|::1' 
   } | Measure-Object
   ```
   *Expected*: `Count: 0`.

4. **Verify Full `sb-proxy` and `sb-ca` Suites**:
   ```powershell
   cargo test -p sb-proxy
   cargo test -p sb-ca
   cargo check --workspace
   ```
   *Expected*: All tests pass with exit code 0 and 0 compiler warnings.
