# Handoff Report: RFC 6066 §3 / RFC 1035 SNI Eligibility Hardening & Remediation

**Milestone**: M2 `sb-proxy` On-Demand TLS Integration  
**Component**: `tools/sb-proxy/src/proxy.rs`, `tools/sb-proxy/tests/adversarial_eligibility.rs`, `~/.sb/ca/certs/`, `~/.sb/ca/index.json`  
**Agent**: `worker_m2_remediation`  
**Date**: 2026-10-27T21:56:55Z  
**Verdict**: **REMEDIATION_COMPLETE_AND_VERIFIED**

---

## 1. Observation

### 1.1 Initial State & Defects
1. **Adversarial Matrix Mismatches**:
   Running `cargo test -p sb-proxy --test adversarial_eligibility test_adversarial_sni_resolution_matrix -- --nocapture` originally produced:
   ```text
   === TOTAL MISMATCH FINDINGS: 9 ===
   FAIL: [Trailing dots / bare TLD] '.sbm' actual_eligible=true (resolved=true, minted=true) vs expected_eligible=false
   FAIL: [Trailing dots / bare TLD] '.sbm.' actual_eligible=true (resolved=true, minted=true) vs expected_eligible=false
   FAIL: [Wildcards] '*.sbm' actual_eligible=true (resolved=true, minted=true) vs expected_eligible=false
   FAIL: [Wildcards] '*.*.sbm' actual_eligible=true (resolved=false, minted=false) vs expected_eligible=false
   FAIL: [Wildcards] 'foo.*.sbm' actual_eligible=true (resolved=false, minted=false) vs expected_eligible=false
   FAIL: [Colon / Port] 'foo:bar.sbm' actual_eligible=true (resolved=true, minted=true) vs expected_eligible=false
   FAIL: [Colon / IPv6] '::1.sbm' actual_eligible=true (resolved=true, minted=true) vs expected_eligible=false
   FAIL: [Non-ASCII] '日本語.sbm' actual_eligible=true (resolved=false, minted=false) vs expected_eligible=false
   FAIL: [Control chars] 'domain\r\n.sbm' actual_eligible=true (resolved=false, minted=false) vs expected_eligible=false
   ```
2. **Spurious On-Disk Files & Index Entries**:
   Prior to remediation, inspection of `C:\Users\leonf\.sb\ca\certs` confirmed 8 spurious files generated during earlier testing:
   - `.sbm.crt` & `.sbm.key`
   - `_wildcard_.sbm.crt` & `_wildcard_.sbm.key`
   - `__1.sbm.crt` & `__1.sbm.key`
   - `foo_bar.sbm.crt` & `foo_bar.sbm.key`
   And `C:\Users\leonf\.sb\ca\index.json` contained 4 matching registry entries (`.sbm`, `*.sbm`, `::1.sbm`, `foo:bar.sbm`).
3. **Missing Pre-filtering in Resolution**:
   In `tools/sb-proxy/src/proxy.rs`, `resolve_for_server_name` checked on-disk certs (Fast-Path 3) and RAM cache (Fast-Path 1) before the eligibility gate (Fast-Path 4), allowing malformed SNIs to trigger disk reads, JSON deserialization, and lock acquisition.

---

## 2. Logic Chain

### 2.1 Root Cause Reasoning
1. **Permissive Suffix Check**:
   The original `is_eligible_for_on_demand` relied on negative blacklist patterns (`d.contains('/')`, `'\\'`, `'\0'`, `".."`) followed by `d.ends_with(".sbm")`. Strings such as `*.sbm`, `.sbm`, `foo:bar.sbm`, `日本語.sbm`, and `domain\r\n.sbm` ended with `.sbm` and did not contain directory separators, thereby bypassing the check.
2. **Standards Violation (RFC 6066 §3 & RFC 1035 §2.3.4)**:
   - RFC 6066 §3 mandates that TLS SNI `HostName` is strictly ASCII DNS hostname without trailing dot, forbids IP literals (IPv6 colons/brackets), and explicitly states *"A 'HostName' is not a wildcard."*
   - RFC 1035 §2.3.4 / RFC 1123 §2.1 require FQDN representation length <= 253 octets and individual dot-delimited label lengths of 1..=63 octets containing only alphanumeric, hyphen, or underscore characters.
3. **Downstream Side Effects**:
   Because `sb_ca::x509::get_or_issue_on_demand` permitted wildcards (`*.sbm`) and colons (`::1.sbm`), the permissive gate allowed on-demand generation to mint permanent wildcard and bare-TLD certificates onto disk.
4. **Resolution Ordering**:
   By adding early fail-closed SNI pre-filtering at the very entry point of `resolve_for_server_name`, any malformed SNI is immediately routed to fallback without incurring cache lookup, route scan, or filesystem I/O.

### 2.2 Applied Modifications
1. **`tools/sb-proxy/src/proxy.rs` — `is_eligible_for_on_demand`**:
   - Replaced naive checks with 4-tier structural validation:
     - Tier 1: FQDN presentation length check (`!d.is_empty() && d.len() <= 253`).
     - Tier 2: RFC 6066 §3 character blocklist (`*`, `:`, `[`, `]`, `/`, `\`, `\0`, `..`, whitespace, control chars).
     - Tier 3: RFC 1035 label syntax (`!d.starts_with('.')`, all characters in `[a-z0-9_.-]`, each dot-delimited label `1..=63` octets).
     - Tier 4: Sanctioned suffix / route matching (`.sbm`, `.mesh`, `.local`, `localhost`, `127.0.0.1`, active `EscapeSpaceStore` routes).
   - Added complete dynamic security threat modeling documentation header and formal standards citations (RFC 6066 §3, RFC 1035 §2.3.1/§2.3.4, RFC 1123 §2.1, RFC 8446, RFC 5280).
2. **`tools/sb-proxy/src/proxy.rs` — `resolve_for_server_name`**:
   - Added early fail-closed RFC 6066 §3 / RFC 1035 pre-filtering at the very top of `resolve_for_server_name` before Fast-Path 1, 2, 3, or 4.
   - Added dynamic threat audit header documenting mitigation of CA stampede, CWE-400, CWE-295, and CWE-22.
3. **Disk Hygiene**:
   - Deleted the 8 spurious files from `C:\Users\leonf\.sb\ca\certs\`.
   - Filtered out the 4 spurious records from `C:\Users\leonf\.sb\ca\index.json` (1347 -> 1343 entries).
4. **`tools/sb-proxy/tests/adversarial_eligibility.rs`**:
   - Upgraded `test_adversarial_trailing_dots` with strict assertions for `.sbm` and `.sbm.`.
   - Upgraded `test_adversarial_wildcards` with strict assertions for `*.*.sbm`, `foo.*.sbm`, and `*.sbm`.
   - Upgraded `test_adversarial_ipv6_colons_null_and_non_ascii` with strict assertions for all IPv6, colon, null byte, and non-ASCII inputs.
   - Upgraded `test_adversarial_sni_resolution_matrix` with `assert_eq!(findings.len(), 0, "Expected 0 adversarial matrix mismatches, found {}", findings.len());`.

---

## 3. Caveats

- **Pragmatic Loopback Exception**: RFC 6066 §3 prohibits literal IP addresses in SNI. However, `DynamicSniResolver` intentionally supports `localhost` and `127.0.0.1` to facilitate local unit testing and development proxies.
- **Underscore Support**: Standard internet DNS hostnames strictly forbid underscores (RFC 952/1123). In Skulls & Bones, underscores (`_`) are explicitly permitted within labels to support internal sovereign mesh service naming conventions (e.g., `service_node.sbm`).
- **Punycode / IDNA**: Non-ASCII Unicode characters (such as `日本語.sbm`) are rejected in accordance with RFC 6066 §3 ASCII encoding rules. Any internationalized domain names must arrive in ASCII Punycode form (`xn--...`).
- No other caveats.

---

## 4. Conclusion

1. The eligibility gate and SNI resolution pipeline are fully remediated, standards-compliant, and hardened against CWE-400, CWE-295, CWE-22, and CWE-20.
2. Spurious disk certificates and index entries have been completely eradicated from the system.
3. All 7 adversarial tests pass cleanly with zero warnings, and the 23-case adversarial test matrix reports **0 mismatches**.
4. Full workspace test hygiene is verified across `sb-proxy` (58/58), `sb-ca` (15/15), and `sb-cli` (85/85) with clean compiler status (0 errors, 0 warnings).

---

## 5. Verification Method

To independently reproduce and verify the remediation:

1. **Verify Workspace Compilation**:
   ```powershell
   cargo check --workspace
   ```
   *Result*: 0 errors, 0 warnings. Finished in 0.66s.

2. **Verify Adversarial Matrix & Battery (Zero Mismatches)**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture
   ```
   *Result*:
   ```text
   === ADVERSARIAL MATRIX EXECUTION ===
   ...
   === TOTAL MISMATCH FINDINGS: 0 ===
   test test_adversarial_sni_resolution_matrix ... ok
   test test_adversarial_trailing_dots ... ok
   test test_adversarial_wildcards ... ok
   test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.26s
   ```

3. **Verify All `sb-proxy` Tests**:
   ```powershell
   cargo test -p sb-proxy
   ```
   *Result*: 58 passed, 0 failed (42 unit + 7 adversarial + 4 integration + 5 stress).

4. **Verify `sb-ca` Tests**:
   ```powershell
   cargo test -p sb-ca
   ```
   *Result*: 15 passed, 0 failed (7 adversarial + 4 ssh e2e + 4 x509 e2e).

5. **Verify `sb-cli` Tests**:
   ```powershell
   cargo test -p sb-cli
   ```
   *Result*: 85 passed, 0 failed.

6. **Verify Disk & Index Hygiene**:
   ```powershell
   Get-ChildItem -Path C:\Users\leonf\.sb\ca\certs | Where-Object { $_.Name -match '^\.sbm|__1|_wildcard_|foo_bar' } | Measure-Object
   (Get-Content -Path C:\Users\leonf\.sb\ca\index.json | ConvertFrom-Json).certs | Where-Object { $_.primary_domain -match '^\.sbm|__1|\*|foo:bar|::1' } | Measure-Object
   ```
   *Result*: Count = 0 for both commands.
