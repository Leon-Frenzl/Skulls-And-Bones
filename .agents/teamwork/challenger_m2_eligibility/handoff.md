# Adversarial Challenge & Verification Report: Domain Eligibility Gate & SNI Parsing

**Milestone**: M2 `sb-proxy` On-Demand TLS Integration  
**Component**: `tools/sb-proxy/src/proxy.rs` (`DynamicSniResolver::is_eligible_for_on_demand` and `resolve_for_server_name`)  
**Verdict**: **REQUEST_CHANGES**

---

## 1. Observation

### Code Inspection
In `tools/sb-proxy/src/proxy.rs` (lines 133–170):
```rust
    pub fn is_eligible_for_on_demand(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() || d.len() > 253 {
            return false;
        }
        // Reject path traversals, null characters, and backslashes
        if d.contains('/') || d.contains('\\') || d.contains('\0') || d.contains("..") {
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
        ...
```

### Empirical Test Execution
A dedicated adversarial test harness was authored and co-located at `tools/sb-proxy/tests/adversarial_eligibility.rs`.
Executed via:
```powershell
cargo test -p sb-proxy --test adversarial_eligibility test_adversarial_sni_resolution_matrix -- --nocapture
```

Verbatim execution log:
```text
=== ADVERSARIAL MATRIX EXECUTION ===
processed file: C:\Users\leonf\.sb\ca\certs\valid-trailing.sbm.key
Successfully processed 1 files; Failed processing 0 files
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

---

## 2. Logic Chain

1. **RFC 6066 §3 Conformance**: RFC 6066 §3 defines the TLS Server Name Indication (SNI) extension and explicitly dictates:
   - *"A 'HostName' is not a wildcard."*
   - *"Literal IPv4 and IPv6 addresses are not permitted."*
   - *"The hostname is represented as a byte string using ASCII encoding without a trailing dot."*
2. **RFC 1035 / RFC 1123 Hostname Syntax**: Fully qualified domain names consist of dot-delimited labels of 1–63 octets containing exclusively ASCII letters, digits, and hyphens. A domain cannot begin with a dot (an empty label before a TLD). Colons (`:`), spaces (` `), and control characters (`\r`, `\n`) are strictly invalid.
3. **Observation of False-Positive Minting**:
   - SNI `*.sbm`: `is_eligible_for_on_demand` returns `true`. `resolve_for_server_name` invokes `sb_ca` and actively mints `_wildcard_.sbm.crt` and `_wildcard_.sbm.key` onto disk. This violates RFC 6066 §3 (wildcards in SNI).
   - SNI `.sbm` and `.sbm.`: `is_eligible_for_on_demand` returns `true`. `resolve_for_server_name` actively mints `.sbm.crt` and `.sbm.key` (creating a hidden dotfile on Linux and a bare TLD cert).
   - SNI `::1.sbm` and `foo:bar.sbm`: `is_eligible_for_on_demand` returns `true` because the string ends with `.sbm`. It mints `__1.sbm.crt` and `foo_bar.sbm.crt` on disk despite containing illegal colons.
4. **Observation of Gate Bypasses (CWE-400 Pre-filtering Failure)**:
   - Inputs `*.*.sbm`, `foo.*.sbm`, `日本語.sbm`, `domain\r\n.sbm`, and `domain .sbm` all returned `is_eligible_for_on_demand == true`.
   - The purpose of `is_eligible_for_on_demand` is to act as an edge gate to prevent invoking downstream CA locking, memory allocation, and disk operations for malformed inputs.
   - Because `is_eligible_for_on_demand` only checks `d.ends_with(".sbm")`, it fails to filter these invalid inputs at the gate, relying instead on downstream `sb_ca::x509::get_or_issue_on_demand` to reject them.
5. **Acceptance Criteria Requirement**: The objective requires:
   *"Empirically verify that ineligible inputs are rejected cleanly without crashing or minting certificates."*
   Because `*.sbm`, `.sbm`, `::1.sbm`, and `foo:bar.sbm` actively minted certificates, the system failed this criterion.

---

## 3. Caveats

- No crashes or panics were observed during any test run. The proxy and CA engine remained resilient against unhandled unwraps and memory corruption across all boundary inputs.
- Path traversal rejection (`/`, `\`, `..`, null bytes) and length bounds (`> 253` characters) are implemented correctly and passed 100% of traversal tests without disk side effects.
- Ineligible public domains (`google.com`, `evil.org.sbm.evil.com`, etc.) are correctly rejected.
- Valid FQDN trailing dot notation (`valid-trailing.sbm.`) correctly trims the trailing dot and mints/caches the certificate.

---

## 4. Conclusion & Required Changes

**Verdict**: **REQUEST_CHANGES**

The eligibility gate in `tools/sb-proxy/src/proxy.rs` must be tightened to enforce RFC 6066 §3 and RFC 1035/1123 hostname rules before approving on-demand certificate generation.

### Concrete Remediation for `worker_m2_proxy`

In `tools/sb-proxy/src/proxy.rs`, update `is_eligible_for_on_demand`:

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

---

## 5. Verification Method

To verify the fixes once implemented:

1. **Run the Adversarial Eligibility Suite**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture
   ```
   *Expected Result*: All 7 adversarial tests pass, and in `test_adversarial_sni_resolution_matrix`, `TOTAL MISMATCH FINDINGS` must be `0`.

2. **Verify Zero Spurious On-Disk Certs**:
   Inspect `~/.sb/ca/certs/` to confirm no files named `.sbm.crt`, `_wildcard_.sbm.crt`, `__1.sbm.crt`, or `foo_bar.sbm.crt` are created.

3. **Run Full Workspace Tests**:
   ```powershell
   cargo test --workspace
   ```
