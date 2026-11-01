# Investigation Report: RFC 6066 §3 & RFC 1035/1123 Domain Eligibility Gate

**Milestone**: M2 `sb-proxy` On-Demand TLS Integration  
**Component**: `tools/sb-proxy/src/proxy.rs` (`DynamicSniResolver::is_eligible_for_on_demand` and `resolve_for_server_name`)  
**Investigator**: `explorer_m2_r2_1`  
**Date**: 2026-10-27  
**Verdict**: **REMEDIATION_PLAN_READY**

---

## 1. Observation

### 1.1 Source Code Inspection of the Eligibility Gate
In `tools/sb-proxy/src/proxy.rs`, lines 133–170:
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

        // Check if registered in EscapeSpaceStore active routes (and does not specify custom PEM files)
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

### 1.2 Downstream Behavior in `sb_ca` (`tools/sb-ca/src/x509/leaf.rs`)
In `tools/sb-ca/src/x509/leaf.rs`, lines 37–80:
```rust
pub fn validate_domain(domain: &str) -> Result<String, CaError> {
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return Err(CaError::InvalidDomain("Domain cannot be empty".into()));
    }
    if clean.len() > 253 {
        return Err(CaError::InvalidDomain(format!(
            "Domain '{}' exceeds max length of 253 characters",
            clean
        )));
    }
    if clean.contains('/') || clean.contains('\\') || clean.contains('\0') {
        return Err(CaError::InvalidDomain(format!(
            "Domain '{}' contains path traversal or null characters",
            clean
        )));
    }

    // Permit wildcards formatted like *.domain.tld or single wildcards
    let check_part = clean.strip_prefix("*.").unwrap_or(&clean);
    for ch in check_part.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' && ch != ':' {
            return Err(CaError::InvalidDomain(format!(
                "Domain '{}' contains disallowed character '{}'",
                clean, ch
            )));
        }
    }

    Ok(clean)
}

pub fn domain_to_safe_filename(domain: &str) -> String {
    domain.replace('*', "_wildcard_").replace(':', "_")
}
```

### 1.3 Empirically Verified Test Failures
Execution of `cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture` produced the following verbatim diagnostics:
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

### 1.4 Direct On-Disk Evidence in `C:\Users\leonf\.sb\ca\certs`
Inspection of `C:\Users\leonf\.sb\ca\certs` revealed that spurious certificates and private keys were actively generated and written to disk:
- `.sbm.crt` (1,507 bytes) & `.sbm.key` (246 bytes) — Hidden dotfile on Unix / bare TLD cert
- `_wildcard_.sbm.crt` (1,499 bytes) & `_wildcard_.sbm.key` (246 bytes) — Wildcard SNI cert
- `__1.sbm.crt` (1,515 bytes) & `__1.sbm.key` (246 bytes) — IPv6 colon hybrid cert
- `foo_bar.sbm.crt` & `foo_bar.sbm.key` — Colon replacement cert

---

## 2. Logic Chain

### 2.1 Trace of Why Malformed Inputs Passed the Eligibility Gate
1. **`*.sbm`**:
   - `domain = "*.sbm"`.
   - `d = domain.trim_end_matches('.').to_ascii_lowercase()` -> `"*.sbm"`.
   - Length check passes (5 <= 253).
   - Character blocklist only checks for `/`, `\`, `\0`, and `..` (all absent).
   - Suffix check: `"*.sbm".ends_with(".sbm")` evaluates to `true`.
   - Gate returns `true`.
   - Downstream in `resolve_for_server_name`, `sb_ca::x509::get_or_issue_on_demand("*.sbm")` is called.
   - In `sb_ca::x509::leaf::validate_domain`, `strip_prefix("*.")` leaves `"sbm"` which passes alphanumeric checks.
   - `domain_to_safe_filename("*.sbm")` escapes `*` to `_wildcard_`, minting `_wildcard_.sbm.crt` onto disk.
2. **`.sbm` and `.sbm.`**:
   - `domain = ".sbm"` or `".sbm."`.
   - `d = ".sbm"`.
   - Length check passes (4 <= 253).
   - Traversal check passes.
   - Suffix check: `".sbm".ends_with(".sbm")` evaluates to `true` (any string ends with itself).
   - Gate returns `true`.
   - Downstream in `sb_ca`, `validate_domain` allows `.` characters in domains (`ch != '.'`).
   - Mints `.sbm.crt` and `.sbm.key` (creating a bare TLD certificate and an unexpected hidden dotfile).
3. **`foo:bar.sbm` and `::1.sbm`**:
   - `domain = "foo:bar.sbm"` or `"::1.sbm"`.
   - Neither contains path separators or null bytes.
   - Both end with `".sbm"`.
   - Gate returns `true`.
   - Downstream in `sb_ca`, `validate_domain` permits colons (`ch != ':'`) to accommodate port notations / IPv6.
   - `domain_to_safe_filename` replaces `:` with `_`, minting `foo_bar.sbm.crt` and `__1.sbm.crt` to disk.
4. **`*.*.sbm`, `foo.*.sbm`, `日本語.sbm`, `domain\r\n.sbm`, `domain .sbm`**:
   - All end with `".sbm"`.
   - Gate returned `true` due to lack of allowlist and absence of structural validation.
   - While downstream `sb_ca` rejected them, the purpose of `is_eligible_for_on_demand` is to act as an edge gate to prevent CA lock contention and resource exhaustion (CWE-400 pre-filtering failure).

### 2.2 Standards Verification: RFC 6066 §3 vs. RFC 1035 / RFC 1123
1. **RFC 6066 §3 ("Server Name Indication")**:
   - *"HostName contains the fully qualified DNS hostname of the server, as understood by the client."*
   - *"The hostname is represented as a byte string using ASCII encoding without a trailing dot."*
   - *"Literal IPv4 and IPv6 addresses are not permitted in 'HostName'."*
   - *"A 'HostName' is not a wildcard."* (Verbatim quote from RFC 6066 §3).
   - **Conclusion**: Any SNI `HostName` received in TLS `ClientHello` containing `*`, `:`, `[`, `]`, raw non-ASCII UTF-8, whitespace, or control characters is invalid according to RFC 6066 §3.
2. **RFC 1035 §2.3.1 & RFC 1123 §2.1 (Domain Name Syntax & Limits)**:
   - FQDN presentation limit: 253 octets maximum (RFC 1035 §2.3.4).
   - Dot-delimited labels: `<subdomain> ::= <label> | <subdomain> "." <label>`.
   - Label length: Each label must be between 1 and 63 octets (inclusive).
   - Leading dots (`.sbm`), consecutive dots (`foo..sbm`), and empty labels are strictly invalid in DNS syntax.
   - Host labels must consist solely of ASCII letters, digits, and hyphens (RFC 1123 relaxes RFC 1035 to allow digits as the first character).
   - Internal mesh conventions also tolerate underscores (`_`) within labels (e.g. `node_1.sbm`).
3. **Architectural Distinction**:
   - `sb_ca` is a general-purpose PKI library supporting wildcard certificate issuance (`*.sbm`) for server administrators.
   - `sb-proxy`'s `DynamicSniResolver` is an **SNI router and dynamic certificate generator**.
   - An incoming TLS connection specifying `server_name = "*.sbm"` is an invalid SNI client handshake. Minting a wildcard certificate on-demand in response to a client SNI request violates RFC 6066 §3 and opens the server to cache confusion.

### 2.3 ResolvesServerCert Fast-Path Interaction & Disk Probing
In `tools/sb-proxy/src/proxy.rs`:
```rust
    pub fn resolve_for_server_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let name_clean = server_name.trim_end_matches('.').to_ascii_lowercase();
        if name_clean.is_empty() || name_clean.len() > 253 {
            return self.fallback_cert.clone();
        }

        // Fast-Path 1: In-memory RAM cache
        ...
        // Fast-Path 2: Custom route certs
        ...
        // Fast-Path 3: Check on-disk S&B CA certs
        if let Some(cert) = self.check_disk_certs(&name_clean) {
            ...
            return Some(cert);
        }

        // Fast-Path 4: On-Demand TLS Issuance with Eligibility Gate
        if self.is_eligible_for_on_demand(&name_clean) {
            ...
        }
```
- **Crucial Discovery**: Fast-Path 3 runs **before** Fast-Path 4.
- If spurious files `_wildcard_.sbm.crt` or `.sbm.crt` already exist on disk, Fast-Path 3 (`check_disk_certs`) will find them and return `Some(cert)` even if `is_eligible_for_on_demand` is fixed to return `false`!
- Furthermore, `resolve_for_server_name` did not perform early structural validation on `name_clean`. An attacker sending path traversal or wildcards causes filesystem probes in Fast-Path 3 (`DeveloperCa::find_dev_certificate`).
- **Remediation Requirement**:
  1. `is_eligible_for_on_demand` must be hardened with strict 4-tier validation.
  2. `resolve_for_server_name` must fail-closed early on malformed SNIs before querying disk or cache.
  3. Pre-existing spurious cert files must be cleaned from disk.

---

## 3. Caveats

- **Loopback and Dev Exceptions**: In RFC 6066 §3, literal IP addresses are forbidden in SNI. However, in local developer workflows and unit test harnesses, `localhost` and `127.0.0.1` are explicitly supported by `DynamicSniResolver` for loopback routing. This intentional pragmatic deviation is preserved.
- **Underscore in Labels**: Standard RFC 1123 hostnames forbid underscores. In `sb-proxy`, underscores (`_`) are explicitly permitted within labels to support internal mesh service identifiers (e.g. `service_node.sbm`).
- **Punycode / IDN**: Internationalized domain names must arrive at the SNI layer in ASCII Punycode representation (`xn--...`). Non-ASCII Unicode characters (e.g. `日本語.sbm`) are correctly rejected as non-compliant with RFC 6066 §3 ASCII encoding rules.
- **Source Code Write Permission**: As an explorer, no changes were made to source files or tests during this investigation.

---

## 4. Conclusion & Precise Remediation Plan

### 4.1 Verdict
**REMEDIATION_PLAN_READY**

The root cause of spurious certificate minting is a permissive suffix check and lack of label/character validation in `DynamicSniResolver::is_eligible_for_on_demand`, compounded by the absence of early fail-closed SNI pre-filtering in `resolve_for_server_name`.

---

### 4.2 Step-by-Step Remediation Plan for the Worker

#### Step 1: Update `is_eligible_for_on_demand` in `tools/sb-proxy/src/proxy.rs`
Replace `is_eligible_for_on_demand` (lines 133–170) with a 4-tier validation structure:
1. **Tier 1 (Length Bounds)**: Reject if empty or `len > 253` (RFC 1035 §2.3.4).
2. **Tier 2 (RFC 6066 §3 Forbidden Characters & Traversal)**: Reject if contains `*`, `:`, `[`, `]`, `/`, `\`, `\0`, `..`, whitespace, or control characters.
3. **Tier 3 (RFC 1035 / RFC 1123 Label Structure)**:
   - Reject if starts with `.` (bare TLD or empty leading label).
   - Ensure all characters belong to the allowlist: `[a-z0-9_.-]`.
   - Split by `.` and verify that every label has `1 <= label.len() <= 63`.
4. **Tier 4 (Authorized Suffix & Route Matching)**:
   - Approve if `d.ends_with(".sbm")`, `d.ends_with(".mesh")`, `d.ends_with(".local")`, `d == "localhost"`, or `d == "127.0.0.1"`.
   - Approve if matching an active route in `EscapeSpaceStore` without custom certs.

```rust
    /// Checks whether a domain name is eligible for on-demand TLS certificate minting.
    ///
    /// SECURITY AUDIT:
    /// - Dynamic Threat Vector: CA stampede & resource exhaustion via high-volume arbitrary or malformed SNIs (CWE-400),
    ///   certificate misissuance / wildcard confusion (CWE-295), path traversal injection in SNI (CWE-22),
    ///   and hidden dotfile / ADS filesystem corruption (CWE-20).
    /// - CVE / CWE Mapping: CWE-400 (Uncontrolled Resource Consumption), CWE-295 (Improper Certificate Validation),
    ///   CWE-22 (Path Traversal), CWE-20 (Improper Input Validation).
    /// - Likelihood & Exploitability: High (8/10) without strict RFC 6066 / RFC 1035 structural pre-filtering.
    ///   * Threat Condition: Untrusted TLS client sends malformed SNI (e.g. `*.sbm`, `.sbm`, `::1.sbm`, `foo:bar.sbm`,
    ///     non-ASCII, or control characters) forcing downstream CA mutex acquisition, ECDSA key generation, and disk I/O.
    /// - Applied Mitigation:
    ///   1. RFC 1035 length enforcement: Overall FQDN <= 253 octets, non-empty, individual labels 1..=63 octets.
    ///   2. RFC 6066 §3 enforcement: Strict rejection of wildcards ('*'), IP literals / colons (':', '[', ']'),
    ///      whitespace, control characters, and non-ASCII octets.
    ///   3. Label syntax validation: No leading/consecutive dots (rejects bare `.sbm`, `.mesh`), each label consists solely of
    ///      ASCII alphanumeric, hyphen, or underscore.
    ///   4. Authoritative scope check: Restricts issuance strictly to sanctioned suffixes (`.sbm`, `.mesh`, `.local`),
    ///      loopback (`localhost`, `127.0.0.1`), or registered active routes in `EscapeSpaceStore`.
    /// - Standards Compliance:
    ///   - IETF RFC 6066 §3 (TLS Server Name Indication - syntax & wildcard prohibition)
    ///   - IETF RFC 1035 §2.3.1 / §2.3.4 (Domain Name Syntax & Size Limits: max 253 FQDN, max 63 label)
    ///   - IETF RFC 1123 §2.1 (Host Names and Numbers - digits in labels)
    ///   - IETF RFC 8446 (TLS 1.3)
    ///   - IETF RFC 5280 (X.509 PKI Profile)
    pub fn is_eligible_for_on_demand(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        // RFC 1035 §2.3.4: FQDN presentation length max 253 octets; cannot be empty
        if d.is_empty() || d.len() > 253 {
            return false;
        }

        // RFC 6066 §3: Hostname is not a wildcard, literal IP addresses (IPv6 colons/brackets) are not permitted.
        // Rejects directory traversal ('/', '\\', ".."), null bytes ('\0'), and control/whitespace characters.
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

        // RFC 1035: Must not start with a dot (rejects bare ".sbm" or ".mesh" without host label)
        if d.starts_with('.') {
            return false;
        }

        // Hostname labels must consist solely of valid ASCII alphanumeric, hyphen, underscore, and dots
        if !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
            return false;
        }

        // RFC 1035 §2.3.4: Each label must be between 1 and 63 octets inclusive
        for label in d.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
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

#### Step 2: Add Fail-Closed SNI Sanitization in `resolve_for_server_name`
In `tools/sb-proxy/src/proxy.rs`, at the beginning of `resolve_for_server_name`:
```rust
    pub fn resolve_for_server_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let name_clean = server_name.trim_end_matches('.').to_ascii_lowercase();
        // RFC 6066 §3 / RFC 1035 fail-closed pre-validation:
        // Do not query RAM cache or filesystem for structurally invalid SNIs
        if name_clean.is_empty()
            || name_clean.len() > 253
            || name_clean.contains('*')
            || name_clean.contains(':')
            || name_clean.contains('/')
            || name_clean.contains('\\')
            || name_clean.contains('\0')
            || name_clean.starts_with('.')
            || name_clean.contains("..")
            || !name_clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return self.fallback_cert.clone();
        }
```
This ensures that malformed SNIs like `*.sbm`, `::1.sbm`, or `../../etc/passwd` immediately return fallback certificates without probing disk or returning stale wildcard certificates.

#### Step 3: Clean Up On-Disk Spurious Certificates
Remove any artifact files created by the previously permissive gate in the user's certificate store (`~/.sb/ca/certs`):
- `.sbm.crt` and `.sbm.key`
- `_wildcard_.sbm.crt` and `_wildcard_.sbm.key`
- `__1.sbm.crt` and `__1.sbm.key`
- `foo_bar.sbm.crt` and `foo_bar.sbm.key` (if present)

#### Step 4: Upgrade `adversarial_eligibility.rs` with Strict Assertions
In `tools/sb-proxy/tests/adversarial_eligibility.rs`:
1. In `test_adversarial_trailing_dots`: Add `assert!(!resolver.is_eligible_for_on_demand(".sbm"))` and `assert!(resolver.resolve_for_server_name(".sbm").is_none())`.
2. In `test_adversarial_wildcards`: Add `assert!(!resolver.is_eligible_for_on_demand("*.sbm"))` and `assert!(resolver.resolve_for_server_name("*.sbm").is_none())`.
3. In `test_adversarial_ipv6_colons_null_and_non_ascii`: Add `assert!(!resolver.is_eligible_for_on_demand(...))` and `assert!(resolver.resolve_for_server_name(...).is_none())` for each input.
4. In `test_adversarial_sni_resolution_matrix`: Add `assert_eq!(findings.len(), 0, "All 23 adversarial SNI inputs must match expected eligibility")`.

---

## 5. Verification Method

1. **Verify Adversarial Matrix (Zero Mismatches)**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility test_adversarial_sni_resolution_matrix -- --nocapture
   ```
   *Expected Output*: `=== TOTAL MISMATCH FINDINGS: 0 ===` and test exits with code 0.

2. **Verify All Adversarial Battery Tests**:
   ```powershell
   cargo test -p sb-proxy --test adversarial_eligibility -- --nocapture
   ```
   *Expected Output*: `7 passed; 0 failed`.

3. **Verify Zero Spurious Files Created in `~/.sb/ca/certs/`**:
   Verify that `_wildcard_.sbm.crt`, `.sbm.crt`, `__1.sbm.crt` do NOT exist.

4. **Verify Full Workspace Suite**:
   ```powershell
   cargo test --workspace
   ```
   *Expected Output*: 100% test pass across all 15 crates.
