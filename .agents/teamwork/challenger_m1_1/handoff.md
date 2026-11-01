# Challenger 1 Empirical Verification Report: OpenSSH CA Engine (`sb_ca::ssh` and `fleet.rs`)

**VERDICT: REQUEST_CHANGES**

---

## 1. Observation

### Empirical Adversarial Probe Execution
Executed dedicated integration test suite `tools/sb-ca/tests/adversarial_ssh_probe.rs` covering all four assigned mission dimensions:

```
Command: cargo test -p sb-ca --test adversarial_ssh_probe -- --nocapture
Result: Exit code 0
Output:
running 5 tests
test test_concurrent_issuance_stress ... ok
[OBSERVATION] Padded principal emitted as: ["  alice  "]
[VULNERABILITY] Newline accepted! Emitted principals: ["alice\n"]
test test_user_cert_extreme_principals ... ok
[OBSERVATION] Auto-generated serial sequence: strictly_increasing = false
[OBSERVATION] First 5 auto serials: [425555682553302468, 7611407179288232530, 8331664659117001109, 5332242805430237542, 3809779822756134400]
test test_serial_number_behavior_and_monotonicity ... ok
[OBSERVATION] Host certificate rejected u64::MAX: SshKey(CertificateFieldInvalid(ValidBefore))
test test_validity_boundaries_and_clock_drift ... ok
test test_wire_format_strict_rfc4251_and_decoding ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.46s
```

### Direct Code Observations

1. **Vulnerability: Newline and Whitespace Injection in Certificate Principals (`tools/sb-ca/src/ssh/cert.rs`)**
   - Lines 34–55:
     ```rust
     fn validate_principal(principal: &str) -> Result<(), CaError> {
         let trimmed = principal.trim();
         if trimmed.is_empty() {
             return Err(CaError::InvalidPrincipal("Principal cannot be empty".into()));
         }
         if trimmed.len() > 64 {
             return Err(CaError::InvalidPrincipal(format!(
                 "Principal '{}' exceeds max length of 64 characters",
                 trimmed
             )));
         }
         // Principals must be safe UNIX usernames or DNS hostnames
         for ch in trimmed.chars() {
             if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' {
                 return Err(CaError::InvalidPrincipal(format!(
                     "Principal '{}' contains disallowed character '{}'",
                     trimmed, ch
                 )));
             }
         }
         Ok(())
     }
     ```
   - Lines 99–101 & 132–134 in `issue_user_certificate`:
     ```rust
     for p in principals {
         validate_principal(p)?;
     }
     ...
     for p in principals {
         builder.valid_principal(p.as_str())?;
     }
     ```
   - Lines 163 & 194 in `issue_host_certificate`:
     ```rust
     validate_principal(hostname)?;
     ...
     builder.valid_principal(hostname)?;
     ```
   - When an untrusted input with leading/trailing whitespace or newlines is passed (e.g. `"alice\n"` or `"  alice  "`):
     * `principal.trim()` strips `\n` or ` `, leaving `"alice"`.
     * `validate_principal` checks only `trimmed.chars()`, which passes the alphanumeric check without error.
     * The un-trimmed input `p.as_str()` (`"alice\n"`) or `hostname` is then passed directly to `builder.valid_principal()`.
     * The CA signs and emits a certificate with `principals = ["alice\n"]` or `principals = ["  alice  "]`.

2. **Serial Number Generation Behavior (`tools/sb-ca/src/ssh/cert.rs`)**
   - Lines 115–118 & 178–181:
     ```rust
     let cert_serial = serial.unwrap_or_else(|| {
         let mut rng = rand::thread_rng();
         rng.gen::<u64>() & 0x7FFFFFFFFFFFFFFF
     });
     ```
   - Worker handoff report (`worker_m1_ca\handoff.md` Section 2.2) claimed:
     *"User certificates are built with random 16-byte nonces, monotonic/random 64-bit serial numbers..."*
   - Empirical observation over 200 consecutive issuances with `serial: None`:
     * Serial numbers are 100% unique (0 collisions).
     * Serial numbers are NOT monotonically increasing: window `[8331664659117001109, 5332242805430237542]` decreased. Default serial generation is purely pseudorandom.

3. **OpenSSH Public Key Wire Format Compliance (`tools/sb/src/commands/fleet.rs` & `tools/sb-ca/src/ssh/key.rs`)**
   - In `tools/sb/src/commands/fleet.rs` lines 204–218:
     * `encode_openssh_ed25519_wire` strictly rejects any `pubkey_bytes.len() != 32`.
     * Assembles `uint32(11) + "ssh-ed25519" + uint32(32) + 32_bytes_key` (51 bytes).
     * Output base64 is exactly 68 characters, prefixed with `AAAAC3NzaC1lZDI1NTE5AAAAI`.
   - In `tools/sb-ca/tests/adversarial_ssh_probe.rs` section 1.6:
     * Proved that `fleet.rs::encode_openssh_ed25519_wire` output is 100% bit-identical to `ssh_key::PublicKey::to_openssh()` across all tested keypairs.
     * `parse_public_key` strictly rejects empty strings, truncated base64, invalid base64 chars, and oversized inputs (1MB buffer) without panic or hang.

4. **Validity Boundaries and Clock Drift (`tools/sb-ca/src/ssh/cert.rs`)**
   - Lines 111–114:
     ```rust
     let now = current_unix_timestamp()?;
     let valid_after = now.saturating_sub(CLOCK_DRIFT_MARGIN_SECONDS);
     let valid_before = now.saturating_add(actual_ttl);
     ```
   - Clock drift margin (60s backdating) is correctly applied (`valid_after = now - 60`).
   - `MAX_USER_CERT_TTL_SECONDS` (28,800s / 8h) is strictly enforced for user certs (`TtlExceeded` returned on 28,801s).
   - `issue_host_certificate` does not define an explicit maximum TTL cap; `ttl = u64::MAX` causes `ssh_key` upstream builder rejection (`SshKey(CertificateFieldInvalid(ValidBefore))`).

5. **Concurrency & Stress Resilience (`tools/sb-ca/tests/adversarial_ssh_probe.rs`)**
   - 8 concurrent threads issuing 200 certificates simultaneously completed with 0 panics, 0 deadlocks, and 100% valid cryptographic signatures verified against the Root CA key.

---

## 2. Logic Chain

1. **Derivation of the Principal Validation Bypass (CWE-20 / CWE-74)**:
   - Observation 1 establishes that `validate_principal` defines `let trimmed = principal.trim()`, and all subsequent validation logic (length <= 64, character allowlist `is_ascii_alphanumeric() || '.' || '-' || '_'`) is evaluated strictly against `trimmed`.
   - When untrusted input contains whitespace or newline delimiters at the boundaries (e.g. `"alice\n"`, `"\ralice"`, or `"  alice  "`), `principal.trim()` strips those characters prior to validation.
   - Observation 1 establishes that `issue_user_certificate` and `issue_host_certificate` iterate over the raw `principals` slice and invoke `builder.valid_principal(p.as_str())?` using the original, un-trimmed string.
   - Therefore, any leading or trailing whitespace, tab, carriage return, or newline bypasses validation completely and is encoded into the OpenSSH certificate wire format.
   - OpenSSH `sshd` utilizes newline-delimited configuration files (e.g., `AuthorizedPrincipalsFile`). Emitting certificates with embedded newlines creates delimiter injection, log forging (CWE-117), and authorization bypass risks (CWE-287).
   - This constitutes an invalid certificate emission and invalidates the claimed active mitigation in `validate_principal` header.

2. **Derivation of the Monotonicity Finding**:
   - The worker's handoff report claimed that certificates use "monotonic/random 64-bit serial numbers".
   - Observation 2 establishes that `issue_user_certificate` and `issue_host_certificate` generate serials via `rng.gen::<u64>() & 0x7FFFFFFFFFFFFFFF` when `serial: None`.
   - Empirical sampling over 200 issuances showed non-monotonic value sequences (e.g. 8.33e18 followed by 5.33e18).
   - While OpenSSH `PROTOCOL.certkeys` does not enforce monotonicity for serial numbers, systems relying on serial monotonicity (for audit trails or revocation tracking) cannot rely on the auto-generation fallback. If monotonicity is required by callers, `serial: Some(seq)` must be explicitly passed.

3. **Derivation of Wire Format Correctness**:
   - Observation 3 proves that both `fleet.rs::encode_openssh_ed25519_wire` and `sb_ca::ssh::ca_public_key_openssh` strictly satisfy RFC 4251 and RFC 8709:
     - 4 bytes len (11) + "ssh-ed25519" + 4 bytes len (32) + 32-byte key = 51 bytes binary wire format.
     - 51 bytes Base64-encodes to exactly 68 characters, prefixed with `AAAAC3NzaC1lZDI1NTE5AAAAI`.
     - Non-32 byte slices are strictly rejected.
     - Bit-level parity between `fleet.rs` and `ssh-key` is verified.

---

## 3. Caveats

1. **Host Certificate Maximum TTL Policy**:
   - `issue_host_certificate` currently does not enforce an explicit `MAX_HOST_CERT_TTL_SECONDS`. While `ssh_key` crate rejects `u64::MAX`, very large TTLs (e.g. 100 years) are accepted. If the project intended a policy limit (e.g. 1 year or 30 days max), it should be enforced at the gate.
2. **Review-Only Constraint Compliance**:
   - In accordance with Teamwork challenger instructions, no source files under `src/` were altered. The adversarial probe suite was implemented in `tools/sb-ca/tests/adversarial_ssh_probe.rs`.

---

## 4. Conclusion

**Verdict: REQUEST_CHANGES**

The OpenSSH CA implementation is robust against wire format corruption, concurrency race conditions, memory leakage, and interior character injection. However, a significant vulnerability exists that permits the **emission of invalid certificates with embedded newlines and whitespace** in principal names:

### Required Changes for Worker (`worker_m1_ca`):
1. **Fix `validate_principal` in `tools/sb-ca/src/ssh/cert.rs`**:
   - Disallow boundary whitespace and newlines by validating `principal` directly without calling `trim()`:
     ```rust
     fn validate_principal(principal: &str) -> Result<(), CaError> {
         if principal.is_empty() {
             return Err(CaError::InvalidPrincipal("Principal cannot be empty".into()));
         }
         if principal.len() > 64 {
             return Err(CaError::InvalidPrincipal(format!(
                 "Principal '{}' exceeds max length of 64 characters",
                 principal
             )));
         }
         for ch in principal.chars() {
             if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' {
                 return Err(CaError::InvalidPrincipal(format!(
                     "Principal '{}' contains disallowed character '{}'",
                     principal, ch
                 )));
             }
         }
         Ok(())
     }
     ```
   - Alternatively, if trimming is intentionally permitted, ensure that the trimmed string is passed into `builder.valid_principal(trimmed)` rather than the raw `p.as_str()`. However, direct rejection of all whitespace characters (leading, trailing, and interior) is strongly recommended per `secure-function-coder` invariant enforcement.
2. **Apply Same Hardening to `hostname` in `issue_host_certificate`**:
   - Ensure `hostname` does not contain leading/trailing whitespace or newlines.
3. **Clarify Serial Number Documentation**:
   - Clarify in `README.md` and docstrings that auto-generated serial numbers are CSPRNG 63-bit pseudorandom integers (ensuring collision resistance), not monotonic sequences. Monotonic sequencing requires callers to supply `serial: Some(seq)`.

---

## 5. Verification Method

To independently verify all findings and reproduce the vulnerability:

```bash
# 1. Run the comprehensive adversarial probe suite
cargo test -p sb-ca --test adversarial_ssh_probe -- --nocapture

# 2. Run the specific extreme principal probe demonstrating newline leakage
cargo test -p sb-ca --test adversarial_ssh_probe test_user_cert_extreme_principals -- --nocapture

# 3. Verify fleet.rs RFC 4251 wire format unit tests
cargo test -p sb-cli --bin sb -- fleet

# 4. Verify overall sb-ca test health
cargo test -p sb-ca
```

**Invalidation Conditions**:
- If `issue_user_certificate(&pub, "id", &["alice\n".into()], 3600, None)` returns `Err(CaError::InvalidPrincipal(_))`, the vulnerability is fixed.
- If `encode_openssh_ed25519_wire(&[0u8; 31])` returns `Err(_)`, wire length enforcement remains intact.
