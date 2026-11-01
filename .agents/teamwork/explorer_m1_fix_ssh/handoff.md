# Handoff Report: Remediation Strategy for Milestone 1 OpenSSH CA Issues

**Mission**: Explorer planning remediation for OpenSSH CA issues in `tools/sb-ca`.  
**Agent**: `explorer_m1_fix_ssh`  
**Status**: Ready for implementation by Worker agent (`worker_m1_ca`)  

---

## 1. Observation

### 1.1 Principal Validation Bypass (`tools/sb-ca/src/ssh/cert.rs`)
- In `tools/sb-ca/src/ssh/cert.rs:34-55`:
  ```rust
  fn validate_principal(principal: &str) -> Result<(), CaError> {
      let trimmed = principal.trim();
      if trimmed.is_empty() {
          return Err(CaError::InvalidPrincipal("Principal cannot be empty".into()));
      }
      ...
  ```
- In `tools/sb-ca/src/ssh/cert.rs:99-101` and `132-134` (`issue_user_certificate`):
  ```rust
  for p in principals {
      validate_principal(p)?;
  }
  ...
  for p in principals {
      builder.valid_principal(p.as_str())?;
  }
  ```
- In `tools/sb-ca/src/ssh/cert.rs:163` and `194` (`issue_host_certificate`):
  ```rust
  validate_principal(hostname)?;
  ...
  builder.key_id(format!("host-cert-{}", hostname))?;
  builder.cert_type(CertType::Host)?;
  builder.valid_principal(hostname)?;
  ```
- **Direct observation**: `validate_principal` trimmed the input string into a local variable `trimmed`, validated characters against `trimmed`, but returned `Result<(), CaError>`. Callers then passed the original, un-trimmed strings (`p.as_str()` and `hostname`) to `builder.valid_principal(...)`.
- **Empirical test confirmation**: In `tools/sb-ca/tests/adversarial_ssh_probe.rs:207-228`, passing `["  alice  "]` or `["alice\n"]` resulted in certificates emitting `valid_principals = ["  alice  "]` and `valid_principals = ["alice\n"]`.

### 1.2 Arbitrary Filesystem Probing in Library Function (`tools/sb-ca/src/ssh/key.rs`)
- In `tools/sb-ca/src/ssh/key.rs:100-115`:
  ```rust
  pub fn parse_public_key(input: &str) -> Result<PublicKey, CaError> {
      let trimmed = input.trim();
      if trimmed.is_empty() {
          return Err(CaError::InvalidPublicKey("Empty public key input".into()));
      }

      // Try reading directly from file if it is a valid path
      let candidate_path = std::path::Path::new(trimmed);
      if candidate_path.exists() && candidate_path.is_file() {
          let content = fs::read_to_string(candidate_path)?;
          return PublicKey::from_openssh(content.trim())
              .map_err(|e| CaError::InvalidPublicKey(e.to_string()));
      }

      PublicKey::from_openssh(trimmed).map_err(|e| CaError::InvalidPublicKey(e.to_string()))
  }
  ```
- **Direct observation**: The library function `parse_public_key` automatically invoked `candidate_path.exists() && candidate_path.is_file()` and `fs::read_to_string(candidate_path)` on any input passed to it. In any library or daemon context (e.g., node bootstrapping or remote RPC), an untrusted input string causes disk reads and path existence probing (CWE-200, CWE-73).
- In `tools/sb-ca/src/main.rs:254-294`, the CLI commands `IssueUser` and `IssueHost` relied on `parse_public_key` to accept file paths from `--pubkey`.
- In `tools/sb-ca/tests/adversarial_ssh_probe.rs:105-108`, an integration test asserted that passing a file path to `parse_public_key` succeeded.

### 1.3 Unbounded Host Certificate Lifetime (`tools/sb-ca/src/ssh/cert.rs`)
- In `tools/sb-ca/src/ssh/cert.rs:80-85`:
  ```rust
  if ttl_seconds > MAX_USER_CERT_TTL_SECONDS {
      return Err(CaError::TtlExceeded {
          requested: ttl_seconds,
          max: MAX_USER_CERT_TTL_SECONDS,
      });
  }
  ```
- In contrast, in `tools/sb-ca/src/ssh/cert.rs:157-170` (`issue_host_certificate`):
  No maximum TTL check existed. Requesting `ttl = u64::MAX` or 100 years bypassed CA policy caps until rejected deep in `ssh_key` upstream builder.

---

## 2. Logic Chain

1. **Fixing Principal Whitespace / Delimiter Smuggling (CWE-20 / CWE-74)**:
   - Changing `validate_principal` signature to `fn validate_principal(principal: &str) -> Result<&str, CaError>` guarantees that validation and trimming are coupled. The function returns `Ok(trimmed)`.
   - `issue_user_certificate` maps `principals` to a `Vec<&str>` of trimmed, validated slices and passes `*p` to `builder.valid_principal(...)`.
   - `issue_host_certificate` stores `let valid_hostname = validate_principal(hostname)?` and passes `valid_hostname` to both `builder.key_id(...)` and `builder.valid_principal(...)`.
   - Result: Whitespace and newlines at the boundaries are stripped prior to signing. No certificates can contain leading/trailing spaces, carriage returns, or newlines. Interior newlines or illegal characters continue to be strictly rejected.

2. **Decoupling Filesystem I/O from Library Layer (CWE-200 / CWE-73)**:
   - `parse_public_key` in `src/ssh/key.rs` must become a pure in-memory parser: trim input and call `PublicKey::from_openssh(trimmed)`. File paths will cleanly fail OpenSSH key wire syntax parsing without accessing the filesystem.
   - The CLI convenience of accepting either a file path (e.g. `~/.ssh/id_ed25519.pub`) or a raw wire string is moved exclusively to `tools/sb-ca/src/main.rs` via a dedicated CLI helper function `resolve_public_key_arg`.
   - Existing tests in `tests/adversarial_ssh_probe.rs` that passed file paths to `parse_public_key` must be updated to verify that the library strictly rejects file paths, while CLI or callers read file content before invoking the library.

3. **Bounding Host Certificate Lifetimes (CWE-613)**:
   - Define `pub const MAX_HOST_CERT_TTL_SECONDS: u64 = 90 * 86400;` (90 days / 7,776,000 seconds) in `src/ssh/cert.rs` and re-export in `src/ssh/mod.rs`.
   - In `issue_host_certificate`, enforce `if ttl_seconds > MAX_HOST_CERT_TTL_SECONDS` and return `Err(CaError::TtlExceeded { requested: ttl_seconds, max: MAX_HOST_CERT_TTL_SECONDS })`.
   - This aligns host certificate lifespans with modern PKI standards (RFC 5280 / Let's Encrypt / modern mTLS 90-day cycle).

---

## 3. Caveats

- `adversarial_ssh_probe.rs:211` previously contained an explicit assertion verifying that untrimmed principal `["  alice  "]` was emitted (written by Challenger 1 to document the bug). When the fix is applied, that assertion will fail unless updated to expect `["alice"]`. The test update is included in this remediation plan.
- `adversarial_ssh_probe.rs:107` previously tested that `parse_public_key` loaded from a file path. When filesystem probing is removed from the library, this probe must be inverted to assert that file paths are rejected.
- No other crates in the workspace currently depend on `sb-ca::ssh`, so changing `parse_public_key` behavior has zero external breaking blast radius.

---

## 4. Conclusion & Actionable Fix Strategy

The remediation is organized into 5 exact file edits.

### File 1: `tools/sb-ca/src/ssh/cert.rs`

1. **Add `MAX_HOST_CERT_TTL_SECONDS` constant**:
   ```rust
   /// Hard upper bound for host certificates: 90 days (7,776,000 seconds).
   pub const MAX_HOST_CERT_TTL_SECONDS: u64 = 90 * 86400;
   ```

2. **Update `validate_principal` to return `Result<&str, CaError>` and add Security Audit header**:
   ```rust
   /// Validates principal strings to prevent injection or malformed principal names,
   /// returning the sanitized, trimmed string slice.
   ///
   /// SECURITY AUDIT:
   /// - Dynamic Threat Vector: Shell meta-character injection, newline injection into sshd
   ///   AuthorizedPrincipalsFile, or boundary whitespace smuggling in OpenSSH certificate principals.
   /// - CVE / CWE Mapping: CWE-20 (Improper Input Validation), CWE-74 (Improper Neutralization of Special Elements),
   ///   CWE-287 (Improper Authentication).
   /// - Likelihood & Exploitability: High (7/10).
   ///   * Threat Condition: Untrusted client provides crafted principal string (e.g. `root\n*` or boundary whitespace).
   /// - Applied Mitigation: Strips boundary whitespace and validates against strict RFC 1123 / safe UNIX username
   ///   character allowlist (`[a-zA-Z0-9._-]`); returns trimmed slice so un-trimmed strings cannot be signed.
   fn validate_principal(principal: &str) -> Result<&str, CaError> {
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
       // Principals must be safe UNIX usernames or DNS hostnames (RFC 1123 / POSIX 3.437)
       for ch in trimmed.chars() {
           if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' {
               return Err(CaError::InvalidPrincipal(format!(
                   "Principal '{}' contains disallowed character '{}'",
                   trimmed, ch
               )));
           }
       }
       Ok(trimmed)
   }
   ```

3. **Update `issue_user_certificate`**:
   Replace validation and principal insertion:
   ```rust
       if principals.is_empty() {
           return Err(CaError::InvalidPrincipal(
               "At least one valid principal (e.g. username) is required".into(),
           ));
       }

       let mut validated_principals = Vec::with_capacity(principals.len());
       for p in principals {
           let v = validate_principal(p)?;
           validated_principals.push(v);
       }

       let trimmed_key_id = key_id.trim();
       if trimmed_key_id.is_empty() {
           return Err(CaError::Security("key_id must not be empty".into()));
       }
   ...
       builder.serial(cert_serial)?;
       builder.key_id(trimmed_key_id)?;
       builder.cert_type(CertType::User)?;

       for p in &validated_principals {
           builder.valid_principal(*p)?;
       }
   ```

4. **Update `issue_host_certificate`**:
   Add TTL check, validate hostname, and use `valid_hostname`:
   ```rust
   pub fn issue_host_certificate(
       subject_pubkey_openssh: &str,
       hostname: &str,
       ttl_seconds: u64,
       serial: Option<u64>,
   ) -> Result<String, CaError> {
       if ttl_seconds > MAX_HOST_CERT_TTL_SECONDS {
           return Err(CaError::TtlExceeded {
               requested: ttl_seconds,
               max: MAX_HOST_CERT_TTL_SECONDS,
           });
       }

       let valid_hostname = validate_principal(hostname)?;

       let actual_ttl = if ttl_seconds == 0 {
           DEFAULT_HOST_CERT_TTL_SECONDS
       } else {
           ttl_seconds
       };
   ...
       builder.serial(cert_serial)?;
       builder.key_id(format!("host-cert-{}", valid_hostname))?;
       builder.cert_type(CertType::Host)?;
       builder.valid_principal(valid_hostname)?;

       let cert = builder.sign(&ca_key)?;
       let cert_str = cert.to_openssh()?;

       Ok(cert_str)
   }
   ```

---

### File 2: `tools/sb-ca/src/ssh/key.rs`

1. **Add `SECURITY AUDIT` docstring to `ca_public_key_openssh`**:
   ```rust
   /// Returns the OpenSSH Root CA public key string formatted according to RFC 4251.
   ///
   /// E.g. `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... sovereign-swarm-ca@local`
   ///
   /// SECURITY AUDIT:
   /// - Dynamic Threat Vector: Tampering or disclosure of CA public key format causing signature verification failures.
   /// - CVE / CWE Mapping: CWE-347 (Improper Verification of Cryptographic Signature).
   /// - Likelihood & Exploitability: Low (1/10).
   ///   * Threat Condition: Corrupted public key file on disk.
   /// - Applied Mitigation: Re-derives public key directly from private key if public file is missing or empty; conforms strictly to RFC 4251 / RFC 8709.
   pub fn ca_public_key_openssh() -> Result<String, CaError> {
   ```

2. **Hardened `parse_public_key` without filesystem probing**:
   ```rust
   /// Parses an OpenSSH public key wire/line string conforming to RFC 4251 into a PublicKey object.
   ///
   /// SECURITY AUDIT:
   /// - Dynamic Threat Vector: Arbitrary file disclosure / filesystem probing via crafted key paths (CWE-200), or malformed key wire format (CWE-20).
   /// - CVE / CWE Mapping: CWE-20 (Improper Input Validation), CWE-200 (Exposure of Sensitive Information), CWE-73 (External Control of File Name or Path).
   /// - Likelihood & Exploitability: Low (2/10).
   ///   * Threat Condition: Untrusted caller supplies a sensitive filesystem path (e.g. `/etc/shadow`) as the public key argument to probe file existence.
   /// - Applied Mitigation: Pure in-memory string parsing via `PublicKey::from_openssh`; filesystem reading is strictly prohibited in the library layer and confined to the CLI layer.
   pub fn parse_public_key(input: &str) -> Result<PublicKey, CaError> {
       let trimmed = input.trim();
       if trimmed.is_empty() {
           return Err(CaError::InvalidPublicKey("Empty public key input".into()));
       }

       PublicKey::from_openssh(trimmed).map_err(|e| CaError::InvalidPublicKey(e.to_string()))
   }
   ```

---

### File 3: `tools/sb-ca/src/ssh/mod.rs`

Update re-exports on lines 11–14:
```rust
pub use cert::{
    issue_host_certificate, issue_user_certificate, DEFAULT_HOST_CERT_TTL_SECONDS,
    DEFAULT_USER_CERT_TTL_SECONDS, MAX_HOST_CERT_TTL_SECONDS, MAX_USER_CERT_TTL_SECONDS,
};
```

---

### File 4: `tools/sb-ca/src/main.rs`

1. **Import `MAX_HOST_CERT_TTL_SECONDS`**:
   ```rust
   use sb_ca::ssh::{
       SshCa, DEFAULT_HOST_CERT_TTL_SECONDS, DEFAULT_USER_CERT_TTL_SECONDS,
       MAX_HOST_CERT_TTL_SECONDS, MAX_USER_CERT_TTL_SECONDS,
   };
   ```

2. **Add CLI public key resolver function**:
   ```rust
   /// Resolves public key input from either a filesystem path or raw OpenSSH wire format string.
   ///
   /// SECURITY AUDIT:
   /// - Dynamic Threat Vector: File traversal or unauthorized file read via command-line `--pubkey` argument.
   /// - CVE / CWE Mapping: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CWE-200 (Information Disclosure).
   /// - Likelihood & Exploitability: Low (2/10).
   ///   * Threat Condition: CLI user executes sb-ca with a path to a key file.
   /// - Applied Mitigation: Confined exclusively to user-driven CLI interface; reads local file if it exists, otherwise falls back to parsing raw string.
   fn resolve_public_key_arg(input: &str) -> Result<String, CaError> {
       let trimmed = input.trim();
       if trimmed.is_empty() {
           return Err(CaError::InvalidPublicKey("Empty public key input".into()));
       }

       let candidate = std::path::Path::new(trimmed);
       if candidate.exists() && candidate.is_file() {
           let content = fs::read_to_string(candidate)?;
           let content_trimmed = content.trim();
           if content_trimmed.is_empty() {
               return Err(CaError::InvalidPublicKey(format!(
                   "Public key file '{}' is empty",
                   candidate.display()
               )));
           }
           Ok(content_trimmed.to_string())
       } else {
           Ok(trimmed.to_string())
       }
   }
   ```

3. **Use resolver in `SshCommands::IssueUser` and `SshCommands::IssueHost`**:
   ```rust
               SshCommands::IssueUser(args) => {
                   let pubkey_str = resolve_public_key_arg(&args.pubkey)?;
                   let cert_str = SshCa::issue_user_certificate(
                       &pubkey_str,
                       &args.key_id,
                       &args.principals,
                       args.ttl,
                       args.serial,
                   )?;
   ...
               SshCommands::IssueHost(args) => {
                   let pubkey_str = resolve_public_key_arg(&args.pubkey)?;
                   let cert_str = SshCa::issue_host_certificate(
                       &pubkey_str,
                       &args.hostname,
                       args.ttl,
                       args.serial,
                   )?;
   ```

---

### File 5: `tools/sb-ca/tests/adversarial_ssh_probe.rs` & `tests/e2e_ssh_ca.rs`

1. **In `adversarial_ssh_probe.rs:104-112`**:
   Update file path probe to verify library rejection:
   ```rust
       // File paths must NOT be probed or read by the library parser (security hardening)
       let temp_key_file = _tmp.join("test_key.pub");
       fs::write(&temp_key_file, &ca_pub).unwrap();
       assert!(
           parse_public_key(temp_key_file.to_str().unwrap()).is_err(),
           "Library parse_public_key must reject file paths without probing disk"
       );

       // Reading from disk is caller/CLI responsibility
       let key_content = fs::read_to_string(&temp_key_file).unwrap();
       let parsed_from_file = parse_public_key(&key_content).expect("Parsing raw string from file content must succeed");
       assert_eq!(parsed_from_file.to_openssh().unwrap(), ca_pub);
   ```

2. **In `adversarial_ssh_probe.rs:207-229`**:
   Update assertion to expect trimmed principal output:
   ```rust
       // 2.5 Whitespace padding and newline leakage remediation verification
       let res_padded = issue_user_certificate(&pub_line, "id1", &["  alice  ".into()], 3600, None);
       assert!(res_padded.is_ok(), "Padded principal must be accepted and sanitized");
       let cert = Certificate::from_str(&res_padded.unwrap()).unwrap();
       assert_eq!(
           cert.valid_principals(),
           &["alice".to_string()],
           "Padded principal MUST be trimmed before being signed into certificate"
       );

       // Probe trailing newline: "alice\n"
       let res_newline = issue_user_certificate(&pub_line, "id1", &["alice\n".into()], 3600, None);
       assert!(res_newline.is_ok(), "Trailing newline must be trimmed and sanitized");
       let cert_nl = Certificate::from_str(&res_newline.unwrap()).unwrap();
       assert_eq!(
           cert_nl.valid_principals(),
           &["alice".to_string()],
           "Trailing newline MUST be trimmed away and not present in emitted certificate"
       );
   ```

3. **In `adversarial_ssh_probe.rs:337-348`**:
   Update host cert TTL probe to verify rejection by `MAX_HOST_CERT_TTL_SECONDS`:
   ```rust
       // 3.8 Host certificate with u64::MAX (far-future) — must be rejected by MAX_HOST_CERT_TTL_SECONDS
       let res_host_max = issue_host_certificate(&pub_line, "host1.sbm", u64::MAX, None);
       assert!(
           matches!(res_host_max, Err(CaError::TtlExceeded { requested, max }) if requested == u64::MAX && max == sb_ca::ssh::MAX_HOST_CERT_TTL_SECONDS),
           "Host cert TTL exceeding MAX_HOST_CERT_TTL_SECONDS must be rejected"
       );
   ```

4. **In `e2e_ssh_ca.rs:140-182`**:
   Add test assertions for:
   - Host cert TTL exceeding `MAX_HOST_CERT_TTL_SECONDS + 1` returning `CaError::TtlExceeded`.
   - Untrimmed input `["  alice  ", "deploy\n"]` emitting `["alice", "deploy"]`.
   - `parse_public_key` rejecting file path strings.

---

## 5. Verification Method

To independently verify the implementation:

1. **Compilation Check**:
   ```powershell
   cargo check --workspace
   ```
   *Expected*: Exit code 0, 0 compiler warnings.

2. **Execute Unit and Integration Tests**:
   ```powershell
   cargo test -p sb-ca --test e2e_ssh_ca
   cargo test -p sb-ca --test adversarial_ssh_probe -- --nocapture
   ```
   *Expected*: All tests pass.
   - Padded principals `["  alice  "]` emit `["alice"]`.
   - Newline strings `["alice\n"]` emit `["alice"]`.
   - File paths passed to `parse_public_key` return `Err(CaError::InvalidPublicKey(_))`.
   - Host cert with `ttl > 90 * 86400` returns `Err(CaError::TtlExceeded { .. })`.

3. **CLI End-to-End Verification**:
   ```powershell
   cargo run -p sb-ca -- ssh issue-host --pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test" --hostname "  node1.sbm  " --ttl 7776001
   ```
   *Expected*: Fails with `TtlExceeded` (requested 7776001 > max 7776000).
   ```powershell
   cargo run -p sb-ca -- ssh issue-host --pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... test" --hostname "  node1.sbm  " --ttl 86400
   ```
   *Expected*: Emits valid certificate with principal `node1.sbm` (trimmed) and key ID `host-cert-node1.sbm`.

4. **Invalidation Conditions**:
   - If `issue_user_certificate` emits a certificate with leading/trailing whitespace in principals, the fix is invalid.
   - If `parse_public_key` calls `fs::read_to_string`, the fix is invalid.
   - If `issue_host_certificate` accepts `ttl = u64::MAX`, the fix is invalid.
