# Comprehensive Survey & Architecture Report: Unified PKI & On-Demand TLS Engine (`sb-ca` & `sb-proxy`)

## 1. Observation

### Codebase & Workspace Architecture
- **Workspace Root Manifest (`Cargo.toml`)**:
  - Uses Cargo resolver `"2"`.
  - Currently contains 14 member crates in `members`:
    `tools/sb`, `tools/sb-code`, `tools/sb-forge`, `tools/sb-key`, `tools/sb-mesh`, `tools/sb-node`, `tools/sb-proxy`, `tools/sb-db`, `tools/sb-dns`, `tools/sb-core`, `tools/sb-app-contract`, `tools/sb-app-protocol`, `tools/sb-drive`, `tools/sb-auth`.
  - Workspace package defaults: `version = "0.2.0"`, `edition = "2021"`, `authors = ["Skulls & Bones Lab <dev@skulls-and-bones.org>"]`, `license = "MIT"`.
  - Release profile: `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`.
- **Product Inventory (`product-inventory.json`)**:
  - Catalogs 14 consolidated core tools (`sb`, `core`, `app-contract`, `app-protocol`, `auth`, `code`, `db`, `dns`, `drive`, `forge`, `key`, `mesh`, `node`, `proxy`).
  - No `sb-ca` crate exists yet.
- **`sb-ssh` Historical Context**:
  - `sb-ssh` was an earlier prototype / satellite tool.
  - In `tools/sb-core/src/binary_resolver.rs` (line 92): "Resolves `sb-ssh` binary, or falls back to system `ssh`."
  - In `tools/sb/src/commands/delegate.rs` (lines 154-155, 250-262): If binary is `sb-ssh`, it checks `which::which("ssh")` and falls back to system OpenSSH.
  - In `tools/sb/README.md` (lines 40, 108): "Historische Bezeichnungen `sb-ssh` und `sb-vault` sind keine installierbaren Produkte... Ein systemeigener SSH-Client wird nicht als S&B-Binary ausgeliefert."
  - The Suite delegates `sb ssh` to system OpenSSH, wrapped with S&B stealth tunneling (loopback port 58822) and OpenSSH certificates.
- **Current CA Implementation in `sb-proxy`**:
  - `tools/sb-proxy/src/ca.rs` (lines 42–470) contains an initial `DeveloperCa` manager for local development HTTPS certificates using `rcgen 0.14`.
  - Generates ECDSA P-256 self-signed Root CA cert and key in `~/.sb/ca/root_ca.crt` and `~/.sb/ca/root_ca.key`.
  - Issues leaf certs saved to `~/.sb/ca/certs/<primary_domain>.crt` with SANs and writes index to `~/.sb/ca/index.json`.
  - Implements OS trust store installation (`certutil` on Windows, `security` on macOS, `trust anchor` on Linux).
  - CLI subcommand in `tools/sb-proxy/src/main.rs` (lines 196–220, 677–800): `sb-proxy ca <init|install|uninstall|issue|list|status>`.
  - Delegated in `tools/sb/src/main.rs` (lines 298–302): `Commands::Ca { args }` delegates to `sb-proxy ca`.
- **Existing TLS Termination in `sb-proxy`**:
  - `tools/sb-proxy/src/proxy.rs` (lines 51–130): Implements `DynamicSniResolver` implementing `tokio_rustls::rustls::server::ResolvesServerCert`.
  - SNI Resolution in `resolve_for_server_name(server_name)`:
    1. Checks custom cert in `EscapeSpaceStore`.
    2. Calls `DeveloperCa::find_dev_certificate(&name_clean)`.
    3. Falls back to ACME or fallback key.
  - **Critical Flaw Observed**: `DeveloperCa::find_dev_certificate` only searches `index.json` for previously issued certificates. If no cert exists on disk, it returns `None`. No on-demand certificate generation occurs dynamically during incoming TLS handshakes.
  - **Performance Flaw Observed**: `load_certified_key` (lines 20–47) reads PEM files from disk and parses private keys synchronously on every TLS resolution without an in-memory `RwLock<HashMap<String, Arc<CertifiedKey>>>` cache.
- **Defective OpenSSH Public Key Generation in `fleet.rs`**:
  - In `tools/sb/src/commands/fleet.rs` (lines 154–165):
    ```rust
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pub_b64 = simple_base64_encode(verifying_key.as_bytes());
    let pub_entry = format!("ssh-ed25519 {} sovereign-swarm-ca@local", pub_b64);
    ```
  - **Defect**: Base64 encoding the raw 32 bytes of the Ed25519 public key violates RFC 4251 and OpenSSH wire format! OpenSSH requires wire format serialization (`string "ssh-ed25519"` + `string <32-byte key>` = 51 bytes encoded as 68 base64 characters). Standard OpenSSH `sshd` rejects the 32-byte string in `TrustedUserCAKeys`.
- **Cryptographic Dependencies Across Workspace**:
  - `ed25519-dalek = "2.1"` (used in `sb`, `sb-auth`, `sb-dns`, `sb-drive`, `sb-app-contract`; 2.2 in `sb-node`).
  - `rcgen = "0.14"` (in `sb-proxy`, `features = ["pem", "ring", "x509-parser"]`).
  - `tokio-rustls = "0.26"` (in `sb-proxy`, `features = ["ring", "logging", "tls12"]`, using `rustls 0.23` and `rustls-pki-types 1.x`).
  - `rustls-acme = "0.15.4"`, `rustls-pemfile = "2.2"`.
  - `zeroize = "1.8"` with `features = ["derive", "zeroize_derive"]` in `sb-key`, `sb-auth`, `sb-core`.
  - `ssh-key = "0.6.7"` is already present and cached in the local cargo registry (`C:\Users\leonf\.cargo\registry\cache\index.crates.io-1949cf8c6b5b557f\ssh-key-0.6.7.crate`). Verified to contain `ssh_key::certificate::Builder` and support Ed25519 certificate generation and signing out of the box.

---

## 2. Logic Chain

```
[Requirement R1: Unified PKI & On-Demand TLS Engine]
       │
       ├─► 1. Dedicated Crate `tools/sb-ca`
       │      • Independent library (`sb_ca`) + binary CLI (`sb-ca`)
       │      • Reusable by `sb-proxy`, `sb-node`, and `sb`
       │      • Workspace integration: Cargo.toml members + product-inventory.json
       │
       ├─► 2. Dual-Engine Cryptography
       │      ├─► Engine A: OpenSSH CA (RFC 4251 & PROTOCOL.certkeys)
       │      │   • Ed25519 Root CA keypair (`~/.sb/ca/ssh/ca_key`)
       │      │   • Standard OpenSSH wire format (`ssh-key 0.6.7`)
       │      │   • Fixes fleet.rs 32-byte base64 defect
       │      │   • Short-lived user certs (TTL 1-8h) with principal binding
       │      │   • Host certs for remote provisioning & TrustedUserCAKeys
       │      │
       │      └─► Engine B: X.509 CA (RFC 5280 & TLS 1.3 RFC 8446)
       │          • ECDSA P-256 Root CA (`rcgen 0.14`)
       │          • Mesh domain SANs (*.sbm, *.mesh, app.sbm, localhost)
       │          • mTLS: ServerAuth + ClientAuth EKUs
       │          • OS trust store automation (Windows/macOS/Linux)
       │
       └─► 3. On-Demand TLS Integration into `sb-proxy`
              • Refactor `DynamicSniResolver` with in-memory RAM cache
              • Incoming TLS Handshake (SNI: *.sbm, *.mesh, or route)
              • Cache hit -> immediate return (sub-microsecond)
              • Cache miss -> validate eligibility & rate limits
              • Dynamic issuance via `sb-ca` engine -> cache & return
              • Eliminates manual cert generation; zero-warning HTTPS
```

### Step 1: Separation of PKI Engine from Reverse-Proxy
Currently, `sb-proxy` conflates edge reverse-proxying with certificate authority responsibilities in `src/ca.rs`, while `tools/sb/src/commands/fleet.rs` independently hand-rolls broken SSH key generation. Creating `tools/sb-ca` consolidates all PKI logic into a sovereign, single source of truth. Both `sb-proxy` and `sb-node` (for remote bootstrapping) can import `sb-ca` as a library crate.

### Step 2: OpenSSH Certificate Generation (`PROTOCOL.certkeys`)
OpenSSH certificates require strict compliance with OpenSSH's `PROTOCOL.certkeys` binary wire framing. The `ssh-key` crate (v0.6.7, already present in the local Cargo registry cache) provides:
- Fully compliant OpenSSH public key encoding (`ssh-ed25519 <base64>`).
- Native `certificate::Builder`:
  - `Builder::new_with_random_nonce(&mut rng, subject_pubkey, valid_after, valid_before)`
  - `cert_builder.serial(serial)`
  - `cert_builder.key_id(key_id)`
  - `cert_builder.cert_type(CertType::User)` or `CertType::Host`
  - `cert_builder.valid_principal(principal)`
  - `cert_builder.sign(&ca_key)`
- Outputs `cert.to_openssh()` yielding standard OpenSSH certificate strings (`ssh-ed25519-cert-v01@openssh.com ...`).
- When remote nodes configure `/etc/ssh/trusted_user_ca_keys`, operators presenting this cert bypass password/key prompts completely.

### Step 3: X.509 Certificate Generation & mTLS
`rcgen 0.14` (already a workspace dependency) handles RFC 5280 compliance:
- Self-signed ECDSA P-256 Root CA with `BasicConstraints::Unconstrained`, `KeyCertSign`, `CrlSign`.
- Leaf certificate issuance with SAN extensions supporting wildcard mesh domains (`*.sbm`, `*.mesh`), explicit mesh names, and IP addresses.
- Extended Key Usage including `ServerAuth` (OID 1.3.6.1.5.5.7.3.1) and `ClientAuth` (OID 1.3.6.1.5.5.7.3.2) enables seamless mTLS mutual authentication between mesh nodes without external tools.

### Step 4: On-Demand TLS Architecture in `sb-proxy`
In `sb-proxy`, `DynamicSniResolver` implements `tokio_rustls::rustls::server::ResolvesServerCert`.
The current implementation fails when an unissued domain is requested.
By adding:
1. An in-memory cache `Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>`.
2. An eligibility check matching domains against `EscapeSpaceStore` or mesh domain suffixes (`.sbm`, `.mesh`, `.local`).
3. An on-demand invocation of `sb_ca::x509::issue_certificate`:
When an incoming TLS ClientHello requests an eligible domain, the certificate is generated dynamically in ~1-2 ms, loaded into `CertifiedKey`, cached in memory, written to disk, and returned to complete the TLS handshake.

---

## 3. Critical Thinking & Quantitative Decision Matrix

### Decision 1: SSH Certificate Implementation Strategy
- **Option A**: Use `ssh-key = "0.6.7"` from RustCrypto.
- **Option B**: Hand-roll RFC 4251 byte-level wire serializer and sign with `ed25519-dalek`.

| Criterion | Option A (`ssh-key 0.6.7`) | Option B (Hand-rolled RFC 4251) | Evaluation & Justification |
| :--- | :---: | :---: | :--- |
| **Feasibility & Effort** | **10/10** | **4/10** | `ssh-key` is already cached locally, has complete `certificate::Builder`, and requires ~50 lines of code. Hand-rolling wire format requires hundreds of lines of complex binary packing. |
| **Performance & Scalability** | **9/10** | **9/10** | Both execute in microseconds using pure-Rust curve25519 math. |
| **Maintainability & Elegance** | **10/10** | **4/10** | `ssh-key` has extensive upstream test coverage against actual OpenSSH releases. Custom wire parsers risk subtle byte desynchronization bugs. |
| **Robustness & Security** | **9/10** | **5/10** | `ssh-key` enforces type-safe builders, bounds checking, and constant-time comparisons. |
| **Future-Proofing / Standards** | **10/10** | **6/10** | Directly conforms to OpenSSH `PROTOCOL.certkeys` and RFC 4251. |
| **Total Score** | **48/50** | **28/50** | **Definitive Decision: ADOPT Option A (`ssh-key 0.6.7`)** |

### Decision 2: X.509 Cryptographic Curve for Root & Leaf
- **Option A**: ECDSA P-256 (`PKCS_ECDSA_P256_SHA256`) via `rcgen 0.14`.
- **Option B**: Ed25519 (`PKCS_ED25519`) via `rcgen 0.14`.

| Criterion | Option A (ECDSA P-256) | Option B (Ed25519 X.509) | Evaluation & Justification |
| :--- | :---: | :---: | :--- |
| **Interoperability & Trust Stores** | **10/10** | **4/10** | Windows `certutil`, macOS Keychain, and standard browsers (Chrome, Edge, Safari, Firefox) have 100% universal support for P-256 Root CAs. Ed25519 X.509 is rejected by several OS stores and browsers. |
| **Performance & Handshake Latency** | **9/10** | **10/10** | P-256 hardware acceleration in modern CPUs makes difference negligible (<0.5ms). |
| **Standard Compliance (RFC 5280 / TLS 1.3)** | **10/10** | **8/10** | RFC 8446 designates P-256 as mandatory-to-implement for TLS 1.3. |
| **Total Score** | **29/30** | **22/30** | **Definitive Decision: ADOPT Option A (ECDSA P-256 for X.509)** |

---

## 4. Dynamic Security & Threat Modeling (Mandatory Security Rule)

In compliance with the project's Dynamic Security & Threat Modeling rules, the following 5 vulnerability vectors are audited:

### Threat Vector 1: CA Private Key Extraction & Memory Leakage
- **Contextual Threat Analysis**: The Root CA private keys (`ca_key` for SSH, `root_ca.key` for X.509) are loaded into memory to sign certificates. If file permissions are overly permissive, other unprivileged processes on the host can read them. If buffers remain in memory, core dumps or heap analysis can extract key material.
- **CVE / CWE Mapping**: CWE-312 (Cleartext Storage of Sensitive Information at Rest), CWE-316 (Cleartext Storage of Sensitive Information in Memory), CWE-276 (Incorrect Default Permissions).
- **Likelihood & Exploitability**: Medium (6/10).
- **Threat Condition**: Local attacker or unprivileged daemon reads user files or accesses memory core dumps.
- **Applied Mitigation**:
  1. Enforce strict filesystem mode `0o600` on Unix (`set_permissions`) and user-restricted ACLs on Windows when creating `~/.sb/ca/` private key files.
  2. Implement `Zeroize` / `ZeroizeOnDrop` on all private key buffers, ensuring memory is securely zeroed immediately after signing.
  3. Never log or transmit private keys over IPC, HTTP, or stdout.

### Threat Vector 2: On-Demand TLS DoS & CA Stampede (Resource Exhaustion)
- **Contextual Threat Analysis**: If `sb-proxy` issues a certificate for ANY incoming SNI hostname dynamically, an attacker could flood the proxy with thousands of random hostnames (`attacker1.sbm`, `attacker2.sbm`, etc.). Each request would trigger key generation, signing, and disk writes, starving CPU and filling the disk.
- **CVE / CWE Mapping**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits or Throttling).
- **Likelihood & Exploitability**: High (8/10).
- **Threat Condition**: External client sends rapid bursts of distinct SNI ClientHello messages.
- **Applied Mitigation**:
  1. **Strict Eligibility Gate**: Only issue on-demand certificates for:
     a) Exact domains registered in `EscapeSpaceStore` (or active routes), OR
     b) Domains matching sanctioned mesh suffixes (`.sbm`, `.mesh`, `.local`, `localhost`).
  2. **Hostname Invariant Sanitization**: Reject any domain containing path traversals, control characters, non-RFC 1123 characters, or length > 253 bytes.
  3. **Rate Limiting**: Rate limit on-demand cert generation (e.g. max 5 new certificates/minute per client IP; global limit of 20/minute).
  4. **Single-Flight Lock**: Deduplicate concurrent requests for the same unminted domain so only one certificate is generated.
  5. **Bounded LRU Cache**: Constrain in-memory cert cache to 1,000 entries with TTL expiration.

### Threat Vector 3: OpenSSH Principal Spoofing & Privilege Escalation
- **Contextual Threat Analysis**: A user requests an OpenSSH certificate with `root` or `admin` as principal, gaining unauthorized superuser access across all nodes trusting the CA.
- **CVE / CWE Mapping**: CWE-287 (Improper Authentication), CWE-269 (Improper Privilege Management).
- **Likelihood & Exploitability**: High (8/10).
- **Threat Condition**: Client passes unvalidated principal argument to CA issuance endpoint.
- **Applied Mitigation**:
  1. Require role/policy verification before issuing user certificates with elevated principals.
  2. Enforce short maximum TTL (default 1 hour, hard maximum 8 hours).
  3. Audit log all issued certificates with monotonic 64-bit serial numbers.
  4. Optionally inject OpenSSH `source-address` critical option restricting certificate usage to specific IP subnets.

### Threat Vector 4: Replay & Time-Shift Attacks (Clock Drift Desynchronization)
- **Contextual Threat Analysis**: Certificates rejected due to minor clock skew between nodes, or expired certificates accepted due to caching.
- **CVE / CWE Mapping**: CWE-294 (Authentication Bypass by Capture-replay), CWE-613 (Insufficient Session Expiration).
- **Likelihood & Exploitability**: Medium (5/10).
- **Threat Condition**: Node clocks differ by a few seconds, or proxy serves stale cached certs.
- **Applied Mitigation**:
  1. Backdate certificate `valid_after` / `not_before` by 60 seconds to absorb legitimate NTP clock drift.
  2. Strict cache expiration checks: on each resolution, verify `now < valid_before - margin`; evict expired certs immediately.

### Threat Vector 5: Wildcard & Domain Confusion in X.509 SAN
- **Contextual Threat Analysis**: Malicious SNI injection attempting to claim wildcards or confuse certificate validation.
- **CVE / CWE Mapping**: CWE-295 (Improper Certificate Validation), CWE-20 (Improper Input Validation).
- **Likelihood & Exploitability**: Medium (5/10).
- **Threat Condition**: Untrusted client supplies wildcard SNI in ClientHello.
- **Applied Mitigation**:
  1. On-demand dynamic issuance rejects wildcard requests in SNI (wildcards only permitted via explicit manual CLI configuration).
  2. Strict validation ensuring SAN entries match exact domain syntax.

---

## 5. Architectural Blueprint & Target Design

### 5.1 Crate Structure: `tools/sb-ca`

```
tools/sb-ca/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs              # Public library interface
│   ├── main.rs             # Standalone CLI binary (sb-ca)
│   ├── error.rs            # CaError enum (thiserror)
│   ├── paths.rs            # Canonical CA paths (~/.sb/ca/...)
│   ├── ssh/
│   │   ├── mod.rs          # SshCa engine
│   │   ├── cert.rs         # ssh-key certificate builder & signing
│   │   └── key.rs          # OpenSSH Ed25519 keypair handling
│   └── x509/
│       ├── mod.rs          # X509Ca engine
│       ├── root.rs         # ECDSA P-256 Root CA generation & trust store install
│       ├── leaf.rs         # SAN leaf cert issuance & fullchain PEM
│       └── store.rs        # Cert index & cache persistence
└── tests/
    ├── e2e_ssh_ca.rs       # OpenSSH cert roundtrip & verification
    └── e2e_x509_ca.rs      # X.509 issuance, SAN parsing, mTLS validation
```

### 5.2 Library API Specification (`sb_ca::lib`)

```rust
// OpenSSH CA API
pub struct SshCa;
impl SshCa {
    pub fn init_ca(force: bool) -> Result<SshCaStatus, CaError>;
    pub fn ca_public_key_openssh() -> Result<String, CaError>;
    pub fn issue_user_certificate(
        subject_pubkey_openssh: &str,
        key_id: &str,
        principals: &[String],
        ttl_seconds: u64,
        serial: Option<u64>,
    ) -> Result<String, CaError>;
    pub fn issue_host_certificate(
        subject_pubkey_openssh: &str,
        hostname: &str,
        ttl_seconds: u64,
        serial: Option<u64>,
    ) -> Result<String, CaError>;
}

// X.509 CA API
pub struct X509Ca;
impl X509Ca {
    pub fn init_root_ca(force: bool) -> Result<X509CaStatus, CaError>;
    pub fn install_root_ca() -> Result<String, CaError>;
    pub fn uninstall_root_ca() -> Result<String, CaError>;
    pub fn issue_leaf_certificate(
        domains: &[String],
        ttl_days: u32,
    ) -> Result<IssuedCertPair, CaError>;
    pub fn get_or_issue_on_demand(
        domain: &str,
    ) -> Result<IssuedCertPair, CaError>;
}

pub struct IssuedCertPair {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}
```

### 5.3 `sb-proxy` Dynamic SNI Resolver Integration

In `tools/sb-proxy/src/proxy.rs`:

```rust
pub struct DynamicSniResolver {
    acme_resolver: Option<Arc<rustls_acme::ResolvesServerCertAcme>>,
    routes: Arc<RwLock<EscapeSpaceStore>>,
    fallback_cert: Option<Arc<CertifiedKey>>,
    cert_cache: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    generation_lock: Arc<tokio::sync::Mutex<()>>,
}

impl DynamicSniResolver {
    fn resolve_for_server_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let name_clean = server_name.trim_end_matches('.').to_ascii_lowercase();

        // 1. In-Memory RAM Cache (Instant sub-microsecond return)
        if let Ok(cache) = self.cert_cache.read() {
            if let Some(cert) = cache.get(&name_clean) {
                return Some(cert.clone());
            }
        }

        // 2. Custom escape space PEM certs
        if let Some(cert) = self.check_custom_route_certs(&name_clean) {
            self.cache_cert(&name_clean, cert.clone());
            return Some(cert);
        }

        // 3. On-Disk S&B CA certs
        if let Some(cert) = self.check_disk_certs(&name_clean) {
            self.cache_cert(&name_clean, cert.clone());
            return Some(cert);
        }

        // 4. On-Demand Dynamic Generation (for eligible mesh / route domains)
        if self.is_eligible_for_on_demand(&name_clean) {
            if let Ok(cert) = self.generate_on_demand(&name_clean) {
                self.cache_cert(&name_clean, cert.clone());
                return Some(cert);
            }
        }

        // 5. Global Fallback Cert
        self.fallback_cert.clone()
    }
}
```

---

## 6. Caveats

1. **Root CA Trust Store Scope**:
   Installing the Root CA into OS trust stores (`certutil` / `trust anchor`) requires local user or administrative privileges. In headless container environments (Docker/Podman), `trust anchor` or `/etc/ssl/certs` updates require root permissions.
2. **OpenSSH CA Server Reload**:
   When `TrustedUserCAKeys` is added to `/etc/ssh/sshd_config`, `sshd` must be signaled (`systemctl reload sshd`) for changes to take effect.
3. **Synchronous TLS Resolution**:
   `rustls::server::ResolvesServerCert::resolve` is synchronous. While ECDSA P-256 key generation and signing takes only ~1 ms, any disk writes during on-demand generation should be handled cleanly to avoid latency jitter on the initial connection handshake.

---

## 7. Conclusion

Requirement R1 is fully architecturally vetted and actionable:
1. **`sb-ca`** crate can be implemented cleanly using `ssh-key 0.6.7` (already present in the Cargo cache) for OpenSSH certificates and `rcgen 0.14` (already a workspace dependency) for X.509 mTLS.
2. The defective 32-byte base64 SSH public key generation in `fleet.rs` will be resolved by delegating to `sb-ca`'s RFC 4251-compliant OpenSSH key formatter.
3. `sb-proxy` can achieve true On-Demand TLS by integrating `sb-ca` into `DynamicSniResolver` backed by an in-memory `RwLock<HashMap<String, Arc<CertifiedKey>>>` cache and an eligibility gate, eliminating manual certificate management for mesh domains.
4. The dynamic threat model strictly neutralizes key leakage (zeroization, 0600 mode), DoS CA stampedes (eligibility gate, rate limiting, single-flight locking), and principal spoofing (role policy, short TTL).

---

## 8. Verification Method

To independently verify the findings and prospective implementation:

1. **Compile & Workspace Hygiene Check**:
   ```bash
   cargo check --workspace
   ```
   *Expected*: Exits with code 0, 0 compiler warnings, 0 errors.

2. **Run Existing Proxy & Suite Tests**:
   ```bash
   cargo test -p sb-proxy
   ```
   *Expected*: All 39 tests pass.

3. **Verify OpenSSH Wire Format Compliance**:
   Generate an Ed25519 keypair and inspect the public key string.
   *Verification assertion*: Must begin with `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI` (length 68 base64 chars), NEVER raw 44 chars.

4. **Verify On-Demand TLS Handshake**:
   Configure a test route `test.sbm` on `sb-proxy`. Send a TLS 1.3 ClientHello with SNI `test.sbm`.
   *Verification assertion*: `sb-proxy` terminates TLS, dynamically mints the cert, caches it, and serves valid HTTPS with 0 browser warnings against the installed Root CA.
