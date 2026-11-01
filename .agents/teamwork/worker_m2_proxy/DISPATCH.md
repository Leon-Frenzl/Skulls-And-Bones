## 2026-10-27T21:16:39Z
You are Worker subagent `worker_m2_proxy` implementing Milestone 2: `sb-proxy` On-Demand TLS Integration.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m2_proxy
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Project Scope Document: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md
- PKI Survey Report: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_ca\handoff.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

File Write Boundaries (Exclusively):
- `tools/sb-proxy/Cargo.toml`
- `tools/sb-proxy/src/proxy.rs`
- `tools/sb-proxy/src/ca.rs`
- `tools/sb-proxy/src/main.rs`
- `tools/sb-proxy/tests/`

Implementation Requirements:
1. In `tools/sb-proxy/Cargo.toml`, add dependency:
   `sb-ca = { path = "../sb-ca" }`
2. In `tools/sb-proxy/src/proxy.rs`:
   - Enhance `DynamicSniResolver` (implementing `rustls::server::ResolvesServerCert`):
     - Add `cert_cache: Arc<std::sync::RwLock<std::collections::HashMap<String, Arc<tokio_rustls::rustls::sign::CertifiedKey>>>>` (in-memory cache).
     - Initialize `cert_cache` when `DynamicSniResolver::new` is created.
     - In `resolve_for_server_name(&self, server_name: &str)`:
       1. Clean domain (`trim_end_matches('.').to_ascii_lowercase()`).
       2. Fast-Path 1: Check `self.cert_cache.read()`. If present, return `Some(cert.clone())` immediately (sub-microsecond latency).
       3. Fast-Path 2: Check custom route certs / escape spaces.
       4. Fast-Path 3: Check on-disk S&B CA certs.
       5. Fast-Path 4: On-Demand TLS Issuance with Eligibility Gate:
          - Eligibility: Check if domain ends with `.sbm`, `.mesh`, `.local`, or is `localhost`, or is registered in `EscapeSpaceStore` active routes.
          - If eligible: Call `sb_ca::x509::get_or_issue_on_demand(&name_clean)`.
          - Convert the resulting `cert_pem` and `key_pem` into `tokio_rustls::rustls::sign::CertifiedKey` using `load_certified_key` or `rustls_pemfile`.
          - Insert into `self.cert_cache.write()` so future requests hit RAM cache.
          - Return `Some(Arc::new(certified_key))`.
       6. Fallback: Return `self.fallback_cert.clone()`.
3. In `tools/sb-proxy/src/ca.rs` and `src/main.rs`:
   - Delegate `sb-proxy ca` commands (`init`, `status`, `issue`, `install`, `uninstall`) to `sb_ca::x509` or ensure seamless interoperability.
4. User Global Rules (Mandatory):
   - Dynamic Threat Modeling: Include `SECURITY AUDIT:` comments documenting threat vector, CWE mapping (CWE-400 resource exhaustion / CA stampede, CWE-295), likelihood 1-10, and active mitigations (eligibility gate, RAM cache).
   - Standards Compliance: Cite RFC 5280, TLS 1.3 RFC 8446, and SNI RFC 6066.
5. Tests:
   - Add integration tests verifying:
     - On-demand TLS resolution: requesting `test.sbm` dynamically issues and serves a valid certificate.
     - In-memory cache hit: subsequent requests return the cached `CertifiedKey` from memory.
     - Ineligible domains do not trigger on-demand generation.
6. Verification:
   - `cargo check --workspace` (0 errors, 0 warnings).
   - `cargo test -p sb-proxy` (100% pass).
   - `cargo test -p sb-ca` (100% pass).
   - `cargo test -p sb-cli` (100% pass).

Output Requirements:
- Write completion report to `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m2_proxy\handoff.md`.
- Include verbatim test outputs and send completion message back to parent.
