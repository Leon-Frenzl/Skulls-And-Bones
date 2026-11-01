## 2026-10-27T19:51:45Z
You are an Explorer subagent for the Skulls-And-Bones project.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_ca
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

Mission: Survey and investigate Requirement R1:
Unified PKI & On-Demand TLS Engine (`sb-ca` and `sb-proxy` integration).

Please perform an in-depth codebase and architecture survey covering:
1. Workspace `Cargo.toml` and existing tool crates in `tools/` (including `sb-proxy`, `sb-ssh`, `sb-node`, etc.).
2. What cryptographic and TLS libraries are currently used in the workspace (e.g., ring, rcgen, ed25519-dalek, rustls, sshkey, etc.)? What dependencies should `sb-ca` use for minimal bloat, high security, and standard compliance?
3. OpenSSH Certificates (RFC 4251): What is required to issue short-lived Ed25519 user and host certificates (`ssh-ed25519-cert-v01@openssh.com`)? Binary wire format encoding, key generation, serial numbers, validity windows, principals, signing with CA private key, format of public keys and certs.
4. X.509 Certificates (RFC 5280 / TLS 1.3): How to implement CA generation and leaf certificate issuance for mesh domains (`*.sbm`, `*.mesh`), mTLS client/server certs, SAN extensions, and PEM/DER encoding.
5. `sb-proxy` Architecture: How does `sb-proxy` currently terminate TLS and route requests? How to cleanly integrate on-demand dynamic certificate generation and caching (e.g. via rustls `ResolvesServerCert` or similar) so `sb-proxy` automatically generates and serves valid certs for incoming requests.
6. Dynamic Threat Modeling & Security Hardening: Apply the user's mandatory rule for dynamic threat modeling (CVE/CWE mapping, trust boundaries, key material protection in memory, zeroization, replay protection, validity checks).

Output Requirements:
- Maintain your heartbeat in `progress.md` with `Last visited: [timestamp]`.
- Write your comprehensive, evidence-based survey and recommendations report to `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_ca\handoff.md`.
- When finished, send a message to parent (60991008-ad8c-4620-be18-d84298ed02f0) with `send_message`.
