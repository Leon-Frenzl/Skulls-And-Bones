# BRIEFING — 2026-10-27T20:00:10Z

## Mission
Survey and investigate Requirement R1: Unified PKI & On-Demand TLS Engine (`sb-ca` and `sb-proxy` integration), covering workspace crates, crypto/TLS libs, OpenSSH Ed25519 certs, X.509/TLS 1.3, `sb-proxy` dynamic cert generation, and dynamic threat modeling.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigation, synthesis
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_survey_ca
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: Requirement R1 - PKI & On-Demand TLS Engine Survey

## 🔒 Key Constraints
- Read-only investigation — do NOT implement production code
- Adhere to User Global Rules:
  1. Dynamic Security & Threat Modeling (CWE/CVE mapping, likelihood, exploitability, mitigations, zeroization, replay protection)
  2. Standards Compliance (RFC 5280, RFC 8446, RFC 4251, OpenSSH PROTOCOL.certkeys, etc.)
  3. Architecture evaluation (critical-thinking skill)
- Write only to working directory (`.agents/teamwork/explorer_survey_ca/`)
- Handoff report in `handoff.md` with 5 components
- Send update to parent via `send_message`

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: not yet

## Investigation State
- **Explored paths**: `Cargo.toml`, `product-inventory.json`, `tools/sb-proxy/`, `tools/sb/`, `tools/sb-core/`, `tools/sb-key/`, `tools/sb-auth/`, `tools/sb-node/`, OpenSSH `PROTOCOL.certkeys`, `ssh-key 0.6.7` in cargo cache.
- **Key findings**:
  1. Workspace is clean (`cargo check --workspace` exits 0, `cargo test -p sb-proxy` passes 39/39).
  2. `ssh-key 0.6.7` is cached locally; perfectly suited for Ed25519 OpenSSH certificates (`ssh-ed25519-cert-v01@openssh.com`).
  3. Discovered bug in `tools/sb/src/commands/fleet.rs`: base64 was calculated on raw 32 bytes of verifying key instead of RFC 4251 wire format.
  4. `rcgen 0.14` is active in `sb-proxy`; can be extracted into `sb-ca` for ECDSA P-256 Root CA and leaf certificates supporting mTLS (`ServerAuth` + `ClientAuth`).
  5. `sb-proxy` dynamic SNI resolver currently lacks in-memory caching and fails on unminted mesh domains. Adding on-demand dynamic issuance with in-memory caching resolves this seamlessly.
  6. Dynamic threat model developed across 5 concrete vectors (CWE-312, CWE-400, CWE-287, CWE-294, CWE-295) with actionable hardening.
- **Unexplored areas**: None for R1 survey scope. Ready for implementation planning.

## Key Decisions Made
- Architecture decision: Implement `sb-ca` as dedicated library and CLI tool using `ssh-key 0.6.7` and `rcgen 0.14`.
- On-Demand TLS decision: Refactor `DynamicSniResolver` in `sb-proxy` to use an in-memory `RwLock<HashMap<String, Arc<CertifiedKey>>>` and on-demand issuance gate.

## Artifact Index
- DISPATCH.md — Initial dispatch message
- BRIEFING.md — Situational awareness
- progress.md — Liveness heartbeat
- handoff.md — Comprehensive 5-component survey and recommendations report
