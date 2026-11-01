# BRIEFING — 2026-10-27T20:42:00Z

## Mission
Investigate and design exact fix strategies for Milestone 1 OpenSSH CA issues: principal trimming bypass in cert.rs, arbitrary filesystem probing in key.rs, and host certificate max TTL bounding.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigation, synthesis
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_ssh
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: Milestone 1 OpenSSH CA Remediation

## 🔒 Key Constraints
- Read-only investigation — do NOT implement directly in source code
- Address 3 specific findings: validate_principal trimmed string pass-through, remove fs probing from parse_public_key, and introduce MAX_HOST_CERT_TTL_SECONDS
- Produce concise, actionable handoff report adhering to the 5-Component structure and engineering standards

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: 2026-10-27T20:42:00Z

## Investigation State
- **Explored paths**:
  - `tools/sb-ca/src/ssh/cert.rs`: Identified root cause of principal injection bypass (lines 34–55, 99–101, 132–134, 163, 194) and missing `MAX_HOST_CERT_TTL_SECONDS`.
  - `tools/sb-ca/src/ssh/key.rs`: Identified arbitrary filesystem probing in library function `parse_public_key` (lines 100–115) and missing `SECURITY AUDIT` docstrings.
  - `tools/sb-ca/src/ssh/mod.rs`: Re-export definitions for constants and functions.
  - `tools/sb-ca/src/main.rs`: CLI layer argument parsing and public key file reading.
  - `tools/sb-ca/tests/adversarial_ssh_probe.rs`: Integration probes covering principals, serials, wire format, and TTLs.
  - `tools/sb-ca/tests/e2e_ssh_ca.rs`: End-to-end SSH CA integration tests.
- **Key findings**:
  1. `validate_principal` trimmed input but returned `Result<(), CaError>`, leaving callers to pass untrimmed `p.as_str()` and `hostname` to `builder.valid_principal(...)`.
  2. `parse_public_key` performed filesystem existence probing and read, creating a file existence oracle / side channel in library code.
  3. `issue_host_certificate` accepted unbounded TTL values, requiring `MAX_HOST_CERT_TTL_SECONDS` (90 days).
  4. Updating library `parse_public_key` requires moving file reading to CLI `resolve_public_key_arg` and updating test assertions in `adversarial_ssh_probe.rs`.
- **Unexplored areas**: None. Scope fully investigated and verified.

## Key Decisions Made
- Design `validate_principal` to return `Result<&str, CaError>` so callers are forced to use the validated, trimmed slice.
- Confine file-reading to CLI layer (`main.rs`) via `resolve_public_key_arg`; make `parse_public_key` strictly in-memory wire format parsing.
- Set `MAX_HOST_CERT_TTL_SECONDS = 90 * 86400` (90 days) matching industry best practices (e.g., Let's Encrypt / modern mTLS lifetimes).
- Add full `SECURITY AUDIT` headers conforming to User Global Rule 1.

## Artifact Index
- BRIEFING.md — Persistent state and working memory
- DISPATCH.md — Initial dispatch log
- progress.md — Liveness heartbeat tracking
- handoff.md — 5-Component actionable remediation strategy
