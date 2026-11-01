# BRIEFING — 2026-10-27T22:49:00Z

## Mission
Investigate CWE-400 pre-filtering and input sanitization in tools/sb-proxy/src/proxy.rs, downstream side-effects, and challenger fix efficacy.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigation, synthesis
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m2_r2_2
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: m2_r2_2

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Do NOT modify source code

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: not yet

## Investigation State
- **Explored paths**:
  - `tools/sb-proxy/src/proxy.rs` (DynamicSniResolver, is_eligible_for_on_demand, resolve_for_server_name)
  - `tools/sb-proxy/src/ca.rs` (DeveloperCa, find_dev_certificate)
  - `tools/sb-ca/src/x509/leaf.rs` (validate_domain, domain_to_safe_filename, get_or_issue_on_demand, issue_leaf_certificate)
  - `tools/sb-ca/src/x509/store.rs` (DevCertIndex, INDEX_MUTEX)
  - `tools/sb-proxy/tests/adversarial_eligibility.rs`
  - On-disk cert store: `~/.sb/ca/certs/` and `~/.sb/ca/index.json`
- **Key findings**:
  1. Bypasses in `is_eligible_for_on_demand`: Used negative substring blocklist (`/`, `\`, `\0`, `..`) + suffix match (`.sbm`). Lacked checks for wildcards `*`, non-ASCII, and control characters (CRLF).
  2. Rejection downstream: `*.*.sbm`, `foo.*.sbm`, `日本語.sbm`, `domain\r\n.sbm` were rejected in `sb_ca::x509::validate_domain` before any file creation, leaving no on-disk artifacts. However, Fast-Path 3 prior to eligibility gate incurs synchronous disk I/O and `INDEX_MUTEX` lock contention, plus warning log spam on rejection.
  3. Spurious disk writes: Malformed inputs `*.sbm`, `.sbm`, `::1.sbm`, `foo:bar.sbm` passed BOTH gates and actively minted certificates (`_wildcard_.sbm.crt`, `.sbm.crt`, `__1.sbm.crt`, `foo_bar.sbm.crt`) and polluted `index.json`.
  4. Challenger fix evaluation: Completely prevents malformed requests and spurious disk writes. However, does not solve valid-looking randomized domain DoS (unbounded HashMap RAM growth and lack of SNI rate limiting).
- **Unexplored areas**: None.

## Key Decisions Made
- Confirmed empirical findings and on-disk spurious certificate presence.
- Outlined remediation and architectural recommendations for the implementer.

## Artifact Index
- DISPATCH.md — Incoming dispatch message
- BRIEFING.md — Working memory
- progress.md — Liveness heartbeat
- handoff.md — Final investigation report
