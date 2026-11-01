# BRIEFING — 2026-10-27T21:41:30Z

## Mission
Investigate domain eligibility gate in tools/sb-proxy/src/proxy.rs (is_eligible_for_on_demand) to enforce RFC 6066 §3 and RFC 1035/1123 rules, and formulate remediation plan.

## 🔒 My Identity
- Archetype: explorer
- Roles: investigator, synthesis
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m2_r2_1
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: m2_r2 (Domain Eligibility RFC Compliance)

## 🔒 Key Constraints
- Read-only investigation — do NOT implement / modify source code
- Strictly adhere to RFC 6066 §3, RFC 1035, RFC 1123
- Document findings with exact file paths, line numbers, and evidence chain
- Write handoff.md and notify caller via send_message

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: not yet

## Investigation State
- **Explored paths**: `tools/sb-proxy/src/proxy.rs`, `tools/sb-proxy/src/ca.rs`, `tools/sb-ca/src/x509/leaf.rs`, `tools/sb-proxy/tests/adversarial_eligibility.rs`, `~/.sb/ca/certs/`
- **Key findings**:
  1. `is_eligible_for_on_demand` relied on a superficial suffix check (`d.ends_with(".sbm")`) with weak blocklist.
  2. RFC 6066 §3 explicitly forbids wildcards (`*`) and IP literals (`::1`, `127.0.0.1`, colons, brackets) in SNI `HostName`.
  3. RFC 1035 §2.3.1 / §2.3.4 dictates dot-delimited labels of 1..=63 octets and total length <= 253. Bare `.sbm` starts with empty label.
  4. `sb_ca` allowed wildcards and colons for general X.509 issuance, resulting in active minting of `_wildcard_.sbm.crt`, `.sbm.crt`, `__1.sbm.crt`, `foo_bar.sbm.crt`.
  5. `resolve_for_server_name` checked disk certs prior to on-demand gate, meaning pre-existing spurious certs on disk could be returned to invalid SNIs unless fail-closed pre-validation is enforced.
- **Unexplored areas**: None; root causes and solution space fully mapped.

## Key Decisions Made
- Formulate strict 4-tier structural validation in `is_eligible_for_on_demand`:
  - Tier 1: Length bounds (1 <= len <= 253)
  - Tier 2: RFC 6066 §3 forbidden character check (`*`, `:`, `[`, `]`, `/`, `\`, `\0`, `..`, whitespace, control chars)
  - Tier 3: RFC 1035 / RFC 1123 label validation (no leading dot, every label 1..=63 octets, ASCII alphanumeric / hyphen / underscore)
  - Tier 4: Authorized domain scope (`.sbm`, `.mesh`, `.local`, `localhost`, `127.0.0.1`, or active routes)
- Formulate early fail-closed check at top of `resolve_for_server_name` to prevent disk probing on malformed SNIs.
- Recommend worker cleanup of stale on-disk spurious certs.
- Recommend upgrading `adversarial_eligibility.rs` assertions from diagnostic prints to hard assertions (`assert_eq!(findings.len(), 0)`).

## Artifact Index
- DISPATCH.md — Raw incoming messages
- BRIEFING.md — Situational awareness
- progress.md — Liveness heartbeat
- handoff.md — Final investigation report
