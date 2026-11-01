# BRIEFING — 2026-10-27T20:47:00Z

## Mission
Investigate and design exact fix strategies for Milestone 1 Security & Integrity issues (inventory status, Windows ACLs, IssuedCertPair debug/zeroize, security audit headers).

## 🔒 My Identity
- Archetype: explorer
- Roles: investigation, synthesis
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_security
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: Milestone 1 Remediation (Security & Integrity)

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Design concrete, actionable remediation for:
  1. product-inventory.json status & evidence demotion
  2. Windows ACL hardening in tools/sb-ca/src/paths.rs & POSIX 0600
  3. IssuedCertPair in tools/sb-ca/src/x509/store.rs (redacted Debug & Zeroize on drop)
  4. Missing in-code security audit headers on helper functions (User Global Rule 1)

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: 2026-10-27T20:47:00Z

## Investigation State
- **Explored paths**:
  - `product-inventory.json`
  - `tools/sb-core/src/catalog.rs`
  - `tools/sb-ca/src/paths.rs`
  - `tools/sb-ca/src/x509/store.rs`
  - `tools/sb-ca/src/ssh/key.rs`
  - `tools/sb-ca/src/x509/leaf.rs`
  - `tools/sb-ca/src/x509/root.rs`
  - `tools/sb-ca/src/trust.rs`
  - `tools/sb/src/commands/fleet.rs`
  - `tools/sb-ca/src/main.rs`
  - `tools/sb-ca/tests/adversarial_ssh_probe.rs`
- **Key findings**:
  - `ca` entry in `product-inventory.json` copied release hash/timestamp from 2026-10-26 and asserted 14 products in `sb-core` unit test (now 15).
  - Windows `ensure_private_permissions` only cleared read-only bit without disabling inheritance or setting exclusive ACEs (`icacls` needed).
  - `IssuedCertPair` exposes plaintext private keys via `Debug` and does not zeroize sensitive key memory on drop.
  - `parse_public_key` contains arbitrary local file read probing.
  - Several helper and cryptographic functions lack mandatory User Global Rule 1 security audit docstrings.
- **Unexplored areas**: None (investigation complete).

## Key Decisions Made
- Formulated exact replacement JSON for `ca` with `"maturity": "integrated"` and `"release_evidence": []`.
- Added alias support in `tools/sb-core/src/catalog.rs` and aligned unit test for 15 products.
- Designed Windows `icacls` inheritance stripping (`/inheritance:r /grant:r "%USERNAME%:(F)"`) and `write_private_key_file` with `0600` on Unix.
- Designed custom `fmt::Debug` redacting `key_pem` and `key_der` and implemented `Zeroize` and `Drop` on `IssuedCertPair`.
- Designed decoupling of file reading to CLI (`main.rs`) and drafted full `SECURITY AUDIT:` docstrings for all 8 identified functions.

## Artifact Index
- DISPATCH.md — Incoming task dispatch record
- BRIEFING.md — Persistent working state
- progress.md — Liveness heartbeat
- handoff.md — 5-component comprehensive remediation plan
