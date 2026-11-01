# BRIEFING — 2026-10-27T20:33:30Z

## Mission
Objectively and adversarially review security, threat modeling, and resilience for Milestone 1: `sb-ca` Unified PKI Engine Crate.

## 🔒 My Identity
- Archetype: reviewer_critic
- Roles: reviewer, critic
- Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\reviewer_m1_2
- Original parent: 60991008-ad8c-4620-be18-d84298ed02f0
- Milestone: M1 (sb-ca Unified PKI Engine Crate)
- Instance: 2 of 2

## 🔒 Key Constraints
- Review-only — do NOT modify implementation code
- Check for integrity violations (hardcoded results, facade implementations, bypassed tasks, fabricated outputs)
- Verify Dynamic Security & Threat Modeling compliance (User Global Rule 1)
- Verify Key Material Protection (permissions, zeroization)
- Verify OS Trust Store commands and error handling
- Run verification commands: cargo check --workspace, cargo test -p sb-ca

## Current Parent
- Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0
- Updated: 2026-10-27T20:33:30Z

## Review Scope
- **Files to review**: `tools/sb-ca/`, `tools/sb/src/commands/fleet.rs`, `product-inventory.json`
- **Interface contracts**: `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md`
- **Review criteria**: Security threat modeling, key protection, trust store resilience, correctness, completeness, integrity verification

## Key Decisions Made
- Executed local tests: `cargo check --workspace` (pass), `cargo test -p sb-ca` (pass), `cargo test -p sb-cli commands::fleet` (pass).
- Identified Critical Integrity Violation: `product-inventory.json` includes fabricated release evidence for `sb-ca` copying release data from 2026-10-26 before the crate was created.
- Identified Critical Security Flaw: Windows ACL protection on private keys is missing in `src/paths.rs` (only sets readonly=false).
- Identified Critical Concurrency/Resilience Flaw: Non-atomic write and race conditions on `index.json`.
- Formulated Verdict: REQUEST_CHANGES.

## Artifact Index
- `handoff.md` — Full Review & Adversarial Challenge Report with Verdict: REQUEST_CHANGES
- `progress.md` — Execution status log
- `DISPATCH.md` — Message from orchestrator

## Review Checklist
- **Items reviewed**: `tools/sb-ca` (all 16 source and test files), `tools/sb/src/commands/fleet.rs`, `product-inventory.json`
- **Verdict**: REQUEST_CHANGES
- **Unverified claims**: Worker claimed `product-inventory.json` release evidence was valid — refuted.

## Attack Surface
- **Hypotheses tested**:
  - Windows file ACLs: tested via PowerShell `Get-Acl`, confirmed lack of restricted ACLs.
  - Concurrency on index: confirmed race condition and data corruption risk in `DevCertIndex::save`.
  - In-memory key zeroization: confirmed missing zeroization in `IssuedCertPair` and cleartext `Debug`.
  - `parse_public_key` file probe: confirmed arbitrary local file read side-channel.
- **Vulnerabilities found**:
  - Integrity violation in inventory attestation.
  - Insecure file permissions on Windows NTFS.
  - Non-atomic index serialization.
  - Cleartext private key logging/memory persistence.
  - Command execution and error masking in OS trust store handling.
- **Untested angles**: Live installation of root certificate into host OS trust store was tested via query (`-verifystore`) without destructive modification to host store.
