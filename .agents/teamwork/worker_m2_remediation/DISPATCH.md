## 2026-10-27T21:49:21Z
You are worker_m2_remediation.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m2_remediation

Read ORIGINAL_REQUEST.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
Read PROJECT.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md
Read Explorer handoff reports at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m2_r2_1\handoff.md
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m2_r2_2\handoff.md
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m2_r2_3\handoff.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

File write ownership:
You own `tools/sb-proxy/src/proxy.rs`, `tools/sb-proxy/tests/adversarial_eligibility.rs`, and cleanup of spurious files in `C:\Users\leonf\.sb\ca\certs\`.

Your Objectives:
1. In `tools/sb-proxy/src/proxy.rs`:
   - Update `is_eligible_for_on_demand`: Enforce 4-tier structural RFC 6066 §3 / RFC 1035 / RFC 1123 label validation (reject empty, >253 chars, wildcards '*', colons ':', brackets '[]', directory traversal '/', '\\', '..', null bytes '\0', whitespace/control chars, leading dots, and ensure each dot-separated label is 1..=63 octets containing only ASCII alphanumeric, '-', '_'). Add dynamic threat modeling comments and standards citations.
   - In `resolve_for_server_name`: Add early fail-closed SNI pre-filtering at the very top (before Fast-Path 1/2/3) so malformed SNIs like `*.sbm`, `::1.sbm`, `../../etc/passwd` immediately return fallback certificates without querying disk certs or index.
2. Clean up spurious on-disk files in `C:\Users\leonf\.sb\ca\certs\`:
   - Delete `.sbm.crt`, `.sbm.key`, `_wildcard_.sbm.crt`, `_wildcard_.sbm.key`, `__1.sbm.crt`, `__1.sbm.key`, and `foo_bar.sbm.crt`, `foo_bar.sbm.key` if present. Also clean any corresponding entries from `C:\Users\leonf\.sb\ca\index.json`.
3. In `tools/sb-proxy/tests/adversarial_eligibility.rs`:
   - Upgrade test assertions: assert that `test_adversarial_sni_resolution_matrix` finishes with `assert_eq!(findings.len(), 0)`.
   - Ensure all 7 adversarial tests pass cleanly with strict assertions.
4. Verify:
   - Run `cargo check --workspace` (0 errors, 0 warnings).
   - Run `cargo test -p sb-proxy` (all 58 tests pass).
   - Run `cargo test -p sb-ca` (15 tests pass).
   - Run `cargo test -p sb-cli` (85 tests pass).
5. Document changes and test results in `handoff.md` and send completion message to caller.
