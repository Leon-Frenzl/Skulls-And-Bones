## 2026-10-27T21:41:06Z
You are explorer_m2_r2_1.
Your working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m2_r2_1
Read ORIGINAL_REQUEST.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
Read PROJECT.md at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\PROJECT.md
Read challenger handoff report at:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m2_eligibility\handoff.md

Objective:
Investigate the domain eligibility gate in `tools/sb-proxy/src/proxy.rs` (`is_eligible_for_on_demand`) to enforce RFC 6066 §3 and RFC 1035/1123 rules:
1. Examine why `*.sbm`, `.sbm`, `foo:bar.sbm`, `::1.sbm` were allowed through the eligibility gate.
2. Verify RFC 6066 §3 restrictions against wildcards in SNI and RFC 1035 label format.
3. Formulate a precise, minimal, robust remediation plan for the Worker.
Write your report in handoff.md and send completion message to caller. Do NOT modify source code.
