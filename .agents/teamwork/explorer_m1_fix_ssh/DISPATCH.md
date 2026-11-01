## 2026-10-27T20:37:48Z
You are an Explorer subagent planning remediation for Milestone 1 OpenSSH CA issues.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_ssh
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Gate Feedback Document: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\GATE_STATUS.md
- Challenger 1 Report: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m1_1\handoff.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

Mission:
Investigate and design exact fix strategies for:
1. `tools/sb-ca/src/ssh/cert.rs`: Fix input validation bypass where `validate_principal` trimmed input, but untrimmed strings `p.as_str()` and `hostname` were passed to `builder.valid_principal(...)`. Pass the validated, trimmed strings.
2. `tools/sb-ca/src/ssh/key.rs`: Remove arbitrary filesystem probing (`fs::read_to_string`) from the library function `parse_public_key`. Confine file-reading to CLI layer in `src/main.rs`.
3. Introduce `MAX_HOST_CERT_TTL_SECONDS` (e.g. 90 days) in `issue_host_certificate` to bound host certificate lifetimes.

Output Requirements:
- Write your concise, actionable fix strategy to `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_ssh\handoff.md`.
- Send a completion message back to parent.
