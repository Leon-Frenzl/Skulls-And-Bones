## 2026-10-27T20:37:48Z
You are an Explorer subagent planning remediation for Milestone 1 X.509 & Concurrency issues.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_x509
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Gate Feedback Document: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\GATE_STATUS.md
- Challenger 2 Report: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m1_2\handoff.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

Mission:
Investigate and design exact fix strategies for:
1. Broken wildcard handling in `tools/sb-ca/src/x509/leaf.rs:252-260`: Prevent double-prefixing `*.` when domain already starts with `*` or `*.`, resolving the `*.*.sbm` bug.
2. `DevCertIndex` lost updates under concurrency in `tools/sb-ca/src/x509/store.rs`: Implement atomic file replacement (`tempfile` / `.tmp` + `fs::rename`) and thread synchronization (`static INDEX_MUTEX`) around `DevCertIndex::load()`, upsert, and `save()`. Also ensure `get_or_issue_on_demand` falls back to checking disk files if `index.find` missed an entry.
3. Filename colon sanitization in `domain_to_safe_filename`: Replace `:` with `_` to prevent Windows OS error 123 with IPv6 addresses (`::1`).
4. Review the adversarial test suite `tools/sb-ca/tests/adversarial_x509.rs` created by Challenger 2, and ensure all 7 probes will pass with this strategy.

Output Requirements:
- Write your concise, actionable fix strategy to `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_x509\handoff.md`.
- Send a completion message back to parent.
