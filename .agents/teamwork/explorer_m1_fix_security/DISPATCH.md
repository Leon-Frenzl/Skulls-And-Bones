## 2026-10-27T20:37:48Z
You are an Explorer subagent planning remediation for Milestone 1 Security & Integrity issues.

Identity and Paths:
- Working Directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_security
- Workspace Root: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
- Authoritative User Request: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- Gate Feedback Document: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_2\GATE_STATUS.md
- Reviewer 2 Report: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\reviewer_m1_2\handoff.md
- Parent Conversation ID: 60991008-ad8c-4620-be18-d84298ed02f0

Mission:
Investigate and design exact fix strategies for:
1. `product-inventory.json`: Demote `sb-ca` from `"releasevalidated"` to `"integrated"` (or `"development"`), and remove the copied historical release evidence from 2026-10-26. Formulate exact replacement JSON.
2. Windows ACL hardening in `tools/sb-ca/src/paths.rs`: How to implement explicit user-exclusive ACL restrictions on Windows (`icacls <path> /inheritance:r /grant:r "%USERNAME%:(F)"` or Windows API) when private keys are created. Ensure POSIX 0600 on Unix.
3. `IssuedCertPair` in `tools/sb-ca/src/x509/store.rs`: Implement custom `fmt::Debug` that redacts `key_pem` and `key_der` to prevent logging private keys, and implement `Zeroize` on drop.
4. Missing in-code security audit headers on helper functions (User Global Rule 1).

Output Requirements:
- Write your concise, actionable fix strategy to `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\explorer_m1_fix_security\handoff.md`.
- Send a completion message back to parent.
