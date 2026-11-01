# E2E Test Infra: Skulls & Bones PKI, Bootstrap, Cockpit & Remote Live Verification

## Test Philosophy
- Requirement-driven, opaque-box testing derived directly from `ORIGINAL_REQUEST.md`.
- Methodology: Category-Partition + Boundary Value Analysis + Pairwise Combinatorial + Real-World Workload Testing.
- Verification without depending on internal implementation details.

## Feature Inventory Coverage Map
| # | Feature | Requirement | Tier 1 (Isolated) | Tier 2 (Boundary) | Tier 3 (Pairwise) | Tier 4 (Scenario) |
|---|---------|-------------|:-----------------:|:-----------------:|:-----------------:|:-----------------:|
| F1 | `sb-ca` OpenSSH User Cert Issuance | R1 (RFC 4251) | 5 cases | 5 cases | ✓ | ✓ |
| F2 | `sb-ca` OpenSSH Host Cert Issuance | R1 (RFC 4251) | 5 cases | 5 cases | ✓ | ✓ |
| F3 | `sb-ca` X.509 Root CA & Leaf (`*.sbm`) | R1 (RFC 5280) | 5 cases | 5 cases | ✓ | ✓ |
| F4 | `sb-ca` mTLS Client/Server Certs | R1 (TLS 1.3) | 5 cases | 5 cases | ✓ | ✓ |
| F5 | `sb-proxy` On-Demand TLS Generation | R1 (Dynamic SNI) | 5 cases | 5 cases | ✓ | ✓ |
| F6 | `sb-proxy` In-Memory Cert Caching | R1 (RAM Cache) | 5 cases | 5 cases | ✓ | ✓ |
| F7 | `sb node bootstrap` Pre-flight & SFTP Deploy | R2 (`sb-ssh push`) | 5 cases | 5 cases | ✓ | ✓ |
| F8 | `sb node bootstrap` SSHD CA & Rollback | R2 (`TrustedUserCAKeys`) | 5 cases | 5 cases | ✓ | ✓ |
| F9 | `sb node bootstrap` Systemd & Mesh Onboarding | R2 (`sb-node.service`) | 5 cases | 5 cases | ✓ | ✓ |
| F10 | `sb cockpit` / `sb hud` Daemon HUD Table | R3 (Ratatui TUI) | 5 cases | 5 cases | ✓ | ✓ |
| F11 | `sb cockpit` WireGuard Peers & Routing Table | R3 (TUI Mesh) | 5 cases | 5 cases | ✓ | ✓ |
| F12 | `sb cockpit` Audit & Access Event Table | R3 (TUI Audit) | 5 cases | 5 cases | ✓ | ✓ |
| F13 | Remote Live Target Verification | R4 (145.223.83.235) | 5 cases | 5 cases | ✓ | ✓ |

## Test Architecture
- **E2E Test Runner**: `cargo test --workspace` and integration test binaries under `tools/sb-ca/tests/`, `tools/sb/tests/`, and `tools/sb-proxy/tests/`.
- **Remote Target Harness**: Over SSH to `145.223.83.235`: `/root/verify_all.sh` and `/root/.cargo/bin/sb doctor`.
- **Pass/Fail Semantics**: All test assertions must exit with code 0. Zero warnings in `cargo check --workspace`.

## Test Tiers & Target Counts
- **Tier 1 - Feature Coverage**: 13 features × 5 = 65 test cases (happy-path isolated validation).
- **Tier 2 - Boundary & Corner**: 13 features × 5 = 65 test cases (empty inputs, invalid base64, expired certs, clock drift, non-existent host, syntax error rollback, terminal resize).
- **Tier 3 - Cross-Feature Pairwise**: 15 test cases (e.g. `sb-ca` issuing cert -> `sb-proxy` serving TLS; `sb-ca` issuing CA pubkey -> `sb node bootstrap` configuring sshd -> `sb-ssh` logging in with user cert).
- **Tier 4 - Real-World Scenarios**: 8 end-to-end full scenarios (e.g., zero-touch onboarding of fresh VPS, HTTPS request to `https://app.sbm` dynamically terminating TLS with 0 warnings, operator monitoring HUD with active peer).
- **Tier 5 - Adversarial Coverage Hardening**: White-box stress tests, fuzzing inputs, race condition probes, and memory zeroization validation.
