# Project: Skulls & Bones Release Validation, Documentation Synchronization & Suite Quality Gates

## Architecture & System Overview
- **Consolidated Workspace**: Exactly 14 Rust crates under `tools/`:
  - 11 CLI tools: `sb` (`sb-cli` v0.2.1), `auth` (`sb-auth` v0.2.0), `code` (`sb-code` v0.1.0), `db` (`sb-db` v0.2.0), `dns` (`sb-dns` v0.2.0), `drive` (`sb-drive` v0.2.0), `forge` (`sb-forge` v0.1.1), `key` (`sb-key` v0.1.0), `mesh` (`sb-mesh` v0.3.0), `node` (`sb-node` v0.1.0), `proxy` (`sb-proxy` v0.1.0).
  - 3 Core libraries: `core` (`sb-core` v0.2.0), `app-contract` (`sb-app-contract` v0.2.0), `app-protocol` (`sb-app-protocol` v0.2.0).
  - 1 Separate Surface: `website/` (React/Vite).
- **Release & Distribution**: `sb release` subsystem with Ed25519 signing, SHA-256 integrity, atomic Win32 `MoveFileExW` installation, SemVer downgrade protection, and isolated staging via `SB_HOME`.
- **Integrity Baseline**: `npm run verify:suite` verifies inventory, cargo sync, formatting, workspace check, 882 unit/integration tests, website build, and dependency audit.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Release Binaries Build | Clean build of all 14 crates via `cargo build --release --workspace` | M1 (Release) | Survey R1 |
| F2 | Release Key Rotation | Generate Ed25519 keypair, sync pinned trust anchor `RELEASE_PUBLIC_KEY` in `tools/sb/src/commands/release.rs` and `tools/sb/tests/pkg.rs` | M1 (Release) | Survey R1 |
| F3 | Release Packaging & Signing | Execute `sb release pack-all` for target `x86_64-pc-windows-msvc`, generating signed zip archives and `release-manifest.json` | M1 (Release) | Survey R1 |
| F4 | Staging Installation | Execute `sb install all` into isolated `$env:SB_HOME`, verifying atomic extraction | M1 (Release) | Survey R1 |
| F5 | Security & Protection Verification | Verify `sb release verify-key`, `sb release verify`, test tamper rejection (checksum & signature mismatch), and downgrade rejection fail-closed | M1 (Release) | Survey R1 |
| F6 | Binary Execution Validation | Execute all 11 installed CLI tools (`--version` / `--help`) and verify library test integrity | M1 (Release) | Survey R1 |
| F7 | Product Inventory & Catalog Sync | Upgrade maturity to `releasevalidated` with `release_evidence` in `product-inventory.json`, sync test assertions in `sb-core/src/catalog.rs` and `sb/src/commands/daemon.rs` | M2 (Inventory) | Survey R1/R3 |
| F8 | Core Docs Sync (Batch 1) | Update `README.md` and `ROADMAP.md` to reflect 14 core tools and remove deleted desktop/skel/shell references | M3 (Docs) | Survey R2 |
| F9 | Architecture & Gates Sync (Batch 2) | Update `docs/ARCHITECTURE.md`, `docs/QUALITY_GATES.md`, `docs/MANIFESTO.md` | M3 (Docs) | Survey R2 |
| F10 | Brain Strategy Sync (Batch 3) | Update `brain/README.md`, `brain/decisions.md`, `brain/backlog.md`, `brain/vision.md`, `brain/implementation_plan.md` | M3 (Docs) | Survey R2 |
| F11 | Specifications Sync (Batch 4) | Add historical extraction/deprecation notices to `docs/SB_PORTS_PORTSENTRY_SPEC.md`, `docs/SB_SHELL_SOVEREIGN_TERMINAL_SPEC.md`, `docs/SKEL_FRAMEWORK.md` | M3 (Docs) | Survey R2 |
| F12 | Tool Docs Sync (Batch 5) | Update `tools/README.md` and all tool-specific README/TODO files across the 14 tools | M3 (Docs) | Survey R2 |
| F13 | Full Suite Quality Gate Verification | Run and pass 100% of `npm run verify:suite` (cargo fmt, check, test, build, audit) | M4 (Suite Gate) | Survey R3 |
| F14 | Forensic Integrity Audit | Independent forensic verification of authentic implementation, no bypasses or test hardcoding | M4 (Suite Gate) | Project Hard Rule |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Release Packaging, Signing & Staging Validation | F1, F2, F3, F4, F5, F6: Key rotation, release pack, sign, staging install, downgrade & tamper validation, binary execution | None | DONE |
| M2 | Product Inventory & Catalog Synchronization | F7: `product-inventory.json` maturity bump to `releasevalidated`, `release_evidence` population, test assertion updates | M1 | DONE |
| M3 | Comprehensive Documentation Synchronization | F8, F9, F10, F11, F12: Sync all 38 Markdown files across Batches 1 to 5 + Iteration 2 link & buzzword remediations | None | DONE |
| M4 | Final Suite Verification & Quality Gates | F13, F14: `npm run verify:suite`, Challenger stress testing, and Forensic Integrity Audit | M2, M3 | DONE (Gate PASSED in Iteration 2) |

## Interface Contracts
### `sb release` ↔ `product-inventory.json`
- `pack-all` reads `product-inventory.json` to discover installable CLI tools.
- All installable tools must have matching release binaries in `target/release`.
- Pinned `RELEASE_PUBLIC_KEY` in `tools/sb/src/commands/release.rs` must match the public key of the keypair used for signing.

### `product-inventory.json` ↔ `tools/sb-core/src/catalog.rs`
- If `maturity == "releasevalidated"`, `release_evidence` array must not be empty.
- Unit test in `tools/sb-core/src/catalog.rs:195-200` must assert `product.maturity == ProductMaturity::Releasevalidated`.
- Unit test in `tools/sb/src/commands/daemon.rs:2651` must assert `product.maturity == ProductMaturity::Releasevalidated`.

### Documentation ↔ Suite Truth
- Active tool count across all markdown files must be consistently 14.
- Deprecated components (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `skel`, `skully`, `sb-shell`, `sb-ports`, `sb-securenet`, `sb-ui`) must not be described as active suite components.

## Code Layout
- Exclusive write ownership per milestone:
  - M1 Worker: `tools/sb/src/commands/release.rs`, `tools/sb/tests/pkg.rs`, staging artifacts in `staging/`
  - M2 Worker: `product-inventory.json`, `tools/sb-core/src/catalog.rs`, `tools/sb/src/commands/daemon.rs`
  - M3 Worker: Markdown files only (`README.md`, `ROADMAP.md`, `docs/*.md`, `brain/*.md`, `tools/**/*.md`)
