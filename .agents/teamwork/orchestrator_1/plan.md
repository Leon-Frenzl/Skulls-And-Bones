# Project Orchestration Plan: Release Validation, Docs Sync & Suite Verification

## Objective
Fulfill all 3 core requirements from ORIGINAL_REQUEST.md:
1. R1: Local release build, signing (Ed25519), checksum verification, atomic staging installation, downgrade protection check, binary execution validation, and updating product-inventory.json.
2. R2: Synchronize all markdown documentation across workspace (`README.md`, `ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/QUALITY_GATES.md`, `docs/MANIFESTO.md`, `brain/*`, tool READMEs) to accurately reflect the 14 consolidated core tools and eliminate deprecated component references.
3. R3: Ensure suite quality gate `npm run verify:suite` is 100% green and passing.

## Strategy & Phasing
- **Phase 0: Survey (3 Parallel Explorers)**
  - Explorer 1: Release Tooling, `sb release`, Packaging, Signing, Keys, Staging & `product-inventory.json`.
  - Explorer 2: Documentation Audit across the entire workspace for deprecated references (`skel`, `skully`, `sb-shell`, `sb-ports`, `sb-securenet`, `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `sb-ui`).
  - Explorer 3: Suite Verification Status, `npm run verify:suite`, tests, builds, and cargo workspace checks.
- **Phase 1: Synthesis & PROJECT.md Definition**
  - Synthesize Explorer reports into `PROJECT.md`.
  - Define exact tasks, interface contracts, and acceptance gates.
- **Phase 2: Targeted Worker Execution & Review**
  - Work stream A: R2 Documentation Synchronization.
  - Work stream B: R1 Release Build, Signing, Staging & Product Inventory Update.
  - Work stream C: R3 Suite Verification & Integration.
- **Phase 3: Challenger & Forensic Auditor Gate**
  - Empirical challenge of packaging, staging, downgrade protection, and binary runnability.
  - Forensic integrity audit on code and docs authenticity.
  - Final green run of `npm run verify:suite`.
