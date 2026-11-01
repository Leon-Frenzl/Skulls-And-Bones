# Independent Quality & Adversarial Review Report: Documentation Synchronization (Requirement R2)

**Reviewer Agent:** `reviewer_docs_sync`  
**Parent Agent:** `c8fec1da-c1b6-4134-8c79-b8c105380ce3`  
**Subject:** Milestone M3 (Requirement R2) Documentation Synchronization Review  
**Date:** 2026-10-26  

---

## 1. Review Summary

**Verdict:** **REQUEST_CHANGES**

### Overview
`worker_docs_m3` completed substantial and commendable work aligning root architecture documents (`README.md`, `ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/QUALITY_GATES.md`, `docs/MANIFESTO.md`), brain decision registers (`brain/README.md`, `brain/decisions.md`, `brain/backlog.md`, `brain/implementation_plan.md`), and historical specifications with prominent deprecation banners. The workspace test pipeline (`npm run verify:suite`) was independently run and verified to pass with Exit Code 0 (all 882 tests passing, cargo check/fmt clean, website building with 0 security audit vulnerabilities).

However, rigorous adversarial verification and exhaustive link checking across the entire repository revealed several critical discrepancies that require remediation before Requirement R2 can be approved:
1. **Broken relative links and non-portable machine-specific `file:///c:/Users/leonf/...` URLs in `brain/vision.md`**, including a reference to a completely non-existent source file (`tools/sb-mesh/src/instance.rs`).
2. **An un-synchronized tool file (`tools/sb-mesh/TODO.md`)** that was omitted from Batch 5 and continues to assert active implementation status for extracted tools (`sb-browser`, `sb-ssh`, `sb-vault`) and retains prohibited "Zero-Trust" marketing buzzwords.
3. **Residual broken links to extracted directories** in historical specs (`docs/SKEL_FRAMEWORK.md`).
4. **Residual prohibited "Zero-Trust" buzzword** re-introduced into `tools/README.md:28`.

---

## 2. Findings & Required Changes

### [Major] Finding 1: Broken Relative Links and Machine-Specific Absolute URIs in `brain/vision.md`
- **Location:** `brain/vision.md` (lines 36, 37, 53, 54, 55, 56, 70, 71, 85, 88, 102)
- **Problem:**
  1. *Broken Relative Links:* Lines 36, 37, 85, 88, and 102 link to `tools/...` without the necessary `../` prefix (e.g. `[tools/sb-core/src/catalog.rs](tools/sb-core/src/catalog.rs)`). Relative to `brain/vision.md`, this resolves to `brain/tools/...` which does not exist.
  2. *Machine-Specific File URIs:* Lines 53, 54, 55, 56, 70, and 71 use hardcoded absolute URLs pointing to the local developer username directory: `file:///c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/tools/...`. This breaks cross-machine and team documentation portability.
  3. *Non-Existent Target File:* Line 53 specifically links to `file:///c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/tools/sb-mesh/src/instance.rs`. **This file does not exist anywhere in the repository.** (Named mesh instance state logic resides in `tools/sb-mesh/src/state.rs`).
- **Required Fix:**
  - Replace broken relative links with correct relative paths (e.g., `../tools/sb-core/src/catalog.rs`, `../tools/sb/src/commands/release.rs`, `../tools/sb-proxy/src/http_server.rs`, `../tools/sb-core/src/vault.rs`).
  - Replace absolute `file:///...` links with relative workspace paths (`../tools/sb-mesh/src/service.rs`, `../tools/sb-mesh/src/network.rs`, `../tools/sb-mesh/src/rbac.rs`, `../tools/sb-code/src/language.rs`, `../tools/sb-code/src/ast.rs`).
  - Correct the link for instance isolation to point to `../tools/sb-mesh/src/state.rs` instead of the non-existent `instance.rs`.

---

### [Major] Finding 2: Omitted Documentation & Active Claims for Extracted Components in `tools/sb-mesh/TODO.md`
- **Location:** `tools/sb-mesh/TODO.md` (lines 3, 4, 135, 140, 143, 145, 230, 345)
- **Problem:**
  `tools/sb-mesh/TODO.md` was omitted from Batch 5 tool synchronization. As a result, it directly contradicts the 14-core model and the requirements of R2:
  - Line 4: Claims `sb-mesh` is the active network engine for `sb-browser` and `sb-ssh` (`> Autarke Netzwerk-Engine für den Sovereign Browser (sb-browser) und NetGate (sb-ssh).`).
  - Lines 135–148: Phase 5 is labeled as `(Implementiert)` with active checkmarks for `sb-browser Anbindung` and `sb-ssh NetGate AutoSSH Integration (Aktiviert für Flotten-Architektur)`, claiming live fleet discovery feeds into `sb-ssh` and `sb-vault`.
  - Lines 3, 230, 345: Multiple instances of the prohibited marketing phrase "Zero-Trust" (`Zero-Trust Node Attestation`, `Zero-Trust Firewall`, `Zero-Trust User Management`), violating decisions confirmed in `brain/decisions.md` and `brain/backlog.md` (P0-1, P0-7).
  - Outdated claims regarding WireGuard / boringtun that directly conflict with the warnings in `tools/sb-mesh/README.md`.
- **Required Fix:**
  - Synchronize `tools/sb-mesh/TODO.md`: Remove claims of active integration with `sb-browser`, `sb-ssh`, and `sb-vault`, or mark Phase 5 as historical/extracted.
  - Purge "Zero-Trust" phrases and align terminology with `tools/sb-mesh/README.md` and the 14-core architecture.

---

### [Minor] Finding 3: Broken Relative Link to Extracted Component in `docs/SKEL_FRAMEWORK.md`
- **Location:** `docs/SKEL_FRAMEWORK.md` (line 79)
- **Problem:**
  Line 79 states: `Im Verzeichnis [`../tools/skel`](../tools/skel) existiert ein Rust-Crate-Verbund...`. Because `tools/skel` was extracted from the repository, the markdown link `../tools/skel` is dead and fails local file resolution.
- **Required Fix:**
  Change `[`../tools/skel`](../tools/skel)` to inline code `` `tools/skel` `` or a note explaining that `tools/skel` existed prior to the external satellite extraction.

---

### [Minor] Finding 4: Prohibited "Zero-Trust" Buzzword in `tools/README.md`
- **Location:** `tools/README.md` (line 28)
- **Problem:**
  Line 28 defines: `14. **sb-proxy** (tools/sb-proxy): Zero-Trust Reverse-Proxy, Edge Gateway & TLS Termination Engine`.
  This contradicts the explicit policy in `brain/decisions.md` and `brain/backlog.md` (P0-1, P0-7) prohibiting "Zero-Trust" / "Zero Trust" from active suite component descriptions.
- **Required Fix:**
  Replace `Zero-Trust Reverse-Proxy` with `Pure-Rust Reverse-Proxy` or `Sovereign Reverse-Proxy` (matching `tools/sb-proxy/README.md`).

---

### [Minor] Finding 5: Extracted Tool `sb-vault` Referenced in `tools/sb-code/BEST_PRACTICES.md`
- **Location:** `tools/sb-code/BEST_PRACTICES.md` (line 103)
- **Problem:**
  Heading 6 reads: `## 6. Zero-Secret Policy (sb-forge & sb-vault)`. `sb-vault` was extracted as a historical component; the shared vault is now in `sb-core`.
- **Required Fix:**
  Update heading to `## 6. Zero-Secret Policy (sb-forge & sb-core Vault)`.

---

### [Minor] Finding 6: Upstream Handoff Reporting Inaccuracy Regarding `check-product-inventory.mjs`
- **Location:** `worker_docs_m3/handoff.md` (line 26) & `worker_docs_m3/report.md` (line 42)
- **Problem:**
  The report claims: `node scripts/check-product-inventory.mjs passed`. Executing this command directly fails with `MODULE_NOT_FOUND` because `scripts/check-product-inventory.mjs` does not exist. Inventory validation is actually an internal step embedded directly within `scripts/verify-suite.mjs`.
- **Recommendation:**
  Ensure verification instructions and handoffs accurately document `npm run verify:suite` as the unified verification command.

---

## 3. Verified Claims

| Claim from Worker | Verification Method | Status | Notes |
|---|---|---|---|
| `cargo fmt --all -- --check` passes | Executed via `npm run verify:suite` | **PASS** | Exit code 0, 0 formatting issues. |
| `cargo check --workspace` passes | Executed via `npm run verify:suite` | **PASS** | Exit code 0, all 14 crates typecheck cleanly. |
| `cargo test --workspace` passes (882 tests) | Executed via `npm run verify:suite` | **PASS** | Exit code 0, all 882 unit/integration tests pass. |
| `website` build passes | `tsc -b && vite build` in `verify:suite` | **PASS** | Built client bundle cleanly in ~300ms. |
| `website` dependency audit passes | `npm audit` in `verify:suite` | **PASS** | 0 vulnerabilities found. |
| Root Cargo workspace has exactly 14 crates | Inspected `Cargo.toml` | **PASS** | Matches 11 binaries + 3 libraries. |
| `product-inventory.json` matches 14 tools | Inspected `product-inventory.json` | **PASS** | Exactly 14 tools listed; zero extracted apps in active catalog. |
| Deprecation banners on Batch 4 specs | Inspected all 16 files in Batch 4 | **PASS** | Prominent warning banners present at top of files. |
| Extracted tools removed from active CLI table in `sb/TODO.md` | Inspected `tools/sb/TODO.md` | **PASS** | `sb ports`, `sb ssh`, `sb vault` marked as historical prototypes. |

---

## 4. Adversarial Stress-Testing Results

1. **Broken Link Scanner across all Workspace Markdown Files:**
   - Evaluated all markdown links in `.md` files outside `node_modules` and `target`.
   - **Result: 12 path defects identified** (11 in `brain/vision.md`, 1 in `docs/SKEL_FRAMEWORK.md`).
2. **Target File Existence Audit:**
   - Attempted resolution of `tools/sb-mesh/src/instance.rs`.
   - **Result: FAIL.** The file does not exist on disk.
3. **Deleted Component Search across Tool Documentation:**
   - Scanned all tool directories for active claims on `sb-browser`, `sb-ssh`, `sb-vault`, `sb-ports`, `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `skel`, `skully`.
   - **Result: Discovered un-synchronized `tools/sb-mesh/TODO.md`** presenting `sb-browser` and `sb-ssh` as active and implemented.

---

## 5. Conclusion & Actionable Next Steps

While the architectural restructuring and core documentation alignment are in good shape, the integrity of the documentation is compromised by non-portable local paths, broken links, and stale active claims in `tools/sb-mesh/TODO.md`.

To achieve `APPROVE`, the implementer must:
1. Fix the 11 link/path defects in `brain/vision.md`.
2. Synchronize `tools/sb-mesh/TODO.md` to remove active claims for `sb-browser`, `sb-ssh`, `sb-vault`, and purge "Zero-Trust" phrasing.
3. Fix the dead link to `../tools/skel` in `docs/SKEL_FRAMEWORK.md`.
4. Replace "Zero-Trust" in `tools/README.md:28`.
5. Update `tools/sb-code/BEST_PRACTICES.md:103` heading.
