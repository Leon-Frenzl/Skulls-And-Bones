# Quality Gate Integrity Analysis (Requirement R3)

**Author:** `explorer_survey_gates` (Teamwork Explorer Agent)  
**Date:** 2026-10-26  
**Target:** Skulls & Bones Sovereign Workspace  
**Status:** Completed & Validated

---

## Executive Summary

The Skulls & Bones Quality Gate is governed by the root NPM script `npm run verify:suite`, implemented via `scripts/verify-suite.mjs`. It coordinates a multi-stage validation pipeline spanning inventory integrity, source formatting, workspace-wide compilation, unit/integration/E2E test suites, website production builds, and security audits.

On the local Windows development machine, the entire suite completes cleanly in **~10.5 seconds** with **Exit Code 0** (0 vulnerabilities, 0 test failures, 14 products verified, 1 delivery surface verified).

However, our investigation uncovered a **critical cross-requirement trap between R1 (Release Staging / Maturity Upgrade) and R3 (Quality Gate Integrity)**: Two unit test assertions in the Rust workspace (`tools/sb-core/src/catalog.rs:199` and `tools/sb/src/commands/daemon.rs:2651`) explicitly assert that `product.maturity != ProductMaturity::Releasevalidated`. Furthermore, `sb-core::catalog::validate_products()` enforces that any product with maturity `releasevalidated` MUST provide non-empty `release_evidence`. If `product-inventory.json` is modified for R1 without updating these assertions and providing evidence, `cargo test --workspace` will fail, breaking the Quality Gate.

---

## 1. Command Tree & Verification Architecture

### Root `package.json` Scripts

The root `package.json` defines five scripts:

```json
{
  "name": "skulls-and-bones",
  "private": true,
  "scripts": {
    "install:verify-deps": "node scripts/install-verification-deps.mjs",
    "verify:suite": "node scripts/verify-suite.mjs",
    "dev:website": "npm --prefix website run dev",
    "build:website": "npm --prefix website run build",
    "preview:website": "npm --prefix website run preview"
  }
}
```

### Complete Execution Pipeline (`scripts/verify-suite.mjs`)

`verify-suite.mjs` executes an uninterrupted, fail-closed pipeline divided into six consecutive phases:

```
[npm run verify:suite]
 │
 ├─► Phase 1: Product Inventory & Directory Integrity (Node.js)
 │    ├─ Check schema & non-empty products list
 │    ├─ Enforce ID & directory uniqueness
 │    ├─ Enforce 100% coverage of `tools/*` directories (no ghost or unclassified folders)
 │    ├─ Enforce `separate_surfaces` validation (website directory check & non-overlap)
 │    ├─ Check `desktop_app_catalog` classifications
 │    └─ Validate Cargo manifests for all 14 tools (name, version, binary target, verification cmd)
 │
 ├─► Phase 2: Rust Formatting Gate
 │    └─ `cargo fmt --all -- --check`
 │
 ├─► Phase 3: Rust Workspace Compilation Gate
 │    └─ `cargo check --workspace`
 │
 ├─► Phase 4: Rust Workspace Test Suite Gate
 │    └─ `cargo test --workspace` (runs all unit, integration, and doc tests across 14 crates)
 │
 ├─► Phase 5: Desktop Products Gate (Conditional)
 │    └─ (Currently 0 desktop products; skipped)
 │
 ├─► Phase 6: Website Production Build Gate
 │    └─ `node <npmCli> --prefix website run build` -> `tsc -b && vite build`
 │
 └─► Phase 7: High-Severity Dependency Audit Gate
      └─ `node <npmCli> --prefix website audit --audit-level=high`
```

---

## 2. Detailed Breakdown of Targets & Checks

### 2.1 Inventory & Cargo Manifest Checks (Phase 1)
- **Source:** `scripts/verify-suite.mjs:44-250`
- **Targets:** `product-inventory.json`, `Cargo.toml`, and each `tools/<dir>/Cargo.toml`.
- **Validation Rules:**
  1. `products`: Array length > 0.
  2. Uniqueness: Unique `product.id` and unique `product.source_directory`.
  3. Support directories: All subdirectories in `tools/` must be classified in either `products` or `support_directories`. An unclassified folder or missing folder triggers immediate exit code 1.
  4. Separate delivery surfaces: Each surface (e.g. `website`) must exist on disk and must NOT overlap with any tool directory.
  5. Desktop app catalog: All desktop applications must be in `optional_native_clients` or `excluded_products`.
  6. Cargo manifest synchronicity:
     - Manifest path: `tools/<tool>/Cargo.toml`.
     - `package.name == product.package_name`.
     - `package.version == product.package_version` (evaluates `version.workspace = true` against `[workspace.package].version` in root `Cargo.toml`).
     - Binary target presence: If `product.binary_name` is non-null, verifies that either a `[[bin]]` section exists, `src/main.rs` exists, or `src/bin/<binary>.rs` exists.
     - Verification command: Must be a non-empty string.

### 2.2 The 14 Consolidated Core Products
The 14 active products verified across manifests and workspace:

| ID | Title | Package Name | Version | Kind | Binary Name | Source Directory |
|---|---|---|---|---|---|---|
| `sb` | S&B Suite CLI | `sb-cli` | 0.2.1 | `cli_tool` | `sb` | `tools/sb` |
| `core` | S&B Core | `sb-core` | 0.2.0 | `library` | `null` | `tools/sb-core` |
| `app-contract` | S&B Mesh App Contract | `sb-app-contract` | 0.2.0 | `library` | `null` | `tools/sb-app-contract` |
| `app-protocol` | S&B Mesh App Protocol | `sb-app-protocol` | 0.2.0 | `library` | `null` | `tools/sb-app-protocol` |
| `auth` | S&B Auth Kit | `sb-auth` | 0.2.0 | `cli_tool` | `sb-auth` | `tools/sb-auth` |
| `code` | S&B Code | `sb-code` | 0.1.0 | `cli_tool` | `sb-code` | `tools/sb-code` |
| `db` | S&B Sovereign DB | `sb-db` | 0.2.0 | `cli_tool` | `sb-db` | `tools/sb-db` |
| `dns` | S&B Sovereign DNS | `sb-dns` | 0.2.0 | `cli_tool` | `sb-dns` | `tools/sb-dns` |
| `drive` | S&B Drive | `sb-drive` | 0.2.0 | `cli_tool` | `sb-drive` | `tools/sb-drive` |
| `forge` | S&B Forge | `sb-forge` | 0.1.1 | `cli_tool` | `sb-forge` | `tools/sb-forge` |
| `key` | S&B Key | `sb-key` | 0.1.0 | `cli_tool` | `sb-key` | `tools/sb-key` |
| `mesh` | S&B Sovereign Mesh | `sb-mesh` | 0.3.0 | `cli_tool` | `sb-mesh` | `tools/sb-mesh` |
| `node` | S&B Server Agent | `sb-node` | 0.1.0 | `cli_tool` | `sb-node` | `tools/sb-node` |
| `proxy` | S&B Proxy | `sb-proxy` | 0.1.0 | `cli_tool` | `sb-proxy` | `tools/sb-proxy` |

### 2.3 Rust Workspace Checks & Tests (Phases 2-4)
- **Formatting:** `cargo fmt --all -- --check`
  Ensures consistent coding standards and indentation across all 14 crates.
- **Compilation Check:** `cargo check --workspace`
  Typechecks all workspace members, dev dependencies, build scripts, and examples in dev profile. Completed in ~0.60s.
- **Test Harness:** `cargo test --workspace`
  Executes unit tests, module tests, integration tests, and doc tests across all 14 crates.
  Notable test areas:
  - `sb_app_contract`: Bundle roundtrip, trusted publisher checks, operation grants, replay/revocation/epoch gates, manifest signatures, install rollback & downgrade prevention (17 tests).
  - `sb_app_protocol`: Control framing, chunk transfer digests, request validation (7 tests).
  - `sb_auth`: API key format/entropy, lifecycle integration tests (`tests/auth_lifecycle_tests.rs`).
  - `sb_code`: Live AST parser, AST lock table, shadow baseline cache, Merkle commit store, stream anchor tests, ingress tests, zero-conflict E2E workflow (`tests/e2e_tests.rs`).
  - `sb_core`: Vault encryption & salt derivation, domain DTOs, paths, catalog schema and embedded inventory validation.
  - `sb_db`: Document-KV engine, MVCC concurrency, TTL expiration, indexing, watchers.
  - `sb_dns`: Sovereign DNS protocol resolver, loopback routing, record management.
  - `sb_drive`: Peer filesystem sync, chunk streaming, authorization checks.
  - `sb_forge`: Workflow execution, task graphs, secret handling with fail-closed legacy envelope blocking.
  - `sb_key`: Identity generation, lease generation, cryptographic signing.
  - `sb_mesh`: Peer table, S/Kademlia DHT, Diffie-Hellman AEAD, PFS ratchet, ZK mutual attestation & replay defense, connection roaming, multi-hop routing, instance isolation (`tests/test_mesh_instance_isolation.rs`), stealth ingress (`tests/test_stealth_ingress.rs`).
  - `sb_node`: Headless daemon, DC catalog membership, quorum freshness leases, 4-eyes approval, route admission gates on port 58831-58834 (38 tests).
  - `sb_proxy`: Reverse proxy, loopback HTTP/2 streaming, dynamic SNI, ACME challenges, internal developer CA, rate limiting, static asset delivery (39 tests).
  - `sb-cli`: Launcher, CLI dispatch, cockpit, system doctor, daemon RPC, release packaging and staging installation.

### 2.4 Website Production Build (Phase 5)
- **Source:** `website/package.json`, `website/vite.config.ts`, `website/tsconfig.json`
- **Command:** `npm --prefix website run build` -> `tsc -b && vite build`
- **Execution Environment:** `NPM_CONFIG_ALLOW_SCRIPTS: ""` (mitigates npm malicious install script vectors).
- **Result:**
  - TypeScript compiles with zero errors (`tsc -b`).
  - Vite v8.3.3 bundles client environment in ~294ms.
  - Outputs bundled assets to `website/dist/` (`index.html`, `index-[hash].css`, `index-[hash].js`).

### 2.5 Security Dependency Audit (Phase 6)
- **Command:** `npm --prefix website audit --audit-level=high`
- **Scope:** Evaluates dependencies against npm advisory database at `high` and `critical` severity.
- **Result:** `found 0 vulnerabilities`.

---

## 3. Toolchain & Environment Requirements

| Tool | Version (Local Dev) | Version (CI `.github/workflows/quality.yml`) | Notes |
|---|---|---|---|
| **OS** | Windows 11 (win32) | `windows-latest` | Matched OS environment |
| **Rust / Cargo** | `1.98.0` (2026-08-05) | Stable (latest) | Root `Cargo.toml` edition = "2021" |
| **rustfmt** | `1.9.0-stable` | Added via `rustup component add rustfmt` | Required for `cargo fmt` check |
| **Node.js** | `v24.19.0` | `22` (via `actions/setup-node@v4`) | ES module support (`.mjs`) |
| **npm** | `11.17.0` | Node bundled | Lockfile v3 format |

---

## 4. Platform Quirks, Error Surfacing, and Known Issues

### 4.1 Invocation Entry Requirement (`npm_execpath`)
`scripts/verify-suite.mjs` checks:
```javascript
const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error("Run this verifier with `npm run verify:suite` so the npm CLI path is available.");
  process.exit(1);
}
```
Directly invoking `node scripts/verify-suite.mjs` from PowerShell will fail because `npm_execpath` is only injected by `npm`. Always execute through `npm run verify:suite`.

### 4.2 Shell Avoidance & Spawning on Windows
`verify-suite.mjs` avoids running commands through `cmd.exe` or `powershell.exe` (`shell: false`). It spawns `cargo` and `process.execPath` (Node executable) directly, passing `npmCli` as argument:
```javascript
spawnSync(process.execPath, [npmCli, "--prefix", prefix, ...args], { ... })
```
This avoids Windows cmd batch file argument-mangling, nested quoting problems, and interactive prompts.

### 4.3 `NPM_CONFIG_ALLOW_SCRIPTS` Override
On development environments where `allow-scripts` is configured in `~/.npmrc`, modern npm (v10+) refuses installations with `EALLOWSCRIPTS`. The verifier explicitly clears `NPM_CONFIG_ALLOW_SCRIPTS: ""` in the spawned child processes (`scripts/verify-suite.mjs:259`).

### 4.4 Prerequisite Dependency Installation
Before `verify:suite` can run on a fresh checkout, `npm run install:verify-deps` must be run once:
- It calls `scripts/install-verification-deps.mjs`.
- It executes `npm ci --prefix website`.
- In `.github/workflows/quality.yml`, step 22 explicitly runs `npm run install:verify-deps` prior to `npm run verify:suite`.

### 4.5 Obsolete Quality Gate Documentation
`docs/QUALITY_GATES.md` contains obsolete references to deleted components:
- Mentions `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, and `SKEL E2E tests`.
- Claims `npm audit` is performed on those desktop apps.
In reality:
- `scripts/verify-suite.mjs` lines 286-287 explicitly note:
  ```javascript
  // NetGrid lint removed with desktop apps
  // SKEL E2E tests removed with skel
  ```
- All four desktop applications and NetGrid/Skel were removed.
- Updating `docs/QUALITY_GATES.md` is part of Requirement R2.

---

## 5. Critical Finding: The Maturity Assertion Trap (R1 vs R3)

During deep inspection of test suites in `tools/sb-core` and `tools/sb`, we identified an important trap between Requirement R1 ("Reifegrade in product-inventory.json hochstufen") and Requirement R3 ("Quality-Gate fehlerfrei grün"):

### Finding A: Strict Evidence Requirement
In `tools/sb-core/src/catalog.rs:157-164`:
```rust
if product.maturity == ProductMaturity::Releasevalidated
    && product.release_evidence.is_empty()
{
    return Err(format!(
        "Product '{}' is marked releasevalidated without release evidence",
        product.id
    ));
}
```
If a product's `maturity` is upgraded from `"implemented_not_releasevalidated"` to `"releasevalidated"` without adding valid evidence strings to `"release_evidence": [...]` in `product-inventory.json`, `sb-core` will fail to parse and validate the embedded product catalog, causing compilation/test failures.

### Finding B: Hardcoded Test Assertions Rejecting `Releasevalidated`
Two separate tests in the workspace currently assert that **no** product has `ProductMaturity::Releasevalidated`:

1. `tools/sb-core/src/catalog.rs:195-200`:
   ```rust
   assert!(installable.iter().all(|product| {
       product.binary_name.is_some()
           && product.product_kind == ProductKind::CliTool
           && product.release_targets.len() == 5
           && product.maturity != ProductMaturity::Releasevalidated
   }));
   ```
2. `tools/sb/src/commands/daemon.rs:2649-2651`:
   ```rust
   assert!(products
       .iter()
       .all(|product| { product.maturity != sb_core::ProductMaturity::Releasevalidated }));
   ```

### Impact & Recommendation
If an agent working on R1 changes `product-inventory.json` to mark the products as `releasevalidated`, `cargo test --workspace` will immediately fail on both `sb-core` and `sb-cli` unless:
1. `release_evidence` array is populated with documented evidence for each release-validated product in `product-inventory.json`.
2. The unit test assertions in `tools/sb-core/src/catalog.rs` and `tools/sb/src/commands/daemon.rs` are intentionally updated to reflect the new expected maturity state (e.g. asserting `product.maturity == ProductMaturity::Releasevalidated` or checking specific validated products).

This must be communicated to the orchestrator and the agent handling R1.

---

## 6. How to Verify Cleanly

To run the complete verification suite locally:

```powershell
# 1. (Optional, if node_modules is missing or updated)
npm run install:verify-deps

# 2. Run the full verification suite
npm run verify:suite
```

Expected Output:
```text
Validated 14 products, 14 tool directories, and 0 optional Mesh app clients (0 explicit exclusion), plus 1 separate delivery surface(s).

==> Rust formatting
==> Root Rust workspace check
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.60s
==> Root Rust workspace tests
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.64s
    ... (all 14 crates pass) ...
==> Website build
    tsc -b && vite build
    ... (built in ~300ms) ...
==> Website dependency audit
    found 0 vulnerabilities

Suite verification passed.
```
Exit code: `0`.
