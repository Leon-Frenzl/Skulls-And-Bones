# Investigation Report: Requirement R1 — Lokale Release-Kette & Staging-Validierung

## 1. Executive Summary

Requirement R1 demands the complete local build, cryptographic Ed25519 signing, packaging, and staging installation run for the 14 consolidated core tools of the Skulls & Bones suite (`sb release pack`, Ed25519 signing, checksum verification, atomic installation, downgrade protection, and binary runnability validation), followed by truthfully updating the maturity status in `product-inventory.json` to `releasevalidated`.

This investigation conducted a thorough, line-by-line inspection of:
- The `sb` CLI source tree (`tools/sb/src/commands/release.rs`, `commands/pkg.rs`, `meta.rs`, `cli.rs`, `main.rs`).
- The shared domain contracts in `sb-core` (`tools/sb-core/src/catalog.rs`, `paths.rs`).
- The canonical product inventory (`product-inventory.json`).
- Existing release lifecycle specifications (`docs/RELEASE_KEY_LIFECYCLE.md`, `docs/RELEASE_AND_DISTRIBUTION_MANIFEST.md`, `packaging/DISTRIBUTION_GUIDE.md`).
- Existing test suites and verification scripts (`scripts/verify-suite.mjs`).

### Key Discoveries & Hard Constraints
1. **The 14 Consolidated Core Tools**:
   - Exactly 11 CLI tools with standalone binary targets: `sb`, `sb-auth`, `sb-code`, `sb-db`, `sb-dns`, `sb-drive`, `sb-forge`, `sb-key`, `sb-mesh`, `sb-node`, `sb-proxy`.
   - Exactly 3 core libraries without binary targets: `sb-core`, `sb-app-contract`, `sb-app-protocol`.
   - All 14 belong to the unified root Cargo workspace (`Cargo.toml`). All direct workspace dependencies check and test cleanly.
2. **Hardcoded Trust Anchor (`RELEASE_PUBLIC_KEY`)**:
   - `tools/sb/src/commands/release.rs:18-21` hardcodes a 32-byte Ed25519 public key (`0xd4, 0x22, 0x2e, 0x09...`).
   - Both `sign_release_manifest` (line 768) and `install_requested_with_source_and_key` (line 213) strictly check against this pinned public key fail-closed.
   - The corresponding private seed is intentionally not stored in the repository (per security specification `docs/RELEASE_KEY_LIFECYCLE.md §2`).
   - Therefore, to execute a real signed packaging run and staging installation, an operator/worker must execute an official key rotation as specified in `docs/RELEASE_KEY_LIFECYCLE.md §5`: generate a valid release keypair with `sb release gen-key`, update `RELEASE_PUBLIC_KEY` in `release.rs`, update the test fixture in `pkg.rs`, and rebuild `sb`.
3. **Maturity Bump Invariant (`release_evidence`)**:
   - `tools/sb-core/src/catalog.rs:157-164` enforces: If `product.maturity == ProductMaturity::Releasevalidated`, the `release_evidence` array in `product-inventory.json` **must not be empty**; otherwise catalog deserialization fails fail-closed!
   - Furthermore, `tools/sb-core/src/catalog.rs:199` contains a unit test asserting `product.maturity != ProductMaturity::Releasevalidated`. When bumping maturity in `product-inventory.json`, this test assertion must be updated to `== ProductMaturity::Releasevalidated`, or `cargo test --workspace` will fail.
4. **Isolated Staging via `SB_HOME`**:
   - `tools/sb-core/src/paths.rs:7-17` honors the `SB_HOME` environment variable. By setting `SB_HOME=<staging_dir>`, staging installations run with 100% isolation from the developer's real `~/.sb/`, allowing reproducible verification of installation, ledger tracking, downgrade protection, and binary execution without touching live system state.

---

## 2. Codebase Evidence Chain

### 2.1 Implementation of `sb release` and `sb install`

| Subcommand | Source Location | Implementation Details & Behavioral Guarantees |
|---|---|---|
| `sb release pack` | `tools/sb/src/commands/release.rs:625-736` | Takes `--version`, `--target`, `--input-dir`, `--output-dir`, `--format` (`tar.gz` or `zip`). Validates SemVer version format and target string. Discovers binaries in `input_dir` matching `is_release_binary_for_target`. Compresses into archive `sb-<ver>-<target>.<ext>`. Computes SHA-256 digest. Creates/updates `release-manifest.json` (schema_version 1). Atomically removes any stale `.ed25519` signature file to prevent signature reuse. |
| `sb release pack-all` | `tools/sb/src/commands/release.rs:778-942` | Strictly validates that **all** installable products declared in `product-inventory.json` for the given target exist in `input_dir` (`commands/release.rs:811-845`). If even one binary is missing, packaging aborts fail-closed. On Windows, packs all 11 core binaries (`sb.exe`, `sb-auth.exe`, `sb-code.exe`, `sb-db.exe`, `sb-dns.exe`, `sb-drive.exe`, `sb-forge.exe`, `sb-key.exe`, `sb-mesh.exe`, `sb-node.exe`, `sb-proxy.exe`). If `--key-file` is passed, automatically signs the resulting manifest. |
| `sb release sign` | `tools/sb/src/commands/release.rs:759-776` | Reads key file, parses seed (32 raw bytes or 64 hex chars) using `parse_signing_seed` (`release.rs:1958`). Uses `zeroize::Zeroizing` to wipe private key material from RAM immediately after use. Checks if verifying key matches `RELEASE_PUBLIC_KEY`. Signs exact manifest bytes with Ed25519 (`release.rs:750`). Writes 128 hex chars to `<manifest>.ed25519` atomically. |
| `sb release verify` | `tools/sb/src/commands/release.rs:1351-1467` | Reads manifest and `.ed25519` signature from `~/.sb/`. Verifies Ed25519 signature against pinned key. Reads `installed_ledger.json`. Recomputes SHA-256 for all binaries in `~/.sb/bin/`. Compares in constant time against ledger entries. Flags files as `✓ VERIFIZIERT`, `✗ MANIPULIERT`, or `i LOKAL / UNVERIF`. Returns error if any tampering is detected. |
| `sb release gen-key` | `tools/sb/src/commands/release.rs:1469-1524` | Fills 32-byte seed from `rand::thread_rng()`. On Unix, enforces `0600` file permissions. Writes 64 hex characters to the specified key file. Outputs public key in hex and Rust array format `[0x..., ...]`. |
| `sb release verify-key` | `tools/sb/src/commands/release.rs:1526-1569` | Audits key file. Validates Ed25519 seed syntax. Derives public key and compares against `RELEASE_PUBLIC_KEY`. Reports `VERIFIZIERT` if matching pinned key, or `GÜLTIG` (with warning) if unpinned. |
| `sb install` | `tools/sb/src/commands/pkg.rs:8-43` & `release.rs:276-534` | Resolves requested tools (`all` installs all available tools + `sb`). Resolves source (`--from-dir`, `--from-url`, or `--from-mesh`). Loads manifest and `.ed25519` signature. Validates Ed25519 signature **before** parsing manifest (fail-closed). Enforces downgrade protection against `installed_ledger.json`. Verifies archive SHA-256 in constant time. Safe extraction (anti-Zip-Slip). Atomically installs binaries via `atomic_install`. Atomically updates `installed_ledger.json` and copies manifest and signature to root. |

### 2.2 Security Mechanisms in Code

#### A. Downgrade Protection (`tools/sb/src/commands/release.rs:404-418`)
```rust
    let sb_dir = target_dir.parent().unwrap_or(target_dir);
    let ledger_path = sb_dir.join(INSTALLED_LEDGER_NAME);
    let existing_ledger = read_installed_ledger(&ledger_path)?;
    // CVE-Threat: A replayed, correctly signed old manifest can roll back installed binaries.
    // Analysis: Signatures authenticate a release but do not establish freshness.
    // Hardening: Compare SemVer against the local ledger; only an explicit flag allows rollback.
    if !allow_downgrade {
        if let Some(ledger) = &existing_ledger {
            if compare_release_versions(&manifest.version, &ledger.release_version)?
                == std::cmp::Ordering::Less
            {
                return Err(ReleaseError::DowngradeBlocked {
                    installed: ledger.release_version.clone(),
                    attempted: manifest.version.clone(),
                });
            }
        }
    }
```
*Verification*: `compare_release_versions` uses `semver::Version::parse` (stripping leading 'v'). If candidate version < installed version, returns `ReleaseError::DowngradeBlocked` unless `--allow-downgrade` is explicitly set.

#### B. Anti-Zip-Slip & Path Traversal Protection (`tools/sb/src/commands/release.rs:1778-1885`)
- In `read_selected_binaries`:
  - Enforces `entry.is_file()` (no directories, symlinks, or block devices).
  - Enforces single-component path name: `path.components().count() == 1`.
  - Rejects duplicate names and names outside `requested`.
  - Caps extracted binary size to `MAX_BINARY_SIZE = 256 MB` (`release.rs:22`).

#### C. Atomic File Installation (`tools/sb/src/commands/release.rs:1984-2065`)
- Writes payload to temporary file `.sb-install-<pid>-<nonce>.tmp`.
- Calls `file.sync_all()` to flush buffers to disk.
- Platform-specific atomic swap:
  - **Windows** (`release.rs:2038-2065`): Invokes Win32 API `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`. Ensures same-volume atomic replacement without leaving partial binaries on failure.
  - **Unix** (`release.rs:2033-2036`): Sets `0755` permissions and uses POSIX `fs::rename`.

#### D. Constant-Time Hash Comparison (`tools/sb/src/commands/release.rs:1946-1956`)
```rust
fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |difference, (a, b)| {
            difference | (a.to_ascii_lowercase() ^ b.to_ascii_lowercase())
        })
        == 0
}
```
Eliminates timing side-channel leakage when comparing SHA-256 digests.

---

## 3. Product Inventory Analysis (`product-inventory.json`)

The canonical inventory `product-inventory.json` defines exactly 14 products:

| ID | Title | Package Name | Version | Kind | Installable | Release Targets | Verification Command |
|---|---|---|---|---|---|---|---|
| `sb` | S&B Suite CLI | `sb-cli` | 0.2.1 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-cli; cargo check -p sb-cli` |
| `core` | S&B Core | `sb-core` | 0.2.0 | `library` | `false` | `[]` | `cargo test -p sb-core` |
| `app-contract` | S&B Mesh App Contract | `sb-app-contract` | 0.2.0 | `library` | `false` | `[]` | `cargo test -p sb-app-contract` |
| `app-protocol` | S&B Mesh App Protocol | `sb-app-protocol` | 0.2.0 | `library` | `false` | `[]` | `cargo test -p sb-app-protocol` |
| `auth` | S&B Auth Kit | `sb-auth` | 0.2.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-auth; cargo check -p sb-auth` |
| `code` | S&B Code | `sb-code` | 0.1.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-code` |
| `db` | S&B Sovereign DB | `sb-db` | 0.2.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-db` |
| `dns` | S&B Sovereign DNS | `sb-dns` | 0.2.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-dns` |
| `drive` | S&B Drive | `sb-drive` | 0.2.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-drive` |
| `forge` | S&B Forge | `sb-forge` | 0.1.1 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-forge` |
| `key` | S&B Key | `sb-key` | 0.1.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-key` |
| `mesh` | S&B Sovereign Mesh | `sb-mesh` | 0.3.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-mesh` |
| `node` | S&B Server Agent | `sb-node` | 0.1.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-node` |
| `proxy` | S&B Proxy | `sb-proxy` | 0.1.0 | `cli_tool` | `true` | 5 targets | `cargo test -p sb-proxy` |

### 3.1 Maturity Lifecycle Definition
In `tools/sb-core/src/catalog.rs:28-44`:
```rust
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProductMaturity {
    Planned,
    Prototype,
    ImplementedNotReleasevalidated,
    Releasevalidated,
}
```

### 3.2 Required Inventory Changes for Release-Validation
1. In `product-inventory.json`:
   - Change `"maturity": "implemented_not_releasevalidated"` to `"maturity": "releasevalidated"` for all 14 products.
   - For every product, add `"release_evidence"` containing verifiable proof strings, for example:
     `"release_evidence": ["local_release_staging_validation_v0.2.0_pass"]`.
2. In `tools/sb-core/src/catalog.rs`:
   - Update line 199 in `inventory_has_unique_installable_binaries_and_no_legacy_products`:
     Change `&& product.maturity != ProductMaturity::Releasevalidated` to `&& product.maturity == ProductMaturity::Releasevalidated`.

---

## 4. Dynamic Security & Threat Modeling

Per User Rule 1, we conduct dynamic first-principles threat modeling of the release and installation process:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                DYNAMIC THREAT MODEL AUDIT                                   │
├──────────────────────┬─────────────┬───────────┬──────────────┬─────────────────────────────┤
│ Threat Vector        │ CWE Mapping │ Likelihood│ Exploit Score│ Active Mitigation in Code   │
├──────────────────────┼─────────────┼───────────┼──────────────┼─────────────────────────────┤
│ Manifest Signature   │ CWE-347     │ High      │ 8/10         │ Pinned 32-byte Ed25519 key; │
│ Forgery / Key Spoof  │ CWE-295     │           │              │ verify_strict before parse  │
├──────────────────────┼─────────────┼───────────┼──────────────┼─────────────────────────────┤
│ Silent Downgrade /   │ CWE-372     │ Medium    │ 6/10         │ SemVer comparison against   │
│ Replay of Old Bug    │ CWE-294     │           │              │ ledger; --allow-downgrade   │
├──────────────────────┼─────────────┼───────────┼──────────────┼─────────────────────────────┤
│ Archive Path Escape  │ CWE-22      │ High      │ 8/10         │ components().count() == 1;  │
│ (Zip Slip attack)    │ CWE-29      │           │              │ exact name matching; no dir │
├──────────────────────┼─────────────┼───────────┼──────────────┼─────────────────────────────┤
│ Incomplete Binary /  │ CWE-377     │ Medium    │ 5/10         │ Win32 MoveFileExW replace;  │
│ Crash Race Condition │ CWE-362     │           │              │ temp file + sync_all flush  │
├──────────────────────┼─────────────┼───────────┼──────────────┼─────────────────────────────┤
│ Timing Discrepancy   │ CWE-208     │ Low       │ 2/10         │ Constant-time hex XOR loop  │
│ on Digest Equality   │             │           │              │ in constant_time_hex_eq     │
├──────────────────────┼─────────────┼───────────┼──────────────┼─────────────────────────────┤
│ Plaintext Transport  │ CWE-319     │ High      │ 7/10         │ URL prefix https:// check;  │
│ Interception         │             │           │              │ cleartext HTTP rejected     │
└──────────────────────┴─────────────┴───────────┴──────────────┴─────────────────────────────┘
```

---

## 5. Standards Compliance Radar

Per User Rule 2, the following engineering standards apply and are verified:
- **IETF RFC 8032**: Edwards-Curve Digital Signature Algorithm (Ed25519) with strict point verification (`ed25519_dalek::VerifyingKey::verify_strict`).
- **NIST FIPS 180-4**: Secure Hash Standard (SHA-256) for artifact digests, manifest validation, and ledger verification.
- **Semantic Versioning 2.0.0**: Strict SemVer version precedence comparison in `compare_release_versions` via `semver::Version`.
- **IETF RFC 9110 & RFC 8446**: HTTP Semantics and TLS 1.3 enforced for remote downloads (`ureq::AgentBuilder` with HTTPS only).
- **ISO/IEC 8601 / RFC 3339**: Timestamps in `installed_ledger.json` and identity documents.

---

## 6. Concrete Worker Execution Plan for Requirement R1

The Worker assigned to execute Requirement R1 must perform the following deterministic 8-step sequence:

### Step 1: Clean Build of All 14 Workspace Targets
```powershell
# 1. Clean old stale binaries in target\release
Remove-Item -Force -ErrorAction SilentlyContinue target\release\sb-ports.exe, target\release\sb-securenet.exe, target\release\sb-shadow.exe, target\release\sb-shell.exe

# 2. Build complete workspace in release mode
cargo build --release --workspace

# 3. Verify that all 11 binary executables exist
$bins = @("sb.exe", "sb-auth.exe", "sb-code.exe", "sb-db.exe", "sb-dns.exe", "sb-drive.exe", "sb-forge.exe", "sb-key.exe", "sb-mesh.exe", "sb-node.exe", "sb-proxy.exe")
foreach ($b in $bins) {
    if (-not (Test-Path "target\release\$b")) { throw "Missing binary target\release\$b" }
}
```

### Step 2: Release Keypair Generation & Pinned Trust Anchor Alignment
Per `docs/RELEASE_KEY_LIFECYCLE.md §5` ("Rotationsverfahren"):
```powershell
# 1. Create staging directory for key
New-Item -ItemType Directory -Force -Path "staging\keys"

# 2. Generate new official local release keypair
cargo run -p sb-cli -- release gen-key --output staging\keys\release.key

# 3. Inspect public key output from the command
# (e.g. Hex string and Rust array: [0xaa, 0xbb, ...])
```
- In `tools/sb/src/commands/release.rs:18-21`: Update `RELEASE_PUBLIC_KEY` with the generated 32-byte array.
- In `tools/sb/src/commands/pkg.rs:349`: Sign `b"sb-release-signing-fixture-v1"` with the new key seed and update the expected fixture signature in `release_manifest_signature_matches_the_pinned_release_key`.
- Rebuild CLI:
  `cargo build --release -p sb-cli`
- Verify key against client:
  `cargo run -p sb-cli -- release verify-key --key-file staging\keys\release.key`
  Must output: `VERIFIZIERT — Entspricht dem im Client gepinnten Produktions-Schlüssel`.

### Step 3: Package & Sign Full Suite Release (`sb release pack-all`)
```powershell
New-Item -ItemType Directory -Force -Path "staging\dist"

# Pack all 11 binaries into release zip and sign with key
cargo run -p sb-cli -- release pack-all `
    --version "0.2.0" `
    --target "x86_64-pc-windows-msvc" `
    --input-dir "target\release" `
    --output-dir "staging\dist" `
    --format "zip" `
    --key-file "staging\keys\release.key"

# Verify artifacts in staging\dist
Test-Path "staging\dist\sb-0.2.0-x86_64-pc-windows-msvc.zip"
Test-Path "staging\dist\release-manifest.json"
Test-Path "staging\dist\release-manifest.json.ed25519"
```

### Step 4: Staging Installation in Isolated `SB_HOME`
```powershell
# Create isolated staging environment
$stagingHome = "$((Get-Location).Path)\staging\sb_home"
New-Item -ItemType Directory -Force -Path $stagingHome
$env:SB_HOME = $stagingHome

# Install all tools from staging\dist
cargo run -p sb-cli -- install all --force --from-dir "staging\dist"

# Verify installed ledger and binaries
Test-Path "$stagingHome\bin\sb.exe"
Test-Path "$stagingHome\bin\sb-mesh.exe"
Test-Path "$stagingHome\installed_ledger.json"
```

### Step 5: Verification of Downgrade & Tamper Protection
```powershell
# 1. Tamper detection on installed binary
Add-Content -Path "$stagingHome\bin\sb-db.exe" -Value "evil_tamper_bytes"
# sb release verify must detect tampering!
cargo run -p sb-cli -- release verify --bin-dir "$stagingHome\bin"
# Expected: sb-db.exe marked as MANIPULIERT, exit code non-zero.

# Re-install clean to restore
cargo run -p sb-cli -- install db --force --from-dir "staging\dist"

# 2. Tamper detection on manifest signature
$sigPath = "staging\dist\release-manifest.json.ed25519"
$origSig = Get-Content $sigPath
Set-Content $sigPath -Value ("0" * 128)
# Installation must fail closed!
cargo run -p sb-cli -- install drive --force --from-dir "staging\dist"
# Expected: Error "Signaturprüfung fehlgeschlagen"
Set-Content $sigPath -Value $origSig

# 3. Downgrade Protection test
# Create mock older package v0.1.9 in staging\dist_old and try to install without --allow-downgrade
# Expected: Error "Downgrade von 0.2.0 auf 0.1.9 blockiert"
```

### Step 6: Binary Runnability Audit (All 14 Core Tools)
Execute every installed binary in `$stagingHome\bin` to confirm successful invocation and version reporting:
```powershell
& "$stagingHome\bin\sb.exe" --version
& "$stagingHome\bin\sb-auth.exe" --version
& "$stagingHome\bin\sb-code.exe" --version
& "$stagingHome\bin\sb-db.exe" --version
& "$stagingHome\bin\sb-dns.exe" --version
& "$stagingHome\bin\sb-drive.exe" --version
& "$stagingHome\bin\sb-forge.exe" --version
& "$stagingHome\bin\sb-key.exe" --version
& "$stagingHome\bin\sb-mesh.exe" --version
& "$stagingHome\bin\sb-node.exe" --version
& "$stagingHome\bin\sb-proxy.exe" --version

# Verify the 3 library products via cargo test
cargo test -p sb-core
cargo test -p sb-app-contract
cargo test -p sb-app-protocol
```

### Step 7: Update `product-inventory.json` & Sync Catalog Test
1. In `product-inventory.json`:
   Update all 14 products:
   ```json
   "maturity": "releasevalidated",
   "release_evidence": [
     "local_staging_release_pack_sign_and_execution_verified_v0.2.0"
   ]
   ```
2. In `tools/sb-core/src/catalog.rs:199`:
   Update unit test expectation:
   `&& product.maturity == ProductMaturity::Releasevalidated`
3. Remove staging directory after verification or leave documented staging log.

### Step 8: Verify Complete Suite Quality Gate
```powershell
Remove-Item Env:\SB_HOME
npm run verify:suite
```
Confirm all Cargo fmt checks, workspace checks, workspace tests, website build, and npm audits exit 0 with 0 vulnerabilities.
