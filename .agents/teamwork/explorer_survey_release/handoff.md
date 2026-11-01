# Handoff Report: Requirement R1 — Lokale Release-Kette & Staging-Validierung

## 1. Observation

1. **Workspace & Product Inventory Structure**:
   - `Cargo.toml:1-18`: Workspace contains 14 members (`tools/sb`, `tools/sb-code`, `tools/sb-forge`, `tools/sb-key`, `tools/sb-mesh`, `tools/sb-node`, `tools/sb-proxy`, `tools/sb-db`, `tools/sb-dns`, `tools/sb-core`, `tools/sb-app-contract`, `tools/sb-app-protocol`, `tools/sb-drive`, `tools/sb-auth`).
   - `product-inventory.json:16-338`: Exactly 14 products classified under `"products"`:
     - 11 installable CLI tools: `sb` (`sb-cli` v0.2.1), `auth` (`sb-auth` v0.2.0), `code` (`sb-code` v0.1.0), `db` (`sb-db` v0.2.0), `dns` (`sb-dns` v0.2.0), `drive` (`sb-drive` v0.2.0), `forge` (`sb-forge` v0.1.1), `key` (`sb-key` v0.1.0), `mesh` (`sb-mesh` v0.3.0), `node` (`sb-node` v0.1.0), `proxy` (`sb-proxy` v0.1.0).
     - 3 non-installable core libraries: `core` (`sb-core` v0.2.0), `app-contract` (`sb-app-contract` v0.2.0), `app-protocol` (`sb-app-protocol` v0.2.0).
     - All 14 currently declare `"maturity": "implemented_not_releasevalidated"`.
   - `scripts/verify-suite.mjs:158-250`: Validates that every product's package name and version match its `Cargo.toml`.
   - Baseline check: `npm run verify:suite` ran to completion with exit code 0 (`Suite verification passed.`, 0 vulnerabilities).

2. **`sb` CLI Release Command Implementation**:
   - `tools/sb/src/commands/release.rs:625-736`: `pack_release` validates version, target, filters release binaries, packages archive, updates `release-manifest.json`, and deletes stale `.ed25519` signature.
   - `tools/sb/src/commands/release.rs:778-942`: `pack_all_release` enforces that **all** installable products declared in `product-inventory.json` for the target are present in `input_dir` (`release.rs:838-844`). Missing binaries trigger `ReleaseError::PackagingError` fail-closed.
   - `tools/sb/src/commands/release.rs:759-776`: `sign_release_manifest` parses the 32-byte Ed25519 seed (`release.rs:1958-1982`) with memory zeroization (`zeroize::Zeroizing`). Line 768 enforces:
     ```rust
     if signing_key.verifying_key().to_bytes() != RELEASE_PUBLIC_KEY {
         return Err(ReleaseError::KeyError(
             "Signing-Key passt nicht zum im Installer gepinnten Release-Key.".to_string(),
         ));
     }
     ```
   - `tools/sb/src/commands/release.rs:18-21`: Pinned public key is hardcoded:
     ```rust
     pub const RELEASE_PUBLIC_KEY: [u8; 32] = [
         0xd4, 0x22, 0x2e, 0x09, 0x89, 0x4d, 0x85, 0x2e, 0x73, 0x18, 0xbd, 0x02, 0xde, 0xfd, 0xd1, 0xfa,
         0x63, 0xbf, 0x9b, 0x26, 0x09, 0x78, 0xa9, 0xd2, 0x4f, 0x11, 0xcc, 0x70, 0x7f, 0xd1, 0x5a, 0x8d,
     ];
     ```
   - `tools/sb/src/commands/release.rs:276-534`: `install_requested_to_dir_with_options` enforces:
     - Pre-manifest signature check: `verify_manifest_signature(&manifest_bytes, &signature_str, public_key)` (lines 393, 1571-1598).
     - Downgrade protection: SemVer comparison against `installed_ledger.json` (`release.rs:407-418`). Blocks rollback unless `allow_downgrade` is true.
     - Archive SHA-256 verification in constant time (`release.rs:474-481`, `constant_time_hex_eq:1946-1956`).
     - Safe extraction: `read_selected_binaries` (`release.rs:1778-1885`) validates `path.components().count() == 1`, file size `<= 256MB`, and exact filename match (prevents Zip Slip).
     - Atomic replacement (`release.rs:1984-2065`): writes `.sb-install-<pid>-<nonce>.tmp`, calls `sync_all()`, and on Windows executes Win32 `MoveFileExW(source, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
     - Ledger updates: atomically writes `installed_ledger.json` and copies manifest and signature to root directory.

3. **Maturity Bump Invariants in `sb-core`**:
   - `tools/sb-core/src/catalog.rs:157-164`:
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
   - `tools/sb-core/src/catalog.rs:195-200`:
     ```rust
     assert!(installable.iter().all(|product| {
         product.binary_name.is_some()
             && product.product_kind == ProductKind::CliTool
             && product.release_targets.len() == 5
             && product.maturity != ProductMaturity::Releasevalidated
     }));
     ```

4. **Staging Isolation Hook**:
   - `tools/sb-core/src/paths.rs:7-17`: `sb_home()` checks `$env:SB_HOME`. Setting `SB_HOME` redirects the entire installation directory, runtime state, and ledger tracking to an isolated staging directory.

---

## 2. Logic Chain

1. From Observation 1, the product suite is strictly consolidated into 14 core tools (11 CLI binaries, 3 libraries). The repository builds and passes verification tests cleanly.
2. From Observation 2, `sb release pack-all` requires all 11 binary targets for the current platform (`x86_64-pc-windows-msvc`) to be present in the build directory. Stale binaries from deleted tools (`sb-ports.exe`, etc.) exist in `target/release` and must be cleaned up before packaging.
3. From Observation 2, `sb release sign` and `sb install` strictly enforce Ed25519 signing against `RELEASE_PUBLIC_KEY`. Per `docs/RELEASE_KEY_LIFECYCLE.md §2`, the private production seed is not stored in the repository. Per `docs/RELEASE_KEY_LIFECYCLE.md §5` (Rotationsverfahren), performing a verifiable release build and signature requires generating an official local keypair (`sb release gen-key`), updating the pinned constant in `release.rs:18-21`, and updating the signing test fixture in `pkg.rs:349`.
4. From Observation 2 and 4, setting `SB_HOME=<staging_path>` allows running `sb install all --from-dir <dist>` in complete isolation, testing atomic installation, tamper detection (`sb release verify`), and downgrade protection without polluting the user's host environment.
5. From Observation 3, upgrading the maturity of the 14 products in `product-inventory.json` from `implemented_not_releasevalidated` to `releasevalidated` requires populating `"release_evidence"` on all 14 entries and updating line 199 in `tools/sb-core/src/catalog.rs` to assert `== ProductMaturity::Releasevalidated`. Without both, either catalog validation fails or unit tests fail.

---

## 3. Caveats

1. **Host-Specific Target Validation**:
   - The local workstation environment is `x86_64-pc-windows-msvc`. Binaries can be built and executed natively for Windows x86_64. Cross-compilation to Linux musl or Apple Darwin targets requires external cross-toolchains (`cross` or musl/osxcross), which are not validated in this local run.
2. **Read-Only Explorer Constraint**:
   - In accordance with agent constraints, no repository files or source codes were altered. All proposals and step-by-step plans are packaged in `report.md` for the implementing Worker.

---

## 4. Conclusion

Requirement R1 is completely mapped, fully designed, and ready for immediate implementation by a Worker:
1. `sb` CLI contains an enterprise-grade, cryptographically hardened release and installation subsystem with Ed25519 signature verification, SHA-256 checksum checks, Win32 `MoveFileExW` atomic installation, Zip-Slip prevention, and SemVer downgrade protection.
2. The Worker execution plan provides an exact 8-step recipe:
   - Clean stale binaries and build all 14 crates via `cargo build --release --workspace`.
   - Generate local release keypair and align pinned trust anchor in `release.rs` and `pkg.rs`.
   - Run `sb release pack-all` to produce signed archive and manifest.
   - Run `sb install` into isolated `$env:SB_HOME` staging directory.
   - Verify tamper rejection (checksum + signature) and downgrade rejection fail-closed.
   - Verify binary execution for all 11 CLI tools and test execution for the 3 libraries.
   - Update `product-inventory.json` with `maturity: "releasevalidated"` and `"release_evidence"`, and update catalog unit test in `sb-core`.
   - Run `npm run verify:suite` to confirm 100% green status.

---

## 5. Verification Method

1. **Suite Baseline**:
   ```bash
   npm run verify:suite
   ```
2. **Release Key Verification**:
   ```bash
   cargo run -p sb-cli -- release verify-key --key-file <key_path>
   ```
3. **Staging Packaging & Verification**:
   ```bash
   cargo run -p sb-cli -- release pack-all --version "0.2.0" --input-dir "target/release" --output-dir "staging/dist" --format "zip" --key-file "<key_path>"
   cargo run -p sb-cli -- release verify --bin-dir "staging/sb_home/bin"
   ```
4. **Invalidation Conditions**:
   - If `cargo test -p sb-core` fails, check if `release_evidence` was omitted in `product-inventory.json` or if line 199 of `catalog.rs` was not updated.
   - If `sb release pack-all` fails, check if all 11 binaries exist in the input directory.
   - If `sb install` fails signature verification, check if `RELEASE_PUBLIC_KEY` in `release.rs` matches the public key of the signing key.
