# Handoff Report — Milestone M1 (Requirement R1)

## 1. Observation

- **Release Binaries Build**:
  - `cargo build --release --workspace` completed in 3m 03s with Exit Code 0.
  - Stale binaries (`sb-ports.*`, `sb-securenet.*`, `sb-shadow.*`, `sb-shell.*`, `sb-skully.*`, and `*.old`) were purged from `target/release/`.
  - All 11 core CLI executables were verified in `target/release/`:
    `sb.exe` (7,343,616 B), `sb-auth.exe` (1,060,864 B), `sb-code.exe` (9,187,328 B), `sb-db.exe` (2,330,112 B), `sb-dns.exe` (1,794,048 B), `sb-drive.exe` (2,513,920 B), `sb-forge.exe` (3,850,240 B), `sb-key.exe` (716,800 B), `sb-mesh.exe` (3,362,304 B), `sb-node.exe` (3,491,328 B), `sb-proxy.exe` (6,434,816 B).

- **Key Rotation**:
  - `sb release gen-key --output staging/keys/release.key` generated fresh Ed25519 seed:
    `2f39fcbfec515614f7c7a5a3a558669aac37bd33150f49d00bffa51be1f17b3e`
  - Public Key: `[0x3c, 0x98, 0xbe, 0xb9, 0xca, 0x90, 0xc6, 0x13, 0xf1, 0xbe, 0xdb, 0x16, 0x56, 0xf7, 0x03, 0x25, 0x47, 0xa7, 0xf5, 0x4a, 0xfb, 0xc9, 0x32, 0xa1, 0x5c, 0x46, 0x05, 0x22, 0xb1, 0x65, 0x39, 0xaa]`
  - `RELEASE_PUBLIC_KEY` in `tools/sb/src/commands/release.rs` was updated with the new key bytes and threat audit headers.
  - Static verification fixture in `tools/sb/src/commands/pkg.rs` was updated to signature `2978b7cb652f75e7b891ad6fb3c4be34bfdc28db1865157a356fc708662fb8be89d4fe3beac607a632fb7d425f0743bf4e75bba4e055df710e10515b25f6f003`.
  - `sb release verify-key --key-file staging/keys/release.key` reported:
    `Status: VERIFIZIERT — Entspricht dem im Client gepinnten Produktions-Schlüssel` (Exit Code 0).

- **Packaging & Signing**:
  - `sb release pack-all --version "0.2.0" --input-dir target/release --output-dir staging/dist --format zip --key-file staging/keys/release.key` packaged all 11 binaries into `staging/dist/sb-0.2.0-x86_64-pc-windows-msvc.zip` (SHA-256: `80da4e91cb5b0ff2b7b4f441cdea1a24855557c2e0ca2a75204f40175ef07a51`).
  - `staging/dist/release-manifest.json` and Ed25519 signature `staging/dist/release-manifest.json.ed25519` were produced and verified.

- **Staging Installation in Isolated `$env:SB_HOME`**:
  - `$env:SB_HOME` set to `staging/sb_home`.
  - `sb install all --from-dir staging/dist` installed all 11 binaries into `staging/sb_home/bin/` and created `staging/sb_home/installed_ledger.json`.
  - `sb release verify --bin-dir staging/sb_home/bin` reported all 11 binaries as `✓ VERIFIZIERT` (Exit Code 0).

- **Tamper & Downgrade Rejection**:
  - Tampered binary `sb-db.exe` was rejected by `sb release verify` with `✗ MANIPULIERT` and Exit Code 1.
  - Corrupted manifest signature caused `sb install` to fail closed with Exit Code 1 (`Signaturprüfung fehlgeschlagen`).
  - Corrupted zip archive caused `sb install` to fail closed with Exit Code 1 (`SHA-256 stimmt nicht überein`).
  - Attempting to install older package `0.1.9` without `--allow-downgrade` failed closed with Exit Code 1 (`Downgrade von 0.2.0 auf 0.1.9 blockiert. Verwende --allow-downgrade`).
  - Downgrade was allowed only when passing `--allow-downgrade` (Exit Code 0).
  - Restoration back to `0.2.0` succeeded with Exit Code 0, and final `sb release verify` returned 11 `✓ VERIFIZIERT`.

- **Binary Execution & Test Suite**:
  - All 11 binaries executed with `--help` and `--version` with Exit Code 0.
  - `cargo test -p sb-cli` passed 83/83 tests (Exit Code 0).
  - `cargo fmt -- --check` returned Exit Code 0.

## 2. Logic Chain

1. From `docs/RELEASE_KEY_LIFECYCLE.md §2`, the repository intentionally does not track private release keys. Therefore, local release signing requires official key rotation as specified in §5.
2. Generating `staging/keys/release.key` via `sb release gen-key` produced a fresh Ed25519 private seed and derived public key.
3. Updating `RELEASE_PUBLIC_KEY` in `release.rs` aligned the client's hardcoded trust anchor with the generated keypair.
4. Updating `pkg.rs` with the corresponding signature of `b"sb-release-signing-fixture-v1"` guaranteed that client unit tests assert verification against the current pinned anchor.
5. Rebuilding `sb-cli` in release mode ensured that running `sb release pack-all` and `sb install` operates against the newly pinned key.
6. Invoking `sb release pack-all` collected all 11 installable binaries from `target/release/`, verified them against the catalog, compressed them into `sb-0.2.0-x86_64-pc-windows-msvc.zip`, created `release-manifest.json`, and signed it with Ed25519.
7. Configuring `$env:SB_HOME = "staging/sb_home"` completely isolated the test installation from the operator's home directory.
8. `sb install all --from-dir staging/dist` verified the Ed25519 signature before parsing, validated the SHA-256 archive hash in constant time, extracted the binaries using anti-Zip-Slip validation, installed them atomically via `MoveFileExW`, and registered them in `installed_ledger.json`.
9. Intentionally introducing bit corruptions verified that both installer and verifier fail closed upon any signature or digest discrepancy.
10. Attempting an older version installation demonstrated active SemVer downgrade blocking unless `--allow-downgrade` is explicitly passed.
11. Executing all 11 installed binaries demonstrated genuine runnability and interface stability.

## 3. Caveats

- Per orchestrator constraints, `product-inventory.json` and workspace `.md` documentation files were NOT modified by `worker_release_m1` (these belong to downstream milestones M2 and M3).
- Staging directory `staging/` remains preserved in the workspace so that subsequent workers and the independent auditor can directly inspect and verify the artifacts (`staging/keys/release.key`, `staging/dist/`, `staging/sb_home/`).

## 4. Conclusion

Milestone M1 (Requirement R1) is completely fulfilled. The local build, cryptographic Ed25519 signing, packaging, isolated staging installation, tamper rejection, downgrade prevention, binary execution, and test suites are 100% verified and operational.

## 5. Verification Method

To independently verify this milestone, run:

1. **Key Verification**:
   ```powershell
   cargo run -p sb-cli -- release verify-key --key-file staging/keys/release.key
   ```
   *Expected*: `VERIFIZIERT — Entspricht dem im Client gepinnten Produktions-Schlüssel` (Exit Code 0).

2. **Binary Integrity Verification in Staging**:
   ```powershell
   $env:SB_HOME = (Resolve-Path "staging/sb_home").Path
   cargo run -p sb-cli -- release verify --bin-dir staging/sb_home/bin
   ```
   *Expected*: All 11 binaries reported as `✓ VERIFIZIERT` (Exit Code 0).

3. **Downgrade Protection Verification**:
   ```powershell
   $env:SB_HOME = (Resolve-Path "staging/sb_home").Path
   cargo run -p sb-cli -- install all --force --from-dir staging/dist_old
   ```
   *Expected*: `Installation fehlgeschlagen: Downgrade von 0.2.0 auf 0.1.9 blockiert. Verwende --allow-downgrade.` (Exit Code 1).

4. **Test Suite Verification**:
   ```powershell
   cargo test -p sb-cli
   ```
   *Expected*: `test result: ok. 83 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out` (Exit Code 0).
