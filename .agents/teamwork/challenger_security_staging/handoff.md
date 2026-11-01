# Handoff Report — Challenger Security & Staging

**Agent**: `challenger_security_staging`  
**Milestone**: Release & Staging Installation Security (Requirement R1)  
**Verdict**: **APPROVE**  
**Date**: 2026-10-26

---

## 1. Observation

Direct empirical observations recorded during adversarial testing:

- **Key Authenticity Verification**:
  - Command: `cargo run -p sb-cli -- release verify-key --key-file staging/keys/release.key`
  - Output verbatim:
    ```
    ► RELEASE-SCHLÜSSEL VALIDIERUNG [KEY-AUDIT]
    Schlüsseldatei:               staging/keys/release.key
    Format:                       Gültiger Ed25519 Private Seed
    Public Key (Hex):             3c98beb9ca90c613f1bedb1656f7032547a7f54afbc932a15c460522b16539aa
    Public Key (Rust Array):      [0x3c, 0x98, 0xbe, 0xb9, 0xca, 0x90, 0xc6, 0x13, 0xf1, 0xbe, 0xdb, 0x16, 0x56, 0xf7, 0x03, 0x25, 0x47, 0xa7, 0xf5, 0x4a, 0xfb, 0xc9, 0x32, 0xa1, 0x5c, 0x46, 0x05, 0x22, 0xb1, 0x65, 0x39, 0xaa];
    Status:                       VERIFIZIERT — Entspricht dem im Client gepinnten Produktions-Schlüssel
    ```
  - Exit code: `0`.
  - Malformed key (`staging/keys/invalid.key`): Fails closed with Exit Code `1` and error:
    `Schlüsselprüfung fehlgeschlagen: Schlüsselfehler: Signing-Key muss 32 rohe Bytes oder 64 Hex-Zeichen enthalten.`

- **Binary Integrity Verification in Staging**:
  - Environment: `$env:SB_HOME = (Resolve-Path "staging/sb_home").Path`
  - Command: `cargo run -p sb-cli -- release verify --bin-dir staging/sb_home/bin`
  - Output verbatim:
    All 11 suite binaries (`sb-auth.exe`, `sb-code.exe`, `sb-db.exe`, `sb-dns.exe`, `sb-drive.exe`, `sb-forge.exe`, `sb-key.exe`, `sb-mesh.exe`, `sb-node.exe`, `sb-proxy.exe`, `sb.exe`) reported as `✓ VERIFIZIERT` against release version `0.2.0 (Signatur: GÜLTIG (Ed25519 Pinning))`.
  - Exit code: `0`.

- **Tamper Protection Fail-Closed Stress Tests**:
  - Modified binary `staging/sb_home/bin/sb-db.exe` (appended 6 bytes):
    `sb release verify --bin-dir staging/sb_home/bin` reported `sb-db.exe ✗ MANIPULIERT 06f0f55e8a55` and exited with Exit Code `1`.
  - Corrupted Ed25519 manifest signature:
    `sb install all --force --from-dir staging/dist_tampered_sig` rejected install with Exit Code `1` and verbatim error:
    `Installation fehlgeschlagen: Signaturprüfung fehlgeschlagen: Ed25519-Signaturprüfung des Release-Manifests fehlgeschlagen.`
  - Corrupted zip payload archive:
    `sb install all --force --from-dir staging/dist_tampered_zip` rejected install with Exit Code `1` and verbatim error:
    `Installation fehlgeschlagen: SHA-256 stimmt nicht überein für 'sb-0.2.0-x86_64-pc-windows-msvc.zip'...`
  - Unauthorized key signing attempt:
    `sb release sign --manifest ... --key-file staging/keys/attacker.key` rejected signing with Exit Code `1` and verbatim error:
    `Release-Signierung fehlgeschlagen: Schlüsselfehler: Signing-Key passt nicht zum im Installer gepinnten Release-Key.`

- **Downgrade Protection Stress Test**:
  - Command: `cargo run -p sb-cli -- install all --force --from-dir staging/dist_old`
  - Output verbatim:
    `Installation fehlgeschlagen: Downgrade von 0.2.0 auf 0.1.9 blockiert. Verwende --allow-downgrade.`
  - Exit code: `1` (Fail-closed).
  - Explicit bypass with `--allow-downgrade` succeeded with Exit Code `0`. Re-upgrade to `0.2.0` succeeded with Exit Code `0` and re-established clean verified state.

- **Binary Execution Challenge**:
  - All 11 alias executables in `staging/sb_home/bin` (`sb.exe`, `auth.exe`, `code.exe`, `db.exe`, `dns.exe`, `drive.exe`, `forge.exe`, `key.exe`, `mesh.exe`, `node.exe`, `proxy.exe`) executed with `--help` and returned Exit Code `0`.
  - All 11 full executables (`sb-*.exe`) executed with `--version` and returned Exit Code `0`.
  - Deployed `sb.exe` directly executed `release verify` without cargo, returning Exit Code `0`.

- **Regression & Suite Tests**:
  - `cargo test -p sb-cli` passed 83/83 tests with Exit Code `0`.

---

## 2. Logic Chain

1. **Observation 1** proves that `staging/keys/release.key` is mathematically identical to the public key bytes `[0x3c, 0x98, ... 0xaa]` hardcoded as `RELEASE_PUBLIC_KEY` in `tools/sb/src/commands/release.rs:26`. Any deviation or invalid format is rejected.
2. **Observation 2** proves that the binaries in `staging/sb_home/bin` match the cryptographically signed `installed_ledger.json` and release manifest, and the manifest is signed by the pinned production key.
3. **Observation 3** proves that bit flipping in binaries, signatures, or zip payload causes immediate fail-closed termination with non-zero exit codes. The installer and verifier never fall back to trusting unverified inputs.
4. **Observation 4** proves that SemVer downgrade prevention is active and strictly halts attempts to install older releases unless explicitly overridden by the operator.
5. **Observation 5** proves that all 11 binaries are functional PE32+ executables capable of starting, parsing CLI flags, and terminating cleanly without crashes, memory faults, or missing DLLs.
6. **Observation 6** confirms that the underlying unit and integration test suite remains completely green (83 passed, 0 failed).

Therefore, Milestone M1 meets all requirements of R1 and all security criteria are empirically satisfied.

---

## 3. Caveats

- Tests were conducted locally on Windows MSVC x86_64; Linux/macOS cross-target package extraction is validated via cargo unit tests (`commands::release::tests::pack_and_extract_only_named_binaries_from_both_formats`), but native execution of ELF/Mach-O binaries cannot run on the Windows host.
- No caveats regarding Windows release artifacts or staging security mechanisms.

---

## 4. Conclusion

**Verdict: APPROVE**

The release and staging artifacts are validated without defect. The release pipeline, Ed25519 signatures, SHA-256 integrity checks, downgrade guards, and executable runnability meet sovereign engineering standards. Milestone M1 can be accepted and downstream milestones (M2 inventory & documentation, M3 quality gates) may proceed.

---

## 5. Verification Method

To reproduce and verify these findings independently:

1. **Key Verification**:
   ```powershell
   cargo run -p sb-cli -- release verify-key --key-file staging/keys/release.key
   ```
   *Expected*: Exit Code `0`, Status `VERIFIZIERT`.

2. **Binary Integrity Verification**:
   ```powershell
   $env:SB_HOME = (Resolve-Path "staging/sb_home").Path
   cargo run -p sb-cli -- release verify --bin-dir staging/sb_home/bin
   ```
   *Expected*: Exit Code `0`, all 11 binaries `✓ VERIFIZIERT`.

3. **Tamper Test**:
   ```powershell
   [System.IO.File]::AppendAllText("staging/sb_home/bin/sb-db.exe", "BAD")
   $env:SB_HOME = (Resolve-Path "staging/sb_home").Path
   cargo run -p sb-cli -- release verify --bin-dir staging/sb_home/bin
   # Assert $LASTEXITCODE -eq 1
   ```

4. **Downgrade Test**:
   ```powershell
   $env:SB_HOME = (Resolve-Path "staging/sb_home").Path
   cargo run -p sb-cli -- install all --force --from-dir staging/dist_old
   # Assert $LASTEXITCODE -eq 1
   ```

5. **Binary Execution**:
   ```powershell
   & "staging/sb_home/bin/sb.exe" release verify --bin-dir "staging/sb_home/bin"
   # Assert $LASTEXITCODE -eq 0
   ```
