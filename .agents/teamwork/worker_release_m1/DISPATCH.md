## 2026-10-26T18:08:27Z

You are worker_release_m1, a teamwork_preview_worker agent.
Your working directory is: c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/worker_release_m1/
You must read the original user request at: c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/ORIGINAL_REQUEST.md
Also read the explorer report at: c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/explorer_survey_release/report.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Scope & Exclusive File Ownership:
You own `tools/sb/src/commands/release.rs`, `tools/sb/tests/pkg.rs`, and staging directories under `staging/`.
DO NOT edit `product-inventory.json` or `.md` documentation files (those belong to M2 and M3).

Your Mission (Milestone M1 — Requirement R1):
1. Build release binaries:
   Run `cargo build --release --workspace`. Ensure all 11 installable CLI binaries exist in `target/release/` (`sb.exe`, `auth.exe`, `code.exe`, `db.exe`, `dns.exe`, `drive.exe`, `forge.exe`, `key.exe`, `mesh.exe`, `node.exe`, `proxy.exe`). Remove any stale deleted binaries from `target/release/` if present.
2. Release Key Rotation & Pinned Anchor Sync:
   - Generate a fresh Ed25519 release keypair using `cargo run -p sb-cli -- release gen-key --output staging/keys/release.key`.
   - Update `RELEASE_PUBLIC_KEY` in `tools/sb/src/commands/release.rs` and the test fixture in `tools/sb/tests/pkg.rs` with the generated public key bytes.
   - Verify the key using `cargo run -p sb-cli -- release verify-key --key-file staging/keys/release.key`.
3. Release Packaging & Signing:
   - Run `cargo run -p sb-cli -- release pack-all --version "0.2.0" --input-dir target/release --output-dir staging/dist --format zip --key-file staging/keys/release.key`.
   - Verify that all 11 archives, `release-manifest.json`, and `release-manifest.json.ed25519` are produced.
4. Staging Installation in Isolated `$env:SB_HOME`:
   - Set `$env:SB_HOME = (Resolve-Path "staging/sb_home").Path` (ensure directory exists).
   - Run `cargo run -p sb-cli -- install all --from-dir staging/dist`.
   - Verify atomic extraction and ledger creation in `staging/sb_home`.
   - Verify binary hashes with `cargo run -p sb-cli -- release verify --bin-dir staging/sb_home/bin`.
5. Downgrade & Tamper Protection Validation:
   - Verify tamper rejection: Corrupt a byte in an archive or signature and confirm `sb install` / `sb release verify` fails closed.
   - Verify downgrade protection: Attempt to install an older version without `--allow-downgrade` and confirm it is rejected fail-closed.
6. Execution Verification:
   - Execute all 11 installed CLI binaries in `staging/sb_home/bin` (`sb.exe --help`, `auth.exe --help`, etc.) and record outputs and exit codes.
   - Run `cargo test -p sb-cli` to ensure release tests pass with the rotated key.
7. Write your full report with all command outputs and evidence to `c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/worker_release_m1/report.md` and write `handoff.md`. Send completion message when done.
