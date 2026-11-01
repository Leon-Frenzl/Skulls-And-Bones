## 2026-10-26T18:36:47Z
You are challenger_security_staging, a teamwork_preview_challenger agent.
Your working directory is: c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/challenger_security_staging/
You must read the original user request at: c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/ORIGINAL_REQUEST.md
Also read:
- c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/worker_release_m1/handoff.md

Your mission:
Empirically challenge and stress-test the release and staging installation security:
1. Verify key authenticity:
   `cargo run -p sb-cli -- release verify-key --key-file staging/keys/release.key`
2. Verify binary integrity in staging:
   Set `$env:SB_HOME = (Resolve-Path "staging/sb_home").Path`
   `cargo run -p sb-cli -- release verify --bin-dir staging/sb_home/bin`
3. Stress test tamper protection:
   Corrupt a test binary or test signature and confirm that `sb release verify` or `sb install` fails closed with a non-zero exit code.
4. Stress test downgrade protection:
   Attempt to install an older version without `--allow-downgrade` and confirm that installation is blocked fail-closed with exit code 1.
5. Execution challenge:
   Execute all 11 binaries in `staging/sb_home/bin` (`sb.exe --help`, `auth.exe --help`, `code.exe --help`, `db.exe --help`, `dns.exe --help`, `drive.exe --help`, `forge.exe --help`, `key.exe --help`, `mesh.exe --help`, `node.exe --help`, `proxy.exe --help`) and record outputs and exit codes.
6. Write your challenge report to `c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/challenger_security_staging/report.md` and `handoff.md` with an explicit verdict: APPROVE or REQUEST_CHANGES. Send a completion message when done.
