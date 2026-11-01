## 2026-10-28T02:26:44Z
You are worker_m4_remediation.
Your working directory is:
C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m4_remediation

Read:
- C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\ORIGINAL_REQUEST.md
- C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\challenger_m4_safety_panic\handoff.md
- C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\orchestrator_3\PROJECT.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Context:
Milestone 4 (`sb cockpit` / `sb hud`) is 95% complete and approved by 4 verifiers, but `challenger_m4_safety_panic` identified two critical vulnerabilities:
1. Vulnerability 1 — UTF-8 Slicing Panic (CWE-248 / CWE-754 / CWE-125):
   In `tools/sb/src/cockpit.rs` lines 898–902 (in `render_snapshot`) and lines 1110–1114 (in `ui` / `draw_peers`), `&p.node_id[..14]` byte-slices `p.node_id` without char-boundary awareness. If `node_id` contains multi-byte UTF-8 (e.g. `sbm-öäüß🦀foo`), it panics with `end byte index 14 is not a char boundary`. In headless `--snapshot` mode, this crashes the CLI with exit code 101.
2. Vulnerability 2 — Missing ANSI Sanitization on Peer Metadata (CWE-150 / CWE-116):
   `p.node_id` (`short_id`) and `p.overlay_ip` bypass `sanitize_tui_string` in both `render_snapshot` and TUI table rows (`draw_peers`).

Write Ownership:
You exclusively own `tools/sb/src/cockpit.rs`. Do not edit other files unless strictly necessary.

Required Implementation Actions:
1. In `render_snapshot` (`tools/sb/src/cockpit.rs`):
   Replace:
   ```rust
   let short_id = if p.node_id.len() > 14 {
       &p.node_id[..14]
   } else {
       &p.node_id
   };
   ```
   with:
   ```rust
   let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
   ```
   And sanitize `p.overlay_ip`:
   ```rust
   sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
   ```
2. In TUI `draw_peers` (`tools/sb/src/cockpit.rs`):
   Replace:
   ```rust
   let short_id = if p.node_id.len() > 14 {
       &p.node_id[..14]
   } else {
       &p.node_id
   };
   ```
   with:
   ```rust
   let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
   ```
   And sanitize `p.overlay_ip`:
   ```rust
   sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
   ```
3. Update/add a unit test in `tools/sb/src/cockpit.rs` (in `mod tests`) testing:
   - `test_peer_node_id_utf8_char_boundary_slicing_reproduction`: verify that `render_snapshot` succeeds without panic when a peer has `node_id: "sbm-öäüß🦀foo"` and multi-byte ANSI sequences.
4. Run verification commands:
   - `cargo check --workspace` (must be 0 errors, 0 warnings)
   - `cargo test -p sb-cli --bin sb cockpit` (all tests must pass)
   - `cargo test -p sb-cli` (all tests must pass)
   - `cargo run -p sb-cli -- cockpit --snapshot`
   - `cargo run -p sb-cli -- hud --snapshot`
5. Write your handoff report to:
   `C:\Users\leonf\Documents\Projekte\Skulls-And-Bones\.agents\teamwork\worker_m4_remediation\handoff.md`
   and send a completion message back to the orchestrator.
