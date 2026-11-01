# Forensic Audit Report: Milestone 4 Remediation (`sb cockpit` / `sb hud`)

**Work Product**: `tools/sb/src/cockpit.rs` and related test suites  
**Auditor**: `auditor_m4_r2`  
**Date**: 2026-10-28  
**Profile**: General Project  
**Integrity Mode**: Development (conforming to `ORIGINAL_REQUEST.md`)  
**Verdict**: **CLEAN**

---

## Forensic Audit Summary

| Mandatory Check | Target / Function | Result | Details |
|---|---|:---:|---|
| **Check 1: Zero hardcoded test strings or dummy facades** | `tools/sb/src/cockpit.rs` | **PASS** | No test strings ("adversary", "sbm-öäüß🦀foo", "hacked") exist in production logic. Zero dummy stubs or bypass checks. |
| **Check 2: Universal char-boundary slicing & ANSI sanitization** | `render_snapshot` & `render_mesh_peers_panel` | **PASS** | `.chars().take(14).collect::<String>()` and `sanitize_tui_string` are applied uniformly to all peer rows in both snapshot and TUI table. |
| **Check 3: Workspace compilation hygiene** | `cargo check --workspace --all-targets` | **PASS** | Exited 0 with exactly 0 compiler errors and 0 warnings. |
| **Check 4: Cockpit test suite execution** | `cargo test -p sb-cli --bin sb cockpit` | **PASS** | Exited 0 with 14 passed; 0 failed; 0 ignored. |

---

## 5-Component Handoff Report

### 1. Observation

#### 1.1 Source Code Verification (`tools/sb/src/cockpit.rs`)
- **`render_snapshot`** (lines 889–910):
  ```rust
  for p in &snapshot.peers {
      let rtt = p
          .rtt_ms
          .map(|r| format!("{:.0}ms", r))
          .unwrap_or_else(|| "-".to_string());
      let traffic = format!(
          "{} / {}",
          format_bytes(p.bytes_sent),
          format_bytes(p.bytes_recv)
      );
      let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
      writeln!(
          out,
          "  {:<16} {:<16} {:<18} {:<8} {:<18} {}",
          sanitize_tui_string(&p.callsign),
          short_id,
          sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
          rtt,
          traffic,
          p.status
      )?;
  }
  ```
- **`render_mesh_peers_panel`** (lines 1107–1147):
  ```rust
  snap.peers
      .iter()
      .enumerate()
      .map(|(i, p)| {
          let style = if i == selected {
              Style::default()
                  .fg(Color::Black)
                  .bg(Color::Cyan)
                  .add_modifier(Modifier::BOLD)
          } else {
              Style::default().fg(Color::White)
          };
          let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
          let rtt = p
              .rtt_ms
              .map(|r| format!("{:.0}ms", r))
              .unwrap_or_else(|| "-".to_string());
          let traffic = format!(
              "{} / {}",
              format_bytes(p.bytes_sent),
              format_bytes(p.bytes_recv)
          );
          let status_badge = if p.status == "ONLINE" {
              "● ONLINE"
          } else if p.status == "STANDBY" {
              "▲ STANDBY"
          } else {
              "✖ OFFLINE"
          };

          Row::new(vec![
              sanitize_tui_string(&p.callsign),
              short_id,
              sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
              status_badge.to_string(),
              rtt,
              traffic,
          ])
          .style(style)
      })
      .collect()
  ```
- **Zero Bypass Branches or String Constants**:
  - A comprehensive search across `tools/sb/src` confirmed that strings such as `"adversary"`, `"sbm-öäüß🦀foo"`, and `"hacked"` exist solely inside the unit test `test_peer_node_id_utf8_char_boundary_slicing_reproduction` (lines 1770–1830).
  - No string equality checks (`== "adversary"`, `contains("öäüß")`) exist anywhere in production logic.
  - No raw byte slicing `&str[..14]` exists in `tools/sb/src/cockpit.rs`. The only `[..` usages are standard byte buffer slices (`&buf[..n]`, `&chunk[..n]`) for network I/O.

#### 1.2 Tool Execution Results

1. **`cargo check --workspace --all-targets`**:
   - Exit code: `0`
   - Output:
     ```text
     Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.61s
     ```
   - Errors: `0`, Warnings: `0`.

2. **`cargo test -p sb-cli --bin sb cockpit`**:
   - Exit code: `0`
   - Output:
     ```text
     running 14 tests
     test cockpit::tests::test_adversarial_ansi_sanitization_comprehensive ... ok
     test cockpit::tests::test_format_bytes ... ok
     test cockpit::tests::test_panic_hook_registration_safety ... ok
     test cockpit::tests::test_health_status_badges ... ok
     test cockpit::tests::test_sanitize_tui_string_control_characters ... ok
     test cockpit::tests::test_sanitize_tui_string_csi_escape ... ok
     test cockpit::tests::test_sanitize_tui_string_osc_escape ... ok
     test cockpit::tests::test_sanitize_tui_string_preserves_valid_unicode ... ok
     test cockpit::tests::test_render_snapshot_output ... ok
     test cockpit::tests::test_peer_node_id_utf8_char_boundary_slicing_reproduction ... ok
     test cockpit::tests::test_adversarial_socket_probe_timeouts ... ok
     test cockpit::tests::test_cockpit_app_initialization ... ok
     test cockpit::tests::test_cockpit_snapshot_collection_structure ... ok
     test cockpit::tests::test_cockpit_tab_switching ... ok

     test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 98 filtered out; finished in 0.80s
     ```

3. **Live Headless Executions**:
   - `cargo run -p sb-cli -- cockpit --snapshot`: Exited `0`, successfully rendered full ASCII HUD table with active registered peer (`hostinger-anchor`, `peer-KzPz8UJ4`, `10.240.0.1`).
   - `cargo run -p sb-cli -- hud --snapshot`: Exited `0`, alias functionally identical to `cockpit --snapshot`.

4. **Broader Regression Suite**:
   - `cargo test -p sb-cli`: Exited `0`, 112 passed; 0 failed.
   - `cargo test -p sb-ca`: Exited `0`, 15 passed (including `e2e_ssh_ca` and `e2e_x509_ca`).

---

### 2. Logic Chain

1. **Integrity Violation Analysis**:
   - A work product violates integrity if it uses hardcoded outputs, fake facades, or conditional bypasses tailored specifically to make a test pass without genuine logic.
   - Observation 1.1 proves that `tools/sb/src/cockpit.rs` contains zero test-specific strings or bypass branches in production code. The rendering logic operates identically on any input data.
2. **UTF-8 Char-Boundary Safety (CWE-248 / CWE-754 / CWE-125)**:
   - In Rust, indexing a string by byte count (e.g., `&p.node_id[..14]`) will panic at runtime if index 14 falls within a multi-byte UTF-8 character (such as 4-byte emoji or 2-byte accented characters).
   - In both `render_snapshot` and `render_mesh_peers_panel`, the code replaces byte slicing with `.chars().take(14).collect::<String>()`. This guarantees that truncation occurs on Unicode scalar boundaries, eliminating the panic condition.
3. **ANSI Injection Defense (CWE-150 / CWE-116)**:
   - Malicious peers can supply arbitrary UTF-8 strings containing VT100/ECMA-48 escape codes (CSI/OSC), which can manipulate cursor positions, alter colors, or inject terminal titles.
   - Observation 1.1 proves that `sanitize_tui_string` is uniformly invoked across all peer fields (`callsign`, `node_id`, `overlay_ip`) in both output paths (`render_snapshot` for CLI streams and `render_mesh_peers_panel` for the interactive Ratatui widget).
4. **Compilation and Test Suite Hygiene**:
   - `cargo check --workspace --all-targets` verified 0 warnings and 0 errors across all workspace crates and targets.
   - All unit and integration tests executed cleanly and authentically.

---

### 3. Caveats

No caveats. All checks were verified independently through direct file inspection and clean empirical CLI tool runs without relying on cached logs or prior assertions.

---

### 4. Conclusion

The remediation performed by `worker_m4_remediation` on `tools/sb/src/cockpit.rs` is genuine, complete, and architecturally robust. Zero hardcoded bypasses or dummy facades exist. Char-boundary slicing and ANSI sanitization are universally applied across both headless snapshot and interactive Ratatui rendering surfaces. All workspace targets compile cleanly, and all cockpit tests pass.

**Final Verdict**: **CLEAN**

---

### 5. Verification Method

To independently reproduce the forensic audit findings:

```powershell
# 1. Compilation check (must produce 0 errors, 0 warnings)
cargo check --workspace --all-targets

# 2. Cockpit unit & adversarial test suite (must report 14 passed)
cargo test -p sb-cli --bin sb cockpit

# 3. Headless snapshot live execution (must exit 0 and render HUD)
cargo run -p sb-cli -- cockpit --snapshot
cargo run -p sb-cli -- hud --snapshot

# 4. Full CLI test suite (must report 112 passed)
cargo test -p sb-cli
```
