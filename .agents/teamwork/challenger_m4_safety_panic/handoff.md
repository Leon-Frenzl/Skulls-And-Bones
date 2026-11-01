# Milestone 4 Adversarial Challenge Report: Operator Cockpit Safety & Panic Hardening

**Challenger**: `challenger_m4_safety_panic`  
**Date**: 2026-10-28  
**Scope**: Milestone 4 (`sb cockpit` / `sb hud`), Terminal Panic Safety (CWE-754), ANSI Sanitization (CWE-150 / CWE-116), Decoupled Background Poller (CWE-400), UTF-8 Slicing Boundary Safety (CWE-248 / CWE-125).  
**Explicit Verdict**: `REQUEST_CHANGES`

---

## 1. Observation

### 1.1 Baseline Test Execution
Executed `cargo test -p sb-cli --bin sb cockpit`:
```text
running 10 tests
test cockpit::tests::test_health_status_badges ... ok
test cockpit::tests::test_format_bytes ... ok
test cockpit::tests::test_sanitize_tui_string_control_characters ... ok
test cockpit::tests::test_sanitize_tui_string_csi_escape ... ok
test cockpit::tests::test_sanitize_tui_string_osc_escape ... ok
test cockpit::tests::test_sanitize_tui_string_preserves_valid_unicode ... ok
test cockpit::tests::test_render_snapshot_output ... ok
test cockpit::tests::test_cockpit_tab_switching ... ok
test cockpit::tests::test_cockpit_snapshot_collection_structure ... ok
test cockpit::tests::test_cockpit_app_initialization ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; finished in 0.80s
```

### 1.2 Adversarial Testing of ANSI Sanitizer (`sanitize_tui_string`)
The core function `sanitize_tui_string` was tested against adversarial attack vectors:
1. **CSI Complex Attributes & Colors**: `\x1b[38;2;255;0;0;1;4mINJECTED_RED\x1b[0m` -> Sanitized to `"INJECTED_RED"`.
2. **CSI Terminal Control / Cursor Repositioning**: `\x1b[2J\x1b[H\x1b[10;10H\x1b[?25lCLEAR_AND_HIDE\x1b[?25h` -> Sanitized to `"CLEAR_AND_HIDE"`.
3. **CSI Device Status Report**: `\x1b[5n\x1b[6nSTATUS_PROBE` -> Sanitized to `"STATUS_PROBE"`.
4. **OSC Window Title Hijacking (BEL & ST)**: `\x1b]0;MALICIOUS_TITLE\x07Peer` and `\x1b]2;MALICIOUS_TITLE\x1b\\Peer` -> Both cleanly sanitized to `"Peer"`.
5. **OSC 52 Clipboard Injection**: `\x1b]52;c;d2hvYW1p\x07SafeDisplay` -> Sanitized to `"SafeDisplay"`.
6. **OSC 8 Hyperlinks**: `\x1b]8;;http://evil.com/phish\x1b\\PhishText\x1b]8;;\x1b\\` -> Sanitized to `"PhishText"`.
7. **Truncated/Incomplete Sequences**: `"trailing\x1b"`, `"trailing_csi\x1b["`, `"trailing_osc\x1b]0;never_ends"` -> Neutralized fail-closed without panicking or hanging.
8. **C0/C1 Control Characters & DEL**: Bytes 0x00..=0x1F and 0x7F..=0x9F are filtered out (preserving only `\t` as space and `\n` as newline).
9. **Unicode Preservation**: Multi-byte emojis (`🚀`, `🦀`, `🛡️`), German Umlauts (`äöüÄÖÜß`), and CJK characters (`日本語`) are preserved intact.

### 1.3 Verified Vulnerability 1: Byte Slicing Panic on Multi-Byte UTF-8 `node_id` (CWE-248 / CWE-754 / CWE-125)
In `tools/sb/src/cockpit.rs`:
- Line 898–902 (in `render_snapshot`):
  ```rust
  let short_id = if p.node_id.len() > 14 {
      &p.node_id[..14]
  } else {
      &p.node_id
  };
  ```
- Line 1110–1114 (in `ui` / `draw_peers`):
  ```rust
  let short_id = if p.node_id.len() > 14 {
      &p.node_id[..14]
  } else {
      &p.node_id
  };
  ```

**Empirical Reproduction**:
When a registered or discovered peer provides a `node_id` containing multi-byte UTF-8 characters (e.g., German umlauts or emojis) where byte index 14 does not coincide with a character boundary (such as `"sbm-öäüß🦀foo"` where `🦀` spans byte offsets 12..16), `&p.node_id[..14]` panics immediately:
```text
thread 'cockpit::tests::test_peer_node_id_utf8_char_boundary_slicing_reproduction' (2948) panicked at tools\sb\src\cockpit.rs:899:27:
end byte index 14 is not a char boundary; it is inside '🦀' (bytes 12..16 of string)
```
- In headless `--snapshot` mode (used in CI/CD, scripting, and remote health checks), `render_snapshot` is invoked before terminal initialization. The unhandled panic causes `sb.exe cockpit --snapshot` to crash with exit code 101.
- In interactive TUI mode, `ui()` panics inside `terminal.draw()`, crashing the cockpit session.

### 1.4 Verified Vulnerability 2: Missing ANSI Sanitization on `p.node_id` and `p.overlay_ip` (CWE-150 / CWE-116)
In `tools/sb/src/cockpit.rs`:
- Line 906–912 (in `render_snapshot`):
  ```rust
  writeln!(
      out,
      "  {:<16} {:<16} {:<18} {:<8} {:<18} {}",
      sanitize_tui_string(&p.callsign),
      short_id,
      p.overlay_ip.as_deref().unwrap_or("-"),
      rtt,
      traffic,
      p.status
  )?;
  ```
- Line 1132–1139 (in `ui` / `draw_peers`):
  ```rust
  Row::new(vec![
      sanitize_tui_string(&p.callsign),
      short_id.to_string(),
      p.overlay_ip.clone().unwrap_or_else(|| "-".to_string()),
      status_badge.to_string(),
      rtt,
      traffic,
  ])
  ```
`p.callsign` is properly sanitized, but `p.node_id` (`short_id`) and `p.overlay_ip` are passed raw to `render_snapshot` and Ratatui's `Table`. If an untrusted peer injects ANSI escape sequences into `node_id` or `overlay_ip` (e.g. `\x1b[31;1m` or `\x1b]0;Hacked\x07`), they bypass sanitization.

### 1.5 Terminal Panic Hook Verification (CWE-754)
In `tools/sb/src/cockpit.rs:201-214`:
```rust
fn setup_terminal_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = crossterm::execute!(
            stdout,
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show
        );
        default_hook(panic_info);
    }));
}
```
- Hook is installed in `run_cockpit` before `enable_raw_mode()?`.
- Reliably invokes `disable_raw_mode()`, `LeaveAlternateScreen`, `DisableMouseCapture`, and `crossterm::cursor::Show`.
- Ignores I/O errors (`let _ = ...`), preventing double-panics on broken stdout pipes.
- Verified that repeated invocation chains cleanly without panic.

### 1.6 Non-Blocking Socket Probes & UI Concurrency (CWE-400)
- `SOCKET_PROBE_TIMEOUT = Duration::from_millis(150)` is strictly applied across `probe_node_daemon`, `probe_mesh_daemon`, `probe_proxy_daemon`, and `probe_dns_daemon`.
- Tested connection against dead loopback endpoints: returns within <1ms (kernel TCP RST) or <=150ms timeout.
- Architectural Concurrency Decoupling: In interactive mode, `run_cockpit` spawns a dedicated background thread `cockpit-telemetry-poller` (lines 1435–1448). The main interactive loop (`run_interactive_loop`, lines 1350–1389) only acquires a read lock on `snapshot_state` (drawing in <0.1ms) and polls keyboard input every 50ms (`event::poll(Duration::from_millis(50))`). Socket latency or daemon freezes NEVER block keystroke processing or UI frame rendering.

---

## 2. Logic Chain

```
[Untrusted WireGuard / Config Mesh Peers]
                    │
                    ▼
       [PeerSummaryPayload]
   node_id = "sbm-öäüß🦀foo"
                    │
                    ▼
     [tools/sb/src/cockpit.rs]
  Lines 898-902 & Lines 1110-1114:
  `if p.node_id.len() > 14 { &p.node_id[..14] }`
                    │
                    ▼
   [Byte Index 14 Slicing Attempt]
   Byte 14 falls at offset 2 inside 4-byte UTF-8 char '🦀' (bytes 12..16)
                    │
                    ▼
   [Panic: "end byte index 14 is not a char boundary"]
                    │
       ┌────────────┴────────────┐
       ▼                         ▼
[Headless --snapshot]     [Interactive TUI]
Panic hook NOT active     Panic hook resets terminal
Process crashes (Exit 101) Process crashes on draw
```

1. Rust slices `&str[..N]` operate strictly on byte offsets, not unicode scalar values or grapheme clusters.
2. Peer metadata is untrusted input from remote swarm participants or local peer lists.
3. Slicing at `[..14]` without checking `is_char_boundary(14)` or using `.chars().take(14)` is guaranteed to panic when international characters or emojis are present.
4. Furthermore, passing `short_id` and `p.overlay_ip` unsanitized permits ANSI escape injection into snapshot and TUI displays.
5. Because these defects directly compromise stability and terminal output sanitization in Milestone 4, the correct verdict is `REQUEST_CHANGES` with clear mitigation instructions.

---

## 3. Caveats

1. The core `sanitize_tui_string` function itself is robust and correctly strips CSI, OSC, and C0/C1 control codes while preserving valid unicode. The vulnerability lies in the calling sites where `p.node_id` and `p.overlay_ip` bypassed the sanitizer.
2. The panic hook (`setup_terminal_panic_hook`) works as designed, but is intentionally bypassed in `--snapshot` mode to keep headless executions lightweight. This makes snapshot mode particularly vulnerable to the UTF-8 slicing crash.

---

## 4. Conclusion

**Verdict**: `REQUEST_CHANGES`

Milestone 4 is 95% complete and exhibits high engineering quality in terminal panic handling, background polling decoupling, and the core ANSI sanitizer. However, before approval, the following targeted hardening changes must be implemented:

### Required Action Items for Worker (`worker_m4_cockpit`):

1. **Fix UTF-8 Slicing and Sanitize `p.node_id` in `render_snapshot` (`tools/sb/src/cockpit.rs:898–902`)**:
   Replace:
   ```rust
   let short_id = if p.node_id.len() > 14 {
       &p.node_id[..14]
   } else {
       &p.node_id
   };
   ```
   With:
   ```rust
   let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
   ```

2. **Sanitize `p.overlay_ip` in `render_snapshot` (`tools/sb/src/cockpit.rs:908`)**:
   Replace:
   ```rust
   p.overlay_ip.as_deref().unwrap_or("-"),
   ```
   With:
   ```rust
   sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
   ```

3. **Fix UTF-8 Slicing and Sanitize `p.node_id` in TUI `draw_peers` (`tools/sb/src/cockpit.rs:1110–1114`)**:
   Replace:
   ```rust
   let short_id = if p.node_id.len() > 14 {
       &p.node_id[..14]
   } else {
       &p.node_id
   };
   ```
   With:
   ```rust
   let short_id: String = sanitize_tui_string(&p.node_id).chars().take(14).collect();
   ```

4. **Sanitize `p.overlay_ip` in TUI `draw_peers` (`tools/sb/src/cockpit.rs:1135`)**:
   Replace:
   ```rust
   p.overlay_ip.clone().unwrap_or_else(|| "-".to_string()),
   ```
   With:
   ```rust
   sanitize_tui_string(p.overlay_ip.as_deref().unwrap_or("-")),
   ```

5. **Update reproduction test in `tools/sb/src/cockpit.rs:1765`**:
   Change assertion to verify that `render_snapshot` succeeds without panic (`assert!(panic_result.is_ok())`).

---

## 5. Verification Method

To verify the defect reproduction and subsequent fix:

1. **Run Unit & Adversarial Tests**:
   ```powershell
   cargo test -p sb-cli --bin sb cockpit
   ```
   Verifies that all 14 tests pass cleanly.

2. **Run Full CLI Suite**:
   ```powershell
   cargo test -p sb-cli
   ```
   Verifies that all 112 workspace CLI tests pass cleanly with 0 failures and 0 warnings.

3. **Verify Headless Snapshot Clean Exit**:
   ```powershell
   cargo run -p sb-cli -- cockpit --snapshot
   cargo run -p sb-cli -- hud --snapshot
   ```
   Both commands must print the formatted HUD snapshot and exit with code 0.
