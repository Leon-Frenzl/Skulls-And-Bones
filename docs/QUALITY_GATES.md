# Suite Quality Gates

The entire Skulls & Bones workspace is validated continuously using the suite verification script:

```bash
npm run verify:suite
```

The verifier fails immediately if any step fails (fail-closed). It covers:

1. **Rust Code Formatting**: Ensures all workspace code adheres to formatting guidelines (`cargo fmt --all -- --check`).
2. **Root Workspace Compilation**: Validates compilation across all 14 core tools and shared crates (`cargo check --workspace`).
3. **Automated Test Suite**: Executes all unit and integration tests across the entire Cargo workspace (`cargo test --workspace`), verifying over 880 tests green.
4. **Canonical Product Inventory Validation**: Verifies `product-inventory.json` against all 14 tool source directories, Cargo manifests, package versions, and release target metadata.
5. **Website Production Build**: Compiles the public web presentation (`npm --prefix website run build`).
6. **Website Dependency Audit**: Audits website npm dependencies for security vulnerabilities (`npm --prefix website audit --audit-level=high`).

*Note on extracted components:* Desktop applications (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web UI frameworks (`skel`, `sb-ui`), and standalone terminal experiments (`sb-shell`, `skully`) have been extracted from the core workspace and are no longer part of the core verification pipeline.
