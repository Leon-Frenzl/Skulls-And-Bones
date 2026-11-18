---
name: typst-docs
description: "Use when writing, updating or reviewing documentation for this repository: all code documentation must be authored in Typst (.typ). Keywords: documentation, docs, Typst, .typ, API docs, crate docs, specification, security section, standard deviations."
argument-hint: "Crate or module to document"
---

# Typst Documentation

All code documentation is written in **Typst** (`.typ`), not Markdown.

## Layout

```
docs/typ/
  <crate>/index.typ       # crate overview, public API, examples
  <crate>/<module>.typ    # per-module detail
```

Each crate document contains: Überblick, Öffentliche API, Beispiele, Fehlerbehandlung, **Sicherheit** (findings from `security-cve-audit`), **Abweichungen vom Standard** (from `standards-compliance`), Tests.

## Rules

- New or changed behavior must update the matching `.typ` file in the same change.
- Rust doc comments (`///`, `//!`) stay short (one summary line plus the path of the `.typ` file) because rustdoc cannot render Typst.
- Security annotations in code (`SECURITY(...)`, `DEVIATION(...)`) are mirrored in the Sicherheit / Abweichungen sections.
- Existing `.md` files are migrated only when touched; `AGENTS.md`, `README.md` and files consumed by tooling stay Markdown.

## Build and check

```text
typst compile docs/typ/<crate>/index.typ target/doc-typ/<crate>.pdf
```

The compile must succeed without warnings. Install: `cargo install typst-cli --locked`. Editor support: VS Code extension `myriad-dreamin.tinymist`.

Start from the [template](./assets/template.typ).
