# Skulls & Bones — AGENTS.md

## Projekt Overview

**Skulls & Bones** ist ein Rust-Workspace (v0.2.0) mit 12 Crates + Web-Konsole (`console/`).
- **Edition:** Rust 2021
- **Lizenz:** MIT

### Crate-Struktur

| Crate | Rolle |
|---|---|
| `sb` | Main CLI / Entry Point |
| `sb-core` | Kern-Logik, Shared Utilities |
| `sb-key` | Key-Management, Cryptography |
| `sb-mesh` | Mesh Network Layer |
| `sb-node` | Node/Peer Management |
| `sb-proxy` | Reverse Proxy / Routing |
| `sb-db` | Persistenz / Data Layer |
| `sb-dns` | DNS-Resolution, Name Resolution |
| `sb-auth` | Authentication / Authorization |
| `sb-ca` | Certificate Authority |
| `sb-cred-provider` | Windows Credential Provider COM DLL |
| `sb-linux-auth` | Linux PAM / NSS Modul |
| **console/** | React + Vite Web-Konsole |

## Team-Rollen

### 🔧 Backend Developer (sb-backend)
- Rust-Crates entwickeln, refactor, debuggen
- `cargo build`, `cargo test`, `cargo clippy`
- API-Design, Protocol-Definitionen
- Abhängigkeiten aktualisieren (TOML, Feature-Flags)

### 🖥️ Frontend Developer (sb-frontend)
- Website (npm/Node.js) entwickeln
- HTML/CSS/JS, Components, State Management
- Build-Pipeline (npm scripts)
- Responsive Design, UX

### 🛡️ Security & Quality (sb-sec)
- Semgrep-Scans (via MCP)
- Dependency Audits (`cargo audit`, `npm audit`)
- Code Review, Security Best Practices
- Performance-Profiling

### 📋 Tech Lead / Orchestrator (sb-lead)
- Tasks verteilen, Reviews merge
- Architektur-Entscheidungen
- Release-Management
- Kanban-Board-Management

## Entwicklungs-Werkzeuge

```
Build:      cargo build --workspace
Test:       cargo test --workspace
Clippy:     cargo clippy --workspace -- -D warnings
Check:      cargo check --workspace
Fmt:        cargo fmt --all
Website:    cd website && npm install && npm run dev
Website:    cd website && npm run build
Docs:       cargo doc --workspace --no-deps
```

## Konventionen

### Code Style
- `cargo fmt` — Einhalten der Rust-Fmt-Regeln
- `cargo clippy -- -D warnings` — Null-Warnungen in CI
- Consistent error handling: `?` operator, thiserror/anyhow
- Meaningful error messages, context preservation

### Git Workflow
- Feature-Branches: `feature/<name>`
- Bugfixes: `bugfix/<issue-description>`
- Commits: Conventional Commits (feat, fix, refactor, docs, chore)
- Rebase on main vor Merge, kein Fast-Forward auf main

### Error Handling
```rust
// Verwende thiserror für lib errors, anyhow für bin errors
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol violation: {0}")]
    Protocol(String),
    // ...
}
```

### Testing
- Unit Tests im selben Crate, mod test
- Integration Tests: `tests/` Verzeichnis im Crate
- Edge cases, Error paths, concurrent scenarios

## Verbindliche Entwicklungsregeln (für Menschen und KI-Assistenten)

Bei **jeder** Entwicklungsaufgabe (Feature, Bugfix, Refactoring, Dependency-Änderung):

1. **Sicherheitsprüfung** — Skill `security-cve-audit`: betroffene Funktionen und Dependencies prüfen (`cargo audit`, Semgrep-MCP), Funde mit **verifizierter** Kennung im Code kommentieren (`// SECURITY(CVE-YYYY-NNNNN): …`), Ausnutzungswahrscheinlichkeit für dieses Projekt bewerten und Lücken ab Stufe Medium im selben Change beheben. CVE-Nummern werden nie erfunden; ohne CVE gelten `RUSTSEC-…` oder `CWE-…`.
2. **Standards** — Skill `standards-compliance`: Für definierte Standards (RFC, IEEE, ISO, NIST, …) gilt die Spezifikation. Abweichung nur, wenn die Spezifikation selbst eine Sicherheitslücke erzeugt; dann patchen, mit `// DEVIATION(RFC NNNN §x): …` kennzeichnen, testen und dokumentieren.
3. **Dokumentation in Typst** — Skill `typst-docs`: Code-Dokumentation wird in `.typ` unter `docs/typ/<crate>/` geschrieben; Rust-Doc-Kommentare bleiben kurze Verweise.
4. **CLI-Vereinheitlichung** — Standard `docs/CLI_UNIFICATION_STANDARD.md` & `docs/typ/sb/cli-unification.typ`: Keine neuen CLI-Binaries und keine unnötigen Top-Level-Commands erzeugen. Neue Workflows, OS-Dienststeuerung (`sc.exe`/`systemctl`) und Update-Pfade immer in bestehende `sb`-Subcommands (`sb agent`, `sb service`, `sb update`, `sb domain`, …) integrieren.

MCP-Server (`.vscode/mcp.json`): `semgrep` (statische Analyse), `fetch` (RFC-, NVD-, OSV- und RustSec-Abfragen).

## Task-Zuständigkeiten

| Bereich | Hauptverantwortlich |
|---|---|
| Rust Core Crates | sb-backend |
| Protocol / Messages | sb-backend |
| Networking / Mesh | sb-backend |
| Database / Storage | sb-backend |
| Website / Frontend | sb-frontend |
| Authentication Flow | sb-frontend + sb-backend |
| Security Scans | sb-sec |
| Dependency Updates | sb-sec + sb-lead |
| Code Reviews | sb-lead |
| Releases | sb-lead |

## Sicherheitshinweise

- **Keine Secrets in Code** — `.env`, config files (ausgeschlossen von Version Control)
- **Dependencies regularly aktualisieren** — Security Patches prüfen
- **Semgrep + cargo audit** — Automatisierte Security-Checks
- **Certificate Management** — `sb-ca` Crate besonders sensibel
