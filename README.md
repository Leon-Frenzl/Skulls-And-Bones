# Skulls & Bones — Souveräne Entwicklungs- und Infrastrukturwerkzeuge

> **Souveräne Werkzeuge. Klare Grenzen. Nachprüfbare Sicherheit.**
> // MODULAR DEVELOPER & INFRASTRUCTURE TOOLING

Skulls & Bones entwickelt modulare Werkzeuge für Entwicklungs- und Infrastruktur-Workflows. Die Suite besteht aus eigenständigen Tools, nicht aus einem Monolithen. Ziel ist, dass Einzelpersonen und Teams Quellcode, Identitäten, Secrets und Betriebsabläufe selbst kontrollieren können. Sicherheits- und Reifegrad-Aussagen sind an konkrete Implementierungen und Tests gebunden; Markenbegriffe sind keine Garantie.

## Architektur und Projektstruktur

```text
Skulls-And-Bones/
├── brain/              # KI-freundliche Wissensbasis und Entscheidungsregister
├── docs/               # Zielarchitektur, Produktspezifikationen und Release-Dokumente
├── packaging/          # Installer und Release-Bundler
├── website/            # Web-Präsenz
└── tools/
    ├── sb/             # Modularer Suite-Launcher und Tool-Manager (CLI)
    ├── sb-core/        # Gemeinsame Bibliothek, Domain-Typen und Service-Verträge (Library)
    ├── sb-app-contract/# SB-MAP Manifest- und Operations-Grants (Library)
    ├── sb-app-protocol/# SB-MAP Protokoll-Framing und Objekt-Transfer (Library)
    ├── sb-auth/        # Sovereign Identity, Tokens und Authentifizierung (CLI)
    ├── sb-code/        # Code Engine, AST-Scopes und Mesh-Synchronisation (CLI)
    ├── sb-db/          # Embedded Document-KV Store mit MVCC (CLI)
    ├── sb-dns/         # Sovereign DNS-Resolver und Mesh-Router (CLI)
    ├── sb-drive/       # Peer-Filesystem und Mesh-Storage (CLI)
    ├── sb-forge/       # CI/CD Pipeline-Runner und Secret-Engine (CLI)
    ├── sb-key/         # Root-Identity und Ephemeral Lease Engine (CLI)
    ├── sb-mesh/        # P2P-Overlay-Netzwerk und Mesh-Routing (CLI)
    ├── sb-node/        # Headless Mesh-Anchor und Server-Daemon (CLI)
    └── sb-proxy/       # Reverse Proxy, Auto-TLS und Edge Gateway (CLI)
```

`sb` verwaltet die separaten Tools. `sb-core` enthält gemeinsame Verträge und Service-Schnittstellen; der lokale Daemon bietet diese über versionierte IPC an. Die Suite fokussiert sich auf autarke, hochsichere CLI-Werkzeuge, Daemons und Vertragslaufzeiten. Frühere Desktop-Frontends (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Pakete (`sb-ui`, `skel`) sowie separate Terminal-/Shell-Prototypen (`sb-shell`, `skully`) wurden aus der Core-Suite ausgegliedert.

Das kanonische [Produktinventar](./product-inventory.json) führt die 14 konsolidierten Kern-Tools (11 CLI-Tools/Binaries und 3 Bibliotheken/Vertragscrates) mit Paketversion, Binary-/Release-Zielen, Abhängigkeiten, Prüfpfad und Reifegrad. `sb status` zeigt die Reifegrade; `sb catalog` liest dasselbe Inventar über `suite.catalog` (API v1) vom authentisierten lokalen Daemon. Aufgeführte Release-Ziele sind die deklarierten Build-Ziele und Validierungsergebnisse.

Das langfristige Ziel ist die Entwicklung und Code-Versionierung im eigenen Sovereign Dev Mesh mit `sb-code`. Jedes Tool soll einen eigenen Projekt-Working-Space erhalten; Topologie und Replikationsmodell sind noch offen. Die [Zielarchitektur](./docs/ARCHITECTURE.md) und das [KI-freundliche Dokumentenregister](./brain/README.md) halten Entscheidungen, Status und bekannte Abweichungen fest.

## Schnellstart: CLI aus dem lokalen Quellcode

Voraussetzung: eine installierte Rust-Toolchain. Führe die Befehle im bereits
vorhandenen Suite-Workspace aus; die CLI benötigt zur Installation und Laufzeit
keinen Git-Client:

```text
cargo install --path tools/sb --bin sb
sb --help
sb status
```

Damit wird der Suite-Launcher lokal aus dem Quellcode gebaut und in Cargos
Binary-Verzeichnis installiert. `sb status` zeigt installierte Tools und ihren
Reifegrad; es startet keine Mesh-Dienste automatisch.

Für einzelne Suite-Tools kann der Launcher signierte Release-Artefakte beziehen:

```text
sb install --help
sb install <tool>
```

Dieser Installationsweg setzt voraus, dass signiertes Manifest und Artefakt für
das eigene Plattformziel unter dem konfigurierten Release-Hosting verfügbar
sind. Automatisierte CI-Releases und ein separater Bootstrap-Installer sind derzeit
nicht Teil des Projekts.

## Suite-Verifikation und Tests

Die gesamte Suite wird über das zentrale Verifikationsskript geprüft:

```text
npm run verify:suite
```

Dieser Prüflauf verifiziert:
- Rust-Code-Formatierung (`cargo fmt --all -- --check`)
- Vollständige Cargo-Workspace-Kompilierung über alle 14 Crates (`cargo check --workspace`)
- Alle Workspace-Unit- und Integrationstests (`cargo test --workspace`)
- Konsistenz des Produktinventars (`product-inventory.json` gegen Crate-Manifeste)
- Build der öffentlichen Website (`npm --prefix website run build`)
- Sicherheitsaudit der Website-Abhängigkeiten (`npm --prefix website audit`)

Für die gezielte Entwicklung einzelner Crates kann direkt Cargo genutzt werden:

```text
cargo test -p sb-core
cargo test -p sb-auth
```

## Website lokal entwickeln

```text
cd website
npm install
npm run dev
```

Website im Browser: [http://localhost:3000](http://localhost:3000). Dies startet
nur die Website-Entwicklungsumgebung, nicht die S&B-CLI, den Suite-Daemon oder
das Mesh.
