# Analyse- und Bestandsbericht: Dokumentations-Synchronisation (.md)

> **Dokument-ID:** `REPORT-SURVEY-DOCS-R2`  
> **Status:** Abgeschlossen  
> **Erstellt durch:** Agent `explorer_survey_docs` (teamwork_preview_explorer)  
> **Bezug:** Anforderung R2 aus `ORIGINAL_REQUEST.md`  
> **Gültig ab:** 2026-10-26  

---

## 1. Executive Summary & Das 14-Core-Ökosystem

Das Projekt **Skulls & Bones** wurde architektonisch bereinigt und konsolidiert:
- Sämtliche **Desktop-Anwendungen** (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Frameworks (`skel`, `sb-ui`) sowie separate Shell-/Terminal-Experimente (`sb-shell`, `skully`) und Altsysteme (`sb-ports`, `sb-securenet`, `sb-ssh`, `sb-vault`, `sb-shadow`) wurden aus dem Core-Workspace ausgegliedert bzw. restlos entfernt.
- Der offizielle Quellcode- und Release-Bestand (`Cargo.toml`, `product-inventory.json`) besteht nun aus **exakt 14 autarken Kern-Tools** (11 Binaries/CLI-Tools und 3 geteilte Bibliotheken/Vertragscrates) sowie der separaten Webpräsenz (`website/`).
- Der Root-Cargo-Workspace umfasst alle 14 Crates lückenlos. `npm run verify:suite` führt `cargo fmt`, `cargo check --workspace`, `cargo test --workspace`, den Website-Build sowie Website-Audits durch und läuft mit Exit-Code 0 fehlerfrei durch.
- **Problemstellung:** Über 30 Markdown-Dokumente im Workspace (`README.md`, `ROADMAP.md`, `docs/*.md`, `brain/*.md`, `tools/*/README.md`) referenzieren jedoch weiterhin veraltete Komponenten als aktive Suite-Bestandteile, nennen veraltete Zählwerte (z. B. 22 oder 23 Inventarprodukte) oder verweisen auf gelöschte Tauri-/Desktop- und SKEL-Build-Gates.

---

## 2. Kanonisches Inventar der 14 konsolidierten Kern-Tools

Gemäß `product-inventory.json` und `Cargo.toml` setzt sich das autoritative Ökosystem wie folgt zusammen:

| # | Produkt-ID | Crate-Name | Version | Art | Kategorie | Binary | Beschreibung |
|---|---|---|---|---|---|---|---|
| 1 | `sb` | `sb-cli` | `0.2.1` | `cli_tool` | Suite Launcher | `sb` | Modularer Launcher, Installer und API-Client der Suite. |
| 2 | `core` | `sb-core` | `0.2.0` | `library` | Shared Contracts | *keines* | Gemeinsame Domain-Typen, Service-Verträge, IPC und Runtime-Helfer. |
| 3 | `app-contract` | `sb-app-contract` | `0.2.0` | `library` | Mesh Application Platform | *keines* | SB-MAP manifest verification and service-, app-, resource-, and policy-bound operation grants. |
| 4 | `app-protocol` | `sb-app-protocol` | `0.2.0` | `library` | Mesh Application Platform | *keines* | Versioned SB-MAP control framing and bounded, digest-verified object-transfer primitives. |
| 5 | `auth` | `sb-auth` | `0.2.0` | `cli_tool` | Authentication & Identity | `sb-auth` | Sovereign Authentication Kit mit Ed25519-Tokens, Multi-Tier Revocation und Argon2id. |
| 6 | `code` | `sb-code` | `0.1.0` | `cli_tool` | Code Engine & VCS | `sb-code` | Lokale Code-Engine, AST-Scopes und Mesh-Synchronisierung. |
| 7 | `db` | `sb-db` | `0.2.0` | `cli_tool` | Database & State | `sb-db` | Embedded Document-KV Store mit MVCC, TTL, Indizes und Watch. |
| 8 | `dns` | `sb-dns` | `0.2.0` | `cli_tool` | DNS & Resolution | `sb-dns` | Sovereign DNS-Resolver und Mesh-Router. |
| 9 | `drive` | `sb-drive` | `0.2.0` | `cli_tool` | Mesh Storage | `sb-drive` | Peer-Filesystem, Dateiübertragung und Mesh-Drive-CLI. |
| 10 | `forge` | `sb-forge` | `0.1.1` | `cli_tool` | DevOps & Secrets | `sb-forge` | CI/CD-Pipeline-Runner und Secret-Engine. |
| 11 | `key` | `sb-key` | `0.1.0` | `cli_tool` | Cryptography & Identity | `sb-key` | Sovereign Root Identity und Ephemeral Lease Engine. |
| 12 | `mesh` | `sb-mesh` | `0.3.0` | `cli_tool` | Overlay Network | `sb-mesh` | P2P-Overlay-Netzwerk und Mesh-Management. |
| 13 | `node` | `sb-node` | `0.1.0` | `cli_tool` | Fleet & Server | `sb-node` | Headless Mesh-Anchor und explizite Service-Routen. |
| 14 | `proxy` | `sb-proxy` | `0.1.0` | `cli_tool` | Edge & Egress | `sb-proxy` | Reverse Proxy, Auto-TLS und Edge Gateway. |

### Separate Bereitstellungsflächen (`separate_surfaces`):
- **`website`** (`website/`): Öffentlicher Web-Auftritt, ausgeliefert via `sb-proxy static`. Vite + React 19 SPA, unabhängig von Desktop- oder Mesh-Runtimes.

---

## 3. Bestandsaufnahme der gelöschten / ausgegliederten Komponenten

Im Workspace wurden 10 wesentliche Altsysteme identifiziert, die physisch aus `tools/` entfernt wurden, aber in den Dokumenten noch als aktiv dargestellt werden:

| Komponente | Ehemalige Rolle | Heutiger realer Status |
|---|---|---|
| **`sb-desktop`** | Tauri/React bzw. egui Desktop-Client | Ausgegliedert/Entfernt; Suite ist rein headless/CLI/Library. |
| **`sb-studio`** | Tauri/React bzw. egui IDE & Code-Editor | Ausgegliedert/Entfernt; Versionierung erfolgt über `sb-code` CLI/Service. |
| **`sb-workbench`** | Tauri/React bzw. egui UI-Komponenten-Workbench | Ausgegliedert/Entfernt. |
| **`netgrid`** | Tauri Netzwerk-Scanner Desktop-App | Ausgegliedert/Entfernt. |
| **`skel`** | Rust-basiertes servergetriebenes Web-UI-Framework | Ausgegliedert/Entfernt; nicht Teil der Core-Suite. |
| **`sb-ui`** | Privates npm-Paket / React Design System | Entfernt; `website` nutzt direkt Tailwind/Vite ohne `@skulls-and-bones/ui`. |
| **`sb-shell`** | Plattformübergreifende Kommando-Shell (`.sbsh`) | Ausgegliedert/Entfernt; System nutzt native Shells. |
| **`skully`** | GPU-beschleunigter Terminal-Emulator (`wgpu`) | Ausgegliedert/Entfernt. |
| **`sb-ports`** | PortSentry / Port-Manager & Killer | Entfernt/Ehemaliges Tool; nicht im 14-Core-Bestand. |
| **`sb-securenet`** | Anti-Timing / Anycast Anonymitätsnetzwerk | Ausgegliedert (nur als theoretisches Forschungspapier archiviert). |

*Weitere veraltete Begriffe und Hilfskonstrukte:* `sb-desktop-native`, `sb-studio-native`, `sb-workbench-native`, `sb-ssh` (historischer SSH-Prototyp), `sb-vault` (veralteter Name für Desktop-Vault), `sb-shadow` (gelöschter Remote-PC-Dienst).

---

## 4. Fundstellen-Matrix der veralteten Komponenten (.md)

Ein vollständiger Grep-Scan über alle 52 Markdown-Dateien im Workspace ergab folgende konkrete Fundstellen (Dateien und Zeilen):

| Datei | Betroffene Komponenten / Veraltete Begriffe | Konkrete Zeilennummern |
|---|---|---|
| `README.md` | `sb-desktop`, `sb-studio`, `sb-workbench`, `sb-ui`, `netgrid`, `skully`, `sb-shell`, veraltete npm-Befehle | 20–25, 28, 30, 62–78 |
| `ROADMAP.md` | `sb-desktop`, `sb-shell`, `skully`, `sb-studio`, `SSH/NetGate`, `sb-vault`, veraltete Workspace-Grenzen | 23–27, 62, 71, 75, 77, 78 |
| `docs/ARCHITECTURE.md` | `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `sb-ui`, `skel`, `sb-shell`, `skully`, `sb-ports`, `sb-securenet`, `sb-ssh`, `sb-vault` | 15, 26–31, 33–36, 38, 64, 74, 95, 97, 105, 161, 162, 163, 164, 179, 189 |
| `docs/QUALITY_GATES.md` | `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `skel`, Tauri-Manifests, SKEL E2E, NetGrid Lint | 3, 8, 9, 10, 11, 12, 14 |
| `docs/MANIFESTO.md` | `sb-desktop`, `sb-shell`, `skully` | 20–22 |
| `brain/README.md` | `skel` (`SKEL_FRAMEWORK.md`), `walkthrough.md` (`sb-desktop`), `sb-workbench` | 16, 19, 21, 53, 75, 78, 81 |
| `brain/decisions.md` | `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `sb-shell`, `skully`, `skel`, `sb-ssh` | 19–24, 26, 28–30, 34–37, 68–73 |
| `brain/backlog.md` | Alle gelöschten Desktop-Apps, `skel`, `skully`, `sb-shell`, `sb-ui`, `netgrid`, 23 Produkte | 24, 25, 34, 35, 38, 39, 47, 59, 63, 72–77, 85–86, 96–98, 103–105, 109 |
| `brain/vision.md` | `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `sb-ui`, Tauri-Checks, Säule 6 | 24, 26, 42, 44, 74, 77, 115–127, 136 |
| `brain/implementation_plan.md` | `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `skel`, `skully`, `sb-shell`, 22/23 Produkte, SKEL-E2E | 22, 73, 74, 78–86, 88–110, 122–123, 128–139 |
| `tools/README.md` | `sb-desktop`, `sb-studio`, `sb-shell`, `skully`, `netgrid`, falsche Workspace-Aussage | 9–14, 21 |
| `docs/SB_PORTS_PORTSENTRY_SPEC.md` | `sb-ports` (vollständige Datei behauptet aktive Suite-Komponente) | Ganze Datei (speziell Z. 3, 31) |
| `docs/SB_SHELL_SOVEREIGN_TERMINAL_SPEC.md` | `sb-shell`, `skully` (vollständige Spezifikation) | Ganze Datei (speziell Z. 8–11, 15–17, 20–34) |
| `docs/SKEL_FRAMEWORK.md` | `skel` (vollständige Rahmenspezifikation) | Ganze Datei (speziell Z. 1, 7, 74, 114, 119, 127) |
| `docs/SOVEREIGN_SUITE_INTEGRATION_MAP.md` | `sb-ports`, `sb-shell`, `sb-securenet`, `sb-ssh`, `sb-vault` als „Produktiv“ | 6, 25, 61, 62, 66, 113, 136, 184, 205 |
| `docs/VISION_AND_PRIORITIZED_TASKS.md` | `sb-desktop`, `sb-shell`, `skully`, `sb-ui`, `sb-workbench`, `sb-ssh` | 21, 34, 35, 39, 47, 49, 75 |
| `docs/DEV_SERVER_SETUP.md` | `npm run install:ui`, `npm run build:desktop`, `sb-ssh` | 37, 38, 47 |
| `docs/SOVEREIGN_FLEET_ARCHITECTURE.md` | `sb-ports`, `sb-vault`, `sb-ssh` | 11, 33, 49, 132 |
| `docs/DEVELOPER_SOP_FORGE_RELEASE_FLOW.md` | Tauri/Frontend-Workspaces separat | 25, 41 |
| `docs/RELEASE_AND_DISTRIBUTION_MANIFEST.md` | `sb-shell`, `skully`, `sb-ssh`, `sb-vault`, separate Workspaces | 41, 43, 44 |
| `docs/SB_MESH_APP_STANDARD.md` | `sb-desktop` als ständiger Client, `sb-studio`, `sb-workbench`, `netgrid` | 12, 36, 44, 52, 113, 130, 160, 166, 176, 230–236 |
| `docs/MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md` | `sb-workbench`, `src-tauri` | 142, 210 |
| `brain/walkthrough.md` | `tools/sb-desktop/`, `src-tauri`, React-Frontend | Ganze Datei (speziell Z. 15, 23–27, 33–45, 66) |
| `brain/continuation_summary.md` | `tools/sb-desktop/` | 19, 26 |
| `brain/forge-complete-concept.md` | `sb-desktop`, `sb-studio` | 22 |
| `tools/sb/README.md` | `sb-desktop`, Tauri-Adapter, separate UI-Workspaces | 52, 112 |
| `tools/sb/TODO.md` | `sb-ports`, `sb-ssh`, `sb-vault` | 9, 23, 25, 31, 34, 46–48, 126–127, 134 |
| `tools/sb-auth/README.md` | `@skulls-and-bones/ui`, Desktop-Clients | 142–161 |
| `tools/sb-code/README.md` | `sb-studio` Version History sync | 30 |
| `tools/sb-drive/TODO.md` | `sb-shell`, `Phantom Desktop`, `Tauri v2 sb-vault` | 26–27, 65, 68 |
| `tools/sb-forge/README.md` | `sb-ssh/NetGate` | 33 |
| `tools/sb-forge/TODO.md` | `Tauri-/Frontend-Workspaces` | 39 |
| `tools/sb-key/TODO.md` | `sb-ssh`, `sb-vault`, `sb-login` | 13, 24, 85 |
| `tools/sb-node/README.md` | `Studio code sync` | 38 |
| `tools/sb-proxy/README.md` | `S&B Studio Integration / Studio Cockpit` | 15 |
| `tools/sb-proxy/TODO.md` | `S&B Studio`, `Tauri IPC` | 13, 80–87, 122–125 |
| `docs/SB_DNS_SOVEREIGN_RESOLVER_SPEC.md` | `sb-ports` Health/Exposure | 300, 358 |
| `docs/OPERATIONS_HARDENING.md` | `npm run install:ui` | 42 |

---

## 5. Detaillierter Datei-für-Datei Änderungsplan

Nachfolgend ist für jede der betroffenen Dateien der exakte Anpassungsbedarf aufgeführt, um vollständige Konformität mit dem 14-Core-Ökosystem und der Anforderung R2 herzustellen:

### Kategorie A: Root-Dokumente (`README.md`, `ROADMAP.md`)

#### 1. `README.md`
- **Ziel:** Konsequente Darstellung der 14 autarken Kern-Tools; Beseitigung aller Desktop-, Tauri- und UI-Befehle.
- **Konkrete Änderungen:**
  - **Z. 16–26 (Projektbaum):** Ersetzen der alten Verzeichnisstruktur unter `tools/`. Nicht mehr `sb-desktop`, `sb-studio`, `sb-workbench`, `sb-ui`, `netgrid`, `skully` aufführen, sondern die 14 echten Ordner: `sb`, `sb-core`, `sb-app-contract`, `sb-app-protocol`, `sb-auth`, `sb-code`, `sb-db`, `sb-dns`, `sb-drive`, `sb-forge`, `sb-key`, `sb-mesh`, `sb-node`, `sb-proxy`.
  - **Z. 28:** Satz über `sb-desktop`, `sb-shell`, `skully` entfernen. Klarstellen, dass die Suite aus fokussierten CLI-Tools, Daemons und Vertragslaufzeiten besteht.
  - **Z. 30:** Erwähnung von `sb-ui`, `sb-workbench` und der Suite-Inventaransicht in `sb-desktop` entfernen. Erläutern, dass `product-inventory.json` die 14 Kern-Tools führt.
  - **Z. 62–83 („Desktop-Tools lokal entwickeln“):** Diesen gesamten Abschnitt restlos streichen (keine `npm run dev:desktop`, `dev:studio`, `dev:workbench`, `tauri:studio`, `build:*` mehr in `package.json`).
  - **Ersatz für Z. 62–83:** Neuer Abschnitt „Suite-Verifikation und Tests“ mit `npm run verify:suite` (führt Cargo Workspace Checks, 882 Tests, Website-Build und Audits aus) und Hinweisen zur Entwicklung einzelner Crates via `cargo test -p <crate>`.

#### 2. `ROADMAP.md`
- **Ziel:** Aktualisierung des Produktmodells auf 14 Kern-Tools; Statusklärung der ausgegliederten Apps.
- **Konkrete Änderungen:**
  - **Z. 23–27:** Entfernen von `sb-desktop`, `sb-shell`, `skully`, `SSH/NetGate` und `sb-vault` aus dem aktiven Produktmodell.
  - **Ersatz in Produktmodell:** Auflistung der konsolidierten 14 Kern-Tools nach Kategorien (Launcher, Verträge, Security/Auth, Storage/DB/DNS, Network/Edge, Fleet/DevOps).
  - **Z. 60–63 (Priorität 6):** Anpassen der Priorität „Produktgrenzen“: Dokumentieren, dass Desktop-Apps, Shell und Terminal ausgegliedert wurden und die Suite autark als Headless-Infrastruktur betrieben wird.
  - **Z. 71:** Aussage korrigieren: Das Root-Cargo-Workspace umfasst alle 14 Kern-Tools vollständig.
  - **Z. 75, 77, 78:** Entfernen von `sb-desktop` und Tauri-Migration aus den Statusabschnitten.

---

### Kategorie B: Grundsatz- und Architekturdokumente (`docs/`)

#### 3. `docs/ARCHITECTURE.md`
- **Ziel:** Das maßgebliche Zielbild muss die Ausgliederung der Desktop-Apps/Skel/Shell/Terminal widerspiegeln.
- **Konkrete Änderungen:**
  - **Z. 15:** Streichen der Leitplanke `sb-desktop ist die eigene Desktop-Oberfläche...`. Ersetzen durch: *„Skulls & Bones fokussiert sich auf autarke, hochsichere CLI- und Daemon-Werkzeuge sowie servicegebundene Verträge.“*
  - **Z. 19–37 (Tabelle Komponenten und Zuständigkeiten):**
    - Entfernen von `sb-desktop` (Z. 26), `sb-studio` (Z. 27), `sb-workbench` (Z. 28), `netgrid` (Z. 29, 36), `sb-ui` (Z. 30), `skel` (Z. 31), `SSH-/NetGate-Prototyp` (Z. 33), `sb-shell` (Z. 34), `skully` (Z. 35) als aktive Suite-Komponenten.
    - Aufnahme der 14 konsolidierten Tools in die Tabelle: Hinzufügen von `sb-app-contract`, `sb-app-protocol`, `sb-auth`, `sb-db`, `sb-dns`, `sb-drive`, `sb-key`, `sb-node`, `sb-proxy`.
    - Neuer separater Unterabschnitt oder Hinweiskasten: Dokumentation der Ausgliederung (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `skel`, `sb-shell`, `skully`) als externe oder archivierte Satelliten.
  - **Z. 38:** Entfernen von `sb-ports` und `sb-securenet` aus der Aufzählung der Tools.
  - **Z. 74 (Diagramm):** `sb-desktop / sb-studio / sb / weitere Clients` ersetzen durch `sb CLI / sb-auth / sb-drive / externe Clients`.
  - **Z. 95, 97:** Erwähnungen von Desktop-UIs, Tauri Commands und Shadow entfernen.
  - **Z. 105:** Streichen der Behauptung über getrennte Cargo-Workspaces.
  - **Z. 159–169 (Abschnitt 7 Abweichungen):**
    - Punkte 1, 2 und 4 (Root-Workspace enthält skully aber nicht desktop; sb-shell vs skully; Tauri-Commands) als historisch erledigt bzw. durch Ausgliederung obsolet kennzeichnen oder entfernen.
  - **Z. 179:** Punkt 8 („Für jede Desktop-App native Rust-Funktionsparität...“) anpassen: Desktop-Ausgliederung ist erfolgt.

#### 4. `docs/QUALITY_GATES.md`
- **Ziel:** Exakter Abgleich mit der Realität von `scripts/verify-suite.mjs`.
- **Konkrete Änderungen:**
  - **Z. 3:** Streichen von „The install targets are derived from desktop-application entries... plus SKEL E2E project“.
  - **Z. 8–12:** Komplettes Bereinigen der veralteten Gate-Auflistung:
    - Streichen von „Tauri and frontend checks are derived from its desktop-application entries“.
    - Streichen von „Check and tests for the separate sb-desktop, sb-studio, sb-workbench and NetGrid Tauri manifests“.
    - Streichen von „Production frontend builds for those four apps and the website“.
    - Streichen von „Warning-free, source-scoped NetGrid lint...“.
    - Streichen von „SKEL E2E tests...“.
  - **Neuer Inhalt:** Das Quality Gate prüft verbindlich:
    1. Rust Code Formatting (`cargo fmt --all -- --check`).
    2. Root Rust Workspace Check (`cargo check --workspace` über alle 14 Tools).
    3. Root Rust Workspace Unit- & Integrationstests (`cargo test --workspace`, 882+ Tests grün).
    4. Produkt-Inventar Validierung (`product-inventory.json` gegen alle 14 Tool-Verzeichnisse und Manifeste).
    5. Website Production Build (`npm --prefix website run build`).
    6. Website Dependency Audit (`npm --prefix website audit --audit-level=high`).
  - **Z. 14:** Erwähnung des „Tauri target“ streichen.

#### 5. `docs/MANIFESTO.md`
- **Ziel:** Beseitigung veralteter Produktziele.
- **Konkrete Änderungen:**
  - **Z. 20–22:** Streichen von:
    - `- sb-desktop ist die S&B-eigene Desktop-Oberfläche, nicht die einzige mögliche Oberfläche.`
    - `- sb-shell ist als plattformübergreifende Kommando-Shell mit eigener Sprache vorgesehen.`
    - `- skully ist davon getrennt ein GPU-Terminal-Emulator.`
  - **Ersatz:** Betonen der autarken 14 Kern-Tools, der servicebasierten Headless-Architektur und modularer CLI-/Daemon-Interaktion.

#### 6. `docs/SB_PORTS_PORTSENTRY_SPEC.md`
- **Ziel:** Klare Kennzeichnung als historisches/ausgegliedertes Modul.
- **Konkrete Änderungen:**
  - **Z. 3:** Status von `Produktiv & Integriert (tools/sb-ports)` ändern zu: `Ausgegliedert / Deprecated (nicht Teil der 14 Core-Tools)`.
  - Hinweiskasten an den Dateianfang setzen, dass `sb-ports` nicht mehr im aktiven Workspace existiert.

#### 7. `docs/SB_SHELL_SOVEREIGN_TERMINAL_SPEC.md`
- **Ziel:** Klare Kennzeichnung als ausgegliederte Spezifikation.
- **Konkrete Änderungen:**
  - Header und Status anpassen: `sb-shell` und `skully` wurden aus der Core-Suite ausgegliedert. Die Datei dient als historische Referenz und beschreibt keine aktiven Suite-Komponenten.

#### 8. `docs/SKEL_FRAMEWORK.md`
- **Ziel:** Statusanpassung auf ausgegliedertes Web-Framework.
- **Konkrete Änderungen:**
  - Header und Status anpassen: `skel` wurde aus dem Core-Workspace ausgegliedert.

#### 9. `docs/SOVEREIGN_SUITE_INTEGRATION_MAP.md`
- **Ziel:** Bereinigung der Architektur-Matrix.
- **Konkrete Änderungen:**
  - **Z. 23–28 (Mermaid Diagramm):** Entfernen von `sb-ssh`, `sb-ports`, `sb-vault`.
  - **Z. 58–70 (Tabelle):** Entfernen von `sb-shell`, `sb-ports`, `sb-securenet` als „Produktiv“. Einfügen der tatsächlichen Core-Tools (`sb-auth`, `sb-db`, `sb-dns`, `sb-drive`, `sb-app-contract`, `sb-app-protocol`).
  - **Z. 113–140, 184–185, 205:** Erwähnungen von `sb-ports` bereinigen bzw. als historisch kennzeichnen.

#### 10. `docs/VISION_AND_PRIORITIZED_TASKS.md`
- **Ziel:** Konsistenz mit dem 14-Tool-Iststand.
- **Konkrete Änderungen:**
  - **Z. 21, 34, 35, 39, 47, 49, 75:** Entfernen von `sb-desktop`, `sb-shell`, `skully`, `sb-ui`, `sb-workbench`, `sb-ssh`.

#### 11. `docs/DEV_SERVER_SETUP.md`
- **Ziel:** Korrektur veralteter Workstation- und SSH-Hinweise.
- **Konkrete Änderungen:**
  - **Z. 37–38:** Streichen von `npm run install:ui` und `npm run build:desktop`. Ersetzen durch `npm run verify:suite` bzw. `cargo test --workspace`.
  - **Z. 47:** Erwähnung von `sb-ssh` in `~/.cargo/bin/ssh.exe` bereinigen.

#### 12. `docs/SOVEREIGN_FLEET_ARCHITECTURE.md`
- **Ziel:** Bereinigung historischer Namen.
- **Konkrete Änderungen:**
  - **Z. 11, 33, 49, 132:** Bereinigen der Nennung von `sb-ports`, `sb-vault`, `sb-ssh`.

#### 13. `docs/DEVELOPER_SOP_FORGE_RELEASE_FLOW.md`
- **Ziel:** Angleichung der Test- und Releasevorgaben.
- **Konkrete Änderungen:**
  - **Z. 25:** Hinweis auf getrennte Tauri-/Frontend-Workspaces entfernen; alle 14 Tools sind im Root-Cargo-Workspace.
  - **Z. 41:** Klarstellen, dass Release-Artefakte nun über `sb release pack` gebaut und signiert werden.

#### 14. `docs/RELEASE_AND_DISTRIBUTION_MANIFEST.md`
- **Ziel:** Bereinigung der Produkt- und Workspace-Grenzen.
- **Konkrete Änderungen:**
  - **Z. 41, 43, 44:** Streichen der Erwähnungen von separaten Desktop-/Frontend-Workspaces sowie `sb-shell`, `skully`, `sb-ssh`, `sb-vault`.

#### 15. `docs/SB_MESH_APP_STANDARD.md`
- **Ziel:** Abgrenzung des SB-MAP-Standards von gelöschten internen Apps.
- **Konkrete Änderungen:**
  - Hinweiskasten ergänzen: Klarstellen, dass `sb-desktop`, `sb-studio`, `sb-workbench` und `netgrid` nicht Teil der Core-Suite sind, sondern SB-MAP rein als allgemeiner Standard für externe Mesh-Clients und -Services dient.

#### 16. `docs/MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md`
- **Ziel:** Historischer Statusvermerk.
- **Konkrete Änderungen:**
  - Hinweiskasten ergänzen: `sb-workbench` wurde ausgegliedert; AST- und VCS-Operationen sind rein in `sb-code` verankert.

#### 17. `docs/SB_DNS_SOVEREIGN_RESOLVER_SPEC.md`
- **Ziel:** Bereinigung von Querverweisen auf `sb-ports`.
- **Konkrete Änderungen:**
  - **Z. 300–302, 358:** Entfernen der Erwähnungen von `sb-ports`.

#### 18. `docs/OPERATIONS_HARDENING.md`
- **Ziel:** Entfernen des veralteten UI-Install-Befehls.
- **Konkrete Änderungen:**
  - **Z. 42:** `npm run install:ui` entfernen.

---

### Kategorie C: KI-Wissensbasis & Projektsteuerung (`brain/`)

#### 19. `brain/README.md`
- **Ziel:** Bereinigung des Einstiegsdokuments und des Dokumentenregisters.
- **Konkrete Änderungen:**
  - **Z. 16, 75:** Verweis auf `SKEL_FRAMEWORK.md` entfernen oder als archiviert kennzeichnen.
  - **Z. 19, 78:** Verweis auf `walkthrough.md` (`sb-desktop`) als archiviert kennzeichnen.
  - **Z. 21, 81:** Verweis auf `MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md` als archiviert kennzeichnen.
  - **Z. 53:** `ergonomische CLI-, Desktop-, Shell-, Terminal- und Code-Workflows` ändern zu `ergonomische CLI-, Daemon- und Service-Workflows`.

#### 20. `brain/decisions.md`
- **Ziel:** Festhalten der verbindlichen Ausgliederungsentscheidung.
- **Konkrete Änderungen:**
  - **Z. 19–24 (Produktmodell):** Streichen der Entscheidungen zu `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, egui/eframe und AppContainer-Sandbox als Suite-Bestandteile.
  - **Neue bestätigte Entscheidung:** *„Ausgliederung der Desktop-Anwendungen und GUI-Clients: Die Suite konzentriert sich vollständig auf das autarke 14-Core-Ökosystem aus Headless-CLI-Werkzeugen, Daemons und gemeinsamen Vertragscrates. Desktop-Frontends (sb-desktop, sb-studio, sb-workbench, netgrid), UI-Frameworks (skel, sb-ui) sowie Shell- und Terminal-Prototypen (sb-shell, skully) sind vollständig ausgegliedert.“*
  - **Z. 26:** SSH/NetGate-Prototyp entfernen.
  - **Z. 28–30:** Entscheidungen zu `sb-shell`, `skully` und `skel` entfernen oder in den Ausgliederungsabschnitt überführen.
  - **Z. 34–37:** Erwähnungen von `sb-desktop` im Secret-Management streichen; Vault wird von `sb daemon`, `sb-core` und `sb-forge` genutzt.
  - **Z. 68–73 (Terminal und Shell):** Gesamten Abschnitt entfernen oder als ausgegliedert kennzeichnen.

#### 21. `brain/vision.md`
- **Ziel:** Säule 6 und Belegmatrix an das 14-Core-Ökosystem anpassen.
- **Konkrete Änderungen:**
  - **Z. 24:** `sb-desktop` aus der Aufzählung entfernen.
  - **Z. 26:** Design System (`sb-ui`) und GUI-Workflows streichen.
  - **Z. 42, 44:** Desktop-Apps aus Säule 1 entfernen; belegen, dass alle 14 Tools im Root-Workspace liegen.
  - **Z. 74, 77:** `sb-workbench` aus Säule 3 entfernen.
  - **Z. 115–127 (Säule 6):** Titel anpassen von „Standardisierte Entwickler-UI (sb-ui, sb-desktop, Website)“ auf „Öffentliche Webpräsenz & Edge-Auslieferung (Website, sb-proxy)“. Beseitigen der Aussagen zu `sb-ui`, `sb-desktop`, `sb-studio`, `sb-workbench`.
  - **Z. 136 (Tabelle):** Zeile `Desktop Frontends & Tauri` entfernen; stattdessen Zeile `14 Core Tools & Website` mit `npm run verify:suite` (0 Fehler, 882+ Tests bestanden) einfügen.

#### 22. `brain/implementation_plan.md`
- **Ziel:** Synchronisation mit dem erreichten Verifikationsstand.
- **Konkrete Änderungen:**
  - **Z. 22:** Erwähnung von `sb-desktop` bereinigen.
  - **Z. 73, 74:** `sb-workbench` und `sb-studio` aus Phase 5 entfernen.
  - **Z. 78–86 (Phase 6):** Umformulieren: Phase 6 dokumentiert die Ausgliederung von Shell und Terminal.
  - **Z. 88–110 (Phase 7):** Umformulieren: Dokumentieren der Ausgliederung der Desktop-Apps und Fokussierung auf die 14 Core-Tools.
  - **Z. 98:** „alle 23 Produkte“ korrigieren auf **„14 konsolidierte Kern-Tools“**.
  - **Z. 128–139 (Qualitäts-Gates):** Vollständig aktualisieren:
    - „22 Inventarprodukte“ korrigieren auf **14 Kern-Tools**.
    - Streichen von separaten Tauri-Manifesten, SKEL-E2E (4 Tests), NetGrid Lint und 6 Dependency-Audits.
    - Dokumentieren des aktuellen Stands: `npm run verify:suite` prüft 14 Core-Tools im Root-Workspace (882 Tests grün), baut `website` und auditiert `website` mit 0 Schwachstellen.

#### 23. `brain/backlog.md`
- **Ziel:** Aktualisierung aller Backlog-Karten auf den konsolidierten Stand.
- **Konkrete Änderungen:**
  - **Z. 24, 25:** P3- und P4-Übersichten bereinigen.
  - **Z. 34, 35, 38, 39:** P0-Karten anpassen (Tauri-/Desktop-Pfade als historisch kennzeichnen).
  - **Z. 47, 59, 63:** P1/P2-Karten bereinigen.
  - **Z. 72–77 (P3):** P3-1 bis P3-5 als durch Ausgliederung obsolet bzw. historisch kennzeichnen.
  - **Z. 85–86 (P4):** P4-1 und P4-2 als durch Ausgliederung obsolet kennzeichnen.
  - **Z. 96–98 (F0-1 bis F0-3):** F0-1 und F0-3 auf 14 Produkte und reinen Cargo-Workspace + Website aktualisieren; F0-2 (NetGrid Lint) als obsolet markieren.
  - **Z. 103–105, 109 (F1-4, F1-5, F2-3):** Aktualisieren: Desktop-Apps wurden vollständig ausgegliedert.

#### 24. `brain/walkthrough.md`
- **Ziel:** Historisierung.
- **Konkrete Änderungen:**
  - Prominenten Header ergänzen: *„Historisches Archiv: Dieses Dokument beschreibt die ehemals existierende Tauri/React-Oberfläche sb-desktop. Die Desktop-Anwendung wurde im Zuge der 14-Core-Konsolidierung vollständig aus der Suite ausgegliedert.“*

#### 25. `brain/continuation_summary.md`
- **Ziel:** Historisierung.
- **Konkrete Änderungen:**
  - Vermerk ergänzen, dass `tools/sb-desktop` nicht mehr existiert.

#### 26. `brain/forge-complete-concept.md`
- **Ziel:** Bereinigung der Client-Referenzen.
- **Konkrete Änderungen:**
  - **Z. 22:** `sb-desktop und sb-studio sind mögliche UIs/Clients...` anpassen.

---

### Kategorie D: Werkzeug-Dokumentationen (`tools/*/`)

#### 27. `tools/README.md`
- **Ziel:** Vollständige Übereinstimmung mit den 14 Tools unter `tools/`.
- **Konkrete Änderungen:**
  - **Z. 9–14:** Streichen von `sb-desktop`, `sb-studio`, `sb-shell`, `skully`, `NetGrid`.
  - **Ersatz:** Auflistung aller 14 im Verzeichnis vorhandenen Tools (`sb`, `sb-core`, `sb-app-contract`, `sb-app-protocol`, `sb-auth`, `sb-code`, `sb-db`, `sb-dns`, `sb-drive`, `sb-forge`, `sb-key`, `sb-mesh`, `sb-node`, `sb-proxy`).
  - **Z. 21:** Aussage korrigieren: Alle Tools sind vollwertige Mitglieder des Root-Cargo-Workspace.

#### 28. `tools/sb/README.md`
- **Ziel:** Beseitigung von Desktop-/Tauri-Artefakten.
- **Konkrete Änderungen:**
  - **Z. 52:** Erwähnung des Desktop-Clients und Tauri-Adapters streichen.
  - **Z. 112:** Behauptung über separate UI-/App-Workspaces entfernen.

#### 29. `tools/sb/TODO.md`
- **Ziel:** Bereinigung der Delegations- und Befehlsübersicht.
- **Konkrete Änderungen:**
  - **Z. 9, 23, 25, 31, 34, 46–48:** Altreferenzen auf `sb-ssh`, `sb-vault`, `sb-ports` bereinigen.
  - **Z. 126, 127, 134:** Befehlstabelle: `sb ports`, `sb ssh`, `sb vault` entfernen.

#### 30. `tools/sb-auth/README.md`
- **Ziel:** Entfernung von Frontend- und UI-Bibliotheks-Altlasten.
- **Konkrete Änderungen:**
  - **Z. 142–161 (Abschnitt Option B):** Streichen der React-Komponenten aus `@skulls-and-bones/ui` und Desktop-Client-Referenzen. Verweis auf reine REST/JSON- und Embedded-HTML-Nutzung beschränken.

#### 31. `tools/sb-code/README.md`
- **Ziel:** Beseitigung der `sb-studio`-Kopplung.
- **Konkrete Änderungen:**
  - **Z. 30:** Erwähnung von `sb-studio` und dessen Sync-Bar entfernen; stattdessen die `sb-code`-Mesh-Sync-API allgemein dokumentieren.

#### 32. `tools/sb-drive/TODO.md`
- **Ziel:** Bereinigung alter Desktop- und Shell-Konzepte.
- **Konkrete Änderungen:**
  - **Z. 26, 27, 65, 67–68:** `sb-shell`, `Phantom Desktop` und `Tauri v2 Phantom Desktop (sb-vault)` entfernen.

#### 33. `tools/sb-forge/README.md`
- **Ziel:** Bereinigung alter SSH-Prototyp-Hinweise.
- **Konkrete Änderungen:**
  - **Z. 33:** Erwähnung von `sb-ssh/NetGate` bereinigen.

#### 34. `tools/sb-forge/TODO.md`
- **Ziel:** Bereinigung alter Workspace-Referenzen.
- **Konkrete Änderungen:**
  - **Z. 39:** `Forge-/Tauri-/Frontend- und Release-Workspaces` korrigieren auf Cargo-Workspace.

#### 35. `tools/sb-key/TODO.md`
- **Ziel:** Bereinigung alter Tool-Listen.
- **Konkrete Änderungen:**
  - **Z. 13, 24, 85:** `sb-ssh`, `sb-vault`, `sb-login` bereinigen.

#### 36. `tools/sb-node/README.md`
- **Ziel:** Bereinigung des `sb-studio`-Verweises.
- **Konkrete Änderungen:**
  - **Z. 38:** `For Studio code sync...` ändern zu `For remote code sync...`.

#### 37. `tools/sb-proxy/README.md` & `tools/sb-proxy/TODO.md`
- **Ziel:** Beseitigung von `sb-studio`- und Tauri-Referenzen.
- **Konkrete Änderungen:**
  - `README.md` Z. 15: `Nahtlose S&B Studio Integration...` entfernen.
  - `TODO.md` Z. 13, 80–87, 122–125: Milestone 6 („S&B Studio Live-Synchronisation“) und Tauri-IPC-Referenzen als obsolet/ausgegliedert markieren.

---

## 6. Verifikations- und Ausführungsstrategie für die nachfolgende Dokumentenpflege

Für den nachfolgenden Umsetzungsagenten (Editor/Writer) empfiehlt sich folgende strukturierte Vorgehensweise:

1. **Batch 1 — Root & Manifeste (Höchste Priorität):**
   - `README.md`
   - `ROADMAP.md`
   - `docs/QUALITY_GATES.md`
   - `docs/MANIFESTO.md`
   - `tools/README.md`
2. **Batch 2 — Kern-Architektur & Entscheidungen:**
   - `docs/ARCHITECTURE.md`
   - `brain/decisions.md`
   - `brain/README.md`
3. **Batch 3 — Pläne & Backlogs:**
   - `brain/implementation_plan.md`
   - `brain/backlog.md`
   - `brain/vision.md`
4. **Batch 4 — Spezifikationen & historische Konzeptpapiere:**
   - `docs/SB_PORTS_PORTSENTRY_SPEC.md`
   - `docs/SB_SHELL_SOVEREIGN_TERMINAL_SPEC.md`
   - `docs/SKEL_FRAMEWORK.md`
   - `docs/SOVEREIGN_SUITE_INTEGRATION_MAP.md`
   - `docs/VISION_AND_PRIORITIZED_TASKS.md`
   - `docs/DEV_SERVER_SETUP.md`
   - `docs/SOVEREIGN_FLEET_ARCHITECTURE.md`
   - `docs/DEVELOPER_SOP_FORGE_RELEASE_FLOW.md`
   - `docs/RELEASE_AND_DISTRIBUTION_MANIFEST.md`
   - `docs/SB_MESH_APP_STANDARD.md`
   - `docs/MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md`
   - `docs/SB_DNS_SOVEREIGN_RESOLVER_SPEC.md`
   - `docs/OPERATIONS_HARDENING.md`
   - `brain/walkthrough.md`
   - `brain/continuation_summary.md`
   - `brain/forge-complete-concept.md`
5. **Batch 5 — Tool-READMEs & Tool-TODOs:**
   - `tools/sb/README.md`
   - `tools/sb/TODO.md`
   - `tools/sb-auth/README.md`
   - `tools/sb-code/README.md`
   - `tools/sb-drive/TODO.md`
   - `tools/sb-forge/README.md`
   - `tools/sb-forge/TODO.md`
   - `tools/sb-key/TODO.md`
   - `tools/sb-node/README.md`
   - `tools/sb-proxy/README.md`
   - `tools/sb-proxy/TODO.md`

### Verifikationsprüfung nach Dokumenten-Änderung:
Nach allen Dokumentationsanpassungen muss die Suite-Integrität nachgewiesen werden durch:
```bash
npm run verify:suite
```
Erwartetes Ergebnis: Exit-Code 0, alle 14 Crate-Prüfungen und 882+ Tests grün, Website gebaut, 0 Schwachstellen.
