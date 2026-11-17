---
title: "Skulls & Bones — Vision und Belegmatrix"
document_type: architecture-evidence
status: kanonisch
language: de
updated: 2026-10-08
---

# Skulls & Bones — Vision & Belegmatrix

Dieses Dokument definiert das verbindliche Zielbild von Skulls & Bones und belegt für jede Säule den **tatsächlichen Ist-Stand im Quellcode**, die **geprüften Nachweise** sowie die **verbleibenden Lücken und Risiken**.

Gemäß den Projektleitplanken ([`brain/README.md`](README.md)) werden Werbebegriffe wie „Zero Trust“, „Zero Trace“, „100% sicher“ oder „produktionsreif“ nicht als pauschale Garantien verwendet, sondern auf konkrete Code-Pfade, Bedrohungsmodelle und Testläufe begrenzt.

---

## 1. Vision

Skulls & Bones entwickelt eine modulare, souveräne Suite aus Entwicklungs- und Infrastrukturwerkzeugen für Einzelpersonen und Teams, die ihren Quellcode, ihre kryptografischen Identitäten, Secrets und Release-Abläufe selbst kontrollieren wollen – ohne Abhängigkeit von zentralen Plattformen oder SaaS-Monopolen.

### Kernprinzipien

1. **Souveränität statt Plattformzwang**: Selbst gehostete Infrastruktur, dezentrale Peer-to-Peer-Kopplung und lokale Datenhoheit.
2. **Modularität statt Monolith**: Eigenständige Tools mit klarer Fachzuständigkeit (14 Kern-Tools: `sb`, `sb-core`, `sb-app-contract`, `sb-app-protocol`, `sb-auth`, `sb-code`, `sb-db`, `sb-dns`, `sb-drive`, `sb-forge`, `sb-key`, `sb-mesh`, `sb-node`, `sb-proxy`). `sb` ist Launcher, Orchestrator und Paketmanager.
3. **Sicherheit als belegte Eigenschaft**: Klare Trust Boundaries, kryptografische Verifikation, gehärtete Defaults und ehrliche Kennzeichnung von Grenzen statt Marketing-Superlativen.
4. **Ergonomische Entwicklerwerkzeuge**: Konsistente CLI-, Daemon- und Service-Workflows sowie moderne Webpräsenz.

---

## 2. Die 6 Säulen: Soll-Bild, Ist-Stand & Code-Belege

### Säule 1: Modulare Werkzeug-Suite & Paketierung (`sb`, `sb-core`)

* **Soll-Bild**: `sb` fungiert als leichtgewichtiger Launcher und Manager für eigenständige, einzeln versionierte Tools. Das integrierte Produktinventar ist Single Source of Truth für Namen, Binaries und Reifegrade.
* **Ist-Stand**:
  * Zentrale Katalog-Definition in [`tools/sb-core/src/catalog.rs`](../tools/sb-core/src/catalog.rs).
  * Paket-Installation mit Release-Manifest-Parsing und Downgrade-Schutz via SemVer in [`tools/sb/src/commands/release.rs`](../tools/sb/src/commands/release.rs).
  * Atomare Dateiersetzung auf Plattform-Ebene (`MoveFileExW` mit `MOVEFILE_WRITE_THROUGH` auf Windows) in `release.rs`.
  * Alle 14 Kern-Tools sind lückenlos im Root-Cargo-Workspace vereint; Desktop-Frontends wurden ausgegliedert.
* **Geprüft (2026-10-26)**:
  * `cargo check --workspace` (0 Fehler, 0 Warnungen).
  * Unit- und Integrationstests über alle 14 Crates im Workspace erfolgreich (882+ Tests grün).
  * Suite-Verifikation via `npm run verify:suite` läuft vollständig fehlerfrei durch.
* **Lücken & Backlog**:
  * Verknüpfung zu Backlog: **[P2-1]** (Erledigt), **[P2-2]** (Erledigt), **[F0-1]** (Geprüft).

---

### Säule 2: Dezentrale Vernetzung (`sb-mesh`)

* **Soll-Bild**: Sicheres Peer-to-Peer-Overlay-Netzwerk mit getrennten Mesh-Instanzen, strikter Mandanten-/Identitätstrennung und User-Space-Routing.
* **Ist-Stand**:
  * Verzeichnisstruktur für benannte Meshes (`~/.sb-mesh/instances/<mesh>/`) in [`tools/sb-mesh/src/state.rs`](../tools/sb-mesh/src/state.rs).
  * Systemd-Härtung (Sandboxing) in [`tools/sb-mesh/src/service.rs`](../tools/sb-mesh/src/service.rs).
  * User-Space-VRF-Prüfung (`validate_vrf_boundary`) in [`tools/sb-mesh/src/network.rs`](../tools/sb-mesh/src/network.rs).
  * Constant-Time-Secret-Vergleich im RBAC-System in [`tools/sb-mesh/src/rbac.rs:487`](../tools/sb-mesh/src/rbac.rs).
  * Mandanten-/Instanzisolation und Vertrauensdomänen (`TrustDomain`) in `sb-mesh::state` implementiert; Schutz vor Key-Wiederverwendung in `sb-mesh::identity`.
* **Geprüft (2026-10-09)**:
  * `sb-mesh`-Tests im Workspace grün (159 passed).
* **Lücken & Risiken**:
  * Multi-Mesh-Isolation ist auf Dateisystem- und Key-Ebene isoliert, bietet aber unter Windows keine getrennten OS-Dienstkonten ([ARCHITECTURE §6](../docs/ARCHITECTURE.md)).
  * Verknüpfung zu Backlog: **[P1-2]** (Erledigt).

---

### Säule 3: Souveräne Versionskontrolle (`sb-code`)

* **Soll-Bild**: Quellcodeverwaltung ohne Git-Monopol, basierend auf AST-/CST-Scopes statt rein zeilenbasierten Diffs. Opaque Regions bei Syntaxfehlern oder unbekannten Sprachen.
* **Ist-Stand**:
  * Tree-sitter-Integration (Version 0.25) mit Grammatiken für Rust, TypeScript und Java in [`tools/sb-code/src/language.rs`](../tools/sb-code/src/language.rs).
  * Scoping und Fallback-Heuristiken in [`tools/sb-code/src/ast.rs`](../tools/sb-code/src/ast.rs).
  * BLAKE3 Merkle-DAG mit kryptografischer Ed25519-Commit-Signierung (`vcs.rs`).
  * Isolierte Dev-Mesh-Namespaces mit Single-Writer-Autorität und CAS-Divergenzschutz (`dev_workspace.rs`, `mesh_sync.rs`).
* **Geprüft (2026-10-26)**:
  * `cargo test -p sb-code` erfolgreich (168 passed).
* **Lücken & Risiken**:
  * Verknüpfung zu Backlog: **[P2-3]** (Erledigt), **[P2-4]** (Erledigt), **[P1-5]** (Erledigt).

---

### Säule 4: Kryptografische Integrität & Release-Pipeline (`sb-release`, `sb-proxy`)

* **Soll-Bild**: Streng verifizierte Verteilung von Binaries über Ed25519-Signaturen und SHA-256-Prüfsummen. Gekapselter Release-Download und sichere statische Auslieferung.
* **Ist-Stand**:
  * Gepinnter Ed25519-Signaturschlüssel (`RELEASE_PUBLIC_KEY`) und strikte Prüfung via `verify_strict` in [`tools/sb/src/commands/release.rs`](../tools/sb/src/commands/release.rs).
  * Mesh-Release-Verteilung (`sb release publish`, `sb release fetch`, `sb install --from-mesh`, `sb update --from-mesh`) mit Signatur-, Digest-, Idempotenz- und Divergenzprüfung.
  * Statische Datei-Auslieferung in `sb-proxy` mit Pfad-Normalisierung, Blockierung von Directory-Traversal, Dotfiles und unsicheren Symlinks.
  * Vollwertiger HTTP/1.1- und HTTP/2-Stack mit Keep-Alive, Streaming und MIME-Guessing in [`tools/sb-proxy/src/http_server.rs`](../tools/sb-proxy/src/http_server.rs).
  * Echtes Let's-Encrypt-ACME via TLS-ALPN-01 und Fail-Closed ohne TLS bei öffentlicher Bindung.
* **Geprüft (2026-10-09)**:
  * `cargo test -p sb-cli -p sb-proxy -p sb-code` erfolgreich (72 CLI-Tests, 39 Proxy-Tests, 168 Code-Tests).
* **Lücken & Risiken**:
  * Live-Release-Host `skulls-and-bones.org`: Port 443 netzwerkseitig auf Server noch zu öffnen (UFW/Firewall).
  * Verknüpfung zu Backlog: **[P0-4]** (Geprüft), **[P1-3]** (Erledigt), **[P2-2]** (Erledigt).

---

### Säule 5: Gemeinsames Secret-Management (`sb-core` / Vault)

* **Soll-Bild**: Zentrales Vault-Modul in `sb-core` mit Argon2id + AES-256-GCM. Alle UIs und Tools greifen über dieselbe Schnittstelle auf denselben lokalen Vault (`~/.sb/vault`) zu.
* **Ist-Stand**:
  * Vault-Kryptografie in [`tools/sb-core/src/vault.rs`](../tools/sb-core/src/vault.rs) mit Zeroizing für sensible Speicherbereiche.
  * Master-Passwort-Mindestlänge auf >= 12 Zeichen gehärtet.
  * Einheitlicher Service-Vertrag (`MeshService`, kanonische RPC-Methoden in `sb daemon`).
* **Geprüft (2026-10-09)**:
  * Unit-Tests in `sb-core` erfolgreich (29 passed).
* **Lücken & Risiken**:
  * Kein Speicherschutz gegen OS-Paging/Dumps (ehrlich in `decisions.md` dokumentiert).
  * Verknüpfung zu Backlog: **[P0-3]** (Erledigt), **[P1-1]** (Erledigt).

---

### Säule 6: Öffentliche Webpräsenz & Edge-Auslieferung (Website, `sb-proxy`)

* **Soll-Bild**: Autarke öffentliche Webpräsenz (`website/`), unabhängig von Desktop- oder Mesh-Runtimes, modular ausgeliefert via `sb-proxy static`.
* **Ist-Stand**:
  * Website als moderne Vite + React 19 SPA mit Tailwind CSS.
  * Live-Bestandsdaten direkt aus dem autoritativen `product-inventory.json`.
  * Auslieferung über `sb-proxy static` mit HTTP/2, ETag-Caching, Gzip-Kompression und SPA-Fallback.
  * *Hinweis zu ausgegliederten Frontends:* Frühere Desktop-Apps (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`) sowie das interne UI-Paket (`sb-ui`) wurden aus der Suite ausgegliedert.
* **Geprüft (2026-10-26)**:
  * `npm --prefix website run build` baut fehlerfrei.
  * `npm --prefix website audit --audit-level=high` meldet 0 Schwachstellen.
* **Lücken & Risiken**:
  * Verknüpfung zu Backlog: **[P0-1]** (Erledigt), **[P0-2]** (Erledigt).

---

## 3. Nachweis- und Prüfstatus-Übersicht

| Komponente | Letzte Prüfung | Prüfumfang | Befund |
|---|---|---|---|
| **14 Core Tools Workspace** | 2026-10-26 | `cargo check --workspace` | 0 Warnungen, 0 Fehler |
| **Rust Tests** | 2026-10-26 | `cargo test --workspace` | 882+ Tests bestanden (100% grün) |
| **Suite Quality Gate** | 2026-10-26 | `npm run verify:suite` | Exit-Code 0 (Format, Workspace, Tests, Website-Build, Audit) |
| **Website & Edge** | 2026-10-26 | `npm --prefix website run build && audit` | 0 Schwachstellen, Build fehlerfrei |
| **Release-Netzwerk** | 2026-10-08 | `Test-NetConnection -Port 443` | Host antwortet auf Ping, Port 443 verwirft TCP-Pakete (Server-Firewall) |
| **Lokales System** | 2026-10-09 | `sb doctor` | 2 Warnungen (Root-CA im OS nicht installiert, SSH.exe im Cargo-Pfad) |


