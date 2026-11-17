---
title: "Skulls & Bones — Priorisierter Architektur-Arbeitsplan"
document_type: implementation-roadmap
status: canonical
language: de
updated: 2026-10-18
---

# Priorisierter Arbeitsplan

Dieser Plan ordnet die Architekturarbeit und dokumentiert die erreichten Meilensteine zur Verwirklichung der Vision ([`brain/vision.md`](vision.md)).

## Leitplanken

- Maßgeblich: [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) und [`decisions.md`](decisions.md).
- Keine große Implementierung über offene Vertrauensgrenzen hinweg.
- Eigenständige Tools behalten ihre Fachlogik; gemeinsame Verträge gehören in `sb-core`.
- Sämtliche Änderungen werden über `sb-code` versioniert und signiert.

## Abschlussstatus (2026-10-26)

Die Phasen 1–6 dokumentieren umgesetzte Funktionsbereiche. Für die Suite gilt die bestätigte Ausgliederungsentscheidung aus [`decisions.md`](decisions.md): Desktop-Frontends (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Frameworks (`skel`, `sb-ui`) sowie Shell und Terminal (`sb-shell`, `skully`) wurden vollständig aus der Core-Suite ausgegliedert. Das Ökosystem konzentriert sich rein auf die 14 konsolidierten Kern-Tools und die Webpräsenz (`website/`). Die verbleibenden Reifegrad- und Release-Gates stehen im [Abschluss-Backlog](backlog.md#abschluss-gates-nach-projektcheck-2026-10-17).

## Phase 1 — Produktinventar und Wahrheit der Dokumentation (Erledigt)

**Ziel:** Eine Quelle für Produkt-ID, Verzeichnis, Crate/Binary, Version, Build-/Release-Einheit, Zuständigkeit, Status und Abhängigkeiten.

- Single Source of Truth [`product-inventory.json`](../product-inventory.json) etabliert.
- Bereinigung aller unzulässigen Marketingbegriffe („Zero Trust“, „100% Offline-Resilienz“) in Website, READMEs und Codebasis.
- Website auf Vite + React 19 SPA mit dynamischem Laden des Inventars umgestellt.

**Status:** Vollständig umgesetzt & verifiziert (**[P0-1]**, **[P0-2]**, **[P0-7]**).

## Phase 2 — `sb-core`, Services und lokale API (Erledigt)

**Ziel:** Werkzeuge und externe Clients können dieselben Suite-Funktionen über stabile Verträge nutzen, ohne den Code zu einem Monolithen zu koppeln.

- Gemeinsamer Vault-Vertrag (`derive_vault_key`, `encrypt_payload`, `decrypt_payload`) in `sb-core::vault` mit >= 12 Zeichen Mindestpasswortlänge konsolidiert.
- Standardisierter Mesh-Service-Vertrag (`MeshService` Trait, `mesh.status`, `mesh.nodes`, `mesh.ping`, `mesh.set_air_gap`) in `sb-core::rpc` und `sb daemon`.
- Versioniertes JSON-RPC 2.0 mit Envelope, Bearer-Token-Authentisierung und `MAX_RPC_REQUEST_BYTES` Größenlimit.

**Status:** Vollständig umgesetzt & verifiziert (**[P0-3]**, **[P1-1]**).

## Phase 3 — `sb-mesh` Trust Boundaries (Erledigt)

**Ziel:** Mesh-Mitgliedschaft und lokale Schlüsselräume so trennen, dass die Sicherheitsbehauptung zur tatsächlichen OS- und Prozessgrenze passt.

- Vertrauensdomänen (`TrustDomain`: Public, Dev, Secret) in `sb-mesh::state`.
- Prozess- und Isolationsinspektion (`sb mesh isolation`) für OS-Dienstkonten.
- Kollisionsschutz (`validate_identity_isolation`) gegen Key-Wiederverwendung über mehrere Meshes.
- Katalog-DC-Membership, Freshness-Lease und Replikations-Gate in `sb-node` (Port 58831).

**Status:** Vollständig umgesetzt & verifiziert (**[P1-2]**, **[P1-4]**).

## Phase 4 — Release-Artefakte und Signing (Erledigt)

**Ziel:** `sb` bezieht versionierte Tools aus dem öffentlichen Sovereign Mesh oder HTTPS-Mirrors mit strikter kryptografischer Verifikation.

- Gekapselter Release-Download und Signaturprüfung gegen den gepinnten Schlüsselanker (`RELEASE_PUBLIC_KEY`).
- Vollständige SOP [`docs/RELEASE_KEY_LIFECYCLE.md`](../docs/RELEASE_KEY_LIFECYCLE.md) für Keygen, Backup, Recovery und Rotation; CLI-Befehl `sb release verify-key`.
- Mesh-Release-Verteilung (`sb release publish`, `sb release fetch`, `sb install/update --from-mesh`) mit Divergenz- und Digest-Validierung.
- Vollwertiger HTTP/1.1- & HTTP/2-Edge-Stack in `sb-proxy` mit ACME, SNI-Mischbetrieb und Security-Headern.

**Status:** Vollständig umgesetzt & verifiziert (**[P0-4]**, **[P1-3]**, **[P2-2]**). *(Netzwerkseitige Port 443 Freischaltung auf Live-Host als Ops-Aufgabe dokumentiert).*

## Phase 5 — `sb-code` und Projekt-Working-Spaces (Erledigt)

**Ziel:** `sb-code` ist die maßgebliche Versionsverwaltung; AST-gebundenes Review, Scopes und dezentrale Replikation.

- BLAKE3 Merkle-DAG mit kryptografischer Ed25519-Commit-Signierung (`sb code commit`, `sb code verify`).
- Logische Working-Spaces pro Tool (`dev/tools/<tool>`) im Dev Mesh mit Single-Writer-Autorität und CAS-Divergenzschutz (`dev_workspace.rs`, `mesh_sync.rs`).
- Souveräner Bundle Export/Import für Snapshot-Recovery.

**Status:** Vollständig umgesetzt & verifiziert (**[P0-5]**, **[P1-5]**, **[P2-3]**, **[P2-4]**).

## Phase 6 — Shell- und Terminal-Ausgliederung (Abgeschlossen)

**Ziel:** Bereinigung des Core-Workspaces durch Ausgliederung experimenteller Shell- und GPU-Terminal-Projekte.

- `sb-shell` und `skully` wurden als separate Projekte ausgegliedert und aus dem Core-Workspace entfernt.
- Die Suite stützt sich auf Standard-Terminals und native Shells der Betriebssysteme.

**Status:** Ausgliederung abgeschlossen.

## Phase 7 — Ausgliederung der Desktop-Frontends & 14-Core-Konsolidierung (Abgeschlossen)

**Ziel:** Vollständige Fokussierung des Core-Workspaces auf das 14-Core-Ökosystem aus autarken CLI-Tools, System-Daemons und gemeinsamen Vertragscrates.

- **Ausgliederung:** Sämtliche Desktop-Anwendungen (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Frameworks (`skel`, `sb-ui`) sowie Shell/Terminal (`sb-shell`, `skully`) wurden aus dem Core-Workspace ausgegliedert bzw. entfernt.
- **Konsolidierter Workspace:** Alle 14 Kern-Tools (`sb`, `sb-core`, `sb-app-contract`, `sb-app-protocol`, `sb-auth`, `sb-code`, `sb-db`, `sb-dns`, `sb-drive`, `sb-forge`, `sb-key`, `sb-mesh`, `sb-node`, `sb-proxy`) sind lückenlos im Root-Cargo-Workspace vereint und werden gemeinsam gebaut und getestet.
- **SB-MAP Verträge:** `sb-app-contract` und `sb-app-protocol` verbleiben im Core als autoritative Spezifikation und Rust-Implementierung für externe Mesh-Clients und -Services.
- **Web-Präsenz:** Die öffentliche Website (`website/`) bleibt eine getrennte Vite + React 19 SPA, die statisch via `sb-proxy static` ausgeliefert wird.

**Status:** Konsolidierung auf 14 Kern-Tools erfolgreich umgesetzt & im Root-Workspace verifiziert.

## Qualitäts-Gates & Verifikationsstand (2026-10-26)

- `npm run verify:suite` ist lokal auf Windows vollständig grün (Exit-Code 0). Der Prüflauf validiert:
  1. **Rust Formatting**: `cargo fmt --all -- --check` über alle Crates.
  2. **Root Workspace Check**: `cargo check --workspace` über alle 14 Kern-Tools fehler- und warnungsfrei.
  3. **Root Workspace Tests**: `cargo test --workspace` mit 882+ bestandenen Tests (100% grün).
  4. **Produktinventar**: `product-inventory.json` validiert gegen alle 14 Tool-Verzeichnisse, Manifeste und Paketversionen.
  5. **Website Production Build**: `npm --prefix website run build` fehlerfrei.
  6. **Website Dependency Audit**: `npm --prefix website audit --audit-level=high` (0 Schwachstellen).
- *Hinweis zu gelöschten Gates:* Frühere Prüfungen für separate Tauri-Manifeste, SKEL-E2E-Tests und NetGrid-Lint wurden mit der Ausgliederung der entsprechenden Altsysteme entfernt.
- **Release-Kette:** Lokale Release-Paketierung und atomare Installation erfolgen über `sb release pack` und `sb install` mit Ed25519-Signaturprüfung und Downgrade-Schutz.
