---
title: "Skulls & Bones — Roadmap"
status: target-plan
updated: 2026-11-20
---

# Skulls & Bones — Roadmap

> Skulls & Bones baut modulare Werkzeuge für souveräne Entwicklungs- und Infrastruktur-Workflows. Diese Roadmap beschreibt Ziele und Prioritäten, keine Release-Zusagen oder vollständige Implementierung.

## Markenversprechen

**Souveräne Werkzeuge. Klare Grenzen. Nachprüfbare Sicherheit.**

Die Marke steht für Betreiberkontrolle, modulare Tools und verständliche, überprüfbare technische Entscheidungen. Skulls & Bones ist keine einzelne Desktop-Anwendung, kein selbsternanntes „Betriebssystem“ und keine pauschale Sicherheitsgarantie. „Zero Trust“, „Air-Gap“, „cloudfrei“ und ähnliche Begriffe nur für einen konkreten, getesteten Ablauf und dessen Bedrohungsmodell verwenden.

## Produktmodell

Das aktuelle Workspace-Modell umfasst **12 Rust-Crates** sowie die Web-Konsole (`console/`):
- **CLI & Kern:** `sb` (CLI), `sb-core` (Domain-Typen, Verträge, IPC, Dateiberechtigungen)
- **Identität, CA & Authentifizierung:** `sb-auth` (Ed25519-Tokens, Argon2id), `sb-ca` (X.509/SSH CA), `sb-key` (Key-Management), `sb-cred-provider` (Windows COM), `sb-linux-auth` (Linux PAM/NSS)
- **Daten, DNS & Mesh:** `sb-db` (SQLite WAL, AES-256-GCM, X25519 E2EE, Ticket-RBAC), `sb-dns` (Name Resolution), `sb-mesh` (Mesh Network Layer), `sb-proxy` (Reverse Proxy), `sb-node` (Node/DC-Agent mit OIDC, LAPS und OS-Logon-Provisionierung)
- **Web-Konsole:** `console/` (React + Vite SPA)

*Hinweis zu ausgegliederten Komponenten:* Frühere Desktop-Apps (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Pakete (`skel`, `sb-ui`) sowie separate Shell-/Terminal-Projekte (`sb-shell`, `skully`) wurden aus der Core-Suite ausgegliedert. Historische Namen wie `sb-ssh` und `sb-vault` sind keine Suite-Produkte.

## Beschlossene Richtung

- Die Suite bleibt modular; kein Monolith.
- Quellcode und maßgebliche Entwicklung sollen künftig im Sovereign Dev Mesh stattfinden. `sb-code` soll die Versionsverwaltung werden; alte Git-Historie wird nicht in die neue Historie importiert.
- Jedes Tool soll einen eigenen logischen Projekt-Working-Space im Dev Mesh erhalten. Topologie, ACLs und Replikation sind noch zu entwerfen.
- `sb` soll versionierte Tool-Artefakte aus dem öffentlichen Sovereign Mesh beziehen und die Signatur mit einem gepinnten öffentlichen Schlüssel prüfen. Der Mesh-Transport selbst ist kein Trust Anchor.
- Die zuerst vereinbarte Betriebsgrenze erlaubt denselben physischen Host für Public Web, Mesh und Signierer, setzt jedoch getrennte Prozesse und OS-Servicekonten voraus. Root/Kernel gelten zunächst als vertrauenswürdig.
- FROST/Threshold Signing mit unabhängigen Teilnehmern ist ein späteres Härtungsziel, nicht der aktuelle Release-Prozess.

## Prioritäten

### 1. Produktinventar und Release-Wahrheit

Crates, Binaries, Anwendungen, Workspaces, Plattformen, Abhängigkeiten und Reifegrade in einem überprüfbaren Inventar zusammenführen. Alte Produktnamen und nicht gebaute Artefakte aus Installer-/Release-Aussagen entfernen. `cargo install` aus einem Registry ist nicht der beschlossene langfristige Sovereign-Artefaktfluss.

### 2. Gemeinsame Service-Verträge

`sb-core`, Tauri Commands und `sb daemon` zu einer versionierten lokalen Service-Grenze entwickeln. Authentisierung, Autorisierung, Versionierung, Größenlimits und echtes Fehlerverhalten vor Produktivnutzung festlegen.

### 3. Mesh-Instanzisolation

Identität, Schlüssel, Peer-/RBAC-State und Konfiguration pro Mesh-Instanz trennen. Re-Initialisierung erfordert neues Peer-Pairing; keine automatische Übernahme oder Löschung alter lokaler Zustände.

### 4. Sichere Artefaktverteilung

Release-Signaturen vor Download-/Installationsautomatisierung implementieren und testen. Rotation, Recovery und Kompromittierung des gepinnten Schlüssels regeln.

### 5. `sb-code` und Working Spaces

Das lokale Daten-, Integritäts-, Backup- und Recovery-Modell stabilisieren, bevor Mesh-Replikation oder paralleles Schreiben freigegeben wird. Konfliktmodell und Autorisierung zuerst prototypisieren.

### 6. Produktgrenzen

Die Core-Suite konzentriert sich auf die 14 autarken CLI-Tools, Daemons und Vertragscrates. Desktop-Frontends (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Frameworks (`skel`, `sb-ui`) sowie separate Shell- und Terminal-Experimente (`sb-shell`, `skully`) sind ausgegliedert und werden nicht im Core-Workspace weitergeführt.

## Produkt- und Sicherheitsstatus

Das Repository enthält laufende Implementierungen und Prototypen; diese Roadmap zertifiziert keine davon als produktionsreif. Insbesondere:

- Das frühere `sb-forge env.sealed`-Format besaß keine belegte serverseitige Schlüsselbindung; Erzeugung und Nutzung sind inzwischen fail-closed deaktiviert. Vorhandene Dateien sind nicht vertraulich; siehe [`brain/forge-secrets-design.md`](brain/forge-secrets-design.md).
- `sb-forge exec` reicht Secret-Werte über Prozess-Environment-Variablen an einen Kindprozess weiter; dies ist kein Zero-Trace- oder fd-basiertes Verfahren.
- Die heutige `sb`-Installation ist noch nicht der beschlossene signaturgeprüfte Public-Mesh-Artefaktfluss.
- Der Root-Cargo-Workspace umfasst alle 14 konsolidierten Kern-Tools lückenlos.

### Umsetzungsstand: Produktinventar und 14-Core-Konsolidierung

- `product-inventory.json` ist die autoritative Inventarquelle für `sb`, den Suite-Daemon und das Release-Staging. Sie führt alle 14 Kern-Tools mit Package-/Binary-Identität, Version, Produktart, Reifegrad, Abhängigkeiten, Release-Targets und Prüfpfad.
- Die Installer-Auswahl und die Release-Pipeline (`sb release pack`) paketieren ausschließlich im Inventar als installierbar und für das Target freigegebene Binaries. Historische Altsysteme (`sb-ssh`, `sb-vault`, `sb-ports`) sind nicht katalogisiert.
- `suite.catalog` ist über API-Version 1 im authentisierten Loopback-JSON-RPC erreichbar und wird von `sb catalog` verwendet. Request-/Response-Größen, Framing und Verbindungszahl sind begrenzt; nicht abgefragte Dienste werden im Status als `not_probed` ausgewiesen.
- Alle 14 Kern-Tools sind im gemeinsamen Cargo-Workspace vereint und werden über `npm run verify:suite` lückenlos getestet und auditiert.

## Quellen und Status

- Zielarchitektur und Ist-Abweichungen: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- KI- und Maintainer-Kontext: [`brain/README.md`](brain/README.md)
- Bestätigte Produktentscheidungen: [`brain/decisions.md`](brain/decisions.md)
- Priorisierter Arbeitsplan: [`brain/implementation_plan.md`](brain/implementation_plan.md)

Checkboxen, Versionsnummern oder frühere Roadmaps sind kein Nachweis einer abgeschlossenen Implementierung. Ein Status darf erst nach Prüfung des betroffenen Codes und der vorgesehenen Tests aktualisiert werden.
