# Skulls & Bones — Release- und Distributionsvertrag

> **Status (2026-10-03):** Zielvertrag und Inventar-Anforderungen, keine historische Release-Bestätigung. Frühere Versionsnummern, Binary-Anzahlen, Prüfsummen und CI-Behauptungen sind nicht als Nachweis eines aktuellen Releases zu verstehen.

Für die gegenwärtigen Abweichungen gilt [`ARCHITECTURE.md`](./ARCHITECTURE.md); priorisierte Arbeit steht in [`../brain/implementation_plan.md`](../brain/implementation_plan.md).

## 1. Produktmodell

Skulls & Bones besteht aus eigenständig gebauten, getesteten und versionierten Tools. `sb` ist Launcher und Tool-Manager, kein Bundle, in dem alle Fachfunktionen zusammengeführt werden.

Das Release-Inventar soll für jede Verteilung mindestens folgende Felder führen:

| Feld | Zweck |
|---|---|
| Produkt-ID / Anzeigename | Kanonischer Produktname; alte Namen explizit als historisch ausweisen |
| Crate / Binary / Paket | Exakte Bau- und Installationsartefakte |
| Version und Suite-Kompatibilität | Unabhängige Version plus geprüfte optionale Suite-Kombination |
| Plattform / Architektur | Konkrete Ziel-Triple und Testumfang |
| Build-Quelle | Nachvollziehbarer Commit/`sb-code`-Change-Set und Toolchain |
| Signatur-Key-ID | Zugeordneter Release-Key und Verifikationsweg |
| Reifegrad | geplant, Prototyp, implementiert (nicht releasevalidiert) oder releasevalidiert |

## 2. Beschlossene Zielverteilung

- `sb` bezieht versionierte Tool-Artefakte aus dem öffentlichen Sovereign Mesh; Website und Artefakt-Hosting können dort liegen.
- Der Client vertraut einem gepinnten öffentlichen Release-Schlüssel und verifiziert damit die Signatur über die exakten Artefaktbytes, bevor Installation oder Update erfolgt.
- Das Mesh ist Transport und Hosting, nicht der kryptografische Trust Anchor.
- Unbekannte, manipulierte oder ungültig signierte Artefakte werden fail-closed abgelehnt.
- Checksummen unterstützen Integritäts-/Übertragungsprüfungen, ersetzen aber keine kryptografische Signatur.
- Schlüsselrotation, Backup, Recovery, Rollback-Schutz und Kompromittierungsablauf müssen vor produktiver Verteilung feststehen.

## 3. Vereinbarte Betriebsgrenze des Signierers

Public Web, Mesh-Instanzen und Signierer dürfen zunächst denselben physischen Host nutzen, aber nicht denselben Prozess- oder Berechtigungsbereich. Erforderlich sind getrennte Prozesse, OS-Servicekonten und restriktive Dateirechte. Der Public-Webdienst erhält keinen Datei- oder IPC-Zugriff auf den privaten Signierschlüssel. Root und Kernel gelten in diesem Modell zunächst als vertrauenswürdig; es schützt nicht gegen deren Kompromittierung.

FROST/Threshold Signing mit unabhängigen Teilnehmern ist ein späteres Härtungsziel, kein derzeit belegter Releaseprozess.

## 4. Aktuelle Grenzen und Konsolidierungsstand

- Der bestehende `sb`-Installationspfad verwendet `cargo install <crate>` bzw. `sb release pack` und implementiert noch nicht den vollendeten Public-Mesh-Artefaktfluss samt gepinnter Signaturverifikation.
- Alle 14 Core-Tools (11 CLI/Daemon-Binaries + 3 Bibliotheken) sind im einheitlichen Root-Cargo-Workspace konsolidiert und werden mit `cargo check --workspace` und `cargo test --workspace` getestet.
- Das Website-Frontend (`website/`) wird separat mit Astro gebaut und auditiert (`npm run verify:suite`).
- Desktop-Applikationen (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), UI-Frameworks (`sb-ui`, `skel`) sowie eigenständige Shell-/Terminal-Tools (`sb-shell`, `skully`) und Prototypen (`sb-ssh`, `sb-vault`, `sb-ports`) wurden aus dem Core-Workspace als externe Satelliten bzw. historische Entwürfe extrahiert.
- Fehlt ein erwartetes Core-Artefakt oder schlägt ein Test fehl, meldet das Quality Gate `npm run verify:suite` einen Fehler.

## 5. Freigabekriterien

Ein Release darf erst als releasevalidiert bezeichnet werden, wenn:

1. Produkt und genaue Artefaktliste aus dem gepflegten `product-inventory.json` stammen.
2. Der Root-Cargo-Workspace (`cargo check/test --workspace`) und das Website-Frontend fehlerfrei gebaut und geprüft sind (`npm run verify:suite`).
3. Reproduzierbare Checksummen und Release-Signaturen für jedes Artefakt vorliegen.
4. Verifikation mit dem vorgesehenen gepinnten Schlüssel im Installer nachweislich vor Installation erfolgt.
5. Ungültige Signatur, unbekannter Schlüssel, beschädigtes Artefakt und unzulässiges Downgrade abgelehnt werden.
6. Release-Key-Betrieb und Recovery den vereinbarten Trust Boundaries entsprechen.

Eine Versionsnummer, ein Tag, CI-Lauf, Archiv oder SHA256-Datei allein erfüllt diese Kriterien nicht.
