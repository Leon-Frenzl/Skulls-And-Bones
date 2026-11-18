# Skulls & Bones — Developer and Release SOP

> **Status:** Zielablauf und Qualitätsleitplanken; kein Nachweis eines bereits automatisierten Release-Flows.
> **Maßgebliche Quellen:** [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`../brain/README.md`](../brain/README.md), [`../brain/decisions.md`](../brain/decisions.md).

## 1. Arbeitsprinzipien

1. **Modulare Produkte:** Änderungen bleiben im verantwortlichen Tool; gemeinsame Typen und Service-Verträge gehören in `sb-core`.
2. **Wahrheit vor Marketing:** Code, Tests und Konfiguration bestimmen den Ist-Stand. Roadmap-Checkboxes, Versionsnummern und Website-Illustrationen tun es nicht.
3. **Erhalt des Worktree:** Vorhandene uncommittete Änderungen vor Bearbeitung lesen und erhalten. Keine fremden Änderungen zurücksetzen.
4. **Sovereign Code — Ziel, nicht Ist-Claim:** `sb-code` und das Dev Mesh sollen die Quelle der Wahrheit werden. Die Migration ist nicht abgeschlossen; alte Git-Historie wird nicht in `sb-code` importiert.
5. **Kein unbelegtes Sicherheitsversprechen:** Keine Aussagen wie „zero trace“, „air-gapped“, „BSI-konform“ oder „produktionsreif“ ohne definierten Umfang und reproduzierbaren Nachweis.

## 2. Entwicklung und Prüfung

Vor einer Änderung:

- Betroffene crate-/app-Workspaces, lokale Änderungen, Codepfade und Tests bestimmen.
- Produktname und Zustand von Ziel und Ist trennen; offene Sicherheitsgrenzen nicht übergehen.
- Releases-/Installer-/Website-Oberflächen nur dann anpassen, wenn der reale Artefaktfluss nachweisbar mit geändert wird.

Vor einer technischen Freigabe:

1. Betroffene Rust-Crates mit `cargo check` und passenden `cargo test` (bzw. `--workspace`) prüfen.
2. Frontend- bzw. Website-Komponenten (`website/`) separat bauen und prüfen (integriert in `npm run verify:suite`); Desktop- und GUI-Apps wurden als externe Satelliten ausgelagert. Alle 14 Core-Tools liegen im einheitlichen Root-Cargo-Workspace.
3. OS-Integration (Tray, Clipboard, PTY, Child-Prozesse, Dateirechte) dort manuell testen, wo sie betroffen ist.
4. Ein Quality-Gate darf keinen Erfolg melden, wenn ein benötigtes Binary, Test-Target oder Artefakt fehlt.
5. Build-Logs, Plattformen und Umfang dokumentieren. Keine Testzahlen oder erfolgreiche Ausführung erfinden.

## 3. Ziel-Release-Vertrag

Die Zielarchitektur verlangt:

1. Eigenständiges, versioniertes Artefakt je Tool und ausgewiesene Suite-Kompatibilität.
2. Reproduzierbare Zielplattform- und Build-Metadaten.
3. Signatur über exakt die verteilten Artefaktbytes.
4. `sb` prüft die Signatur gegen einen gepinnten öffentlichen Schlüssel, bevor installiert oder aktualisiert wird.
5. Unbekannte, manipulierte oder ungültig signierte Artefakte werden abgelehnt.
6. Schlüsselrotation, Recovery, Rückstufungsschutz und Kompromittierungsablauf sind vor produktiver Verteilung dokumentiert.

Öffentliches Sovereign Mesh ist Transport/Hosting, nicht die Vertrauensbasis. Der aktuelle `sb`-Pfad verwendet noch `cargo install <crate>` und erfüllt diesen Zielvertrag nicht. Checksummen erkennen Übertragungsfehler, ersetzen aber keine Signatur.

## 4. Vereinbarte Hosting-Grenze

Public Web, Mesh-Instanzen und Release-Signierer dürfen zunächst auf demselben physischen Host laufen, sofern sie als getrennte Prozesse mit getrennten OS-Servicekonten und restriktiven Dateirechten betrieben werden. Root und Kernel gelten für dieses Modell als vertrauenswürdig. Ein kompromittierter Root/Kernel liegt außerhalb dieser ersten Trust Boundary.

Der Public-Webdienst erhält keinen Datei- oder IPC-Zugriff auf den privaten Release-Schlüssel. Signing-Key-Backup, Recovery und Rotation sind vor produktiver Veröffentlichung festzulegen. FROST/Threshold Signing mit unabhängigen Teilnehmern ist späteres Härtungsziel.

## 5. Forge-spezifische Sicherheit

- Das frühere `sb-forge env.sealed` verwendete keinen privaten Zielserver-Schlüssel für die Schlüsselableitung. `env seal`, `exec --sealed` und die automatische Legacy-Datei-Nutzung sind inzwischen fail-closed deaktiviert; alte Dateien sind nicht vertraulich und werden nicht automatisch gelöscht. Details in [`../brain/forge-secrets-design.md`](../brain/forge-secrets-design.md).
- Aktuelles `sb-forge exec` startet einen Kindprozess und übergibt Werte über Prozess-Environment. Dies ist kein fd-basiertes Verfahren und keine Zero-Trace-Garantie.
- Forge Git-Hooks/Scans spiegeln nicht automatisch die künftige `sb-code`-Integration wider.
- AONT-/Sharding-Funktionen nicht allein aufgrund ihres Algorithmusnamens als geprüft, vertraulich oder kollusionssicher deklarieren.

## 6. Source-, Website- und Deployment-Änderungen

- Maßgebliche Code-Entwicklung soll künftig im Dev Mesh mit `sb-code` liegen; aktuelle Git-/CI-Metadaten belegen keine erfolgte Migration.
- Es ist nicht beschlossen, dass jedes Release ausschließlich via Forge gepackt oder deployed wird. Weder `Forge.toml`-Pipeline noch Hostinger-Ziel als verbindlichen Produktionsablauf behandeln, sofern ein Maintainer das nicht konkret bestätigt.
- Keine Produktionsbereitstellung, Schlüsseloperation oder Remote-Änderung ohne ausdrücklichen Auftrag und Bestätigung von Ziel und Wirkung.
- Website- und Installationsanweisungen müssen auf tatsächliche Produkte, Artefakte und Sicherheitsgrenzen verweisen.

## 7. Dokumentationspflege

Änderungen an Zielentscheidungen in [`../brain/decisions.md`](../brain/decisions.md) und [`ARCHITECTURE.md`](./ARCHITECTURE.md) synchronisieren. Ist-Änderungen in Tool-READMEs, Release-Inventar und relevanten Website-Texten nachziehen. Historische Dokumente klar kennzeichnen statt ihre überholten Aussagen als aktuelle Vorgabe stehen zu lassen.
