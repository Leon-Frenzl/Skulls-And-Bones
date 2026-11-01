# `sb-forge` — Implementierungsstand und offene Arbeit

> **Status (2026-10-03):** Dieser Überblick ersetzt nicht die Quellcodeprüfung. Frühere Checkboxen und Testergebnisse waren nicht belastbar genug, um heutigen Status zu belegen.

## Im Repository vorhanden

Quellcode enthält CLI-Bereiche für:

- `Forge.toml`-basierte Rezepte und Pipelines.
- Lokale Secret-Vault-Befehle und Secret-Audit.
- `exec` zum Start von Kindprozessen mit Secret-Variablen im Prozess-Environment.
- Secret-Scan, Git-Hooks, Watch, Remote- und Mesh-Funktionen.
- Shard-/Assemble-/Reshare-Implementierungen.
- Environment-Aktivierung, -Liste und -Widerruf.

Die Funktionsflächen sind nicht automatisch releasevalidiert. Prüfe das betroffene Verhalten und seine Tests vor jeder Reifegrad- oder Sicherheitsbehauptung.

## Sicherheitsblocker: Legacy `env.sealed`

Das frühere `SB_FORGE_SEALED_V1`-Format leitete seinen AEAD-Schlüssel aus Metadaten und einem Salt ab, die mit dem Envelope gespeichert wurden. Es benutzte keinen privaten Schlüssel des Zielservers.

**Umgesetzte Sperre:**

- `sb-forge env seal` schlägt geschlossen fehl und erstellt oder überträgt kein Artefakt.
- `sb-forge exec --sealed <path>` wird abgelehnt.
- Eine automatisch gefundene `env.sealed`-Datei wird ebenfalls abgelehnt und nicht als lokaler Vault-Fallback behandelt.
- Der Legacy-Entschlüsselungseinstieg gibt immer einen Fehler zurück.
- Bereits vorhandene `.sealed`-Dateien werden weder automatisch gelöscht noch als vertraulich behandelt. Nicht weiter verwenden; gegebenenfalls gesondert und sicher bereinigen.
- Integrationstests sichern die Sperre und verhindern die Wiederverwendung des Formats.

Es gibt noch **keinen Ersatz** für servergebundene Secret-Verteilung. Produktions-Secrets nicht mit diesem Format deployen. Threat Model und Designkriterien: [`../../brain/forge-secrets-design.md`](../../brain/forge-secrets-design.md).

## Offene Arbeiten

1. Threat Model, Empfänger-Key-Provisionierung, Herausgeber-Authentizität, Replay-/Rollback-Schutz und Recovery festlegen.
2. Ein standardisiertes und unabhängig geprüftes Envelope-Verfahren entwerfen; keine eigene Kryptografie-Konstruktion.
3. Versioniertes Format, Testvektoren und Fehlerszenarien implementieren und prüfen.
4. Release-Signaturprüfung von Secrets-Verteilung getrennt behandeln.
5. Forge- und Release-Workspaces in einem nachweisbaren Qualitätsinventar (`product-inventory.json`) führen; Frontend-/Desktop-Apps wurden als externe Satelliten ausgelagert.
6. Bestehende Git-Hooks später über eine klare VCS-Schnittstelle an das geplante `sb-code`-Modell anbinden.

## Validierung

Die Integrationstests unter `tests/legacy_seal_disabled.rs` decken direkte Erstellung, explizite Entschlüsselung über `exec --sealed` und automatische Erkennung ab. Vor einer Freigabe `cargo check -p sb-forge` und die `sb-forge`-Testsuite ausführen (bzw. die Gesamtsuite via `npm run verify:suite`).
