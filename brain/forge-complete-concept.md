---
title: "S&B Forge — Produkt- und Workflow-Konzept"
document_type: product-concept
status: vision-plus-current-boundaries
language: de
updated: 2026-10-03
---

# S&B Forge — Produkt- und Workflow-Konzept

## Zweck

`sb-forge` ist ein eigenständiges Tool für projektbezogene Tasks, Pipelines und Secret-Workflows. Es soll Routineabläufe lokal oder auf selbst betriebenen Infrastrukturknoten reproduzierbar machen, ohne Forge zu einem zentralen S&B-Monolithen zu machen.

**Markenversprechen:** Der Betreiber kontrolliert Ausführung, Quellcode und Infrastruktur. Forge soll lesbare Konfiguration und nachvollziehbare Befehle bieten. Das ist ein Ziel, keine Behauptung, dass jeder vorhandene Workflow cloudfrei, deterministisch oder produktionsgeeignet ist.

## Zuständigkeiten

- `sb` installiert, versioniert und startet Forge als Suite-Tool.
- `sb-forge` besitzt Parser/Ausführung von `Forge.toml`, Rezepten, Pipelines, Audits und Forge-spezifischen Secret-Aktionen.
- Externe Frontends/Clients (wie die ausgelagerten Satelliten `sb-desktop` und `sb-studio`) sowie CLI-Aufrufer sollen keine zweite Pipeline-Engine oder VCS implementieren, sondern den stabilen CLI/RPC-Vertrag nutzen.
- Mesh-Transport, Code-Versionierung und Signatur-Vertrauen haben jeweils eigene Zuständigkeiten (`sb-mesh`, `sb-code`, Release-Verifikationslogik).

## Aktuell sichtbare CLI-Flächen

Das CLI in `tools/sb-forge/src/cli.rs` enthält unter anderem:

- `secret`: lokale Secret-Verwaltung und -Audit; zusätzlich Shard-/Assemble-/Reshare-Unterbefehle.
- `env`: Environment aktivieren, listen, versiegeln und widerrufen.
- `run`: Rezept oder Pipeline aus `Forge.toml` ausführen, lokal oder mit Remote-Optionen.
- `exec`: Kindprozess mit Environment-Variablen starten.
- `scan`, `audit`, `init`, `watch`, `hooks`, `systemd-unit`, `check`, `fix`, `mesh`, `remote`.

Die Existenz eines CLI-Unterbefehls ist kein Sicherheitsnachweis, kein Nachweis vollständiger Fehlerbehandlung und keine Release-Freigabe.

## Konfigurationsmodell

`Forge.toml` soll deklarativ festhalten:

- Projektname und Metadaten.
- Secret-Definitionen (Namen/Beschreibungen/Umgebungen, keine Secret-Werte).
- Nicht geheime Umgebungskonfiguration.
- Rezepte als atomare Tasks.
- Pipelines als Stages, Abhängigkeiten und kontrollierte Parallelität.

Beispielkonfigurationen aus älteren Konzepten sind illustrative Beispiele. Vor Verwendung gegen den aktuellen Parser und das aktuelle `ForgeConfig`-Schema prüfen.

## Gewünschter Workflow

```text
Forge.toml
   ├── run <recipe>       → einen begrenzten Task ausführen
   ├── run --pipeline ... → geprüfte Stages orchestrieren
   ├── exec -- <command> → Kindprozess mit ausgewählten Variablen starten
   ├── scan / audit       → Befunde und Aktionen ausgeben
   └── mesh / remote      → optionale Integration mit anderen Tools
```

Rezepte sollen explizite Abhängigkeiten, nachvollziehbare Exit-Codes und klare Zielumgebungen besitzen. Eine Pipeline darf eine fehlgeschlagene Stage nicht als Erfolg darstellen. Produktionsaktionen brauchen sichtbare Freigaben und eine getestete Wiederherstellungsstrategie.

## Implementierungsgrenzen und Korrekturen alter Konzepte

- Der aktuelle `exec.rs` startet einen **Kindprozess** mit `tokio::process::Command` und übergibt Werte über `.envs(...)`. Es handelt sich nicht um `execve()`-Prozessersetzung und nicht um fd-/memfd-basierte Secret-Übergabe.
- Secret-Werte in Environment-Variablen können für Zielprozess und entsprechend privilegierte lokale Prozesse sichtbar sein. Diese Übergabe ist nicht „zero trace“.
- Das frühere, unsichere `env.sealed`-Format ist in der CLI inzwischen fail-closed deaktiviert; es gibt noch keinen Ersatz. Alte Dateien sind nicht vertraulich und werden nicht automatisch gelöscht. Details: [`forge-secrets-design.md`](forge-secrets-design.md).
- Forge benutzt in vorhandenem Code und Dokumentation Git-bezogene Hooks/Scans. Das widerspricht dem beschlossenen Ziel, künftig `sb-code` als Versionsverwaltung einzusetzen; die neue Integration ist offen und noch nicht umgesetzt.
- `sb-ssh`-basierte Deployments sind an mehreren Stellen historisch verdrahtet. `sb-ssh` ist vorerst Desktop-Prototyp, kein separat zu installierendes Suite-Produkt.

## Nicht-Ziele

- Forge ist kein Paket-Manager und nicht die Suite-Produktverwaltung; dafür ist `sb` zuständig.
- Forge ist kein eigener Mesh-Transport, keine Versionsverwaltung und kein allgemeiner Secrets-Daemon, solange dies nicht als eigenständige Architekturentscheidung beschlossen wurde.
- „BSI-konform“, „revisionssicher“ oder „Zero Trust“ nicht allein aus einem Audit-Log, systemd-Template oder Kryptografie-Primitiv ableiten.

## Nächste sinnvolle Schritte

1. Forge-CLI und Konfigurationsschema als überprüfbares Tool-Inventar dokumentieren.
2. `exec`-Verhalten und Secret-Exposition explizit als Teil des Bedrohungsmodells testen.
3. Ein neues, geprüftes Seal-Verfahren entwerfen; das unsichere Legacy-Format ist bereits gesperrt. Siehe Secret-Design.
4. Forge-Versionierung und Artefaktverteilung an `sb`-Release-Metadaten anbinden.
5. Git-Hooks durch abstrahierte VCS-Schnittstelle ersetzen, sobald `sb-code` stabile lokale Commit-/Workspace-Verträge besitzt.
