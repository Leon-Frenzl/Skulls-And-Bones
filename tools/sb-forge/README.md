# `sb-forge` — Tasks, Pipelines und Secret-Workflows

`sb-forge` ist ein eigenständiges Suite-Tool zur Ausführung projektbezogener Rezepte und Pipelines sowie zur Verwaltung lokaler Secret-Workflows. Es soll selbst betriebene, nachvollziehbare Entwicklungsabläufe ermöglichen, ohne eine allgemeine CI/CD- oder Suite-Monolithenrolle zu übernehmen.

> **Sicherheitsblocker:** Das frühere `env.sealed`-Format war nicht an einen privaten Schlüssel des Zielservers gebunden. `sb-forge env seal`, `exec --sealed` und automatische Nutzung vorhandener Dateien sind inzwischen fail-closed deaktiviert. Alte Dateien werden nicht gelöscht und sind nicht vertraulich. Es gibt noch keinen Ersatz. Siehe [`../../brain/forge-secrets-design.md`](../../brain/forge-secrets-design.md).

## Sichtbare Funktionsbereiche

Die CLI in `src/cli.rs` stellt unter anderem folgende Bereiche bereit:

- `Forge.toml`-basierte Tasks, Rezepte und Pipelines.
- Lokale Secret-Vault- und Environment-Befehle.
- `exec` zum Start eines Kindprozesses mit Secrets als Environment-Variablen.
- Secret-Scan, Audit, Watch, Remote- und Mesh-Integrationen.
- Shard-/Assemble-/Reshare-Befehle; Existenz allein ist keine unabhängige Sicherheitsbewertung dieses Verfahrens.

Jede vorhandene Funktion muss vor Nutzung gegen das aktuelle CLI-Schema und ihren tatsächlichen Codepfad geprüft werden. Historische Beispiele, Checkboxen und Versionsnummern belegen weder Verhalten noch Reifegrad.

## Secret-Übergabe

`sb-forge exec` startet einen Kindprozess und übergibt Secret-Werte über dessen Environment. Das ist weder fd-basierte Secret-Übergabe noch eine Garantie, dass keine Klartextkopien oder Diagnose-/Crash-Daten entstehen. Nicht als „RAM-only“, „zero trace“ oder gleichwertig bewerben.

Forge hat keine Git-CLI-, Staging-, Historien- oder Hook-Abhängigkeit.
`sb-forge scan` prüft das Arbeitsverzeichnis oder einen explizit angegebenen Pfad;
automatische Pre-Commit-Scans sind nicht eingerichtet. Workspace-Ausschlüsse
werden in `.sbignore` gepflegt. Dieselben Regeln gelten für `sb-code`-Tracking,
Sync und History-Analysen.

## Architektur und Distribution

- `sb` ist Launcher und Manager; Forge behält seine Pipeline- und Secret-Fachlogik.
- `sb-core` enthält gemeinsame Typen und Verträge, nicht die komplette Forge-Implementierung.
- Frühere SSH-Prototypen (`sb-ssh`/NetGate) wurden aus dem Kern-Repository ausgelagert; Remote- und Node-Workflows laufen über `sb-node` und das Mesh.
- Signierte Release-Artefakte aus dem öffentlichen Sovereign Mesh und deren Verifikation im Installer sind Zielarchitektur, nicht der gegenwärtige Forge-Releaseweg.

## Weiterführende Dokumente

- [Forge-Konzept und Zuständigkeiten](../../brain/forge-complete-concept.md)
- [Forge-Secret-Bedrohungsmodell](../../brain/forge-secrets-design.md)
- [Zielarchitektur](../../docs/ARCHITECTURE.md)

Keine Standardskonformität, Produktionsreife oder Sicherheitsgarantie aus einem Algorithmusnamen, Audit-Log oder Konfigurationsbeispiel ableiten. Sie erfordert einen klaren Umfang, unabhängige Prüfung und reproduzierbare Tests.
