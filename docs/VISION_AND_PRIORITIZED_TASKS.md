---
title: "Skulls & Bones — Vision, Nachweise und priorisierte offene Tasks"
document_type: vision-evidence-and-backlog
status: Arbeitsgrundlage; Tasks noch nicht gemeinsam priorisiert
language: de
updated: 2026-10-07
---

# Vision, Nachweise und priorisierte offene Tasks

Dieses Dokument verbindet die bestätigte Produktvision mit konkreten Repository-Belegen und einem daraus abgeleiteten Arbeitsbestand. Es ist eine Planungs- und Nachweisübersicht, keine Sicherheitsprüfung, Release-Freigabe oder Behauptung, dass die beschriebenen Funktionen bereits produktionsreif sind.

## Unsere Vision

Skulls & Bones ist eine **modulare Suite eigenständiger Entwicklungs- und Infrastrukturwerkzeuge**. Menschen und Teams sollen Quellcode, Identitäten, Secrets und Betriebsabläufe selbst kontrollieren können, ohne an einen einzelnen kommerziellen Cloud-Anbieter gebunden zu sein. Verhalten, Vertrauensgrenzen und Abhängigkeiten sollen nachvollziehbar sein.

Die Suite soll:

- eigenständige, einzeln versionierbare Tools über einen gemeinsamen Launcher verwalten, statt ihre Fachlogik in einen Monolithen zu verlagern;
- gemeinsame Typen und versionierte Service-Verträge in `sb-core` bündeln und diese über einen lokal abgesicherten Suite-Daemon mehreren Clients zugänglich machen;
- fokussierte CLI-Tools, Daemons und Vertragscrates bereitstellen (Desktop-Frontends und Terminal/Shell wurden ausgegliedert);
- `sb-code` zur maßgeblichen Versionsverwaltung machen und pro Tool eigene Projekt-Working-Spaces im Sovereign Dev Mesh ermöglichen;
- signierte und versionierte Tool-Artefakte über selbst kontrollierte Infrastruktur verteilen, wobei die Signatur und nicht der Transport die Vertrauensbasis bildet;
- Sicherheits- und Reifegrad-Aussagen auf konkret implementiertes und getestetes Verhalten begrenzen.

Souveränität bedeutet dabei **Kontrolle und Wechselmöglichkeit**, nicht automatisch vollständigen Offline-Betrieb oder Abwesenheit jeder externen Abhängigkeit. Die vollständigen Leitplanken und bestätigten Produktentscheidungen stehen im [Manifest](./MANIFESTO.md), der [Zielarchitektur](./ARCHITECTURE.md) und dem [Entscheidungsregister](../brain/decisions.md).

## Belege im Repository

Die folgenden Belege stützen die Vision als **beschlossenes Ziel und begonnene technische Richtung**. Sie belegen für sich genommen weder Vollständigkeit noch Produktionsreife.

| Beleg | Was er konkret stützt | Grenze des Belegs |
|---|---|---|
| [Manifest](./MANIFESTO.md) und [Entscheidungsregister](../brain/decisions.md) | Modulare Suite, `sb` als Launcher, gemeinsame Verträge in `sb-core`, `sb-code` als angestrebte Versionsverwaltung sowie die Ausgliederung von Desktop, Web-UI, Shell und Terminal sind als Richtung festgehalten. | Beschlossene Richtung ist keine Implementierung. |
| [Root-Cargo-Workspace](../Cargo.toml), [sb-core](../tools/sb-core/) und [Produktinventar](../product-inventory.json) | Alle 14 konsolidierten Kern-Tools liegen im gemeinsamen Root-Cargo-Workspace und maschinenlesbaren Inventar. | Packaging- und Release-Abdeckung wird über `sb release pack` und `product-inventory.json` nachgewiesen. |
| [Zielarchitektur: Services und IPC](./ARCHITECTURE.md#3-core-services-und-ipc) | Ein versionierter `sb`-Daemon-Vertrag wird von CLI und externen Clients für den Suite-Katalog verwendet; Vault-RPC und Laufzeitstatus zeigen weitere Services. | Der Bearer-Token ist keine Prozessisolation: Prozesse desselben Benutzerkontos bleiben eine Vertrauensdomäne. |
| [Zielarchitektur: Code und Working Spaces](./ARCHITECTURE.md#5-sovereign-code-und-working-space-modell) | Die vorgesehene Quelle der Wahrheit, `sb-code` und separate logische Working-Spaces sind explizit beschrieben. | Working-Space-Topologie, Replikation, Offline-Verhalten und Konfliktregeln sind noch offen. |
| [Zielarchitektur: Signing und Mesh-Grenzen](./ARCHITECTURE.md#6-mesh-isolation-und-release-signierung) | Die Vertrauensbasis für signierte Artefakte, die gewünschte Mesh-Isolation und die akzeptierte Bedrohungsgrenze sind benannt. | Ein erfolgreicher Online-Installationslauf und die vollständigen Schlüssel-Lifecycle-Verfahren sind nicht nachgewiesen. |
| Frühere Desktop-Komponenten (Historisch) | Historischer Prototyp einer Desktop-Oberfläche; im Zuge der 14-Core-Konsolidierung ausgegliedert. | Diente nur als UI-Prototyp. |

## Priorisierte offene Tasks

Die Tasks sind aus den dokumentierten Abweichungen und offenen Entscheidungen abgeleitet. Sie bleiben offen, bis ihre Abnahmekriterien erfüllt und mit Tests oder reproduzierbarer Laufzeitevidenz belegt sind.

### P0 — Vor produktiven Sicherheits- und Release-Aussagen

**P0-1 — Erledigt:** Das Inventar führt exakt die 14 konsolidierten Kern-Tools; Tests gleichen Paketnamen, Versionen, installierbare Cargo-Binary-Ziele und Root-Workspace-Mitgliedschaft mit den Manifesten ab. `sb release pack` bricht bei fehlenden erforderlichen Binaries ab.

**P0-2 — Erledigt:** Der Loopback-HTTP-Vertrag verlangt jetzt explizite JSON-RPC-/API-Versionen, eindeutige Authentisierung und JSON-Content-Type; Browser-Origin-Requests, unbekannte RPC-Pfade und ungültige Medientypen werden abgelehnt. Body- und Headerlimits passen zusammen, und der Client berücksichtigt HTTP-Overhead bei Antwortlimits. `sb catalog` nutzt den lokalen Katalog nur bei nicht laufendem Daemon; echte RPC- und Protokollfehler werden sichtbar weitergegeben. Daemon, CLI und Service-Endpunkte verwenden bereits denselben versionierten Suite-Katalog-Service. Die Vertrauensgrenze gegenüber Prozessen desselben Benutzerkontos ist dokumentiert; sie sind ausdrücklich nicht voneinander isoliert. Belegt durch 65 CLI- und 25 Core-Tests sowie erfolgreiche Core- und CLI-Checks.

| ID | Task | Warum / Abhängigkeiten | Abnahmekriterium |
|---|---|---|---|
| P0-1 | **Produktinventar, Produktnamen und Release-Prüfpfade konsistent machen.** Tatsächliche Crates, Binaries, Plattformziele, Reifegrade und Packaging-Listen gegeneinander prüfen; Release-Checks müssen fehlende Artefakte als Fehler melden. | Grundlage für alle folgenden Integrations- und Release-Arbeiten; ohne konsistente Produktidentität sind Build- und Release-Aussagen nicht belastbar. | Ein kanonisches Inventar stimmt mit CLI-Katalog, Workspace-Builds und Packaging überein; jeder angebotene Release hat einen reproduzierbaren Build- und Testpfad; nicht abgedeckte Targets schlagen sichtbar fehl. |
| P0-2 | **Lokalen Daemon-Vertrag samt IPC-Sicherheitsmodell festlegen und Ende zu Ende integrieren.** Authentisierung, Autorisierung, Transport, Größenlimits, Versionaushandlung und Fehlerverhalten spezifizieren; danach mindestens einen echten Service über Daemon und CLI verwenden lassen. | Die Zielarchitektur benennt den aktuellen Loopback-Endpunkt ausdrücklich nicht als produktionsreife Sicherheitsgrenze. Abhängig von P0-1; Voraussetzung für die breite Service-Integration. | Ein dokumentierter, versionierter Vertrag wird von Daemon und CLI gemeinsam verwendet; erlaubte und abgelehnte Requests, ungültige Versionen, Größenlimits und Fehlerfälle sind automatisiert getestet. Grenzen gegenüber Prozessen desselben Benutzerkontos sind explizit dokumentiert. |
| P0-3 | **Erledigt — Mesh-Identitäten und lokales State pro Vertrauensdomäne isolieren.** Eigene Identität, Schlüssel, Peer-/RBAC-Daten und Konfiguration je benanntem Mesh erzwingen; keine implizite Wiederverwendung, Bridge standardmäßig aus; sichere Neuinitialisierung und Umgang mit Legacy-Dateien dokumentieren. | Die logische Mesh-State-Isolation und explizite PSK-Migration sind umgesetzt. User-Space-Routing und per-Mesh-Dateipfade sind keine Prozess- oder OS-Isolation; Prozesse desselben OS-Benutzers bleiben eine Vertrauensdomäne. Daraus folgt ausdrücklich keine Behauptung kryptografischer Trennung gegen lokale Prozesse. | Zwei gleichzeitig laufende Daemons verwenden nachweislich getrennte Identitäten und State-Dateien; Ticketvergabe ist an die Mesh-Identität gebunden; Neustart und PSK-Migration sind getestet; Legacy-Dateien werden nicht automatisch importiert oder gelöscht. |
| P0-4 | **Signierte Release-Verteilung und Bootstrap nachweisbar schließen.** Vorhandene Manifest-/Signaturprüfung mit tatsächlichem Hosting und Live-Installationslauf verbinden; Manipulation, falscher Schlüssel, Downgrade und fehlendes Artefakt fail-closed behandeln; Backup, Recovery, Rotation und Kompromittierungsverfahren für den Release-Schlüssel festlegen. | Die Signaturprüfung in `sb install` ist bereits dokumentiert, aber Online-Bereitstellung und Live-Installationslauf sind nicht nachgewiesen. Abhängig von P0-1; Schlüssel-/Dienstgrenzen aus P0-3 berücksichtigen. | Ein sauberer Client installiert ein für sein Plattformziel veröffentlichtes Artefakt reproduzierbar und prüft die exakten Bytes gegen einen gepinnten Schlüssel. Manipulierte, unbekannte, fehlende und unzulässig zurückgestufte Releases werden abgewiesen; Schlüsselwiederherstellung und Rotation sind getestet oder als kontrollierter Ablauf dokumentiert. |

**P0-4 — Teilfortschritt (noch offen):** `sb install`/`sb update` blockieren nun ein niedrigeres SemVer als im lokalen Ledger dokumentiert; eine Rückstufung benötigt explizit `--allow-downgrade`, nicht nur `--force`. Ein ungültiges Ledger und fehlgeschlagene Ledger-/Manifest-/Signatur-Schreibvorgänge führen zu sichtbaren Fehlern. `sb release sign` weist Schlüssel zurück, deren Public Key nicht dem eingebetteten Installer-Key entspricht. `sb-proxy` kann statische Verzeichnisse mit HTTP/1.1-Keep-Alive und HTTP/2 ausliefern; echtes ACME über TLS-ALPN-01, konfigurierbare Sicherheits-Header, MIME-Erkennung und strukturierte Logs sind implementiert und lokal getestet. Das ermöglicht einen möglichen selbst betriebenen Artefakt-Host, ersetzt aber noch keine tatsächliche Bereitstellung. **Nicht erledigt:** DNS-/Port-Erreichbarkeit, erfolgreicher Zertifikatsbezug/-erneuerung, Hosting und Live-Installation sind noch nicht praktisch nachgewiesen; es gibt keine Release-Automatisierung. Das Ledger ist lokal manipulierbar/löschbar und kein Rollback-Schutz gegen einen lokalen Angreifer. Die Rotation eines einzelnen gepinnten Keys setzt eine koordinierte Client-Veröffentlichung voraus; ein getesteter Backup-/Recovery-/Kompromittierungsablauf fehlt. P0-4 bleibt bis zu einem tatsächlichen veröffentlichten Client-Lauf und einem betrieblich verantworteten Schlüssel-Lifecycle offen.

**P0-3 — Erledigt (Implementierung und lokale Abnahme):** Mesh-spezifische Identitäts-, Konfigurations-, Peer-, RBAC-, Ticket-, Routen- und Runtime-Pfade sind umgesetzt; Join überträgt Mesh-Metadaten in den lokalen Katalog, und Ticketvergabe ist an den Schlüssel des angefragten Meshes gebunden. `network migrate-psks` verschiebt Katalog-PSKs erst nach erfolgreicher privater Ablage und Verifikation. Zwei getrennte Daemon-Prozesse und ein Daemon-Neustart werden im Integrationstest geprüft. `cargo test -p sb-mesh` besteht mit 157 Tests; `cargo check -p sb-mesh -p sb-core -p sb-cli` ist erfolgreich. Legacy-Dateien bleiben unangetastet. Die getestete Grenze ist logische State-Isolation: Prozesse desselben OS-Benutzers bleiben ausdrücklich eine gemeinsame Vertrauensdomäne; für Isolation gegen lokale Prozesse wären getrennte OS-Servicekonten erforderlich.

### P1 — Fundament für souveräne Code- und Mesh-Workflows

| ID | Task | Warum / Abhängigkeiten | Abnahmekriterium |
|---|---|---|---|
| P1-1 | **Lokales `sb-code`-Datenmodell und Recovery-Baseline stabilisieren.** Commit-Identität, Integrität, Export/Backup und Wiederherstellung festlegen, bevor `sb-code` als maßgebliche Versionsverwaltung verwendet wird. | Der geplante Wechsel von Git zur eigenen Versionsgeschichte darf nicht auf einem ungeprüften lokalen Datenmodell beruhen. Die alte Git-Historie wird nicht importiert. | Ein neues Repository kann lokal angelegt, geändert, geprüft, exportiert und aus Backup wiederhergestellt werden; Identität und Integritätsfehler sind testbar und dokumentiert. |
| P1-2 | **Pro-Tool-Working-Spaces und Replikationsregeln prototypisieren.** Als Startpunkt getrennte logische Namespaces in einem gemeinsamen Dev Mesh prüfen; ACLs, Schreibrechte, Offline-Verhalten, parallele Writes und Konfliktauflösung explizit definieren. | Hängt für Mesh-Nutzung von P0-3 und für verlässliche Code-Historie von P1-1 ab. Topologie und Replikationsmodell sind noch nicht abschließend beschlossen. | Ein Prototyp isoliert mindestens zwei Tool-Workspaces, repliziert einen dokumentierten Commit auf einen zweiten Peer und weist Verhalten bei konkurrierenden Änderungen, Offline-Zeit und Wiederherstellung nach. |
| P1-3 | **Katalog-DC-Membership und Freshness bis zum Laufzeit-Gate vervollständigen.** Sicheren Bootstrap/Wiederherstellungspfad, CLI, persistentes manipulationsnachweisbares Journal, Quorumverlust und die Verbindung zum Replikations-/Autorisierungs-Gate umsetzen. | Die Zielarchitektur beschreibt bereits Prüf- und Membership-Verträge, aber noch keinen vollständigen nutzbaren Betriebsweg; geschützt auf Katalogdaten zuzugreifen setzt diese Verbindung voraus. | DC-Mitgliedschaft kann nur über autorisierte, signierte und quorum-bestätigte Transitionen geändert werden; Neustart, Wiederholung, Konflikt, Quorumverlust und beschädigter lokaler State führen zu deterministischem, fail-closed Verhalten und nachvollziehbaren Tests. |
| P1-4 | **Historisch — Desktop-Ausgliederung.** Desktop-Frontends wurden im Zuge der 14-Core-Konsolidierung vollständig ausgegliedert; die Core-Suite konzentriert sich auf Headless-Services und CLI-Tools. | Erledigt durch Ausgliederung. | Core-Workspace umfasst 14 autarke Kern-Tools. |

### P2 — Produktgrenzen und weitere Integrationen

| ID | Task | Warum / Abhängigkeiten | Abnahmekriterium |
|---|---|---|---|
| P2-1 | **Historisch — Shell-, Terminal- und SSH-Ausgliederung.** `sb-shell`, `skully` und `sb-ssh` wurden vollständig aus der Core-Suite ausgegliedert. | Erledigt durch Ausgliederung. | Native Betriebssystem-Terminals und -Shells werden verwendet. |

## Empfohlene Reihenfolge

1. P0-1: Inventar und Nachweiswege konsolidieren.
2. P0-2 und P0-3: IPC- und Mesh-Vertrauensgrenzen implementieren und testen.
3. P0-4: Erst danach den souveränen Release-/Bootstrap-Weg praktisch nachweisen.
4. P1-1 vor P1-2: zuerst lokale Code- und Recovery-Baseline, dann Working-Spaces und Replikation.
5. P1-3 vor produktivem Einsatz geschützter Katalogdaten; P1-4 nach Festlegung des Service-Vertrags.
6. P2-1 parallelisieren, ohne Produktnamen oder Prototypen als Release-Nachweis auszugeben.

## Arbeitsregeln für den Backlog

- Ein Task wird erst geschlossen, wenn das jeweilige Abnahmekriterium erfüllt ist und der Beleg (Test, Build, Laufzeitnachweis oder überprüfte Entscheidung) verlinkt wurde.
- „Vorhanden“, „implementiert“, „integriert“ und „releasevalidiert“ sind verschiedene Reifegrade.
- Nicht verifizierte historische Statusangaben aus älteren Spezifikationen gelten nicht als Abnahme.
- Die Tasks sind aus der [Zielarchitektur](./ARCHITECTURE.md) und dem [priorisierten Architektur-Arbeitsplan](../brain/implementation_plan.md) abgeleitet. Bei Abweichungen ist die Zielarchitektur samt bestätigtem [Entscheidungsregister](../brain/decisions.md) maßgeblich.
