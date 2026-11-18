# Mesh-, Release- und Workbench-Vorhaben: Strukturelle Abschätzung

> **Status:** Historischer Implementierungsvorschlag / Entwurfsdokument  
> **Stand:** 2026-10-09 (Aktualisiert für Milestone M3)  
> **Hinweis zur Konsolidierung (Milestone M3):** Die in dieser Abschätzung behandelte grafische Workbench (`sb-workbench`) wurde im Rahmen der 14-Core-Konsolidierung aus dem Kern-Repository ausgelagert. Die Kernlogik für AST-gestützte Versionsverwaltung verbleibt in `sb-code`.
> **Zweck:** Die Backlog-Punkte P1-1, P1-2, P1-5, P2-2 und P3-4 anhand des vorhandenen Codes in abgrenzbare, prüfbare Lieferungen übersetzen.

Diese Abschätzung trennt den Ist-Stand von Ziel und Vorschlag. Aufwand ist eine grobe Entwickler:innen-Tageschätzung für eine Person, ohne Wartezeiten auf Infrastruktur, unabhängige Sicherheitsprüfung oder plattformübergreifende Testgeräte. Sie ist kein Terminversprechen.

## Kurzfazit

Die fünf Punkte sind keine unabhängigen Kleinstaufgaben. Die sinnvolle Reihenfolge ist:

1. **P1-1:** Mesh-IPC auf den bestehenden Core-RPC-Vertrag und die bestehenden DTOs migrieren.
2. **P1-2:** Mesh-Identitäten und OS-Servicekonten als getrennte, testbare Betriebsgrenzen umsetzen.
3. **P1-5:** Auf diesen Grenzen pro Tool einen logisch benannten `sb-code`-Workspace mit expliziten ACLs und Replikationsregeln aufbauen.
4. **P2-2:** Release-Builds reproduzierbar paketieren, signieren und als Mesh-Objekte publizieren; der Installer vertraut weiter dem gepinnten Schlüssel, nicht dem Mesh.
5. **P3-4:** Die Workbench schrittweise von UI-Entwurfsdaten zu überprüfbaren AST-Scope-Änderungen erweitern.

**Grobe Gesamtgröße: 30–55 Entwickler:innentage**, zuzüglich etwa 20–30 % Reserve für Integration, Security-Review und plattformspezifische Tests. Die größten Risiken liegen in Betrieb und Isolation (P1-2), im noch offenen Autorisierungs-/Konfliktmodell von `sb-code` (P1-5) sowie in der sicheren, nachvollziehbaren Bearbeitung von Quellcode-Scopes (P3-4).

## Bestandsaufnahme und Vorschlag je Vorhaben

### P1-1 — Einheitlicher Service-Vertrag (`sb-core` / Daemon / Mesh)

**Ist-Stand**

- `sb-core` definiert bereits `RpcRequest`, `RpcResponse`, API-Versionen, Fehlercodes, Größenlimits und Mesh-DTOs.
- **Erster Implementierungsschritt (2026-10-09):** Die bisherigen `sb-mesh::ipc`-Request-/Response- und Payload-Typen wurden nach `sb-core::mesh_ipc` verschoben; `sb-mesh` re-exportiert sie zur Quellkompatibilität. Contract-Tests halten das vorhandene JSON-Format fest.
- `sb daemon` verwendet JSON-RPC 2.0 über authentisiertes Loopback-HTTP und liest Mesh-Telemetrie aus einem kurzlebigen Runtime-Status-Snapshot.
- `sb-mesh::ipc` hat daneben eigene `IpcRequest`-/`IpcResponse`-Enums und einen separaten TCP-Listener auf Port 58890. Der dort sichtbare Pfad hat weder den Core-RPC-Umschlag noch die Daemon-Token-Authentisierung, Timeouts oder die gleichen Framing-/Größenregeln.
- `sb-core::service` enthält noch keine Mesh-Service-Schnittstelle.

**Empfohlener Schnitt**

Der Suite-Daemon bleibt der UI-/CLI-Einstiegspunkt. `sb-mesh` stellt eine typisierte Mesh-Service-Implementierung bereit; `sb-core` besitzt nur die stabilen DTOs, Methoden-IDs, Fehler und API-Verträge. Die vorhandene Mesh-IPC wird entweder durch einen Daemon-Adapter ersetzt oder vorübergehend als strikt lokale, versionierte Kompatibilitätsschicht gehalten. Keine Mesh-Fachlogik nach `sb-core` verschieben.

Migration in kleinen Schritten:

1. Aktuelle Mesh-Methoden und Payloads als Core-Vertrag modellieren; Status und Peer-Liste zuerst.
2. Serde-Kompatibilität mit Fixture-/Round-Trip-Tests festlegen.
3. Daemon-Adapter auf diese DTOs umstellen und Fehler explizit auf `ServiceError` abbilden.
4. Desktop/CLI-Aufrufer auf den Daemon-Vertrag lenken.
5. Alten Port erst entfernen, wenn keine Verbraucher mehr darauf angewiesen sind; ansonsten befristete, dokumentierte Übergangsversion.

**Abnahmekriterien**

- Ein Typ und eine API-Version je Mesh-Request/-Response; kein parallel gepflegtes JSON-Schema.
- Versionsabweichung, unbekannte Methode, ungültige Parameter, fehlende Laufzeitdaten und übergroße Payloads liefern definierte Fehler, niemals Erfolg-förmige Defaults.
- Vertragstests für Core, Daemon und Mesh nutzen dieselben JSON-Fixtures.
- Authentisierung und Transportgrenzen sind nicht schwächer als der bestehende Daemon-Vertrag.

**Aufwand:** 4–7 Tage. **Risiko:** mittel-hoch, weil die beiden heutigen Transportwege unterschiedliche Vertrauens- und Fehlergrenzen haben.

**Status nach dem ersten Umsetzungsschritt:** Die IPC-Datentypen sind jetzt single-source in `sb-core`; der Mesh-Listener verwendet sie unverändert. Noch offen bleiben JSON-RPC/API-Versionierung für diesen Pfad, dieselben Fixtures in Daemon und Mesh sowie die authentisierte und begrenzte Transportmigration. Das ist ein Contract-Konsolidierungsschritt, kein abgeschlossener Sicherheits- oder Service-Vertrag.

### P1-2 — Mesh-Prozess- und Identitätsisolation

**Ist-Stand**

- `MeshStatePaths` trennt State nach `~/.sb-mesh/instances/<mesh>/`, schützt Unix-Verzeichnisse mit Modus `0700` und prüft Symlinks.
- `NodeIdentity` lädt die zum registrierten Mesh gehörende Identität und weist stille Neuerzeugung bzw. einen Katalogschlüssel-Mismatch zurück.
- `sb-mesh` besitzt einen Systemd-Unit-Generator mit eigenem Unix-Konto `sb-mesh`; dieser ist nicht per Vertrauensdomäne getrennt. Bootstrap-Deployment-Dateien verwenden weiterhin gemeinsame Pfade.
- Die Windows-Installationsvorlage registriert eine geplante Aufgabe mit `/RL HIGHEST`; das ist kein eigener Service-Principal pro Mesh und erfüllt die geforderte OS-Identitätstrennung nicht.

**Empfohlener Schnitt**

- Identitätsdomäne und Dienstkonto an die **Vertrauensklasse** binden, z. B. `sb-public`, `sb-dev`, `sb-secret`, nicht einfach ein Konto je beliebigem Mesh-Namen erzeugen.
- Instanzpfade unter einem für den Dienst kontrollierten Datenverzeichnis halten; jede Instanz erhält eindeutige OS-ACLs. Shared-User-Dateirechte allein gelten nicht als Prozessisolation.
- Erst Linux systemd mit getrennten unprivilegierten Konten und verifizierten Zustands-/Socket-Berechtigungen abnehmen. Windows bis zu einem echten Windows-Service samt eigenem Logon-Token als nicht isoliert kennzeichnen; geplante Aufgabe nicht als gleichwertigen Fallback darstellen.
- Cross-Mesh-Bridge bleibt explizit deaktiviert, bis Quell-/Zielidentität, Capability und Audit-Entscheidung erfolgreich geprüft sind.

**Abnahmekriterien**

- Positiver Isolationstest: Dienst A kann Identität, Secret-State und beschreibbare Dateien von Dienst B nicht lesen oder ändern.
- Negativtests für falsche Eigentümer/ACL, fehlende Identität, Symlinks, Profilwechsel und Doppelstart derselben Instanz.
- Installieren, Starten, Status, Update, Deinstallation und Recovery sind pro unterstützter Plattform getestet.
- Dokumentiert ist, dass Root/Kernel bzw. Windows-Administrator die Grenze weiterhin umgehen können; kein kryptografisches Isolationsversprechen.

**Aufwand:** 7–12 Tage für Linux-MVP und Windows-Scope/Abgrenzung; 12–20 Tage, wenn echter Windows-Service und dessen Installations-/Upgradepfad Teil des MVPs sind. **Risiko:** hoch.

### P1-5 — Pro-Tool Dev-Mesh-Working-Spaces

**Ist-Stand**

- `sb-code::VcsEngine` verwaltet eine lokale Historie und kennt Projektname, Branches, Scope-Snapshots und Replikationsoperationen.
- `sb-code::mesh_sync` bietet Push/Pull über einen Mesh-Cross-Stream; der Sync-Daemon selbst bindet nur an Loopback und erwartet Mesh-Ingress über `sb-node`.
- Der Sync-Vertrag benennt Projekte, enthält aber noch keine verbindliche Workspace-ID mit ACL- und Replikationsrichtlinie. Die Architektur lässt Topologie, ACLs und Konfliktregeln ausdrücklich offen.

**Empfohlener Start**

Ein gemeinsames Dev-Mesh als Transportdomäne verwenden und pro Tool getrennte logische Workspace-IDs anlegen, z. B. `dev/tools/sb-core`. Jede Workspace-Registrierung enthält eine unveränderliche ID, Repository-/Projektbindung, autorisierte Schreibrollen, erlaubte Replica-Peers und eine Policy-Version. Namespace-Namen allein sind keine Autorisierung.

Für den ersten Prototyp:

- Genau ein autoritativer Writer pro Workspace, weitere Peers zunächst lesende Replikate.
- Push/Pull muss die Workspace-ID, den erwarteten Branch-Head und Capability-Kontext binden.
- ACL-Änderungen und Workspace-Membership sind signierte, nachvollziehbare Ereignisse; fehlende/ungültige Policy führt zu Deny.
- Divergierende Heads werden gemeldet und nicht mit Zeitstempel oder stillem Last-Writer-Wins überschrieben.
- Zwei isolierte Workspaces `sb-core` und `sb-mesh` aufsetzen und deren Commits auf einen Test-Peer replizieren.

**Abnahmekriterien**

- Ein Capability-Token für Workspace A kann weder lesen noch schreiben in Workspace B.
- Zwei-Projekt-Ende-zu-Ende-Test mit Push, Pull, Neustart, Peer-Ausfall und Wiederanlauf.
- Offline- und Divergenzverhalten ist deterministisch beschrieben; Konflikte bleiben explizit und manuell auflösbar.
- Eine eigene `sb-code`-Historie pro Tool; keine gemeinsame Historie, die nur durch Branch-Namen partitioniert ist.

**Aufwand:** 8–15 Tage für Registry/Policy/Single-Writer-Prototyp und Integrationstests. Multi-Writer, Konfliktauflösung und Offline-first-Replikation sind eine separate Folgestufe. **Risiko:** hoch.

### P2-2 — Signierte Paketverteilung im Mesh

**Ist-Stand**

- `sb release pack`, `pack-all`, `sign` und Installer-Verifikation über gepinnten Ed25519-Schlüssel sind vorhanden.
- `pack-all` scheitert bei fehlenden Binaries statt ein unvollständiges Suite-Paket als vollständig auszugeben.
- Automatische Multi-Plattform-Build-/Release-Abläufe wurden entfernt; ein Mesh-Upload-/Downloadpfad für Release-Pakete ist noch nicht Teil der dokumentierten Release-Kette.
- Das aktuelle Release-Manifest signiert Metadaten mit Hashes. Es muss weiter geprüft werden, dass die Verifikation die exakten heruntergeladenen Archivbytes und nicht nur den Transport-/Mesh-Pfad vertraut.

**Empfohlener Schnitt**

Release-Pipeline und Mesh-Verteilung bleiben getrennte Schritte:

1. Pro Plattform bauen und Tests/Inventar-Allowlist prüfen.
2. Archive und Manifest deterministisch erstellen; Release-Key in einem isolierten Signierschritt verwenden.
3. Signatur lokal mit unabhängigem Verifikationspfad prüfen.
4. Signierte Release-Objekte in einen dedizierten Public-Release-Namespace publizieren, der für Publisher schreibbar und für den Public-Webdienst nur lesbar ist.
5. Installer lädt über Mesh/HTTP als Transport und validiert Schlüsselbindung, Signatur, Manifest-Version, Artefaktpfad, Hash, Zielplattform und Größenlimits vor Installation.

**Abnahmekriterien**

- Reproduzierbarer Pack-/Sign-/Verify-/Publish-/Fetch-/Install-Test mit Testschlüssel und lokalem Test-Mesh.
- Manipuliertes Manifest, Archiv, Pfad, Ziel oder Signatur wird vor Installation fail-closed abgelehnt.
- Unvollständige Plattform-Builds werden nicht publiziert; erneutes Publizieren derselben Release-Identität ist entweder idempotent oder ein expliziter Fehler.
- Rollback/Key-Rotation bleibt an den dokumentierten Release-Key-Lifecycle gebunden; Mesh-Identität ist kein Trust Anchor.

**Aufwand:** 5–9 Tage nach P1-2/P1-5 für Publish-Namespace und Prozessgrenzen; 8–13 Tage, falls plattformübergreifende Build-Automatisierung ebenfalls neu aufgebaut werden muss. **Risiko:** mittel-hoch.

### P3-4 — UI-Workbench Live-Editing an AST-Code-Scopes *(Historischer Entwurf / Externe Satelliten-App)*

**Ist-Stand**

- `sb-workbench` wurde als separates Frontend ausgelagert; frühere Entwürfe speicherten validierte Design-JSON-Entwürfe lokal oder im Tauri-App-Datenverzeichnis.
- Es gibt im Core keine direkte Kopplung mehr; die maßgebliche Logik für AST-Scopes und Quelltext-Versionierung liegt in `sb-code`.
- `sb-code` kann AST-Scopes und opaque Regionen erfassen. AST-Erkennung ist keine semantische Korrektheitsgarantie; Parser-/Adapterversion und Basis-Commit sind relevant.

**Empfohlener Schnitt**

Nicht beliebiges Live-Schreiben in Dateien implementieren. Die Workbench bleibt zunächst der visuelle Editor; eine „Code-Scopes“-Ansicht zeigt eine Vorschau für unterstützte Komponenten-Dateien. Jede Änderung ist eine explizite, überprüfbare Patch-Transaktion:

1. Nutzer wählt Workspace, Basis-Commit und unterstützten Scope.
2. Workbench zeigt Scope-ID, Datei, Parser-/Adapterversion und Opaque-/Diagnosestatus.
3. Visuelle Bearbeitung erzeugt zunächst einen Patch-Entwurf, keine Dateisystemänderung.
4. Patch wird gegen den gespeicherten Scope-Hash und Basis-Commit validiert; bei veraltetem Basisstand muss neu geladen/verglichen werden.
5. Preview und Tests laufen; erst nach expliziter Bestätigung schreibt `sb-code` einen neuen Commit oder eine klar abgegrenzte Änderung.
6. Undo ist ein neuer nachvollziehbarer Commit, keine unprotokollierte Überschreibung.

**MVP-Grenze**

Ein Komponenten-Typ oder eine einzelne unterstützte React-Komponenten-Datei, nur eindeutige erkannte Scopes, keine opaque Regionen, kein automatisches Merge. Design-JSON bleibt unverändert verfügbar und exportierbar. Ein schreibgeschützter Scope-Inspektor plus Patch-Vorschau ist die erste Lieferung; Live-Schreiben kommt erst nach sicheren Patch- und Konfliktverträgen.

**Abnahmekriterien**

- Geänderte Scope-Quelle bleibt bei Syntaxfehler, Parserdiagnose, opaque Region oder veraltetem Basis-Hash unberührt.
- Preview zeigt exakte Änderungen und zugehörige Datei/Scope/Basisversion.
- Erfolgreiche Bestätigung erzeugt eine reproduzierbare `sb-code`-Änderung; Undo/Recovery ist getestet.
- Tests decken Parserfehler, kollidierende Änderungen, abgebrochene Vorschau und Wiederöffnung des Workspaces ab.

**Aufwand:** 7–12 Tage für Scope-Inspektor und sicheren Patch-Prototyp; 12–20 Tage für einen integrierten visuellen Write-Flow samt Undo/Conflict UX. **Risiko:** mittel-hoch.

## Abhängigkeiten und Lieferung

```text
P1-1 Core-Service-Vertrag ───────┐
                                 ├── P1-5 Workspace-ACLs und Replikation
P1-2 Prozess-/Identitätsgrenzen ─┘             └── P2-2 signierte Mesh-Paketverteilung

P3-4 kann parallel read-only prototypisiert werden,
     schreibt aber erst nach Scope-Patch-/Transaktionsvertrag
```

P1-1 und P1-2 können parallel entwickelt werden. P1-5 benötigt beide: einen stabilen Vertrag für Workspace-Operationen und eine belastbare Identitäts-/Betriebsgrenze. Ein isolierter lokaler Workspace-Prototyp kann früher entstehen, darf dann aber nicht als im Mesh oder auf OS-Ebene isoliert bezeichnet werden. P3-4 kann unabhängig mit einem read-only Inspektor beginnen; verbindliche Änderungen hängen von einer stabilen `sb-code`-Patch-API ab.

### Empfohlene Lieferstufen

| Stufe | Inhalt | Größenordnung | Freigabekriterium |
|---|---|---:|---|
| A | P1-1 Vertrag, Fixtures und Daemon-Adapter für Status/Peers | 4–7 Tage | Kein zweites Mesh-JSON-Schema; Auth-/Fehler-/Versions-Tests grün |
| B | P1-2 Linux-Konto-/Instanztrennung, Windows-Grenze ehrlich markiert | 7–12 Tage | Negativtests der OS-Dateigrenze und dokumentierte Plattformabdeckung |
| C | P1-5 Zwei Workspaces, Single-Writer, isolierte ACLs, Push/Pull | 8–15 Tage | Cross-workspace Deny und Ausfall-/Divergenztests grün |
| D | P2-2 signierte Artefakte in dediziertem Release-Namespace | 5–9 Tage | Ende-zu-Ende-Test bis zur verifizierten Installation |
| E | P3-4 read-only Scope-Inspektor, danach Patch-Prototyp | 7–12 Tage + | Veraltete/ungültige Scopes können keine Änderungen schreiben |

## Vor der Umsetzung bewusst nicht festzurren

- Unbegrenzte Multi-Writer-Replikation oder automatische Konfliktauflösung.
- Eigene Mesh-Overlay-Netze für jedes Tool, bevor Vertrauensgrenzen dies erfordern.
- Windows Service Support als bereits vorhanden; aktuell erzeugt die Vorlage eine Scheduled Task.
- Live-Schreiben aus der UI vor einem expliziten `sb-code`-Patch-/Commit-Vertrag.
- Mesh-Transport als Authentizitätsbeweis für Release-Pakete.
- „Sicher“, „isoliert“ oder „revisionssicher“ ohne die zugehörigen Plattformtests und Betriebsnachweise.

## Quellen im Repository

- Backlog und Akzeptanzkriterien: [`../brain/backlog.md`](../brain/backlog.md)
- Zielarchitektur und Isolationsempfehlung: [`ARCHITECTURE.md`](ARCHITECTURE.md), Abschnitte 3, 5 und 6
- Core-RPC: `tools/sb-core/src/rpc.rs`, `service.rs`, `dto.rs`
- Mesh-IPC und State: `tools/sb-mesh/src/ipc.rs`, `state.rs`, `identity.rs`, `service.rs`
- Mesh-Sync und AST/VCS: `tools/sb-code/src/mesh_sync.rs`, `vcs.rs`, `ast.rs`
- Release-Implementierung und Grenzen: `tools/sb/src/commands/release.rs`, [`../packaging/DISTRIBUTION_GUIDE.md`](../packaging/DISTRIBUTION_GUIDE.md)
- UI-Workbench: `tools/sb-workbench/src/App.tsx`, `src-tauri/src/lib.rs`
