# Skulls & Bones — Zielarchitektur

> **Status:** Gemeinsames Zielbild; Details der Mesh-Replikation und mehrere heutige Produktgrenzen sind noch offen.
> **Gültig ab:** 2026-10-03

Dieses Dokument hält die vereinbarte Zielrichtung für die Suite fest. Es unterscheidet bewusst zwischen Architekturentscheidungen, dem gegenwärtigen Repository-Stand und noch offenen technischen Entscheidungen. Ältere Pläne und Release-Dokumente sind keine verlässliche Beschreibung des Ist-Zustands, sofern sie diesem Dokument widersprechen.

## 1. Leitplanken

- Skulls & Bones ist eine **modulare Suite, kein Monolith**.
- Die Tools bleiben eigenständige Programme und werden als getrennte Binaries entwickelt, versioniert und installiert.
- `sb` ist Launcher und Manager: Es entdeckt, installiert, aktualisiert und startet Tools und verwaltet deren Kompatibilität.
- Der Quellcode und die maßgebliche Entwicklung sollen im eigenen Sovereign Dev Mesh stattfinden, nicht bei einem zentralen Code-Hosting-Anbieter.
- `sb-code` soll die Versionsverwaltung werden. Die alte Git-Historie wird nicht in die neue Versionsgeschichte übernommen.
- Skulls & Bones fokussiert sich auf autarke, hochsichere CLI- und Daemon-Werkzeuge sowie servicegebundene Verträge (14 konsolidierte Kern-Tools). Desktop-Frontends und UI-Experimente wurden aus der Core-Suite ausgegliedert.

## 2. Komponenten und Zuständigkeiten

| Komponente | Zuständigkeit im Zielbild | Status im 14-Core-Ökosystem |
|---|---|---|
| `sb` | Einstiegspunkt, Tool-Launcher und Tool-Manager | Rust-CLI im Root-Cargo-Workspace. Modularer Launcher, Paket- und Release-Verifikation (`sb release pack`, `sb install`). |
| `sb-core` | Gemeinsame Domain-Typen, Konfiguration, Identität/Autorisierungsverträge und versionierte Service-/IPC-Schnittstellen | Rust-Bibliothek im Root-Cargo-Workspace mit DTO-, RPC-, Pfad-, Port- und Vault-Modulen. |
| `sb-app-contract` | SB-MAP Manifest-Verifikation und Service-, App-, Ressourcen- und Policy-gebundene Operation Grants | Gemeinsame Rust-Vertragsbibliothek im Root-Cargo-Workspace. |
| `sb-app-protocol` | Versioniertes SB-MAP Control-Framing und digest-verifizierte Objekt-Transfer-Primitive | Gemeinsame Rust-Protokollbibliothek im Root-Cargo-Workspace. |
| `sb-auth` | Sovereign Authentication Kit mit Ed25519-Tokens, Multi-Tier Revocation und Argon2id | Eigenständiges Rust-CLI-Tool und Identity-Service. |
| `sb-code` | Lokale Code-Engine, AST-Scopes und Mesh-Synchronisierung | Eigenständiges Rust-CLI-Tool für Code- und Projektarbeitsbereiche. |
| `sb-db` | Embedded Document-KV Store mit MVCC, TTL, Indizes und Watch | Eigenständiges Rust-CLI-Tool und lokaler Datenbankdienst. |
| `sb-dns` | Sovereign DNS-Resolver und Mesh-Router | Eigenständiges Rust-CLI-Tool und lokaler/Mesh-DNS-Dienst. |
| `sb-drive` | Peer-Filesystem, Dateiübertragung und Mesh-Drive-CLI | Eigenständiges Rust-CLI-Tool für verteilte Mesh-Speicherung. |
| `sb-forge` | CI/CD-Pipeline-Runner und Secret-Engine | Eigenständiges Rust-CLI-Tool und DevOps-Automatisierung. |
| `sb-key` | Sovereign Root Identity und Ephemeral Lease Engine | Eigenständiges Rust-CLI-Tool für kryptografische Identitäten. |
| `sb-mesh` | P2P-Overlay-Netzwerk und Mesh-Management | Eigenständiges Rust-CLI-Tool und Overlay-Netzwerk-Daemon. |
| `sb-node` | Headless Mesh-Anchor und explizite Service-Routen | Eigenständiges Rust-CLI-Tool und Katalog-DC / Server-Daemon. |
| `sb-proxy` | Reverse Proxy, Auto-TLS und Edge Gateway | Eigenständiges Rust-CLI-Tool für Ingress-, Egress- und statische Auslieferung. |

*Hinweis zu ausgegliederten und historischen Komponenten:*  
Frühere Desktop-Anwendungen (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Frameworks (`skel`, `sb-ui`) sowie separate Shell-/Terminal-Projekte (`sb-shell`, `skully`) und Altsysteme (`sb-ports`, `sb-securenet`, `sb-ssh`, `sb-vault`) wurden aus dem Core-Workspace ausgegliedert bzw. restlos entfernt. Die Suite konzentriert sich rein auf die 14 konsolidierten Kern-Tools und die Webpräsenz (`website/`).

Clients rufen remote bereitgestellte Mesh-Funktionen über explizite, versionierte und authentisierte Verträge auf; sie laden keine unverifizierten Remote-UIs oder ausführbaren Module. Signierte Suite-Artefakte können Mesh als Transport nutzen, müssen aber vor lokaler Installation kryptografisch verifiziert und gemäß der lokalen Sandbox-Policy ausgeführt werden.

### Mesh-Verzeichnis und Katalog-DCs

Für digitale Mesh-Objekte (Dateien, Bilder, Datenbankeinträge und Container) liegt der autoritative Metadaten-/ACL-Katalog auf ausdrücklich eingerichteten `sb-node`-Katalog-DCs. Normale Mesh-Peers erhalten keine Katalogkopie allein dadurch, dass sie dem Mesh beitreten. Payload-Inhalte bleiben bei den zuständigen Speicherdiensten; der Katalog verwaltet Objektidentität, Versionen, ACLs und Payload-Verweise.

Das vereinbarte Ziel ist AD-inspiriertes Multi-Master-Verhalten zwischen diesen ausgewählten DCs: Jeder Katalog-DC darf Änderungen annehmen und repliziert sie mit den anderen berechtigten DCs. Es gibt keine stillschweigende Last-Writer-Wins-Regel anhand lokaler Uhren. Wenn getrennte DCs inkompatible Änderungen derselben ACL oder Gruppenmitgliedschaft erzeugen, wird der Konflikt explizit gespeichert und der betroffene Zugriff bis zur administrativen Auflösung fail-closed behandelt. Die Auflösung erzeugt eine nachvollziehbare neue Änderung.

Für geschützte Zugriffe muss ein DC außerdem nachweisen, dass sein Katalogstand aktuell genug ist; ohne diesen Nachweis verweigert er den Zugriff. Als Freshness-Grundlage wird ein Quorum mit expliziter DC-Mitgliedschaft und monotonen Epochen verwendet. Lese- und Schreibquoren müssen sich überschneiden (`R + W > N`); Schreibquoren müssen sich ebenfalls überschneiden (`2W > N`). Änderungen gelten erst nach dauerhafter Bestätigung des Schreibquorums als committed. Geschützte Zugriffe benötigen ein gültiges Lesequorum und verweigern den Zugriff, wenn Quorum, Epoch oder Konfliktfreiheit nicht nachweisbar sind.

Das Hinzufügen oder Entfernen eines Katalog-DCs ist eine administrative Membership-Änderung: Eine explizite Mesh-Admin-Gruppe autorisiert und signiert den Vorschlag; die aktuell gültige DC-Konfiguration muss ihn anschließend über ihr bestehendes Schreibquorum dauerhaft committen. Erst der committed Membership-Wechsel aktiviert die nächste monotone Epoch. Der versionierte Prüfvertrag in `sb-node` erzwingt getrennte Ed25519-Schlüssel für Admins und DCs, eine Admin-Signaturschwelle und eine Mehrheitssignatur der bisherigen DC-Mitgliedschaft auf exakt derselben Transition. `CatalogMembershipStore` speichert Membership und die pro Epoch getroffene lokale Signierentscheidung unter einem exklusiven Betriebssystem-Dateilock atomar; die Entscheidung wird vor Rückgabe einer Signatur persistiert, identische Wiederholung ist erlaubt, eine andere Transition derselben Epoch wird auch nach Neustart abgelehnt. Das Mehrheitsquorum schützt nur unter der Annahme, dass DCs keine widersprüchlichen Commits signieren; es ist kein byzantinisch fehlertoleranter Konsens. Der Store hat noch keine signierte, manipulationsnachweisbare Append-only-Journalverkettung, sichere Bootstrap-/Wiederherstellungsprozedur, CLI oder Laufzeitverbindung zum Replikations-Gate; Verlust oder gezielte Manipulation lokaler Store-Dateien ist nicht abgesichert. Diese Punkte und das Verhalten bei Quorumverlust müssen vor produktivem Einsatz folgen; ein lokaler CLI-Aufruf allein darf keinen DC eigenmächtig hinzufügen.

Die Zuständigkeiten zwischen Mesh und Server bleiben getrennt:

- `sb-mesh` ist der gemeinsame Transport für DC-zu-DC-Kommunikation: authentisierte Peer-Sitzungen, vertrauliche/integritätsgeschützte Streams sowie die dafür nötigen Replay-, Größen- und Flusskontrollen. Die Katalogreplikation verwendet einen expliziten, adressierten Control-Plane-Stream über diesen Transport; sie baut weder ein paralleles Overlay noch einen zweiten, ungeschützten Listener.
- `sb-node` hostet die Katalog-DC-Rolle und verantwortet DC-Mitgliedschaft und Epochen, Quorum-Leases sowie die Anwendung validierter Snapshot-Updates. Der Stream-Gate verlangt einen aktiven Peer mit explizitem `catalog:replicate`-Grant im Quell-Mesh und dessen aktive DC-Mitgliedschaft im Ziel-Mesh. Eine explizite Cross-Mesh-Route und eine gültige Quorum-Freshness-Lease sind zusätzliche Voraussetzungen; `stream:transfer` oder ein erfolgreicher Mesh-Handshake allein reichen nicht.
- Objekt-ACL-Principals (Benutzer, Geräte und Gruppen) sind von Mesh-Peer-/DC-Identitäten getrennt. `sb-mesh` entscheidet nicht über Dateizugriff; Fach-Services fragen die autoritative Katalog-Autorisierung ab und beachten deren Fail-Closed-/Freshness-Ergebnis.

Die Replikationsberechtigung gilt für den vollständigen Katalog eines Meshs, nicht für ausgewählte Container oder Objekte. Das hält Replikate als konsistente Kopien von Verzeichnis, ACLs und Objektmetadaten verwendbar; selektive Replikation würde Referenzen, Gruppenauflösung und Quorum-Zustand fragmentieren. Ein berechtigter Katalog-DC kann deshalb auch Metadaten sehen, deren Nutzdatenzugriff durch Objekt-ACLs eingeschränkt ist. Objekt-ACLs autorisieren den Zugriff auf Objekte/Payloads bei den zuständigen Diensten; sie sind keine Metadaten-Filter für die Katalogreplikation.

Der Admission-Gate für neue Verbindungen an Port `58831` prüft vor Weitergabe an den Mesh-Stream die aktive `catalog:replicate`-Capability des authentisierten Quell-Mesh-Peers sowie dessen aktuelle Katalog-DC-Mitgliedschaft im Ziel-Mesh. Zusätzlich muss unter `~/.sb-node/catalog/<mesh>/freshness.json` ein höchstens 30 Sekunden gültiger Ed25519-Nachweis einer strikten Mehrheit zur exakt geladenen Membership-Epoch und ihrem Digest vorliegen; Membership und Freshness liegen unter `membership.json` beziehungsweise `freshness.json` im selben Verzeichnis. Bei gültiger Membership registriert `sb-node` einen loopback-gebundenen Dienst und leitet den freigegebenen Cross-Mesh-Stream dorthin weiter. Das Datenprotokoll bietet Digest-Abfrage, Snapshot-Lesen und Snapshot-Anwendung. Ein Snapshot wird schema-validiert, auf die Ziel-Mesh-ID gebunden und nur angewendet, wenn der aktuelle SHA-256-Digest dem explizit angegebenen Basis-Digest entspricht; `absent` autorisiert ausschließlich die Initialisierung eines fehlenden Katalogs. Divergenz wird fail-closed abgelehnt, es gibt keinen automatischen Merge. Store-Schreibvorgänge koordinieren sich über einen exklusiven Dateilock und atomare Ersetzung. Die Katalogdatei liegt unter `object-catalog.json`.

`CatalogMembershipStore` kann Quorum-Lease-Signaturen erzeugen; Bootstrap, sichere Schlüsselbereitstellung und verteiltes Einsammeln/Erneuern der Lease sind noch nicht als nutzbarer CLI-Workflow verdrahtet. Ohne provisionierte Membership- und Freshness-Dateien bleibt der Dienst fail-closed. Außerdem fehlen persistente Replikationsjournale, kausale Änderungsmetadaten und automatischer Konflikt-Merge; die implementierte CAS-Regel verhindert lediglich stilles Überschreiben divergenter Snapshots. Der aktuelle `sb-mesh`-Transport ist ausdrücklich experimentell, nicht extern auditiert und noch kein produktionsreifer Vertrauenskanal für Katalog- oder ACL-Daten.

### Gemeinsamer lokaler Vault und Forge-Secrets

Der Standardpfad des gemeinsamen Vaults ist `~/.sb/vault`; ein aktives Vault-Profil kann einen anderen gemeinsamen Pfad bestimmen. `sb-core::vault::VaultStore` validiert Environment-Namen und meldet ungültige Dateien oder Dateizugriffsfehler explizit. Neue Vaults erhalten bei der ersten Initialisierung einen verschlüsselten Prüfdatensatz, damit auch ein leerer Vault falsche Passwörter ablehnt. `sb vault unlock` bzw. der lokale Daemon initialisiert einen leeren Vault beim ersten erfolgreichen Entsperren; Forge initialisiert beim ersten Secret-Setzen. Bestehende nicht initialisierte Vaults mit Einträgen werden nicht automatisch übernommen. Der Daemon bietet authentisierte RPC-Methoden für Initialize/Unlock/Lock, Secret CRUD und Passwortwechsel sowie eine sitzungsgebundene Entschlüsselung. Forge verwendet den Daemon, wenn er erreichbar ist, und fällt nur bei nicht verfügbarem Daemon auf die interaktive direkte Store-Nutzung zurück. Der frühere automatisch erzeugte Forge-`master.key`-Schlüsselpfad ist nicht mehr Teil des Vault-Zugriffs.

Die frühere `sb-forge env.sealed`-Implementierung verwendete keinen privaten Schlüssel des Zielservers bei der Envelope-Key-Ableitung; sie basierte auf Metadaten und Salt, die im Envelope enthalten waren. Deshalb war das Format keine servergebundene Vertraulichkeitsgrenze. `env seal`, explizite `exec --sealed`-Nutzung und automatische Nutzung vorhandener Legacy-Dateien sind inzwischen fail-closed deaktiviert. Vorhandene Dateien werden nicht automatisch gelöscht und dürfen nicht als vertraulich gelten. `sb-forge exec` startet für lokale Vault-Secrets weiterhin einen Kindprozess und übergibt diese über Prozess-Environment. Details und Designanforderungen stehen in [`../brain/forge-secrets-design.md`](../brain/forge-secrets-design.md).

## 3. Core, Services und IPC

Die Abhängigkeitsrichtung lautet:

```text
Clients & Werkzeuge
  sb CLI / sb-auth / sb-drive / externe Clients
                    │
                    ▼
       versionierter lokaler IPC-Vertrag
                    │
                    ▼
        Suite-Daemon / Composition Root
          │         │            │
          ▼         ▼            ▼
     sb-mesh sb-forge ... Fach-Services
          └──────────┬────────────┘
                     ▼
                 sb-core
```

- `sb-core` darf keine Abhängigkeit von allen konkreten Tool-Crates bekommen. So bleibt es als gemeinsame Bibliothek verwendbar und es entstehen keine zirkulären Abhängigkeiten.
- Core definiert stabile Request-/Response-Typen, Fehler, Versionen und Service-Schnittstellen. Es enthält nur dann API-Ablauflogik, wenn diese wirklich gemeinsame, toolübergreifende Anwendungslogik ist.
- Die Tools behalten die Implementierung ihrer Fachlogik und stellen Services gemäß den Core-Verträgen bereit.
- Der Daemon verbindet diese Services und ist die IPC-Transportgrenze. Transport, Authentisierung, Autorisierung, Größenlimits, Fehlerabbildung und Version-Aushandlung sind Teil des API-Designs, nicht Annahmen der UI.
- Der lokale Vertrag verwendet HTTP/1.1 ausschließlich über IPv4-Loopback: `POST /` verlangt genau ein zufälliges Bearer-Token aus `~/.sb/run/daemon.token` und `Content-Type: application/json`; RPC-POST-Requests mit `Origin` werden abgewiesen und es werden keine CORS-Freigaben erteilt. `GET /` und `GET /health` liefern nur Status. JSON-RPC 2.0 sowie `api_version` müssen in Request und Response explizit angegeben werden. Der Body ist auf 60 KiB (Request) bzw. 8 MiB (Response), HTTP-Header sind auf 8 KiB begrenzt; die HTTP-Puffer berücksichtigen Body und Header gemeinsam.
- Auf Unix sind Run-Verzeichnis und Token auf den Benutzer beschränkt. Unter Windows stützt sich die Dateizugriffskontrolle auf die Vererbung der Benutzerprofil-ACL. Das Token belegt nur Besitz des lokalen Geheimnisses, keine getrennte Prozessidentität oder Method-Rollen: Prozesse desselben Benutzerkontos gelten als gemeinsame Vertrauensdomäne. Der Transport ist nicht TLS-verschlüsselt; Vault-Passwörter und zurückgegebene Secret-Werte dürfen deshalb nur über vertrauenswürdige lokale Clients übertragen werden. Autorisierung bleibt zusätzlich an Service-/Vault-Zustände gebunden; die lokale IPC-Grenze ist keine Isolation gegenüber demselben Benutzerkonto.
- Clients und CLI-Werkzeuge sprechen für lokale Suite-Funktionen über diesen Vertrag. Remote-Fachfunktionen verwenden davon getrennte Mesh-Service-Endpunkte mit Peer-Identität, Capability und aktueller serverseitiger Autorisierung. Frühere Tauri-Commands wurden im Zuge der Desktop-Ausgliederung vollständig entfernt.

Der aktuelle `sb daemon`-Endpunkt ist ein Ausgangspunkt, aber noch keine fertige, produktionsreife API. Mesh-Telemetrie stammt jetzt aus `sb-mesh`-Peer-Laufzeitdaten und einem höchstens fünf Sekunden alten Snapshot unter `~/.sb-mesh/runtime-status.json`; ein fehlender, ungültiger oder veralteter Snapshot darf nicht als Online-Zustand gelten. Das experimentelle User-Space-Protokoll ist kein WireGuard-/Noise_IK-Tunnel; `tunnel_active` bleibt daher false. Drive-Zustände sind weiterhin unbekannt, bis echte Services diese melden.

## 4. Tools und Versionierung

- Jedes Tool ist eigenständig baubar, testbar und versionierbar.
- `sb` verwaltet optionale Tools und deren Kompatibilität; ein einzelnes Gesamtpaket ist nicht die Produktarchitektur.
- Ein Suite-Profil bzw. Lockfile kann für reproduzierbare Installationen konkrete, gemeinsam getestete Tool-Versionen festhalten, ohne die unabhängige Versionierung aufzugeben.
- Ein Tool-Inventar soll mindestens Produkt-ID, Binary-/Crate-Name, Version, Plattformen, Abhängigkeiten, Core-API-Version, Installationsquelle und Reifegrad enthalten.
- Alle 14 Kern-Tools sind lückenlos im gemeinsamen Root-Cargo-Workspace eingebunden. `cargo test --workspace` und `npm run verify:suite` decken die gesamte Core-Suite und Web-Präsenz ab.

## 5. Sovereign Code- und Working-Space-Modell

Die Quelle der Wahrheit soll im eigenen Dev Mesh liegen. `sb-code` wird die Versionsverwaltung; es ist keine bloße Git-Oberfläche. Die alte Git-Historie wird nicht in die neue Historie importiert. Eine mögliche Zwischenarchivierung der alten Arbeitskopie ist eine Migrations-/Sicherungsfrage, kein Teil der neuen Versionsgeschichte.

Die Softwareverteilung ist davon getrennt: `sb` lädt signierte, versionierte Tool-Artefakte aus dem öffentlichen Sovereign Mesh, in dem auch die Website liegt. Der Client vertraut dafür einem dauerhaft gepinnten öffentlichen Release-Schlüssel; das Mesh selbst ist kein Trust Anchor und ein Artefakt ohne gültige Signatur darf nicht installiert werden.

`sb-proxy` besitzt einen nativen statischen Auslieferungspfad (`sb proxy static <domain> <verzeichnis>`) neben Reverse-Proxy und Mesh-Tunnel. Ein Hyper-Server bedient HTTP/1.1 mit Keep-Alive und HTTP/2; statische Dateien werden gestreamt und MIME-Typen über `mime_guess` bestimmt. TLS kann explizite Zertifikate oder echtes Let's-Encrypt-ACME über TLS-ALPN-01 mit persistentem Cache verwenden; ACME startet standardmäßig gegen Staging. Konfigurierbare HSTS-/CSP-/`X-Content-Type-Options`-Header und JSON-Access-/Error-Logs sind vorhanden. Dies ist noch keine produktionsvalidierte Release-Infrastruktur: DNS, öffentlicher Port 443, Erneuerung und ein Live-Installationslauf müssen praktisch geprüft werden. Die Implementierung ist keine Prozess-/OS-Isolation vom restlichen `sb-proxy`; Webprozess, Publish-Verzeichnis und Signierer müssen vor Live-Betrieb durch getrennte OS-Berechtigungen und einen geprüften Betriebsablauf abgegrenzt werden.

Jedes Tool soll einen eigenen Projekt-Working-Space im Dev Mesh erhalten. **Noch offen ist, wie dieser logisch und technisch umgesetzt wird.** Als Startpunkt wird empfohlen:

- Ein gemeinsames Dev Mesh als Transport- und Vertrauensdomäne verwenden und darin je Projekt isolierte, benannte Arbeitsbereiche bereitstellen.
- Je Arbeitsbereich getrennte ACLs/Rollen, Schlüssel- und Replikationsrichtlinien sowie eine eigene `sb-code`-Historie führen.
- Einen physisch getrennten Mesh-Overlay nur dann aufbauen, wenn ein Projekt tatsächlich eine andere Vertrauens- oder Netzgrenze benötigt.
- Für die erste belastbare Version mit expliziten Schreibrechten und nachvollziehbaren Änderungen beginnen. Mehrschreiber-Replikation, Konfliktauflösung, offline-first Merge-Verhalten und automatische AST-/CRDT-Merges erst nach einem Prototyp und Bedrohungsmodell festlegen.

So bekommt jedes Tool einen klar isolierten Workspace, ohne vorschnell für jedes Projekt ein separates Netzwerk samt eigener Betriebs- und Schlüsselverwaltung zu erzwingen.

## 6. Mesh-Isolation und Release-Signierung

Ein öffentlicher und ein privater Mesh-Zugang auf demselben physischen Host sind keine hinreichende lokale Sicherheitsgrenze. Das Mesh kann Teilnehmer und Netzwerkverkehr trennen; es kann nicht verhindern, dass ein kompromittierter lokaler Prozess oder Host-Root auf Dateien und Schlüssel zugreift, für die derselbe Host Berechtigungen besitzt.

Der Mesh-State-Umbau ist begonnen, aber noch nicht als vollständige Sicherheitsgrenze abgenommen:

- Benannte Meshes verwenden nun `~/.sb-mesh/instances/<mesh>/` für Identität, Konfiguration, Peer-Tabelle, Runtime-Status, RBAC, Tickets und Subnet-Routen. Mesh-Namen werden auf kanonische Kleinbuchstaben/Ziffern/Bindestriche begrenzt; Instanzverzeichnisse dürfen keine Symlinks sein.
- Der Daemon und explizite Mesh-Flows wählen den zum Mesh gehörenden lokalen Schlüssel. Ein registriertes Mesh darf nicht still eine neue Identität erhalten; der lokale Schlüssel muss zum Mesh-Katalog passen. Join-Invites erzeugen bzw. verwenden den lokalen Schlüssel des Ziel-Meshes; der Server muss das Overlay-Subnetz im Ticket mitliefern, damit der Client den Mesh-Katalog lokal anlegen kann.
- Alte gemeinsame Dateien und frühere RBAC-/Ticket-Dateien werden nicht automatisch importiert oder gelöscht. Bootstrap und Daemon weisen auf gefundene Legacy-Dateien hin. Bei neuen Identitäten müssen Gegenstellen erneut gekoppelt werden.
- `networks.json` bleibt ein gemeinsamer Metadatenkatalog. Legacy-PSKs können dort bis zur expliziten Migration verbleiben; `sb-mesh network migrate-psks` legt sie pro Mesh als `network.psk` ab, verifiziert die Kopie und entfernt den Katalogwert erst danach. Fehler oder Konflikte lassen den Katalogwert erhalten. Die PSKs werden derzeit nicht in der Laufzeit verwendet.
- Ticket-Ausstellung prüft zusätzlich, dass der Daemon-Schlüssel zum Katalogschlüssel des angefragten Meshes passt; ein Daemon kann damit keine Tickets für ein anderes registriertes Mesh ausstellen.
- `NetworkStore::validate_vrf_boundary()` ist eine User-Space-Prüfung von Zieladressen gegen konfigurierte Subnetze. Sie ersetzt weder Prozess- noch Betriebssystem-Isolation. Route-/Bridge-Funktionen starten nicht automatisch; sie benötigen weiterhin einen expliziten Aufruf.

Die Mesh-spezifischen Pfade, Join-Metadaten, Ticket-Bindung und explizite PSK-Migration sind implementiert. Der Verzeichniszuschnitt reduziert versehentliche State-Vermischung, ist aber keine OS-Prozessisolation: Prozesse desselben Benutzerkontos bleiben eine gemeinsame Vertrauensdomäne. Die Website-Dokumentation beschreibt Multi-Mesh als „kryptographische Trennung“; diese Aussage bleibt ohne getrennte OS-Servicekonten und Dateirechte zu weitgehend und ist keine Sicherheitsgarantie.

Die Website-Dokumentation beschreibt Multi-Mesh als „kryptographische Trennung“. Diese Aussage ist für die vorhandene Implementierung zu weitgehend und wird daher bis zu einer stärkeren Implementierung als Ziel, nicht als Sicherheitsgarantie behandelt.

### Zielentwurf

1. Jedes Mesh bekommt eine eigene Identität, eigene Schlüssel, Peer-/RBAC-Daten und Konfiguration. Es gibt keine implizite Identitäts- oder Schlüsselwiederverwendung zwischen Public-, Dev- und Secret-Meshes.
2. Unterschiedliche Vertrauensdomänen laufen zunächst als getrennte `sb-mesh`-Instanzen mit getrennten OS-Servicekonten und Dateirechten. Cross-Mesh-Bridge-Funktionen bleiben standardmäßig aus und erfordern explizite, auditierte Regeln.
3. Der Public-Web-/Artefaktdienst erhält nur Leserechte auf veröffentlichte Pakete und hat keinen Dateisystem- oder IPC-Zugriff auf den Signierer. Der Signierer legt den privaten Schlüssel nicht in einer Mesh-Konfigurationsdatei ab; der Unlock- und Signiervorgang wird über einen getrennten Dienst und `sb-key` entworfen.
4. `sb` vertraut einem gepinnten öffentlichen Release-Schlüssel und akzeptiert nur Signaturen über die exakten Artefakt-Bytes. Das Mesh ist Transport, nicht Vertrauensanker. Schlüsselrotation und Sperrung müssen vor einer Produktionsverteilung spezifiziert werden.
5. Ein einzelner Signierer auf demselben Host kann einen kompromittierten Webprozess abgrenzen, solange OS-Root und Kernel vertrauenswürdig bleiben. Gegen Host-Root-Kompromittierung ist ein getrennter Hardware-Signer oder Threshold Signing mit Teilnehmern auf getrennten Hosts erforderlich.

Das Manifesto nennt FROST/Threshold-Signing als längerfristiges Ziel. Das kann mit einem einzelnen, im Client gepinnten öffentlichen Verifikationsschlüssel vereinbar sein: Der öffentliche Schlüssel bleibt stabil, während seine Nutzung durch mehrere unabhängige Teilnehmer freigegeben wird. FROST ist hier ein Architekturziel, kein im aktuellen Repository nachgewiesener Release-Signierpfad.

### Vereinbarte Bedrohungsgrenze

- Public-Webdienst, Mesh-Instanzen und Signierer laufen auf demselben physischen Host, aber als getrennte Prozesse und OS-Servicekonten mit getrennten Berechtigungen.
- Der private Release-Key ist verschlüsselt und wird nur für einen autorisierten Release entsperrt. Der Public-Webdienst erhält weder Dateisystem- noch IPC-Zugriff auf ihn.
- OS-Root und Kernel dieses Hosts gelten zunächst als vertrauenswürdig. Gegen deren Kompromittierung schützt diese Trennung nicht; Threshold Signing mit unabhängigen Teilnehmern auf getrennten Geräten/Hosts bleibt das spätere Ziel.
- Vor produktiver Veröffentlichung sind Schlüssel-Backup, Verifikation, Wiederherstellung und ein Verfahren für Kompromittierung/Rotation des gepinnten Schlüssels festzulegen.
- Beim Mesh-Umbau werden alle Netze mit neuen Identitäten und leeren Peer-/RBAC-Stores initialisiert; alle Gegenstellen müssen neu gekoppelt werden. Alte lokale Zustände werden nicht automatisch übernommen oder gelöscht und dürfen erst nach gesicherter Umstellung ausdrücklich bereinigt werden.

## 7. Aktuelle Abweichungen, die vor größerer Integration bereinigt werden müssen

1. Konsolidierung des Root-Cargo-Workspaces: Alle 14 Kern-Tools sind lückenlos im Root-Cargo-Workspace vereint; Desktop-Frontends (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`) wurden ausgegliedert.
2. Shell und Terminal: `sb-shell` und `skully` wurden als separate Projekte ausgegliedert und sind nicht Teil des 14-Core-Ökosystems.
3. Bereinigung von Altsystemen: `sb-ssh`, `sb-vault` und `sb-ports` sind historische Namen und nicht im kanonischen 14-Tool-Bestand enthalten.
4. Lokale IPC-Verträge: Der `sb`-Daemon stellt JSON-RPC bereit; Tauri-Commands wurden mit den Desktop-Apps entfernt.
5. Release-Dokumente, Workspace-Mitglieder und Packaging-Listen nennen unterschiedliche Tool-Mengen: Dies wird durch die verbindliche Orientierung an den 14 konsolidierten Tools in `product-inventory.json` behoben.
6. Der initiale `sb`-Bootstrap erfolgt derzeit aus einem Repository-Checkout mit Rust/Cargo (`cargo install --path tools/sb --bin sb`). `sb release pack` und `sb install` bilden die releasevalidierte lokale Signatur- und Installationskette. Ein verifizierter 1-Klick-Bootstrap-Installer existiert noch nicht.

Diese Abweichungen sind Inventar- und Integrationsaufgaben; sie rechtfertigen nicht, die eigenständigen Tools in einen Monolithen umzubauen.

## 8. Empfohlene Aufräum-Reihenfolge

1. Dieses Zielbild und das kanonische Tool-Inventar verbindlich machen; alte `Produktiv`- und Versionsbehauptungen als geprüft oder ungeprüft kennzeichnen.
2. Master-CLI, tatsächliche Binaries, Crates, Apps und optional installierbare Produkte aufeinander abbilden.
3. Mesh-Identitäten, lokale Prozessgrenzen und Release-Signierung spezifizieren; bestehende Multi-Mesh-Aussagen erst nach Tests als Sicherheitsgarantie führen.
4. Core-Service-Verträge und den Daemon als getrennte API-Grenze spezifizieren; Platzhalterdaten schrittweise durch echte Service-Implementierungen ersetzen.
5. Workspace- und Release-Prüfungen auf alle Rust- und UI-Projekte ausweiten.
6. `sb-code` lokal mit neuem Datenmodell und Recovery-/Backup-Strategie stabilisieren, bevor die Autorität der Versionsverwaltung ins Mesh verlagert wird.
7. Pro-Tool-Working-Spaces im gemeinsamen Dev Mesh prototypisieren; Isolations-, Replikations- und Konfliktmodell anhand des Prototyps festlegen.
8. Ausgliederung der Desktop-Apps: Desktop-Frontends (Tauri/React) wurden vollständig ausgegliedert; die Suite konzentriert sich auf Headless-Services und CLI-Tools. Die öffentliche Website bleibt eine getrennte Webanwendung.
9. Erst danach den Quellcode-Betrieb und die Installation vollständig auf die souveräne Infrastruktur umstellen. Alte Git-Daten nicht in `sb-code` importieren.

## 9. Noch offene Entscheidungen

- Wie werden Remote-Service-Implementierungen im Mesh katalogisiert, entdeckt und zusammengesetzt, ohne Discovery mit Berechtigung zu verwechseln?
- Wie authentisieren und autorisieren sich lokale IPC-Clients? Wie werden API-Versionen zwischen unabhängig aktualisierbaren Tools ausgehandelt?
- Ist jeder Dev-Mesh-Working-Space ein logischer Projekt-Namespace oder in bestimmten Fällen ein eigenes Overlay?
- Welche Replikation, Schreib-Leases, Konfliktauflösung und Wiederherstellung unterstützt `sb-code` zuerst?
- Wie werden Katalog-DC-Mitgliedschaft und Epoch-Wechsel sicher administriert, insbesondere das Hinzufügen/Entfernen eines DCs und die Wiederherstellung nach Verlust eines Quorums?
- Welche Protokoll- und Relay-Funktionen sollen künftig nativ in `sb-mesh` und `sb-node` integriert werden? (Historische Prototypen wie `sb-ssh` wurden ausgegliedert).
- Wann wird Threshold Signing als zusätzliche Freigabe des gepinnten Release-Schlüssels eingeführt?
- Welche Reifegrade und Plattformen sind tatsächlich releasefähig? Ältere Statusangaben wie „Produktiv“ sind bis zur Prüfung nicht als Qualitätsnachweis zu verwenden.
