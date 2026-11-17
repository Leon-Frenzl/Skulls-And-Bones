---
title: "Skulls & Bones — Bestätigte Produkt- und Architekturentscheidungen"
document_type: decision-register
status: canonical
language: de
updated: 2026-10-18
---

# Bestätigte Entscheidungen

Diese Liste hält explizit bestätigte Maintainer-Entscheidungen fest. Sie ist keine vollständige Implementierungsbeschreibung. Ist-Stand und Abweichungen: [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

## Produktmodell

- Skulls & Bones bleibt eine modulare Suite, kein Monolith.
- `sb` ist Launcher und Manager für die eigenständigen Suite-Tools.
- `sb-core` enthält gemeinsame Typen, DTOs, Vault-Kryptografie und Service-Schnittstellen.
- Ein lokaler Daemon (`sb daemon`) stellt versionierte IPC (JSON-RPC 2.0) für lokale Clients und Werkzeuge bereit.
- **Ausgliederung von Desktop, Web-UI, Shell und Terminal:** Die Suite konzentriert sich vollständig auf das autarke 14-Core-Ökosystem aus Headless-CLI-Werkzeugen, Daemons und gemeinsamen Vertragscrates (`sb`, `sb-core`, `sb-app-contract`, `sb-app-protocol`, `sb-auth`, `sb-code`, `sb-db`, `sb-dns`, `sb-drive`, `sb-forge`, `sb-key`, `sb-mesh`, `sb-node`, `sb-proxy`). Frühere Desktop-Frontends (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Frameworks (`skel`, `sb-ui`) sowie separate Shell-/Terminal-Projekte (`sb-shell`, `skully`) wurden vollständig aus der Core-Suite ausgegliedert.
- Die öffentliche Produktwebsite (`website/`) bleibt eine eigenständige Webanwendung und wird über `sb-proxy static` ausgeliefert.
- Altsysteme wie `sb-ssh`, `sb-vault` und `sb-ports` sind keine Suite-Produkte.
- Tools bleiben einzeln versionierbar. Das kanonische `product-inventory.json` führt die 14 Kern-Tools.

## Secret-Management

- Die gemeinsame Vault-Implementierung und ihr versionierter Vertrag gehören in `sb-core`; alle Werkzeuge und Dienste verwenden diesen Standard statt eigene Vault-Kryptografie oder parallele Secret-Speicherpfade einzuführen.
- `sb vault`, `sb daemon` und `sb-forge` verwenden dieselbe logische Vault-Datenquelle und denselben Secret-Bestand; es gibt keine unabhängigen tool-spezifischen Secret-Speicher.
- Der Standardpfad für den gemeinsamen lokalen Vault ist `~/.sb/vault`; explizit gewählte Vault-Profile bestimmen für alle Suite-Komponenten denselben aktiven Speicher.
- `sb-forge` nutzt eine verfügbare Daemon-Sitzung und fällt andernfalls auf den interaktiven direkten Store-Zugriff zurück; beide Pfade greifen auf dieselbe Vault-Datenquelle zu.
- Anwendungs-Secrets dürfen in einem lokalen Vault dauerhaft gespeichert werden, sofern sie dort verschlüsselt abgelegt sind.
- Secret-Klartext wird nur nach Entsperrung und während der aktiven Nutzung in den Arbeitsspeicher geladen; Laufzeitkopien sind nach Möglichkeit bei Sperrung oder Ende der Nutzung zu löschen.
- Verschlüsselte Ablage ist keine Garantie gegen Betriebssystem-Paging, Ruhezustandsabbilder, Crash-Dumps oder kompromittierte Prozesse. Der Schutzumfang muss dokumentiert und darf nicht als strikt „nur RAM“ oder „zero trace“ überversprochen werden.

## Code und Dev Mesh

- `sb-code` ist die maßgebliche Versionsverwaltung des Projekts.
- Alte Git-Historie wird nicht in die neue `sb-code`-Historie importiert.
- Für Quellcode sind AST-/CST-Scopes die primäre Einheit für Vergleich, Review und Integration; Dateien und Blobs bleiben Speicher- und Transportformat. Nicht erkannte Bereiche werden opaque und standardmäßig manuell behandelt; eine einseitige Übernahme ist nur bei stabiler, eindeutiger Begrenzung zulässig. Binärdateien bleiben dateibasierte, nicht automatisch mergebare Objekte.
- Parser werden über eine erweiterbare, sprachneutrale Adapter-Registry eingebunden. Tree-sitter ist die Syntaxbasis; jede Scope-Aufnahme speichert Parser-/Adapterversion. Fehlende Parser oder Syntaxfehler erzeugen diagnostizierte Opaque-Bereiche statt heuristisch geratenem Merge-Verhalten.
- AST-Struktur ist keine semantische Korrektheitsgarantie. Automatische Integrationspläne müssen Basis und beide Branch-Heads ausweisen; Konflikte, Parsergrenzen und fehlende semantische Validierung bleiben sichtbar.
- Jedes Tool besitzt einen eigenen logischen Projekt-Working-Space (`dev/tools/<tool>`) im gemeinsamen Dev Mesh mit Single-Writer-Autorität (`authoritative_writer`), Capability-Tokens und CAS-Divergenzschutz.
- Offline-Replikation und parallele Schreibzugriffe erzwingen Fast-Forward an erwartete Branch-Heads (`expected_head`); divergierende Stände werden fail-closed abgewiesen.

## Release und Vertrauen

- `sb` bezieht signierte, versionierte Tool-Artefakte aus dem öffentlichen Sovereign Mesh oder HTTPS-Mirrors.
- Der Client verwendet einen gepinnten öffentlichen Ed25519-Signierschlüssel (`RELEASE_PUBLIC_KEY`) zur strikten Verifikation; das Mesh ist Transport und Speicher, nicht der Trust Anchor.
- Website, Public Mesh und Signierer dürfen zunächst auf demselben physischen Host laufen, aber müssen durch Prozesse, OS-Servicekonten und Berechtigungen getrennt sein.
- OS-Root und Kernel gelten unter dieser ersten Betriebsgrenze als vertrauenswürdig.
- Das Release-Key-Material soll verschlüsselt und nur für autorisierte Releases entsperrt sein.
- Backup, Recovery und Rotation des Release-Schlüssels sind in [`docs/RELEASE_KEY_LIFECYCLE.md`](../docs/RELEASE_KEY_LIFECYCLE.md) definiert.
- FROST/Threshold Signing mit unabhängigen Teilnehmern ist ein späteres Ziel, nicht als implementierte Funktion auszugeben.

## IPC und Schnittstellen

- Lokale IPC zwischen Tools, Daemon und Frontends nutzt versioniertes JSON-RPC 2.0 mit Envelope, Bearer-Token-Authentisierung, maximalem Request-Limit (`MAX_RPC_REQUEST_BYTES`) und strukturierter Fehlerbehandlung.
- Browser-Origins und unpassende Content-Types werden strikt abgewiesen.
- Die lokale UI-/Daemon-IPC ist von der Mesh-Service-Transportgrenze zu unterscheiden. Remote-Aufrufe laufen über authentisierte, versionierte Mesh-Verträge und prüfen die aktuelle Autorisierung am Dienst; Loopback-Bearer-IPC darf nicht als Mesh-Identität oder Ressourcen-ACL missverstanden werden.

## Terminal und Shell (Ausgegliedert)

- `sb-shell` und `skully` wurden im Zuge der 14-Core-Konsolidierung vollständig aus der Core-Suite ausgegliedert.
- Die Suite setzt auf Standard-Betriebssystem-Terminals und native Shells auf.

## Mesh-Neuaufbau

- Beim Umbau werden Meshes mit neuen Identitäten und leeren Peer-/RBAC-Stores neu initialisiert.
- Peers müssen erneut gekoppelt werden.
- Alte Dateien werden nicht automatisch übernommen oder gelöscht; vor manueller Bereinigung ist eine gesicherte Umstellung erforderlich.
- User-Space-VRF ist Routingkontrolle, keine Isolation vor kompromittierten Prozessen, OS-Root oder Kernel.

## Noch offen

- Physische Mehrknoten-Automatisierung für FROST/Threshold Signing.
- Freischaltung der Server-Firewall auf Port 443 des Live-Hosts `skulls-and-bones.org`.
