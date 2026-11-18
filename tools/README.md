# Skulls & Bones — Suite-Tools

Die Projekte unter `tools/` bilden eine modulare Suite, keinen Monolithen. Jedes Tool behält eine eigene fachliche Zuständigkeit und soll eigenständig baubar, versionierbar und installierbar bleiben. `sb` ist der Launcher und Manager für optionale Tools.

## Architekturgrenzen

- **`sb`** startet und verwaltet Suite-Tools; die Fachlogik bleibt in den jeweiligen Tools.
- **`sb-core`** stellt gemeinsame Typen, Konfigurationen, Service-Schnittstellen und versionierte API-Verträge bereit. Es soll nicht von allen konkreten Tool-Crates abhängen.
- Der **Suite-Daemon** (`sb daemon`) verbindet Tool-Services über einen versionierten lokalen IPC-Vertrag. RPC-POST-Anfragen verlangen ein zufälliges Bearer-Token aus `~/.sb/run/daemon.token`; unter Unix werden Runtime-Verzeichnis und Token restriktiv berechtigt. `sb-forge` und Clients nutzen denselben Daemon für Secret- und Status-Operationen. Der Loopback-HTTP-Transport bleibt eine lokale Vertrauensgrenze.

### Die 14 Kern-Tools im Root-Workspace

Alle 14 im Repository verbleibenden Tools befinden sich im einheitlichen Root-Cargo-Workspace:

1. **`sb`** (`tools/sb`): Root CLI Launcher, Installer, Tool Manager und Daemon (`sb daemon`)
2. **`sb-core`** (`tools/sb-core`): Gemeinsame DTOs, Crypto-Primitives, Fehlercodes und IPC-Verträge (Bibliothek)
3. **`sb-app-contract`** (`tools/sb-app-contract`): Standardisierte Verträge für modulare Mesh-Apps (Bibliothek)
4. **`sb-app-protocol`** (`tools/sb-app-protocol`): Typisierte Wire-Transfer-Protokolle und Bounded Streams (Bibliothek)
5. **`sb-auth`** (`tools/sb-auth`): Authentifizierungs-Engine, Key Exchange und Sitzungsverwaltung
6. **`sb-code`** (`tools/sb-code`): Dezentrales Versionskontrollsystem (VCS) und Code-Sync
7. **`sb-db`** (`tools/sb-db`): Dezentrale, verifizierte relationale & dokumentenbasierte Datenbank
8. **`sb-dns`** (`tools/sb-dns`): Dezentraler Sovereign DNS Resolver & Split-DNS Authority Engine
9. **`sb-drive`** (`tools/sb-drive`): E2E-verschlüsselter dezentraler Objektspeicher
10. **`sb-forge`** (`tools/sb-forge`): Task Runner, Reproducible Build Pipelines, Audit & Secret Orchestration
11. **`sb-key`** (`tools/sb-key`): Kryptografisches Schlüsselmanagement & Identitäts-Souveränität
12. **`sb-mesh`** (`tools/sb-mesh`): P2P WireGuard-/Noise-basiertes Overlay-Netzwerk
13. **`sb-node`** (`tools/sb-node`): Sovereign Node Daemon, Fleet Management & Ingress Controller
14. **`sb-proxy`** (`tools/sb-proxy`): Pure-Rust Reverse-Proxy, Edge Gateway & TLS Termination Engine

*(Hinweis: Desktop-Anwendungen wie `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, Web-UI-Komponenten wie `sb-ui`, `skel` sowie eigenständige Shells wie `sb-shell`, `skully` wurden im Rahmen von Milestone M3 als eigenständige externe Satelliten ausgelagert).*

Die Zielarchitektur, die Ist-Abweichungen und offene Designfragen sind in [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) beschrieben.
Der versionierte Zielvertrag für mesh-scoped Magic DNS, Mesh Authority und Split-DNS steht in [`docs/SB_DNS_SOVEREIGN_RESOLVER_SPEC.md`](../docs/SB_DNS_SOVEREIGN_RESOLVER_SPEC.md). `sb-dns` hat inzwischen die Hickory-basierte Resolver-Grundlage mit UDP/TCP-Listener, privater fail-closed Auflösung, verifizierbarer Directory-Record-Aufnahme und geprüftem Upstream-Forwarding. Lokal konfigurierte Authority-Keys werden validiert; `serve` lädt signierte Snapshots aus `~/.sb/dns/directory-snapshots.json` und übernimmt jeden vollständigen Mesh-Snapshot erst nach Validierung atomar. Authority-Enrolment, authentifizierter Snapshot-Transport, Aktualisierung und persistenter Anti-Rollback-Zustand stehen weiterhin aus.

## Bestand und Workspace-Verifikation

Alle 14 Kern-Tools sind vollwertige Mitglieder des Root-Cargo-Workspace und werden durch `cargo check --workspace` und `cargo test --workspace` gemeinsam gebaut und mit 882+ Tests geprüft. Der Gesamtzustand inklusive Website-Build und `product-inventory.json` wird über `npm run verify:suite` auditiert.

Die langfristige Quelle der Wahrheit für Code soll das eigene Sovereign Dev Mesh sein. `sb-code` soll eine neue Versionsgeschichte führen; vorhandene Git-Historie wird nicht in diese neue Historie importiert. Pro Tool vorgesehene Working Spaces im Dev Mesh sind noch in Entwurfsphase.
