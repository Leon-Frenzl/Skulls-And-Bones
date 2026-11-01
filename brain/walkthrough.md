---
title: "S&B Desktop — Implementierungsüberblick"
document_type: implementation-map
status: historical-archive
language: de
updated: 2026-10-26
---

# S&B Desktop — Implementierungsüberblick (Archiviert / Historischer Stand)

> **ARCHIV-HINWEIS (Milestone M3):**  
> `sb-desktop` (ehemals `tools/sb-desktop/`) sowie `sb-studio`, `sb-workbench` und `sb-ui` wurden im Rahmen der 14-Core-Konsolidierung aus dem Kern-Repository als externe Satelliten-Applikationen ausgelagert. Dieses Dokument dient ausschließlich der historischen Dokumentation des damaligen Desktop-Implementierungsstands.

Dieses Dokument beschreibt den historischen Implementierungsstand der früheren Desktop-Anwendung. Es führt selbst keine Build-, Test- oder Laufzeitverifikation im aktuellen Core-Repository durch.

## Produktgrenze

- `sb-desktop` (`tools/sb-desktop/`) ist die S&B-eigene Tauri-/React-Oberfläche.
- `sb-core` enthält gemeinsam genutzte DTOs und Vault-Krypto, wird von `sb-desktop/src-tauri` eingebunden.
- SSH-/NetGate-Code ist im aktuellen UI/Backend eng integriert, benötigt an mehreren Stellen jedoch ein externes `sb-ssh`-Binary. Das ist vorerst ein Prototyp bzw. eine noch nicht bereinigte Produktgrenze, kein nachgewiesenes eigenständiges Suite-Release.
- Der gemeinsame lokale Suite-Daemon/API-Vertrag ist Zielarchitektur, nicht der aktuelle Kommunikationspfad der gesamten Desktop-App. Das Backend registriert zahlreiche Tauri Commands direkt.

## Struktur

```text
tools/sb-desktop/
├── src/                 React-Oberfläche, Komponenten, Frontend-Adapter
└── src-tauri/
    └── src/             Tauri-Commands, Zustand, PTY, Mesh-/SSH-Integration
```

Die Tauri-App hat ihr eigenes Cargo-Workspace; Root-`cargo test --workspace` prüft sie nicht automatisch.

## Vorhandene Backend-Flächen

Die Module sind in `tools/sb-desktop/src-tauri/src/lib.rs` registriert:

| Bereich | Backend | Statushinweis |
|---|---|---|
| Vault und Secrets | `vault.rs`, `backup.rs` | Gemeinsame Verschlüsselungsfunktionen aus `sb-core`; Frontend-Schlüssel und Mock-Modus getrennt betrachten. |
| Server / SFTP / SSH-Keys | `servers.rs`, `sftp.rs`, `ssh_keys.rs` | SSH-Binary-Aufruf und Remote-Verhalten gegen das Prototyp-Produktmodell prüfen. |
| PTY-Terminal | `terminal.rs` | `portable-pty`; lokal startet die native System-Shell, Remote-Sitzungen verwenden `sb-ssh`. |
| Profile | `profiles.rs` | Profile liegen separat; Wechsel sperrt Vault-Session und beendet aktive Tunnel/Log-Streams. |
| Tunnels / Logs | `tunnels.rs`, `logs.rs` | Asynchrone Prozesse und Remote-Kommandos; nicht mit einer zentralen Daemon-API verwechseln. |
| Tray / Diagnose | `tray.rs`, `diagnostics.rs` | Tray-Commands und Ereignisse werden direkt im Tauri-Prozess behandelt. |
| Mesh / Phantom / Shadow | `mesh_desktop.rs` | Suite-Integrationen im Desktop-Backend; prüfen, ob Antworten vom echten Mesh-Dienst oder aus Mock-/Platzhalterdaten kommen. |
| Pipelines / Audit | `pipelines.rs`, `audits.rs` | Bindet Forge- und Aufzeichnungsdaten in die UI ein. |

## Frontend

- `src/App.tsx` verwaltet Views, Vault-Status, Profile, Quick-Copy und Auto-Lock.
- `src/lib/ipc.ts` kapselt Tauri `invoke`-Aufrufe und bietet außerhalb von Tauri Demo-/Mock-Antworten.
- Komponenten liegen unter `src/components/`; `PhantomDesktop.tsx`, `ServerHub.tsx`, `TerminalHub.tsx`, `VaultManager.tsx` sind größere Funktionsflächen.
- Browser-Mocks sind Entwicklungs-UX, kein Nachweis für Backend-Funktion oder echte Mesh-Verbindungen.

## Sichtbare Implementierungsbeispiele

- **Tauri IPC:** `src-tauri/src/lib.rs` baut den Handler aus direkten Modulfunktionen auf. `sb-core::RpcRequest` ist derzeit nicht die generelle UI-IPC-Grenze.
- **Profilwechsel:** `profiles.rs::switch_profile` setzt die aktive Vault-Session zurück und stoppt Tunnel und Log-Streams, bevor es das Profil wechselt. Verhalten unter Fehlern/Parallelaufrufen muss separat getestet werden.
- **Vault-Sperre:** `sb-core::vault::VaultSession` verwendet `Zeroize`/`ZeroizeOnDrop`; das ist eine konkrete Maßnahme, keine Garantie, dass alle Kopien, Strings oder Betriebssystempuffer genullt sind.
- **Quick-Copy:** `QuickCopyModal.tsx` kopiert über Browser Clipboard API und plant ein Löschen nach 30 Sekunden. Laufzeitfehler werden teils ignoriert; daher nicht als verlässlicher Clipboard-Schutz versprechen.
- **PTY:** `terminal.rs` erstellt PTY-Sitzungen und emittiert Ausgabe als Tauri Events; bei Remote-Zielen wird `sb-ssh` aufgerufen.
- **Tray:** `tray.rs` bietet Anzeigen/Sperren/Beenden und Fenster ein-/ausblenden. „Sperren“ setzt dort Vault-Session zurück und sendet ein Frontend-Event.

## Überprüfung vor konkreter Arbeit

1. Bestehende lokale Änderungen berücksichtigen; Dateien in diesem Bereich können bereits bearbeitet sein.
2. Zum betroffenen Tauri-Crate: `cargo check` und relevante `cargo test`.
3. Frontend: `npm run build` in `tools/sb-desktop`.
4. Verhalten mit nativer Tauri-App testen, wenn IPC, Tray, Clipboard, PTY oder Prozesse betroffen sind. Reiner Browser-Build testet diese Laufzeitpfade nicht.
5. Fehler bei Clipboard, Child-Prozessen, Tauri Events und Profilwechsel nicht als Erfolg verschweigen.

## Abgrenzung zur alten Historie

Die frühere Fassung behauptete unter anderem eine bestimmte Executable-Größe, genaue Testanzahlen und ein vollständiges `sb-vault`-Feature-Set. Diese Angaben sind nicht als aktueller Nachweis übernommen. Aktuelle Zielarchitektur und Produktgrenzen stehen in [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).
