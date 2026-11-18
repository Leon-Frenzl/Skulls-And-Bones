---
title: "Historischer Sitzungs-Handoff — Desktop/SSH-Keys"
document_type: historical-session-note
status: historical
language: de
updated: 2026-10-03
---

# Historischer Handoff (2026-09-09)

Dieses Dokument bewahrt den Kontext einer älteren Implementierungssitzung. Es ist **kein** aktueller Task-Tracker und seine To-dos dürfen nicht blind fortgesetzt werden.

## Damaliger Kontext

Die Sitzung untersuchte eine frühere „S&B Vault“-Desktop-App und die Erweiterung um SSH-Key-Management. Der Handoff hielt fest, dass damals Tauri Commands, UI-Wrapper und weitere Server-CRUD-Arbeit offen waren.

## Warum das nicht als aktueller Stand gilt

- Das Produkt hieß zwischenzeitlich `sb-desktop`, wurde jedoch im Rahmen der 14-Core-Konsolidierung (Milestone M3) mitsamt aller Frontend-/Tauri-Komponenten aus dem Kern-Repository als externer Satellit ausgelagert.
- `tools/sb-desktop/` existiert im Kern-Repository nicht mehr; der Suite-Kern konzentriert sich auf die 14 Core-Tools (11 CLI/Daemon-Binaries + 3 Bibliotheken).
- Dateien und Komponenten wurden seitdem verändert; der Handoff nennt Pfade, die nicht mehr existieren.
- Die damaligen Build-/Testaussagen sind zeitgebunden und belegen keinen heutigen Build.
- Aktuelle Zuständigkeiten und Entscheidungen stehen in [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md), die vom Maintainer bestätigten Beschlüsse in [`decisions.md`](decisions.md).

## Nutzung

Nur als rein historischer Verlaufshinweis lesen. Desktop- und UI-Entwicklungen werden in separaten Satelliten-Repositories fortgeführt.
