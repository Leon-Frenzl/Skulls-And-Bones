# Skulls & Bones // PortSentry: Process-Tree Killer & Cyber TUI Cockpit
> **Dokument-ID:** `SBM-DOC-2026-PORTS`  
> **Status:** Ausgegliedert / Historische Spezifikation (Nicht Teil der 14 Core-Tools)  
> **Hinweis:** `sb-ports` wurde im Zuge der 14-Core-Konsolidierung aus der aktiven Core-Suite ausgegliedert. Dieses Dokument verbleibt ausschließlich als historische Referenz.
> **Ziel:** Vollständige Behebung von Port-Blockaden, Socket-Konflikten und Zombie-Prozessen ohne Root-Zwang

---

## 1. Das Problem: Die "EADDRINUSE" Realität

Moderne Web-Entwickler und DevOps-Ingenieure starten täglich dutzende lokale Server:
- Frontend: Vite (5173), Next.js (3000), Webpack (8080)
- Backend: FastAPI (8000), Spring Boot (8080), Express (3000)
- Datenbanken: PostgreSQL (5432), Redis (6379), MySQL (3306)

Wenn eine Shell abstürzt, ein Watcher-Prozess einfriert oder ein Hintergrund-Worker hängenbleibt, bleibt der Port gebunden. Das traditionelle Vorgehen:
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID 14820 /F

# Linux / macOS
lsof -i :3000
kill -9 14820
```
**Die Schwachstelle:** Beendet man nur die Parent-PID, läuft der eigentliche Worker (z. B. `esbuild` oder `python worker`) oft weiter und hält den Socket blockiert!

---

## 2. Die Lösung: PortSentry Engine

`sb-ports` automatisiert diesen Ablauf in Mikrosekunden:

1. **Kernel ToolHelp32 Snapshot:**
   - Fragt unter Windows direkt die Win32 ToolHelp-API (`CreateToolhelp32Snapshot`) ab.
   - Bildet den gesamten Prozessbaum (PID, PPID, Kindprozesse) in <1ms im Speicher ab.
2. **Rekursiver Tree-Kill:**
   - Beendet die gesamte Prozessfamilie (`taskkill /F /T` auf Windows, `pkill -P` + `kill -9` auf Unix).
3. **Absoluter OS- & Kernel-Schutz:**
   - Schützt System-PIDs (0, 4, 1) und kritische System-Images (`csrss.exe`, `lsass.exe`, `svchost.exe`, `systemd`, `launchd`).

---

## 3. Ratatui Terminal Cockpit (`sb ports tui`)

Das interaktive TUI-Cockpit bietet:
- **Metrics HUD**: Live-Zähler für Total Ports, Dev Ports, Active PIDs und Zombie-Prozesse.
- **Fuzzy Search (`/`)**: Sofortiges Filtern nach Portnummer oder Prozessname.
- **1-Key Modal**: <kbd>k</kbd> oder <kbd>Space</kbd> öffnet eine Sicherheitsabfrage mit Anzeige aller betroffenen Kind-PIDs.

```
┌─ PortSentry HUD ────────────────────────────────────────────────────────┐
│ Total Ports: 48   Dev Ports: 3   Active PIDs: 24   Zombies: 0          │
└─────────────────────────────────────────────────────────────────────────┘
┌─ Active Ports Table ───────────────────────────────────────────────────┐
│ PORT   PROTO  PID    PPID   CHILDREN  PROCESS            STATE         │
│ 3000   TCP    14820  8412   2         node.exe           LISTENING     │
│ 5173   TCP    21904  14820  1         vite.exe           LISTENING     │
│ 58888  UDP    9912   1      0         sb-node.exe        BOUND         │
└─────────────────────────────────────────────────────────────────────────┘
```
