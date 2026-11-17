# S&B Suite Master CLI (`sb`) — Roadmap & TODOs
> **Unified Command Center & Sovereign Developer Ecosystem**  
> 100% Standalone Rust Binary (`sb-cli` auf Crates.io)  
> *Sicherheitsmarke: Skulls & Bones ([skulls-and-bones.org](https://www.skulls-and-bones.org))*

---

## 🎯 Produkt-Vision
Die Master-CLI `sb` ist der zentrale Einstiegspunkt des gesamten Skulls & Bones Ökosystems. Sie steuert und integriert die modularen Werkzeuge der Suite (`sb-mesh`, `sb-forge`, `sb-key`, `sb-node`, `sb-proxy`, `sb-dns`, `sb-code` u. a.) zu einem kohärenten System im Terminal. Frühere Prototypen wie `sb-ssh`, `sb-vault` und `sb-ports` wurden im Rahmen der Konsolidierung bereinigt bzw. ausgelagert.

Statt isolierter CLI-Inseln bietet `sb` hochgradig integrierte Entwickler-Workflows:
- **`sb share <port>`**: Portables, Ende-zu-Ende verschlüsseltes Port-Sharing über das dezentrale WireGuard-Overlay (`sb-mesh`) als Ngrok-Alternative ohne Accounts.
- **`sb doctor`**: 360-Grad Integritäts- und Diagnostik-Audit für Netzwerk, Keys und Daemons.
- **`sb status`**: Echtes Live-System-HUD mit Latenzen, aktiven Tunnels und Peers.
- **Modulare Installation**: Gezielte Installation optionaler Suite-Tools (`sb install <tool>`).

---

## 📋 Entwicklungs-Phasen & Enterprise-Politur

### Phase 1: Fundament & Delegation (Status: 🟢 Erledigt & Veröffentlicht)
- [x] **Master-CLI Scaffolding:** Single-Binary in Rust mit `clap`, `colored`, `tokio`.
- [x] **Live-System HUD (`sb status`):** Prüft PATH-Präsenz der installierten Core-Tools, P2P Mesh-Socket (`127.0.0.1:58890`) und Root-Identity.
- [x] **Modulare Installation (`sb install` / `sb uninstall`):**
  - Selektive Installation (`sb install <tool>`) aus signierten Release-Archiven.
  - Gezielte Deinstallation und Update über das Release-Ledger.
- [x] **Gemeinsame Root-Identität (`sb identity`):**
  - Generiert Ed25519-Schlüsselpaar und Node-Fingerprint (`sbm-<hash>`) in `~/.sb/identity.json`.
- [x] **Transparente Delegation:**
  - `sb forge ...` ➔ delegiert an `sb-forge`.
  - `sb mesh ...` ➔ delegiert an `sb-mesh`.
  - `sb proxy ...` ➔ delegiert an `sb-proxy`.
  - *(Historisch: `sb ssh`, `sb vault`, `sb ports` wurden als frühere Prototypen/Satelliten delegiert).*
- [x] **Crates.io Release:** Veröffentlicht als `sb-cli`.

---

### Phase 2: Enterprise Politur — High-Level Developer Experience (Status: 🟢 Erledigt)
- [x] **`sb share <port>` (P2P Local-Port Tunneling):**
  - 1-Befehl Ngrok-Alternative ohne Cloud-Zwang via `sb-mesh`.
- [x] **`sb doctor` (360° System- & Security-Audit):**
  - Prüft Integrität von Keys, DNS, Mesh-Socket und offene Ports.
- [x] **Interaktive Shell-Completions (`sb completions <shell>`):**
  - Autovervollständigungen für Bash, Zsh, Fish und PowerShell.
- [x] **Portmanagement- & Socket-Diagnostik:**
  - Historische Prototyp-Integration von `sb-ports`; Socket- und Diagnose-Prüfungen in `sb doctor` und `sb status`.
  - Windows Zero-Downtime Self-Update Fix (Rename-Trick) in `sb-cli` v0.1.3 veröffentlicht.

---

### Phase 3: Sovereign Fleet Orchestration & Master Cockpit (Status: 🟢 Erledigt & Produktiv)
- [x] **1-Befehl Server Bootstrap (`sb server init <target>`):**
  - Verbindet frischen Server und Client ins selbe Mesh.
  - Verankert OpenSSH Swarm-CA Trust (`TrustedUserCAKeys`) und generiert `sb-node` systemd/Windows Service.
  - Schließt Port 22 für offenes WAN; schaltet Administration auf AutoSSH um.
  - Automatisches Known-Hosts-Pruning und nativer SSH-Passwort-Prompt.
- [x] **Team-Onboarding (`sb invite client <name>`):**
  - Generiert kryptographische Einladungstokens (`sbm-pair://...` mit TTL).
  - 4-Augen Quorum Konsens-Prüfung (`sb approve <req>`).
  - Verteilt Berechtigungen epidemisch über P2P-Gossip an alle Server.
- [x] **Atomarer Hardware- & User-Rauswurf (`sb revoke <name>`):**
  - Bannt Bobs Hardware-Node-ID sofort auf Netzwerk-Ebene via `GossipKind::RevokeNode`.
  - Trägt Zertifikatsserien in OpenSSH-KRL (`revoked_keys`) und `DenyUsers` in `99-sbm.conf` auf allen Servern ein.
  - Terminiert sofort alle laufenden SSH-Sessions und Tunnel.
- [x] **Master Terminal Cockpit (`sb cockpit`):**
  - Vollbild Ratatui Dashboard im Terminal für Entwickler ohne GUI.
  - Tabs für Flotte (Mesh/Node), Ports & Telemetrie, Ephemere CA und Sovereign Mesh.
  - Live-Telemetrie-Abruf mit Taste `t` direkt von `sb-node` über Mesh.

---

### Phase 4: Sovereign Context Hub & Ephemeral Lease Orchestration (Status: 🟢 Erledigt & Produktiv)
- [x] **Sovereign Context Hub (`sb context` / `sb use`):**
  - Blitzschnelles Umschalten zwischen Projekten, Kunden, Umgebungen (`dev`, `staging`, `prod`) und Servern unter 5ms.
  - Persistenter JSON-Store unter `~/.sb/contexts/<name>.json` mit aktivem Zeiger `current`.
  - Löschschutz für den aktuell aktiven Kontext.
- [x] **Ephemeral RAM Lease & Zero-Trace RAM Shredding (`sb lease` / `sb lock`):**
  - Prägung von 8-Stunden ephemeren Schlüsseln im flüchtigen RAM aus `identity.sbkey`.
  - `sb lock` schreddert alle Session-Keys sofort aus dem RAM via `zeroize`.
- [x] **In-Memory Secret Injection Runner (`sb run -- <cmd...>`):**
  - Startet Child-Prozesse mit direkt aus dem verschlüsselten Vault injizierten Umgebungsvariablen.
  - Verhindert das Ablegen unverschlüsselter `.env`-Dateien auf der Festplatte.

---

### Phase 5: Flotten-Observability, Live-Log Streaming & Database Branching (Status: 🟡 In Planung)
- [x] **Flottenweites Live-Log-Streaming (`sb logs <server> [service] -f`):**
  - Streamt Output entfernter Server/Dienste live über den internen P2P Mesh-Kanal ins lokale Terminal.
  - Smart Error Highlighting für Stack Traces, Panics und Exit Codes != 0.
- [x] **Flotten-Telemetrie & Watchdog Alerts (`sb trace` & `sb cockpit`):**
  - Echtzeit-Tracking von CPU, RAM, Uptime und offenen Sockets direkt im Terminal-Cockpit (`sb cockpit`) und via `sb trace [-w]`.
  - Smart Crash Inspector & Alert-Banner im Tab `[5] Logs & Crashes`.
  - `sb-proxy` HTTP Fehlerquoten (2xx/4xx/5xx) und Latenz-Tracking via IPC.
- [ ] **Ephemeral Database Branching (`sb db snapshot|restore`):**
  - Zustandssynchrone Copy-on-Write Snapshots lokaler SQLite/PostgreSQL-Datenbanken gekoppelt an den aktiven `sb context`.

---

### Phase 6: Multi-Mesh Network Management & Context Integration (Status: 🟢 Implementiert)
- [x] **Multi-Mesh Network Management (`sb mesh network`):**
  - Erstellen, Listen und Umschalten benannter Mesh-Overlays (`sb mesh network create|list|current|switch|delete`).
  - Nahtloser Wechsel des aktiven Overlay-Netzwerks synchron zum aktiven Sovereign Context (`sb use <context>`).

---

## 🛠️ CLI Befehls-Referenz (Ziel-Stand)

| Befehl | Beschreibung |
| :--- | :--- |
| `sb` / `sb cockpit` | Startet das zentrale Master-Terminal-Cockpit (Ratatui) |
| `sb status` | Taktisches System-HUD über alle S&B-Komponenten und Daemons |
| `sb context [list\|create\|rm]` | Verwaltet Kunden- und Projekt-Kontexte |
| `sb use <name>` | Schaltet den aktiven Sovereign Context blitzschnell um |
| `sb run -- <cmd...>` | Startet Prozess mit im RAM injizierten Secrets (ohne `.env` auf Disk) |
| `sb lease` / `sb lock` | Verwaltet ephemere 8h-RAM-Leases / Schreddert RAM-Schlüssel sofort |
| `sb doctor` | 360° Integritäts- und Sicherheitsprüfung der gesamten Suite |
| `sb server init <target>` | 1-Klick Server-Bootstrap (CA-Trust, Mesh-Join, Stealth SSH) |
| `sb invite client <name>` | Erzeugt Einladungstoken für neue Team-Entwickler |
| `sb revoke <name>` | Atomarer Hardware- und Zertifikats-Bann eines Entwicklers |
| `sb share <port>` | Teilt lokalen Dev-Server Ende-zu-Ende verschlüsselt via Mesh |
| `sb logs <server> [svc]` | Streamt Live-Logs von Flottenknoten über das Sovereign Mesh |
| `sb trace [server]` | Live-Telemetrie & Watchdog Alerts (CPU, RAM, Sockets, Proxy) |
| `sb db [snapshot\|restore]` | Copy-on-Write Database Snapshots gekoppelt an den Kontext |
| `sb dns [args]` | Delegiert an `sb-dns` (Sovereign Split-DNS & Authority) |
| `sb drive [args]` | Delegiert an `sb-drive` (E2E Encrypted Object Store) |
| `sb auth [args]` | Delegiert an `sb-auth` (Identity & Session Engine) |
| `sb node [args]` | Delegiert an `sb-node` (Sovereign Node Daemon & Ingress) |
| `sb forge [args]` | Delegiert an `sb-forge` (CI/CD Pipeline-Runner & Secret-Engine) |
| `sb mesh [args]` | Delegiert an `sb-mesh` (P2P Sovereign Mesh Overlay) |
| `sb mesh network [args]` | Verwaltet benannte, isolierte Multi-Mesh Netzwerke (VRF) |
| `sb proxy [args]` | Delegiert an `sb-proxy` (Pure-Rust Reverse-Proxy & Edge Gateway) |
| `sb ca [args]` | Delegiert an `sb-proxy ca` (Developer Root-CA & Zero-Warning HTTPS) |
| `sb code [args]` | Delegiert an `sb-code` (Merkle-DAG VCS, AST-Locks & CRDT) |
| `sb key [args]` | Delegiert an `sb-key` (Root-Identität, TPM 2.0 & FIDO2 YubiKey) |
| `sb install [tools]` | Installiert spezifische oder alle S&B Tools modular |
| `sb uninstall <tools>` | Deinstalliert Werkzeuge sauber ohne Datenverlust |
| `sb update` | Aktualisiert installierte Werkzeuge via Release-Ledger |
| `sb identity` | Zeigt oder erzeugt die gemeinsame Root-Identität |
| `sb completions <shell>` | Generiert Shell-Autovervollständigung |
| `sb ports [args]` | *(Historischer Prototyp: Port-Manager & Geisterprozess-Killer)* |
| `sb ssh [args]` | *(Historischer Prototyp: NetGate SSH Gateway)* |
| `sb vault [args]` | *(Historischer Prototyp: Grafisches Desktop-Cockpit)* |



