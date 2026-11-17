# Skulls & Bones Sovereign Suite // Integrations- & Synergie-Karte
> **Dokument-ID:** `SBM-DOC-2026-INTMAP`  
> **Status:** Historischer Integrationsentwurf & Konzeptpapier  
> **Architekturhinweis:** Dieses Dokument ist ein historischer Entwurf und beschreibt teils Komponenten, die im Zuge der 14-Core-Konsolidierung ausgegliedert wurden (`sb-ports`, `sb-ssh`, `sb-vault`, `sb-shell`, `sb-securenet`). Das autoritative Produktinventar und die verbindliche Zielarchitektur sind in [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) und `product-inventory.json` dokumentiert.

---

## 1. Executive Summary & Ökosystem-Philosophie

Die **Skulls & Bones Sovereign Suite** verfolgt ein radikales Architekturprinzip:  
**Autarkie, minimale Angriffsfläche, Null Cloud-Abhängigkeiten und maximale Developer Experience (DX).**

Anstatt isolierte Einzellösungen zusammenzuschustern, greifen die Module der Sovereign Suite ineinander. Jedes Tool erfüllt eine dedizierte Aufgabe, teilt jedoch Identitäten, Mesh-Transport und kryptographische Vertrauensanker.

---

## 2. Die 14 konsolidierten Kern-Tools im Überblick

| Werkzeug | Crate | Primäre Rolle | Art |
|---|---|---|---|
| **`sb`** | `sb-cli` | Master CLI, Launcher, Flotten-Bootstrap, Paketverwaltung | CLI Tool |
| **`sb-core`** | `sb-core` | Gemeinsame Bibliothek, Domain-Typen, DTOs, Vault | Library |
| **`sb-app-contract`** | `sb-app-contract` | SB-MAP Manifest-Verifikation & Operations Grants | Library |
| **`sb-app-protocol`** | `sb-app-protocol` | SB-MAP Protokoll-Framing & Objekt-Transfer | Library |
| **`sb-auth`** | `sb-auth` | Sovereign Authentication Kit, Ed25519-Tokens, Argon2id | CLI Tool |
| **`sb-code`** | `sb-code` | AST-Scoped Code Engine, VCS & Merkle DAG | CLI Tool |
| **`sb-db`** | `sb-db` | Embedded Document-KV Store mit MVCC | CLI Tool |
| **`sb-dns`** | `sb-dns` | Sovereign DNS-Resolver & Mesh-Router | CLI Tool |
| **`sb-drive`** | `sb-drive` | Peer-Filesystem & Mesh Storage | CLI Tool |
| **`sb-forge`** | `sb-forge` | CI/CD-Pipeline-Runner & Secret-Engine | CLI Tool |
| **`sb-key`** | `sb-key` | Sovereign Root Identity & Ephemeral Leases | CLI Tool |
| **`sb-mesh`** | `sb-mesh` | P2P-Overlay-Netzwerk & Mesh-Management | CLI Tool |
| **`sb-node`** | `sb-node` | Headless Mesh-Anchor, Katalog-DC & Server-Daemon | CLI Tool |
| **`sb-proxy`** | `sb-proxy` | Reverse Proxy, Auto-TLS & Edge Gateway | CLI Tool |

*Historische / ausgegliederte Komponenten in diesem Dokument:*  
`sb-ports`, `sb-ssh`, `sb-vault`, `sb-shell`, `sb-securenet` wurden aus der Core-Suite ausgegliedert. Die nachfolgenden Abschnitte dokumentieren historische Synergiekonzepte.

---

## 3. Bestehende Inter-Tool-Verbindungen (Status Quo)

### A. Team Onboarding & 4-Augen-Prinzip (`sb` ↔ `sb-mesh`)
1. **Initiierung:** `sb invite client <name>` generiert ein Base64-geschütztes Pairing-Token (`sbm-pair://...`).
2. **Konsens:** Bei $\ge 2$ Team-Mitgliedern aktiviert `sb` das 4-Augen-Prinzip (`compute_required_quorum`). 
3. **Gossip-Propagation:** In `sb-mesh` verarbeitet die `GossipEngine` `GossipKind::JoinRequest` und `GossipKind::JoinApproval`. Erst wenn das Quorum erreicht ist (`is_join_approved`), schaltet das Overlay den Knoten frei.

### B. AutoSSH over Mesh & Namensauflösung (`sb-ssh` ↔ `sb-mesh` ↔ `sb-node`)
1. **Target-Resolution:** Entwickler ruft `sb ssh hostinger-prod.sbm` auf.
2. **Mesh Resolver:** `sb-ssh/src/mesh_resolver.rs` prüft:
   - Ist `hostinger-prod.sbm` über den lokalen `sb-mesh` IPC Socket erreichbar?
   - Fallback: Lese Vault (`~/.sb-ssh/servers.toml`) und matche bidirektional (mit oder ohne `.sbm`).
3. **Stealth Connect:** Auf dem Zielserver lauscht `sb-node` auf Loopback `127.0.0.1:58822`. Port 22 ist im Internet blockiert – der Verbindungsaufbau erfolgt durch das Mesh direkt in den lokalen SSH-Daemon.

### C. Atomarer Rauswurf (`sb` ↔ `sb-mesh` ↔ `sb-node`)
1. **Hardware-Ebene:** `sb revoke <name>` setzt die Node-ID und X25519-Keys auf die dezentrale Mesh-Bannliste (CRL). Alle aktiven Tunnel brechen sofort ab.
2. **Identitäts-Ebene:** `sb` weist `sb-node` via SSH an: `sudo sb-node revoke <name>`.
3. **Härtung:** `sb-node` schreibt `DenyUsers <name>` in `/etc/ssh/sshd_config.d/99-sbm.conf` und reloaded `sshd` nach erfolgreichem `sshd -t` Pre-Flight Check.

### D. Zero-Touch Server-Bootstrap (`sb` ↔ `sb-ssh` ↔ `sb-node`)
1. **Initial-Handshake:** `sb server init <target>` nutzt den nativen Passwort-Prompt in `sb-ssh` (oder `--password`).
2. **Bereinigung:** Stale Einträge in `~/.ssh/known_hosts` werden automatisch gepruned.
3. **Automatisierte Übergabe:** Das System richtet den Entwickler-User ein, setzt `99-sbm.conf` (überschreibt alle Cloud-Init-Dateien), verankert die Swarm-CA, deaktiviert Passwörter und startet `sb-node.service`.

---

## 4. Neue Potenziale & Ungehobene Synergien

Aus der engen Verzahnung der Module ergeben sich **sechs disruptive neue Möglichkeiten**, die herkömmliche DevOps- und VPN-Tools nicht bieten können:

### 🚀 Potenzial 1: Dezentrales AONT-Secret-Sharding über das Mesh (`sb-forge` + `sb-mesh`)
* **Das Konzept:** 
  Anstatt sensible Produktions-Geheimnisse (API-Keys, Datenbank-Passwörter, Root-CAs) in einem zentralen HashiCorp Vault oder Cloud KMS zu speichern, zerlegt `sb-forge` das Secret mittels **AONT (All-or-Nothing Transform)** und **Shamir's Secret Sharing ($k$-aus-$n$)** in Shards.
* **Die Synergie:**
  `sb-mesh` verteilt diese Shards verschlüsselt an die aktiven Swarm-Knoten (z. B. 2 Shards auf `hostinger-prod`, 1 Shard auf Bob, 1 Shard auf Alice).
* **Der Clou:**
  Ein Secret kann nur entschlüsselt werden, wenn z. B. mindestens 2 von 3 autorisierten Knoten im Mesh online sind und ihre ZK-Hardware-Attestierung vorweisen. Fällt ein Server in feindliche Hände, besitzt der Angreifer nur einen mathematisch nutzlosen Shard.

---

### 🚀 Potenzial 2: Ephemeres Entwickler-Ingress ("Instant Dev Share") (`sb-ports` + `sb-mesh`)
* **Das Konzept:** 
  Entwickler starten lokal oft Services (Next.js auf `localhost:3000`, API auf `localhost:8080`). Um diese einem Kollegen oder Kunden zu zeigen, nutzt man bisher Drittanbieter wie ngrok.
* **Die Synergie:** 
  `sb-ports` erkennt den offenen Port `3000` und bietet mit einem Klick an:
  ```bash
  sb share 3000 --as preview-app
  ```
* **Der Clou:** 
  `sb-mesh` mappt `preview-app.sbm` sofort swarm-weit. Jedes Teammitglied im Mesh (und optional per Reverse-Proxy auf `hostinger-prod.sbm/preview`) kann die lokale Entwickler-Instanz latenzarm und Ende-zu-Ende verschlüsselt ansteuern – **ohne Portfreigaben am Heim-Router, ohne Drittanbieter-Tools**.

---

### 🚀 Potenzial 1: Dezentrales AONT-Secret-Sharding über das Mesh (`sb-forge` + `sb-mesh`) — [BESTÄTIGT & ROADMAPPED]
* **Das Konzept:** 
  Anstatt sensible Produktions-Geheimnisse (API-Keys, Datenbank-Passwörter, Root-CAs) in einem zentralen HashiCorp Vault oder Cloud KMS zu speichern, zerlegt `sb-forge` das Secret mittels **AONT (All-or-Nothing Transform)** und **Shamir's Secret Sharing ($k$-aus-$n$)** in Shards.
* **Die Synergie:**
  `sb-mesh` verteilt diese Shards verschlüsselt an die aktiven Swarm-Knoten (z. B. 2 Shards auf `hostinger-prod`, 1 Shard auf Bob, 1 Shard auf Alice).
* **Der Clou bei Revocation (Proactive Secret Sharing):**
  Wird ein Node (z.B. Bob) aus dem Swarm ausgeschlossen, wechseln die verbleibenden Nodes im endlichen Galois-Feld $GF(p)$ dezentral auf ein neues Polynom mittels Null-Polynomen ($g(0) = 0$). Das Secret bleibt im Speicher intakt, während Bobs alter Shard mathematisch sofort wertlos wird ($1 / 2^{256}$ Entropie).

---

### 🚀 Potenzial 2: Ephemeres Entwickler-Ingress ("Instant Dev Share") (`sb-ports` + `sb-mesh`) — [PRIORITÄT 1]
* **Das Konzept:** 
  Entwickler starten lokal oft Services (Next.js auf `localhost:3000`, API auf `localhost:8080`). Um diese einem Kollegen oder Kunden zu zeigen, nutzt man bisher Drittanbieter wie ngrok.
* **Die Synergie:** 
  `sb-ports` erkennt den offenen Port `3000` und bietet mit einem Klick an:
  ```bash
  sb share 3000 --as preview-app
  ```
* **Der Clou:** 
  `sb-mesh` mappt `preview-app.<node-id>.sbm` sofort swarm-weit. Jedes Teammitglied im Mesh kann die lokale Entwickler-Instanz latenzarm und Ende-zu-Ende verschlüsselt ansteuern – **ohne Portfreigaben am Heim-Router, ohne Drittanbieter-Tools**.

---

### 🚀 Potenzial 3: Flotten-Cockpit: `sb-vault TUI` & Telemetrie-Stream (`sb-node` + `sb-vault` TUI) — [PRIORITÄT 2]
* **Das Konzept:** 
  Server-Status, Flotten-Health und Socket-Audits sollen direkt in der Entwickler-Konsole über ein interaktives TUI-Cockpit bedienbar sein – ganz ohne schwere Desktop-GUI oder Browser.
* **Die Synergie:** 
  `sb-node` publiziert Telemetrie-Events (CPU-Load, RAM-Nutzung, neu geöffnete Sockets, Watchdog-Alarme) über ein abgesichertes Mesh-Gossip-Topic (`topic: fleet-telemetry`).
* **Der Clou:** 
  Die interaktive **`sb-vault TUI`** (Ratatui / Crossterm) empfängt diesen Stream live. Entwickler sehen in Echtzeit, wenn auf einem Flottenserver ein ungeschützter Port geöffnet wird oder Ressourcen knapp werden.

---

### ⏸️ Potenzial 4: Zero-Knowledge Hardware Passports (`sb-mesh` ZK + `sb` Quorum) — [ZURÜCKGESTELLT]
* **Status:** Zurückgestellt auf die ferne Zukunft. Das softwarebasierte 4-Augen-Quorum via Node-Identitäten reicht für das aktuelle Bedrohungsmodell vollkommen aus.

---

### ❌ Potenzial 5: Git-over-Mesh mit Zero-Trust CA — [VERWORFEN]
* **Status:** Verworfen. Standardmäßiges Git über HTTPS/SSH mit regulären Git-Remotes deckt Entwickler-Workflows bereits gut ab; der zusätzliche Mesh-Layer bietet hier keinen entscheidenden Mehrwert.

---

### ❌ Potenzial 6: Binär-Distribution im Swarm — [VERWORFEN]
* **Status:** Verworfen. Die Verteilung von Binaries und Werkzeugen erfolgt standardkonform und reproduzierbar über `cargo install` und [crates.io](https://crates.io).

---

## 5. Konkrete Roadmap & Nächste Implementierungs-Schritte

```
  [PHASE 1] ✅ BEREITS ERREICHT
  ├── sb-ssh v0.1.1 (AutoSSH, *.sbm Resolution, Nativer Passwort-Prompt)
  ├── sb-node v0.1.0 (Live auf Hostinger, Stealth-SSH, 99-sbm.conf Härtung, DenyUsers Eviction)
  ├── 4-Augen-Prinzip (sb invite client, sb approve, sb join)
  └── Zero-Touch 1-Befehl Bootstrap (sb server init)

  [PHASE 2] 🎯 IMPLEMENTIERUNG (Fokussiert)
  ├── 1. "sb share <port>" Ingress-Tunneling (sb-ports ↔ sb-mesh)
  │      Automatische Service-Erkennung via sb-ports, Mesh P2P Ingress & sbm-pair URL.
  │
  ├── 2. sb-node Echtzeit-Telemetrie Stream
  │      CPU/RAM/Socket-Watchdog Metriken via Mesh Gossip Topic streamen.
  │
  ├── 3. sb-vault TUI (Terminal Cockpit)
  │      Interaktives Ratatui-Cockpit für Server, Keys, Zertifikate & Live-Telemetrie.
  │
  └── 4. AONT Secret Distribution mit Proactive Resharing (sb-forge ↔ sb-mesh)
         Zero-Knowledge Resharing via Null-Polynome bei Member-Revocation.
```

---

## 6. Fazit

Die Werkzeuge der Skulls & Bones Suite sind keine isolierten CLI-Tools mehr, sondern formen ein **zusammenhängendes, souveränes Ökosystem für dezentrale Entwicklerteams**:
- **`sb`** ist der Launcher und Orchestrator.
- **`sb-mesh`** ist das P2P-Overlay-Netzwerk.
- **`sb-core` & `sb-app-*`** bilden das vertragliche Fundament.
- **`sb-node` & `sb-proxy`** sichern Server, Edge und Ingress ab.
- **`sb-forge`, `sb-auth` & `sb-key`** schützen Identitäten, Secrets und Build-Pipelines.
- **`sb-code`, `sb-db`, `sb-dns` & `sb-drive`** stellen dezentrale Daten-, Code- und Storage-Dienste bereit.
