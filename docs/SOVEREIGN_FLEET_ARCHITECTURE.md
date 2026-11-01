# Skulls & Bones — Sovereign Fleet & Server Architecture
> **Status (2026-10-03):** Historischer Strategieentwurf. Produktnamen, Zero-Trust-/Zero-Cloud-Aussagen, Serverfeatures und externe Marktbehauptungen sind nicht als implementiert oder verifiziert anzusehen. Für bestätigte Produktgrenzen und aktuelle Abweichungen gilt [`ARCHITECTURE.md`](./ARCHITECTURE.md).
> **Wichtige Korrektur:** Das historische `sb-forge env seal`-Verfahren ist inzwischen fail-closed deaktiviert. Die folgenden Deployment-Beispiele sind keine ausführbaren oder sicheren aktuellen Anleitungen.
> **Das Whitepaper zur Flotten-Souveränität: Zero-Trust, AutoSSH über Mesh & Autarke Server-Knoten**  
> *Sicherheitsmarke: Skulls & Bones ([skulls-and-bones.org](https://www.skulls-and-bones.org))*

---

## 1. Strategischer Paradigmenwechsel

Bisher war Skulls & Bones darauf fokussiert, dem einzelnen Entwickler die Souveränität über seine **Workstation** zurückzugeben (historische Tools wie `sb-cli`, `sb-vault`, `sb-ports`). 

In einer echten **Sovereign Infrastructure (Zero Cloud / Self-Hosted)** endet die Kontrolle jedoch nicht am Entwickler-Laptop. Entwickler und Unternehmen betreiben heterogene Serverflotten:
- **Linux-Knoten:** Nginx, Apache, Docker, Microservices, Datenbanken (oft ohne klassisches User-Management).
- **Windows Server:** Active Directory Domain Services (AD DS), File & Print Server, IIS, Windows-Dienste.

Dieser Strategieplan definiert, wie Skulls & Bones das Server- und Flottenmanagement revolutioniert: **Einfachstes 1-Befehl-Bootstrapping, automatische Vernetzung über das Sovereign Mesh ("AutoSSH"), kompromisslose Isolation administrativer Ports und selektive Freigabe öffentlicher Dienste.**

---

## 2. Die fundamentale Marktlücke (Reddit, Hacker News & Praxis-Pain-Points)

Eine eingehende Analyse aktueller Diskussionen auf *Hacker News*, *r/devops*, *r/selfhosted* und *r/sysadmin* (2025/2026) deckt vier gravierende Branchen-Pain-Points auf, die Skulls & Bones adressiert:

### 1. Die Teleport- & Tailscale-Falle
*   **Teleports Lizenz-Bruch:** Teleport galt lange als Goldstandard für auditiertes SSH. Durch die jüngsten Lizenzänderungen und drastische Einschränkungen der Open-Source-Edition wandern Teams frustriert ab. Enterprise-Preise sind für kleinere Teams unbezahlbar.
*   **Tailscales proprietäre Control-Plane:** Tailscale SSH bietet eine hervorragende UX, setzt jedoch zwingend eine proprietäre, zentrale Cloud-Koordinationsstelle voraus. Für regulierte Umgebungen, Air-Gap-Deployments oder echte Cloud-Autarkie ist das ein Ausschlusskriterium.
*   **Die S&B-Antwort:** **Vollkommen dezentrales Mesh (Noise_IK / Pure-Rust WireGuard).** Keine zentrale Koordinations-Cloud. AutoSSH funktioniert direkt Peer-to-Peer, auch in abgeschotteten Netzwerken.

### 2. Das Docker `0.0.0.0` Firewall-Bypass-Desaster
*   Einer der meistdiskutierten Sicherheits-Alpträume auf Reddit: Wenn Entwickler oder Tools Ports via `-p 5432:5432` mappen, bindet Docker standardmäßig an `0.0.0.0` und manipuliert `iptables` im `FORWARD`-Chain.
*   **Das Ergebnis:** Lokale Firewalls wie **UFW werden komplett umgangen**. Der Administrator wiegt sich in Sicherheit ("UFW ist aktiv"), während die Produktionsdatenbank ungeschützt weltweit erreichbar im Internet steht.
*   **Die S&B-Antwort (Historisches Konzept):** Port- und Interface-Überwachung gegen Socket-Leaks (`0.0.0.0` vs. Loopback/Mesh).

### 3. Windows Server als Bürger 2. Klasse im DevOps-Zeitalter
*   DevOps-Tools sind fast ausnahmslos Linux-first. Windows Server (AD, File/Print) werden über veraltete oder unsichere Protokolle (WinRM, offene RDP-Ports) angebunden.
*   **Die S&B-Antwort:** **Erstklassiger Windows-Server-Support.** Nativer Windows-Service, ConPTY-PTY-Integration für PowerShell, automatischer CA-Rollout in den Windows-OpenSSH-Dienst und Schutz vor Windows-spezifischen Socket-Locks (Print Spooler, RPC).

### 4. Gefahr von unüberlegtem "Auto-Kill" auf Produktionsservern
*   Auf dem Entwickler-Laptop ist ein aggressiver `kill-port 3000` praktisch. Auf einem Server führt das unweigerlich zu **Datenverlust, Transaktionsabbrüchen oder Ausfall des Domain Controllers**.
*   **Die S&B-Antwort:** **Strikte Trennung:** Workstation-Modus (Auto-Remediation) vs. Server-Modus (reine Diagnostik, Telemetrie, Alarmierung & geführte manuelle Freigabe).

---

## 3. Die Architektur: `sb-node` & AutoSSH over Mesh

```
                         [ DEVELOPER CLIENT ]
                       sb CLI / sb-auth / sb-node
                                    │
               ┌────────────────────┴────────────────────┐
               │   SOVEREIGN MESH OVERLAY (*.sbm)        │
               │   Ende-zu-Ende verschlüsselt (Noise_IK) │
               │   Zero WAN Ports / NAT Traversal        │
               ▼                                         ▼
   ┌───────────────────────────────┐         ┌───────────────────────────────┐
   │      LINUX SERVER NODE        │         │    WINDOWS SERVER NODE        │
   │      [ sb-node Daemon ]       │         │    [ sb-node Windows Svc ]    │
   ├───────────────────────────────┤         ├───────────────────────────────┤
   │ • OpenSSH CA Trust            │         │ • Win32 OpenSSH CA Trust      │
   │   (/etc/ssh/trusted_user_ca)  │         │   (ProgramData/ssh/sshd_conf) │
   │ • AutoSSH Mesh-Listener       │         │ • AutoSSH Mesh-Listener       │
   │ • Forge Deploy Receiver       │         │ • Forge Deploy Receiver       │
   │ • Non-Destructive PortSentry  │         │ • Non-Destructive PortSentry  │
   │ • Selektiver Ingress (80/443) │         │ • Selektiver Ingress (IIS/AD) │
   └───────────────────────────────┘         └───────────────────────────────┘
```

---

## 4. Die 5 Säulen der Flotten-Souveränität

### Säule 1: AutoSSH über das Sovereign Mesh (Zero WAN Port 22)
1. **Kein Port 22 im offenen Internet:** Port 22 wird durch die Firewall für das WAN gesperrt. Der SSH-Transport lauscht entweder nur intern oder wird direkt über den asynchronen P2P-WireGuard-Kanal von `sb-mesh` abgewickelt.
2. **Dynamische Flottenerkennung:** Sobald ein Node das Mesh betritt, registriert er seinen kryptographischen Fingerprint und Hostnamen (`web01.sbm`, `dc01.sbm`).
3. **Client-Erlebnis in `sb-vault` & `sb-ssh`:**
   - In `sb-vault` tauchen neue Server **sofort automatisch im NetGate Hub** auf.
   - Kein manuelles Eintragen von Hostnamen, dynamischen IP-Adressen oder Port-Weiterleitungen in `servers.toml`.
   - 1-Klick Terminal, SFTP-Browser und Latenz-Ping über den Mesh-Tunnel.

### Säule 2: 1-Befehl Server Bootstrap (`sb server init` / `sb server provision`)
Die Einrichtung eines neuen Servers erfolgt wahlweise vom Client aus oder per 1-Zeiler auf dem Server:

```bash
# Vom Entwickler-Client aus (vollautomatisch über Initial-SSH / temporäres VPS-Passwort):
sb server init root@188.40.0.1 --name web01

# Oder direkt auf der Server-Konsole via One-Time-Token:
sb-node init --token sbm-pair://...
```

**Was der Provisioner in unter 30 Sekunden automatisiert:**
1. Erkennt das Betriebssystem (Debian, Ubuntu, RHEL, Alpine oder Windows Server 2019/2022/2025).
2. Tauscht Mesh-Schlüssel aus und bindet Server und Client in denselben privaten Swarm ein (`web01.sbm`).
3. Verankert den Root-CA-Schlüssel von `sb-ssh` in OpenSSH (`TrustedUserCAKeys`).
4. Richtet `sb-node` als Hintergrunddienst ein (`systemd` unter Linux, `Windows Service` unter Windows).
5. Härtet die Server-Firewall: Port 22 wird für das offene Internet geschlossen; Administration, SCP und Deployments laufen ab Sekunde 31 ausschließlich durch das verschlüsselte Mesh.

---

### Säule 2.1: Team-Onboarding & Atomarer Hardware-Rauswurf (`sb invite` & `sb revoke`)

#### 1. Team-Mitglieder einladen (`sb invite client <name>`):
- Der Admin (oder ein autorisierter Server) generiert einen zeitlich befristeten Pairing-Token (TTL 10 min):
  ```bash
  sb invite client bob --role dev
  ```
- Entwickler Bob tippt auf seinem Rechner:
  ```bash
  sb join sbm-pair://...
  ```
- **Kryptographischer Handshake:** Bobs Node-ID wird im Mesh autorisiert und seine Identität über die Swarm-CA signiert. Alle Server im Mesh synchronisieren die Berechtigung in unter einer Sekunde via P2P-Gossip. Bob kann sofort `sb ssh web01.sbm` ausführen.

#### 2. Atomare Hardware- & User-Revocation (`sb revoke <name>`):
Scheidet ein Entwickler aus oder geht ein Laptop verloren, genügt ein einziger Befehl:
```bash
sb revoke bob
```
**Was in Millisekunden über das dezentrale Mesh-Gossip (`GossipKind::RevokeNode`) durchgesetzt wird:**
1. **Hardware-Ebene (Mesh-Bann):**
   - Bobs Hardware Node-ID (`sbm-<node_id>`) und X25519-Schlüssel werden auf die globale Mesh-Sperrliste (CRL) gesetzt.
   - Alle aktiven WireGuard/Noise-Tunnel zu Bobs Hardware werden sofort abgerissen.
   - Sämtliche Pakete von Bobs IP/Socket werden von allen Flottenknoten auf Netzwerk-Ebene lautlos verworfen (`Drop`).
2. **Identitäts- & Zertifikats-Ebene:**
   - Bobs OpenSSH-Zertifikate werden auf allen Servern in die OpenSSH-KRL (`RevokedKeys` / `revoked_keys`) eingetragen und sofort invalidiert.
3. **Laufende Sitzungen terminieren:**
   - Alle aktiven SSH-Shells, Port-Tunnels oder Log-Streams von Bob werden sofort hart gekillt.
4. **Kein Server-Hopping nötig:** Der Admin muss keinen einzigen Server manuell anfassen; der Rauswurf repliziert sich epidemisch über das P2P-Mesh.


### Säule 3: Non-Destructive PortSentry & Anti-Leak Auditor *(Historischer Entwurf / Port-Diagnostik)*
Der ursprüngliche `sb-ports`-Entwurf sah einen dezidierten **Server-Modus (`--server / --no-kill`)** vor:
- **Absoluter Kill-Schutz:** Auf Servern werden niemals Prozesse automatisch beendet.
- **0.0.0.0 Leak-Detektor:** Scannt alle offenen Sockets und prüft, ob sensible Dienste (PostgreSQL, Redis, MySQL, Active Directory LDAP/SMB, interne APIs) fälschlicherweise auf `0.0.0.0` gebunden sind statt auf `127.0.0.1` oder die Mesh-IP.
- **Docker-Firewall-Audit:** Erkennt, wenn Docker-Container UFW- oder nftables-Regeln umgangen haben.
- **Health-Telemetry:** Meldet Port-Statistiken, Socket-Auslastung und Response-Zeiten an die Node-Diagnostik (`sb status` & `sb-node`). *(Hinweis: `sb-ports` und `sb-vault` wurden als eigenständige Binaries extrahiert/konsolidiert).*

### Säule 4: Selektives Port-Exposing (Sovereign Ingress Gates)
Server müssen häufig dedizierte Dienste für Endnutzer bereitstellen (Webserver, APIs, Mail), ohne die Integrität des Management-Netzwerks zu gefährden:

1. **Strikte Interface-Trennung:**
   - **Management-Plane:** Vollständig im Mesh verborgen (`*.sbm`). Kein WAN-Zugriff.
   - **Public-Service-Plane:** Ausschließlich explizit freigegebene Ports (z. B. 80, 443) binden an das WAN.
2. **`sb expose <port>` / Sovereign Reverse-Proxy:**
   - Ermöglicht das kontrollierte Durchleiten eines internen Dienstes nach außen (z. B. über einen dedizierten DMZ- oder Exit-Knoten).
   - Unterstützt **Capability-Tokens (Schnorr-basierte ZK-ACLs)**: Nur Clients mit gültigem kryptographischem Token erhalten Zugriff auf den exponierten Port.
   - Ideal für Staging-Previews, Kunden-Abnahmen oder Partner-Schnittstellen ohne permanentes Loch in der Firewall.

### Säule 5: Sovereign CD — Deploy Receiver über das Mesh (`sb-forge`)
Eliminiert die Abhängigkeit von zentralen CI-Runnern oder offenen Webhook-Ports:
1. Der frühere Entwurf ließ `sb-forge run deploy --server web01.sbm` Artefakte bauen und Secrets als `env.sealed` übertragen. Dieser Seal-/Deployment-Pfad ist nicht als aktueller oder sicherer Ablauf zu verwenden.
2. Das Paket wird Ende-zu-Ende verschlüsselt über das Mesh direkt an den `sb-node` Empfänger gestreamt.
3. Der Server-Agent überprüft die Signatur, entpackt Konfigurationen flüchtig im RAM und orchestriert den unterbrechungsfreien Neustart:
   - **Linux:** `systemctl reload nginx` oder containerless Blue/Green Switch.
   - **Windows Server:** Dienst-Update via Windows Service Manager oder PowerShell Scripting.
4. Vollständiges Audit-Log wird revisionssicher (BSI IT-Grundschutz) lokal und auf dem Client archiviert.

---

## 5. User Journey: Von 0 auf Sovereign Fleet in 2 Minuten

```
[ Tag 1: Frischer Hetzner-Server oder Windows-VPS ]
1. Entwickler tippt auf Laptop:
   $ sb server provision root@188.40.0.1 --name prod-api

2. Skulls & Bones erledigt automatisch:
   ► System analysiert: Ubuntu 24.04 LTS (x86_64)
   ► OpenSSH CA Trust verankert: TrustedUserCAKeys aktiviert
   ► Mesh-Node generiert: prod-api.sbm (Ed25519)
   ► Firewall gehärtet: Port 22 für WAN geschlossen, SSH nur via Mesh
   ► sb-node systemd Daemon aktiv (Deploy-Receiver + PortSentry)

3. Entwickler öffnet sb-vault auf seinem Desktop:
   ► "prod-api.sbm" erscheint sofort grün im NetGate Hub
   ► Live-Latenz: 14ms
   ► 1-Klick SSH, SFTP und Log-Streaming sofort einsatzbereit!
```

---

## 6. Roadmap-Integration

| Phase / Meilenstein | Komponente | Beschreibung |
|---|---|---|
| **Phase S.1** | `sb-node` Core & Daemon | Schlankes Server-Binary für Linux (systemd) & Windows Server (Service) |
| **Phase S.2** | AutoSSH over Mesh | Automatische Peer-Erkennung in `sb-ssh` & `sb-vault` ohne statische IPs |
| **Phase S.3** | `sb server provision` | 1-Klick Provisioner für frische Server (CA-Verankerung & Mesh-Join) |
| **Phase S.4** | PortSentry Server Guard | Non-destructive Port-Monitor mit 0.0.0.0-Leak- und Docker-Bypass-Warnung |
| **Phase S.5** | Sovereign Ingress & Expose | Kontrolliertes Port-Exposing mit Capability-Tokens über DMZ/Relay |
| **Phase S.6** | Forge Mesh Deploy Receiver | P2P-Deployment-Receiver ohne Webhooks und ohne externe CI-Server |

---

> *"Souveränität bedeutet nicht, keine Server zu betreiben – sondern die vollständige Kontrolle über jeden einzelnen Knoten zu besitzen."*  
> — Skulls & Bones Lab
