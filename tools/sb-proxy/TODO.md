# `sb-proxy` — Roadmap & Entwicklungsplan (TODO.md)

> **Sovereign Pure-Rust Reverse Proxy & Edge Gateway**  
> *Kein NGINX-Config-Albtraum. Kein Certbot-Chaos. 100% Airgap-Schutz für das Sovereign Mesh.*

---

## 🎯 Vision & Design-Prinzipien
1. **Zero-Config Developer First**: Keine kryptischen Konfigurationssprachen, keine Trailing-Slash-Fallen.
2. **Airgap-Sicherheit & Anti-Leak**: Leitet ausschließlich an `127.0.0.1:<target_port>` weiter. Interne Mesh-Ports (22, 53, 58888, 4001, 8008, 9090) sind unüberwindbar gesperrt.
3. **Automatisches Pure-Rust ACME**: Zero-Maintenance Let's Encrypt TLS im flüchtigen RAM mit Preflight-DNS-Schutz gegen Rate-Limits.
4. **Interaktives Ratatui Terminal-Cockpit**: TUI-Dashboard mit Status-Ampel, Latenz und 1-Key-Actions (Instant Killswitch, DNS-Check).
5. **Persistente Routenkonfiguration**: Teilt denselben persistenten State (`EscapeSpaceStore` in `~/.sb/escape_spaces.json`) für CLI, Daemons und externe Frontends.

---

## 📌 Milestones

### Milestone 1: Grundarchitektur & CLI Core (✅ Abgeschlossen)
- [x] Initialisierung von `tools/sb-proxy/Cargo.toml` mit Tokio, Clap und Ratatui.
- [x] Integration mit `sb-code::escape` (Sovereign Airgap, `PROTECTED_PORTS`, FQDN-Validierung).
- [x] Implementierung der CLI-Befehle:
  - `sb-proxy list`: Tabellarische Übersicht aller aktiven/pausierten Domains und deren Loopback-Ziele.
  - `sb-proxy add <domain> <target_port> [--node <callsign>]`: Legt eine neue Route an mit sofortiger Port-Prüfung.
  - `sb-proxy remove <id|domain>`: Entfernt eine Domain.
  - `sb-proxy pause <id|domain>` / `resume <id|domain>`: Instant Killswitch (503 Service Unavailable).
  - `sb-proxy check <domain>`: Löst DNS auf und prüft Zuordnung zur Node-Server-IP (`<node_ip>`).
  - `sb-proxy tui`: Interaktives Ratatui Terminal-Cockpit mit 1-Key-Actions (`[Space]`, `[D]`, `[Q]`).
- [x] Integration in die Master-CLI `sb`: `sb proxy [args]` delegiert transparent an `sb-proxy`.

---

### Milestone 2: Developer-Experience & Smart Ingress (✅ Abgeschlossen)
- [x] **Auto-Discovery von lokalen Diensten**:
  - Automatisches Scannen aktiver TCP-Sockets auf `127.0.0.1` (z. B. Ports 3000, 5173, 8080, 8000).
  - Wenn `sb proxy add <domain>` ohne Port aufgerufen wird: Interaktive Auswahlliste gefundener Server.
- [x] **Ephemeral Preview-Subdomains**:
  - `sb proxy preview <domain> <port> [--ttl <hours>]`: Erzeugt temporäre Test-Routen mit automatischer Ablaufzeit (`expires_at`).
  - Automatisches Ausblenden / Bereinigen abgelaufener Preview-Domains mit HTTP 410 Gone.
- [x] **Instant Maintenance Mode**:
  - `sb proxy maintenance <domain> [--msg <text>] [--disable]`: Schaltet eine Domain sofort in den Wartungsmodus.
  - Liefert stylische HTML-Wartungsseite mit HTTP 503 und SEO-freundlichem `Retry-After: 300` Header aus.
- [x] **Canonical Domain & `www.` Normalizer**:
  - Unterstützung für `--alias <domain>` (z. B. `meinedomain.de` mit Alias `www.meinedomain.de`).
  - Automatischer 301 Permanent Redirect auf die kanonische Hauptdomain.

---

### Milestone 3: Asynchrone Tokio Streaming Engine
- [x] Asynchroner HTTP/1.1 TCP-Forwarder mit `tokio::io::copy_bidirectional`.
- [x] Host-Header Router: Parsen von `Host:` und Zuordnung zur registrierten `127.0.0.1:<target_port>` Route.
- [x] Automatische Header-Anreicherung:
  - `X-Forwarded-For`: Echte Client-IP.
  - `X-Forwarded-Proto`: `http` bzw. `https`.
  - `X-Real-IP`: Client-IP.
- [x] Zero-Config WebSocket Pass-Through (bidirektionaler Byte-Stream ohne manuelle NGINX-Direktiven).
- [x] Kein 1MB-Upload-Cap: Streaming-Transfer von File-Uploads ohne Puffer-Blockade.

---

### Milestone 4: TLS/ACME & Dual-Port Gateway (⚠️ Implementiert; Live-Betrieb offen)
- [x] Manueller In-Memory HTTP-01 Challenge-Store auf Port 80.
- [x] Automatischer 301 Redirect von Port 80 auf HTTPS; HSTS wird nur auf TLS-Antworten gesetzt.
- [x] DNS-Prüfung bleibt ein Diagnose-Helfer; sie wird nicht als ACME-Ausstellungsnachweis oder Garantie gegen Rate-Limits behandelt.
- [x] Echtes Let's-Encrypt-ACME über TLS-ALPN-01 mit persistiertem Account-/Zertifikats-Cache (`~/.sb/acme`); Staging ist Standard, Erneuerung wird vom ACME-TLS-Resolver durchgeführt.
- [ ] Öffentliche Staging-Ausstellung und anschließende Produktionserneuerung auf einem erreichbaren Host nachweisen. Port 443 und DNS müssen stimmen; neue TLS-Domains benötigen derzeit einen Gateway-Neustart.
- [x] Optionale Unterstützung für eigene Zertifikate (`--cert <file> --key <file>` & `sb proxy certs import`).
- [x] CLI-Subcommand `sb proxy certs [list|import]` zur Verwaltung und Einsicht; ACME-Erneuerung läuft ausschließlich durch den echten Resolver im gestarteten Gateway.

---

### Milestone 5: Schutz & Traffic-Steuerung (✅ Abgeschlossen)
- [x] Token-Bucket Rate-Limiter pro Client-IP (DDoS-Dämpfung mit `IpRateLimiter` & 429 Too Many Requests).
- [x] Slowloris & Request-Timeout Schutz (10s Socket-Timeout gegen blockierende Angriffe).
- [x] "Graceful Deploying"-Fallback-Seite: Liefert eine schicke Statusseite mit Auto-Polling & Meta-Refresh statt hässlichem `502 Bad Gateway`, wenn ein lokaler Dienst für wenige Sekunden neu startet.
- [x] Blue-Green Port Switching (`sb proxy switch <domain> <new_port>` mit sofortiger Validierung).

---

### Milestone 6: Externe Client-Synchronisation *(Historischer Entwurf / Externe Satelliten-UI)*
- [x] IPC Event-Broadcasting zwischen `sb-proxy` Daemon und Client-Schnittstellen (`127.0.0.1:58900`).
- [x] Status-Synchronisation für externe Cockpits (wie den ausgelagerten Satelliten `sb-studio`):
  - Live Telemetry Status-Bar mit Daemon-Status (Online/Offline Badge), PID, Uptime, Total Requests und Rate-Limited Requests.
  - Wartungsmodus-Toggle für jeden konfigurierten Escape Space.
  - Zero-Downtime Blue-Green Port-Switcher Modal mit Validierung gegen geschützte Mesh-/System-Ports.
  *(Hinweis: `sb-studio` und sein Tauri-Backend wurden im Rahmen von Milestone M3 als externes Satelliten-Projekt ausgelagert).*

---

### Milestone 7: Developer CA (`sb ca` / `sb proxy ca`) — Pure-Rust Local Root-CA & Zero-Warning HTTPS (✅ Abgeschlossen)
- [x] Pure-Rust X.509 v3 Engine (`rcgen`) mit ECDSA P-256 / SHA-256 ohne OpenSSL-Abhängigkeiten.
- [x] Sovereign Developer Root-CA Generator (`sb ca init` / `sb proxy ca init`):
  - Erstellt 10 Jahre gültige Root-CA unter `~/.sb/ca/root_ca.crt` und `root_ca.key`.
  - Korrekte X.509 Basic Constraints (`CA:TRUE`), `keyCertSign` und `cRLSign`.
- [x] Sichere OS-Trust-Store Integration (`sb ca install` & `sb ca uninstall`):
  - Auf Windows: Registrierung im **CurrentUser** Zertifikatsmagazin (`Cert:\CurrentUser\Root`) via `certutil` ohne Admin-Rechte.
  - Auf macOS: Integration in `login.keychain` via `security`.
  - Auf Linux: `trust anchor` / `/usr/local/share/ca-certificates/`.
- [x] Entwickler-Zertifikats-Ausstellung (`sb ca issue <domains...>`):
  - Multi-SAN Unterstützung für Domain-Namen (`localhost`, `app.local`, `*.test`) und IP-Adressen (`127.0.0.1`, `::1`).
  - Automatische Speicherung von Fullchain-Zertifikaten (`<domain>.crt`) und Schlüsseln (`<domain>.key`) unter `~/.sb/ca/certs/`.
  - JSON-basierte Indexierung in `~/.sb/ca/index.json`.
- [x] Diagnose & Übersicht (`sb ca status` & `sb ca list`):
  - Zeigt den Initialisierungszustand, OS-Trust-Store Status und alle aktiven Dev-Zertifikate tabellarisch an.
- [x] Automatische Zertifikatsauflösung in `sb-proxy`:
  - `ProxyConfig::find_certificate` und `list_certificates` erkennen Developer CA Zertifikate automatisch für lokale Domains.
- [x] Top-Level Master CLI Shortcut in `sb`:
  - Direkter Zugriff via `sb ca ...` delegiert transparent an `sb-proxy ca ...`.

---

### Milestone 8: Option A — Sovereign Tunnel (Cloudflare Tunnel & ngrok Killer) (✅ Abgeschlossen)
- [x] **Pure-Rust Zero-Cloud Ingress Tunnel Relay (`tools/sb-proxy/src/tunnel.rs`)**:
  - `SovereignTunnelHub`: Asynchroner Multiplexing-Server gebunden an Port `58910`.
  - Rechner hinter beliebigem NAT/Firewall registrieren sich ausgehend (`REGISTER\t<domain>\t<callsign>`).
  - On-Demand Datenstream-Kopplung via UUIDs (`OPEN_STREAM` / `ATTACH_STREAM`) und `tokio::io::copy_bidirectional`.
- [x] **Anti-Leak Portschutz & Escape Space Integration (`tools/sb-code/src/escape.rs`)**:
  - `SovereignTunnelClient`: Verbindet sich ausgehend zum Hub und leitet Anfragen an `127.0.0.1:<target_port>` weiter.
  - Strikte Schutzliste `PROTECTED_PORTS` (22, 53, 58888, 4001, 8008, 9090).
  - Unterstützung für HTTP/1.1, HTTP/2 und WebSockets (Next.js/Vite HMR).
  - Automatischer 503 Auto-Reload Fallback bei inaktivem Tunnel-Client.
- [x] **CLI & Client-Integration (`sb escape`)**:
  - Master CLI: `sb escape share <port> --as <domain>`, `sb escape list`, `sb escape tunnel <space> --enable`.
  - Externe Clients (Satellit `sb-studio`): Live-Status-Badge, Start/Stop und Tunnel-Modal im Mesh Cockpit via IPC.

---

### Milestone 9: HTTP-Stack und statischer Edge-Host (⚠️ Implementiert; Live-Betrieb offen)
- [x] Hyper-Server für HTTP/1.1-Keep-Alive und HTTP/2; Header-Timeout gegen langsame/invollständige HTTP/1-Header.
- [x] Statische Antworten und Upstream-Requests mit Streaming; MIME-Type-Erkennung über `mime_guess`.
- [x] Konfigurierbare HSTS-/CSP-/`X-Content-Type-Options`-Header; HSTS ausschließlich auf TLS-Verbindungen.
- [x] ETag-Generierung (`size-mtime`) und bedingte `304 Not Modified`-Antworten für `If-None-Match`.
- [x] SPA-Fallback (Single-Page-Application) für statische HTML-Routen via `resolve_file_with_options` / `SB_PROXY_SPA`.
- [x] On-the-Fly Gzip-Kompression (`flate2`) für komprimierbare Text-, JS-, CSS- und JSON-Dateien bei `Accept-Encoding: gzip` mit `Vary: Accept-Encoding`.
- [x] JSON-Access-/Error-Logs ohne Query-Parameter, Header oder Request-/Response-Bodies.
- [ ] Externen TLS-/HTTP/2-Betrieb sowie statische Release-Auslieferung mit einem Live-Client verifizieren.

---

### Milestone 10: Zertifikats-Flexibilität & SNI-Mischbetrieb (✅ Implementiert; Live-Betrieb offen)
- [x] **Dynamic SNI Hybrid Resolver (`DynamicSniResolver`)**:
  - Paralleler Mischbetrieb von Let's Encrypt (ACME TLS-ALPN-01) und manuellen PEM-Zertifikaten bzw. lokaler Developer Root-CA auf demselben TLS-Port (`443`).
  - SNI-Verzweigung zur Laufzeit: Eigene PEMs je Route werden bevorzugt bedient, Let's Encrypt übernimmt die automatisch verwalteten Domains, optionale `--cert`/`--key`-Flags dienen als globaler Fallback.
  - Automatischer TLS-ALPN-01 Challenge-Filter für Let's Encrypt Validierungsanfragen via `rustls_acme::is_tls_alpn_challenge`.
- [ ] Externen Mischbetrieb von ACME- und Custom-PEM-Domains im echten WAN nachweisen.

