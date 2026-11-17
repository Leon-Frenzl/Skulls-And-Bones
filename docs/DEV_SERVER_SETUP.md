# Skulls & Bones — Einrichtung Entwicklungsumgebung und Dev-Server

> **Status:** Betriebsanleitung für einen einzelnen Entwicklungs-Server plus lokale Workstation. Sie beschreibt den tatsächlich durchgeführten Aufbau, kein Release-Verfahren. Sicherheitsaussagen gelten nur für die hier genannten Maßnahmen.
> **Platzhalter:** `<VPS_IP>` (öffentliche Server-IP), `<ADMIN_USER>` (unprivilegierter Admin-Account), `<DOMAIN>` (optional), `<MESH_DEV>` / `<MESH_PUBLIC>` (Mesh-Namen). Keine Zugangsdaten, Einladungs-URIs oder Schlüssel gehören in diese Datei oder ins Repository.

## 1. Zielbild

```text
                Internet
                   │
   ┌───────────────┼──────────────────────────────┐
   │ TCP 22        │ TCP 80/443        UDP 58888  │   ← einzige offene Ports (UFW)
   │ SSH           │ Website & /bin    sb-node    │
   │ (nur Key)     │ (sb-proxy,        Anchor     │
   │               │  sb-public)                  │
   └──────┬────────┴──────┬────────────────┬──────┘
          │               │                │
     Admin-Zugang   Public-Zone     Multi-Mesh-Dispatcher
                    (read-only)     ├─ <MESH_PUBLIC>  10.241.0.0/16
                                    └─ <MESH_DEV>     10.240.0.0/16
                                           │ explizite Route (Default-Deny)
                                           ▼
                                  127.0.0.1:58832  sb-code syncd
```

- **Public-Zone:** Website, statisch, ohne Zugriff auf Mesh-Daten.
- **Dev-Zone:** Entwicklung und Code-Versionierung mit `sb-code`; Dienste lauschen nur auf Loopback und sind nur über eine explizit autorisierte Cross-Mesh-Route des Anchors erreichbar.
- Beide Meshes laufen als getrennte Mandanten (Overlay-Netze) im selben `sb-node`-Prozess hinter einem UDP-Port. Die Trennung beruht auf der Mandantentrennung von `sb-node`/`sb-mesh` und auf Default-Deny-Routen; sie ist nicht unabhängig auditiert.

## 2. Lokale Workstation (Windows)

Voraussetzungen: Rust-Toolchain, Node.js (npm).

```powershell
cargo check --workspace
cargo test --workspace
cargo install --path tools/sb --bin sb
npm run verify:suite
sb status
```

Bekannte Stolperfallen:

| Symptom | Ursache | Lösung |
|---|---|---|
| `npm ci` bricht mit `EALLOWSCRIPTS` ab | Eine Benutzer-`.npmrc` enthält `allow-scripts=…`; neuere npm-Versionen verbieten das bei projektbezogenen Installs | Für den Aufruf eine leere User-Config setzen: `$env:npm_config_userconfig = "<leere Datei>"` |
| `ssh` verhält sich unerwartet | Veraltete Binaries im Cargo-Bin-Pfad | Prüfen, dass keine veralteten Prototyp-Binaries (wie frühere `sb-ssh`-Builds) in `~/.cargo/bin` liegen |
| `website/` ist leer/defekt | Verzeichnis ist eine Junction in den lokalen `.sb`-Stream-Store | Inhalt per `sb-code` aus dem Dev-Mesh beziehen oder Junction neu anlegen |

## 3. Server-Grundhärtung

Basis: Ubuntu LTS, frischer VPS, einmaliger Erstzugang als `root` mit Initialpasswort.

1. **Key-Login einrichten:** Öffentlichen Schlüssel der Workstation in `~/.ssh/authorized_keys` eintragen (Initialpasswort danach nie wieder verwenden).
2. **Admin-Account:** `adduser --disabled-password <ADMIN_USER>`, Key hinterlegen, `sudoers.d`-Eintrag (`NOPASSWD` ist vertretbar, weil Login ausschließlich per Key erfolgt).
3. **Zugang vor dem Abschalten prüfen:** Login und `sudo -n true` als `<ADMIN_USER>` testen, erst dann Schritt 4.
4. **`/etc/ssh/sshd_config.d/10-hardening.conf`:**

   ```text
   PermitRootLogin no
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PubkeyAuthentication yes
   AllowUsers <ADMIN_USER>
   MaxAuthTries 3
   LoginGraceTime 20
   X11Forwarding no
   AllowAgentForwarding no
   ```

   `sshd -t`, dann `systemctl reload ssh`. Bestehende Sitzungen bleiben offen, bis der Test mit neuer Sitzung bestätigt ist.
5. **Firewall (UFW):** Default deny incoming; erlaubt: `22/tcp`, `80/tcp`, `443/tcp`, `58888/udp`.
6. **Brute-Force-/Patch-Schutz:** `fail2ban` (sshd-Jail, 4 Versuche, 1 h Sperre), `unattended-upgrades` aktiv.
7. **Pakete:** `build-essential pkg-config libssl-dev curl ca-certificates rsync` sowie Rust (rustup, minimal) und Node.js (kein Drittanbieter-Webserver wie Caddy oder Nginx erforderlich — die Suite nutzt das eigene `sb-proxy`).

> Das beim Erstzugang verwendete Passwort gilt als offengelegt, sobald es in einem Chat, Ticket oder Log erschien: beim Provider ändern/rotieren oder Passwort-Login dauerhaft deaktiviert lassen.

## 4. Quellcode und Build auf dem Server

Der Server hat keinen Git-Remote; der Quellstand wird als Archiv übertragen (ohne Build-Artefakte, `.sb/`, `.env*`, `*.sbkey`, `*.local`, ohne `website/`):

```powershell
tar -czf sb-src.tar.gz --exclude=target --exclude=node_modules --exclude=dist `
  --exclude=.sb --exclude=.sb-forge --exclude='.env*' --exclude='*.sbkey' --exclude='*.local' `
  Cargo.toml Cargo.lock Forge.toml package.json README.md ROADMAP.md AGENTS.md `
  product-inventory.json .sbignore docs brain packaging tools
# Upload per scp/sftp nach ~/ und entpacken nach ~/src/skulls-and-bones
```

Build (der Suite-Launcher heißt als Cargo-Paket `sb-cli` (crates.io-Name), das Binary heißt `sb`):

```bash
cd ~/src/skulls-and-bones
cargo build --release -p sb-cli -p sb-node -p sb-code -p sb-mesh -p sb-proxy   # ca. 4 min auf 2 vCPU
sudo install -m755 target/release/{sb,sb-node,sb-code,sb-mesh,sb-proxy} /usr/local/bin/
```

Spätere Updates: Archiv erneut übertragen, bauen, Binaries ersetzen, Dienste neu starten.

### 4a. Bootstrap-Pfad für den Quellcode (Henne-Ei-Problem)

`sb-code push/pull` setzt ein laufendes Dev-Mesh voraus, und das Mesh braucht Binaries, die aus dem Quellcode entstehen. Der Ablauf, der das auflöst:

1. **Einmalig per Archiv** (Abschnitt 4) oder mit vorgebauten Binaries: `sb server provision <host> --pubkey <datei> --binaries <dir>` überspringt den Server-Build komplett.
2. Auf dem Server `sb-mesh bootstrap` (macht `provision` selbst), danach im Workspace `sb-code init`.
3. Ab jetzt wird der Code **nur noch über das Mesh** transportiert:
   - Server: `sb-code serve --mesh <MESH_DEV> --workspace ~/workspaces/sb-main` (Route + syncd, nur Loopback), im Dauerbetrieb über `sb-code-syncd.service`.
   - Workstation: dem Mesh beitreten (Einladungsdatei aus `~/.sb-mesh/invites/`), dann `sb-code push --source-mesh <MESH_DEV> --target-mesh <MESH_DEV> --anchor <ANCHOR>:58888`.
4. Das Archiv aus Schritt 1 wird danach nicht mehr benötigt.

## 5. Meshes anlegen (zwei getrennte Mandanten)

Als `<ADMIN_USER>` auf dem Server, nicht-interaktiv:

```bash
sb-mesh bootstrap --headless -n <MESH_DEV>    -a <VPS_IP>:58888 -c 10.240.0.0/16 --admin admin
sb-mesh bootstrap --headless -n <MESH_PUBLIC> -a <VPS_IP>:58888 -c 10.241.0.0/16 --admin admin
sb-mesh network list
```

- Der Bootstrap erzeugt Admin-Identität (`~/.sb-mesh/identity.json`), Tenant-Verzeichnisse und **Einladungs-URIs**. Einladungs-URIs sind Zugangsgeheimnisse: nur über einen sicheren Kanal weitergeben, nie veröffentlichen, bei Verdacht per `sb-mesh invite revoke` widerrufen.
- Das erzeugte `deploy-anchor.sh` startet den Dienst als `root` ohne Sandboxing; stattdessen werden die Units aus Abschnitt 6 verwendet.
- Hinweis: Der Default-Bootstrap hat für `<MESH_DEV>` den gleichen CIDR wie das Mesh `default`. Für strikt getrennte Adressräume einen eigenen CIDR wählen.

## 6. Dienste (systemd, unprivilegiert)

Beide Units laufen als `<ADMIN_USER>` (kein root) mit:

```text
NoNewPrivileges=true  ProtectSystem=strict  ProtectHome=read-only
ReadWritePaths=%h/.sb-mesh %h/.sb-node %h/workspaces
PrivateTmp=true  ProtectKernelTunables=true  ProtectControlGroups=true
RestrictSUIDSGID=true  LockPersonality=true  Restart=always
```

| Unit | Befehl | Bindung |
|---|---|---|
| `sb-node.service` | `sb-node daemon` | UDP `0.0.0.0:58888` (Anchor, alle Meshes) |
| `sb-code-syncd.service` | `sb-code syncd --workspace ~/workspaces/sb-main` | TCP `127.0.0.1:58832` (nur Loopback) |

Workspace für die Code-Versionierung initialisieren: `sb-code init` im Verzeichnis `~/workspaces/sb-main`.

Autorisierung (Default-Deny): Der Zugriff auf `syncd` aus einem Mesh erfordert eine explizite Route und Mitglieder mit `stream:transfer` und `code:sync`:

```bash
sb-node route add-code --source-mesh <MESH_DEV> --target-mesh <MESH_DEV>
sb-node route list
```

Von der Workstation (nach `sb mesh join <Einladungs-URI>`):

```powershell
sb-code push --source-mesh <MESH_DEV> --target-mesh <MESH_DEV> --anchor <VPS_IP>:58888 --branch main --workspace <lokaler-Pfad>
```

Commits sind derzeit unsigniert (siehe `tools/sb-code/README.md`); die Mesh-Autorisierung regelt, wer synchronisieren darf, authentifiziert aber nicht das Feld `author_callsign`.

## 7. Website & Edge Gateway (Public-Zone mit isoliertem Benutzer `sb-public`)

Statt Third-Party-Webservern (Caddy/Nginx) übernimmt das Suite-eigene **`sb-proxy`** die Auslieferung von Website und signierten Releases sowie die TLS-Terminierung.

### 7a. Isoliertes Servicekonto `sb-public` anlegen
Zur strikten Trennung der Public-Zone von Mesh-Diensten und Entwickler-Dateien (`ProtectHome=true`, keine Shell, keine Rechte auf `~/.sb-mesh` oder Secrets):

```bash
# 1. Unprivilegierten System-Benutzer ohne Login anlegen
sudo useradd --system \
  --home-dir /var/lib/sb-public \
  --shell /usr/sbin/nologin \
  --comment "S&B Public Edge Gateway" \
  sb-public

# 2. Verzeichnisse vorbereiten und Berechtigungen setzen
sudo mkdir -p /var/lib/sb-public /var/www/sb-public/bin
sudo chown -R sb-public:sb-public /var/lib/sb-public
sudo chmod 700 /var/lib/sb-public

# Web-Assets gehören root:sb-public; sb-public hat nur Leserechte
sudo chown -R root:sb-public /var/www/sb-public
sudo chmod -R 755 /var/www/sb-public
```

### 7b. systemd Unit für `sb-proxy`
`/etc/systemd/system/sb-proxy.service`:

```ini
[Unit]
Description=Skulls & Bones Sovereign Edge Gateway (sb-proxy)
After=network.target

[Service]
Type=simple
User=sb-public
Group=sb-public
WorkingDirectory=/var/lib/sb-public
Environment=HOME=/var/lib/sb-public
Environment=SB_PROXY_SPA=1

# Linux Capabilities: Port 80 & 443 binden ohne Root-Rechte
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Gateway mit automatischem 301-Redirect (Port 80 -> 443) und Let's Encrypt ACME
ExecStart=/usr/local/bin/sb-proxy start \
    --bind 0.0.0.0:443 \
    --http-bind 0.0.0.0:80 \
    --acme-email dev@skulls-and-bones.org \
    --acme-production

Restart=always
RestartSec=5

# Strikte Systemd-Isolation
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

# Dateizugriff: Nur eigenes State-Verzeichnis beschreibbar, Webroot nur lesbar
ReadWritePaths=/var/lib/sb-public
ReadOnlyPaths=/var/www/sb-public

[Install]
WantedBy=multi-user.target
```

### 7c. Statische Route für `skulls-and-bones.org` registrieren
Als Benutzer `sb-public` die Veröffentlichung des Verzeichnisses konfigurieren:

```bash
sudo -u sb-public HOME=/var/lib/sb-public sb-proxy static skulls-and-bones.org /var/www/sb-public
```

Dienst aktivieren und starten:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sb-proxy
```

## 8. Verifikation

```bash
systemctl is-active sb-node sb-code-syncd sb-proxy fail2ban
sudo ss -tulnp                    # extern: 22/tcp, 80/tcp, 443/tcp, 58888/udp; 58832 nur 127.0.0.1
sudo ufw status verbose
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|allowusers)'
curl -sI https://skulls-and-bones.org/      # 200 + Security-Header + HTTP/2
curl -sI http://skulls-and-bones.org/       # 301 Moved Permanently zu HTTPS
journalctl -u sb-proxy -n 20 --no-pager
```

Erwartung: Root- und Passwort-Login schlagen fehl, nur die genannten Ports sind extern erreichbar; `sb-proxy` läuft isoliert unter `sb-public`.

## 9. Offene Punkte

- TLS und Domain für die Website (erfordert `<DOMAIN>`).
- Echten Website-Build bereitstellen (aktuell Platzhalterseite).
- Mesh-Mitgliedschaften und Routen (`route add-code`, Rollen) für Teammitglieder festlegen.
- Datensicherung von `~/.sb-mesh` (enthält Identität und Mesh-Zustand; verschlüsselt und offline ablegen).
- Optional: `sb-mesh service`-/Anchor-Verhalten und Telemetrie (`sb-node telemetry`) in ein Monitoring einbinden.
