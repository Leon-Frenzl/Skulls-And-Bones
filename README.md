# Skulls & Bones — Sovereign Domain Controller & Mesh Suite

> **Souveräne Identitäten. Signierte Policies. Null Cloud-Zwang.**  
> Modulare Rust-Infrastruktur-Suite für selbstgehostete Active-Directory-Alternativen, Zero-Trust-Mesh-Networking, X.509/OpenSSH-PKI und Cross-Platform-Geräteverwaltung.

[![Version](https://img.shields.io/badge/release-v0.2.2-blue.svg)](https://github.com/Leon-Frenzl/Skulls-And-Bones/releases/tag/v0.2.2)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

---

## Überblick

**Skulls & Bones** ersetzt klassische On-Premise-Domain-Controller und verstreute SSH-/VPN-Skripte durch eine kompakte, auditierbare Rust-Suite ohne Docker-Abhängigkeit:

- **Sovereign Domain Controller (`sb-node dc up`)**: Bootstrapt Authentifizierung (Argon2id + Ed25519-Tokens), X.509 Root/Leaf CA, OpenSSH User/Host CA, Split-DNS, GPO-Authority, Graph API und Web-Konsole in einem einzigen Binary.
- **Einzeiliger Client-Join (`sb join <domain>`)**: Nimmt Windows- und Linux-Rechner per Token oder Benutzername/Passwort auf, sichert das Root-CA-Zertifikat, wendet signierte GPOs an und richtet den Hintergrunddienst ein.
- **Cross-Platform GPOs (`policy_engine`)**: Ed25519-signierte Policy-Bundles mit Anti-Rollback-Schutz:
  - **Linux:** `sshd_config.d`, `sysctl.d`, `systemd-resolved` Split-DNS, Firewall-Baseline & ScreenLock.
  - **Windows:** NRPT Split-DNS, Windows Defender Firewall (`sb-gpo-`-Präfix), ScreenLock-Policies & OpenSSH-Hardening.
- **Cross-Platform LAPS (`laps`)**: Pro-Maschine-Notfall-Admin-Passwörter (`OsRng`), Argon2id + AES-256-GCM verschlüsselt, mit automatischer `rotate_pending`-Markierung nach Abruf — nativ auf Linux (`chpasswd`) und Windows (Win32 `NetUserSetInfo` / `NetUserAdd` + lokalisierte `S-1-5-32-544` Administratoren-Gruppe).
- **Echter Hintergrunddienst (`sb-node service install`)**: Registriert `sb-node-agent` als gehärtete `systemd`-Unit unter Linux bzw. nativen Windows Service (SCM) mit automatischem Policy-Pull und LAPS-Rotation-Timer.

---

## Architektur & Workspace-Struktur

```text
Skulls-And-Bones/
├── scripts/
│   └── install-dc.sh       # 1-Befehl-Server-Installer (Ubuntu/Debian + Caddy TLS + UFW + systemd)
├── console/                # Web-Konsole & Self-Service Enrollment UI
├── docs/                   # Architektur- und Produktspezifikationen
├── website/                # Web-Präsenz
└── tools/
    ├── sb/                 # Master-CLI (sb join, sb status, Delegation an Suite-Tools)
    ├── sb-node/            # Domain Controller, Client-Agent, GPO Engine, LAPS & Service Manager
    ├── sb-core/            # Gemeinsame Domain-, Policy-, Vault- und Service-Verträge
    ├── sb-auth/            # Ed25519-Token-Auth, Argon2id-Passwörter, TOTP & Revocation
    ├── sb-ca/              # X.509 mTLS & OpenSSH User/Host Certificate Authority
    ├── sb-mesh/            # P2P-Overlay-Netzwerk & Mesh-Routing
    ├── sb-dns/             # Sovereign Split-DNS Resolver
    ├── sb-proxy/           # Reverse Proxy & Auto-TLS Edge Gateway
    ├── sb-db/              # Embedded MVCC Document-KV Store
    ├── sb-key/             # Root-Identity & Ephemeral Lease Engine
    ├── sb-code/            # Code Engine & Mesh-Synchronisation
    ├── sb-drive/           # Peer-Filesystem & Mesh-Storage
    ├── sb-forge/           # CI/CD Pipeline-Runner
    ├── sb-app-contract/    # SB-MAP Manifest- & Operations-Grants
    └── sb-app-protocol/    # SB-MAP Protokoll-Framing
```

---

## Schnellstart

### 1. Domain Controller auf einem frischen Ubuntu/Debian-Server einrichten

Das Installationsskript richtet Firewall (`ufw`), `fail2ban`, `caddy` (automatisches Let's-Encrypt-TLS), `sb-dc.service`, Admin-Account und eine initiale Baseline-GPO in einem Durchlauf ein:

```bash
curl -fsSL https://raw.githubusercontent.com/Leon-Frenzl/Skulls-And-Bones/main/scripts/install-dc.sh | sudo bash -s -- \
  --domain corp.example.sb \
  --console-host console.example.org \
  --enroll-host enroll.example.org \
  --admin sb.admin \
  --tarball-url https://github.com/Leon-Frenzl/Skulls-And-Bones/releases/download/v0.2.2/sb-v0.2.2-linux-x86_64.tar.gz
```

Voraussetzung sind gesetzte DNS A-Records für `--console-host` und `--enroll-host` auf die IP des Servers (Ports `80/tcp` und `443/tcp` erreichbar).

---

### 2. Client-Rechner der Domäne beitreten lassen (Windows & Linux)

Lade das passende Release-Paket aus den [GitHub Releases](https://github.com/Leon-Frenzl/Skulls-And-Bones/releases) herunter (`sb` und `sb-node` gehören in denselben Ordner).

**Mit Benutzername & Passwort (in einer Administrator-PowerShell bzw. mit `sudo` für systemweite GPOs & Dienst):**

```powershell
sb join corp.example.sb --dc https://console.example.org --username sb.admin
```

**Oder mit einem Enrollment-/Join-Token:**

```powershell
sb join corp.example.sb --dc https://console.example.org --token <JOIN_TOKEN>
```

Was dabei automatisch passiert:
1. Authentifizierung am DC und Erzeugung eines lokalen Ed25519-Maschinenschlüssels (`~/.sb/domain/machine.key`).
2. Ausstellung von Mesh-IP (`10.42.0.x`), X.509-Gerätezertifikat und Sicherung der Root-CA (`~/.sb/domain/root_ca.crt`).
3. Abruf, Ed25519-Signaturprüfung (HTTPS-TOFU-Pinning) und Anwendung des GPO-Bundles.
4. Einrichtung des Hintergrunddienstes `sb-node-agent` (`systemd` bzw. Windows Service).

---

## Wichtige Befehle im Alltag

| Aufgabe | Befehl |
| :--- | :--- |
| Lokalen Domänenstatus prüfen | `sb-node domain status` |
| GPO-Sync manuell testen (Dry-Run) | `sb-node policy apply --domain corp.example.sb --dc https://console.example.org --dry-run` |
| LAPS-Passwort lokal rotieren | `sb-node laps rotate --machine-id <id> --passphrase "<secret>" --apply` |
| LAPS-Passwort abrufen (markiert Rotation) | `sb-node laps reveal --machine-id <id> --passphrase "<secret>"` |
| Hintergrunddienst-Status prüfen | `sb-node service status` |
| Verschlüsseltes DC-Backup erstellen | `sb-node dc backup --out dc-backup.sb-bak --passphrase "<secret>"` |
| Benutzer inkl. Maschinen offboarden | `sb-node user offboard <username>` |

---

## Aus dem Quellcode bauen & testen

Voraussetzung: Rust-Toolchain (`rustup` / Cargo, Edition 2021).

```bash
# Release-Binaries bauen
cargo build --release -p sb-cli -p sb-node

# Gesamten Workspace testen
cargo test --workspace
```

---

## Sicherheitshinweise

- Alle GPO-Bundles sind Ed25519-signiert und gegen Rollbacks (`revision`) sowie Manipulation geschützt.
- LAPS-Passwörter werden im Speicher über `OsRng` erzeugt, mit Argon2id + AES-256-GCM verschlüsselt und unter Windows ohne Shell-/Kommandozeilen-Weitergabe direkt über die Win32-API (`NetUserSetInfo` / `NetUserAdd`) gesetzt.
- Produktive Passwörter, `.sb-enroll`-Dateien, Vaults und private CA-Schlüssel gehören niemals ins Git-Repository.

---

## Lizenz

MIT — siehe [LICENSE](./LICENSE).
