# Skulls & Bones — Release-Schlüssel-Lifecycle & Notfall-Prozeduren

> **Verbindliche Spezifikation für Key-Generierung, Backup, Disaster Recovery, Rotation und Kompromittierungs-Reaktion.**

---

## 1. Vertrauensmodell & Architektur

Skulls & Bones folgt dem Prinzip: **Transport ist unzuverlässig; kryptografische Signaturen sind maßgeblich.**

```
┌────────────────────────┐         HTTPS / P2P Mesh
│  Release Mirror / CDN  │ ─────────────────────────────────┐
│ (skulls-and-bones.org) │   (Transport ist NICHT vertraut) │
└────────────────────────┘                                  ▼
                                                ┌───────────────────────┐
                                                │      sb install       │
                                                │                       │
                                                │ 1. Download Manifest  │
                                                │ 2. Download .ed25519  │
                                                │ 3. Signaturprüfung    │ ◄─── Pinned Trust Anchor:
                                                │    (FAIL-CLOSED)      │      RELEASE_PUBLIC_KEY
                                                │ 4. Hash-Abgleich      │      (32-Byte Ed25519)
                                                │ 5. Atomarer Tausch    │
                                                └───────────────────────┘
```

1. **Vertrauensanker im Client**:
   In `tools/sb/src/commands/release.rs` ist der öffentliche 32-Byte Ed25519-Schlüssel fest verankert:
   ```rust
   pub const RELEASE_PUBLIC_KEY: [u8; 32] = [
       0xd4, 0x22, 0x2e, 0x09, 0x89, 0x4d, 0x85, 0x2e, 0x73, 0x18, 0xbd, 0x02, 0xde, 0xfd, 0xd1, 0xfa,
       0x63, 0xbf, 0x9b, 0x26, 0x09, 0x78, 0xa9, 0xd2, 0x4f, 0x11, 0xcc, 0x70, 0x7f, 0xd1, 0x5a, 0x8d,
   ];
   ```
2. **Fail-Closed-Garantie**:
   - `sb install` und `sb update` verlangen zwingend HTTPS für Remote-Downloads.
   - Ein Release ohne gültige Ed25519-Signatur über das exakte Manifest wird sofort abgewiesen.
   - Archiv-Hashes (SHA-256) werden vor dem Entpacken gegen das signierte Manifest geprüft.
   - Versionen werden gegen das lokale `installed_ledger.json` geprüft; unberechtigte Downgrades werden blockiert.

---

## 2. Schlüsselgenerierung (Key Generation)

Der private Release-Schlüssel darf **unter keinen Umständen** auf öffentlichen Servern, Webservern/Gateways (`sb-proxy`, Caddy, etc.) oder in Git-Repositories abgelegt werden.

### Generierungs-SOP:
1. Erzeugung auf einer isolierten, gehärteten Workstation:
   ```bash
   sb release gen-key --output ~/.sb/secrets/production-release.key
   ```
2. Dateiberechtigungen auf Unix-Systemen strikt auf `0600` beschränken (nur Owner).
3. Öffentlichen Schlüssel (Hex und Rust-Array) notieren und im Quellcode verifizieren.

---

## 3. Backup-Verfahren (Key Backup)

Für den privaten Release-Schlüssel gilt eine strikte **3-2-1-Backup-Strategie**:

1. **Kopie 1 (Aktiv)**: Auf dem physisch isolierten Signierrechner (`production-release.key`).
2. **Kopie 2 (Digital verschlüsselt)**: 
   - Verschlüsselt mit starkem Master-Passwort (mind. 16 Zeichen, Argon2id + AES-256-GCM / Age):
     ```bash
     # Beispiel mit age oder gpg
     age -p ~/.sb/secrets/production-release.key > production-release.key.age
     ```
   - Gespeichert auf einem luftgetrennten (air-gapped) USB-Speichermedium.
3. **Kopie 3 (Physischer Paper-Key)**:
   - Der 64-stellige Hex-Seed wird ausgedruckt / handschriftlich notiert.
   - Versiegelt in einem feuerfesten Dokumentensafe an einem geografisch getrennten Standort.

---

## 4. Wiederherstellungsverfahren (Disaster Recovery)

Bei Verlust oder Ausfall des Signierrechners erfolgt die Wiederherstellung nach folgender Prozedur:

1. **Wiederherstellung aus Backup**:
   - Entschlüsseln des digitalen Backups oder Abtippen des Hex-Seeds in eine neue Datei:
     ```bash
     # Neuer Speicherort
     nano ~/.sb/secrets/recovered-release.key
     chmod 600 ~/.sb/secrets/recovered-release.key
     ```
2. **Betriebliche Verifikation**:
   - Vor Verwendung muss die Schlüsselintegrität geprüft werden:
     ```bash
     sb release verify-key --key-file ~/.sb/secrets/recovered-release.key
     ```
   - **Erwartetes Ergebnis**:
     ```text
     ► RELEASE-SCHLÜSSEL VALIDIERUNG [KEY-AUDIT]
       Schlüsseldatei:   ~/.sb/secrets/recovered-release.key
       Format:           Gültiger Ed25519 Private Seed
       Public Key (Hex): d4222e09894d852e7318bd02defdd1fa63bf9b260978a9d24f11cc707fd15a8d
       Status:           VERIFIZIERT — Entspricht dem im Client gepinnten Produktions-Schlüssel
     ```
   - Nur wenn der Status `VERIFIZIERT` lautet, ist das Recovery erfolgreich abgeschlossen.

---

## 5. Rotationsverfahren (Geplante Schlüsselrotation)

Da der Vertrauensanker im Binärcode des Clients gepinnt ist, erfolgt eine reguläre Rotation über ein **Transition-Release**:

```
[Phase 1: Vorbereitung]
  - Neuer Schlüssel K_neu erzeugen.
  - Patch für sb: Setzt K_neu als primären Vertrauensanker, akzeptiert aber K_alt für Übergangszeit.

[Phase 2: Transition-Build]
  - Neuer sb-Build v(X+1) wird mit K_alt signiert.
  - Bestehende Clients vX installieren v(X+1), da die Signatur von K_alt stammt.

[Phase 3: Umschaltung]
  - Nach Verteilung von v(X+1) werden nachfolgende Releases v(X+2) mit K_neu signiert.
  - Ältere Clients vX müssen über Notfall-Bootstrap aktualisiert werden.
```

---

## 6. Notfall-Kompromittierungsplan (Compromise Response Plan)

Bei Verdacht auf Schlüsselkompromittierung (z.B. Diebstahl des privaten Seeds) greift der 4-Stufen-Notfallplan:

### Stufe 1: Sofortige Abschaltung des Release-Mirrors (T+0h)
1. Sofortiges Löschen von `release-manifest.json` und `release-manifest.json.ed25519` auf allen Mirrors (`skulls-and-bones.org/bin`).
2. Dadurch schlagen alle automatischen `sb install` / `sb update`-Aufrufe sofort fail-closed fehl, bevor bösartige Pakete bezogen werden können.

### Stufe 2: Taint-Tagging & Veröffentlichung (T+2h)
1. Kennzeichnung des alten Public Keys als widerrufen (`REVOKED`).
2. Bekanntgabe in den offiziellen Kommunikationskanälen unter Angabe des betroffenen Versionsfensters.

### Stufe 3: Emergency Bootstrap & Pin-Update (T+6h)
1. Erzeugung eines neuen Release-Schlüsselpaars.
2. Quellcode-Release mit dem neuen gepinnten Schlüssel.
3. Nutzer aktualisieren den Client per sicherem Bootstrap:
   ```bash
   cargo install --path tools/sb --bin sb --force
   ```

### Stufe 4: Flotten-Audit (T+12h)
1. Alle Betreiber prüfen ihre Systeme mit:
   ```bash
   sb release verify
   sb doctor
   ```
2. Binaries, deren SHA-256-Hash nicht mit dem verifizierten Stand übereinstimmt, werden als `tampered` markiert und sofort isoliert.

---

## 7. Status der Live-Release-Infrastruktur

### Letzte externe Diagnose (2026-10-17) für `skulls-and-bones.org` / `145.223.83.235`:
- **DNS-Auflösung**: Apex-Domain und `www.skulls-and-bones.org` zeigen auf `145.223.83.235`.
- **Port 80 (HTTP)**: Antwortet mit `200 OK`, liefert aber weiterhin die HTML-Platzhalterseite „Platzhalter - Website-Deployment folgt.“ (255 Bytes; `Last-Modified: Wed, 07 Oct 2026 11:55:39 GMT`). Die gewünschte Website ist daher nicht veröffentlicht.
- **Port 443 (HTTPS)**: Der Verbindungsaufbau lief von der Prüfstation nach 8 Sekunden in einen Timeout. Ursache kann Host-Firewall oder TLS-Listener sein und ist ohne Serverzugriff nicht unterscheidbar.
- **Folge**: Die Produktionswebsite und der HTTPS-Release-Endpunkt sind nicht abgenommen; `sb install` kann die geforderte HTTPS-Quelle derzeit nicht erfolgreich erreichen.
- **Zugriffsgrenze**: Die Diagnose war read-only. Für Firewall, Caddy, `sb-public`, Artefakttransfer und Public-Mesh-Dienst ist autorisierter Operatorzugriff erforderlich; private Release-Schlüssel gehören nicht auf den Webhost.

### Bereitstellungsschritte auf dem Produktionsserver (mit `sb-proxy` & `sb-public`):
1. **Firewall öffnen**:
   ```bash
   ufw allow 443/tcp
   ```
2. **Isolierten System-Benutzer `sb-public` anlegen**:
   ```bash
   sudo useradd --system --home-dir /var/lib/sb-public --shell /usr/sbin/nologin sb-public
   sudo mkdir -p /var/lib/sb-public /var/www/sb-public/bin
   sudo chown -R sb-public:sb-public /var/lib/sb-public
   sudo chown -R root:sb-public /var/www/sb-public
   sudo chmod -R 755 /var/www/sb-public
   ```
3. **`sb-proxy.service` aktivieren**:
   - `sb-proxy` läuft unprivilegiert als `sb-public` mit `CAP_NET_BIND_SERVICE`.
   - Lauscht auf Port 80 (HTTP 301-Redirect) und Port 443 (Let's Encrypt ACME TLS-ALPN-01).
   - Statische Route registrieren:
     ```bash
     sudo -u sb-public HOME=/var/lib/sb-public sb-proxy static skulls-and-bones.org /var/www/sb-public
     ```
4. **Artefakte bereitstellen**:
   - Die mit `sb release pack-all` erstellten Archive, `release-manifest.json` und `release-manifest.json.ed25519` nach `/var/www/sb-public/bin` synchronisieren.
   - `sb-proxy` streamt diese Dateien direkt mit `Cache-Control: no-cache` und Security-Headern.

### Lokaler Staging- & Test-Betrieb:
Solange der öffentliche Port 443 nicht freigegeben ist, kann jedes Repository oder Staging-System getestet werden über:
```bash
# Staging über Umgebungsvariable:
export SB_RELEASE_URL="https://staging.skulls-and-bones.org/bin"
sb install mesh code

# Oder direkt über CLI-Flag:
sb install mesh --from-dir ./dist
```
