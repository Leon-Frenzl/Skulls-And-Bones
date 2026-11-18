# `sb-proxy` — Sovereign Pure-Rust Reverse-Proxy & Edge Gateway

`sb-proxy` ist das native Edge-Gateway und der Reverse-Proxy des Skulls & Bones Ökosystems. Es verbindet gekaufte Domains (z. B. `app.meinedomain.de`) direkt mit lokalen Node-Diensten (z. B. Next.js auf Port 3000), **ohne** das interne P2P-Entwicklungs-Mesh zu gefährden oder `0.0.0.0` Interface-Leaks zu erzeugen.

---

## 🚀 Key Features

* **Hermetischer Airgap-Schutz**: Leitet Anfragen strikt an `127.0.0.1:<target_port>` weiter. Interne Mesh- & System-Ports (22, 53, 58888, 4001, 8008, 9090) werden kompromisslos geblockt.
* **HTTP/1.1 Keep-Alive und HTTP/2**: Ein gemeinsamer Hyper-Server verarbeitet beide Protokolle; Dateien und Upstream-Anfragen werden gestreamt.
* **Kein 1MB-Upload-Limit**: Beseitigt das berüchtigte NGINX `413 Payload Too Large`.
* **Echtes Let's-Encrypt-ACME**: TLS-ALPN-01, persistenter Account-/Zertifikat-Cache und Zertifikatserneuerung im laufenden TLS-Resolver. Staging ist Standard; Produktion wird explizit aktiviert.
* **Sicherheits-Header und JSON-Logs**: HSTS nur über TLS, optionale CSP und konfigurierbares `X-Content-Type-Options`; Access-/Fehlerereignisse werden als JSON geschrieben.
* **Interaktives Terminal-Dashboard (`sb proxy tui`)**: Ratatui TUI mit Live-Request-Wasserfall, Latenzen und 1-Key Killswitch.
* **Persistente Routenkonfiguration**: Geteilter State (`~/.sb/escape_spaces.json`) für CLI, Daemons und externe Frontends.

---

## 💻 CLI Quickstart

```bash
# Alle aktiven Egress-Routen und Domains auflisten
sb proxy list

# Domain an lokalen Web-Port binden (mit Airgap-Schutz)
sb proxy add app.meinedomain.de 3000

# Statische Website oder Release-Verzeichnis direkt ausliefern
sb proxy static releases.example.com C:\srv\sb-releases\bin

# Öffentliche Tunnel-Route auf diesem Gateway für eine Mesh-Webseite anlegen
sb proxy tunnel-route add app.example.com --node hostinger-node

# Lokalen Produktionsserver über den Mesh-Tunnel veröffentlichen
sb proxy link app.example.com 3000 --node hostinger-node

# DNS A-Record der Domain gegen den Node-Server prüfen
sb proxy check app.meinedomain.de

# Instant Killswitch: Domain temporär stummschalten (503)
sb proxy pause app.meinedomain.de

# Domain wieder aktivieren
sb proxy resume app.meinedomain.de

# Route löschen
sb proxy remove app.meinedomain.de

# Interaktives Ratatui Terminal-Cockpit öffnen
sb proxy tui

# Gateway mit ACME-Staging starten (TLS-ALPN-01 benötigt eingehenden Port 443)
sb proxy start --acme-email ops@example.com

# Produktive Let's-Encrypt-CA nur nach erfolgreichem Staging-Test aktivieren
sb proxy start --acme-email ops@example.com --acme-production
```

ACME erfordert, dass alle aktivierten TLS-Domains und Aliase in
`~/.sb/escape_spaces.json` eingetragen sind und öffentlich auf dieses Gateway
zeigen. Neu hinzugefügte Domains erfordern derzeit einen Gateway-Neustart.
Der persistente ACME-State liegt unter `~/.sb/acme`; unter Unix wird das
Verzeichnis mit Modus `0700` angelegt. TLS-ALPN-01 validiert über Port 443.
ACME und `--cert`/`--key` können in einem Start nicht kombiniert werden;
Routen mit eigenen PEM-Zertifikatspfaden werden im ACME-Modus ausdrücklich
abgelehnt, statt still ignoriert zu werden. Ohne ACME oder geladenes Zertifikat
verweigert `sb-proxy` einen nicht-loopback TLS-Bind. Plain HTTP ist nur für
Loopback-Entwicklung zulässig.

Optionale globale Antwort-Header werden beim Start über Umgebungsvariablen
konfiguriert:

| Variable | Verhalten |
|---|---|
| `SB_PROXY_HSTS` | HSTS-Wert; wird ausschließlich auf TLS-Verbindungen gesetzt |
| `SB_PROXY_CSP` | Content-Security-Policy-Wert |
| `SB_PROXY_X_CONTENT_TYPE_OPTIONS` | `X-Content-Type-Options`; Standard `nosniff`, leer deaktiviert |

Access-Logs enthalten Methode, Host, Pfad ohne Query, Client-IP, HTTP-Version,
Status und Latenz als JSON-Zeilen auf stderr. Request-/Response-Bodies,
Authorization-Header und Query-Parameter werden nicht protokolliert.

Für einen Mesh-gehosteten Webauftritt wird `tunnel-route add` einmalig auf dem
öffentlichen Gateway ausgeführt. Anschließend kann der Projekt-Host
`sb web publish <domain>` verwenden. Der Befehl baut das JavaScript-Projekt,
startet dessen Produktions-`start`- oder `preview`-Skript, prüft den lokalen
HTTP-Endpunkt und hält während der Sitzung den ausgehenden Mesh-Tunnel offen.
Die Tunnel-Route muss bereits auf dem Gateway vorhanden sein; diese lokale
CLI kann entfernte Gateway-Konfiguration nicht ohne eigene Control-Plane ändern.

Statische Inhalte können direkt durch `sb-proxy` ausgeliefert werden, ohne
einen separaten Webserver-Prozess oder Upstream-Port:
`sb proxy static <domain> <verzeichnis>`. Das ausgewählte Verzeichnis muss
existieren; veröffentlicht werden reguläre Dateien und `index.html`, ohne
Directory Listing. `GET` und `HEAD` sind erlaubt, Pfadtraversal, Dotfiles und
Symlinks außerhalb des freigegebenen Verzeichnisses werden abgewiesen. Die
Route bleibt in der gemeinsamen Escape-Space-Konfiguration gespeichert und
nutzt das bestehende Gateway für TLS, Rate-Limits und Pause/Wartungsmodus.
Statische Antworten verwenden `mime_guess` und werden über HTTP/1.1 oder HTTP/2
ausgeliefert; HTTP/1.1-Verbindungen können mehrere Requests wiederverwenden.
Das Verzeichnis darf während des Betriebs nicht von nicht vertrauenswürdigen
Benutzern verändert werden; Pfadprüfung ist keine Isolation gegen einen
Prozess, der parallel Symlinks oder Dateien im Publish-Baum austauschen kann.
`sb-proxy` kann außerdem alle Dateien lesen, auf die sein OS-Servicekonto Zugriff
hat. Für einen öffentlichen Produktionshost sind ein dediziertes, minimal
berechtigtes OS-Konto und ein nur lesbares Publish-Verzeichnis erforderlich.

Damit ist eine mögliche statische Quelle für signierte Release-Artefakte
vorhanden. Der Release-Client nutzt weiterhin seinen gepinnten Signierschlüssel
und seine HTTPS-Prüfung; vor einem produktiven Release-Host müssen DNS/TLS,
Firewall/Portfreigaben, Inhaltsbereitstellung und ein Live-Installationslauf
separat verifiziert werden.
