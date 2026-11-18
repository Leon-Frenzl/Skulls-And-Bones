# S&B Sovereign Mesh (`sb-mesh`)
> **Experimentelles User-Space P2P-Overlay mit eigenem Forschungsprotokoll & TUI**
> Keine WireGuard- oder Noise_IK-Kompatibilität; nicht als produktionsreifes VPN einstufen.
> Autarke Single-Binary CLI & TUI in 100% Pure Rust (Tokio, Ratatui, X25519, ChaCha20-Poly1305).  
> *Sicherheitsmarke: Skulls & Bones ([skulls-and-bones.org](https://www.skulls-and-bones.org))*

[![Crates.io](https://img.shields.io/crates/v/sb-mesh.svg?style=flat-square)](https://crates.io/crates/sb-mesh)
[![Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?style=flat-square)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Free & Open Source](https://img.shields.io/badge/Cost-100%25_Free_%26_Open--Source-brightgreen.svg?style=flat-square)](#)
[![Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg?style=flat-square)](#)
[![Rust Dependencies](https://img.shields.io/badge/Dependencies-Rust-blueviolet.svg?style=flat-square)](#)

---

## ⚡ Das Problem mit herkömmlichen VPNs & Mesh-Lösungen

* **Zentralisierte Gateways:** Klassische VPNs zwingen den gesamten Datenverkehr durch einen zentralen Konzentrator (Single Point of Failure, Flaschenhals, Überwachungsziel).
* **Bufferbloat & Paketverluste:** Überlastete ISP-Router-Warteschlangen führen bei UDP-Tunneln zu unberechenbarem Jitter und abrupten Paket-Drops.
* **Kernel-Abhängigkeiten:** Herkömmliche WireGuard-Lösungen erfordern Kernel-Module oder Root-Rechte, was den Einsatz in Containern und restriktiven Umgebungen erschwert.
* **Fehlende Forward Error Correction:** Schon geringer Paketverlust auf Funk- oder Transkontinentalstrecken zwingt TCP zu drastischen Window-Drosselungen.

---

## 🛡️ Die Lösung: S&B Sovereign Mesh

**S&B Mesh (`sb-mesh`)** ist ein experimentelles Peer-to-Peer-Overlay im User-Space. Das eigene Forschungsprotokoll befindet sich im Umbau und ist weder WireGuard- noch Noise_IK-kompatibel; diese Implementierung ist nicht extern auditiert und nicht für sicherheitskritische Produktion freigegeben.

Der aktuelle Stand umfasst:
1. **Galois Field $\mathbb{F}_{2^8}$ FEC/RLNC-Prototyp:** `8+4` ist das Profil für unbekannte Streams; größenbekannte Uploads können ein begrenztes Profil aushandeln. Der allgemeine Peer-Transport nutzt FEC noch nicht.
2. **Delay-Gradient-Pacer-Prototyp:** Separates Modul ohne Anbindung an den normalen Transport; keine BBR-Kompatibilität.
3. **Kryptografischer Transport-Prototyp:** X25519-Identitäten, richtungsgetrennte HKDF-SHA-256-Schlüssel und ChaCha20-Poly1305; Handshake, Rekeying und Paketformat benötigen weitere Protokollhärtung und unabhängige Prüfung.

### Lokale Mesh-State-Ablage und PSK-Migration

Jedes benannte Mesh speichert Identität, Konfiguration, Peers, Runtime-Status, RBAC, Tickets, Subnet-Routen und migrierte PSKs unter `~/.sb-mesh/instances/<mesh>/` (Windows: `%USERPROFILE%\.sb-mesh\instances\<mesh>\`). Vorhandene Legacy-Dateien im alten gemeinsamen Layout werden nicht automatisch importiert oder gelöscht. Gegenstellen müssen bei einer neuen Mesh-Identität erneut gekoppelt werden.

Ältere `networks.json`-Dateien können optionale PSKs enthalten. Verschiebe sie nach Prüfung der jeweils mesh-spezifischen Datei explizit:

```powershell
sb-mesh network migrate-psks
```

Der Befehl schreibt `network.psk` im privaten Mesh-Verzeichnis, liest den Wert zur Verifikation zurück und entfernt den Katalogwert erst danach. Bei Schreib-, Rechte- oder Konfliktfehlern bleibt der Katalogwert erhalten; die Migration kann sicher erneut ausgeführt werden. Unix-Dateien erhalten Modus `0600`, Mesh-Verzeichnisse `0700`. `SB_MESH_HOME` kann für Tests oder einen separaten lokalen State-Root gesetzt werden. Diese Ablage isoliert Zustände logisch, aber nicht gegenüber Prozessen desselben OS-Benutzers.

### Cross-Mesh-Stream: aktueller Stand

`MeshClient::connect` nutzt den gepinnten Anchor-Schlüssel aus einem gültigen, zuvor durch `join_with_invite` gespeicherten Mesh-Ticket. UDP-Antworten werden an Anchor-Adresse und Schlüssel gebunden, AEAD-geschützt und mit einem Anti-Replay-Fenster geprüft. Der Anchor bindet Streams an die authentifizierte Node-ID und den Zielport. Die RBAC-Mitgliedschaft und die portbezogene Capability werden beim Connect sowie vor jedem nachfolgenden Stream-Paket frisch aus dem bestehenden RBAC-Speicher geprüft. Bei Widerruf, Ablauf oder nicht verfügbarem Autorisierungszustand wird fail-closed abgewiesen und die aktive Session beendet.

Unbekannte/interaktive Streams verwenden weiterhin das kleine Standardprofil `8+4`. Für bekannte Uploadgrößen bietet `MeshClient::open_cross_mesh_transfer` eine begrenzte Profilauswahl anhand der exakten Schreiblänge, einer angenommenen Symbolverlustrate und eines Transfer-Ausfallziels. Standardmäßig wird mit 10 % unabhängigen Symbolverlusten und höchstens 0,1 % modelliertem Gesamtausfall gerechnet; größere Profile werden nur gewählt, wenn sie das Ziel erreichen. Das erweiterte API erlaubt andere Annahmen in ppm. Der erwartete Uploadumfang wird beim Schreiben durchgesetzt; die Antwort-Richtung nutzt dasselbe Profil, hat aber keine eigene Transfer-Ausfallgarantie.

Die Blöcke sind auf 16 KiB und die Decoder-Pufferung auf acht unvollständige sowie acht geordnet wartende Blöcke begrenzt. Pro Symbol sind höchstens 256 Byte Nutzlast vorgesehen, damit die codierten Envelopes im konservativen 1200-Byte-UDP-Budget bleiben. Jedes Symbol trägt einen Blockindex und wird über SHA-256 pro Block vor dem Weiterreichen geprüft. Ein Block-Ende löst eine selektive Reparaturanfrage mit den fehlenden Symbolindizes aus; nach erfolgreicher Rekonstruktion bestätigt der Empfänger den Block. Es gibt höchstens drei Reparaturrunden pro Block; ohne Bestätigung wird der Stream abgebrochen. Sender halten jeweils nur einen codierten Block zur Reparatur vor, also konservativer als das Decoderlimit von acht Blöcken. Beim FEC-Close wird zusätzlich ein SHA-256-Hash über den geordneten Gesamtstream geprüft. Die Gesamtprüfung erkennt auch fehlende oder anders zusammengesetzte Streams, kann bereits gestreamte Bytes jedoch nicht zurückholen; Datei-/Snapshot-Verbraucher sollten Inhalte bis zum erfolgreichen Close selbst zurückhalten. Beide Hashes ergänzen, ersetzen aber nicht Mesh-AEAD oder anwendungsspezifische Signaturen. Das Wire-Envelope ist auf Version 3 angehoben; alle Cross-Mesh-Peers müssen dieselbe Version unterstützen.

Die FEC-Matrix ist weiterhin eine S&B-Cauchy-Implementierung und **nicht** RFC-6330/RaptorQ-kompatibel. Der 1200-Byte-Datagrammrahmen folgt der konservativen Fragmentierungsvermeidung aus RFC 8085; SHA-256 ist standardisiert, macht den FEC-Code selbst aber nicht standardkonform oder interoperabel. Selektive Reparatur kann auch Verluste oberhalb der Paritätsgrenze ausgleichen, sofern die fehlenden Symbole innerhalb der drei Reparaturrunden ankommen. Sie ist kein unbegrenzter Resend und keine Zusicherung gegen WAN-Ausfälle. Bei Bursts gelten zusätzlich die getesteten Blockgrenzen; das analytische Profilmodell nimmt weiterhin unabhängige Verluste an. Der Transport ist experimentell und noch nicht als produktionsreif oder als alleinige Integritätsgarantie für Dateien freigegeben. DNS-Signatur, Authority-Pin und Gültigkeit bleiben die Vertrauensbasis der Snapshots.

Der reproduzierbare FEC-Metriktest vergleicht `8+4`, `64+8` und `64+25` für 16-MiB-Dateien bei 1 %, 5 % und 10 % unabhängigen Symbolverlusten. Er gibt Block-/Dateierfolg, Redundanz sowie geschätzte Mesh-, IPv4- und IPv6-Datagrammbytes aus und misst zusätzlich den Encoder/Decoder auf deterministisch verlustbehafteten Stichproben. Bursttests prüfen Recovery bis zur Paritätsschwelle und über Blockgrenzen; Integrationstests lassen zudem mehr Symbole als die Parität aus und prüfen selektive Reparatur, Blockbestätigung und Abbruchpfade. Weitere Tests prüfen Profilauswahl, SHA-256-Blockintegrität, Wire-Version und die Speichergrenzen des Stream-Decoders. Die Transfer-Profilauswahl ist eine analytische Schätzung unter unabhängigen Erasures und kein gemessener Verlustregler oder Nachweis für reale WAN-Pfade. Ausführen mit:

```bash
cargo test -p sb-mesh --test fec_loss_metrics -- --nocapture
```

Die analytischen Dateierfolgsraten setzen unabhängige Erasures voraus. Die deterministische 32-Block-Simulation und Bursttests ergänzen diese Rechnung; sie sind keine Messungen eines realen WAN-Pfads.

### Katalog-DC-Replikation über Port 58831

`sb-node` registriert für jedes konfigurierte Mesh mit gültiger lokaler DC-Membership einen loopback-gebundenen Snapshot-Dienst hinter dem adressierten `sb-mesh`-Cross-Mesh-Stream auf Port `58831`. Der Admission-Gate verlangt einen aktiven Peer mit explizitem `catalog:replicate`-Grant im Quell-Mesh, dessen Node-ID zugleich in der aktuellen Ziel-Mesh-DC-Membership steht. Außerdem müssen eine explizite Cross-Mesh-Route und eine höchstens 30 Sekunden gültige, mehrheitlich signierte Freshness-Lease zur aktuellen Membership vorhanden sein. Fehlende oder ungültige Zustände verweigern den Zugriff fail-closed; `stream:transfer` allein ist nicht ausreichend.

Die Route wird auf dem zuständigen Anchor konfiguriert; der Grant wird explizit im RBAC-Store des Quell-Meshs gesetzt (die Member-Verwaltung ersetzt bei `--caps` die Standard-Capabilities). Da der Bridge-Prozess die Policy beim Start lädt, muss `sb-node daemon` nach einer Routenänderung neu gestartet werden:

```powershell
sb-node route add-catalog --source-mesh workstation-mesh --target-mesh engineering
sb-node member add --mesh workstation-mesh --name engineering-dc --pubkey <base64-public-key> --role Consumer --caps catalog:replicate
```

Der versionierte Stream unterstützt Digest-Abfrage, Snapshot-Lesen und Snapshot-Anwendung. Ein Update verwendet einen SHA-256-Compare-and-Swap gegen den explizit angegebenen Basis-Digest (oder `absent` für einen noch nicht angelegten Katalog). Divergente Zustände werden abgelehnt; es gibt bewusst keinen automatischen Merge. Die Katalogdatei liegt unter `~/.sb-node/catalog/<mesh>/object-catalog.json`; Schreibvorgänge des Stores teilen einen exklusiven Lock und ersetzen die Datei atomar. Beispiel:

```powershell
sb-node route add-catalog --source-mesh workstation-mesh --target-mesh engineering
sb-node catalog init --mesh engineering
sb-node catalog inspect --source-mesh workstation-mesh --target-mesh engineering --anchor 203.0.113.10:58888
sb-node catalog push --source-mesh workstation-mesh --target-mesh engineering --anchor 203.0.113.10:58888 --base-digest absent
```

`inspect` gibt `absent` oder den Ziel-Digest aus; bei späteren Pushes ist genau dieser explizit zu bestätigen. Für Pulls muss `--base-digest` dem aktuellen lokalen Digest entsprechen, den `sb-node catalog digest --mesh engineering` liefert. `--token <datei>` ist erforderlich, falls die Route ein Capability-Token verlangt. Das Update kopiert den vollständigen Katalog einschließlich Directory- und ACL-Metadaten. Objekt-ACLs filtern diese Metadatenkopie nicht.

Membership-Bootstrap und sicheres Einsammeln/Erneuern der Quorum-Leases sind noch nicht als CLI-Workflow verfügbar; ohne provisionierte gültige Dateien ist der Dienst nicht nutzbar. Der `sb-mesh`-Transport ist experimentell und nicht extern auditiert. Diese Implementierung ist deshalb kein produktionsreifer Vertrauenskanal für autoritative ACL- oder Katalogdaten.

---

## 🚀 Key Features

| Feature | Beschreibung |
| :--- | :--- |
| **100% Pure-Rust User-Space** | Keine Kernel-Treiber, kein TUN/TAP-Zwang, keine Root-Rechte. Läuft direkt als User-Prozess. |
| **Galois $\mathbb{F}_{2^8}$ FEC** | `8+4`-Standardprofil und größenbasierte Profile für bekannte Cross-Mesh-Uploads; noch nicht im allgemeinen Peer-Transport. |
| **Delay-Gradient Pacing** | Experimentelles Modul; derzeit nicht in den normalen Transportpfad integriert. |
| **Taktisches TUI Dashboard** | Interaktives Ratatui Terminal-HUD mit Live-Latenz, Bandbreiten-Graphen, Peer-Status und Steuerung. |
| **Dynamischer SOCKS5-Proxy** | Integrierter RFC-1928 SOCKS5 Proxy mit dezentraler Namensauflösung (`.sbm` Domains). |
| **Zero-Knowledge Proof** | Schnorr-Proof-Prototyp; belegt keine Hardware-Integrität oder TPM-Attestation. |
| **Air-Gap Killswitch** | Sofortige Krypto-Isolierung aller Schnittstellen auf Knopfdruck. |

### SOCKS5 Mesh-Berechtigungen

`sb-mesh proxy` startet nur mit einem gültigen lokalen Mesh-Ticket, das an die registrierte
Node-ID und das ausgewählte Mesh gebunden ist. Verbindungen zu `.sbm`-Zielen sowie über
konfigurierte Mesh-Subnetz- und Exit-Routen werden zusätzlich gegen die Port-Capabilities
dieses Tickets geprüft; ohne passende `tunnel:ssh`, `tunnel:port:<PORT>`- oder explizit
vergebene `tunnel:any`-Capability wird die Verbindung abgelehnt. Eine konfigurierte lokale
Capability-ACL kann den Zugriff zusätzlich einschränken. Alte Ticket-Caches ohne gebundene
Subject-Node-ID werden abgelehnt; nach einer Einladung muss der Peer nach der Admin-Freigabe
erneut `sb-mesh join <INVITE-URI>` ausführen.

Diese Prüfung autorisiert die lokale SOCKS-Proxy-Instanz. Sie ersetzt keine authentisierte
Peer-Identität oder serverseitige Ressourcen-ACL am Ziel. Der experimentelle TCP-Port-Share
bindet ausschließlich an `127.0.0.1` und ist ein lokaler Entwicklungs-Forwarder, kein Mesh-
oder Internet-Ingress. Remote-Portfreigabe bleibt gesperrt, bis ein authentisierter,
verschlüsselter Mesh-Transport und serverseitige Ressourcenautorisierung integriert sind.
Das gesamte `sb-mesh`-Protokoll ist nicht extern auditiert.

---

## 📦 Lokaler Build & Schnellstart

Aus dem Suite-Workspace-Root (Rust/Cargo erforderlich):

```bash
cargo install --path tools/sb-mesh --force
```

---

## 💻 Benutzung

```bash
# Interaktive TUI-Zentrale starten
sb-mesh tui

# Mesh Daemon im Hintergrund starten (Port 51820)
sb-mesh daemon --port 51820

# Neuen Peer via Pairing-Token hinzufügen
sb-mesh pair --token <TOKEN>

# Invite einlösen; Zugriff wird erst nach lokaler Admin-Freigabe erteilt
sb-mesh join <INVITE-URI>
sb-mesh rbac pending --mesh <MESH>
sb-mesh rbac approve <REQUEST-ID> --mesh <MESH>
# Alternativ: sb-mesh rbac deny <REQUEST-ID> --mesh <MESH> --reason "..."

# Status und verbundene Peers prüfen
sb-mesh status
```

Eine Einladung legt zunächst nur einen persistenten Beitrittsantrag an. Der Mesh-Server stellt
vor der Freigabe keinen Mitgliedseintrag und kein Ticket aus. Ein Administrator des lokalen
Mesh-Hosts kann Anträge mit `rbac pending`, `rbac approve` und `rbac deny` verwalten; Freigaben
werden dem aus `USERNAME` beziehungsweise `USER` gelesenen Prozesskonto im Mesh-Audit-Log
zugeordnet. Diese Kennung ist Audit-Metadatum, keine kryptographische Admin-Authentisierung;
die Freigabe setzt lokalen Zugriff auf den geschützten Mesh-State voraus. Nach der Freigabe
muss der Peer `sb-mesh join <INVITE-URI>` erneut ausführen, um sein Ticket zu erhalten.
Rolle, Gruppen und Capabilities des Antrags stammen ausschließlich aus dem serverseitig
gespeicherten Invite; gleichnamige Claims aus dem vorgelegten Token werden ignoriert. Bei
Genehmigung werden die Invite-Capabilities vergeben und Gruppenrechte ergänzend angewendet.

### Ressourcen-ACL-Kern

`MeshTransport::check_object_access` ist der sichere Einstieg für Objektprüfungen innerhalb
des Mesh-Prozesses: Der Transport ist an genau ein Mesh gebunden, verlangt einen registrierten
Peer im Zustand `Connected`, validiert dessen kanonischen 32-Byte-Public-Key und ordnet ihn
einem eindeutigen Directory-Gerät des Katalog-Meshs zu. `AccessContext` ist nicht serialisierbar
und kann von Aufrufern nicht mit
beliebigen Principals erzeugt werden; Nutzer- und Gruppenrechte werden aus der Gerätebindung
und dem Directory aufgelöst. Der Aufrufer muss den Peer-Schlüssel aus dem authentisierten
Transportpacket beziehen, nicht aus RPC-/Request-Parametern.

Vor jeder solchen Objektprüfung wird die Mesh-RBAC-Datei frisch, größenbegrenzt und ohne
Erzeugung eines Default-Speichers geladen. Mesh-Bindung, eindeutige Mitgliedschaft, Ablaufzeit
und Widerruf werden erneut geprüft; fehlende, beschädigte oder mehrdeutige RBAC-Daten verweigern
den Zugriff. Ein RBAC-Widerruf greift damit beim nächsten Aufruf der Objektprüfung auch dann,
wenn das Directory-Gerät noch nicht deaktiviert wurde.

Das ist noch keine fertige Remote-Directory-API oder Ressourcen-Auslieferung: Der
Katalog-Replikationsstream filtert Metadaten weiterhin nicht anhand der Objekt-ACLs und
`PayloadReference` wird noch nicht als autorisierter Dateiinhalt ausgeliefert. Der Desktop ist
noch nicht mit diesem Objektprüfungsdienst verbunden. Bis diese Pfade integriert und
negativ getestet sind, dürfen Katalog-/Port-Share-Funktionen nicht als produktive
Ressourcenfreigabe gelten.

### Runtime-Status für `sb daemon`

Während `sb-mesh daemon` läuft, veröffentlicht er jede Sekunde einen Snapshot seiner aktiven Mesh-Konfiguration und des tatsächlichen `PeerTable` nach `~/.sb-mesh/runtime-status.json`. `sb daemon` liest nur Snapshots, die höchstens fünf Sekunden alt und schema-validiert sind; fehlt ein Snapshot oder ist er ungültig/veraltet, wird Mesh als offline beziehungsweise unavailable gemeldet. Peer-RTT und Handshake-Zeit werden nur als bekannt ausgegeben, wenn die Laufzeitwerte vorhanden sind. Der Export meldet das experimentelle `sb-mesh`-Protokoll und behauptet keinen aktiven WireGuard-/Noise_IK-Tunnel.

---

## 📄 Lizenz
Lizenziert unter der [MIT Lizenz](LICENSE).  
Copyright (c) 2026 Skulls & Bones Lab <dev@skulls-and-bones.org>.
