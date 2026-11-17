# `sb` — Suite-Launcher und Tool-Manager

`sb` ist der Einstiegspunkt für die modularen Skulls-&-Bones-Tools. Seine Zuständigkeit ist, optionale Tools zu entdecken, zu installieren, zu aktualisieren, zu starten und deren Kompatibilität sichtbar zu machen — nicht deren Fachlogik zu übernehmen.

## Installations- und Release-Vertrag

- Zum ersten lokalen Einstieg in die CLI aus dem Repository-Root:
  `cargo install --path tools/sb --bin sb`. Danach `sb --help` und `sb status`
  ausführen. Das benötigt Rust/Cargo und eine lokale Quellkopie, aber kein
  installiertes Git.
- `sb install <tool>` installiert optionale Tool-Binaries aus signierten
  Release-Artefakten; es installiert nicht die initiale `sb`-CLI selbst.
- `sb install <tool>` bezieht vorkompilierte Plattformarchive über HTTPS. Rust, Cargo und crates.io werden auf dem Zielsystem nicht benötigt.
- Release-HTTP-Verbindungen verwenden ein festes Verbindungs-Timeout von 5 Sekunden sowie 30 Sekunden für Lesen und Schreiben. `SB_RELEASE_URL` muss weiterhin HTTPS sein; HTTP-Dev-Server werden abgelehnt.
- Vor dem Parsen verifiziert `sb` die exakten Bytes von `release-manifest.json` mit einem fest eingebetteten Ed25519-Public-Key. Das signierte Manifest enthält Version, Rust-Target, Artefaktpfad und SHA-256.
- Vor der Installation prüft `sb` zusätzlich den SHA-256-Hash des Archivs und liest ausschließlich angeforderte reguläre Binaries aus dem signierten ZIP/TAR.GZ. Keine Archivpfade werden direkt in das Dateisystem entpackt.
- Binaries werden nach `~/.sb/bin/` in eine temporäre Datei im Zielverzeichnis geschrieben, synchronisiert und erst danach ersetzt. Auf Unix werden ausführbare Rechte gesetzt.
- Das Mesh oder der HTTPS-Server ist Transport, nicht Vertrauensanker. `sb install` und `sb update` vergleichen die signierte Release-Version mit dem lokalen Installations-Ledger und blockieren einen Downgrade standardmäßig. Eine bewusste Rückstufung benötigt `--allow-downgrade`; `--force` allein hebt den Downgrade-Schutz nicht auf. Ein fehlendes Ledger (z. B. bei einer Erstinstallation) liefert naturgemäß keinen lokalen Versionsschutz.
- Ein beschädigtes oder nicht lesbares Ledger bricht Installation/Update ab, statt stillschweigend einen neuen Versionsstand anzunehmen. Ledger, Manifest und Signatur müssen nach der Binary-Installation erfolgreich geschrieben werden; Schreibfehler werden gemeldet.

### Release erzeugen

```text
sb release pack --version v0.2.1 --target x86_64-unknown-linux-musl --input-dir target/x86_64-unknown-linux-musl/release --output-dir dist --format tar.gz
sb release sign --manifest dist/release-manifest.json --key-file <privater-seed>
```

`pack` nimmt nur reguläre Binary-Dateien auf, die im Inventar für das angegebene Target als Release-Binary geführt werden. Es erstellt das Archiv und aktualisiert `release-manifest.json`; wiederholte Aufrufe für weitere Targets ergänzen dasselbe Manifest. `sign` signiert dessen exakte Bytes und schreibt eine Hex-Ed25519-Signatur nach `release-manifest.json.ed25519`. Der Key muss 32 rohe Seed-Bytes oder 64 Hex-Zeichen enthalten und dessen Public Key muss dem im Installer gepinnten Release-Key entsprechen. Der private Key gehört weder ins Repository noch in das Release-Artefakt.

Ein Verzeichnis mit signiertem Manifest und Artefakten kann mit `sb-proxy`
statisch veröffentlicht werden, zum Beispiel
`sb proxy static releases.example.com <release-verzeichnis>`. Der Standard-
Release-Endpunkt des Installers ändert sich dadurch nicht automatisch; dafür
muss der Client gezielt mit `SB_RELEASE_URL` auf den veröffentlichten HTTPS-
Host konfiguriert werden. Ein unverschlüsselter HTTP-Endpunkt wird vom
Installer absichtlich abgelehnt.

Der Release-Key ist ein einzelner, im Installer gepinnter Vertrauensanker. Vor einer Veröffentlichung muss der Betreiber die Seed-Datei offline und verschlüsselt sichern, eine Wiederherstellung auf einem separaten Arbeitsverzeichnis prüfen und den Public Key/Fingerprint mit dem im Quellcode gepinnten Schlüssel abgleichen. Eine kompromittierte oder verlorene Seed-Datei erfordert eine koordinierte Client-Aktualisierung mit neu gepinntem Schlüssel; es gibt derzeit weder überlappende Schlüssel noch eine autonome Rotation oder Recovery-Verteilung. Deshalb Schlüsselverlust/-kompromittierung als Release-Stop behandeln und vor produktivem Betrieb einen getesteten Rotation-/Recovery-Prozess festlegen. Seed-Dateien und Testschlüssel dürfen nicht in Repository, Logs oder Artefakte gelangen.

Die Produktdefinition liegt ausschließlich in [`../../product-inventory.json`](../../product-inventory.json). Suite-Installer und lokale Release-Kommandos wählen installierbare Binaries und unterstützte Targets daraus; fremde `sb-*`-Dateien und Desktop-/Bibliotheksprodukte werden nicht paketiert. Historische Bezeichnungen `sb-ssh` und `sb-vault` sind keine installierbaren Produkte.

Reifegrade sind `planned` (geplant), `prototype` (Prototyp), `implemented_not_releasevalidated` (implementiert, nicht releasevalidiert) und `releasevalidated` (releasevalidiert). Letzterer Status bleibt bis zu nachgewiesenen Artefakt-, Plattform- und Testläufen ungesetzt.

### Lokaler Service-Katalog

```text
sb daemon
sb catalog
sb catalog --json
```

`sb catalog` ruft das Produktinventar über `suite.catalog` und den lokalen, token-authentisierten Suite-Daemon ab. JSON-RPC transportiert `api_version: 1`; übergroße Frames, doppelte `Content-Length`-Header, unzulässige API-Versionen und Fehlerantworten werden abgelehnt. Externe Clients und Frontends können denselben RPC-Endpunkt nutzen. `suite.status` unterscheidet tatsächliche Mesh-Runtime-Daten von Komponenten, die nicht aktiv abgefragt wurden.

Der Installer erwartet Manifest und Signatur unter
`https://skulls-and-bones.org/bin/release-manifest.json` sowie
`.../release-manifest.json.ed25519`; Artefaktpfade müssen einfache Dateinamen
im selben Verzeichnis sein. Die tatsächliche Online-Bereitstellung und ein
Live-Installationslauf sind noch nicht nachgewiesen. Bis dahin ist der lokale
Quell-Build der verlässliche Bootstrap-Weg; nicht vorhandene Installerskripte,
Paketmanagerpakete oder ein crates.io-Release sind keine unterstützten
Alternativen. Der lokale Rollback-Schutz hängt am beschreibbaren Ledger und
schützt nicht gegen einen lokalen Angreifer, der dieses Ledger löscht oder
manipuliert; die Release-Signatur schützt weiterhin die Artefaktintegrität,
nicht die Aktualität des lokalen Zustands.

### Website aus dem Mesh veröffentlichen

Auf dem öffentlichen Gateway einmalig eine HTTPS-Tunnel-Route registrieren und
`sb proxy start` betreiben:

```text
sb proxy tunnel-route add app.example.com --node hostinger-node
```

Auf dem Mesh-Rechner im Webprojekt veröffentlichen:

```text
sb web publish app.example.com
```

`sb web publish` erkennt npm/pnpm/yarn/bun anhand der Projektmetadaten und
Lockdateien, führt das `build`-Skript aus und startet danach `start` (bevorzugt)
oder `preview`. Der Server wird auf Loopback gebunden, per HTTP geprüft und
während der Sitzung durch den ausgehenden Mesh-Tunnel verfügbar gehalten.
Standardport ist 3000; `--project-dir` und `--port` können angepasst werden.
Mit `Ctrl+C` werden Tunnel und Produktionsserver beendet.

Voraussetzungen sind ein vorhandenes `package.json` mit `build` und `start`-
oder `preview`-Skript, installierte Projektabhängigkeiten, eine konfigurierte
Tunnel-Route auf dem Gateway, laufender `sb-proxy`, passende Mesh-Erreichbarkeit
und DNS, das auf das öffentliche Gateway zeigt. TLS wird vom Proxy verwaltet.
Die Gateway-Route ist absichtlich ein separater einmaliger Schritt, weil der
Mesh-Rechner keine Proxy-Konfiguration auf dem entfernten Gateway ändern kann.
Vor dem Build prüft `sb web publish`, ob die Domain per HTTPS erreichbar ist
und erkennt die bekannte Gateway-Antwort für eine fehlende Tunnel-Route. Diese
Prüfung validiert weder die entfernte Konfiguration vollständig noch beweist
sie, dass die erreichbare Route dem gewünschten Projekt zugeordnet ist; sie
ersetzt daher nicht die Gateway- und Mesh-Konfiguration.

`sb web publish` ist der empfohlene, projektbezogene Veröffentlichungsweg.
`sb proxy link` und Tunnel-Kommandos bleiben als fortgeschrittene
Proxy-Grundfunktionen verfügbar.

## Aktueller Status

Der lokale Installations- und Signierpfad ist implementiert. Eine automatisierte Release-Pipeline gibt es nicht mehr. Die Online-Veröffentlichung signierter Dateien nach `/bin` und ein Live-Installationslauf gegen das konfigurierte Release-Hosting müssen separat eingerichtet und verifiziert werden.

Das Installationsinventar ist auf tatsächlich gebaute Workspace-Binaries begrenzt. Ein systemeigener SSH-Client wird nicht als S&B-Binary ausgeliefert.

## Entwicklung und Prüfung

Alle 14 Core-Tools im Root-Cargo-Workspace werden mit `cargo test --workspace` und `cargo check --workspace` geprüft; für gezielte Änderungen am Release-Vertrag mindestens `cargo test -p sb-cli` und `cargo check -p sb-cli` ausführen. Ein veröffentlichter Release muss zusätzlich aus dem veröffentlichten Manifest und Archiv auf einem sauberen Client installiert werden; dieser Online-Nachweis steht noch aus.

Die langfristige Code-Quelle ist das Sovereign Dev Mesh mit `sb-code`. Der
Mesh-basierte Bezugs- und Erststartpfad ist noch nicht releasevalidiert.
