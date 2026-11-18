---
title: "S&B Forge — Secret-Bedrohungsmodell und Seal-Design"
document_type: security-design
status: blocker-identified-redesign-required
language: de
updated: 2026-10-03
---

# S&B Forge — Secret-Bedrohungsmodell und Seal-Design

> **Wichtiger Status:** Das frühere Design und das Legacy-Format liefern keinen belegten vertraulichen servergebundenen Secret-Speicher. Die CLI-Nutzung dieses Formats ist inzwischen fail-closed deaktiviert. Vorhandene Dateien bis zu einem geprüften Ersatz nicht für Produktions-Secrets verwenden und nicht als „serververschlüsselt“ behandeln.

## 1. Sicherheitsziele und Angreifer

Zu schützende Werte sind lokale Team-Secrets, Produktions-Credentials und Release-/Mesh-Schlüssel. Zu unterscheidende Angreifer:

1. Unbefugter Leser eines kopierten Vault-/Artefaktfiles.
2. Kompromittierter Prozess des öffentlichen Web-/Artefakt-Hosts.
3. Kompromittiertes lokales OS-Benutzerkonto.
4. Host-Root- oder Kernel-Kompromittierung.
5. Böswilliger oder kompromittierter Release-Maintainer.

Kein Modell darf behaupten, ein Prozess auf demselben Host könne vor kompromittiertem Root/Kernel schützen. Die vereinbarte erste Betriebsgrenze vertraut Root/Kernel; spätere Threshold-Signierung soll die Abhängigkeit von einem einzelnen Signierer reduzieren.

## 2. Relevante aktuelle Implementierungen

### Lokaler Forge-Vault

`tools/sb-forge/src/secret.rs` speichert Einträge als AES-256-GCM-Ciphertext in Environment-Vaultdateien und leitet den Schlüssel mit Argon2 aus einem lokal abgeleiteten Masterpasswort ab. Die Implementierung enthält in-memory Strings und ruft keine Prozessersetzung auf. Behauptungen zu physischer RAM-Löschung oder vollständiger Zero-Trace-Eigenschaft sind damit nicht belegt.

`tools/sb-core/src/vault.rs` enthält zusätzlich gemeinsame Argon2-/AES-GCM-Hilfsfunktionen und `VaultSession` mit Zeroize-Derives. Die gemeinsame Primitive hebt keine der übrigen Risiken auf (KDF-Parameter, Passwortquelle, Kopien, Fehlerpfade, Dateirechte, Backups und Versionierung müssen jeweils betrachtet werden).

### `sb-forge exec`

`tools/sb-forge/src/exec.rs` entschlüsselt Werte und startet den Zielbefehl als Kindprozess mit `.envs(&secrets)`. Daraus folgen praktische Eigenschaften:

- Secrets sind für den Zielprozess als Prozess-Environment vorgesehen.
- Diese Übergabe ist nicht fd-basiert und kein `execve`-Prozesswechsel.
- Secrets können im Arbeitsspeicher, in Prozessdiagnostik oder in Kindprozessen sichtbar sein; die tatsächliche Sichtbarkeit hängt vom Betriebssystem und den Rechten des Angreifers ab.
- Die Anwendung muss die Secrets selbst sicher verarbeiten und darf sie nicht loggen oder in Crash-Dumps exportieren.

„Nur kurz im RAM“, „nicht in `/proc` sichtbar“ und „zero trace“ nicht versprechen.

## 3. Blocker: Legacy `env.sealed` — jetzt deaktiviert

Die frühere Implementierung in `tools/sb-forge/src/seal.rs` wurde in der Konzeptdokumentation als Bindung an einen SSH-Host-Private-Key beschrieben. Tatsächlich leitete sie den AES-Schlüssel aus folgenden Werten ab:

```text
Konstante || server_host || server_name || environment || salt
```

`server_host`, `server_name`, `environment`, `salt`, Nonce und Ciphertext lagen im serialisierten Envelope. Ein privater Schlüssel des Servers wurde dabei nicht geladen oder verwendet. Ein öffentlicher Server-Fingerprint im Envelope schafft keine Geheimhaltung. **Daher war diese Ableitung keine serverseitige Schlüsselbindung und bot keine belastbare Vertraulichkeit gegen jemanden, der das Envelope auslesen konnte.**

Die betroffene Funktionalität ist inzwischen fail-closed deaktiviert: `env seal` erstellt/überträgt keine Datei, `exec --sealed` wird abgelehnt, und die Legacy-Entschlüsselungsfunktion gibt immer einen Fehler zurück. Tests prüfen diese Fälle. Alte Artefakte werden nicht automatisch gelöscht und sind weiterhin als nicht vertraulich zu behandeln.

Bis ein korrektes Verfahren implementiert und geprüft ist:

- `env seal`-/`env.sealed`-Funktionen nicht für Produktions-Secrets einsetzen.
- Keine `sealed-at-rest`, „nur vom Zielserver entschlüsselbar“ oder gleichwertige Sicherheitsbehauptung ausgeben.
- Keine ausgedachten SSH-Ed25519-zu-X25519-Konvertierungen oder HMAC-Konstruktionen hinzufügen. Kryptografische Bausteine müssen zu einem vollständigen, überprüften Protokoll gehören.

## 4. Designkriterien für ein zukünftiges Seal-Format

Ein künftiges Format muss mindestens festlegen:

- Serverseitigen Entschlüsselungs-Trust Anchor und dessen sicheren privaten Schlüsselbesitz.
- Ein standardisiertes, geprüftes KEM/AEAD-Verfahren samt eindeutiger Key-/Nonce- und Envelope-Versionierung.
- Authenticated context für Environment, Zielidentität, Ablauf/Version, Empfänger-Key-ID und Release-/Policy-Informationen.
- Authentizität des Herausgebers getrennt von Vertraulichkeit zum Empfänger.
- Replay-/Rollback-Regeln und Sperr-/Rotationsverfahren.
- atomare Ausgabe, restriktive Dateirechte, sichere Fehlerbehandlung und reproduzierbare Tests.
- klaren Boot-/Betriebsmodus: interaktives Unlock oder explizit akzeptierte maschinelle Entschlüsselbarkeit; kein Widerspruch zwischen unbeaufsichtigtem Start und „Master-Key existiert nirgends persistent“.
- Recovery und Backup, die nicht denselben kompromittierbaren Schlüsselraum duplizieren.

`sb-mesh` transportiert Pakete, ist aber allein kein Schlüsselmanagement- oder Signatur-Vertrauensanker. Mesh-Mitgliedschaft kann den Zugriff auf einen Dienst begrenzen; sie verschlüsselt keine lokal gespeicherte Datei gegen Prozesse/Root auf demselben Host.

## 5. Release-Signierung ist ein separater Anwendungsfall

Beschlossen ist: `sb` bezieht signierte, versionierte Tool-Artefakte aus dem öffentlichen Sovereign Mesh. Der Client vertraut einem gepinnten öffentlichen Release-Schlüssel. Das Artefakt muss vor Installation gegen die Signatur über exakt diese Bytes geprüft werden.

Beschlossene erste Betriebsgrenze:

- Public-Webdienst, Mesh-Instanzen und Signierer auf demselben physischen Host, aber getrennte Prozesse und OS-Servicekonten.
- Der Signierer-Key ist verschlüsselt und nur für autorisierte Releases entsperrt.
- Kein Datei- oder IPC-Zugriff des Public-Webdienstes auf den Signierer-Key.
- Root und Kernel gelten zunächst als vertrauenswürdig; diese Grenze schützt nicht vor ihrer Kompromittierung.
- Backup, Recovery und Schlüsselrotation vor produktiver Veröffentlichung definieren.
- FROST/Threshold Signing mit unabhängigen Teilnehmern ist späteres Härtungsziel; im Ist-Code ist kein entsprechender Release-Prozess belegt.

## 6. Geeignete erste Implementierungsschritte

1. Tests schreiben, die zeigen, welche Inputs der derzeitige Envelope-Schlüssel tatsächlich nutzt; die bestehende Production-Verwendung blockieren.
2. Threat Model und Key-Provisioning festlegen, bevor Algorithmuscode geschrieben wird.
3. Bibliothekskonstruktionen aus gepflegten Rust-Crates verwenden statt selbst erfundener Kryptografie.
4. Versionierte Testvektoren, falsche Empfänger, manipulierte Daten, falsches Environment, Replay und Rotation testen.
5. Signaturverifikation im `sb`-Installer vor Download-/Installationsautomatisierung fertigstellen.
6. Behauptungen auf Website, Roadmap, Forge-README und Release-Dokumentation erst nach überprüfbarer Umsetzung anheben.
