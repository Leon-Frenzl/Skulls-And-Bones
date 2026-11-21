= `sb` — CLI-Vereinheitlichung und Command-Architektur

== Zweck
Alle Benutzer- und Operator-Aktionen laufen über die zentrale Master-CLI `sb`. Entwickler erzeugen keine neuen eigenständigen CLI-Binaries und keine doppelten Top-Level-Commands.

== Verbindliche Regeln
- *Ein Einstiegspunkt:* Jeder neue Workflow gehört als Subcommand oder Option in `sb` (`tools/sb`).
- *Keine neuen CLI-Binaries:* Erstelle keine neuen Binary-Crates für CLI-Werkzeuge. Daemon- und Core-Crates (`sb-node`, `sb-proxy`, `sb-mesh`, `sb-dns`, `sb-auth`, `sb-ca`, `sb-key`) dienen nur als Laufzeit-Dienste oder Delegationsziele.
- *Bestehende Domains erweitern:* Prüfe vor jedem neuen Command, ob ein bestehender Bereich passt:
  - Dienst- und Agent-Steuerung (`start`, `stop`, `restart`, `status`): `sb agent` und `sb service`
  - Updates und Rollouts (Lokal und Flotte/VPS): `sb update`
  - Domäne, Richtlinien, Benutzer: `sb domain`, `sb policy`, `sb user`
  - Flotte, Server, Tunnel, SSH: `sb fleet`, `sb server`, `sb tunnel`, `sb ssh`
- *Keine OS-Rohbefehle für Nutzer:* Kapsele plattformspezifische Befehle wie `sc.exe`, `systemctl`, `launchctl` oder `scp` immer in `sb`. Zeige dem Nutzer einheitliche `sb`-Befehle statt Rohkommandos.
- *Delegation statt Duplikation:* Wenn ein Daemon-Crate (`sb-node`, `sb-mesh`) die Logik enthält, delegiert `sb` den Subcommand direkt dorthin und spiegelt den vollständigen Lebenszyklus (`install`, `start`, `stop`, `restart`, `status`, `update`, `uninstall`).

== Verifikation
- Prüfe bei jedem neuen Feature im Review, ob `tools/sb/src/main.rs` bereits einen passenden Subcommand besitzt.
- Dokumentiere neue Subcommands im zentralen Hilfetext von `sb` und in `docs/CLI_UNIFICATION_STANDARD.md`.

== Backup & Artefaktverteilung
- *Verschlüsselte DC-Backups:* `sb server backup --encrypt` (Argon2id + AES-256-GCM, Format `SBBK1`) und `sb server restore` sichern und rekonstruieren `domain`, `ca` und `auth` mit CWE-22-Pfadprüfung.
- *Zwei Release-Kanäle:* Öffentliche Nutzer beziehen signierte und SHA-256-geprüfte Bundles (`sb`, `sb-node`, `sb-dns`, `sb-proxy`, `console/dist`, OS-Logon-Module) über GitHub Releases. Organisationen mit eigenem DC nutzen optional `SB_RELEASE_BASE_URL` gegen `/v1/releases/<artifact>` auf dem eigenen Domain Controller.
