# CLI-Vereinheitlichungsstandard (`sb` Master CLI)

Dieses Dokument definiert die verbindliche Architektur für alle Kommandozeilen-Werkzeuge in **Skulls & Bones**. Ziel ist eine einzige, konsistente Operator-Oberfläche über `sb` ohne Zersplitterung in neue Binaries oder redundante Commands.

---

## 1. Grundprinzip: Eine CLI für alle Workflows

- **`sb` ist der einzige primäre Einstiegspunkt** für Entwickler, Administratoren und Endbenutzer.
- **Erstelle keine neuen CLI-Binaries.** Neue Funktionen gehören in bestehende `sb`-Subcommands oder als Sub-Aktion unter einer bestehenden Domäne in `tools/sb`.
- **Vermeide neue Top-Level-Commands.** Prüfe zuerst, welcher bestehende `sb`-Bereich die Funktion abdeckt.

---

## 2. Entscheidungsmatrix: Wohin gehört ein neues Command?

| Anwendungsfall | Ziel-Command in `sb` | Beispiel |
|---|---|---|
| Agent- & Daemon-Lebenszyklus (Start, Stop, Restart, Status, Install) | `sb agent` / `sb service` | `sb agent start`, `sb agent restart`, `sb service status` |
| Lokale & Remote-Updates (Workstation, VPS, Flotte) | `sb update` | `sb update`, `sb update --target srv490042` |
| Domänen-, Policy- & LAPS-Verwaltung | `sb domain`, `sb policy`, `sb laps` | `sb domain status`, `sb policy apply` |
| Benutzer- & Zertifikatsverwaltung | `sb user`, `sb ca`, `sb auth` | `sb user offboard`, `sb ca status` |
| Server-Zugriff, Tunnel & Kopplung | `sb ssh`, `sb tunnel`, `sb link` | `sb ssh exec`, `sb link` |
| Mesh, DNS & Reverse-Proxy | `sb mesh`, `sb dns`, `sb proxy` | `sb mesh status`, `sb dns status` |
| Projekt-Bootstrap & Secrets | `sb init`, `sb env`, `sb run`, `sb lease` | `sb env import`, `sb run -- <cmd>` |

---

## 3. Verbotene Anti-Patterns

1. **Kein neues Binary für Einzelaufgaben:** Erzeuge kein `sb-updater`, `sb-agentctl` oder `sb-vps` als separates Binary.
2. **Keine Rohbefehle in Nutzer-Workflows:** Zwinge Nutzer nicht zu `sc.exe start sb-node-agent`, `systemctl restart sb-dc` oder manuellen `scp`-Kommandos. Kapsele OS-Dienstmanager (`sc.exe`, `systemctl`, `launchctl`) einheitlich hinter `sb agent` und `sb service`.
3. **Keine unvollständigen Lebenszyklen:** Jede verwaltbare Komponente unterstützt einheitlich `install`, `start`, `stop`, `restart`, `status`, `update` und `uninstall`.
4. **Keine parallelen Alias-Hierarchien:** Führe nicht `sb node ...`, `sb agent ...` und `sb start ...` mit abweichendem Verhalten nebeneinander. Delegiere intern auf denselben Handler.

---

## 4. Konkreter Migrationsbedarf (Beispiele aus dem Betrieb)

- **Dienst-Steuerung:** `sb agent start`, `sb agent stop` und `sb agent restart` müssen den nativen Dienstmanager (`sc.exe` auf Windows mit UAC-Hinweis/Elevation, `systemctl` auf Linux) direkt ansprechen, statt nur `install | status | update | uninstall` anzubieten.
- **VPS- & Lokal-Updates:** `sb update` soll sowohl die lokale Workstation (`~/.sb/bin`) als auch konfigurierte Server (`servers.toml`) konsistent aktualisieren können, statt manuelle Build- und Kopierschritte zu erfordern.

---

## 5. Checkliste vor jedem Pull Request

- [ ] Nutzt die Änderung einen bestehenden `sb`-Subcommand statt eines neuen Top-Level-Commands oder Binaries?
- [ ] Werden OS-spezifische Aufrufe (`sc.exe`, `systemctl`, `ssh`) vollständig innerhalb von `sb` / `sb-node` gekapselt?
- [ ] Sind Fehler- und Diagnosemeldungen im kanonischen `logfmt`-Format (`sb_core::logfmt`) umgesetzt?
- [ ] Ist der neue Subcommand in `docs/typ/sb/cli-unification.typ` bzw. der CLI-Hilfe berücksichtigt?
