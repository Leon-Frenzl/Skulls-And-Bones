# Betriebs-Referenz: Gehärtete Konfiguration (Ist-Stand)

Referenz für Operatoren. Quelle der Wahrheit im Code: `tools/sb-mesh/src/service.rs` (`SYSTEMD_HARDENING`),
`tools/sb-mesh/src/bootstrap.rs`, `tools/sb-mesh/src/network.rs`. Platzhalter: `<ADMIN_USER>`, `<VPS_IP>`.

## Dienste (systemd)

`sb-mesh bootstrap` und `sb-mesh service install` erzeugen Units mit:

| Setting | Zweck |
|---|---|
| `User=sb-mesh`, `StateDirectory=sb-mesh` (0700), `UMask=0077` | Kein root; Daten unter `/var/lib/sb-mesh` |
| `NoNewPrivileges`, `CapabilityBoundingSet=` (leer) | Keine Rechte-Eskalation |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices` | Read-only OS, isolierte Pfade |
| `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | Kernel-Oberfläche gesperrt |
| `RestrictAddressFamilies`, `RestrictNamespaces`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `LockPersonality` | Angriffsfläche reduziert |

`deploy-anchor.sh` legt den Systemuser an und installiert dieselbe Unit. Die Dateien liegen unter
`~/.sb-mesh/tenants/<mesh>/deploy/` (nicht mehr im aktuellen Verzeichnis).

## Einladungen

- Standard: **72 h, einmalig** (`sb-mesh invite create`: 24 h / 1 Nutzung).
- Die URI enthält ein 256-Bit-Secret; der Server speichert nur dessen SHA-256 und vergleicht zeitkonstant.
  Alte `sig-…`-Tokens werden nicht mehr akzeptiert.
- Ausgabe in `~/.sb-mesh/invites/<id>.uri` (0600). Auf stdout nur mit `--print`.

## Overlay-Netze

- `sb-mesh bootstrap` ohne `--cidr` wählt den nächsten freien /16 aus `10.240.0.0/12`.
- `create_network` lehnt überlappende CIDRs ab.

## Firewall / Bindung

- UFW: `22/tcp`, `80/tcp`, `443/tcp`, `58888/udp`; alles andere eingehend gesperrt.
- `sb-code syncd` bindet nur an `127.0.0.1:58832`; Zugriff ausschließlich über das Mesh.
- SSH: kein Root-Login, kein Passwort-Login, `AllowUsers <ADMIN_USER>`.

## Diagnose

`sb doctor` prüft zusätzlich: `ssh`-Schatten im PATH, defekte Workspace-Links (`--fix` legt das Ziel an)
sowie Konfigurationsprüfungen.
Das Cargo-Paket heißt `sb-cli` (crates.io-Name, `cargo build -p sb-cli`), das Binary `sb`; der Name `sb` ist auf crates.io bereits vergeben.
Ausgabe ohne TTY ist automatisch farbfrei.

## Noch offen

Umgesetzt: `sb server provision <host> --pubkey <datei> [--binaries <dir>] [--print-script]`
(Admin-User, SSH-/UFW-Härtung, gehärtete Units, Mesh-Bootstrap), `sb code serve --mesh <name>`,
`--json` für `sb status` und `sb-mesh network list`, `sb doctor` (ssh-Shadowing, defekte Workspace-Links,
`.npmrc`-Hinweis). Einladungen: Secret nur als Datei (`~/.sb-mesh/invites`, 0600), 72 h / 1 Nutzung,
`--print` nur explizit.

Noch offen: signierte Release-Artefakte (`sb install`) und Cross-Build (bis dahin `--binaries`),
dokumentierter Bootstrap-Pfad für den Quellcode-Transport, `--json` für `sb-node route list`
(siehe `SOVEREIGN_FLEET_ARCHITECTURE.md`).
