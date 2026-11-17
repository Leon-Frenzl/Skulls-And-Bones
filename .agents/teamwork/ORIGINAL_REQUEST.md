# Original User Request

## Initial Request — 2026-10-26T17:48:15Z

Vollständige lokale Release-Validierung der 14 konsolidierten Skulls & Bones Kern-Tools sowie lückenlose Synchronisation aller Architektur-, Strategie- und Dokumentationsdateien (.md) auf den aktuellen Ist-Stand.

Working directory: c:/Users/leonf/Documents/Projekte/Skulls-And-Bones
Integrity mode: development

## Requirements

### R1. Lokale Release-Kette & Staging-Validierung
Führe einen vollständigen lokalen Build-, Signatur- und Staging-Installationslauf für die 14 konsolidierten Kern-Tools durch (`sb release pack`, Ed25519-Signierung, Prüfsummen-Verifikation und atomare Installation). Überprüfe dabei Downgrade-Schutz, Signatur-Integrität und Ausführbarkeit der Binaries. Stufe nach nachgewiesenem Erfolg die Reifegrade in `product-inventory.json` wahrheitsgemäß hoch.

### R2. Umfassende Dokumentations-Synchronisation (.md)
Aktualisiere alle Markdown-Dokumente im Workspace (`README.md`, `ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/QUALITY_GATES.md`, `docs/MANIFESTO.md`, `brain/README.md`, `brain/decisions.md`, `brain/backlog.md`, `brain/vision.md`, `brain/implementation_plan.md` sowie Tool-READMEs). Entferne sämtliche veralteten Aussagen über gelöschte Komponenten (`skel`, `skully`, `sb-shell`, `sb-ports`, `sb-securenet`, `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `sb-ui`) als aktive Suite-Bestandteile und beschreibe konsistent das autarke 14-Core-Ökosystem.

### R3. Quality-Gate-Integrität
Stelle sicher, dass nach allen Code-, Manifest- und Dokumentationsänderungen der vollständige Suite-Prüflauf (`npm run verify:suite`) inklusive `cargo fmt`, Cargo Workspace Checks, Unit-/Integrations-/E2E-Tests, Website-Build und Dependency-Audits fehlerfrei grün bleibt.

## Acceptance Criteria

### Release-Validierung & Inventar
- [ ] Signiertes Release-Paket wurde lokal erfolgreich gebaut, signiert und gegen den gepinnten Ed25519-Schlüssel verifiziert.
- [ ] Test-Installation via `sb install` / Staging-Verzeichnis funktioniert fehlerfrei; Downgrade- und Manipulationsschutz greifen fail-closed.
- [ ] `product-inventory.json` dokumentiert wahrheitsgemäß die erfolgreich validierten Release-Ziele und Reifegrade.

### Dokumentations-Konsistenz
- [ ] `README.md` und `ROADMAP.md` führen nur noch die 14 aktiven Kern-Tools und verweisen wahrheitsgemäß auf den konsolidierten Stand.
- [ ] `docs/ARCHITECTURE.md` und `brain/decisions.md` spiegeln die Ausgliederung der Desktop-Apps/Skel/Shell/Terminal wider.
- [ ] `brain/backlog.md`, `brain/vision.md` und `brain/implementation_plan.md` sind mit dem erreichten Verifikationsstand synchronisiert.

### Suite Quality Gate
- [ ] `npm run verify:suite` beendet erfolgreich mit Exit Code 0 (alle Cargo Workspace Tests grün, Website gebaut, 0 Schwachstellen).


## 2026-10-27T19:48:28Z

Implement and integrate `sb-ca` (unified PKI for OpenSSH and X.509 mTLS), `sb node bootstrap` (1-command remote server provisioning via `sb-ssh`), and `sb cockpit` (interactive terminal dashboard) in the Skulls-And-Bones workspace, followed by live verification on server `145.223.83.235`.

Working directory: C:\Users\leonf\Documents\Projekte\Skulls-And-Bones
Integrity mode: development

## Requirements

### R1. Unified PKI & On-Demand TLS Engine (`sb-ca`)
Develop a dedicated crate `tools/sb-ca` as both a reusable Rust library and a CLI tool. The engine must support dual-mode certificate issuance:
- **OpenSSH Certificates (RFC 4251):** Issue short-lived Ed25519 user and host certificates consumable by `sb-ssh`.
- **X.509 Certificates (RFC 5280 / TLS 1.3):** Issue mTLS and HTTPS certificates for mesh domains (`*.sbm`, `*.mesh`).
Integrate the X.509 engine into `sb-proxy` to enable automatic on-demand TLS certificate generation and caching for incoming requests.

### R2. Automated Remote Server Bootstrapping (`sb node bootstrap`)
Implement `sb node bootstrap <user@host>` orchestrating zero-touch remote onboarding using `sb-ssh` as the transport layer:
- Authenticate via standard OpenSSH credentials to fresh Linux hosts.
- Deploy the `sb-node` binary and initial configuration via SFTP.
- Register `sb-ca`'s public key in `/etc/ssh/sshd_config` under `TrustedUserCAKeys`.
- Install and start the `sb-node` systemd service and register the node with the mesh.

### R3. Operator Cockpit & Fleet HUD (`sb cockpit` / `sb hud`)
Build an interactive terminal user interface in `sb` (using `ratatui` or similar pure-Rust TUI framework) displaying:
- Live status and metrics of active daemons (`sb-node`, `sb-mesh`, `sb-proxy`, `sb-dns`).
- WireGuard mesh peers and routing status.
- Recent audit and access events.

### R4. Remote Target Integration & Live Verification
Deploy and verify the updated toolchain on the remote target server `192.0.2.1` (root / `[REDACTED]`). Confirm that the new binaries run, services supervise properly, and workspace test suites execute with zero failures.

## Acceptance Criteria

### Build & Test Suite Hygiene
- [ ] `cargo check --workspace` completes cleanly with 0 compiler errors and 0 warnings.
- [ ] `cargo test --workspace` passes 100% across all crates (existing and newly created `sb-ca`).

### Functional Verification
- [ ] `sb-ca` can generate both valid OpenSSH certificates and valid X.509 TLS certificates.
- [ ] `sb-proxy` terminates TLS and serves valid on-demand certificates for configured mesh domains without manual certificate generation.
- [ ] `sb node bootstrap` successfully provisions a remote Linux host and configures `TrustedUserCAKeys`.
- [ ] `sb cockpit` launches an interactive TUI, renders live daemon states, and exits cleanly.
- [ ] Remote verification on `145.223.83.235` executes with exit code 0 across the entire suite (`verify_all.sh` and `sb doctor`).
