# Handoff Report: Requirement R2 — Umfassende Dokumentations-Synchronisation (.md)

> **Agent:** `explorer_survey_docs` (teamwork_preview_explorer)  
> **Working Directory:** `c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/explorer_survey_docs/`  
> **Timestamp:** 2026-10-26T18:05:00Z  
> **Handoff Type:** Hard (Mission abgeschlossen)  

---

## 1. Observation

### A. Aktueller Workspace- und Crate-Bestand
1. **Root-Manifest (`Cargo.toml:3-18`):**
   ```toml
   members = [
       "tools/sb",
       "tools/sb-code",
       "tools/sb-forge",
       "tools/sb-key",
       "tools/sb-mesh",
       "tools/sb-node",
       "tools/sb-proxy",
       "tools/sb-db",
       "tools/sb-dns",
       "tools/sb-core",
       "tools/sb-app-contract",
       "tools/sb-app-protocol",
       "tools/sb-drive",
       "tools/sb-auth",
   ]
   ```
2. **Produktinventar (`product-inventory.json:16-339`):**
   Führt exakt 14 Produkte (`sb`, `core`, `app-contract`, `app-protocol`, `auth`, `code`, `db`, `dns`, `drive`, `forge`, `key`, `mesh`, `node`, `proxy`). `desktop_app_catalog.optional_native_clients` ist `[]`, `desktop_app_catalog.excluded_products` ist `[]`, `support_directories` ist `[]`, `separate_surfaces` enthält ausschließlich `website`.
3. **Physische Ordnerstruktur unter `tools/`:**
   Enthält exakt 14 Verzeichnisse korrespondierend zu den Workspace-Members, plus `README.md` und `sb-brand.css`. Es existieren **keine** Ordner `tools/sb-desktop`, `tools/sb-studio`, `tools/sb-workbench`, `tools/netgrid`, `tools/skel`, `tools/skully`, `tools/sb-shell`, `tools/sb-ports`, `tools/sb-securenet`, `tools/sb-ui`.
4. **Verifikationslauf (`npm run verify:suite`):**
   Befehl beendete mit Exit-Code 0. Alle 14 Crates im Root-Workspace wurden geprüft und getestet (882 Tests bestanden). Website-Build und Website-Dependency-Audit (0 Schwachstellen) waren erfolgreich.

### B. Veraltete Dokumentationsaussagen (Fundstellen)
1. **`README.md` (Z. 20–25, 28, 30, 62–78):**
   - Listet `sb-desktop`, `sb-studio`, `sb-workbench`, `sb-ui`, `netgrid`, `skully` im Verzeichnisbaum.
   - Nennt `sb-desktop`, `sb-shell`, `skully` als Suite-Komponenten (Z. 28).
   - Enthält kompletten Abschnitt „Desktop-Tools lokal entwickeln“ (Z. 62–78) mit nicht existierenden Skripten (`npm run dev:desktop`, `dev:studio`, `dev:workbench`, `tauri:studio`, `build:desktop`, `build:studio`, `build:workbench`).
2. **`ROADMAP.md` (Z. 23–27, 62, 71, 75, 77–78):**
   - Führt `sb-desktop`, `sb-shell`, `skully`, `SSH/NetGate` und `sb-vault` im Produktmodell auf.
   - Behauptet in Z. 71: *„Der Root-Cargo-Workspace prüft nicht automatisch jedes separate Desktop- oder Frontend-Projekt.“* (tatsächlich sind alle 14 Tools im Root-Workspace).
3. **`docs/ARCHITECTURE.md` (Z. 15, 26–31, 33–36, 38, 74, 95, 97, 105, 161–164, 179):**
   - Führt `sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`, `sb-ui`, `skel`, `sb-shell`, `skully` in Tabelle 2 als aktive Komponenten.
   - Nennt `sb-ports` und `sb-securenet` in Z. 38 als eigenständige Suite-Komponenten.
   - Enthält veraltete Abweichungen in Abschnitt 7 zu Skully vs. Shell und getrennten Cargo-Workspaces.
4. **`docs/QUALITY_GATES.md` (Z. 3, 8–12, 14):**
   - Behauptet, Gates leiten sich aus `desktop-application entries` und `SKEL E2E` ab.
   - Listet Tests für separate Desktop-Tauri-Manifeste, NetGrid-Lint und 6 Lockfile-Audits auf.
5. **`docs/MANIFESTO.md` (Z. 20–22):**
   - Nennt `sb-desktop`, `sb-shell`, `skully` unter „Was wir bauen“.
6. **`brain/decisions.md` (Z. 19–24, 28–30, 68–73):**
   - Enthält Entscheidungen zu Desktop-Apps, egui-Clients, AppContainer, Skel, Shell und Terminal als aktive Vorhaben, ohne deren Ausgliederung zu dokumentieren.
7. **`brain/implementation_plan.md` (Z. 78–86, 88–110, 128–139):**
   - Enthält Phasen 6 & 7 für Shell, Terminal und native Desktop-Clients; spricht in Z. 98 und Z. 130 von „22 bzw. 23 Produkten“ und separaten Tauri-/SKEL-Gates.
8. **`brain/backlog.md` (Z. 24, 25, 72–77, 85–86, 96–98, 103–105, 109):**
   - Enthält P3- und P4-Karten für Desktop- und Terminal-Features sowie F0-1/F1-4/F1-5/F2-3.
9. **`brain/vision.md` (Z. 42, 44, 115–127, 136):**
   - Führt Säule 6 („Standardisierte Entwickler-UI (sb-ui, sb-desktop, Website)“) und Desktop-Tauri-Frontends in der Nachweistabelle.
10. **`tools/README.md` (Z. 9–14, 21):**
    - Nennt `sb-desktop`, `sb-studio`, `sb-shell`, `skully`, `NetGrid` und behauptet unvollständige Workspace-Abdeckung.
11. **Spezifikationen (`docs/SB_PORTS_PORTSENTRY_SPEC.md`, `docs/SB_SHELL_SOVEREIGN_TERMINAL_SPEC.md`, `docs/SKEL_FRAMEWORK.md`):**
    - Beschreiben gelöschte Komponenten ohne Ausgliederungsvermerk.
12. **Tool-Dokumente (`tools/sb/README.md`, `tools/sb/TODO.md`, `tools/sb-auth/README.md`, `tools/sb-code/README.md`, `tools/sb-drive/TODO.md`, `tools/sb-forge/README.md`, `tools/sb-forge/TODO.md`, `tools/sb-key/TODO.md`, `tools/sb-node/README.md`, `tools/sb-proxy/README.md`, `tools/sb-proxy/TODO.md`):**
    - Verweisen auf Altnamen (`sb-ssh`, `sb-vault`, `sb-ports`), Desktop-Frontends oder `@skulls-and-bones/ui`.

---

## 2. Logic Chain

1. **Prämisse (Ist-Zustand Codebase):**
   - Gemäß Observation A sind alle Desktop-Apps (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), Web-UI-Frameworks (`skel`, `sb-ui`), Shell/Terminal (`sb-shell`, `skully`) und Altsysteme (`sb-ports`, `sb-securenet`) physisch aus `tools/` entfernt und in `product-inventory.json` sowie `Cargo.toml` bereinigt.
   - Der Workspace besteht stabil aus exakt 14 Werkzeugen, die alle im Root-Cargo-Workspace liegen und `npm run verify:suite` grün bestehen lassen.

2. **Befund (Dokumentations-Diskrepanz):**
   - Gemäß Observation B behaupten über 30 Dokumente weiterhin, dass Desktop-Apps, Skel, Skully und sb-shell aktive Bestandteile des Projekts sind oder demnächst nativ integriert werden.
   - `docs/QUALITY_GATES.md` beschreibt Prüfschritte (Tauri-Checks, NetGrid-Lint, SKEL-E2E), die im aktuellen `scripts/verify-suite.mjs` gar nicht mehr existieren.
   - Die Zählwerte („22 Produkte“, „23 Produkte“) widersprechen der realen Zählung von 14 Produkten.

3. **Inferenz:**
   - Um Anforderung R2 aus `ORIGINAL_REQUEST.md` vollständig zu erfüllen, ist eine systematische Dokumentations-Synchronisation aller 37 betroffenen Dateien erforderlich.
   - Die Dokumente müssen bereinigt werden, indem veraltete Komponenten als ausgegliedert deklariert, veraltete Befehle gelöscht und das autarke 14-Core-Ökosystem konsistent dargestellt wird.

---

## 3. Caveats

- **Keine eigenmächtige Quellcode-Modifikation:** Als Explorer-Agent wurden keine `.md`-Dateien außerhalb des Arbeitsverzeichnisses modifiziert. Der detaillierte Änderungsplan in `report.md` dient dem nachfolgenden Umsetzungsagenten als exakte Handlungsvorlage.
- **Forschungspapier `brain/forschung.md`:** Enthält Erwähnungen von `sb-securenet`, definiert sich jedoch explizit als theoretisches Forschungspapier und stellt klar, dass `sb-securenet` nicht als frei zugängliche Binärsoftware veröffentlicht wird. Diese Datei bedarf keiner inhaltlichen Änderung, da sie bereits wahrheitsgemäß formuliert ist.
- **Historische Dokumente (`brain/walkthrough.md`, `brain/continuation_summary.md`):** Wurden nicht gelöscht, sondern sollten mit einem klaren historischen Archiv-Header versehen werden, um Projektkontext zu bewahren.

---

## 4. Conclusion

- Das Ökosystem ist im Code bereits erfolgreich auf **14 autarke Kern-Tools** und eine separate Web-Oberfläche konsolidiert.
- Der Dokumentationsbestand hinkt diesem Stand hinterher und enthält in 37 Dateien noch veraltete Referenzen auf gelöschte Desktop-, UI-, Shell- und Port-Komponenten.
- In `c:/Users/leonf/Documents/Projekte/Skulls-And-Bones/.agents/teamwork/explorer_survey_docs/report.md` liegt eine vollständige, datei- und zeilengenaue Inventur mit konkreten Formulierungsvorschlägen für alle 37 Dateien vor.
- Die Umsetzung kann direkt durch einen Editor-/Writer-Agenten in 5 strukturierten Batches erfolgen.

---

## 5. Verification Method

Zur unabhängigen Überprüfung der Feststellungen:
1. **Bestand der Tools prüfen:**
   ```powershell
   Get-ChildItem -Directory tools/
   # Erwartung: Exakt 14 Verzeichnisse (sb, sb-app-contract, sb-app-protocol, sb-auth, sb-code, sb-core, sb-db, sb-dns, sb-drive, sb-forge, sb-key, sb-mesh, sb-node, sb-proxy)
   ```
2. **Aktuelle Suite-Verifikation ausführen:**
   ```powershell
   npm run verify:suite
   # Erwartung: Exit-Code 0, "Suite verification passed."
   ```
3. **Dokumentenbericht einsehen:**
   ```powershell
   Get-Content .agents/teamwork/explorer_survey_docs/report.md
   ```
