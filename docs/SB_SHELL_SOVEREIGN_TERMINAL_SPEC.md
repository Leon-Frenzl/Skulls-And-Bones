# S&B Shell und GPU-Terminal — Produktgrenzen und Zielbild (Ausgegliedert)

> **Status:** Ausgegliedert / Historische Spezifikation  
> **Hinweis:** `sb-shell` und `skully` wurden im Zuge der 14-Core-Konsolidierung vollständig aus der Core-Suite ausgegliedert. Skulls & Bones setzt auf native OS-Shells und Terminals. Dieses Dokument dient ausschließlich als historische Referenz.  
> Maßgebliche Quellen: [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`../brain/decisions.md`](../brain/decisions.md).

## 1. Bestätigte Produktgrenze

- **`sb-shell`** ist als eigenständige, plattformübergreifende Kommando-Shell mit eigener Sprache/Skriptsprache vorgesehen.
- **`skully`** ist der davon getrennte GPU-beschleunigte Terminal-Emulator.
- Ein Terminal-Emulator stellt ein Terminalfenster und eine PTY-/Terminal-Session bereit; eine Shell interpretiert Befehle und Skripte. Diese Verantwortlichkeiten sollen nicht unter einem Produktnamen oder einem unbelegten Implementierungsstatus zusammengefasst werden.
- `sb-desktop` kann Shell und Terminal als Clients/Integrationen verwenden, soll aber nicht deren Fachlogik duplizieren.

## 2. Sichtbarer Repository-Stand

- Unter `tools/sb-shell/` existiert eine Rust-Projektstruktur mit terminal-/PTY-bezogenen Abhängigkeiten. Die vollständige Sprache, Grammatik, Auswertungsregeln und Kompatibilitätsgarantien sind noch festzulegen.
- `tools/skully/` ist das separate Projekt für GPU-Terminal-Funktionen; seine Existenz belegt keine vollständige, releasevalidierte Plattformabdeckung.
- Build- und Packaging-Inventare müssen Shell und Emulator als getrennte Produkte abbilden.
- Das Root-Cargo-Workspace allein ist kein Verifikationsnachweis für nicht eingebundene Anwendungen und Plattformziele.

## 3. Ziele für `sb-shell`

Vor Stabilisierung der Sprache festlegen und testen:

1. Tokenisierung, Grammatik, quoting/escaping und Unicode-Verhalten.
2. Variablen, Expansion, Pipelines, Redirection, Exit-Codes und Fehlersemantik.
3. Prozessstart und Environment-Inheritance pro Betriebssystem.
4. Skriptformat-/Sprachversionierung und deterministisch definierte Teilbereiche.
5. Grenzen von Dateisystem-, Netzwerk- und Child-Process-Berechtigungen; keine implizite Sandbox behaupten.
6. Parser- und Executor-Tests einschließlich ungültiger und adversarialer Eingaben.

## 4. Ziele für `skully`

Die Terminal-App soll Rendering, Eingabe und Terminal-/PTY-Integration kapseln; sie darf nicht als Ersatz für die Shell-Implementierung behandelt werden. Plattformabdeckung, GPU-Fallback, Tastatur-/IME-Unterstützung, Resize, Clipboard und Terminal-Protokollkompatibilität sind unabhängig zu verifizieren.

## 5. Release- und Dokumentationsregeln

- Keine Performance-Werte oder Aussagen wie „vollständiger Emulator“, „Pure Rust“, „produktiv“ oder „deterministisch“ ohne klaren Scope und reproduzierbare Tests.
- Installer, Binary-Namen, Versionsmetadaten und Suite-Manager müssen getrennte Produktgrenzen spiegeln.
- Die Suite-Zielarchitektur verwendet einzeln versionierte Tools und signaturgeprüfte Artefakte aus dem öffentlichen Sovereign Mesh; das ist kein Nachweis des gegenwärtigen Releasepfads.
