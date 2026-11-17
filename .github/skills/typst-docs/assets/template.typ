#set document(title: "sb-CRATE")
#set text(lang: "de", size: 11pt)
#set heading(numbering: "1.")

= Überblick
Kurzbeschreibung der Aufgabe des Crates.

= Öffentliche API
== `ExampleType`
Beschreibung, Invarianten, Fehlerverhalten.

= Beispiele
```rust
// minimal lauffähiges Beispiel
```

= Fehlerbehandlung

= Sicherheit
#table(
  columns: 5,
  [Kennung], [Fundstelle], [Schwäche], [Wahrscheinlichkeit], [Status],
  [CVE-YYYY-NNNNN / CWE-NNN], [`datei.rs:123`], [...], [...], [behoben],
)

= Abweichungen vom Standard
Keine. (Sonst: RFC/IEEE-Abschnitt, Begründung mit Kennung, Interop-Auswirkung.)

= Tests
