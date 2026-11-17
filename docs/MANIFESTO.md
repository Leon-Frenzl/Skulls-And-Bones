# Skulls & Bones — Manifest

> **Souveräne Werkzeuge. Klare Grenzen. Nachprüfbare Sicherheit.**

Dieses Manifest beschreibt die Motivation und Richtung von Skulls & Bones. Es ist kein Implementierungsnachweis, Sicherheitszertifikat oder Release-Versprechen. Für Zielarchitektur und bekannte Abweichungen gilt [`ARCHITECTURE.md`](./ARCHITECTURE.md); für bestätigte Produktentscheidungen siehe [`../brain/decisions.md`](../brain/decisions.md).

## Warum Skulls & Bones?

Entwickler und Teams sollten die Kontrolle über ihren Quellcode, ihre Identitäten, ihre Geheimnisse und den Betrieb ihrer Infrastruktur behalten können. Dafür braucht es Werkzeuge, deren Verhalten verständlich und überprüfbar ist — und die auch ohne einen bestimmten kommerziellen Cloud-Anbieter sinnvoll bleiben.

Souveränität bedeutet nicht automatisch, dass jedes Werkzeug vollständig offline funktioniert oder keinerlei externe Abhängigkeit hat. Es bedeutet, Abhängigkeiten sichtbar zu machen, wichtige Schlüssel und Daten unter eigener Kontrolle zu halten und einen Wechsel ermöglichen zu wollen.

## Was wir bauen

Skulls & Bones ist eine modulare Suite eigenständiger Werkzeuge für Entwicklungs- und Infrastruktur-Workflows:

- `sb` startet und verwaltet Tools; es ersetzt nicht deren Fachlogik.
- `sb-core` definiert gemeinsame Typen, DTOs, Vault-Kryptografie und versionierte IPC-Verträge.
- Ein lokaler Suite-Daemon verbindet Tool-Services und exponiert sichere Schnittstellen für Clients.
- 14 konsolidierte Kern-Tools: Die Suite konzentriert sich auf fokussierte, modulare CLI-Tools, Daemons und gemeinsame Bibliotheken.
- `sb-code` soll die maßgebliche Versionsverwaltung werden. Alte Git-Historie wird nicht in die neue Versionsgeschichte importiert.

Frühere Desktop-Frontends (`sb-desktop`, `sb-studio`, `sb-workbench`, `netgrid`), UI-Frameworks (`skel`, `sb-ui`) sowie separate Shell-/Terminal-Projekte (`sb-shell`, `skully`) wurden aus der Core-Suite ausgegliedert. Der autoritative Produktbestand und die Systemarchitektur stehen in der [Zielarchitektur](./ARCHITECTURE.md).

## Unsere Prinzipien

### Souveränität

Quellcode, Identitäten, Schlüssel und Betriebsentscheidungen sollen unter Kontrolle ihrer Betreiber bleiben. Die geplante Quelle der Wahrheit für Code ist das Sovereign Dev Mesh mit `sb-code`; pro Tool sind eigene logische Working Spaces vorgesehen. Replikation und Topologie sind offen.

### Modularität

Ein Tool, eine klare Zuständigkeit. Unabhängige Versionen und austauschbare Clients sind wertvoller als ein Sammelprogramm, das alle Funktionen selbst implementiert.

### Sicherheit ohne Superlative

Sicherheit entsteht aus expliziten Trust Boundaries, begrenzten Berechtigungen, sorgfältiger Fehlerbehandlung und nachvollziehbaren Tests. Kryptografische Primitive allein beweisen keine sichere Gesamtarchitektur. Begriffe wie „Zero Trust“, „Zero Trace“, „air-gap“, „unbrechbar“ und „produktionsreif“ dürfen nicht als pauschale Garantie verwendet werden.

### Offenheit und Ehrlichkeit

Wir unterscheiden klar zwischen beschlossenem Ziel, vorhandenem Code, geprüftem Verhalten, Vorschlag und historischem Kontext. Ein Feature wird nicht durch ein Badge, einen Plan oder eine Website-Illustration real.

## Distribution und Vertrauen

`sb` soll signierte, versionierte Tool-Artefakte aus dem öffentlichen Sovereign Mesh beziehen. Ein gepinnter öffentlicher Schlüssel verifiziert die Signatur der exakten Artefaktbytes; der Mesh-Transport selbst ist kein Trust Anchor. Diese Verifikationskette muss vor der automatisierten Installation umgesetzt und geprüft sein.

Die zuerst vereinbarte Betriebsgrenze erlaubt Public-Webdienst, Mesh-Instanzen und Signierer auf demselben Host, verlangt aber getrennte Prozesse und OS-Servicekonten. Root und Kernel gelten zunächst als vertrauenswürdig. Unabhängiges FROST-/Threshold Signing ist ein späteres Härtungsziel.

## Wohin es geht

Wir arbeiten schrittweise: Produktinventar und belegbare Release-Grenzen, gemeinsame Service-Verträge, Mesh-Identitätstrennung, signierte Artefaktverteilung und ein belastbares lokales `sb-code`-Modell. Erst danach folgen verteilte Working Spaces und weitergehende Replikationsmodelle.

Fortschritt heißt nicht: mehr große Versprechen. Fortschritt heißt: ein klarer Vertrag, ein konkreter Implementierungsschritt und ein reproduzierbarer Nachweis.
