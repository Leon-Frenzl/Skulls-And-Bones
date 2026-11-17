---
title: "Skulls & Bones — AI Knowledge Base"
document_type: index
status: canonical
language: de
updated: 2026-10-10
---

# Skulls & Bones — Wissensbasis für Menschen und KI-Assistenten

`brain/` ist der kompakte, projektbezogene Einstieg für Maintainer und KI-Systeme. Er enthält Markenabsicht, bestätigte Architekturentscheidungen, technische Leitplanken und einen ehrlichen Überblick über relevante Implementierungen.

## Zuerst lesen

1. [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — verbindliches Zielbild, Zuständigkeiten, Ist-Abweichungen und offene Architekturfragen.
2. [`../docs/SKEL_FRAMEWORK.md`](../docs/SKEL_FRAMEWORK.md) — Historische Spezifikation für das inzwischen ausgegliederte Skel Web-UI-Framework.
3. [`decisions.md`](decisions.md) — vom Maintainer bestätigte Produkt- und Architekturentscheidungen (inkl. Ausgliederungsbeschluss).
4. [`implementation_plan.md`](implementation_plan.md) — priorisierte nächste Arbeitsschritte; keine Behauptung, dass etwas umgesetzt ist.
5. [`walkthrough.md`](walkthrough.md) — Historischer Code-Lagebericht zu den ehemals existierenden Desktop-Komponenten (ausgegliedert).
6. [`forge-complete-concept.md`](forge-complete-concept.md) und [`forge-secrets-design.md`](forge-secrets-design.md) — Forge-Ziel und Secret-Bedrohungsmodell.
7. [`../docs/MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md`](../docs/MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md) — Historischer Implementierungsvorschlag (Workbench inzwischen ausgegliedert).
8. [`continuation_summary.md`](continuation_summary.md) — historischer Sitzungsstand; nicht als aktueller Task- oder Projektstatus verwenden.
9. [`../docs/SB_MESH_APP_STANDARD.md`](../docs/SB_MESH_APP_STANDARD.md) — SB-MAP-Entwurf 0.1 für externe native Clients, Mesh-Services, App-Identität, Berechtigungen, SDK und Konformität.

## Quellenhierarchie

Bei Widersprüchen gilt, von stärker zu schwächer:

1. Explizite aktuelle Maintainer-Entscheidung.
2. [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) für das beschlossene Zielbild.
3. Tatsächlicher Quellcode und Konfiguration für den implementierten Ist-Stand.
4. Produktspezifikationen und Tool-READMEs; diese können Visionen, veraltete Namen oder unbelegte Aussagen enthalten.
5. Historische Pläne, Walkthroughs und Session-Zusammenfassungen.

Kein Dokument, Badge, TODO-Häkchen oder Marketingtext ersetzt die Prüfung des zugehörigen Quellcodes. Wenn Code und Dokumentation voneinander abweichen, als **Abweichung** dokumentieren; nicht so tun, als sei die gewünschte Funktion implementiert.

## Statusvokabular

- **Entschieden**: vom Maintainer ausdrücklich festgelegtes Ziel oder Produktverhalten.
- **Ist-Stand**: direkt im aktuellen Quellcode oder in der Projektstruktur gefunden; Build-/Lauffähigkeit ist damit nicht automatisch bestätigt.
- **Vorschlag**: technische Empfehlung, noch nicht freigegeben.
- **Offen**: Entscheidung oder Implementierung steht aus.
- **Historisch**: nützlicher Kontext, aber nicht maßgeblich für aktuelle Arbeit.
- **Geprüft**: nur verwenden, wenn ein konkreter Build, Test oder reproduzierbarer manueller Nachweis dokumentiert ist; immer Umfang und Zeitpunkt nennen.

## Markenabsicht

Skulls & Bones entwickelt souveräne Entwicklungs- und Infrastrukturwerkzeuge für Menschen und Teams, die ihre Codes, Identitäten, Secrets und Betriebsabläufe selbst kontrollieren wollen. Die Marke steht für:

- **Souveränität statt Plattformzwang**: selbst betriebene Infrastruktur und nachvollziehbare Kontrolle über Quellcode, Daten und Schlüssel.
- **Modularität statt Monolith**: eigenständige Tools mit klarer Fachzuständigkeit; `sb` ist Launcher und Manager.
- **Sicherheit als überprüfbare Eigenschaft**: konkrete Trust Boundaries, begrenzte Berechtigungen, gute Defaults und belegte Tests statt Superlative.
- **Nutzbare Entwicklerwerkzeuge**: ergonomische CLI-, Daemon- und Service-Workflows.

Begriffe wie „Zero Trust“, „Zero Trace“, „unbrechbar“, „produktionsreif“, „air-gapped“ oder „100% sicher“ nicht als pauschale Qualitätsgarantie verwenden. Aussagen immer auf Bedrohungsmodell und getestete Implementierung begrenzen.

## Regeln für KI-Assistenten

1. Vor Änderungen Zielarchitektur und betroffene aktuelle Implementierung lesen.
2. Uncommittete Änderungen als fremden/aktuellen Nutzerstand erhalten; nichts ungefragt zurücksetzen oder überschreiben.
3. Erst Ziel, Ist-Stand und offene Punkte unterscheiden; bei einer wesentlichen Produktentscheidung fragen.
4. Keine Funktionen aus Specs, TODOs oder Marketing ableiten, die der Code nicht belegt.
5. Sicherheitsbehauptungen prüfen. Keine CVE-Nummer erfinden und theoretische Schutzwirkung nicht als Laufzeitgarantie ausgeben.
6. Secrets, private Schlüssel, Kundendaten und unveröffentlichte Inhalte nicht in öffentliche Dienste oder externe Systeme übertragen.
7. Codeänderungen mit den passenden subsystemeigenen Checks validieren. Dokumentationsänderungen mindestens auf Links, interne Konsistenz und Whitespace prüfen.
8. Bestehende Tool-Grenzen respektieren; nicht zur Bequemlichkeit einen Suite-Monolithen bauen.

## Dokumentenregister

| Dokument | Zweck | Status |
|---|---|---|
| [`vision.md`](vision.md) | Vision, 6-Säulen-Zielbild und Code-Belegmatrix | Verbindlicher Visionsbeleg |
| [`backlog.md`](backlog.md) | Priorisierte Aufgaben (P0–P3) mit Akzeptanzkriterien | Verbindliches Aufgaben-Backlog |
| [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) | Zielarchitektur und Plan-/Ist-Abgleich | Maßgebliches Architekturziel |
| [`../docs/SKEL_FRAMEWORK.md`](../docs/SKEL_FRAMEWORK.md) | Historische Rahmenspezifikation des ausgegliederten Skel Web-UI-Frameworks | Historisch / Ausgegliedert |
| [`decisions.md`](decisions.md) | Bestätigte Entscheidungen und offene Beschlüsse | Maßgebliches Entscheidungsregister |
| [`implementation_plan.md`](implementation_plan.md) | Empfohlene Reihenfolge der nächsten Arbeiten | Aktueller Arbeitsrahmen |
| [`walkthrough.md`](walkthrough.md) | Historischer Implementierungsüberblick der ausgegliederten Desktop-Apps | Historisch / Archiviert |
| [`forge-complete-concept.md`](forge-complete-concept.md) | Forge-Zuständigkeit und Workflow-Ziel | Konzept, keine Release-Zusage |
| [`forge-secrets-design.md`](forge-secrets-design.md) | Secret-Bedrohungsmodell und aktueller Seal-Blocker | Sicherheitsrelevantes Design |
| [`../docs/MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md`](../docs/MESH_AND_WORKBENCH_IMPLEMENTATION_ASSESSMENT.md) | Historischer Umsetzungsvorschlag für Mesh, Release und ausgegliederte Workbench | Historisch / Archiviert |
| [`../docs/SB_MESH_APP_STANDARD.md`](../docs/SB_MESH_APP_STANDARD.md) | Standardsichtung und Vorschlag für einen S&B-App-/Mesh-Service-Vertrag (SB-MAP v0.1) | Entwurf zur Maintainer-Prüfung |
| [`continuation_summary.md`](continuation_summary.md) | Kontext eines älteren Assistenten-Handoffs | Archiv/Historie |

## Aktualisierung

Bei neuen Maintainer-Entscheidungen zuerst `decisions.md` und `../docs/ARCHITECTURE.md` aktualisieren; danach diesen Index, den Arbeitsplan und betroffene Tool-/Website-Dokumente synchronisieren. Vor einer Implementierung alle Statusangaben erneut im Code verifizieren.
