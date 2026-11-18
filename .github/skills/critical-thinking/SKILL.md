---
name: critical-thinking
description: 'Use when evaluating an idea, design, architecture choice, dependency, feature or any decision with trade-offs: weigh pros and cons, score each 1-10, and derive a justified decision. Keywords: pro und contra, Bewertung, Entscheidung, trade-off, decision, critical thinking, evaluate idea, scoring.'
---

# Critical Thinking – Pro/Contra-Bewertung mit Punkten

Nutze diesen Ablauf, wenn eine Idee oder Entscheidung bewertet werden soll. Antworte auf Deutsch, knapp und begründet.

## Regeln

- Nenne zuerst die Idee und das Ziel in einem Satz. Ist das Ziel unklar, triff eine Annahme und nenne sie.
- Belege Argumente mit Evidenz (Code, Messung, Standard, Advisory). Keine erfundenen Fakten oder Zahlen.
- Bewerte ehrlich: kein Schönreden der eigenen oder der vom Nutzer vorgeschlagenen Idee. Argumentiere aktiv auch gegen die Idee.
- Berücksichtige bei Skulls & Bones immer Sicherheit (Vertrauensgrenzen, siehe `security-cve-audit`) und Standardkonformität (siehe `standards-compliance`).

## Ablauf

1. **Idee & Ziel** – was soll erreicht werden, was sind die Randbedingungen?
2. **Kriterien & Gewichte** – 3–6 relevante Kriterien (z. B. Sicherheit, Aufwand, Wartbarkeit, Performance, Risiko, Nutzen). Gewicht je 1–3 (3 = sehr wichtig).
3. **Pro und Contra** – je Kriterium Argumente dafür und dagegen sammeln. Jedes Argument erhält **1–10 Punkte** für sein Gewicht/seine Stärke (1 = kaum relevant, 10 = ausschlaggebend).
4. **Gegenprüfung** – Alternativen, "Nichtstun" und die stärksten Einwände gegen das eigene Ergebnis prüfen. Annahmen und Unsicherheiten benennen.
5. **Auswertung** – Summe Pro (gewichtet) minus Summe Contra (gewichtet) bzw. Gesamtscore 1–10 für die Idee.
6. **Entscheidung** – anhand der Schwellen:

   | Gesamtscore | Entscheidung |
   |---|---|
   | 8–10 | Umsetzen |
   | 6–7 | Umsetzen mit Auflagen (Risiken benennen und mindern) |
   | 4–5 | Überarbeiten oder Alternative wählen |
   | 1–3 | Ablehnen |

   Bei knappem Ergebnis oder hoher Unsicherheit: kleinen Spike/Prototyp empfehlen. Ein Sicherheits-Contra mit 9–10 Punkten ist ein Veto, unabhängig vom Score.

## Ausgabeformat

**Idee:** …  **Ziel:** …

| Kriterium | Gewicht | Pro (Punkte) | Contra (Punkte) |
|---|---|---|---|
| … | 1–3 | … (n) | … (n) |

**Gegenprüfung:** Alternativen / stärkste Einwände / Annahmen.
**Gesamtscore:** X/10 (Rechnung kurz angeben).
**Entscheidung:** Umsetzen | Mit Auflagen | Überarbeiten | Ablehnen – mit zwei bis drei Sätzen Begründung und nächsten Schritten.
