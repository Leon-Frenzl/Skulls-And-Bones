# Best Practices: Sovereign Code Streaming mit `sb-code` & `sb-mesh`

> **S&B Manifesto:** *„Code ist kein statisches Archiv, das auf fremden Servern parkt. Code ist ein reaktiver Datenstrom zwischen vertrauenswürdigen Peers.“*

---

## 1. Die Kernphilosophie: Continuous Code Streaming

Klassische Versionskontrollsysteme basieren auf **diskreten Batches**:
`Edit -> Add -> Commit -> Push -> Pull Request -> Merge Conflict`. 

`sb-code` bricht dieses 20 Jahre alte Paradigma auf:
1. **P2P Swarm Pub/Sub:** Repositories sind Swarm-Topics (`sbm:code:<project>`).
2. **AST-Level Granularität:** Statt roher Textzeilen werden syntaktische Einheiten (Methoden, Structs, Klassen) isoliert synchronisiert.
3. **Dual-View Shadow Baseline:** Dein lokaler Compiler baut immer stabil gegen den letzten validen Stand deiner Kollegen – selbst während diese unvollständigen Code tippen.

---

## 2. Die Seeding-Anchor-Regel (`sb-node`)

Ein reines P2P-Netzwerk aus Entwickler-Laptops hat eine fundamentale Schwachstelle: **Das „Laptop-Zuklapp-Problem“**. Wenn alle Entwickler Feierabend machen, ist der Code im flüchtigen P2P-Netzwerk nicht mehr erreichbar.

### Die 3 goldenen Anchor-Regeln:

1. **Jedes Team-Projekt benötigt mindestens einen Seeding Anchor:**
   Ein Seeding Anchor ist eine dedizierte `sb-node`-Instanz, die auf einem 24/7 laufenden Server (VPS, Home-Server, Raspberry Pi) im Mesh läuft.
   ```bash
   # Auf dem Server:
   sb node init --name anchor-alpha
   sb node start --anchor
   ```
2. **Anchor-Status beim Veröffentlichen beachten:**
   Wenn du `sb publish` ausführst, prüft das System automatisch:
   * **⚓ Anchor erkannt:** Dein Code wird sofort persistent auf den Server repliziert. Dein Team kann das Projekt jederzeit mit `sb subscribe` abrufen – selbst wenn du offline bist.
   * **⚠️ Kein Anchor erkannt:** Das System warnt dich. Das Projekt läuft nur im *flüchtigen P2P-Modus* (nur verfügbar, solange dein Rechner online ist).
3. **Multi-Anchor Redundanz für Production:**
   Für produktionskritische Repositories sollten 2–3 Seeding Anchors in unterschiedlichen Zonen (z. B. Hetzner + lokales Büro) im Mesh registriert sein.

---

## 3. Workspace-Ausschlüsse (`.sbignore`)

Nicht jede Datei gehört in den P2P-Echtzeitstrom. `sb-code` nutzt einen
verbindlichen Kernel-Filter für sensible Daten, Build-Artefakte und Legacy-VCS-
Metadaten sowie gemeinsame projektspezifische Regeln aus `.sbignore`. Alle
Muster in dieser Datei schließen Dateien sowohl von Tracking/Sync als auch von
`heatmap`/`coupling` aus:

```
Kernel-Filter (immer aktiv)
  ├─ Secrets, Schlüssel und Lease-Daten
  ├─ Builds, Caches und Legacy-VCS-Metadaten
  └─ Nicht durch Projektregeln überschreibbar

Optionale .sbignore-Regeln
  └─ Projektspezifische Ausschlüsse für Tracking, Sync und Analysen
```

### Empfohlene `.sbignore` Vorlage:
```text
# Builds & Binaries
build/
dist/
bin/
*.exe
*.so
*.dylib

# Caches & Logs
logs/
*.log
.cache/
*.tmp
*.bak

# Ggf. große Test-Assets, die nicht im Live-Stream fließen sollen
tests/fixtures/*.sqlite
```

---

## 4. Scope-Disziplin: Private vs. Shared

Um das **„WIP-Shame“**-Problem (das Gefühl, beim unfertigen Coden beobachtet zu werden) zu verhindern:

* **Lokaler Prototyp (Private Scope):**
  Wenn du an einer Methode experimentierst oder große Refactorings machst, halte den Scope lokal. Deltas fließen erst bei syntaktisch validem Zustand oder bei Speicherung.
* **Team-Zusammenarbeit (Shared Scope):**
  Sobald du an einer gemeinsamen Schnittstelle arbeitest, registriert `sb-code` automatisch ein **AST-Soft-Lock**. Deine Kollegen sehen im Cockpit (`sb code tui`), dass du an diesem Block arbeitest, und werden vor Kollisionen geschützt.
* **Kein Cursor-Springen:**
  Fremde Änderungen fließen erst dann in dein aktives Editor-Fenster, wenn dein Cursor die entsprechende Methode verlassen hat.

---

## 5. Signaturen und Quorum-Commits

* **Aktueller Implementierungsstand:** Commit- und Tree-IDs sind inhaltsadressiert; Commits werden derzeit nicht kryptographisch signiert. Die CLI kennzeichnet sie deshalb als nicht signiert.
* **Production-Releases mit 4-Augen-Prinzip:**
  Das beschriebene Multisig-Quorum über `sb lease approve` ist ein Zielkonzept und noch nicht durch die `sb-code`-Commit-Implementierung erzwungen. Releases dürfen daher nicht allein anhand eines Commits als autorisiert gelten.

---

## 6. Zero-Secret Policy (`sb-forge` & `sb-core` Vault)

* **Niemals Passwörter oder API-Keys in Code-Dateien!**
* Nutze stattdessen flüchtige RAM-Injektion:
  ```bash
  # Secrets im verschlüsselten Vault ablegen
  sb env set DATABASE_URL postgres://...
  
  # Anwendung mit flüchtigen Secrets im RAM starten (keine .env auf Disk)
  sb env run -- npm run dev
  ```
