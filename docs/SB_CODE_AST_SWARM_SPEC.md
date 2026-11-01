# Skulls & Bones // sb-code: AST-Scoped Locks & Swarm-Diff-Streaming
> **Dokument-ID:** `SBM-DOC-2026-CODE`  
> **Status:** Produktiv & Integriert (`tools/sb-code`)  
> **Ziel:** Dezentrale Echtzeit-Zusammenarbeit auf Methodenebene ohne Git-Zwang und ohne Merge-Konflikte

---

## 1. Die Vision: Semantische Versionskontrolle

Klassische Versionskontrollsysteme (Git, Mercurial) operieren auf **Zeilenebene**. Ändern zwei Entwickler dieselbe Datei an unterschiedlichen Stellen oder in derselben Klasse, führt dies unweigerlich zu Merge-Konflikten.

`sb-code` löst dieses Problem durch **semantisches AST-Scope-Locking**:

```
src/services/billing.rs (Container: Klasse bleibt frei!)
├── fn create_invoice()     <--- [LOCKED] Alice (180s Lease)
├── fn calculate_vat()      <--- [LOCKED] Bob (180s Lease)
└── fn send_receipt()       <--- [READ-ONLY] Baseline
```

### Kernprinzipien:
1. **Container Isolation:**
   - Klassen, Structs und Interfaces (`is_container: true`) werden nicht exklusiv gesperrt.
   - Mehrere Entwickler können gleichzeitig unterschiedliche Methoden derselben Klasse bearbeiten.
2. **Stable Shadow Baseline:**
   - Vor jeder Bearbeitung wird der letzte fehlerfreie Methodenstand in `.sb/baseline_cache.json` gesichert.
   - Externe Peers und Compiler sehen stets den stabilen Stand – lokale Tippfehler oder unfertige Syntax brechen niemals den Build der Kollegen.
3. **Swarm-Diff-Streaming:**
   - Diffs werden als `AstDiffStreamPacket` direkt über das Sovereign Mesh gestreamt.
   - Zeilenänderungen (`+` / `-`) werden mit Erhalt von Tabs, Whitespace und lokalen Einrückungen 3-Wege-gepatcht.

---

## 2. CLI-Befehlsreferenz

```bash
# Methode sperren (per Zeilennummer oder Name)
sb code lock src/main.rs 42
sb code lock src/services/billing.rs calculate_vat

# Aktive Team-Locks einsehen
sb code locks

# Methode freigeben & neue Baseline im Swarm setzen
sb code unlock src/services/billing.rs calculate_vat

# Lokale Änderungen mit der stabilen Swarm-Baseline vergleichen
sb code baseline diff src/services/billing.rs calculate_vat

# Eintreffende Swarm-Diffs live mitlesen
sb code stream diff
```
