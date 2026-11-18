# Skulls & Bones // Sovereign Document-KV Database (sb-db)
> **Dokument-ID:** `SBM-DOC-2026-DB`  
> **Version:** `0.2.0`  
> **Status:** Produktiv & Integriert (`tools/sb-db`)  
> **Kategorie:** Embedded Database, Document Store, MVCC & Reactive Watch

---

## 1. Vision & Philosophie

Bestehende Embedded-Datenbanken wie SQLite oder RocksDB bringen für moderne, souveräne Anwendungen gravierende Nachteile mit sich:
- **SQLite Concurrency & Lock-Hölle:** Nur ein einziger Schreiber pro Datei (`SQLITE_BUSY` / `database is locked`). Zudem vermüllen `-wal` und `-shm` Dateien das Dateisystem und gefährden Backups.
- **Rigide Migrationen:** Um neue Attribute zu speichern, verlangt SQLite manuelle SQL-Migrationen.
- **Rohe Byte-Suppe in RocksDB:** Keine Unterstützung für strukturierte Dokumente, keine JSON-Pfade, keine nativen TTLs.

**`sb-db`** löst all diese Probleme in einer einzigen, autarken Rust-Datenbank:
1. **Echtes Single-File Format (`.sbdb`):** Genau eine portable Datei. Kein Dateispam, atomares Backup durch einfaches Dateikopieren.
2. **Native Typed JSON Documents:** Beliebige JSON-Objekte ohne starre Schema-Zwänge speichern und manipulieren.
3. **Punkt-Notation für JSON-Pfade:** Direkter Zugriff und Mutation verschachtelter Pfade (`users:alice.profile.city`).
4. **Sekundär-Indizes in O(1):** Indizes auf beliebige JSON-Felder (`sb db index create users: role`) ohne SQL-Overhead.
5. **Native TTL (Time-To-Live):** Automatisch ablaufende Keys wie in Redis direkt in der Embedded-Datei.
6. **Reactive Watch Streams (CDC):** In Echtzeit auf Mutationen lauschen (`sb db tail "users:*"`).
7. **Interaktives TUI-Cockpit:** Terminal-Cockpit (`sb db tui`) mit Key-Browser, Suche (`/`) und JSON-Viewer.

---

## 2. Architektur & Speicher-Format

```
┌────────────────────────────────────────────────────────────────────────┐
│                        sb-db (Engine Core)                             │
├────────────────────────────────────────────────────────────────────────┤
│ APIs:                                                                  │
│  ├─ CLI & TUI:     sb db set / get / scan / find / tail / tui          │
│  ├─ Rust API:      sb_db::Database (open, get, set, transaction)       │
│  └─ Reactive Bus:  tokio::sync::broadcast (Change Data Capture)        │
├────────────────────────────────────────────────────────────────────────┤
│ Storage Layer (Single-File .sbdb):                                     │
│  ├─ Header (32B):  SBDB01 Magic, Version, CreatedAt, Revision          │
│  ├─ Log Stream:    [Kind][TxId][Timestamp][TTL][Key][Value][CRC32]     │
│  ├─ Crash-Safe:    Auto-Truncation bei plötzlichem Stromausfall        │
│  └─ Compactor:     Atomares Umschreiben live bereinigter Keys          │
├────────────────────────────────────────────────────────────────────────┤
│ In-Memory Indexing:                                                    │
│  ├─ Primary Index: BTreeMap<Key, ValueRecord>                          │
│  ├─ Secondary:     (Prefix + Field) -> (FieldValue -> Set<Key>)        │
│  └─ TTL Sweeper:   Hintergrund-Bereinigung abgelaufener Keys           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. CLI Befehlsübersicht (`sb db ...`)

| Befehl | Beschreibung |
| :--- | :--- |
| `sb db get <key>` | Liest ein Dokument oder einen verschachtelten Pfad (z. B. `user:1.profile.city`). |
| `sb db set <key> <json> [--ttl <sec>]` | Speichert ein JSON-Dokument oder setzt einen verschachtelten Pfad. |
| `sb db del <key>` | Löscht einen Eintrag aus der Datenbank. |
| `sb db scan [--prefix <p>]` | Scannt alle Keys mit optionalem Prefix-Filter. |
| `sb db find <prefix> <field> <val>` | Schnelle $O(1)$-Suche über sekundäre Indizes. |
| `sb db index create <prefix> <field>` | Erstellt einen automatischen Sekundär-Index. |
| `sb db tail [pattern]` | Live-Streaming von Datenbankänderungen im Terminal. |
| `sb db compact` | Bereinigt die `.sbdb`-Datei und gibt Speicherplatz frei. |
| `sb db stats` | Zeigt aktive Keys, Indizes, Dateigröße und Transaktions-Zähler. |
| `sb db tui` | Startet das interaktive Terminal-Cockpit. |

---

## 4. Rust Einbettungs-Beispiel

```rust
use sb_db::Database;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::open("app.sbdb")?;

    // 1. JSON-Objekt speichern
    db.set("user:alice", &serde_json::json!({
        "name": "Alice",
        "role": "admin",
        "profile": {
            "city": "Berlin",
            "age": 29
        }
    }))?;

    // 2. Pfad-Zugriff
    let city = db.get_path("user:alice", "profile.city");
    println!("City: {:?}", city);

    // 3. Ephemerer Cache-Key mit TTL
    db.set_with_ttl("session:token123", &"active", Duration::from_secs(3600))?;

    // 4. Sekundär-Index & O(1) Suche
    db.create_index("user:", "role")?;
    let admins = db.find("user:", "role", &serde_json::json!("admin"));
    println!("Admins: {:?}", admins);

    Ok(())
}
```
