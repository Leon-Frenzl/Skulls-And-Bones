= `sb-db` — Verschlüsselte WAL-Persistenz

== Zweck
`sb-db` speichert Domain-Daten und Geheimnisse transaktional in SQLite im WAL-Modus (`synchronous = FULL`, `busy_timeout = 5000`).

== Sicherheitsmodell
- *At-Rest-Verschlüsselung:* `MasterKey` (256-Bit) verschlüsselt Werte mit AES-256-GCM und AAD-Bindung (`namespace:key:vN`).
- *Dateiberechtigungen:* `MasterKey::load_or_create_file` und `SovereignDb::open` setzen `0o600` unter Unix und exklusive Benutzer-ACLs (`icacls`) unter Windows.
- *E2EE-Envelopes:* Ephemeral-Static X25519 + HKDF-SHA256 + AES-256-GCM schützen LAPS-Passwörter Ende-zu-Ende.
- *Ticket-RBAC:* `DbCapability::SecretReveal` erfordert explizit `db:secret:reveal`. Wildcards (`*`, `db:*`, `admin`) gewähren kein Secret-Reveal.

== Verifikation
- Unit-Tests in `tools/sb-db/src/lib.rs` prüfen E2EE-AAD-Manipulation, Single-Use-Tickets, Wildcard-Sperre und parallele IP-Vergabe.
