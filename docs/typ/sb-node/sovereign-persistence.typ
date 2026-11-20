= `sb-node` — OIDC, LAPS und OS-Logon-Provisionierung

== Persistenz in `SovereignDb`
- `LoginCodeStore` und `CredentialStore` (`tools/sb-node/src/oidc.rs`) unterstützen `load_from_db` und `save_to_db` im Namespace `oidc`.
- `LapsMetaStore` (`tools/sb-node/src/laps.rs`) unterstützt `load_from_db` und `save_to_db` im Namespace `laps`.
- JSON-Fallback-Speicher nutzen `sb_core::paths::ensure_private_permissions` für restriktive Dateirechte unter Unix und Windows.

== OS-Logon-Provisionierung
- `tools/sb-node/src/os_logon_provision.rs` prüft lokale Modulpfade vor der Registrierung gegen `..`-Traversal und UNC-Pfade (`\\...`, `//...`).
- Windows registriert `sb_cred_provider.dll` über `regsvr32.exe`. Linux installiert ein PAM-Drop-in für `pam_sb.so`.
- Der Modus `--dry-run` protokolliert geplante Schritte ohne Host-Änderung.
