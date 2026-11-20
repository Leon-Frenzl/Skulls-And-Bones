use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sb_core::domain::MachineRecord;
use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::crypto::{
    decrypt_at_rest, encrypt_at_rest, open_e2ee, seal_e2ee, E2eeEnvelope, EncryptedBlob,
    MasterKey,
};
use crate::error::{DbError, DbResult};
use crate::ticket::{DbCapability, VerifiedDbTicket};

/// Metadata returned when storing or listing encrypted entries without exposing plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbEntryMeta {
    pub entry_id: String,
    pub namespace: String,
    pub version: u32,
    pub updated_at: String,
    pub updated_by: String,
}

/// Transactional, WAL-enabled SQLite store with encryption-at-rest, E2EE envelopes,
/// and ticket-guarded access + audit logging.
pub struct SovereignDb {
    conn: Mutex<Connection>,
    master_key: MasterKey,
}

impl SovereignDb {
    /// Opens (or creates) a SQLite WAL database at `db_path` secured with `master_key`.
    // [SECURITY-VERIFIED] CWE-362 / CWE-732 Mitigiert:
    // Aktiviert WAL-Modus, `busy_timeout = 5000`, `synchronous = FULL`, `foreign_keys = ON`
    // und setzt restriktive Unix-Dateiberechtigungen (0o600).
    pub fn open(db_path: &Path, master_key: MasterKey) -> DbResult<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| DbError::Storage(format!("Failed to create DB directory: {e}")))?;
        }
        let conn = Connection::open(db_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(db_path, fs::Permissions::from_mode(0o600));
        }
        Self::init_connection(conn, master_key)
    }

    /// Opens an in-memory transactional database (for unit and integration tests).
    pub fn open_in_memory(master_key: MasterKey) -> DbResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_connection(conn, master_key)
    }

    fn init_connection(conn: Connection, master_key: MasterKey) -> DbResult<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS machines (
                machine_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                hostname TEXT NOT NULL,
                mesh_ip TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                record_enc TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_machines_domain ON machines(domain, revoked);

            CREATE TABLE IF NOT EXISTS encrypted_entries (
                entry_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                version INTEGER NOT NULL,
                envelope_enc TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entries_ns ON encrypted_entries(namespace);

            CREATE TABLE IF NOT EXISTS used_tickets (
                ticket_id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ticket_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kv_encrypted (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                version INTEGER NOT NULL,
                blob_enc TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            );

            CREATE TABLE IF NOT EXISTS auth_lockouts (
                username TEXT PRIMARY KEY,
                failures INTEGER NOT NULL,
                locked_until INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            master_key,
        })
    }

    fn machine_aad(domain: &str, machine_id: &str) -> Vec<u8> {
        format!("machines:{domain}:{machine_id}").into_bytes()
    }

    fn entry_aad(namespace: &str, entry_id: &str, version: u32) -> Vec<u8> {
        format!("encrypted_entries:{namespace}:{entry_id}:v{version}").into_bytes()
    }

    fn record_ticket_use(
        tx: &rusqlite::Transaction<'_>,
        ticket: &VerifiedDbTicket,
        action: &str,
        target_id: &str,
    ) -> DbResult<()> {
        let now = Utc::now().to_rfc3339();
        if ticket.single_use {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO used_tickets (ticket_id, subject, consumed_at) VALUES (?1, ?2, ?3)",
                params![ticket.ticket_id, ticket.subject, now],
            )?;
            if inserted == 0 {
                return Err(DbError::Unauthorized(
                    "Single-use ticket has already been consumed".into(),
                ));
            }
        }
        tx.execute(
            "INSERT INTO ticket_audit_log (ticket_id, subject, action, target_id, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ticket.ticket_id, ticket.subject, action, target_id, now],
        )?;
        Ok(())
    }

    /// Atomically allocates the next free `10.42.x.y` IPv4 (if `record.mesh_ip` is empty)
    /// and registers or updates a `MachineRecord` inside an `IMMEDIATE` transaction.
    // [SECURITY-VERIFIED] CWE-89 / CWE-362 Mitigiert:
    // Nutzt SQLite `TransactionBehavior::Immediate` (verhindert parallele IP-Doppelvergabe)
    // und strikt parametrisierte Queries. Verschlüsselt `MachineRecord` at-rest mit AAD.
    pub fn register_machine_atomic(
        &self,
        ticket: &VerifiedDbTicket,
        domain: &str,
        mut record: MachineRecord,
    ) -> DbResult<MachineRecord> {
        ticket.authorize(DbCapability::Write)?;
        if domain.trim().is_empty() || record.machine_id.trim().is_empty() {
            return Err(DbError::Validation(
                "domain and machine_id cannot be empty".into(),
            ));
        }

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::record_ticket_use(&tx, ticket, "machine:register", &record.machine_id)?;

        if record.mesh_ip.trim().is_empty() {
            let mut stmt =
                tx.prepare("SELECT mesh_ip FROM machines WHERE domain = ?1 AND revoked = 0")?;
            let rows = stmt.query_map(params![domain], |row| row.get::<_, String>(0))?;
            let mut used = HashSet::new();
            used.insert(Ipv4Addr::new(10, 42, 0, 1));
            for ip_str in rows.flatten() {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    used.insert(ip);
                }
            }
            let mut allocated = None;
            'outer: for third in 0u8..=254 {
                let start_fourth = if third == 0 { 10 } else { 1 };
                for fourth in start_fourth..=254 {
                    let candidate = Ipv4Addr::new(10, 42, third, fourth);
                    if !used.contains(&candidate) {
                        allocated = Some(candidate.to_string());
                        break 'outer;
                    }
                }
            }
            record.mesh_ip = allocated
                .ok_or_else(|| DbError::Exhausted("Domain IPv4 pool (10.42.0.0/16) exhausted".into()))?;
        }

        let record_json = serde_json::to_vec(&record)
            .map_err(|e| DbError::Serialization(format!("Failed to encode MachineRecord: {e}")))?;
        let aad = Self::machine_aad(domain, &record.machine_id);
        let blob = encrypt_at_rest(&self.master_key, &aad, &record_json)?;
        let blob_json = serde_json::to_string(&blob)
            .map_err(|e| DbError::Serialization(format!("Failed to encode EncryptedBlob: {e}")))?;
        let now = Utc::now().to_rfc3339();

        tx.execute(
            "INSERT INTO machines (machine_id, domain, hostname, mesh_ip, revoked, record_enc, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(machine_id) DO UPDATE SET
                domain = excluded.domain,
                hostname = excluded.hostname,
                mesh_ip = excluded.mesh_ip,
                revoked = excluded.revoked,
                record_enc = excluded.record_enc,
                updated_at = excluded.updated_at",
            params![
                record.machine_id,
                domain,
                record.hostname,
                record.mesh_ip,
                if record.revoked { 1i64 } else { 0i64 },
                blob_json,
                now
            ],
        )?;

        tx.commit()?;
        Ok(record)
    }

    /// Lists and decrypts all `MachineRecord` entries for `domain`.
    pub fn list_machines(
        &self,
        ticket: &VerifiedDbTicket,
        domain: &str,
    ) -> DbResult<Vec<MachineRecord>> {
        ticket.authorize(DbCapability::Read)?;
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction()?;
        Self::record_ticket_use(&tx, ticket, "machine:list", domain)?;

        let mut records = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT machine_id, record_enc FROM machines WHERE domain = ?1 ORDER BY hostname ASC",
            )?;
            let rows = stmt.query_map(params![domain], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (machine_id, blob_json) = row?;
                let blob: EncryptedBlob = serde_json::from_str(&blob_json).map_err(|e| {
                    DbError::Serialization(format!("Corrupt EncryptedBlob JSON: {e}"))
                })?;
                let aad = Self::machine_aad(domain, &machine_id);
                let pt = decrypt_at_rest(&self.master_key, &aad, &blob)?;
                let rec: MachineRecord = serde_json::from_slice(&pt).map_err(|e| {
                    DbError::Serialization(format!("Corrupt MachineRecord JSON: {e}"))
                })?;
                records.push(rec);
            }
        }
        tx.commit()?;
        Ok(records)
    }

    /// Internal DC bootstrap/migration helper: lists machines for `domain` without requiring a user ticket.
    pub fn list_machines_internal(&self, domain: &str) -> DbResult<Vec<MachineRecord>> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let mut stmt = guard.prepare(
            "SELECT machine_id, record_enc FROM machines WHERE domain = ?1 ORDER BY hostname ASC",
        )?;
        let rows = stmt.query_map(params![domain], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (machine_id, blob_json) = row?;
            let blob: EncryptedBlob = serde_json::from_str(&blob_json).map_err(|e| {
                DbError::Serialization(format!("Corrupt EncryptedBlob JSON: {e}"))
            })?;
            let aad = Self::machine_aad(domain, &machine_id);
            let pt = decrypt_at_rest(&self.master_key, &aad, &blob)?;
            let rec: MachineRecord = serde_json::from_slice(&pt).map_err(|e| {
                DbError::Serialization(format!("Corrupt MachineRecord JSON: {e}"))
            })?;
            records.push(rec);
        }
        Ok(records)
    }

    /// Internal DC bootstrap helper: atomically upserts a `MachineRecord` during initial migration.
    pub fn upsert_machine_internal(&self, domain: &str, record: &MachineRecord) -> DbResult<()> {
        if domain.trim().is_empty() || record.machine_id.trim().is_empty() {
            return Err(DbError::Validation(
                "domain and machine_id cannot be empty".into(),
            ));
        }
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record_json = serde_json::to_vec(record)
            .map_err(|e| DbError::Serialization(format!("Failed to encode MachineRecord: {e}")))?;
        let aad = Self::machine_aad(domain, &record.machine_id);
        let blob = encrypt_at_rest(&self.master_key, &aad, &record_json)?;
        let blob_json = serde_json::to_string(&blob)
            .map_err(|e| DbError::Serialization(format!("Failed to encode EncryptedBlob: {e}")))?;
        let now = Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO machines (machine_id, domain, hostname, mesh_ip, revoked, record_enc, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(machine_id) DO UPDATE SET
                domain = excluded.domain,
                hostname = excluded.hostname,
                mesh_ip = excluded.mesh_ip,
                revoked = excluded.revoked,
                record_enc = excluded.record_enc,
                updated_at = excluded.updated_at",
            params![
                record.machine_id,
                domain,
                record.hostname,
                record.mesh_ip,
                if record.revoked { 1i64 } else { 0i64 },
                blob_json,
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Imports legacy `MachineRecord` slices into SQLite only if the domain table is empty.
    pub fn import_machines_if_empty(
        &self,
        ticket: &VerifiedDbTicket,
        domain: &str,
        machines: &[MachineRecord],
    ) -> DbResult<usize> {
        ticket.authorize(DbCapability::Admin)?;
        let existing = self.list_machines(ticket, domain)?;
        if !existing.is_empty() {
            return Ok(0);
        }
        let mut imported = 0usize;
        for m in machines {
            self.register_machine_atomic(ticket, domain, m.clone())?;
            imported += 1;
        }
        Ok(imported)
    }

    /// Stores an E2EE-sealed secret in the database, additionally wrapped with encryption-at-rest.
    // [SECURITY-VERIFIED] CWE-312 / CWE-345 Mitigiert:
    // Doppelte Verschlüsselung: Payload wird per `seal_e2ee` (X25519 + AES-GCM) für den Empfänger
    // verschlüsselt und zusätzlich mit `encrypt_at_rest` + Versions-AAD in SQLite gespeichert.
    pub fn put_e2ee_entry(
        &self,
        ticket: &VerifiedDbTicket,
        namespace: &str,
        entry_id: &str,
        recipient_x25519_pub: &[u8; 32],
        plaintext: &[u8],
    ) -> DbResult<DbEntryMeta> {
        ticket.authorize(DbCapability::Write)?;
        if namespace.trim().is_empty() || entry_id.trim().is_empty() || plaintext.is_empty() {
            return Err(DbError::Validation(
                "namespace, entry_id, and plaintext cannot be empty".into(),
            ));
        }

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::record_ticket_use(&tx, ticket, "entry:put_e2ee", entry_id)?;

        let existing_version: Option<u32> = tx
            .query_row(
                "SELECT version FROM encrypted_entries WHERE entry_id = ?1",
                params![entry_id],
                |r| r.get(0),
            )
            .optional()?;
        let next_version = existing_version.unwrap_or(0).saturating_add(1);
        let aad = Self::entry_aad(namespace, entry_id, next_version);

        let envelope = seal_e2ee(recipient_x25519_pub, &aad, plaintext)?;
        let envelope_json = serde_json::to_vec(&envelope)
            .map_err(|e| DbError::Serialization(format!("Failed to serialize E2eeEnvelope: {e}")))?;
        let at_rest = encrypt_at_rest(&self.master_key, &aad, &envelope_json)?;
        let at_rest_json = serde_json::to_string(&at_rest)
            .map_err(|e| DbError::Serialization(format!("Failed to serialize EncryptedBlob: {e}")))?;

        let now = Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO encrypted_entries (entry_id, namespace, version, envelope_enc, created_at, updated_at, updated_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(entry_id) DO UPDATE SET
                namespace = excluded.namespace,
                version = excluded.version,
                envelope_enc = excluded.envelope_enc,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by",
            params![
                entry_id,
                namespace,
                next_version,
                at_rest_json,
                now,
                now,
                ticket.subject
            ],
        )?;

        tx.commit()?;
        Ok(DbEntryMeta {
            entry_id: entry_id.to_string(),
            namespace: namespace.to_string(),
            version: next_version,
            updated_at: now,
            updated_by: ticket.subject.clone(),
        })
    }

    /// Retrieves and decrypts an E2EE-sealed secret if the ticket grants `db:secret:reveal`.
    pub fn get_e2ee_entry(
        &self,
        ticket: &VerifiedDbTicket,
        namespace: &str,
        entry_id: &str,
        recipient_x25519_secret: &StaticSecret,
    ) -> DbResult<Zeroizing<Vec<u8>>> {
        ticket.authorize(DbCapability::SecretReveal)?;
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::record_ticket_use(&tx, ticket, "entry:reveal_e2ee", entry_id)?;

        let row: Option<(u32, String)> = tx
            .query_row(
                "SELECT version, envelope_enc FROM encrypted_entries WHERE entry_id = ?1 AND namespace = ?2",
                params![entry_id, namespace],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (version, at_rest_json) =
            row.ok_or_else(|| DbError::NotFound(format!("Entry '{entry_id}' not found")))?;

        let blob: EncryptedBlob = serde_json::from_str(&at_rest_json)
            .map_err(|e| DbError::Serialization(format!("Corrupt EncryptedBlob: {e}")))?;
        let aad = Self::entry_aad(namespace, entry_id, version);
        let envelope_bytes = decrypt_at_rest(&self.master_key, &aad, &blob)?;
        let envelope: E2eeEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| DbError::Serialization(format!("Corrupt E2eeEnvelope: {e}")))?;

        let plaintext = open_e2ee(recipient_x25519_secret, &aad, &envelope)?;
        tx.commit()?;
        Ok(plaintext)
    }

    /// Returns the audit trail count for verification and monitoring.
    pub fn audit_log_count(&self, ticket: &VerifiedDbTicket) -> DbResult<u64> {
        ticket.authorize(DbCapability::Admin)?;
        let guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let count: i64 =
            guard.query_row("SELECT COUNT(*) FROM ticket_audit_log", [], |r| r.get(0))?;
        Ok(count.max(0) as u64)
    }

    fn kv_aad(namespace: &str, key: &str, version: u32) -> Vec<u8> {
        format!("kv_encrypted:{namespace}:{key}:v{version}").into_bytes()
    }

    /// Stores a serializable domain store (`PolicyStore`, `LapsMetaStore`, `RbacStore`)
    /// encrypted at-rest and bound to `(namespace, key, version)`.
    pub fn put_encrypted_json<T: Serialize>(
        &self,
        ticket: &VerifiedDbTicket,
        namespace: &str,
        key: &str,
        value: &T,
    ) -> DbResult<u32> {
        ticket.authorize(DbCapability::Write)?;
        if namespace.trim().is_empty() || key.trim().is_empty() {
            return Err(DbError::Validation(
                "namespace and key cannot be empty".into(),
            ));
        }

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::record_ticket_use(&tx, ticket, "kv:put", &format!("{namespace}:{key}"))?;

        let existing_version: Option<u32> = tx
            .query_row(
                "SELECT version FROM kv_encrypted WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |r| r.get(0),
            )
            .optional()?;
        let next_version = existing_version.unwrap_or(0).saturating_add(1);
        let payload = serde_json::to_vec(value)
            .map_err(|e| DbError::Serialization(format!("Failed to serialize KV JSON: {e}")))?;
        let aad = Self::kv_aad(namespace, key, next_version);
        let blob = encrypt_at_rest(&self.master_key, &aad, &payload)?;
        let blob_json = serde_json::to_string(&blob)
            .map_err(|e| DbError::Serialization(format!("Failed to encode EncryptedBlob: {e}")))?;
        let now = Utc::now().to_rfc3339();

        tx.execute(
            "INSERT INTO kv_encrypted (namespace, key, version, blob_enc, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(namespace, key) DO UPDATE SET
                version = excluded.version,
                blob_enc = excluded.blob_enc,
                updated_at = excluded.updated_at",
            params![namespace, key, next_version, blob_json, now],
        )?;
        tx.commit()?;
        Ok(next_version)
    }

    /// Loads and decrypts a serializable domain store from `kv_encrypted`.
    pub fn get_encrypted_json<T: DeserializeOwned>(
        &self,
        ticket: &VerifiedDbTicket,
        namespace: &str,
        key: &str,
    ) -> DbResult<Option<T>> {
        ticket.authorize(DbCapability::Read)?;
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction()?;
        Self::record_ticket_use(&tx, ticket, "kv:get", &format!("{namespace}:{key}"))?;

        let row: Option<(u32, String)> = tx
            .query_row(
                "SELECT version, blob_enc FROM kv_encrypted WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((version, blob_json)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let blob: EncryptedBlob = serde_json::from_str(&blob_json)
            .map_err(|e| DbError::Serialization(format!("Corrupt EncryptedBlob JSON: {e}")))?;
        let aad = Self::kv_aad(namespace, key, version);
        let pt = decrypt_at_rest(&self.master_key, &aad, &blob)?;
        let parsed: T = serde_json::from_slice(&pt)
            .map_err(|e| DbError::Serialization(format!("Corrupt KV JSON: {e}")))?;
        tx.commit()?;
        Ok(Some(parsed))
    }

    /// Checks whether `username` is currently locked out across daemon restarts.
    pub fn check_auth_lockout(&self, username: &str) -> DbResult<Option<u64>> {
        let now = Utc::now().timestamp();
        let guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let row: Option<(i64,)> = guard
            .query_row(
                "SELECT locked_until FROM auth_lockouts WHERE username = ?1",
                params![username],
                |r| Ok((r.get(0)?,)),
            )
            .optional()?;
        if let Some((locked_until,)) = row {
            if locked_until > now {
                return Ok(Some((locked_until - now) as u64));
            }
        }
        Ok(None)
    }

    /// Atomically increments failed auth attempts and sets `locked_until` when `max_failures` is reached.
    // [SECURITY-VERIFIED] CWE-307 / CWE-362 Mitigiert:
    // Persistiert Fehlversuche transaktional in SQLite, sodass Dienst-Neustarts Lockouts nicht zurücksetzen.
    pub fn record_auth_failure(
        &self,
        username: &str,
        max_failures: u32,
        lockout_secs: u64,
    ) -> DbResult<Option<u64>> {
        let now = Utc::now().timestamp();
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(u32, i64)> = tx
            .query_row(
                "SELECT failures, locked_until FROM auth_lockouts WHERE username = ?1",
                params![username],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let (prev_failures, prev_locked) = row.unwrap_or((0, 0));
        let base_failures = if prev_locked > 0 && prev_locked <= now {
            0
        } else {
            prev_failures
        };
        let next_failures = base_failures.saturating_add(1);
        let locked_until = if next_failures >= max_failures {
            now.saturating_add(lockout_secs as i64)
        } else {
            0
        };

        tx.execute(
            "INSERT INTO auth_lockouts (username, failures, locked_until, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(username) DO UPDATE SET
                failures = excluded.failures,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at",
            params![username, next_failures, locked_until, now],
        )?;
        tx.commit()?;
        if locked_until > now {
            Ok(Some((locked_until - now) as u64))
        } else {
            Ok(None)
        }
    }

    /// Clears persisted auth failures after a successful login.
    pub fn clear_auth_lockout(&self, username: &str) -> DbResult<()> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        guard.execute("DELETE FROM auth_lockouts WHERE username = ?1", params![username])?;
        Ok(())
    }

    /// Exports an encrypted JSON snapshot of `machines` and `kv_encrypted` for standby DC replication.
    pub fn export_encrypted_snapshot(&self, ticket: &VerifiedDbTicket) -> DbResult<EncryptedBlob> {
        ticket.authorize(DbCapability::Admin)?;
        let guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;

        let mut kv_rows = Vec::new();
        {
            let mut stmt = guard.prepare(
                "SELECT namespace, key, version, blob_enc, updated_at FROM kv_encrypted ORDER BY namespace, key",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(serde_json::json!({
                    "namespace": r.get::<_, String>(0)?,
                    "key": r.get::<_, String>(1)?,
                    "version": r.get::<_, u32>(2)?,
                    "blob_enc": r.get::<_, String>(3)?,
                    "updated_at": r.get::<_, String>(4)?,
                }))
            })?;
            for row in rows.flatten() {
                kv_rows.push(row);
            }
        }
        let mut machine_rows = Vec::new();
        {
            let mut stmt = guard.prepare(
                "SELECT machine_id, domain, record_enc, updated_at FROM machines ORDER BY domain, machine_id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(serde_json::json!({
                    "machine_id": r.get::<_, String>(0)?,
                    "domain": r.get::<_, String>(1)?,
                    "record_enc": r.get::<_, String>(2)?,
                    "updated_at": r.get::<_, String>(3)?,
                }))
            })?;
            for row in rows.flatten() {
                machine_rows.push(row);
            }
        }

        let snapshot = serde_json::json!({
            "v": 1,
            "exported_at": Utc::now().to_rfc3339(),
            "machines": machine_rows,
            "kv": kv_rows,
        });
        let bytes = serde_json::to_vec(&snapshot)
            .map_err(|e| DbError::Serialization(format!("Snapshot serialization failed: {e}")))?;
        encrypt_at_rest(&self.master_key, b"sb-db:snapshot:v1", &bytes)
    }

    /// Decrypts and imports a standby DC snapshot into `machines` and `kv_encrypted` atomically.
    // [SECURITY-VERIFIED] CWE-345 / CWE-863 Mitigiert:
    // Erfordert `DbCapability::Admin`, verifiziert AES-GCM AAD `sb-db:snapshot:v1` und importiert
    // alle Zeilen innerhalb einer `IMMEDIATE`-Transaktion.
    pub fn import_encrypted_snapshot(
        &self,
        ticket: &VerifiedDbTicket,
        blob: &EncryptedBlob,
    ) -> DbResult<(usize, usize)> {
        ticket.authorize(DbCapability::Admin)?;
        let pt = decrypt_at_rest(&self.master_key, b"sb-db:snapshot:v1", blob)?;
        let doc: serde_json::Value = serde_json::from_slice(&pt)
            .map_err(|e| DbError::Serialization(format!("Invalid snapshot JSON: {e}")))?;
        if doc["v"].as_u64() != Some(1) {
            return Err(DbError::Validation("Unsupported snapshot version".into()));
        }

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbError::Storage("Database mutex poisoned".into()))?;
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::record_ticket_use(&tx, ticket, "snapshot:import", "standby")?;

        let mut machine_count = 0usize;
        if let Some(arr) = doc["machines"].as_array() {
            for item in arr {
                let (Some(machine_id), Some(domain), Some(record_enc), Some(updated_at)) = (
                    item["machine_id"].as_str(),
                    item["domain"].as_str(),
                    item["record_enc"].as_str(),
                    item["updated_at"].as_str(),
                ) else {
                    continue;
                };
                // Re-verify ciphertext integrity against row AAD before persisting
                let rec_blob: EncryptedBlob = serde_json::from_str(record_enc)
                    .map_err(|e| DbError::Serialization(format!("Corrupt machine blob: {e}")))?;
                let aad = Self::machine_aad(domain, machine_id);
                let rec_pt = decrypt_at_rest(&self.master_key, &aad, &rec_blob)?;
                let rec: MachineRecord = serde_json::from_slice(&rec_pt)
                    .map_err(|e| DbError::Serialization(format!("Corrupt machine record: {e}")))?;
                tx.execute(
                    "INSERT INTO machines (machine_id, domain, hostname, mesh_ip, revoked, record_enc, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(machine_id) DO UPDATE SET
                        domain = excluded.domain,
                        hostname = excluded.hostname,
                        mesh_ip = excluded.mesh_ip,
                        revoked = excluded.revoked,
                        record_enc = excluded.record_enc,
                        updated_at = excluded.updated_at",
                    params![
                        machine_id,
                        domain,
                        rec.hostname,
                        rec.mesh_ip,
                        if rec.revoked { 1i64 } else { 0i64 },
                        record_enc,
                        updated_at
                    ],
                )?;
                machine_count += 1;
            }
        }

        let mut kv_count = 0usize;
        if let Some(arr) = doc["kv"].as_array() {
            for item in arr {
                let (Some(ns), Some(key), Some(ver), Some(blob_enc), Some(updated_at)) = (
                    item["namespace"].as_str(),
                    item["key"].as_str(),
                    item["version"].as_u64(),
                    item["blob_enc"].as_str(),
                    item["updated_at"].as_str(),
                ) else {
                    continue;
                };
                tx.execute(
                    "INSERT INTO kv_encrypted (namespace, key, version, blob_enc, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(namespace, key) DO UPDATE SET
                        version = excluded.version,
                        blob_enc = excluded.blob_enc,
                        updated_at = excluded.updated_at",
                    params![ns, key, ver as u32, blob_enc, updated_at],
                )?;
                kv_count += 1;
            }
        }

        tx.commit()?;
        Ok((machine_count, kv_count))
    }
}
