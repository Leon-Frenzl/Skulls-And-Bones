//! S&B DB — Transactional SQLite WAL Persistence, Encryption-at-Rest,
//! E2EE Envelope Encryption & Ticket-Guarded Access.

pub mod crypto;
pub mod error;
pub mod store;
pub mod ticket;

pub use crypto::{
    decrypt_at_rest, encrypt_at_rest, open_e2ee, seal_e2ee, E2eeEnvelope, EncryptedBlob,
    MasterKey,
};
pub use error::{DbError, DbResult};
pub use store::{DbEntryMeta, SovereignDb};
pub use ticket::{verify_auth_token, verify_mesh_ticket, DbCapability, VerifiedDbTicket};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rand::rngs::OsRng;
    use sb_auth::{AuthEngine, AuthVerifier, Keypair};
    use sb_core::domain::{MachineRecord, OsKind};
    use sb_mesh::ticket::TicketGrantPayload;
    use std::sync::Arc;
    use tempfile::tempdir;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn test_ticket(caps: Vec<&str>, single_use: bool) -> VerifiedDbTicket {
        VerifiedDbTicket {
            ticket_id: format!("tkt-{}", rand::random::<u64>()),
            subject: "node-alpha".into(),
            role: "Admin".into(),
            capabilities: caps.into_iter().map(String::from).collect(),
            valid_until: (Utc::now().timestamp() + 3600) as u64,
            single_use,
        }
    }

    fn sample_machine(id: &str, host: &str) -> MachineRecord {
        MachineRecord {
            machine_id: id.into(),
            hostname: host.into(),
            domain: "corp.example.sb".into(),
            fqdn: format!("{host}.corp.example.sb"),
            os: OsKind::Linux,
            machine_public_key_b64: "pk-test".into(),
            mesh_ip: String::new(),
            joined_by: "sb.admin".into(),
            joined_at: Utc::now().to_rfc3339(),
            revoked: false,
            revoked_reason: None,
        }
    }

    #[test]
    fn test_e2ee_envelope_roundtrip_and_aad_tamper_fails() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_secret);
        let aad = b"encrypted_entries:laps:host-01:v1";
        let secret = b"super-secret-laps-password";

        let env = seal_e2ee(recipient_pub.as_bytes(), aad, secret).unwrap();
        let opened = open_e2ee(&recipient_secret, aad, &env).unwrap();
        assert_eq!(opened.as_slice(), secret);

        // Tampering with AAD (e.g. moving ciphertext to another row) must fail
        let wrong_aad = b"encrypted_entries:laps:host-02:v1";
        assert!(open_e2ee(&recipient_secret, wrong_aad, &env).is_err());

        // Wrong recipient key must fail
        let attacker_secret = StaticSecret::random_from_rng(OsRng);
        assert!(open_e2ee(&attacker_secret, aad, &env).is_err());
    }

    #[test]
    fn test_concurrent_machine_registration_allocates_unique_ips() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("domain.db");
        let db = Arc::new(SovereignDb::open(&db_path, MasterKey::generate()).unwrap());
        let ticket = test_ticket(vec!["db:write", "db:read"], false);

        let mut handles = Vec::new();
        for i in 0..16 {
            let db_ref = Arc::clone(&db);
            let tkt = ticket.clone();
            handles.push(std::thread::spawn(move || {
                let rec = sample_machine(&format!("m-{i}"), &format!("host-{i}"));
                db_ref
                    .register_machine_atomic(&tkt, "corp.example.sb", rec)
                    .unwrap()
            }));
        }

        let mut ips = std::collections::HashSet::new();
        for h in handles {
            let reg = h.join().unwrap();
            assert!(ips.insert(reg.mesh_ip), "Duplicate IP allocated!");
        }
        assert_eq!(ips.len(), 16);
    }

    #[test]
    fn test_single_use_ticket_and_e2ee_db_storage() {
        let db = SovereignDb::open_in_memory(MasterKey::generate()).unwrap();
        let write_tkt = test_ticket(vec!["db:write"], false);
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_secret);

        db.put_e2ee_entry(
            &write_tkt,
            "laps",
            "srv-01",
            recipient_pub.as_bytes(),
            b"P@ssw0rd-123",
        )
        .unwrap();

        // Read without SecretReveal capability must fail
        let read_only = test_ticket(vec!["db:read"], false);
        assert!(matches!(
            db.get_e2ee_entry(&read_only, "laps", "srv-01", &recipient_secret),
            Err(DbError::Unauthorized(_))
        ));

        // Single-use SecretReveal succeeds once and fails on replay
        let reveal_once = test_ticket(vec!["db:secret:reveal"], true);
        let pt = db
            .get_e2ee_entry(&reveal_once, "laps", "srv-01", &recipient_secret)
            .unwrap();
        assert_eq!(pt.as_slice(), b"P@ssw0rd-123");

        assert!(matches!(
            db.get_e2ee_entry(&reveal_once, "laps", "srv-01", &recipient_secret),
            Err(DbError::Unauthorized(_))
        ));
    }

    #[test]
    fn test_mesh_ticket_verification_binds_to_auth_token() {
        let rev = std::sync::Arc::new(sb_auth::MemoryRevocationStore::new());
        let kp = Keypair::generate();
        let engine = AuthEngine::new(kp, std::sync::Arc::clone(&rev) as _);
        let tokens = engine
            .issue_session(
                "node-42",
                vec!["Admin".into()],
                vec!["db:read".into()],
                serde_json::Value::Null,
            )
            .unwrap();
        let verifier = AuthVerifier::from_public_base64(&engine.public_key_base64(), rev).unwrap();

        let grant = TicketGrantPayload {
            server_node_id: "dc-1".into(),
            server_pubkey: "srv-pk".into(),
            subject_node_id: "node-42".into(),
            granted_mesh: "corp".into(),
            overlay_subnet: "10.42.0.0/16".into(),
            swarm_topic: "corp".into(),
            swarm_tag: [0u8; 8],
            valid_until: (Utc::now().timestamp() + 3600) as u64,
            session_ticket: tokens.access_token,
            assigned_ip: Some("10.42.0.10".into()),
            relay_port: 58888,
            request_nonce: 99,
            role: "Admin".into(),
            capabilities: vec!["db:read".into()],
        };

        let verified = verify_mesh_ticket(&grant, &verifier, false).unwrap();
        assert!(verified.authorize(DbCapability::Read).is_ok());
        assert!(verified.authorize(DbCapability::Write).is_err());

        // Forged subject_node_id must be rejected
        let mut forged = grant;
        forged.subject_node_id = "attacker-node".into();
        assert!(verify_mesh_ticket(&forged, &verifier, false).is_err());
    }

    #[test]
    fn test_kv_encrypted_store_lockouts_and_snapshot() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let key = MasterKey::generate();

        {
            let db = SovereignDb::open(&db_path, key.clone()).unwrap();
            let admin_tkt = test_ticket(vec!["db:admin"], false);
            let sample = serde_json::json!({ "revision": 7, "policy": "baseline" });
            let ver = db
                .put_encrypted_json(&admin_tkt, "policies", "corp.example.sb", &sample)
                .unwrap();
            assert_eq!(ver, 1);

            let loaded: serde_json::Value = db
                .get_encrypted_json(&admin_tkt, "policies", "corp.example.sb")
                .unwrap()
                .unwrap();
            assert_eq!(loaded["revision"], 7);

            assert!(db.record_auth_failure("alice", 3, 60).unwrap().is_none());
            assert!(db.record_auth_failure("alice", 3, 60).unwrap().is_none());
            let locked = db.record_auth_failure("alice", 3, 60).unwrap();
            assert!(locked.is_some());

            let snap = db.export_encrypted_snapshot(&admin_tkt).unwrap();
            let plain_snap = decrypt_at_rest(&key, b"sb-db:snapshot:v1", &snap).unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&plain_snap).unwrap();
            assert_eq!(parsed["kv"].as_array().unwrap().len(), 1);
        }

        // Reopen DB to verify lockout persists across daemon restarts
        let db2 = SovereignDb::open(&db_path, key.clone()).unwrap();
        assert!(db2.check_auth_lockout("alice").unwrap().is_some());
        db2.clear_auth_lockout("alice").unwrap();
        assert!(db2.check_auth_lockout("alice").unwrap().is_none());

        // Standby DC replication test: import snapshot into a fresh DB instance
        let standby_path = dir.path().join("standby.db");
        let standby = SovereignDb::open(&standby_path, key).unwrap();
        let admin_tkt = test_ticket(vec!["db:admin"], false);
        let primary = SovereignDb::open(&db_path, MasterKey::generate()).ok();
        let _ = primary;
        let snap = db2.export_encrypted_snapshot(&admin_tkt).unwrap();
        let (m_cnt, kv_cnt) = standby.import_encrypted_snapshot(&admin_tkt, &snap).unwrap();
        assert_eq!(m_cnt, 0);
        assert_eq!(kv_cnt, 1);
        let replicated: serde_json::Value = standby
            .get_encrypted_json(&admin_tkt, "policies", "corp.example.sb")
            .unwrap()
            .unwrap();
        assert_eq!(replicated["revision"], 7);
    }
}
