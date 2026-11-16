//! Tamper-evident, hash-chained Audit Log (`~/.sb/domain/audit.jsonl`) for `sb-node`.
//!
//! Every security-relevant directory, machine, policy, and offboarding action appends a
//! SHA-256 hash-chained JSONL entry for NIS2 / DSGVO compliance.

use chrono::Utc;
use sb_core::domain::local_domain_dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// A single immutable, hash-chained audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub seq: u64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub details: serde_json::Value,
    pub prev_hash: String,
    pub event_hash: String,
}

/// Returns the default audit log path (`~/.sb/domain/audit.jsonl`).
pub fn default_audit_log_path() -> PathBuf {
    local_domain_dir().join("audit.jsonl")
}

fn compute_event_hash(
    seq: u64,
    timestamp: &str,
    actor: &str,
    action: &str,
    target: &str,
    outcome: &str,
    details: &serde_json::Value,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_le_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.as_bytes());
    hasher.update(b"|");
    hasher.update(actor.as_bytes());
    hasher.update(b"|");
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(target.as_bytes());
    hasher.update(b"|");
    hasher.update(outcome.as_bytes());
    hasher.update(b"|");
    hasher.update(details.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Appends a new hash-chained event to the JSONL audit log.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Silent tampering or deletion of historical audit entries.
/// - **CVE / CWE Mapping:** CWE-778 (Insufficient Logging), CWE-345 (Insufficient Verification
///   of Data Authenticity).
/// - **Likelihood & Exploitability:** Medium (5/10) on compromised hosts.
/// - **Applied Mitigation:** Links each entry via SHA-256 (`prev_hash` -> `event_hash`) so
///   any modification or truncation of prior lines breaks verification.
///
/// # Standards Compliance
/// - Conforms to RFC 8259 (JSON) and RFC 3339 (timestamps).
pub fn append_audit_event(
    path: &Path,
    actor: &str,
    action: &str,
    target: &str,
    outcome: &str,
    details: serde_json::Value,
) -> Result<AuditEvent, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create audit log dir: {e}"))?;
    }

    let existing = read_all_events(path)?;
    let (seq, prev_hash) = match existing.last() {
        Some(last) => (last.seq.saturating_add(1), last.event_hash.clone()),
        None => (1, "0".repeat(64)),
    };

    let timestamp = Utc::now().to_rfc3339();
    let event_hash = compute_event_hash(
        seq, &timestamp, actor, action, target, outcome, &details, &prev_hash,
    );
    let event = AuditEvent {
        seq,
        timestamp,
        actor: actor.to_string(),
        action: action.to_string(),
        target: target.to_string(),
        outcome: outcome.to_string(),
        details,
        prev_hash,
        event_hash,
    };
    let line = serde_json::to_string(&event)
        .map_err(|e| format!("Failed to serialize audit event: {e}"))?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Failed to open audit log {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("Failed to write audit event: {e}"))?;
    Ok(event)
}

/// Reads all audit events from `path`.
pub fn read_all_events(path: &Path) -> Result<Vec<AuditEvent>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read audit log {}: {e}", path.display()))?;
    let mut events = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let ev: AuditEvent = serde_json::from_str(trimmed)
            .map_err(|e| format!("Corrupt audit event at line {}: {e}", idx + 1))?;
        events.push(ev);
    }
    Ok(events)
}

/// Reads up to `limit` most recent audit events (newest first).
pub fn read_recent_events(path: &Path, limit: usize) -> Result<Vec<AuditEvent>, String> {
    let mut events = read_all_events(path)?;
    events.reverse();
    events.truncate(limit);
    Ok(events)
}

/// Verifies the entire SHA-256 hash chain in `path`.
pub fn verify_audit_chain(path: &Path) -> Result<usize, String> {
    let events = read_all_events(path)?;
    let mut expected_prev = "0".repeat(64);
    for (idx, ev) in events.iter().enumerate() {
        if ev.seq != (idx as u64) + 1 {
            return Err(format!("Audit sequence gap at index {idx}"));
        }
        if ev.prev_hash != expected_prev {
            return Err(format!("Audit prev_hash mismatch at seq {}", ev.seq));
        }
        let expected_hash = compute_event_hash(
            ev.seq,
            &ev.timestamp,
            &ev.actor,
            &ev.action,
            &ev.target,
            &ev.outcome,
            &ev.details,
            &ev.prev_hash,
        );
        if ev.event_hash != expected_hash {
            return Err(format!(
                "Audit event_hash tampering detected at seq {}",
                ev.seq
            ));
        }
        expected_prev = ev.event_hash.clone();
    }
    Ok(events.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_chains_hashes_and_detects_tampering() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_audit_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let path = temp.join("audit.jsonl");

        append_audit_event(
            &path,
            "admin",
            "user.upsert",
            "anna.admin",
            "ok",
            serde_json::json!({ "groups": ["engineering"] }),
        )
        .unwrap();
        append_audit_event(
            &path,
            "admin",
            "user.offboard",
            "anna.admin",
            "ok",
            serde_json::json!({ "revoked_machines": 1 }),
        )
        .unwrap();

        assert_eq!(verify_audit_chain(&path).unwrap(), 2);
        let recent = read_recent_events(&path, 10).unwrap();
        assert_eq!(recent[0].action, "user.offboard");

        // Tamper with first line
        let raw = fs::read_to_string(&path).unwrap();
        let tampered = raw.replacen("user.upsert", "user.evil", 1);
        fs::write(&path, tampered).unwrap();
        assert!(verify_audit_chain(&path).is_err());

        let _ = fs::remove_dir_all(&temp);
    }
}
