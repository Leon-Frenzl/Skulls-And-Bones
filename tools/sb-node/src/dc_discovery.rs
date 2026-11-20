//! Real-Time Revocation Push Broadcaster & DNS-Based DC Discovery (RFC 2782).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Real-time revocation event pushed to connected agents and reverse proxies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEvent {
    pub kind: String,
    pub target: String,
    pub domain: String,
    pub issued_at: String,
}

impl RevocationEvent {
    pub fn machine_revoked(machine_id: &str, domain: &str) -> Self {
        Self {
            kind: "machine_revoked".into(),
            target: machine_id.into(),
            domain: domain.into(),
            issued_at: Utc::now().to_rfc3339(),
        }
    }

    pub fn user_offboarded(username: &str, domain: &str) -> Self {
        Self {
            kind: "user_offboarded".into(),
            target: username.into(),
            domain: domain.into(),
            issued_at: Utc::now().to_rfc3339(),
        }
    }

    /// Formats the event as an RFC 8895 / W3C Server-Sent Events frame.
    pub fn to_sse_frame(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        format!("event: revocation\ndata: {json}\n\n")
    }
}

/// Broadcast hub for instant revocation push (`GET /v1/events/revocations`).
#[derive(Clone)]
pub struct RevocationBroadcaster {
    tx: broadcast::Sender<RevocationEvent>,
}

impl Default for RevocationBroadcaster {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self { tx }
    }
}

impl RevocationBroadcaster {
    pub fn publish(&self, ev: RevocationEvent) {
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RevocationEvent> {
        self.tx.subscribe()
    }
}

/// Registers RFC 2782 SRV records for automatic DC discovery in `sb-dns`.
pub fn register_dc_srv_records(
    domain: &str,
    dc_target_host: &str,
    dc_port: u16,
    console_target_host: Option<&str>,
) -> Result<(), String> {
    let clean_domain = domain.trim().trim_end_matches('.');
    let srv_dc = format!("_sb-dc._tcp.{clean_domain}");
    sb_dns::config::ConfigManager::add_srv_record(&srv_dc, 10, 0, dc_port, dc_target_host)?;
    if let Some(console_host) = console_target_host {
        let srv_console = format!("_sb-console._tcp.{clean_domain}");
        sb_dns::config::ConfigManager::add_srv_record(&srv_console, 10, 0, 443, console_host)?;
    }
    Ok(())
}

/// Discovers the Domain Controller HTTPS URL for `domain` via local `sb-dns` SRV records.
pub fn discover_dc_url_from_dns(domain: &str) -> Option<String> {
    let clean_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let records = sb_dns::config::ConfigManager::load_records();
    for prefix in ["_sb-console._tcp.", "_sb-dc._tcp."] {
        let key = format!("{prefix}{clean_domain}");
        if let Some(entries) = records.srv.get(&key) {
            if let Some(best) = entries.iter().min_by_key(|e| e.priority) {
                let target = best.target.trim().trim_end_matches('.');
                if !target.is_empty() {
                    if best.port == 443 {
                        return Some(format!("https://{target}"));
                    }
                    return Some(format!("https://{target}:{}", best.port));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_broadcaster_delivers_events_in_real_time() {
        let hub = RevocationBroadcaster::default();
        let mut rx = hub.subscribe();
        hub.publish(RevocationEvent::machine_revoked("mach_123", "corp.eu"));
        hub.publish(RevocationEvent::user_offboarded("alice", "corp.eu"));

        let ev1 = rx.try_recv().unwrap();
        assert_eq!(ev1.kind, "machine_revoked");
        assert_eq!(ev1.target, "mach_123");
        assert!(ev1.to_sse_frame().starts_with("event: revocation\ndata: "));

        let ev2 = rx.try_recv().unwrap();
        assert_eq!(ev2.kind, "user_offboarded");
        assert_eq!(ev2.target, "alice");
    }

    #[test]
    fn srv_discovery_resolves_dc_url() {
        register_dc_srv_records("test-dc.local", "dc.test-dc.local", 8443, None).unwrap();
        let discovered = discover_dc_url_from_dns("test-dc.local");
        assert_eq!(discovered.as_deref(), Some("https://dc.test-dc.local:8443"));
        let _ = sb_dns::config::ConfigManager::remove_record("_sb-dc._tcp.test-dc.local");
    }
}
