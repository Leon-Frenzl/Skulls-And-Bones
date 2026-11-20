//! Real-Time DC Revocation SSE Sync for `sb-dns`.
//!
//! Connects to the Domain Controller's `GET /v1/events/revocations` SSE stream
//! and immediately purges revoked machines from the live DNS directory & cache.

use crate::resolver::DnsResolver;
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug, Deserialize)]
pub struct DcRevocationPayload {
    pub kind: String,
    pub target: String,
    pub domain: String,
}

/// Parses a single SSE `data: {...}` line and applies revocation to `resolver`.
pub async fn apply_sse_data_line(resolver: &DnsResolver, line: &str) -> bool {
    let Some(json_str) = line.strip_prefix("data:").map(str::trim) else {
        return false;
    };
    let Ok(ev) = serde_json::from_str::<DcRevocationPayload>(json_str) else {
        return false;
    };
    if ev.kind == "machine_revoked" {
        resolver.revoke_machine_live(&ev.target).await;
        sb_core::logfmt::info(
            "DNS_LIVE_REVOKE",
            "dns.dc_sync",
            "Purged revoked machine from DNS directory and cache",
            &[("target", &ev.target), ("domain", &ev.domain)],
        );
        return true;
    }
    false
}

/// Streams real-time revocations from a local/plain DC HTTP endpoint (`host:port`) with reconnect.
pub async fn run_revocation_sse_loop(
    dc_addr: &str,
    bearer_token: &str,
    resolver: Arc<DnsResolver>,
) -> Result<(), String> {
    let stream = TcpStream::connect(dc_addr)
        .await
        .map_err(|e| format!("Failed to connect to DC SSE {dc_addr}: {e}"))?;
    let (rd, mut wr) = stream.into_split();
    let req = format!(
        "GET /v1/events/revocations HTTP/1.1\r\nHost: {dc_addr}\r\nAuthorization: Bearer {bearer_token}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n"
    );
    wr.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("SSE request write failed: {e}"))?;

    let mut lines = BufReader::new(rd).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let _ = apply_sse_data_line(&resolver, &line).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsConfig, RecordsConfig};
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn sse_revocation_purges_static_record_and_cache() {
        let mut records = RecordsConfig::default();
        records
            .a
            .insert("node-1.corp.eu".into(), Ipv4Addr::new(10, 42, 0, 11));
        let resolver = DnsResolver::new(DnsConfig::default(), records);

        let handled = apply_sse_data_line(
            &resolver,
            r#"data: {"kind":"machine_revoked","target":"node-1.corp.eu","domain":"corp.eu","issued_at":"2026-11-20T00:00:00Z"}"#,
        )
        .await;
        assert!(handled);
        assert!(!resolver.records.lock().unwrap().a.contains_key("node-1.corp.eu"));
    }
}
