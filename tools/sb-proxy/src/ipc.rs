use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub use sb_core::dto::ProxyTelemetryDto;

pub struct ProxyTelemetry {
    pub started_at: Instant,
    pub total_requests: u64,
    pub requests_2xx: u64,
    pub requests_4xx: u64,
    pub requests_5xx: u64,
    pub rate_limited_count: u64,
    pub total_latency_ms: f64,
    pub latency_samples: u64,
}

impl Default for ProxyTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyTelemetry {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            total_requests: 0,
            requests_2xx: 0,
            requests_4xx: 0,
            requests_5xx: 0,
            rate_limited_count: 0,
            total_latency_ms: 0.0,
            latency_samples: 0,
        }
    }

    pub fn increment_requests(&mut self) {
        self.total_requests += 1;
    }

    pub fn increment_rate_limited(&mut self) {
        self.rate_limited_count += 1;
        self.requests_4xx += 1;
    }

    pub fn record_status(&mut self, status_code: u16, latency_ms: f32) {
        if (200..300).contains(&status_code) {
            self.requests_2xx += 1;
        } else if (400..500).contains(&status_code) {
            self.requests_4xx += 1;
        } else if (500..600).contains(&status_code) {
            self.requests_5xx += 1;
        }
        if latency_ms >= 0.0 {
            self.total_latency_ms += latency_ms as f64;
            self.latency_samples += 1;
        }
    }

    pub fn to_dto(&self, active_spaces_count: usize) -> ProxyTelemetryDto {
        let avg_latency = if self.latency_samples > 0 {
            (self.total_latency_ms / self.latency_samples as f64) as f32
        } else {
            0.0
        };

        ProxyTelemetryDto {
            status: "online".to_string(),
            pid: std::process::id(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            total_requests: self.total_requests,
            requests_2xx: self.requests_2xx,
            requests_4xx: self.requests_4xx,
            requests_5xx: self.requests_5xx,
            rate_limited_count: self.rate_limited_count,
            avg_latency_ms: (avg_latency * 10.0).round() / 10.0,
            active_spaces_count,
        }
    }
}

/// Runs the local loopback IPC control & telemetry server (default: 127.0.0.1:58900).
pub async fn run_ipc_server(
    bind_addr: &str,
    telemetry: Arc<RwLock<ProxyTelemetry>>,
    routes: Arc<RwLock<sb_code::escape::EscapeSpaceStore>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind_addr).await?;

    loop {
        match listener.accept().await {
            Ok((mut socket, _)) => {
                let tele_clone = telemetry.clone();
                let routes_clone = routes.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    if let Ok(Ok(n)) = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        socket.read(&mut buf),
                    )
                    .await
                    {
                        if n > 0 {
                            let request = String::from_utf8_lossy(&buf[..n]);
                            let path = request
                                .lines()
                                .next()
                                .and_then(|l| l.split_whitespace().nth(1))
                                .unwrap_or("/");

                            if path == "/health" {
                                let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                                let _ = socket.write_all(resp.as_bytes()).await;
                            } else {
                                // Default / or /status -> JSON Telemetry
                                let active_count = if let Ok(r) = routes_clone.read() {
                                    r.spaces
                                        .iter()
                                        .filter(|s| {
                                            s.status == sb_code::escape::EscapeStatus::Active
                                        })
                                        .count()
                                } else {
                                    0
                                };

                                let dto = if let Ok(t) = tele_clone.read() {
                                    t.to_dto(active_count)
                                } else {
                                    ProxyTelemetryDto {
                                        status: "degraded".to_string(),
                                        pid: std::process::id(),
                                        uptime_secs: 0,
                                        total_requests: 0,
                                        requests_2xx: 0,
                                        requests_4xx: 0,
                                        requests_5xx: 0,
                                        rate_limited_count: 0,
                                        avg_latency_ms: 0.0,
                                        active_spaces_count: active_count,
                                    }
                                };

                                let json = serde_json::to_string(&dto)
                                    .unwrap_or_else(|_| "{}".to_string());
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    json.len(),
                                    json
                                );
                                let _ = socket.write_all(resp.as_bytes()).await;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("IPC Accept Fehler: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_dto_conversion() {
        let mut telemetry = ProxyTelemetry::new();
        telemetry.increment_requests();
        telemetry.increment_requests();
        telemetry.increment_rate_limited();
        telemetry.record_status(200, 12.5);
        telemetry.record_status(500, 45.0);

        let dto = telemetry.to_dto(3);
        assert_eq!(dto.status, "online");
        assert_eq!(dto.total_requests, 2);
        assert_eq!(dto.rate_limited_count, 1);
        assert_eq!(dto.requests_2xx, 1);
        assert_eq!(dto.requests_4xx, 1);
        assert_eq!(dto.requests_5xx, 1);
        assert_eq!(dto.avg_latency_ms, 28.8);
        assert_eq!(dto.active_spaces_count, 3);
        assert_eq!(dto.pid, std::process::id());
    }
}
