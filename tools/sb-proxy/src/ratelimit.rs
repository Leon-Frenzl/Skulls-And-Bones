use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Token-Bucket Rate Limiter per Client-IP address.
#[derive(Clone)]
pub struct IpRateLimiter {
    // Map IP -> (tokens, last_update)
    buckets: Arc<RwLock<HashMap<IpAddr, (f64, Instant)>>>,
}

impl Default for IpRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl IpRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Checks whether an incoming request from `ip` is allowed under `rpm` (requests per minute).
    /// If allowed, consumes 1 token and returns Ok(()).
    /// If rate-limited, returns Err(retry_after_secs).
    pub fn check_and_consume(&self, ip: IpAddr, rpm: u32) -> Result<(), u64> {
        let max_capacity = rpm.max(1) as f64;
        let fill_rate_per_sec = max_capacity / 60.0;
        let now = Instant::now();

        let mut buckets = self.buckets.write().map_err(|_| 1u64)?;

        // Periodically cleanup stale entries (> 5 minutes inactive) if bucket map grows
        if buckets.len() > 1000 {
            buckets.retain(|_, (_, last_update)| now.duration_since(*last_update).as_secs() < 300);
        }

        let entry = buckets.entry(ip).or_insert((max_capacity, now));
        let (ref mut tokens, ref mut last_update) = *entry;

        // Calculate elapsed time and replenish tokens
        let elapsed_secs = now.duration_since(*last_update).as_secs_f64();
        *tokens = (*tokens + elapsed_secs * fill_rate_per_sec).min(max_capacity);
        *last_update = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            let needed = 1.0 - *tokens;
            let wait_secs = (needed / fill_rate_per_sec).ceil() as u64;
            Err(wait_secs.max(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_allows_and_blocks() {
        let limiter = IpRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let rpm = 3;

        // 3 requests allowed
        assert!(limiter.check_and_consume(ip, rpm).is_ok());
        assert!(limiter.check_and_consume(ip, rpm).is_ok());
        assert!(limiter.check_and_consume(ip, rpm).is_ok());

        // 4th request must be rate-limited
        let blocked = limiter.check_and_consume(ip, rpm);
        assert!(blocked.is_err());
        assert!(blocked.unwrap_err() >= 1);
    }
}
