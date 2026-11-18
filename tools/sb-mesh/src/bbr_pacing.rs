use std::time::{Duration, Instant};

/// Delay-Gradient Congestion Controller & Anti-Bufferbloat Pacing.
///
/// Continuously tracks the slope of the round-trip time (RTT) before packet loss occurs.
/// Prevents intermediate router queues from overflowing and triggering sudden packet drops.
#[derive(Debug, Clone)]
pub struct BbrGradientPacer {
    pub min_rtt: Duration,
    pub smoothed_rtt: Duration,
    pub last_update: Instant,
    pub current_pacing_delay: Duration,
    pub queue_bloat_detected: bool,
}

impl BbrGradientPacer {
    pub const DEFAULT_PACING: Duration = Duration::from_micros(100);
    pub const MAX_PACING: Duration = Duration::from_millis(5);
    pub const BLOAT_THRESHOLD_RATIO: f64 = 0.15; // 15% increase in RTT triggers gentle pace backoff

    pub fn new() -> Self {
        Self {
            min_rtt: Duration::ZERO,
            smoothed_rtt: Duration::ZERO,
            last_update: Instant::now(),
            current_pacing_delay: Self::DEFAULT_PACING,
            queue_bloat_detected: false,
        }
    }

    /// Feeds a new RTT sample and dynamically adjusts pacing delay
    pub fn update_rtt(&mut self, sample: Duration) {
        if self.min_rtt == Duration::ZERO || sample < self.min_rtt {
            self.min_rtt = sample;
        }

        let new_srtt = if self.smoothed_rtt == Duration::ZERO {
            self.smoothed_rtt = sample;
            sample.as_micros() as f64
        } else {
            // Exponential moving average: SRTT = 0.875 * SRTT + 0.125 * Sample
            let sample_micros = sample.as_micros() as f64;
            let prev_micros = self.smoothed_rtt.as_micros() as f64;
            let calc = 0.875 * prev_micros + 0.125 * sample_micros;
            self.smoothed_rtt = Duration::from_micros(calc as u64);
            calc
        };

        // Compute Delay Gradient: Delta = (SRTT - MinRTT) / MinRTT
        let min_micros = self.min_rtt.as_micros() as f64;
        if min_micros > 0.0 {
            let gradient = (new_srtt - min_micros) / min_micros;
            if gradient > Self::BLOAT_THRESHOLD_RATIO {
                // Buffer queue is building up: gently increase pacing delay by 5%
                self.queue_bloat_detected = true;
                let current = self.current_pacing_delay.as_micros() as f64;
                let adjusted = (current * 1.05).min(Self::MAX_PACING.as_micros() as f64);
                self.current_pacing_delay = Duration::from_micros(adjusted as u64);
            } else {
                // Network queue is clear: gradually recover towards minimal pacing
                self.queue_bloat_detected = false;
                let current = self.current_pacing_delay.as_micros() as f64;
                let adjusted = (current * 0.98).max(Self::DEFAULT_PACING.as_micros() as f64);
                self.current_pacing_delay = Duration::from_micros(adjusted as u64);
            }
        }
        self.last_update = Instant::now();
    }

    /// Returns the recommended pacing sleep duration between consecutive packet transmissions
    pub fn pacing_delay(&self) -> Duration {
        self.current_pacing_delay
    }
}

impl Default for BbrGradientPacer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbr_gradient_pacing_backoff_and_recovery() {
        let mut pacer = BbrGradientPacer::new();
        pacer.update_rtt(Duration::from_millis(20)); // Base RTT: 20ms
        assert_eq!(pacer.min_rtt, Duration::from_millis(20));
        assert!(!pacer.queue_bloat_detected);

        // Simulate buffer queue buildup: RTT rises to 40ms (+100%)
        for _ in 0..5 {
            pacer.update_rtt(Duration::from_millis(40));
        }

        assert!(pacer.queue_bloat_detected);
        assert!(pacer.pacing_delay() > BbrGradientPacer::DEFAULT_PACING);

        // Simulate queue draining: RTT returns to 20ms
        for _ in 0..30 {
            pacer.update_rtt(Duration::from_millis(20));
        }
        assert!(!pacer.queue_bloat_detected);
    }
}
