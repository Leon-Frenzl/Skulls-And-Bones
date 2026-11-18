use serde::{Deserialize, Serialize};

/// RFC 6479 / WireGuard style 1024-packet sliding window anti-replay filter.
/// Protects against replay attacks by maintaining a bitmap of recently received packet sequence counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiReplayWindow {
    /// Highest packet sequence number seen and verified so far
    pub last_seq: u64,
    /// 1024-bit window represented as 16 x 64-bit words
    pub bitmap: [u64; 16],
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayWindow {
    pub const WINDOW_SIZE: u64 = 1024;
    const WORD_BITS: u64 = 64;
    const NUM_WORDS: usize = 16;

    pub fn new() -> Self {
        Self {
            last_seq: 0,
            bitmap: [0u64; 16],
        }
    }

    /// Reset filter state (e.g. upon session re-keying or fresh handshake)
    pub fn reset(&mut self) {
        self.last_seq = 0;
        self.bitmap.fill(0);
    }

    /// Phase 1: Check whether the sequence counter could be valid without modifying internal state.
    /// Returns true if packet sequence is fresh (not a replay and within window).
    pub fn check(&self, seq: u64) -> bool {
        if self.last_seq == 0 && self.bitmap[0] == 0 {
            // First packet received in session
            return true;
        }

        if seq > self.last_seq {
            // New ahead-of-sequence packet, always candidate for acceptance
            return true;
        }

        let diff = self.last_seq - seq;
        if diff >= Self::WINDOW_SIZE {
            // Packet is too old; falls behind the 1024-packet window
            return false;
        }

        let word_idx = (diff / Self::WORD_BITS) as usize;
        let bit_idx = diff % Self::WORD_BITS;

        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// Phase 2: Commit sequence number into sliding window after successful MAC/AEAD authentication.
    pub fn update(&mut self, seq: u64) {
        if self.last_seq == 0 && self.bitmap[0] == 0 {
            self.last_seq = seq;
            self.bitmap[0] = 1;
            return;
        }

        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff >= Self::WINDOW_SIZE {
                // Large jump forward, completely reset window
                self.bitmap.fill(0);
            } else {
                let word_shift = (diff / Self::WORD_BITS) as usize;
                let bit_shift = (diff % Self::WORD_BITS) as u32;

                if word_shift > 0 {
                    for i in (word_shift..Self::NUM_WORDS).rev() {
                        self.bitmap[i] = self.bitmap[i - word_shift];
                    }
                    for i in 0..word_shift {
                        self.bitmap[i] = 0;
                    }
                }

                if bit_shift > 0 {
                    let mut carry = 0u64;
                    for i in 0..Self::NUM_WORDS {
                        let next_carry = self.bitmap[i] >> (64 - bit_shift);
                        self.bitmap[i] = (self.bitmap[i] << bit_shift) | carry;
                        carry = next_carry;
                    }
                }
            }

            self.last_seq = seq;
            self.bitmap[0] |= 1;
        } else {
            let diff = self.last_seq - seq;
            if diff < Self::WINDOW_SIZE {
                let word_idx = (diff / Self::WORD_BITS) as usize;
                let bit_idx = diff % Self::WORD_BITS;
                self.bitmap[word_idx] |= 1u64 << bit_idx;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential_packets() {
        let mut ar = AntiReplayWindow::new();
        assert!(ar.check(1));
        ar.update(1);

        assert!(ar.check(2));
        ar.update(2);

        // Replays of 1 and 2 must fail
        assert!(!ar.check(1));
        assert!(!ar.check(2));

        // 3 is valid
        assert!(ar.check(3));
        ar.update(3);
        assert!(!ar.check(3));
    }

    #[test]
    fn test_out_of_order_packets() {
        let mut ar = AntiReplayWindow::new();
        ar.update(10);

        // Within window, not yet seen
        assert!(ar.check(9));
        assert!(ar.check(8));
        assert!(ar.check(1));

        ar.update(8);
        assert!(!ar.check(8)); // now seen
        assert!(ar.check(9)); // still unseen

        ar.update(9);
        assert!(!ar.check(9)); // now seen
    }

    #[test]
    fn test_window_overflow() {
        let mut ar = AntiReplayWindow::new();
        ar.update(2000);

        // Within window
        assert!(ar.check(2000 - 500));
        // Outside window (diff >= 1024)
        assert!(!ar.check(2000 - 1025));
    }

    #[test]
    fn test_reset() {
        let mut ar = AntiReplayWindow::new();
        ar.update(100);
        assert!(!ar.check(100));

        ar.reset();
        assert!(ar.check(100));
    }
}
