use rand::Rng;
use sha2::{Digest, Sha256};

pub const STANDARD_BUCKETS: &[usize] = &[128, 256, 512, 1024, 1400];
pub const HEADER_MASK_SEPARATOR: &[u8] = b"SBM_HEADER_MASK_V1";

/// Applies random noise padding or bucket-aligned padding to prevent DPI packet-length profiling
pub fn apply_padding(payload: &[u8], target_bucket: Option<usize>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let min_overhead = 2usize; // 2 bytes to store padding length

    let padding_len = if let Some(bucket) = target_bucket {
        if bucket >= payload.len() + min_overhead {
            bucket - payload.len() - min_overhead
        } else {
            // Pick next standard bucket or random noise
            let mut chosen = 0;
            for &b in STANDARD_BUCKETS {
                if b >= payload.len() + min_overhead {
                    chosen = b - payload.len() - min_overhead;
                    break;
                }
            }
            if chosen == 0 {
                rng.gen_range(16..=48)
            } else {
                chosen
            }
        }
    } else {
        // Random noise padding between 16 and 64 bytes
        rng.gen_range(16..=64)
    };

    let mut out = Vec::with_capacity(payload.len() + padding_len + 2);
    out.extend_from_slice(payload);

    // Append pseudorandom noise bytes
    for _ in 0..padding_len {
        out.push(rng.gen::<u8>());
    }

    // Append 2-byte big-endian padding length
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out
}

/// Removes padding and validates packet integrity
pub fn remove_padding(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 2 {
        return Err("Packet too short to contain padding header".to_string());
    }

    let len = padded.len();
    let padding_len = u16::from_be_bytes([padded[len - 2], padded[len - 1]]) as usize;

    if padding_len + 2 > len {
        return Err(format!(
            "Invalid padding length: specified {} bytes, but total length is {}",
            padding_len, len
        ));
    }

    let payload_len = len - 2 - padding_len;
    Ok(padded[..payload_len].to_vec())
}

/// Masks header bytes with a deterministic high-entropy keystream derived from session salt and sequence counter
pub fn mask_header(header: &[u8], session_salt: &[u8; 32], counter: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(HEADER_MASK_SEPARATOR);
    hasher.update(session_salt);
    hasher.update(counter.to_be_bytes());
    let mask = hasher.finalize();

    let mut masked = Vec::with_capacity(header.len());
    for (i, &b) in header.iter().enumerate() {
        masked.push(b ^ mask[i % 32]);
    }
    masked
}

/// Demasks header bytes (XOR operation is symmetric)
pub fn unmask_header(masked: &[u8], session_salt: &[u8; 32], counter: u64) -> Vec<u8> {
    mask_header(masked, session_salt, counter)
}

pub const CHAFF_MAGIC: [u8; 4] = *b"SBMC";

/// Generates a Maybenot/WTF-PAD cover traffic dummy packet (Chaff) indistinguishable from regular encrypted traffic
pub fn generate_chaff_packet(target_bucket: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut inner = Vec::with_capacity(32);
    inner.extend_from_slice(&CHAFF_MAGIC);
    for _ in 0..28 {
        inner.push(rng.gen::<u8>());
    }
    apply_padding(&inner, Some(target_bucket))
}

/// Identifies if a decrypted or unpacked payload is a dummy cover packet to be dropped silently
pub fn is_chaff_packet(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[0..4] == CHAFF_MAGIC
}

/// Computes a stochastic micro-timing jitter (in milliseconds) to destroy Inter-Packet Arrival Time (IAT) AI classifiers
pub fn compute_timing_jitter(min_ms: u64, max_ms: u64) -> std::time::Duration {
    let mut rng = rand::thread_rng();
    let ms = if max_ms > min_ms {
        rng.gen_range(min_ms..=max_ms)
    } else {
        min_ms
    };
    std::time::Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_and_unpadding_roundtrip() {
        let payload = b"SBM_TOP_SECRET_AIRGAP_PAYLOAD_12345";
        let padded = apply_padding(payload, None);
        assert!(padded.len() > payload.len() + 2);

        let recovered = remove_padding(&padded).expect("Failed to unpad");
        assert_eq!(&recovered, payload);
    }

    #[test]
    fn test_bucket_padding_alignment() {
        let payload = b"short_data"; // 10 bytes
        let padded = apply_padding(payload, Some(256));
        assert_eq!(padded.len(), 256);

        let recovered = remove_padding(&padded).expect("Failed to unpad bucket");
        assert_eq!(&recovered, payload);
    }

    #[test]
    fn test_header_masking_roundtrip_and_entropy() {
        let original_header = [0x53, 0x42, 0x4d, 0x31]; // "SBM1"
        let salt = [0x42u8; 32];
        let counter = 1001u64;

        let masked = mask_header(&original_header, &salt, counter);
        assert_ne!(masked.as_slice(), &original_header);

        let unmasked = unmask_header(&masked, &salt, counter);
        assert_eq!(unmasked.as_slice(), &original_header);
    }

    #[test]
    fn test_tampered_padding_rejection() {
        let mut corrupted = vec![1, 2, 3, 4, 5];
        // Set padding length to 100 (which is larger than buffer)
        corrupted.extend_from_slice(&(100u16).to_be_bytes());
        assert!(remove_padding(&corrupted).is_err());
    }

    #[test]
    fn test_chaff_packet_generation_and_detection() {
        let chaff = generate_chaff_packet(256);
        assert_eq!(chaff.len(), 256);

        let unpadded = remove_padding(&chaff).expect("Failed to unpad chaff");
        assert!(is_chaff_packet(&unpadded));

        let legit_data = b"REAL_AUTHENTICATED_TRAFFIC_DATA";
        assert!(!is_chaff_packet(legit_data));
    }

    #[test]
    fn test_timing_jitter_bounds() {
        for _ in 0..20 {
            let delay = compute_timing_jitter(5, 15);
            let millis = delay.as_millis() as u64;
            assert!(millis >= 5 && millis <= 15);
        }
    }
}
