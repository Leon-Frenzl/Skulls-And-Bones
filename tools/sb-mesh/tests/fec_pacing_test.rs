use sb_mesh::bbr_pacing::BbrGradientPacer;
use sb_mesh::fec::{FecDecoder, FecEncoder, Gf256};
use std::time::Duration;

#[test]
fn test_galois_field_properties() {
    // Additive identity
    assert_eq!(Gf256::add(0x42, 0), 0x42);
    // Additive inverse: a ^ a == 0
    assert_eq!(Gf256::add(0x42, 0x42), 0);

    // Multiplicative identity
    assert_eq!(Gf256::mul(0x42, 1), 0x42);
    assert_eq!(Gf256::mul(0x42, 0), 0);

    // Inversion: a * inv(a) == 1 for all non-zero elements
    for a in 1..=255 {
        let inv = Gf256::inv(a);
        assert_eq!(Gf256::mul(a, inv), 1, "Inverse check failed for {}", a);
    }
}

#[test]
fn test_fec_burst_loss_reconstruction() {
    let payload = b"S&B Sovereign Mesh RLNC: High-throughput, zero-retransmit packet recovery under heavy loss.";
    let k = 8;
    let m = 4; // 4 redundant parity packets (total 12 packets)

    let encoder = FecEncoder::new(payload, k);
    let all_packets = encoder.generate_fec_block(m);
    assert_eq!(all_packets.len(), 12);

    // Simulate losing 4 arbitrary packets (e.g. indices 0, 3, 5, 7)
    let lost_indices = [0, 3, 5, 7];
    let mut received_packets = Vec::new();
    for (idx, pkt) in all_packets.into_iter().enumerate() {
        if !lost_indices.contains(&idx) {
            received_packets.push(pkt);
        }
    }
    assert_eq!(received_packets.len(), 8); // exactly k packets survive

    let mut decoder = FecDecoder::new(k, payload.len());
    for pkt in received_packets {
        decoder.add_packet(pkt);
    }

    assert!(decoder.is_complete());
    let recovered = decoder
        .decode()
        .expect("Should successfully reconstruct data");
    assert_eq!(recovered, payload);
}

#[test]
fn test_bbr_delay_gradient_anti_bufferbloat() {
    let mut pacer = BbrGradientPacer::new();
    assert_eq!(pacer.pacing_delay(), BbrGradientPacer::DEFAULT_PACING);

    // Normal baseline RTT: 25ms
    for _ in 0..10 {
        pacer.update_rtt(Duration::from_millis(25));
    }
    assert_eq!(pacer.min_rtt, Duration::from_millis(25));
    assert!(!pacer.queue_bloat_detected);

    // Sudden delay spike (bufferbloat on router queue: 50ms, +100%)
    for _ in 0..5 {
        pacer.update_rtt(Duration::from_millis(50));
    }
    assert!(pacer.queue_bloat_detected);
    assert!(pacer.pacing_delay() > BbrGradientPacer::DEFAULT_PACING);

    // Queue drains back to normal (25ms)
    for _ in 0..40 {
        pacer.update_rtt(Duration::from_millis(25));
    }
    assert!(!pacer.queue_bloat_detected);
}
