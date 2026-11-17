use sb_mesh::bridge::{CrossMeshEnvelope, CrossMeshPayload};
use sb_mesh::fec::{
    FecDecoder, FecEncoder, StreamFecReceiver, STREAM_FEC_DATA_SYMBOLS, STREAM_FEC_MAX_BLOCK_BYTES,
    STREAM_FEC_PARITY_SYMBOLS,
};
use std::time::{Duration, Instant};

const TARGET_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_UDP_PACKET_BYTES: usize = 1200;
const MESH_PACKET_HEADER_BYTES: usize = 53;
const AEAD_TAG_BYTES: usize = 16;
const UDP_IPV4_HEADER_BYTES: usize = 28;
const UDP_IPV6_HEADER_BYTES: usize = 48;
const SAMPLED_BLOCKS: usize = 32;

#[derive(Clone, Copy)]
struct Profile {
    data_symbols: usize,
    parity_symbols: usize,
    symbol_payload_bytes: usize,
}

impl Profile {
    fn name(self) -> String {
        format!("{}+{}", self.data_symbols, self.parity_symbols)
    }

    fn block_bytes(self) -> usize {
        self.data_symbols * self.symbol_payload_bytes
    }

    fn block_count(self) -> usize {
        TARGET_FILE_BYTES.div_ceil(self.block_bytes())
    }

    fn overhead_percent(self) -> f64 {
        self.parity_symbols as f64 / self.data_symbols as f64 * 100.0
    }

    fn block_success_probability(self, loss_probability: f64) -> f64 {
        binomial_cdf(
            self.data_symbols + self.parity_symbols,
            self.parity_symbols,
            loss_probability,
        )
    }

    fn file_success_probability(self, loss_probability: f64) -> f64 {
        self.block_success_probability(loss_probability)
            .powf(self.block_count() as f64)
    }
}

#[test]
fn large_profile_recovers_systematic_parity_and_mixed_erasures() {
    let profile = PROFILES[2];
    let systematic_losses = (0..profile.parity_symbols).collect::<Vec<_>>();
    let parity_start = profile.data_symbols;
    let parity_losses = (parity_start..parity_start + profile.parity_symbols).collect::<Vec<_>>();
    let mixed_losses = (0..13)
        .chain(profile.data_symbols..profile.data_symbols + 12)
        .collect::<Vec<_>>();

    for lost in [&systematic_losses, &parity_losses, &mixed_losses] {
        let recovered = decode_with_losses(profile, 5, lost).unwrap();
        assert_eq!(recovered, packet_payload(profile, 5));
    }
}

const PROFILES: [Profile; 3] = [
    Profile {
        data_symbols: 8,
        parity_symbols: 4,
        symbol_payload_bytes: 256,
    },
    Profile {
        data_symbols: 64,
        parity_symbols: 8,
        symbol_payload_bytes: 256,
    },
    Profile {
        data_symbols: 64,
        parity_symbols: 25,
        symbol_payload_bytes: 256,
    },
];

fn binomial_cdf(n: usize, max_losses: usize, loss_probability: f64) -> f64 {
    let no_loss = 1.0 - loss_probability;
    let mut term = no_loss.powi(n as i32);
    let mut sum = term;
    for losses in 1..=max_losses {
        term *= (n - losses + 1) as f64 / losses as f64 * loss_probability / no_loss;
        sum += term;
    }
    sum
}

fn packet_payload(profile: Profile, block_id: usize) -> Vec<u8> {
    (0..profile.block_bytes())
        .map(|offset| (offset.wrapping_mul(31).wrapping_add(block_id * 17) % 251) as u8)
        .collect()
}

fn decode_with_losses(
    profile: Profile,
    block_id: usize,
    loss_indices: &[usize],
) -> Result<Vec<u8>, usize> {
    let payload = packet_payload(profile, block_id);
    let packets =
        FecEncoder::new(&payload, profile.data_symbols).generate_fec_block(profile.parity_symbols);
    let mut decoder = FecDecoder::new(profile.data_symbols, payload.len());
    let mut received = 0;

    for (index, packet) in packets.into_iter().enumerate() {
        if loss_indices.contains(&index) {
            continue;
        }
        received += 1;
        decoder.add_packet(packet);
    }

    decoder.decode().ok_or(received)
}

fn packet_wire_size(profile: Profile) -> usize {
    let envelope = CrossMeshEnvelope::new(
        "source-mesh",
        "sbm-0x01234567",
        "target-mesh",
        None,
        CrossMeshPayload::StreamDataFec {
            session_id: 1,
            block_id: 1,
            symbol_index: 0,
            data_symbols: profile.data_symbols as u16,
            parity_symbols: profile.parity_symbols as u16,
            original_len: profile.block_bytes() as u32,
            block_digest: sb_mesh::fec::stream_fec_block_digest(1, &vec![1; profile.block_bytes()]),
            coefficients: vec![1; profile.data_symbols],
            data: vec![1; profile.symbol_payload_bytes],
        },
    );
    envelope.encode().len() + MESH_PACKET_HEADER_BYTES + AEAD_TAG_BYTES
}

fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

struct SimulationMetrics {
    sent_symbols: usize,
    lost_symbols: usize,
    decoded_blocks: usize,
    failed_blocks: usize,
    encode_decode_time: Duration,
}

fn simulate_random_loss(profile: Profile, loss_probability: f64, seed: u64) -> SimulationMetrics {
    let started = Instant::now();
    let mut state = seed;
    let mut sent_symbols = 0;
    let mut lost_symbols = 0;
    let mut decoded_blocks = 0;
    let mut failed_blocks = 0;

    for block_id in 0..SAMPLED_BLOCKS {
        let payload = packet_payload(profile, block_id);
        let packets = FecEncoder::new(&payload, profile.data_symbols)
            .generate_fec_block(profile.parity_symbols);
        let mut decoder = FecDecoder::new(profile.data_symbols, payload.len());

        for packet in packets {
            sent_symbols += 1;
            let loss = (xorshift64(&mut state) >> 11) as f64 / ((1u64 << 53) as f64);
            if loss < loss_probability {
                lost_symbols += 1;
                continue;
            }
            if !decoder.is_complete() {
                decoder.add_packet(packet);
            }
        }

        let decoded = decoder.decode();
        if decoded.as_deref() == Some(payload.as_slice()) {
            decoded_blocks += 1;
        } else {
            failed_blocks += 1;
        }
    }

    SimulationMetrics {
        sent_symbols,
        lost_symbols,
        decoded_blocks,
        failed_blocks,
        encode_decode_time: started.elapsed(),
    }
}

#[test]
fn report_full_transfer_reliability_for_random_loss_scenarios() {
    println!(
        "FEC model: {TARGET_FILE_BYTES} byte file, independent symbol erasures, MDS erasure bound."
    );
    println!(
        "profile,overhead,blocks,loss,block_success,file_success,mesh_bytes,ipv4_bytes,ipv6_bytes"
    );

    for profile in PROFILES {
        let wire_size = packet_wire_size(profile);
        assert!(
            wire_size <= MAX_UDP_PACKET_BYTES,
            "{} symbol needs {wire_size} bytes, exceeds {MAX_UDP_PACKET_BYTES}-byte budget",
            profile.name()
        );
        let wire_bytes =
            profile.block_count() * (profile.data_symbols + profile.parity_symbols) * wire_size;

        for loss_probability in [0.01, 0.05, 0.10] {
            let block_success = profile.block_success_probability(loss_probability);
            let file_success = profile.file_success_probability(loss_probability);
            println!(
                "{},{:.1}%,{},{:.0}%,{:.9}%,{:.12e},{},{},{}",
                profile.name(),
                profile.overhead_percent(),
                profile.block_count(),
                loss_probability * 100.0,
                block_success * 100.0,
                file_success * 100.0,
                wire_bytes,
                wire_bytes
                    + profile.block_count()
                        * (profile.data_symbols + profile.parity_symbols)
                        * UDP_IPV4_HEADER_BYTES,
                wire_bytes
                    + profile.block_count()
                        * (profile.data_symbols + profile.parity_symbols)
                        * UDP_IPV6_HEADER_BYTES,
            );
        }
    }

    let current = PROFILES[0];
    let candidate = PROFILES[2];
    assert!(current.file_success_probability(0.10) < 0.001);
    assert!(candidate.file_success_probability(0.10) >= 0.999);
}

#[test]
fn deterministic_random_loss_reaches_the_decoder_and_reports_observed_metrics() {
    for profile in PROFILES {
        for loss_probability in [0.01, 0.05, 0.10] {
            let metrics = simulate_random_loss(profile, loss_probability, 0x5342_4D46_4543);
            let attempted = metrics.sent_symbols;
            let observed_loss = metrics.lost_symbols as f64 / attempted as f64;
            println!(
                "simulation,profile={},configured_loss={:.0}%,observed_loss={:.3}%,blocks={}/{},symbols_sent={},elapsed_ms={}",
                profile.name(),
                loss_probability * 100.0,
                observed_loss * 100.0,
                metrics.decoded_blocks,
                SAMPLED_BLOCKS,
                metrics.sent_symbols,
                metrics.encode_decode_time.as_millis(),
            );
            assert_eq!(
                metrics.decoded_blocks + metrics.failed_blocks,
                SAMPLED_BLOCKS
            );
            assert!(observed_loss < (loss_probability + 0.05));
            assert!(metrics.encode_decode_time < Duration::from_secs(30));
        }
    }
}

#[test]
fn burst_loss_is_recoverable_up_to_profile_parity_and_fails_beyond_it() {
    for profile in PROFILES {
        let n = profile.data_symbols + profile.parity_symbols;
        let burst_lengths = [1, profile.parity_symbols, profile.parity_symbols + 1];
        for burst_len in burst_lengths {
            for start in [0, n.saturating_sub(2)] {
                let mut recovered_blocks = 0;
                let first_block_losses = (start..start + burst_len)
                    .filter(|symbol| *symbol < n)
                    .map(|symbol| symbol - start)
                    .collect::<Vec<_>>();
                if decode_with_losses(profile, 20, &first_block_losses).is_ok() {
                    recovered_blocks += 1;
                }
                let second_block_losses = (start..start + burst_len)
                    .filter(|symbol| *symbol >= n)
                    .map(|symbol| symbol - n)
                    .collect::<Vec<_>>();
                if !second_block_losses.is_empty()
                    && decode_with_losses(profile, 21, &second_block_losses).is_ok()
                {
                    recovered_blocks += 1;
                }
                let touched_blocks = if start + burst_len > n { 2 } else { 1 };
                let expected_complete =
                    burst_len <= profile.parity_symbols || start + burst_len > n;
                println!(
                    "burst_metrics,profile={},length={},start={},recoverable_blocks={}/{},transfer_complete={}",
                    profile.name(),
                    burst_len,
                    start,
                    recovered_blocks,
                    touched_blocks,
                    recovered_blocks == touched_blocks,
                );
                assert_eq!(
                    recovered_blocks == touched_blocks,
                    expected_complete,
                    "unexpected burst result for profile {}, length {burst_len}, start {start}",
                    profile.name()
                );
            }
        }

        for burst_len in 1..=profile.parity_symbols {
            let lost = (0..burst_len).collect::<Vec<_>>();
            let recovered = decode_with_losses(profile, 1, &lost).unwrap();
            assert_eq!(recovered, packet_payload(profile, 1));

            let crosses_block_boundary = (n - 2)..(n - 2 + burst_len);
            let first_block_losses = crosses_block_boundary
                .clone()
                .filter(|index| *index < n)
                .map(|index| index)
                .collect::<Vec<_>>();
            let second_block_losses = crosses_block_boundary
                .filter(|index| *index >= n)
                .map(|index| index - n)
                .collect::<Vec<_>>();
            assert!(first_block_losses.len() <= profile.parity_symbols);
            assert!(second_block_losses.len() <= profile.parity_symbols);
            let first_recovered = decode_with_losses(profile, 10, &first_block_losses).unwrap();
            let second_recovered = decode_with_losses(profile, 11, &second_block_losses).unwrap();
            assert_eq!(first_recovered, packet_payload(profile, 10));
            assert_eq!(second_recovered, packet_payload(profile, 11));

            if burst_len == profile.parity_symbols {
                println!(
                    "burst,profile={},max_recoverable_burst={},boundary=verified",
                    profile.name(),
                    burst_len
                );
            }
        }

        let unrecoverable = (0..=profile.parity_symbols).collect::<Vec<_>>();
        assert!(
            decode_with_losses(profile, 2, &unrecoverable).is_err(),
            "{} unexpectedly decoded a block with {} erasures",
            profile.name(),
            unrecoverable.len()
        );
    }
}

#[test]
fn exhaustive_small_profile_recovers_every_pattern_up_to_parity_count() {
    let profile = PROFILES[0];
    let n = profile.data_symbols + profile.parity_symbols;
    for a in 0..n {
        for b in (a + 1)..n {
            for c in (b + 1)..n {
                for d in (c + 1)..n {
                    let lost = [a, b, c, d];
                    let recovered = decode_with_losses(profile, 3, &lost).unwrap();
                    assert_eq!(recovered, packet_payload(profile, 3));
                }
            }
        }
    }
}

#[test]
fn close_state_does_not_turn_incomplete_fec_data_into_success() {
    let profile = PROFILES[0];
    let payload = packet_payload(profile, 4);
    let packets =
        FecEncoder::new(&payload, profile.data_symbols).generate_fec_block(profile.parity_symbols);
    let mut decoder = FecDecoder::new(profile.data_symbols, payload.len());

    for packet in packets.into_iter().skip(profile.parity_symbols + 2) {
        decoder.add_packet(packet);
    }

    assert!(!decoder.is_complete());
    assert!(decoder.decode().is_none());
}

#[test]
fn receiver_bounds_incomplete_and_out_of_order_block_memory() {
    let profile = PROFILES[0];
    let mut receiver = StreamFecReceiver::default();
    for block_id in 1..=9 {
        let payload = packet_payload(profile, block_id);
        let first_symbol = FecEncoder::new(&payload, STREAM_FEC_DATA_SYMBOLS)
            .systematic_packet(0)
            .unwrap();
        let result = receiver.add_symbol(
            block_id as u64,
            profile.data_symbols,
            profile.parity_symbols,
            payload.len(),
            sb_mesh::fec::stream_fec_block_digest(block_id as u64, &payload),
            first_symbol,
        );
        if block_id <= 8 {
            assert!(result.unwrap().is_empty());
        } else {
            assert!(result.is_err());
        }
    }

    let mut receiver = StreamFecReceiver::default();
    for block_id in 2..=10 {
        let payload = packet_payload(profile, block_id);
        let encoder = FecEncoder::new(&payload, STREAM_FEC_DATA_SYMBOLS);
        let digest = sb_mesh::fec::stream_fec_block_digest(block_id as u64, &payload);
        let mut result = Ok(Vec::new());
        for symbol_id in 0..STREAM_FEC_DATA_SYMBOLS {
            result = receiver.add_symbol(
                block_id as u64,
                STREAM_FEC_DATA_SYMBOLS,
                STREAM_FEC_PARITY_SYMBOLS,
                payload.len(),
                digest,
                encoder.systematic_packet(symbol_id).unwrap(),
            );
        }
        if block_id <= 9 {
            assert!(result.unwrap().is_empty());
        } else {
            assert!(result.is_err());
        }
    }

    assert_eq!(STREAM_FEC_MAX_BLOCK_BYTES, 16 * 1024);
    assert_eq!(STREAM_FEC_PARITY_SYMBOLS, 4);
}
