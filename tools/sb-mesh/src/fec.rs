use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const STREAM_FEC_DATA_SYMBOLS: usize = 8;
pub const STREAM_FEC_PARITY_SYMBOLS: usize = 4;
pub const STREAM_FEC_SYMBOL_PAYLOAD_BYTES: usize = 256;
pub const STREAM_FEC_MAX_DATA_SYMBOLS: usize = 64;
pub const STREAM_FEC_MAX_PARITY_SYMBOLS: usize = 25;
pub const STREAM_FEC_MAX_BLOCK_BYTES: usize =
    STREAM_FEC_MAX_DATA_SYMBOLS * STREAM_FEC_SYMBOL_PAYLOAD_BYTES;
pub const STREAM_FEC_MAX_INCOMPLETE_BLOCKS: usize = 8;
pub const STREAM_FEC_MAX_REPAIR_ROUNDS: u8 = 3;
pub const STREAM_FEC_DEFAULT_TARGET_FAILURE_PPM: u32 = 1_000;
pub const STREAM_FEC_DEFAULT_ESTIMATED_LOSS_PPM: u32 = 100_000;

pub fn is_valid_stream_fec_repair_request(symbol_indices: &[u16], repair_round: u8) -> bool {
    if symbol_indices.is_empty()
        || symbol_indices.len() > STREAM_FEC_MAX_DATA_SYMBOLS + STREAM_FEC_MAX_PARITY_SYMBOLS
        || !(1..=STREAM_FEC_MAX_REPAIR_ROUNDS).contains(&repair_round)
    {
        return false;
    }
    let mut unique = HashSet::with_capacity(symbol_indices.len());
    symbol_indices.iter().all(|index| {
        (*index as usize) < STREAM_FEC_MAX_DATA_SYMBOLS + STREAM_FEC_MAX_PARITY_SYMBOLS
            && unique.insert(*index)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecProfile {
    pub data_symbols: usize,
    pub parity_symbols: usize,
}

impl FecProfile {
    pub const DEFAULT: Self = Self {
        data_symbols: STREAM_FEC_DATA_SYMBOLS,
        parity_symbols: STREAM_FEC_PARITY_SYMBOLS,
    };

    const TRANSFER_CANDIDATES: [Self; 9] = [
        Self {
            data_symbols: 8,
            parity_symbols: 4,
        },
        Self {
            data_symbols: 8,
            parity_symbols: 5,
        },
        Self {
            data_symbols: 16,
            parity_symbols: 8,
        },
        Self {
            data_symbols: 16,
            parity_symbols: 13,
        },
        Self {
            data_symbols: 32,
            parity_symbols: 11,
        },
        Self {
            data_symbols: 32,
            parity_symbols: 18,
        },
        Self {
            data_symbols: 64,
            parity_symbols: 8,
        },
        Self {
            data_symbols: 64,
            parity_symbols: 17,
        },
        Self {
            data_symbols: 64,
            parity_symbols: 25,
        },
    ];

    pub fn is_supported(data_symbols: usize, parity_symbols: usize) -> bool {
        Self::TRANSFER_CANDIDATES
            .into_iter()
            .chain([Self::DEFAULT])
            .any(|profile| {
                profile.data_symbols == data_symbols && profile.parity_symbols == parity_symbols
            })
    }

    pub fn select_for_transfer(
        expected_bytes: u64,
        estimated_loss_ppm: u32,
        target_failure_ppm: u32,
    ) -> Result<Self, String> {
        if expected_bytes == 0 {
            return Err("Expected transfer size must be nonzero".to_string());
        }
        if estimated_loss_ppm > 500_000 {
            return Err("Estimated symbol loss must not exceed 50%".to_string());
        }
        if target_failure_ppm == 0 || target_failure_ppm >= 1_000_000 {
            return Err("Target failure probability must be between 1 and 999999 ppm".to_string());
        }

        let loss_probability = estimated_loss_ppm as f64 / 1_000_000.0;
        let target_failure = target_failure_ppm as f64 / 1_000_000.0;
        let selected = Self::TRANSFER_CANDIDATES
            .into_iter()
            .filter(|profile| {
                let blocks = expected_bytes.div_ceil(profile.max_block_bytes() as u64);
                let block_success = profile.block_success_probability(loss_probability);
                let transfer_failure = 1.0 - block_success.powf(blocks as f64);
                transfer_failure <= target_failure
            })
            .min_by_key(|profile| profile.estimated_symbol_count(expected_bytes));

        selected.ok_or_else(|| {
            "No bounded FEC profile meets the requested transfer reliability".to_string()
        })
    }

    pub fn max_block_bytes(self) -> usize {
        self.data_symbols * STREAM_FEC_SYMBOL_PAYLOAD_BYTES
    }

    fn block_success_probability(self, loss_probability: f64) -> f64 {
        binomial_cdf(
            self.data_symbols + self.parity_symbols,
            self.parity_symbols,
            loss_probability,
        )
    }

    fn estimated_symbol_count(self, expected_bytes: u64) -> u128 {
        expected_bytes.div_ceil(self.max_block_bytes() as u64) as u128
            * (self.data_symbols + self.parity_symbols) as u128
    }
}

fn binomial_cdf(n: usize, max_losses: usize, loss_probability: f64) -> f64 {
    if loss_probability == 0.0 {
        return 1.0;
    }
    if loss_probability == 1.0 {
        return if max_losses >= n { 1.0 } else { 0.0 };
    }

    let no_loss = 1.0 - loss_probability;
    let mut term = no_loss.powi(n as i32);
    let mut sum = term;
    for losses in 1..=max_losses.min(n) {
        term *= (n - losses + 1) as f64 / losses as f64 * loss_probability / no_loss;
        sum += term;
    }
    sum
}

pub fn stream_fec_block_digest(block_id: u64, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SBM_STREAM_FEC_BLOCK_V1");
    hasher.update(block_id.to_be_bytes());
    hasher.update((data.len() as u64).to_be_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// Galois Field GF(2^8) with Rijndael irreducible polynomial 0x11B (x^8 + x^4 + x^3 + x + 1).
/// Provides byte-level linear arithmetic for Forward Error Correction (FEC) and Random Linear Network Coding (RLNC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf256;

impl Gf256 {
    pub const POLY: u16 = 0x11B;

    #[inline]
    pub fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline]
    pub fn sub(a: u8, b: u8) -> u8 {
        a ^ b
    }

    pub fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let carry = (a & 0x80) != 0;
            a <<= 1;
            if carry {
                a ^= (Self::POLY & 0xFF) as u8;
            }
            b >>= 1;
        }
        p
    }

    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        // Fermat's Little Theorem in GF(2^8): a^(254) = a^(-1)
        let mut res: u8 = 1;
        let mut base = a;
        let mut exp: u8 = 254;
        while exp > 0 {
            if (exp & 1) != 0 {
                res = Self::mul(res, base);
            }
            base = Self::mul(base, base);
            exp >>= 1;
        }
        res
    }
}

/// A coded packet containing linear combination coefficients and coded payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedPacket {
    pub coefficients: Vec<u8>,
    pub payload: Vec<u8>,
}

impl CodedPacket {
    pub fn new(coefficients: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            coefficients,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.coefficients.len() + self.payload.len());
        buf.push(self.coefficients.len() as u8);
        buf.extend_from_slice(&self.coefficients);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("Empty buffer".to_string());
        }
        let coeff_len = raw[0] as usize;
        if raw.len() < 1 + coeff_len {
            return Err("Truncated coded packet coefficients".to_string());
        }
        let coefficients = raw[1..1 + coeff_len].to_vec();
        let payload = raw[1 + coeff_len..].to_vec();
        Ok(Self {
            coefficients,
            payload,
        })
    }
}

/// Sender-Side Forward Error Correction (FEC) / RLNC Encoder
pub struct FecEncoder {
    pub k: usize,
    pub chunk_size: usize,
    pub original_chunks: Vec<Vec<u8>>,
}

impl FecEncoder {
    /// Creates an encoder that splits `data` into `k` equal-sized source chunks.
    pub fn new(data: &[u8], k: usize) -> Self {
        assert!(k > 0, "k must be at least 1");
        let chunk_size = data.len().div_ceil(k);
        let mut original_chunks = Vec::with_capacity(k);

        for i in 0..k {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(data.len());
            let mut chunk = Vec::with_capacity(chunk_size);
            if start < data.len() {
                chunk.extend_from_slice(&data[start..end]);
            }
            // Zero-pad last chunk to chunk_size if necessary
            chunk.resize(chunk_size, 0u8);
            original_chunks.push(chunk);
        }

        Self {
            k,
            chunk_size,
            original_chunks,
        }
    }

    /// Produces a systematic source packet (coefficient vector is unit basis vector e_i)
    pub fn systematic_packet(&self, index: usize) -> Option<CodedPacket> {
        if index >= self.k {
            return None;
        }
        let mut coeffs = vec![0u8; self.k];
        coeffs[index] = 1;
        Some(CodedPacket::new(
            coeffs,
            self.original_chunks[index].clone(),
        ))
    }

    /// Generates a parity packet using pseudo-random or provided linear coefficients
    pub fn generate_coded_packet(&self, seed: u64) -> CodedPacket {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut coeffs = Vec::with_capacity(self.k);
        for _ in 0..self.k {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut c = (state >> 33) as u8;
            if c == 0 {
                c = 1;
            }
            coeffs.push(c);
        }

        let mut payload = vec![0u8; self.chunk_size];
        for (i, c) in coeffs.iter().enumerate() {
            let chunk = &self.original_chunks[i];
            for (byte_idx, &b) in chunk.iter().enumerate() {
                payload[byte_idx] = Gf256::add(payload[byte_idx], Gf256::mul(*c, b));
            }
        }

        CodedPacket::new(coeffs, payload)
    }

    /// Generates the complete transmission set: `k` systematic packets + `m` redundant FEC parity packets
    pub fn generate_fec_block(&self, m: usize) -> Vec<CodedPacket> {
        let mut packets = Vec::with_capacity(self.k + m);
        for i in 0..self.k {
            if let Some(pkt) = self.systematic_packet(i) {
                packets.push(pkt);
            }
        }
        for j in 0..m {
            let packet = if self.k <= 128 && m <= self.k {
                self.generate_cauchy_packet(j)
            } else {
                self.generate_coded_packet((j as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15))
            };
            packets.push(packet);
        }
        packets
    }

    fn generate_cauchy_packet(&self, parity_index: usize) -> CodedPacket {
        let mut coeffs = Vec::with_capacity(self.k);
        for source_index in 0..self.k {
            let x = parity_index as u8;
            let y = (self.k + source_index) as u8;
            coeffs.push(Gf256::inv(x ^ y));
        }

        let mut payload = vec![0u8; self.chunk_size];
        for (index, coefficient) in coeffs.iter().enumerate() {
            for (offset, byte) in self.original_chunks[index].iter().enumerate() {
                payload[offset] = Gf256::add(payload[offset], Gf256::mul(*coefficient, *byte));
            }
        }
        CodedPacket::new(coeffs, payload)
    }
}

/// Receiver-Side FEC / RLNC Decoder using Gaussian Elimination over GF(2^8)
pub struct FecDecoder {
    pub k: usize,
    pub chunk_size: usize,
    pub original_len: usize,
    matrix: Vec<Vec<u8>>,
    payloads: Vec<Vec<u8>>,
}

impl FecDecoder {
    pub fn new(k: usize, original_len: usize) -> Self {
        let chunk_size = original_len.div_ceil(k);
        Self {
            k,
            chunk_size,
            original_len,
            matrix: Vec::new(),
            payloads: Vec::new(),
        }
    }

    /// Returns the current rank (number of linearly independent packets received)
    pub fn rank(&self) -> usize {
        self.matrix.len()
    }

    /// Returns true if enough linearly independent packets have been received to reconstruct data
    pub fn is_complete(&self) -> bool {
        self.rank() == self.k
    }

    /// Adds a received coded packet. Performs incremental Gaussian Elimination.
    /// Returns true if the packet was linearly independent (innovative), false if redundant.
    pub fn add_packet(&mut self, packet: CodedPacket) -> bool {
        if self.is_complete()
            || packet.coefficients.len() != self.k
            || packet.payload.len() != self.chunk_size
        {
            return false;
        }

        let mut row = packet.coefficients;
        let mut payload = packet.payload;

        // Reduce against existing echelon rows
        for i in 0..self.matrix.len() {
            let lead_col = match self.matrix[i].iter().position(|&x| x != 0) {
                Some(pos) => pos,
                None => continue,
            };

            let factor = row[lead_col];
            if factor != 0 {
                // row = row ^ (factor * existing_row)
                #[allow(clippy::needless_range_loop)]
                for c in 0..self.k {
                    let term = Gf256::mul(factor, self.matrix[i][c]);
                    row[c] = Gf256::add(row[c], term);
                }
                #[allow(clippy::needless_range_loop)]
                for b in 0..self.chunk_size {
                    let term = Gf256::mul(factor, self.payloads[i][b]);
                    payload[b] = Gf256::add(payload[b], term);
                }
            }
        }

        // Check if row is non-zero (innovative)
        if let Some(pivot_col) = row.iter().position(|&x| x != 0) {
            let inv_pivot = Gf256::inv(row[pivot_col]);
            // Normalize pivot to 1
            #[allow(clippy::needless_range_loop)]
            for c in 0..self.k {
                row[c] = Gf256::mul(row[c], inv_pivot);
            }
            #[allow(clippy::needless_range_loop)]
            for b in 0..self.chunk_size {
                payload[b] = Gf256::mul(payload[b], inv_pivot);
            }

            // Back-eliminate in existing rows
            for i in 0..self.matrix.len() {
                let factor = self.matrix[i][pivot_col];
                if factor != 0 {
                    #[allow(clippy::needless_range_loop)]
                    for c in 0..self.k {
                        let term = Gf256::mul(factor, row[c]);
                        self.matrix[i][c] = Gf256::add(self.matrix[i][c], term);
                    }
                    #[allow(clippy::needless_range_loop)]
                    for b in 0..self.chunk_size {
                        let term = Gf256::mul(factor, payload[b]);
                        self.payloads[i][b] = Gf256::add(self.payloads[i][b], term);
                    }
                }
            }

            self.matrix.push(row);
            self.payloads.push(payload);
            true
        } else {
            false
        }
    }

    /// Reconstructs the original data if rank == k
    pub fn decode(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        // With reduced row echelon form where diagonal is 1, rows correspond to unit chunks
        let mut ordered_chunks = vec![vec![0u8; self.chunk_size]; self.k];

        for i in 0..self.k {
            if let Some(col) = self.matrix[i].iter().position(|&x| x != 0) {
                if col < self.k {
                    ordered_chunks[col] = self.payloads[i].clone();
                }
            }
        }

        let mut result = Vec::with_capacity(self.original_len);
        for chunk in ordered_chunks {
            result.extend_from_slice(&chunk);
        }
        result.truncate(self.original_len);
        Some(result)
    }
}

pub struct StreamFecReceiver {
    blocks: HashMap<u64, FecDecoder>,
    block_metadata: HashMap<u64, StreamFecBlockMetadata>,
    completed: BTreeMap<u64, Vec<u8>>,
    next_block_id: u64,
    final_block_id: Option<u64>,
    final_stream_digest: Option<[u8; 32]>,
    stream_hasher: Sha256,
    finished: bool,
}

struct StreamFecBlockMetadata {
    data_symbols: usize,
    parity_symbols: usize,
    digest: [u8; 32],
    received_symbols: usize,
    received_indices: HashSet<usize>,
    repair_rounds: u8,
}

impl Default for StreamFecReceiver {
    fn default() -> Self {
        Self {
            blocks: HashMap::new(),
            block_metadata: HashMap::new(),
            completed: BTreeMap::new(),
            next_block_id: 1,
            final_block_id: None,
            final_stream_digest: None,
            stream_hasher: Sha256::new(),
            finished: false,
        }
    }
}

impl StreamFecReceiver {
    pub fn add_symbol(
        &mut self,
        block_id: u64,
        data_symbols: usize,
        parity_symbols: usize,
        original_len: usize,
        block_digest: [u8; 32],
        packet: CodedPacket,
    ) -> Result<Vec<Vec<u8>>, String> {
        self.add_indexed_symbol(
            block_id,
            None,
            data_symbols,
            parity_symbols,
            original_len,
            block_digest,
            packet,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_indexed_symbol(
        &mut self,
        block_id: u64,
        symbol_index: Option<usize>,
        data_symbols: usize,
        parity_symbols: usize,
        original_len: usize,
        block_digest: [u8; 32],
        packet: CodedPacket,
    ) -> Result<Vec<Vec<u8>>, String> {
        let supported_profile = FecProfile::is_supported(data_symbols, parity_symbols);
        if block_id == 0
            || !supported_profile
            || original_len == 0
            || original_len > data_symbols * STREAM_FEC_SYMBOL_PAYLOAD_BYTES
            || packet.coefficients.len() != data_symbols
            || packet.payload.len() != original_len.div_ceil(data_symbols)
            || symbol_index
                .is_some_and(|index| index >= data_symbols.saturating_add(parity_symbols))
        {
            return Err("Invalid stream FEC block parameters".to_string());
        }
        if block_id < self.next_block_id {
            return Ok(Vec::new());
        }
        if self.completed.contains_key(&block_id) {
            return Ok(Vec::new());
        }
        if self
            .final_block_id
            .is_some_and(|final_id| block_id > final_id)
        {
            return Err("Stream FEC symbol arrived beyond the declared final block".to_string());
        }

        if !self.blocks.contains_key(&block_id) {
            if self.blocks.len() >= STREAM_FEC_MAX_INCOMPLETE_BLOCKS {
                return Err("Too many incomplete stream FEC blocks".to_string());
            }
            self.blocks
                .insert(block_id, FecDecoder::new(data_symbols, original_len));
            self.block_metadata.insert(
                block_id,
                StreamFecBlockMetadata {
                    data_symbols,
                    parity_symbols,
                    digest: block_digest,
                    received_symbols: 0,
                    received_indices: HashSet::new(),
                    repair_rounds: 0,
                },
            );
        }

        let metadata = self
            .block_metadata
            .get_mut(&block_id)
            .ok_or_else(|| "Stream FEC block metadata disappeared".to_string())?;
        if metadata.data_symbols != data_symbols
            || metadata.parity_symbols != parity_symbols
            || metadata.digest != block_digest
        {
            return Err("Stream FEC block metadata changed between symbols".to_string());
        }
        if let Some(index) = symbol_index {
            if !metadata.received_indices.insert(index) {
                return Ok(Vec::new());
            }
        }
        if metadata.received_symbols >= data_symbols + parity_symbols {
            return Err("Stream FEC block exceeded its declared symbol count".to_string());
        }
        metadata.received_symbols += 1;

        let decoder = self
            .blocks
            .get_mut(&block_id)
            .ok_or_else(|| "Stream FEC block state disappeared".to_string())?;
        if decoder.original_len != original_len {
            return Err("Stream FEC block changed its declared original length".to_string());
        }
        if !decoder.add_packet(packet) {
            return Ok(Vec::new());
        }
        if !decoder.is_complete() {
            return Ok(Vec::new());
        }

        let decoded = decoder
            .decode()
            .ok_or_else(|| "Completed stream FEC block could not be decoded".to_string())?;
        self.blocks.remove(&block_id);
        let metadata = self
            .block_metadata
            .remove(&block_id)
            .ok_or_else(|| "Stream FEC block metadata disappeared".to_string())?;
        if stream_fec_block_digest(block_id, &decoded) != metadata.digest {
            return Err("Decoded stream FEC block failed its SHA-256 integrity check".to_string());
        }
        if block_id < self.next_block_id || self.completed.contains_key(&block_id) {
            return Ok(Vec::new());
        }
        if self.completed.len() >= STREAM_FEC_MAX_INCOMPLETE_BLOCKS {
            return Err("Too many out-of-order stream FEC blocks".to_string());
        }
        self.completed.insert(block_id, decoded);
        let mut ready = Vec::new();
        while let Some(block) = self.completed.remove(&self.next_block_id) {
            self.stream_hasher.update(&block);
            ready.push(block);
            self.next_block_id = self
                .next_block_id
                .checked_add(1)
                .ok_or_else(|| "Stream FEC block sequence exhausted".to_string())?;
        }
        self.verify_final_digest()?;
        Ok(ready)
    }

    pub fn register_block(
        &mut self,
        block_id: u64,
        data_symbols: usize,
        parity_symbols: usize,
        original_len: usize,
        block_digest: [u8; 32],
    ) -> Result<bool, String> {
        if block_id == 0
            || !FecProfile::is_supported(data_symbols, parity_symbols)
            || original_len == 0
            || original_len > data_symbols * STREAM_FEC_SYMBOL_PAYLOAD_BYTES
        {
            return Err("Invalid stream FEC block parameters".to_string());
        }
        if block_id < self.next_block_id || self.completed.contains_key(&block_id) {
            return Ok(true);
        }
        if let Some(metadata) = self.block_metadata.get(&block_id) {
            if metadata.data_symbols != data_symbols
                || metadata.parity_symbols != parity_symbols
                || metadata.digest != block_digest
            {
                return Err("Stream FEC block metadata changed between symbols".to_string());
            }
            return Ok(false);
        }
        if self.blocks.len() >= STREAM_FEC_MAX_INCOMPLETE_BLOCKS {
            return Err("Too many incomplete stream FEC blocks".to_string());
        }
        self.blocks
            .insert(block_id, FecDecoder::new(data_symbols, original_len));
        self.block_metadata.insert(
            block_id,
            StreamFecBlockMetadata {
                data_symbols,
                parity_symbols,
                digest: block_digest,
                received_symbols: 0,
                received_indices: HashSet::new(),
                repair_rounds: 0,
            },
        );
        Ok(false)
    }

    pub fn missing_symbol_indices(
        &mut self,
        block_id: u64,
        data_symbols: usize,
        parity_symbols: usize,
        original_len: usize,
        block_digest: [u8; 32],
    ) -> Result<Option<(Vec<u16>, u8)>, String> {
        if self.register_block(
            block_id,
            data_symbols,
            parity_symbols,
            original_len,
            block_digest,
        )? {
            return Ok(None);
        }
        let metadata = self
            .block_metadata
            .get_mut(&block_id)
            .ok_or_else(|| "Stream FEC block metadata disappeared".to_string())?;
        if metadata.repair_rounds >= STREAM_FEC_MAX_REPAIR_ROUNDS {
            return Err("Stream FEC block exceeded its repair-round limit".to_string());
        }
        let missing = (0..data_symbols + parity_symbols)
            .filter(|index| !metadata.received_indices.contains(index))
            .map(|index| index as u16)
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Err(
                "Stream FEC block is incomplete but has no missing symbol indexes".to_string(),
            );
        }
        metadata.repair_rounds += 1;
        Ok(Some((missing, metadata.repair_rounds)))
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.block_metadata.clear();
        self.completed.clear();
        self.next_block_id = 1;
        self.final_block_id = None;
        self.final_stream_digest = None;
        self.stream_hasher = Sha256::new();
        self.finished = false;
    }

    pub fn mark_finished(
        &mut self,
        final_block_id: u64,
        stream_digest: [u8; 32],
    ) -> Result<bool, String> {
        if self
            .final_block_id
            .is_some_and(|existing| existing != final_block_id)
            || self
                .final_stream_digest
                .is_some_and(|existing| existing != stream_digest)
            || final_block_id.saturating_add(1) < self.next_block_id
        {
            return Err("Conflicting or stale final stream FEC block ID".to_string());
        }
        self.final_block_id = Some(final_block_id);
        self.final_stream_digest = Some(stream_digest);
        self.verify_final_digest()?;
        Ok(self.finished)
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    fn verify_final_digest(&mut self) -> Result<(), String> {
        let Some(final_block_id) = self.final_block_id else {
            return Ok(());
        };
        let Some(expected_digest) = self.final_stream_digest else {
            return Ok(());
        };
        if self.next_block_id <= final_block_id {
            return Ok(());
        }
        let actual_digest: [u8; 32] = self.stream_hasher.clone().finalize().into();
        if actual_digest != expected_digest {
            return Err("Completed stream failed its SHA-256 integrity check".to_string());
        }
        self.finished = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_basic_arithmetic() {
        assert_eq!(Gf256::add(0x57, 0x83), 0xD4);
        assert_eq!(Gf256::mul(0x57, 0x83), 0xC1);
        let inv = Gf256::inv(0x57);
        assert_eq!(Gf256::mul(0x57, inv), 1);
    }

    #[test]
    fn test_fec_recovery_from_dropped_packets() {
        let original_data =
            b"Sovereign peer-to-peer payload resilient against random loss.".to_vec();
        let k = 4;
        let m = 2; // 2 redundant parity packets (total 6 packets)

        let encoder = FecEncoder::new(&original_data, k);
        let packets = encoder.generate_fec_block(m);
        assert_eq!(packets.len(), 6);

        // Simulate dropping 2 packets (e.g. packets 0 and 2 dropped)
        let surviving_packets = vec![
            packets[1].clone(),
            packets[3].clone(),
            packets[4].clone(),
            packets[5].clone(),
        ];

        let mut decoder = FecDecoder::new(k, original_data.len());
        for pkt in surviving_packets {
            decoder.add_packet(pkt);
        }

        assert!(decoder.is_complete());
        let recovered = decoder.decode().expect("Decoding should succeed");
        assert_eq!(recovered, original_data);
    }

    #[test]
    fn stream_fec_recovers_any_four_erasures_from_systematic_block() {
        let original = (0..STREAM_FEC_DATA_SYMBOLS * STREAM_FEC_SYMBOL_PAYLOAD_BYTES)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let packets = FecEncoder::new(&original, STREAM_FEC_DATA_SYMBOLS)
            .generate_fec_block(STREAM_FEC_PARITY_SYMBOLS);
        let total = packets.len();

        for a in 0..total {
            for b in (a + 1)..total {
                for c in (b + 1)..total {
                    for d in (c + 1)..total {
                        let mut decoder = FecDecoder::new(STREAM_FEC_DATA_SYMBOLS, original.len());
                        for (index, packet) in packets.iter().enumerate() {
                            if [a, b, c, d].contains(&index) {
                                continue;
                            }
                            decoder.add_packet(packet.clone());
                        }
                        assert!(decoder.is_complete(), "erasures: {a}, {b}, {c}, {d}");
                        assert_eq!(
                            decoder.decode().unwrap(),
                            original,
                            "erasures: {a}, {b}, {c}, {d}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn all_transfer_profiles_recover_at_their_parity_boundary() {
        for profile in FecProfile::TRANSFER_CANDIDATES {
            let original = (0..profile.max_block_bytes())
                .map(|index| (index.wrapping_mul(37) % 251) as u8)
                .collect::<Vec<_>>();
            let packets = FecEncoder::new(&original, profile.data_symbols)
                .generate_fec_block(profile.parity_symbols);
            let mut decoder = FecDecoder::new(profile.data_symbols, original.len());
            for (index, packet) in packets.into_iter().enumerate() {
                if index < profile.parity_symbols {
                    continue;
                }
                decoder.add_packet(packet);
            }
            assert!(decoder.is_complete(), "profile {profile:?}");
            assert_eq!(decoder.decode().unwrap(), original, "profile {profile:?}");

            let packets = FecEncoder::new(&original, profile.data_symbols)
                .generate_fec_block(profile.parity_symbols);
            let mut decoder = FecDecoder::new(profile.data_symbols, original.len());
            for (index, packet) in packets.into_iter().enumerate() {
                if index < profile.parity_symbols + 1 {
                    continue;
                }
                decoder.add_packet(packet);
            }
            assert!(!decoder.is_complete(), "profile {profile:?}");
        }
    }

    #[test]
    fn stream_fec_receiver_reorders_completed_blocks() {
        let first = b"block one";
        let second = b"block two";
        let first_packets = FecEncoder::new(first, STREAM_FEC_DATA_SYMBOLS)
            .generate_fec_block(STREAM_FEC_PARITY_SYMBOLS);
        let second_packets = FecEncoder::new(second, STREAM_FEC_DATA_SYMBOLS)
            .generate_fec_block(STREAM_FEC_PARITY_SYMBOLS);
        let first_digest = stream_fec_block_digest(1, first);
        let second_digest = stream_fec_block_digest(2, second);
        let mut receiver = StreamFecReceiver::default();

        for packet in second_packets {
            assert!(receiver
                .add_symbol(
                    2,
                    STREAM_FEC_DATA_SYMBOLS,
                    STREAM_FEC_PARITY_SYMBOLS,
                    second.len(),
                    second_digest,
                    packet,
                )
                .unwrap()
                .is_empty());
        }
        let mut stream_hasher = Sha256::new();
        stream_hasher.update(first);
        stream_hasher.update(second);
        let stream_digest = stream_hasher.finalize().into();
        assert!(!receiver.mark_finished(2, stream_digest).unwrap());
        let mut ready = Vec::new();
        for packet in first_packets {
            ready.extend(
                receiver
                    .add_symbol(
                        1,
                        STREAM_FEC_DATA_SYMBOLS,
                        STREAM_FEC_PARITY_SYMBOLS,
                        first.len(),
                        first_digest,
                        packet,
                    )
                    .unwrap(),
            );
        }
        assert_eq!(ready, vec![first.to_vec(), second.to_vec()]);
        assert!(receiver.is_finished());
    }

    #[test]
    fn stream_fec_receiver_requests_only_missing_symbols_and_stops_after_recovery() {
        let profile = FecProfile {
            data_symbols: 8,
            parity_symbols: 5,
        };
        let payload = b"selective symbol repair";
        let digest = stream_fec_block_digest(1, payload);
        let symbols = FecEncoder::new(payload, profile.data_symbols)
            .generate_fec_block(profile.parity_symbols);
        let mut receiver = StreamFecReceiver::default();
        for (index, symbol) in symbols.iter().enumerate().skip(6) {
            receiver
                .add_indexed_symbol(
                    1,
                    Some(index),
                    profile.data_symbols,
                    profile.parity_symbols,
                    payload.len(),
                    digest,
                    symbol.clone(),
                )
                .unwrap();
        }

        assert_eq!(
            receiver
                .missing_symbol_indices(
                    1,
                    profile.data_symbols,
                    profile.parity_symbols,
                    payload.len(),
                    digest,
                )
                .unwrap(),
            Some(((0..6).collect(), 1))
        );

        for index in 0..6 {
            receiver
                .add_indexed_symbol(
                    1,
                    Some(index),
                    profile.data_symbols,
                    profile.parity_symbols,
                    payload.len(),
                    digest,
                    symbols[index].clone(),
                )
                .unwrap();
        }
        assert_eq!(
            receiver
                .missing_symbol_indices(
                    1,
                    profile.data_symbols,
                    profile.parity_symbols,
                    payload.len(),
                    digest,
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn stream_fec_receiver_bounds_repair_rounds() {
        let mut receiver = StreamFecReceiver::default();
        let digest = stream_fec_block_digest(1, b"payload");
        for expected_round in 1..=STREAM_FEC_MAX_REPAIR_ROUNDS {
            assert_eq!(
                receiver
                    .missing_symbol_indices(1, 8, 4, 7, digest,)
                    .unwrap()
                    .unwrap()
                    .1,
                expected_round
            );
        }
        assert!(receiver.missing_symbol_indices(1, 8, 4, 7, digest).is_err());
    }

    #[test]
    fn stream_fec_receiver_rejects_a_bad_final_stream_digest() {
        let mut receiver = StreamFecReceiver::default();
        assert!(receiver.mark_finished(0, [0; 32]).is_err());
        assert!(!receiver.is_finished());
    }

    #[test]
    fn stream_fec_receiver_rejects_oversized_symbols_without_panicking() {
        let mut receiver = StreamFecReceiver::default();
        let malformed = CodedPacket::new(vec![1; STREAM_FEC_DATA_SYMBOLS], vec![0; 4096]);
        assert!(receiver
            .add_symbol(
                1,
                STREAM_FEC_DATA_SYMBOLS,
                STREAM_FEC_PARITY_SYMBOLS,
                32,
                [0; 32],
                malformed,
            )
            .is_err());
    }

    #[test]
    fn stream_fec_repair_requests_are_bounded_and_unique() {
        assert!(is_valid_stream_fec_repair_request(&[0, 4, 12], 1));
        assert!(!is_valid_stream_fec_repair_request(&[], 1));
        assert!(!is_valid_stream_fec_repair_request(&[1, 1], 1));
        assert!(!is_valid_stream_fec_repair_request(&[89], 1));
        assert!(!is_valid_stream_fec_repair_request(&[1], 0));
        assert!(!is_valid_stream_fec_repair_request(
            &[1],
            STREAM_FEC_MAX_REPAIR_ROUNDS + 1
        ));
    }

    #[test]
    fn transfer_profile_selection_meets_the_requested_failure_budget() {
        assert_eq!(
            FecProfile::select_for_transfer(5, 100_000, 1_000).unwrap(),
            FecProfile {
                data_symbols: 8,
                parity_symbols: 5,
            }
        );
        let profile = FecProfile::select_for_transfer(
            16 * 1024 * 1024,
            100_000,
            STREAM_FEC_DEFAULT_TARGET_FAILURE_PPM,
        )
        .unwrap();
        assert_eq!(
            profile,
            FecProfile {
                data_symbols: 64,
                parity_symbols: 25,
            }
        );
        assert!(FecProfile::select_for_transfer(100_000_000, 100_000, 1_000).is_err());
    }

    #[test]
    fn stream_fec_receiver_rejects_a_bad_decoded_block_digest() {
        let payload = b"integrity checked";
        let packets = FecEncoder::new(payload, STREAM_FEC_DATA_SYMBOLS)
            .generate_fec_block(STREAM_FEC_PARITY_SYMBOLS);
        let mut receiver = StreamFecReceiver::default();
        let mut result = Ok(Vec::new());
        for packet in packets {
            result = receiver.add_symbol(
                1,
                STREAM_FEC_DATA_SYMBOLS,
                STREAM_FEC_PARITY_SYMBOLS,
                payload.len(),
                [0; 32],
                packet,
            );
            if result.is_err() {
                break;
            }
        }
        assert!(result.unwrap_err().contains("SHA-256 integrity check"));
    }
}
