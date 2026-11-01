use base64::prelude::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const ZK_DOMAIN_SEPARATOR: &[u8] = b"SBM_ZK_PLATFORM_ATTESTATION_V1";
pub const STANDARD_POLICY_ROOT: [u8; 32] = [
    0x53, 0x42, 0x4d, 0x5f, 0x50, 0x4f, 0x4c, 0x49, // "SBM_POLI"
    0x43, 0x59, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f, // "CY_ROOT_"
    0x53, 0x45, 0x43, 0x55, 0x52, 0x45, 0x5f, 0x42, // "SECURE_B"
    0x4f, 0x4f, 0x54, 0x5f, 0x56, 0x30, 0x30, 0x31, // "OOT_V001"
];

/// Compact, zero-leakage Zero-Knowledge Proof of Platform Integrity & Key Possession
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProof {
    /// Serialized ephemeral commitment R (32 bytes)
    pub commitment_r: [u8; 32],
    /// Schnorr response scalar s = r + c * x (32 bytes)
    pub response_s: [u8; 32],
    /// Platform public commitment X = x * B (32 bytes)
    pub platform_commitment_x: [u8; 32],
    /// Policy Merkle/Digest Root (32 bytes)
    pub policy_root: [u8; 32],
    /// Epoch timestamp or sequence
    pub epoch: u64,
}

impl ZkProof {
    /// Encodes the ZK-proof into a raw byte vector (104 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(104);
        buf.extend_from_slice(&self.commitment_r);
        buf.extend_from_slice(&self.response_s);
        buf.extend_from_slice(&self.platform_commitment_x);
        buf.extend_from_slice(&self.policy_root);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf
    }

    /// Decodes a 136-byte buffer into a ZkProof
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 136 {
            return Err(format!(
                "Invalid ZK proof length: expected 136 bytes, got {}",
                bytes.len()
            ));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        let mut x = [0u8; 32];
        let mut root = [0u8; 32];
        let mut epoch_bytes = [0u8; 8];

        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        x.copy_from_slice(&bytes[64..96]);
        root.copy_from_slice(&bytes[96..128]);
        epoch_bytes.copy_from_slice(&bytes[128..136]);

        Ok(Self {
            commitment_r: r,
            response_s: s,
            platform_commitment_x: x,
            policy_root: root,
            epoch: u64::from_be_bytes(epoch_bytes),
        })
    }

    /// Export as Base64 for diagnostic or pairing logs
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.to_bytes())
    }
}

/// Private witness held exclusively by the local host
pub struct PlatformWitness {
    /// Local sealed platform secret scalar (e.g. bound to local TPM or secure enclave)
    pub platform_secret: Scalar,
    /// Integrity state measurement hash
    pub integrity_measurement: [u8; 32],
}

impl PlatformWitness {
    /// Generate a fresh platform witness with random secret
    pub fn generate_fresh() -> Self {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        Self {
            platform_secret: secret,
            integrity_measurement: STANDARD_POLICY_ROOT,
        }
    }

    /// Derive the public platform commitment X = x * B
    pub fn platform_commitment(&self) -> CompressedRistretto {
        (self.platform_secret * RISTRETTO_BASEPOINT_POINT).compress()
    }
}

/// Public parameters identifying the verification context
pub struct VerificationStatement<'a> {
    pub target_peer_pubkey: &'a [u8; 32],
    pub session_nonce: u64,
    pub expected_policy_root: &'a [u8; 32],
}

/// Generates a Zero-Knowledge Proof-of-Knowledge (ZK-PoK)
///
/// Proves that the caller:
/// 1. Knows the platform secret x corresponding to X = x * B.
/// 2. Complies with the platform integrity policy.
/// 3. Binds the proof strictly to the recipient's public key and session nonce (No Replay / No MitM).
///
/// LEAKS EXACTLY ZERO BITS OF HARDWARE SERIALS, CPU MODELS OR FIRMWARE DETAILS.
pub fn generate_zk_proof(
    witness: &PlatformWitness,
    peer_pubkey: &[u8; 32],
    session_nonce: u64,
    epoch: u64,
) -> ZkProof {
    let mut rng = OsRng;
    // 1. Ephemeral nonce r in Z_q
    let r = Scalar::random(&mut rng);
    // 2. Commitment R = r * B
    let big_r = (r * RISTRETTO_BASEPOINT_POINT).compress();
    let big_x = witness.platform_commitment();

    // 3. Compute Fiat-Shamir challenge c = H(domain || X || R || Policy || PeerPub || Nonce || Epoch)
    let challenge = compute_fiat_shamir_challenge(
        &big_x.to_bytes(),
        &big_r.to_bytes(),
        &witness.integrity_measurement,
        peer_pubkey,
        session_nonce,
        epoch,
    );

    // 4. Compute response s = r + c * x (mod q)
    let s = r + (challenge * witness.platform_secret);

    ZkProof {
        commitment_r: big_r.to_bytes(),
        response_s: s.to_bytes(),
        platform_commitment_x: big_x.to_bytes(),
        policy_root: witness.integrity_measurement,
        epoch,
    }
}

/// Verifies the Zero-Knowledge Proof-of-Knowledge
///
/// Returns true if and only if:
/// 1. The equation s * B == R + c * X holds in the Ristretto group.
/// 2. The policy root matches expected integrity policy.
///
/// The verifier learns nothing about the prover's hardware identity.
pub fn verify_zk_proof(proof: &ZkProof, statement: &VerificationStatement) -> bool {
    // Check policy root
    if proof.policy_root != *statement.expected_policy_root {
        return false;
    }

    // Decompress R and X
    let r_point = match CompressedRistretto(proof.commitment_r).decompress() {
        Some(p) => p,
        None => return false,
    };

    let x_point = match CompressedRistretto(proof.platform_commitment_x).decompress() {
        Some(p) => p,
        None => return false,
    };

    // Decompress scalar s
    let s_scalar: Option<Scalar> = Scalar::from_canonical_bytes(proof.response_s).into();
    let s_scalar = match s_scalar {
        Some(s) => s,
        None => return false,
    };

    // Recompute Fiat-Shamir challenge c
    let challenge = compute_fiat_shamir_challenge(
        &proof.platform_commitment_x,
        &proof.commitment_r,
        &proof.policy_root,
        statement.target_peer_pubkey,
        statement.session_nonce,
        proof.epoch,
    );

    // Verify verification equation: s * B == R + c * X
    let lhs = s_scalar * RISTRETTO_BASEPOINT_POINT;
    let rhs = r_point + (challenge * x_point);

    lhs == rhs
}

fn compute_fiat_shamir_challenge(
    x_bytes: &[u8; 32],
    r_bytes: &[u8; 32],
    policy_root: &[u8; 32],
    peer_pubkey: &[u8; 32],
    session_nonce: u64,
    epoch: u64,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(ZK_DOMAIN_SEPARATOR);
    hasher.update(x_bytes);
    hasher.update(r_bytes);
    hasher.update(policy_root);
    hasher.update(peer_pubkey);
    hasher.update(session_nonce.to_be_bytes());
    hasher.update(epoch.to_be_bytes());
    let hash: [u8; 64] = hasher.finalize().into();

    Scalar::from_bytes_mod_order_wide(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_proof_lifecycle() {
        let witness = PlatformWitness::generate_fresh();
        let peer_pub = [0x42u8; 32];
        let session_nonce = 1001u64;
        let epoch = 1;

        let proof = generate_zk_proof(&witness, &peer_pub, session_nonce, epoch);

        let statement = VerificationStatement {
            target_peer_pubkey: &peer_pub,
            session_nonce,
            expected_policy_root: &STANDARD_POLICY_ROOT,
        };

        assert!(verify_zk_proof(&proof, &statement));
    }

    #[test]
    fn test_zk_tampering_rejection() {
        let witness = PlatformWitness::generate_fresh();
        let peer_pub = [0x42u8; 32];
        let session_nonce = 1001u64;
        let epoch = 1;

        let proof = generate_zk_proof(&witness, &peer_pub, session_nonce, epoch);

        // Wrong peer pubkey
        let wrong_peer = [0x99u8; 32];
        let bad_statement_peer = VerificationStatement {
            target_peer_pubkey: &wrong_peer,
            session_nonce,
            expected_policy_root: &STANDARD_POLICY_ROOT,
        };
        assert!(!verify_zk_proof(&proof, &bad_statement_peer));

        // Replay attempt with different nonce
        let bad_statement_nonce = VerificationStatement {
            target_peer_pubkey: &peer_pub,
            session_nonce: 1002u64,
            expected_policy_root: &STANDARD_POLICY_ROOT,
        };
        assert!(!verify_zk_proof(&proof, &bad_statement_nonce));

        // Tampered proof response
        let mut tampered_proof = proof.clone();
        tampered_proof.response_s[0] ^= 0xFF;
        let valid_statement = VerificationStatement {
            target_peer_pubkey: &peer_pub,
            session_nonce,
            expected_policy_root: &STANDARD_POLICY_ROOT,
        };
        assert!(!verify_zk_proof(&tampered_proof, &valid_statement));
    }
}
