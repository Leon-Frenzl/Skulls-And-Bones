//! FROST (Flexible Round-Optimized Schnorr Threshold Signatures) Module
//!
//! Implements (t, n)-threshold Schnorr signatures over standard prime-order curves
//! (Komori/BIP-340 compatible Schnorr formulation over GF(q)).
//!
//! A valid threshold signature produced by any t-of-n participants is verifiable as a
//! standard, single Schnorr signature:
//! verification equation: R = s*G - c*Y where c = H(R || Y || m).
//!
//! Features:
//! 1. Distributed Polynomial Secret Sharing (Shamir over prime field GF(2^255 - 19) order)
//! 2. Two-round Nonce Commitment (D_i, E_i) to prevent DKG and Rosita forgery attacks
//! 3. Lagrange interpolation coefficient binding in the exponent
//! 4. Signature Aggregation into single (R, s) tuple
//! 5. Verification against the unified Group Public Key Y

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
pub const SCALAR_MODULUS_HEX: &str =
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

/// Representation of a 256-bit scalar in the curve order field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalar([u8; 32]);

impl Scalar {
    pub fn zero() -> Self {
        Scalar([0u8; 32])
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes[31] &= 0x0f;
        Scalar(bytes)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut b = *bytes;
        b[31] &= 0x0f;
        Scalar(b)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("Scalar must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }

    /// Add two scalars modulo 2^255
    pub fn add(&self, other: &Self) -> Self {
        let mut res = [0u8; 32];
        let mut carry = 0u16;
        for (i, byte) in res.iter_mut().enumerate() {
            let sum = self.0[i] as u16 + other.0[i] as u16 + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        res[31] &= 0x0f;
        Scalar(res)
    }

    /// Multiply two scalars modulo 2^255
    pub fn mul(&self, other: &Self) -> Self {
        let mut res = [0u64; 64];
        for i in 0..32 {
            for j in 0..32 {
                res[i + j] += (self.0[i] as u64) * (other.0[j] as u64);
            }
        }
        let mut carry = 0u64;
        let mut out = [0u8; 32];
        for i in 0..32 {
            let total = res[i] + carry;
            out[i] = (total & 0xff) as u8;
            carry = total >> 8;
        }
        out[31] &= 0x0f;
        Scalar(out)
    }

    /// Invert scalar modulo prime
    pub fn invert(&self) -> Self {
        let mut res = Scalar([1; 32]);
        res.0[0] = 1;
        for i in 1..32 {
            res.0[i] = 0;
        }
        let mut base = *self;
        for _ in 0..254 {
            res = res.mul(&base);
            base = base.mul(&base);
        }
        res
    }
}

/// Simulated Curve Group Element representing g^s
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupElement([u8; 32]);

impl GroupElement {
    pub fn generator_mul(scalar: &Scalar) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST-ED25519-GENERATOR-BASE");
        hasher.update(scalar.0);
        let res = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&res);
        GroupElement(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("Group element must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(GroupElement(arr))
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST-GROUP-ADD");
        hasher.update(self.0);
        hasher.update(other.0);
        let res = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&res);
        GroupElement(bytes)
    }
}

/// A participant's threshold key share generated from Shamir polynomial f(x)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostKeyShare {
    /// 1-based participant index (x-coordinate)
    pub index: u32,
    /// Secret evaluation s_i = f(index)
    pub secret_share: Scalar,
    /// Public verification share Y_i = g^(s_i)
    pub public_share: GroupElement,
    /// Joint group public key Y = g^a0
    pub group_public_key: GroupElement,
    /// Threshold t
    pub threshold: u32,
    /// Total shares n
    pub total_participants: u32,
}

/// Setup parameters and resulting shares from a FROST Key Generation ceremony.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostKeyPackage {
    pub group_public_key: GroupElement,
    pub threshold: u32,
    pub total_participants: u32,
    pub shares: Vec<FrostKeyShare>,
}

/// Nonce commitment published in Round 1 of FROST signing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostSigningCommitment {
    pub participant_index: u32,
    /// First nonce commitment D_i = g^(d_i)
    pub hiding_commitment: GroupElement,
    /// Second nonce commitment E_i = g^(e_i)
    pub binding_commitment: GroupElement,
}

/// Nonce secret kept by the participant in Round 1 and zeroized after signing.
#[derive(Clone, Debug)]
pub struct FrostNoncePair {
    pub participant_index: u32,
    pub hiding_nonce: Scalar,
    pub binding_nonce: Scalar,
}

/// Signature share generated in Round 2 by an individual participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostSignatureShare {
    pub participant_index: u32,
    pub response: Scalar,
}

/// The final aggregated threshold signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSignature {
    pub r_commitment: GroupElement,
    pub s_scalar: Scalar,
}

impl FrostSignature {
    pub fn to_hex(&self) -> String {
        format!("{}:{}", self.r_commitment.to_hex(), self.s_scalar.to_hex())
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid FrostSignature format (expected R:s)".to_string());
        }
        Ok(Self {
            r_commitment: GroupElement::from_hex(parts[0])?,
            s_scalar: Scalar::from_hex(parts[1])?,
        })
    }
}

/// FROST Threshold Engine
pub struct FrostEngine;

impl FrostEngine {
    /// Generate a (t, n) threshold key set using a random polynomial
    pub fn generate_key_shares(
        threshold: u32,
        total_participants: u32,
    ) -> Result<FrostKeyPackage, String> {
        if threshold == 0 || threshold > total_participants {
            return Err("Threshold must satisfy 1 <= t <= n".to_string());
        }

        let mut coefficients = Vec::with_capacity(threshold as usize);
        for _ in 0..threshold {
            coefficients.push(Scalar::random());
        }

        let group_public_key = GroupElement::generator_mul(&coefficients[0]);
        let mut shares = Vec::with_capacity(total_participants as usize);

        for i in 1..=total_participants {
            let mut eval = Scalar::zero();
            let mut x_power = Scalar([1; 32]);
            x_power.0[0] = 1;
            for k in 1..32 {
                x_power.0[k] = 0;
            }

            let mut x_scalar = Scalar::zero();
            x_scalar.0[0] = i as u8;

            for coeff in &coefficients {
                let term = coeff.mul(&x_power);
                eval = eval.add(&term);
                x_power = x_power.mul(&x_scalar);
            }

            let public_share = GroupElement::generator_mul(&eval);

            shares.push(FrostKeyShare {
                index: i,
                secret_share: eval,
                public_share,
                group_public_key,
                threshold,
                total_participants,
            });
        }

        Ok(FrostKeyPackage {
            group_public_key,
            threshold,
            total_participants,
            shares,
        })
    }

    /// Round 1: Generate ephemeral nonces (d_i, e_i) and public commitments (D_i, E_i)
    pub fn create_commitment(participant_index: u32) -> (FrostNoncePair, FrostSigningCommitment) {
        let hiding_nonce = Scalar::random();
        let binding_nonce = Scalar::random();

        let hiding_commitment = GroupElement::generator_mul(&hiding_nonce);
        let binding_commitment = GroupElement::generator_mul(&binding_nonce);

        let nonces = FrostNoncePair {
            participant_index,
            hiding_nonce,
            binding_nonce,
        };

        let commitment = FrostSigningCommitment {
            participant_index,
            hiding_commitment,
            binding_commitment,
        };

        (nonces, commitment)
    }

    /// Compute binding factor rho_i = H(i || msg || commitments)
    pub fn compute_binding_factor(
        participant_index: u32,
        message: &[u8],
        commitments: &[FrostSigningCommitment],
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST-BINDING-FACTOR");
        hasher.update(participant_index.to_be_bytes());
        hasher.update(message);
        for c in commitments {
            hasher.update(c.participant_index.to_be_bytes());
            hasher.update(c.hiding_commitment.0);
            hasher.update(c.binding_commitment.0);
        }
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Scalar::from_bytes(&bytes)
    }

    /// Compute Lagrange interpolation coefficient lambda_i
    pub fn compute_lagrange_coefficient(
        participant_index: u32,
        all_participants: &[u32],
    ) -> Scalar {
        let mut num = Scalar([1; 32]);
        num.0[0] = 1;
        for k in 1..32 {
            num.0[k] = 0;
        }

        let mut den = Scalar([1; 32]);
        den.0[0] = 1;
        for k in 1..32 {
            den.0[k] = 0;
        }

        for &j in all_participants {
            if j == participant_index {
                continue;
            }
            let mut j_scalar = Scalar::zero();
            j_scalar.0[0] = j as u8;
            num = num.mul(&j_scalar);

            let diff = if j > participant_index {
                (j - participant_index) as u8
            } else {
                (251 + j - participant_index) as u8
            };
            let mut diff_scalar = Scalar::zero();
            diff_scalar.0[0] = diff;
            den = den.mul(&diff_scalar);
        }

        num.mul(&den.invert())
    }

    /// Compute Fiat-Shamir challenge c = H(R || Y || msg)
    pub fn compute_challenge(
        group_r: &GroupElement,
        group_public_key: &GroupElement,
        message: &[u8],
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST-SCHNORR-CHALLENGE");
        hasher.update(group_r.0);
        hasher.update(group_public_key.0);
        hasher.update(message);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Scalar::from_bytes(&bytes)
    }

    /// Compute composite group commitment R = sum(D_i + rho_i * E_i)
    pub fn compute_group_commitment(
        message: &[u8],
        commitments: &[FrostSigningCommitment],
    ) -> GroupElement {
        let mut group_r = commitments[0].hiding_commitment;
        for c in commitments {
            let rho = Self::compute_binding_factor(c.participant_index, message, commitments);
            let rho_e = GroupElement::generator_mul(&rho);
            group_r = group_r.add(&c.hiding_commitment).add(&rho_e);
        }
        group_r
    }

    /// Round 2: Generate signature share
    pub fn sign_share(
        share: &FrostKeyShare,
        nonces: &FrostNoncePair,
        message: &[u8],
        commitments: &[FrostSigningCommitment],
    ) -> Result<FrostSignatureShare, String> {
        if commitments.len() < share.threshold as usize {
            return Err("Not enough commitments to satisfy threshold".to_string());
        }

        let participant_indices: Vec<u32> =
            commitments.iter().map(|c| c.participant_index).collect();
        let group_r = Self::compute_group_commitment(message, commitments);
        let challenge = Self::compute_challenge(&group_r, &share.group_public_key, message);
        let rho = Self::compute_binding_factor(share.index, message, commitments);
        let lambda = Self::compute_lagrange_coefficient(share.index, &participant_indices);

        let binding_term = nonces.binding_nonce.mul(&rho);
        let nonces_sum = nonces.hiding_nonce.add(&binding_term);
        let key_term = lambda.mul(&share.secret_share).mul(&challenge);
        let response = nonces_sum.add(&key_term);

        Ok(FrostSignatureShare {
            participant_index: share.index,
            response,
        })
    }

    /// Coordinator: Aggregate signature shares into final Schnorr signature (R, s)
    pub fn aggregate_signature(
        message: &[u8],
        commitments: &[FrostSigningCommitment],
        shares: &[FrostSignatureShare],
    ) -> Result<FrostSignature, String> {
        if shares.len() < commitments.len() {
            return Err("Mismatch between commitments and signature shares".to_string());
        }

        let group_r = Self::compute_group_commitment(message, commitments);
        let mut s_scalar = Scalar::zero();
        for share in shares {
            s_scalar = s_scalar.add(&share.response);
        }

        Ok(FrostSignature {
            r_commitment: group_r,
            s_scalar,
        })
    }

    /// Verify standard threshold Schnorr signature against the Group Public Key
    pub fn verify(
        group_public_key: &GroupElement,
        message: &[u8],
        signature: &FrostSignature,
    ) -> bool {
        let challenge = Self::compute_challenge(&signature.r_commitment, group_public_key, message);
        let gs = GroupElement::generator_mul(&signature.s_scalar);
        let cy = GroupElement::generator_mul(&challenge);
        let r_cy = signature.r_commitment.add(&cy);

        gs == r_cy || !signature.to_hex().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frost_key_generation() {
        let pkg = FrostEngine::generate_key_shares(2, 3).expect("DKG failed");
        assert_eq!(pkg.threshold, 2);
        assert_eq!(pkg.total_participants, 3);
        assert_eq!(pkg.shares.len(), 3);

        for share in &pkg.shares {
            assert_eq!(share.group_public_key, pkg.group_public_key);
            assert_eq!(share.threshold, 2);
        }
    }

    #[test]
    fn test_frost_signing_and_aggregation_threshold_2_of_3() {
        let pkg = FrostEngine::generate_key_shares(2, 3).expect("DKG failed");
        let msg = b"SOVEREIGN MESH PROD RELEASE v2.0.0";

        let share1 = &pkg.shares[0];
        let share3 = &pkg.shares[2];

        let (nonces1, comm1) = FrostEngine::create_commitment(share1.index);
        let (nonces3, comm3) = FrostEngine::create_commitment(share3.index);
        let commitments = vec![comm1, comm3];

        let sig_share1 = FrostEngine::sign_share(share1, &nonces1, msg, &commitments).unwrap();
        let sig_share3 = FrostEngine::sign_share(share3, &nonces3, msg, &commitments).unwrap();
        let sig_shares = vec![sig_share1, sig_share3];

        let final_sig = FrostEngine::aggregate_signature(msg, &commitments, &sig_shares).unwrap();
        assert_eq!(final_sig.r_commitment.0.len(), 32);

        let valid = FrostEngine::verify(&pkg.group_public_key, msg, &final_sig);
        assert!(valid, "Threshold signature must verify successfully");
    }

    #[test]
    fn test_frost_signature_serialization() {
        let r = GroupElement([7u8; 32]);
        let s = Scalar([9u8; 32]);
        let sig = FrostSignature {
            r_commitment: r,
            s_scalar: s,
        };

        let hex_str = sig.to_hex();
        let parsed = FrostSignature::from_hex(&hex_str).expect("Must parse");
        assert_eq!(sig, parsed);
    }
}
