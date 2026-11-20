use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PACKET_MAGIC: [u8; 4] = *b"SBM1";
pub const PACKET_MAGIC_V2: [u8; 4] = *b"SBM2";

/// Derive deterministic 8-byte Swarm Tag from topic name for Single-Port Dispatching
pub fn derive_swarm_tag(topic: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"SBM_SWARM_TAG_V2:");
    hasher.update(topic.as_bytes());
    let hash = hasher.finalize();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hash[..8]);
    tag
}

pub const PREAUTH_SWARM_TOPIC: &str = "sbm-preauth-knock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    HandshakeInit = 1,
    HandshakeResp = 2,
    Ping = 3,
    Pong = 4,
    Data = 5,
    RekeyInit = 6,
    RekeyResp = 7,
    TicketReq = 8,
    TicketGrant = 9,
}

impl PacketType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(PacketType::HandshakeInit),
            2 => Some(PacketType::HandshakeResp),
            3 => Some(PacketType::Ping),
            4 => Some(PacketType::Pong),
            5 => Some(PacketType::Data),
            6 => Some(PacketType::RekeyInit),
            7 => Some(PacketType::RekeyResp),
            8 => Some(PacketType::TicketReq),
            9 => Some(PacketType::TicketGrant),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub send: ZeroizingKey,
    pub receive: ZeroizingKey,
}

// CVE-Threat: Reusing one AEAD key with independently advancing peer counters can repeat a nonce.
// Analysis: Both endpoints can emit the same counter before exchanging any state.
// Hardening: HKDF derives distinct keys using ordered sender and recipient identities.
/// Derive direction-separated keys from the authenticated static X25519 identities.
pub fn derive_session_keys(
    local_secret: &StaticSecret,
    remote_public: &PublicKey,
) -> Result<SessionKeys, String> {
    let local_public = PublicKey::from(local_secret);
    if local_public.as_bytes() == remote_public.as_bytes() {
        return Err("Cannot establish a session with the local identity".to_string());
    }

    let shared = local_secret.diffie_hellman(remote_public);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err("Remote X25519 public key produced an all-zero shared secret".to_string());
    }

    let send = derive_directional_key(
        shared.as_bytes(),
        local_public.as_bytes(),
        remote_public.as_bytes(),
    )?;
    let receive = derive_directional_key(
        shared.as_bytes(),
        remote_public.as_bytes(),
        local_public.as_bytes(),
    )?;

    Ok(SessionKeys {
        send: ZeroizingKey::new(send),
        receive: ZeroizingKey::new(receive),
    })
}

fn derive_directional_key(
    shared_secret: &[u8; 32],
    sender_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"SBM_SESSION_KDF_V2"), shared_secret);
    let mut info = Vec::with_capacity(64 + 40);
    info.extend_from_slice(b"SBM_CHACHA20_POLY1305_DIRECTION_V2");
    info.extend_from_slice(sender_public);
    info.extend_from_slice(recipient_public);

    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| "Failed to derive directional session key".to_string())?;
    Ok(key)
}

/// Build standard 12-byte AEAD nonce from a 64-bit monotonically increasing sequence number
pub fn build_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&nonce_bytes)
}

/// Encrypt payload using ChaCha20-Poly1305 with 64-bit anti-replay sequence number
pub fn encrypt_payload(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("Invalid cipher key: {}", e))?;
    let nonce = build_nonce(counter);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("Encryption failure: {}", e))
}

/// Decrypt payload using ChaCha20-Poly1305 with 64-bit anti-replay sequence number
pub fn decrypt_payload(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("Invalid cipher key: {}", e))?;
    let nonce = build_nonce(counter);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| format!("Authentication/Decryption failure: {}", e))
}

/// Encode a complete WireGuard-style packet:
/// [0..4]: Magic (SBM1)
/// [4]: PacketType
/// [5..37]: Sender Public Key (32 bytes)
/// [37..45]: Nonce / Counter (8 bytes, Big-Endian)
/// [45..]: Encrypted payload + Poly1305 Tag (16 bytes)
pub fn pack_message(
    packet_type: PacketType,
    sender_pubkey: &[u8; 32],
    counter: u64,
    encrypted_payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(45 + encrypted_payload.len());
    buf.extend_from_slice(&PACKET_MAGIC);
    buf.push(packet_type as u8);
    buf.extend_from_slice(sender_pubkey);
    buf.extend_from_slice(&counter.to_be_bytes());
    buf.extend_from_slice(encrypted_payload);
    buf
}

/// Parse and validate header of an incoming packet
#[allow(clippy::type_complexity)]
pub fn unpack_header(packet: &[u8]) -> Result<(PacketType, [u8; 32], u64, &[u8]), String> {
    if packet.len() < 45 {
        return Err("Packet too short (< 45 bytes header)".to_string());
    }
    if packet[0..4] != PACKET_MAGIC {
        return Err("Invalid packet magic header".to_string());
    }
    let ptype = PacketType::from_u8(packet[4])
        .ok_or_else(|| format!("Unknown packet type: {}", packet[4]))?;

    let mut sender_pubkey = [0u8; 32];
    sender_pubkey.copy_from_slice(&packet[5..37]);

    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&packet[37..45]);
    let counter = u64::from_be_bytes(counter_bytes);

    let payload = &packet[45..];
    Ok((ptype, sender_pubkey, counter, payload))
}

/// Encode a complete WireGuard-style packet with Multi-Tenant Swarm Tag (SBM2):
/// [0..4]: Magic (SBM2)
/// [4..12]: Swarm Tag (8 bytes)
/// [12]: PacketType (1 byte)
/// [13..45]: Sender Public Key (32 bytes)
/// [45..53]: Nonce / Counter (8 bytes, Big-Endian)
/// [53..]: Encrypted payload + Poly1305 Tag (16 bytes)
pub fn pack_message_v2(
    packet_type: PacketType,
    swarm_tag: &[u8; 8],
    sender_pubkey: &[u8; 32],
    counter: u64,
    encrypted_payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(53 + encrypted_payload.len());
    buf.extend_from_slice(&PACKET_MAGIC_V2);
    buf.extend_from_slice(swarm_tag);
    buf.push(packet_type as u8);
    buf.extend_from_slice(sender_pubkey);
    buf.extend_from_slice(&counter.to_be_bytes());
    buf.extend_from_slice(encrypted_payload);
    buf
}

/// Parse and validate header of an incoming V2 multi-tenant packet
#[allow(clippy::type_complexity)]
pub fn unpack_header_v2(
    packet: &[u8],
) -> Result<(PacketType, [u8; 8], [u8; 32], u64, &[u8]), String> {
    if packet.len() < 53 {
        return Err("V2 packet too short (< 53 bytes header)".to_string());
    }
    if packet[0..4] != PACKET_MAGIC_V2 {
        return Err("Invalid V2 packet magic header".to_string());
    }
    let mut swarm_tag = [0u8; 8];
    swarm_tag.copy_from_slice(&packet[4..12]);

    let ptype = PacketType::from_u8(packet[12])
        .ok_or_else(|| format!("Unknown packet type: {}", packet[12]))?;

    let mut sender_pubkey = [0u8; 32];
    sender_pubkey.copy_from_slice(&packet[13..45]);

    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&packet[45..53]);
    let counter = u64::from_be_bytes(counter_bytes);

    let payload = &packet[53..];
    Ok((ptype, swarm_tag, sender_pubkey, counter, payload))
}

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protected in-memory key that securely zeros its buffer upon drop
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingKey(pub [u8; 32]);

impl ZeroizingKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ZeroizingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizingKey([REDACTED])")
    }
}

impl std::ops::Deref for ZeroizingKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// KDF Ratchet step: Derives the next epoch key from current key and ephemeral Diffie-Hellman secret.
/// Advances epoch and ensures Perfect Forward Secrecy (PFS).
pub fn ratchet_forward(
    current_key: &[u8; 32],
    ephemeral_shared: &[u8; 32],
    epoch: u64,
) -> ZeroizingKey {
    let mut hasher = Sha256::new();
    hasher.update(b"SBM_PFS_RATCHET_FORWARD_V1");
    hasher.update(current_key);
    hasher.update(ephemeral_shared);
    hasher.update(epoch.to_be_bytes());
    let result = hasher.finalize();
    let mut new_key = [0u8; 32];
    new_key.copy_from_slice(&result);
    ZeroizingKey(new_key)
}

pub fn ratchet_session_keys(
    current_keys: &SessionKeys,
    ephemeral_shared: &[u8; 32],
    epoch: u64,
) -> SessionKeys {
    SessionKeys {
        send: ratchet_forward(current_keys.send.as_bytes(), ephemeral_shared, epoch),
        receive: ratchet_forward(current_keys.receive.as_bytes(), ephemeral_shared, epoch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroizing_key_clears_memory() {
        let mut key = ZeroizingKey::new([0x42; 32]);
        assert_eq!(key[0], 0x42);
        key.zeroize();
        assert_eq!(key.0, [0u8; 32]);
    }

    #[test]
    fn test_ratchet_forward_pfs() {
        let base_key = [0x11u8; 32];
        let eph_shared = [0x22u8; 32];

        let epoch1_key = ratchet_forward(&base_key, &eph_shared, 1);
        let epoch2_key = ratchet_forward(&epoch1_key, &eph_shared, 2);

        assert_ne!(&epoch1_key[..], &base_key[..]);
        assert_ne!(&epoch2_key[..], &epoch1_key[..]);

        // Deterministic ratchet with same inputs
        let verify_key = ratchet_forward(&base_key, &eph_shared, 1);
        assert_eq!(&epoch1_key[..], &verify_key[..]);
    }

    #[test]
    fn test_directional_session_keys_prevent_cross_direction_nonce_reuse() {
        let alice_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);

        let alice_keys = derive_session_keys(&alice_secret, &bob_public).unwrap();
        let bob_keys = derive_session_keys(&bob_secret, &alice_public).unwrap();

        assert_eq!(alice_keys.send, bob_keys.receive);
        assert_eq!(alice_keys.receive, bob_keys.send);
        assert_ne!(alice_keys.send, alice_keys.receive);

        let plaintext = b"directional nonce test";
        let ciphertext = encrypt_payload(alice_keys.send.as_bytes(), 1, plaintext).unwrap();
        assert!(decrypt_payload(bob_keys.receive.as_bytes(), 1, &ciphertext).is_ok());
        assert!(decrypt_payload(bob_keys.send.as_bytes(), 1, &ciphertext).is_err());

        let zero_public = PublicKey::from([0u8; 32]);
        assert!(derive_session_keys(&alice_secret, &zero_public).is_err());
    }

    #[test]
    fn test_directional_keys_remain_consistent_after_ratchet() {
        let alice_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);
        let alice_keys = derive_session_keys(&alice_secret, &bob_public).unwrap();
        let bob_keys = derive_session_keys(&bob_secret, &alice_public).unwrap();
        let eph_shared = [0x27u8; 32];

        let alice_next = ratchet_session_keys(&alice_keys, &eph_shared, 1);
        let bob_next = ratchet_session_keys(&bob_keys, &eph_shared, 1);

        assert_eq!(alice_next.send, bob_next.receive);
        assert_eq!(alice_next.receive, bob_next.send);
        assert_ne!(alice_next.send, alice_keys.send);
    }

    #[test]
    fn test_pack_unpack_v2_with_swarm_tag() {
        let topic = "sbm-swarm-acme-prod";
        let tag = derive_swarm_tag(topic);
        assert_ne!(tag, [0u8; 8]);

        let sender_pub = [0x77u8; 32];
        let counter = 42u64;
        let payload = b"HELLO_SBM2_SWARM";

        let packed = pack_message_v2(PacketType::Data, &tag, &sender_pub, counter, payload);
        assert_eq!(&packed[0..4], &PACKET_MAGIC_V2);

        let (ptype, unpacked_tag, unpacked_pub, unpacked_counter, unpacked_payload) =
            unpack_header_v2(&packed).unwrap();

        assert_eq!(ptype, PacketType::Data);
        assert_eq!(unpacked_tag, tag);
        assert_eq!(unpacked_pub, sender_pub);
        assert_eq!(unpacked_counter, counter);
        assert_eq!(unpacked_payload, payload);
    }

    #[test]
    fn test_unpack_v2_rejects_malformed_and_truncated_packets() {
        assert!(unpack_header_v2(&[]).is_err());
        assert!(unpack_header_v2(b"SBM2").is_err());
        assert!(unpack_header_v2(&[0u8; 52]).is_err());

        let mut bad_magic = pack_message_v2(PacketType::Ping, &[1u8; 8], &[2u8; 32], 1, b"x");
        bad_magic[0] = b'X';
        assert!(unpack_header_v2(&bad_magic).is_err());

        let mut bad_type = pack_message_v2(PacketType::Ping, &[1u8; 8], &[2u8; 32], 1, b"x");
        bad_type[12] = 250;
        assert!(unpack_header_v2(&bad_type).is_err());

        for len in 0..=128usize {
            let mut buf = vec![0xAAu8; len];
            if len >= 4 {
                buf[0..4].copy_from_slice(&PACKET_MAGIC_V2);
            }
            let _ = unpack_header_v2(&buf);
        }
    }
}
