use serde::{Deserialize, Serialize};
use std::io::Read;

pub const MAGIC_BYTES: &[u8; 6] = b"SBDB01";
pub const HEADER_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EntryKind {
    Set = 1,
    Delete = 2,
    TxBegin = 3,
    TxCommit = 4,
    CreateIndex = 5,
    DropIndex = 6,
}

impl TryFrom<u8> for EntryKind {
    type Error = String;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(EntryKind::Set),
            2 => Ok(EntryKind::Delete),
            3 => Ok(EntryKind::TxBegin),
            4 => Ok(EntryKind::TxCommit),
            5 => Ok(EntryKind::CreateIndex),
            6 => Ok(EntryKind::DropIndex),
            other => Err(format!("Unknown entry kind byte: {}", other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub kind: EntryKind,
    pub tx_id: u64,
    pub timestamp: u64,
    pub ttl_expires_at: u64, // 0 = no expiration
    pub key: String,
    pub value: serde_json::Value,
}

impl Entry {
    pub fn new_set(
        tx_id: u64,
        timestamp: u64,
        ttl_expires_at: u64,
        key: String,
        value: serde_json::Value,
    ) -> Self {
        Self {
            kind: EntryKind::Set,
            tx_id,
            timestamp,
            ttl_expires_at,
            key,
            value,
        }
    }

    pub fn new_delete(tx_id: u64, timestamp: u64, key: String) -> Self {
        Self {
            kind: EntryKind::Delete,
            tx_id,
            timestamp,
            ttl_expires_at: 0,
            key,
            value: serde_json::Value::Null,
        }
    }

    /// Encode entry into bytes with trailing CRC32
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(64);
        body.push(self.kind as u8);
        body.extend_from_slice(&self.tx_id.to_be_bytes());
        body.extend_from_slice(&self.timestamp.to_be_bytes());
        body.extend_from_slice(&self.ttl_expires_at.to_be_bytes());

        let key_bytes = self.key.as_bytes();
        body.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(key_bytes);

        let val_bytes = serde_json::to_vec(&self.value).unwrap_or_default();
        body.extend_from_slice(&(val_bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(&val_bytes);

        let crc = crc32fast::hash(&body);
        let mut final_bytes = body;
        final_bytes.extend_from_slice(&crc.to_be_bytes());
        final_bytes
    }

    /// Decode entry from reader, validating CRC32
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, String> {
        let mut header_buf = [0u8; 1 + 8 + 8 + 8 + 4]; // kind(1) + tx_id(8) + ts(8) + ttl(8) + key_len(4) = 29 bytes
        if let Err(e) = reader.read_exact(&mut header_buf) {
            return Err(format!("Failed to read entry header: {}", e));
        }

        let kind = EntryKind::try_from(header_buf[0])?;
        let tx_id = u64::from_be_bytes(header_buf[1..9].try_into().unwrap());
        let timestamp = u64::from_be_bytes(header_buf[9..17].try_into().unwrap());
        let ttl_expires_at = u64::from_be_bytes(header_buf[17..25].try_into().unwrap());
        let key_len = u32::from_be_bytes(header_buf[25..29].try_into().unwrap()) as usize;

        let mut key_buf = vec![0u8; key_len];
        reader
            .read_exact(&mut key_buf)
            .map_err(|e| format!("Failed to read key: {}", e))?;

        let mut val_len_buf = [0u8; 4];
        reader
            .read_exact(&mut val_len_buf)
            .map_err(|e| format!("Failed to read val len: {}", e))?;
        let val_len = u32::from_be_bytes(val_len_buf) as usize;

        let mut val_buf = vec![0u8; val_len];
        reader
            .read_exact(&mut val_buf)
            .map_err(|e| format!("Failed to read value: {}", e))?;

        let mut crc_buf = [0u8; 4];
        reader
            .read_exact(&mut crc_buf)
            .map_err(|e| format!("Failed to read CRC: {}", e))?;
        let expected_crc = u32::from_be_bytes(crc_buf);

        // Verify CRC32 FIRST before interpreting untrusted bytes
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&header_buf);
        hasher.update(&key_buf);
        hasher.update(&val_len_buf);
        hasher.update(&val_buf);
        let actual_crc = hasher.finalize();

        if actual_crc != expected_crc {
            return Err(format!(
                "CRC32 mismatch! Expected 0x{:08x}, got 0x{:08x}",
                expected_crc, actual_crc
            ));
        }

        let key = String::from_utf8(key_buf).map_err(|e| format!("Invalid UTF-8 in key: {}", e))?;
        let value = serde_json::from_slice(&val_buf)
            .map_err(|e| format!("Invalid JSON value payload: {}", e))?;

        Ok(Self {
            kind,
            tx_id,
            timestamp,
            ttl_expires_at,
            key,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_encode_decode_roundtrip() {
        let entry = Entry::new_set(
            42,
            1720000000,
            1720003600,
            "users:alice".to_string(),
            serde_json::json!({
                "name": "Alice",
                "role": "admin",
                "active": true
            }),
        );

        let encoded = entry.encode();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = Entry::decode(&mut cursor).unwrap();

        assert_eq!(entry, decoded);
    }

    #[test]
    fn test_corrupted_crc_detection() {
        let entry = Entry::new_delete(10, 1720000000, "session:123".to_string());
        let mut encoded = entry.encode();

        // Corrupt one byte of key
        encoded[30] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(encoded);
        let err = Entry::decode(&mut cursor).unwrap_err();
        assert!(err.contains("CRC32 mismatch"));
    }
}
