use crate::db::DbStats;
use crate::event::DbEvent;
use crate::transaction::Transaction;
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_PORT: u16 = 58830;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbRequest {
    Ping,
    Get {
        key: String,
        path: Option<String>,
    },
    Set {
        key: String,
        value: serde_json::Value,
        ttl_secs: Option<u64>,
    },
    SetPath {
        key: String,
        path: String,
        value: serde_json::Value,
    },
    Delete {
        key: String,
    },
    Scan {
        prefix: String,
    },
    CreateIndex {
        prefix: String,
        field: String,
    },
    DropIndex {
        prefix: String,
        field: String,
    },
    Find {
        prefix: String,
        field: String,
        value: serde_json::Value,
    },
    Transaction {
        tx: Transaction,
    },
    Watch {
        pattern: String,
    },
    Compact,
    Stats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbResponse {
    Pong,
    Value(Option<serde_json::Value>),
    Success,
    CompactSuccess(u64),
    ScanResult(Vec<(String, serde_json::Value)>),
    FindResult(Vec<(String, serde_json::Value)>),
    Stats(DbStats),
    Event(DbEvent),
    Error(String),
}

/// Write a framed message: [4 bytes length][4 bytes CRC32][payload]
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut hasher = Hasher::new();
    hasher.update(&payload);
    let checksum = hasher.finalize();

    let len = payload.len() as u32;

    writer.write_u32(len).await?;
    writer.write_u32(checksum).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;

    Ok(())
}

/// Read a framed message: [4 bytes length][4 bytes CRC32][payload]
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let len = match reader.read_u32().await {
        Ok(l) => l,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection closed",
            ));
        }
        Err(e) => return Err(e),
    };

    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Frame size {} exceeds maximum allowed (64MB)", len),
        ));
    }

    let expected_crc = reader.read_u32().await?;

    let mut buffer = vec![0u8; len as usize];
    reader.read_exact(&mut buffer).await?;

    let mut hasher = Hasher::new();
    hasher.update(&buffer);
    let actual_crc = hasher.finalize();

    if actual_crc != expected_crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CRC32 mismatch: expected 0x{:08X}, got 0x{:08X}",
                expected_crc, actual_crc
            ),
        ));
    }

    serde_json::from_slice(&buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let req = DbRequest::Set {
            key: "user:42".to_string(),
            value: serde_json::json!({"name": "Leon", "role": "admin"}),
            ttl_secs: Some(3600),
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: DbRequest = read_frame(&mut cursor).await.unwrap();

        match decoded {
            DbRequest::Set {
                key,
                value,
                ttl_secs,
            } => {
                assert_eq!(key, "user:42");
                assert_eq!(value["name"], "Leon");
                assert_eq!(ttl_secs, Some(3600));
            }
            _ => panic!("Unexpected request variant"),
        }
    }

    #[tokio::test]
    async fn test_frame_crc_corruption() {
        let req = DbRequest::Ping;
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).await.unwrap();

        // Corrupt a byte in the payload
        let last_idx = buf.len() - 1;
        buf[last_idx] ^= 0xFF;

        let mut cursor = Cursor::new(buf);
        let res: io::Result<DbRequest> = read_frame(&mut cursor).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("CRC32 mismatch"));
    }
}
