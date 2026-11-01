use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_DATA_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidField(&'static str),
    UnsupportedVersion(u16),
    FrameTooLarge,
    InvalidFrameLength,
    InvalidChunk(&'static str),
    IncompleteTransfer,
    TransferDigestMismatch,
    Io(String),
    Encoding(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "Invalid SB-MAP field: {field}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "Unsupported SB-MAP protocol version {version}")
            }
            Self::FrameTooLarge => {
                formatter.write_str("SB-MAP control frame exceeds its configured limit")
            }
            Self::InvalidFrameLength => formatter.write_str("Invalid SB-MAP control frame length"),
            Self::InvalidChunk(reason) => write!(formatter, "Invalid SB-MAP data chunk: {reason}"),
            Self::IncompleteTransfer => {
                formatter.write_str("SB-MAP transfer did not match its declared size")
            }
            Self::TransferDigestMismatch => {
                formatter.write_str("SB-MAP transfer digest does not match its offer")
            }
            Self::Io(message) | Self::Encoding(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub version: u16,
    pub request_id: String,
    pub mesh_id: String,
    pub subject_node_id: String,
    pub app_id: String,
    pub client_digest: String,
    pub service_id: String,
    pub api_version: u16,
    pub operation: String,
    pub resource_id: String,
    pub resource_version: Option<String>,
    pub policy_epoch: u64,
    pub deadline_unix_ms: u64,
    pub grant_id: String,
}

impl OperationRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        for (field, value) in [
            ("request_id", self.request_id.as_str()),
            ("mesh_id", self.mesh_id.as_str()),
            ("subject_node_id", self.subject_node_id.as_str()),
            ("app_id", self.app_id.as_str()),
            ("service_id", self.service_id.as_str()),
            ("operation", self.operation.as_str()),
            ("resource_id", self.resource_id.as_str()),
            ("grant_id", self.grant_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if let Some(version) = &self.resource_version {
            validate_identifier("resource_version", version)?;
        }
        if !is_sha256_digest(&self.client_digest) {
            return Err(ProtocolError::InvalidField("client_digest"));
        }
        if self.api_version == 0 || self.deadline_unix_ms == 0 {
            return Err(ProtocolError::InvalidField(
                "api_version or deadline_unix_ms",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferOffer {
    pub version: u16,
    pub request_id: String,
    pub transfer_id: String,
    pub resource_id: String,
    pub resource_version: String,
    pub total_bytes: u64,
    pub sha256: String,
    pub max_chunk_bytes: u32,
}

impl TransferOffer {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        for (field, value) in [
            ("request_id", self.request_id.as_str()),
            ("transfer_id", self.transfer_id.as_str()),
            ("resource_id", self.resource_id.as_str()),
            ("resource_version", self.resource_version.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if self.total_bytes > MAX_OBJECT_BYTES {
            return Err(ProtocolError::InvalidField("total_bytes"));
        }
        if self.max_chunk_bytes == 0
            || self.max_chunk_bytes as usize > MAX_DATA_CHUNK_BYTES
            || !is_sha256_digest(&self.sha256)
        {
            return Err(ProtocolError::InvalidField("max_chunk_bytes or sha256"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChunkHeader {
    pub version: u16,
    pub transfer_id: String,
    pub sequence: u32,
    pub offset: u64,
    pub payload_bytes: u32,
    pub sha256: String,
}

impl ChunkHeader {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        validate_identifier("transfer_id", &self.transfer_id)?;
        if self.payload_bytes == 0
            || self.payload_bytes as usize > MAX_DATA_CHUNK_BYTES
            || !is_sha256_digest(&self.sha256)
        {
            return Err(ProtocolError::InvalidField("payload_bytes or chunk sha256"));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct TransferVerifier {
    offer: TransferOffer,
    next_sequence: u32,
    received_bytes: u64,
    digest: Sha256,
}

impl TransferVerifier {
    pub fn new(offer: TransferOffer) -> Result<Self, ProtocolError> {
        offer.validate()?;
        Ok(Self {
            offer,
            next_sequence: 0,
            received_bytes: 0,
            digest: Sha256::new(),
        })
    }

    pub fn accept_chunk(
        &mut self,
        header: &ChunkHeader,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        header.validate()?;
        if header.transfer_id != self.offer.transfer_id {
            return Err(ProtocolError::InvalidChunk("wrong transfer ID"));
        }
        if header.sequence != self.next_sequence || header.offset != self.received_bytes {
            return Err(ProtocolError::InvalidChunk(
                "chunk sequence or offset is not contiguous",
            ));
        }
        if header.payload_bytes > self.offer.max_chunk_bytes
            || payload.len() != header.payload_bytes as usize
            || self.received_bytes.saturating_add(payload.len() as u64) > self.offer.total_bytes
        {
            return Err(ProtocolError::InvalidChunk(
                "chunk length exceeds the authorized transfer",
            ));
        }
        let chunk_digest = format!("sha256:{}", hex_lower(&Sha256::digest(payload)));
        if chunk_digest != header.sha256 {
            return Err(ProtocolError::InvalidChunk("chunk digest mismatch"));
        }
        self.digest.update(payload);
        self.received_bytes += payload.len() as u64;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ProtocolError::InvalidChunk("sequence overflow"))?;
        Ok(())
    }

    pub fn finish(self) -> Result<(), ProtocolError> {
        if self.received_bytes != self.offer.total_bytes {
            return Err(ProtocolError::IncompleteTransfer);
        }
        let digest = format!("sha256:{}", hex_lower(&self.digest.finalize()));
        if digest != self.offer.sha256 {
            return Err(ProtocolError::TransferDigestMismatch);
        }
        Ok(())
    }
}

pub async fn write_control<W, T>(writer: &mut W, message: &T) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    write_control_with_limit(writer, message, MAX_CONTROL_FRAME_BYTES).await
}

pub async fn write_control_with_limit<W, T>(
    writer: &mut W,
    message: &T,
    max_frame_bytes: usize,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    if max_frame_bytes == 0 || max_frame_bytes > MAX_CONTROL_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrameLength);
    }
    let bytes =
        serde_json::to_vec(message).map_err(|error| ProtocolError::Encoding(error.to_string()))?;
    if bytes.is_empty() || bytes.len() > max_frame_bytes {
        return Err(ProtocolError::FrameTooLarge);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    writer
        .write_u32(length)
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))
}

pub async fn read_control<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_control_with_limit(reader, MAX_CONTROL_FRAME_BYTES).await
}

pub async fn read_control_with_limit<R, T>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    if max_frame_bytes == 0 || max_frame_bytes > MAX_CONTROL_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrameLength);
    }
    let length = reader
        .read_u32()
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))? as usize;
    if length == 0 {
        return Err(ProtocolError::InvalidFrameLength);
    }
    if length > max_frame_bytes {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| ProtocolError::Encoding(error.to_string()))
}

pub async fn write_chunk<W>(
    writer: &mut W,
    transfer_id: &str,
    sequence: u32,
    offset: u64,
    payload: &[u8],
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() || payload.len() > MAX_DATA_CHUNK_BYTES {
        return Err(ProtocolError::InvalidChunk("payload length outside limits"));
    }
    let header = ChunkHeader {
        version: PROTOCOL_VERSION,
        transfer_id: transfer_id.to_string(),
        sequence,
        offset,
        payload_bytes: u32::try_from(payload.len())
            .map_err(|_| ProtocolError::InvalidChunk("payload length overflow"))?,
        sha256: format!("sha256:{}", hex_lower(&Sha256::digest(payload))),
    };
    header.validate()?;
    write_control(writer, &header).await?;
    writer
        .write_all(payload)
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))
}

pub async fn read_chunk<R>(reader: &mut R) -> Result<(ChunkHeader, Vec<u8>), ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let header: ChunkHeader = read_control(reader).await?;
    header.validate()?;
    let mut payload = vec![0; header.payload_bytes as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| ProtocolError::Io(error.to_string()))?;
    let digest = format!("sha256:{}", hex_lower(&Sha256::digest(&payload)));
    if digest != header.sha256 {
        return Err(ProtocolError::InvalidChunk("chunk digest mismatch"));
    }
    Ok((header, payload))
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    fn transfer_offer(payload: &[u8]) -> TransferOffer {
        TransferOffer {
            version: PROTOCOL_VERSION,
            request_id: "request-1".into(),
            transfer_id: "transfer-1".into(),
            resource_id: "object-1".into(),
            resource_version: "version-1".into(),
            total_bytes: payload.len() as u64,
            sha256: format!("sha256:{}", hex_lower(&Sha256::digest(payload))),
            max_chunk_bytes: MAX_DATA_CHUNK_BYTES as u32,
        }
    }

    #[tokio::test]
    async fn control_frame_roundtrips_strict_request() {
        let request = OperationRequest {
            version: PROTOCOL_VERSION,
            request_id: "request-1".into(),
            mesh_id: "mesh-public".into(),
            subject_node_id: "node-1".into(),
            app_id: "org.example.editor".into(),
            client_digest: format!("sha256:{}", "a".repeat(64)),
            service_id: "org.example.code".into(),
            api_version: 1,
            operation: "workspace.read".into(),
            resource_id: "workspace-1".into(),
            resource_version: Some("version-1".into()),
            policy_epoch: 4,
            deadline_unix_ms: 10_000,
            grant_id: "grant-1".into(),
        };
        request.validate().unwrap();
        let (mut writer, mut reader) = duplex(MAX_CONTROL_FRAME_BYTES);
        write_control(&mut writer, &request).await.unwrap();
        let decoded: OperationRequest = read_control(&mut reader).await.unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn operation_request_rejects_paths_bad_digests_and_unknown_versions() {
        let mut request = OperationRequest {
            version: PROTOCOL_VERSION,
            request_id: "request-1".into(),
            mesh_id: "mesh-public".into(),
            subject_node_id: "node-1".into(),
            app_id: "org.example.editor".into(),
            client_digest: format!("sha256:{}", "a".repeat(64)),
            service_id: "org.example.code".into(),
            api_version: 1,
            operation: "workspace.read".into(),
            resource_id: "workspace-1".into(),
            resource_version: None,
            policy_epoch: 1,
            deadline_unix_ms: 10_000,
            grant_id: "grant-1".into(),
        };
        request.resource_id = "../secret".into();
        assert_eq!(
            request.validate(),
            Err(ProtocolError::InvalidField("resource_id"))
        );
        request.resource_id = "workspace-1".into();
        request.client_digest = format!("sha256:{}", "A".repeat(64));
        assert_eq!(
            request.validate(),
            Err(ProtocolError::InvalidField("client_digest"))
        );
        request.client_digest = format!("sha256:{}", "a".repeat(64));
        request.version = PROTOCOL_VERSION + 1;
        assert_eq!(
            request.validate(),
            Err(ProtocolError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_payload_allocation() {
        let (mut writer, mut reader) = duplex(8);
        writer
            .write_u32((MAX_CONTROL_FRAME_BYTES as u32) + 1)
            .await
            .unwrap();
        assert_eq!(
            read_control::<_, ChunkHeader>(&mut reader).await,
            Err(ProtocolError::FrameTooLarge)
        );
    }

    #[tokio::test]
    async fn control_frame_rejects_unknown_fields() {
        let (mut writer, mut reader) = duplex(128);
        let bytes = br#"{"version":1,"extra":"not allowed"}"#;
        writer.write_u32(bytes.len() as u32).await.unwrap();
        writer.write_all(bytes).await.unwrap();
        assert!(matches!(
            read_control::<_, OperationRequest>(&mut reader).await,
            Err(ProtocolError::Encoding(_))
        ));
    }

    #[tokio::test]
    async fn chunk_transfer_checks_order_size_and_digests() {
        let first = b"mesh ";
        let second = b"object";
        let all = [first.as_slice(), second.as_slice()].concat();
        let offer = transfer_offer(&all);
        let (mut writer, mut reader) = duplex(1024);
        write_chunk(&mut writer, "transfer-1", 0, 0, first)
            .await
            .unwrap();
        write_chunk(&mut writer, "transfer-1", 1, first.len() as u64, second)
            .await
            .unwrap();

        let mut verifier = TransferVerifier::new(offer).unwrap();
        let (header, payload) = read_chunk(&mut reader).await.unwrap();
        verifier.accept_chunk(&header, &payload).unwrap();
        let (header, payload) = read_chunk(&mut reader).await.unwrap();
        verifier.accept_chunk(&header, &payload).unwrap();
        verifier.finish().unwrap();
    }

    #[test]
    fn transfer_verifier_rejects_reordering_and_wrong_content() {
        let payload = b"authorized bytes";
        let offer = transfer_offer(payload);
        let mut verifier = TransferVerifier::new(offer.clone()).unwrap();
        let digest = format!("sha256:{}", hex_lower(&Sha256::digest(payload)));
        let out_of_order = ChunkHeader {
            version: PROTOCOL_VERSION,
            transfer_id: offer.transfer_id.clone(),
            sequence: 1,
            offset: 0,
            payload_bytes: payload.len() as u32,
            sha256: digest,
        };
        assert_eq!(
            verifier.accept_chunk(&out_of_order, payload),
            Err(ProtocolError::InvalidChunk(
                "chunk sequence or offset is not contiguous"
            ))
        );

        let mut verifier = TransferVerifier::new(offer.clone()).unwrap();
        let chunk = ChunkHeader {
            version: PROTOCOL_VERSION,
            transfer_id: offer.transfer_id,
            sequence: 0,
            offset: 0,
            payload_bytes: payload.len() as u32,
            sha256: format!("sha256:{}", hex_lower(&Sha256::digest(payload))),
        };
        verifier.accept_chunk(&chunk, payload).unwrap();
        let mut wrong_offer = transfer_offer(b"different bytes");
        wrong_offer.total_bytes = payload.len() as u64;
        let mut verifier = TransferVerifier {
            offer: wrong_offer,
            next_sequence: 0,
            received_bytes: 0,
            digest: Sha256::new(),
        };
        let chunk = ChunkHeader {
            transfer_id: "transfer-1".into(),
            ..chunk
        };
        verifier.accept_chunk(&chunk, payload).unwrap();
        assert_eq!(
            verifier.finish(),
            Err(ProtocolError::TransferDigestMismatch)
        );
    }

    #[tokio::test]
    async fn chunk_reader_rejects_payload_digest_mismatch() {
        let (mut writer, mut reader) = duplex(512);
        let header = ChunkHeader {
            version: PROTOCOL_VERSION,
            transfer_id: "transfer-1".into(),
            sequence: 0,
            offset: 0,
            payload_bytes: 4,
            sha256: format!("sha256:{}", hex_lower(&Sha256::digest(b"good"))),
        };
        write_control(&mut writer, &header).await.unwrap();
        writer.write_all(b"evil").await.unwrap();
        assert_eq!(
            read_chunk(&mut reader).await,
            Err(ProtocolError::InvalidChunk("chunk digest mismatch"))
        );
    }
}
