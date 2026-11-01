use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

pub const DIRECTORY_SCHEMA_V1: &str = "sbm-directory/v1";
const NODE_RECORD_DOMAIN: &[u8] = b"SBM_DIRECTORY_NODE_RECORD_V1";
const SERVICE_RECORD_DOMAIN: &[u8] = b"SBM_DIRECTORY_SERVICE_RECORD_V1";
const SNAPSHOT_DOMAIN: &[u8] = b"SBM_DIRECTORY_SNAPSHOT_V1";
pub const DIRECTORY_SNAPSHOT_SCHEMA_V1: &str = "sbm-directory-snapshot/v1";
pub const MAX_SNAPSHOT_RECORDS: usize = 50_000;
const MAX_IDENTIFIER_LENGTH: usize = 128;
const MAX_OVERLAY_ADDRESSES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    InvalidField(&'static str),
    InvalidMeshFqdn(String),
    MeshMismatch,
    UnknownAuthority(String),
    InvalidAuthorityKey,
    InvalidSignatureLength,
    InvalidSignature,
    LeaseExpired,
    InvalidVersion,
    StaleAuthorityTerm,
    RevisionRollback,
    VersionEquivocation,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid directory field: {field}"),
            Self::InvalidMeshFqdn(name) => {
                write!(f, "name '{name}' is not a canonical mesh-scoped FQDN")
            }
            Self::MeshMismatch => write!(f, "directory record belongs to a different mesh"),
            Self::UnknownAuthority(key_id) => {
                write!(f, "authority key '{key_id}' is not pinned for this mesh")
            }
            Self::InvalidAuthorityKey => write!(f, "pinned authority key is invalid"),
            Self::InvalidSignatureLength => write!(f, "directory signature must be 64 bytes"),
            Self::InvalidSignature => write!(f, "directory signature verification failed"),
            Self::LeaseExpired => write!(f, "directory record lease has expired"),
            Self::InvalidVersion => write!(f, "authority term and revision must be nonzero"),
            Self::StaleAuthorityTerm => write!(f, "directory update has a stale authority term"),
            Self::RevisionRollback => {
                write!(f, "directory update rolls back the committed revision")
            }
            Self::VersionEquivocation => {
                write!(
                    f,
                    "directory version was previously observed with different content"
                )
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    Active,
    Revoked,
    Tombstone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub schema: String,
    pub mesh_id: String,
    pub mesh_name: String,
    pub fqdn: String,
    pub node_id: String,
    pub identity_key_id: String,
    pub overlay_addresses: Vec<IpAddr>,
    pub owner_id: String,
    pub state: RecordState,
    pub revision: u64,
    pub lease_expires_at: u64,
    pub authority_term: u64,
    pub authority_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub schema: String,
    pub mesh_id: String,
    pub mesh_name: String,
    pub service_fqdn: String,
    pub target_node_id: String,
    pub service_protocol: ServiceProtocol,
    pub service_port: u16,
    pub owner_id: String,
    pub state: RecordState,
    pub revision: u64,
    pub lease_expires_at: u64,
    pub authority_term: u64,
    pub authority_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectorySnapshot {
    pub schema: String,
    pub mesh_id: String,
    pub mesh_name: String,
    pub authority_term: u64,
    pub revision: u64,
    pub valid_until: u64,
    pub authority_key_id: String,
    pub nodes: Vec<NodeRecord>,
    pub services: Vec<ServiceRecord>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuthorityTrust {
    mesh_id: String,
    pinned_keys: HashMap<String, [u8; 32]>,
}

impl AuthorityTrust {
    pub fn new(
        mesh_id: impl Into<String>,
        pinned_keys: HashMap<String, [u8; 32]>,
    ) -> Result<Self, DirectoryError> {
        let mesh_id = mesh_id.into();
        validate_identifier(&mesh_id, "mesh ID")?;
        if pinned_keys.is_empty() {
            return Err(DirectoryError::InvalidField("pinned authority keys"));
        }
        for (key_id, key_bytes) in &pinned_keys {
            validate_identifier(key_id, "authority key ID")?;
            VerifyingKey::from_bytes(key_bytes).map_err(|_| DirectoryError::InvalidAuthorityKey)?;
        }
        Ok(Self {
            mesh_id,
            pinned_keys,
        })
    }

    pub fn mesh_id(&self) -> &str {
        &self.mesh_id
    }

    pub fn verify_node_record(
        &self,
        record: &NodeRecord,
        now_epoch: u64,
    ) -> Result<(), DirectoryError> {
        validate_node_record(record)?;
        self.verify_common(
            &record.mesh_id,
            &record.authority_key_id,
            record.authority_term,
            record.revision,
            record.lease_expires_at,
            now_epoch,
            &record.signature,
            &record.signing_bytes()?,
        )
    }

    pub fn verify_service_record(
        &self,
        record: &ServiceRecord,
        now_epoch: u64,
    ) -> Result<(), DirectoryError> {
        validate_service_record(record)?;
        self.verify_common(
            &record.mesh_id,
            &record.authority_key_id,
            record.authority_term,
            record.revision,
            record.lease_expires_at,
            now_epoch,
            &record.signature,
            &record.signing_bytes()?,
        )
    }

    pub fn verify_snapshot(
        &self,
        snapshot: &DirectorySnapshot,
        now_epoch: u64,
    ) -> Result<(), DirectoryError> {
        // CVE-Threat: Snapshot substitution or signature forgery.
        // Analysis: A snapshot may replace an entire mesh directory, so an unpinned signer is untrusted.
        // Hardening: Bind its mesh to local trust and verify a domain-separated Ed25519 signature.
        validate_snapshot(snapshot, now_epoch)?;
        if snapshot.mesh_id != self.mesh_id {
            return Err(DirectoryError::MeshMismatch);
        }
        let key_bytes = self
            .pinned_keys
            .get(&snapshot.authority_key_id)
            .ok_or_else(|| DirectoryError::UnknownAuthority(snapshot.authority_key_id.clone()))?;
        let key =
            VerifyingKey::from_bytes(key_bytes).map_err(|_| DirectoryError::InvalidAuthorityKey)?;
        let signature_array: [u8; 64] = snapshot
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| DirectoryError::InvalidSignatureLength)?;
        key.verify(
            &snapshot.signing_bytes()?,
            &Signature::from_bytes(&signature_array),
        )
        .map_err(|_| DirectoryError::InvalidSignature)
    }

    // CVE-Threat: Authority-key substitution or record forgery.
    // Analysis: Mesh identity is checked against enrollment state; authority keys are selected from local pins.
    // Hardening: Verify Ed25519 over deterministic record bytes before accepting the signed lease.
    #[allow(clippy::too_many_arguments)]
    fn verify_common(
        &self,
        mesh_id: &str,
        authority_key_id: &str,
        authority_term: u64,
        revision: u64,
        lease_expires_at: u64,
        now_epoch: u64,
        signature_bytes: &[u8],
        message: &[u8],
    ) -> Result<(), DirectoryError> {
        if mesh_id != self.mesh_id {
            return Err(DirectoryError::MeshMismatch);
        }
        if authority_term == 0 || revision == 0 {
            return Err(DirectoryError::InvalidVersion);
        }
        if now_epoch >= lease_expires_at {
            return Err(DirectoryError::LeaseExpired);
        }
        let key_bytes = self
            .pinned_keys
            .get(authority_key_id)
            .ok_or_else(|| DirectoryError::UnknownAuthority(authority_key_id.to_string()))?;
        let key =
            VerifyingKey::from_bytes(key_bytes).map_err(|_| DirectoryError::InvalidAuthorityKey)?;
        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| DirectoryError::InvalidSignatureLength)?;
        key.verify(message, &Signature::from_bytes(&signature_array))
            .map_err(|_| DirectoryError::InvalidSignature)
    }
}

impl NodeRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        mesh_id: &str,
        mesh_name: &str,
        fqdn: &str,
        node_id: &str,
        identity_key_id: &str,
        overlay_addresses: Vec<IpAddr>,
        owner_id: &str,
        state: RecordState,
        revision: u64,
        lease_expires_at: u64,
        authority_term: u64,
        authority_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<Self, DirectoryError> {
        let mut record = Self {
            schema: DIRECTORY_SCHEMA_V1.to_string(),
            mesh_id: mesh_id.to_string(),
            mesh_name: mesh_name.to_string(),
            fqdn: fqdn.to_string(),
            node_id: node_id.to_string(),
            identity_key_id: identity_key_id.to_string(),
            overlay_addresses,
            owner_id: owner_id.to_string(),
            state,
            revision,
            lease_expires_at,
            authority_term,
            authority_key_id: authority_key_id.to_string(),
            signature: Vec::new(),
        };
        validate_node_record(&record)?;
        record.signature = signing_key
            .sign(&record.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(record)
    }

    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>, DirectoryError> {
        let mut out = Vec::new();
        out.extend_from_slice(NODE_RECORD_DOMAIN);
        push_string(&mut out, &self.schema)?;
        push_string(&mut out, &self.mesh_id)?;
        push_string(&mut out, &self.mesh_name)?;
        push_string(&mut out, &self.fqdn)?;
        push_string(&mut out, &self.node_id)?;
        push_string(&mut out, &self.identity_key_id)?;
        let mut addresses = self.overlay_addresses.clone();
        addresses.sort();
        push_u32(&mut out, addresses.len())?;
        for address in addresses {
            match address {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
        }
        push_string(&mut out, &self.owner_id)?;
        out.push(state_tag(self.state));
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.lease_expires_at.to_be_bytes());
        out.extend_from_slice(&self.authority_term.to_be_bytes());
        push_string(&mut out, &self.authority_key_id)?;
        Ok(out)
    }
}

impl ServiceRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        mesh_id: &str,
        mesh_name: &str,
        service_fqdn: &str,
        target_node_id: &str,
        service_protocol: ServiceProtocol,
        service_port: u16,
        owner_id: &str,
        state: RecordState,
        revision: u64,
        lease_expires_at: u64,
        authority_term: u64,
        authority_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<Self, DirectoryError> {
        let mut record = Self {
            schema: DIRECTORY_SCHEMA_V1.to_string(),
            mesh_id: mesh_id.to_string(),
            mesh_name: mesh_name.to_string(),
            service_fqdn: service_fqdn.to_string(),
            target_node_id: target_node_id.to_string(),
            service_protocol,
            service_port,
            owner_id: owner_id.to_string(),
            state,
            revision,
            lease_expires_at,
            authority_term,
            authority_key_id: authority_key_id.to_string(),
            signature: Vec::new(),
        };
        validate_service_record(&record)?;
        record.signature = signing_key
            .sign(&record.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(record)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, DirectoryError> {
        let mut out = Vec::new();
        out.extend_from_slice(SERVICE_RECORD_DOMAIN);
        push_string(&mut out, &self.schema)?;
        push_string(&mut out, &self.mesh_id)?;
        push_string(&mut out, &self.mesh_name)?;
        push_string(&mut out, &self.service_fqdn)?;
        push_string(&mut out, &self.target_node_id)?;
        out.push(match self.service_protocol {
            ServiceProtocol::Tcp => 6,
            ServiceProtocol::Udp => 17,
        });
        out.extend_from_slice(&self.service_port.to_be_bytes());
        push_string(&mut out, &self.owner_id)?;
        out.push(state_tag(self.state));
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.lease_expires_at.to_be_bytes());
        out.extend_from_slice(&self.authority_term.to_be_bytes());
        push_string(&mut out, &self.authority_key_id)?;
        Ok(out)
    }
}

impl DirectorySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        mesh_id: &str,
        mesh_name: &str,
        authority_term: u64,
        revision: u64,
        valid_until: u64,
        authority_key_id: &str,
        mut nodes: Vec<NodeRecord>,
        mut services: Vec<ServiceRecord>,
        signing_key: &SigningKey,
    ) -> Result<Self, DirectoryError> {
        nodes.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
        services.sort_by(|left, right| {
            left.service_fqdn
                .cmp(&right.service_fqdn)
                .then_with(|| left.service_protocol.cmp(&right.service_protocol))
        });
        let mut snapshot = Self {
            schema: DIRECTORY_SNAPSHOT_SCHEMA_V1.to_string(),
            mesh_id: mesh_id.to_string(),
            mesh_name: mesh_name.to_string(),
            authority_term,
            revision,
            valid_until,
            authority_key_id: authority_key_id.to_string(),
            nodes,
            services,
            signature: vec![0; 64],
        };
        validate_snapshot(&snapshot, 0)?;
        snapshot.signature = signing_key
            .sign(&snapshot.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(snapshot)
    }

    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>, DirectoryError> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_DOMAIN);
        push_string(&mut out, &self.schema)?;
        push_string(&mut out, &self.mesh_id)?;
        push_string(&mut out, &self.mesh_name)?;
        out.extend_from_slice(&self.authority_term.to_be_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.valid_until.to_be_bytes());
        push_string(&mut out, &self.authority_key_id)?;

        let mut nodes = self.nodes.clone();
        nodes.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
        let node_bytes = serde_json::to_vec(&nodes)
            .map_err(|_| DirectoryError::InvalidField("snapshot nodes"))?;
        push_bytes(&mut out, &node_bytes)?;

        let mut services = self.services.clone();
        services.sort_by(|left, right| {
            left.service_fqdn
                .cmp(&right.service_fqdn)
                .then_with(|| left.service_protocol.cmp(&right.service_protocol))
        });
        let service_bytes = serde_json::to_vec(&services)
            .map_err(|_| DirectoryError::InvalidField("snapshot services"))?;
        push_bytes(&mut out, &service_bytes)?;
        Ok(out)
    }
}

fn validate_snapshot(snapshot: &DirectorySnapshot, now_epoch: u64) -> Result<(), DirectoryError> {
    if snapshot.schema != DIRECTORY_SNAPSHOT_SCHEMA_V1 {
        return Err(DirectoryError::InvalidField("snapshot schema"));
    }
    validate_identifier(&snapshot.mesh_id, "mesh ID")?;
    validate_mesh_name(&snapshot.mesh_name)?;
    validate_identifier(&snapshot.authority_key_id, "authority key ID")?;
    if snapshot.authority_term == 0 || snapshot.revision == 0 {
        return Err(DirectoryError::InvalidVersion);
    }
    if now_epoch >= snapshot.valid_until {
        return Err(DirectoryError::LeaseExpired);
    }
    if snapshot.nodes.len().saturating_add(snapshot.services.len()) > MAX_SNAPSHOT_RECORDS {
        return Err(DirectoryError::InvalidField("snapshot record count"));
    }
    if snapshot.signature.len() != 64 {
        return Err(DirectoryError::InvalidSignatureLength);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RevisionCursor {
    term: u64,
    revision: u64,
    digest: Option<[u8; 32]>,
}

impl RevisionCursor {
    pub fn current(&self) -> (u64, u64) {
        (self.term, self.revision)
    }

    /// Call only after authenticating the update's signature and mesh binding.
    /// Reapplying an identical version is idempotent; rollback and equivocation are rejected.
    pub fn observe(
        &mut self,
        term: u64,
        revision: u64,
        digest: [u8; 32],
    ) -> Result<(), DirectoryError> {
        if term == 0 || revision == 0 {
            return Err(DirectoryError::InvalidVersion);
        }
        if term < self.term {
            return Err(DirectoryError::StaleAuthorityTerm);
        }
        if revision < self.revision {
            return Err(DirectoryError::RevisionRollback);
        }
        if term == self.term
            && revision == self.revision
            && self.digest.is_some_and(|observed| observed != digest)
        {
            return Err(DirectoryError::VersionEquivocation);
        }
        self.term = term;
        self.revision = revision;
        self.digest = Some(digest);
        Ok(())
    }
}

pub fn validate_mesh_name(mesh_name: &str) -> Result<(), DirectoryError> {
    if !is_dns_label(mesh_name) {
        return Err(DirectoryError::InvalidField("mesh name"));
    }
    Ok(())
}

pub fn validate_mesh_fqdn(fqdn: &str, mesh_name: &str) -> Result<(), DirectoryError> {
    validate_mesh_name(mesh_name)?;
    let expected_suffix = format!(".{mesh_name}.sbm");
    let Some(host_label) = fqdn.strip_suffix(&expected_suffix) else {
        return Err(DirectoryError::InvalidMeshFqdn(fqdn.to_string()));
    };
    if !is_dns_label(host_label) {
        return Err(DirectoryError::InvalidMeshFqdn(fqdn.to_string()));
    }
    Ok(())
}

fn validate_node_record(record: &NodeRecord) -> Result<(), DirectoryError> {
    if record.schema != DIRECTORY_SCHEMA_V1 {
        return Err(DirectoryError::InvalidField("schema"));
    }
    validate_identifier(&record.mesh_id, "mesh ID")?;
    validate_mesh_name(&record.mesh_name)?;
    validate_mesh_fqdn(&record.fqdn, &record.mesh_name)?;
    validate_identifier(&record.node_id, "node ID")?;
    validate_identifier(&record.identity_key_id, "identity key ID")?;
    validate_identifier(&record.owner_id, "owner ID")?;
    validate_identifier(&record.authority_key_id, "authority key ID")?;
    if record.overlay_addresses.is_empty() || record.overlay_addresses.len() > MAX_OVERLAY_ADDRESSES
    {
        return Err(DirectoryError::InvalidField("overlay addresses"));
    }
    let unique: HashSet<_> = record.overlay_addresses.iter().collect();
    if unique.len() != record.overlay_addresses.len() {
        return Err(DirectoryError::InvalidField("duplicate overlay address"));
    }
    if record.revision == 0 || record.authority_term == 0 {
        return Err(DirectoryError::InvalidVersion);
    }
    Ok(())
}

fn validate_service_record(record: &ServiceRecord) -> Result<(), DirectoryError> {
    if record.schema != DIRECTORY_SCHEMA_V1 {
        return Err(DirectoryError::InvalidField("schema"));
    }
    validate_identifier(&record.mesh_id, "mesh ID")?;
    validate_mesh_name(&record.mesh_name)?;
    validate_mesh_fqdn(&record.service_fqdn, &record.mesh_name)?;
    validate_identifier(&record.target_node_id, "target node ID")?;
    validate_identifier(&record.owner_id, "owner ID")?;
    validate_identifier(&record.authority_key_id, "authority key ID")?;
    if record.service_port == 0 {
        return Err(DirectoryError::InvalidField("service port"));
    }
    if record.revision == 0 || record.authority_term == 0 {
        return Err(DirectoryError::InvalidVersion);
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), DirectoryError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LENGTH
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(DirectoryError::InvalidField(field));
    }
    Ok(())
}

fn is_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && label.as_bytes()[0].is_ascii_alphanumeric()
        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
}

fn state_tag(state: RecordState) -> u8 {
    match state {
        RecordState::Active => 1,
        RecordState::Revoked => 2,
        RecordState::Tombstone => 3,
    }
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), DirectoryError> {
    push_u32(out, value.len())?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), DirectoryError> {
    push_u32(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: usize) -> Result<(), DirectoryError> {
    let value = u32::try_from(value).map_err(|_| DirectoryError::InvalidField("encoded length"))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MESH_ID: &str = "mesh-7f2a";
    const MESH_NAME: &str = "dev";
    const AUTHORITY_KEY_ID: &str = "authority-1";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn trust_for(key: &SigningKey) -> AuthorityTrust {
        AuthorityTrust::new(
            MESH_ID,
            HashMap::from([(AUTHORITY_KEY_ID.to_string(), key.verifying_key().to_bytes())]),
        )
        .unwrap()
    }

    fn signed_node(key: &SigningKey) -> NodeRecord {
        NodeRecord::sign(
            MESH_ID,
            MESH_NAME,
            "anchor-01.dev.sbm",
            "node-01",
            "identity-key-01",
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            "admin-01",
            RecordState::Active,
            12,
            2_000,
            3,
            AUTHORITY_KEY_ID,
            key,
        )
        .unwrap()
    }

    #[test]
    fn accepts_mesh_scoped_names_and_rejects_ambiguous_or_noncanonical_names() {
        assert!(validate_mesh_fqdn("api.dev.sbm", "dev").is_ok());
        assert!(validate_mesh_fqdn("api.prod.sbm", "prod").is_ok());
        assert!(validate_mesh_fqdn("api.sbm", "dev").is_err());
        assert!(validate_mesh_fqdn("API.dev.sbm", "dev").is_err());
        assert!(validate_mesh_fqdn("api.other.sbm", "dev").is_err());
        assert!(validate_mesh_fqdn("api..dev.sbm", "dev").is_err());
        assert!(validate_mesh_fqdn("api-.dev.sbm", "dev").is_err());
    }

    #[test]
    fn verifies_node_record_only_with_pinned_authority_key() {
        let key = signing_key();
        let record = signed_node(&key);
        let trust = trust_for(&key);
        assert!(trust.verify_node_record(&record, 1_999).is_ok());

        let untrusted = SigningKey::from_bytes(&[8; 32]);
        assert!(matches!(
            trust_for(&untrusted).verify_node_record(&record, 1_999),
            Err(DirectoryError::InvalidSignature)
        ));

        let unknown_key_id = NodeRecord {
            authority_key_id: "untrusted-authority".to_string(),
            ..record.clone()
        };
        assert!(matches!(
            trust.verify_node_record(&unknown_key_id, 1_999),
            Err(DirectoryError::UnknownAuthority(_))
        ));
    }

    #[test]
    fn rejects_tampering_mesh_mismatch_and_expired_lease() {
        let key = signing_key();
        let trust = trust_for(&key);
        let record = signed_node(&key);

        let mut tampered = record.clone();
        tampered.owner_id = "attacker".to_string();
        assert!(matches!(
            trust.verify_node_record(&tampered, 1_999),
            Err(DirectoryError::InvalidSignature)
        ));

        let mut renamed_mesh = record.clone();
        renamed_mesh.mesh_name = "prod".to_string();
        renamed_mesh.fqdn = "anchor-01.prod.sbm".to_string();
        assert!(matches!(
            trust.verify_node_record(&renamed_mesh, 1_999),
            Err(DirectoryError::InvalidSignature)
        ));

        let mut wrong_mesh = record.clone();
        wrong_mesh.mesh_id = "mesh-prod".to_string();
        assert!(matches!(
            trust.verify_node_record(&wrong_mesh, 1_999),
            Err(DirectoryError::MeshMismatch)
        ));

        assert_eq!(
            trust.verify_node_record(&record, 2_000),
            Err(DirectoryError::LeaseExpired)
        );
    }

    #[test]
    fn verifies_service_records_and_binds_protocol_and_port() {
        let key = signing_key();
        let trust = trust_for(&key);
        let record = ServiceRecord::sign(
            MESH_ID,
            MESH_NAME,
            "api.dev.sbm",
            "node-01",
            ServiceProtocol::Tcp,
            8443,
            "service-owner",
            RecordState::Active,
            15,
            2_000,
            3,
            AUTHORITY_KEY_ID,
            &key,
        )
        .unwrap();

        assert!(trust.verify_service_record(&record, 1_999).is_ok());
        let mut modified = record;
        modified.service_port = 22;
        assert!(matches!(
            trust.verify_service_record(&modified, 1_999),
            Err(DirectoryError::InvalidSignature)
        ));
    }

    #[test]
    fn validates_schema_versions_and_record_inputs_before_signing() {
        let key = signing_key();
        assert!(NodeRecord::sign(
            MESH_ID,
            MESH_NAME,
            "api.prod.sbm",
            "node-01",
            "identity-key-01",
            vec![IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1))],
            "admin-01",
            RecordState::Active,
            1,
            2_000,
            1,
            AUTHORITY_KEY_ID,
            &key,
        )
        .is_err());

        let trust = trust_for(&key);
        let mut unsupported = signed_node(&key);
        unsupported.schema = "sbm-directory/v2".to_string();
        assert!(matches!(
            trust.verify_node_record(&unsupported, 1_999),
            Err(DirectoryError::InvalidField("schema"))
        ));

        assert!(NodeRecord::sign(
            MESH_ID,
            MESH_NAME,
            "node.dev.sbm",
            "node-01",
            "identity-key-01",
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            ],
            "admin-01",
            RecordState::Active,
            1,
            2_000,
            1,
            AUTHORITY_KEY_ID,
            &key,
        )
        .is_err());
    }

    #[test]
    fn rejects_revision_and_authority_term_rollback() {
        let mut cursor = RevisionCursor::default();
        cursor.observe(1, 8, [1; 32]).unwrap();
        cursor.observe(1, 8, [1; 32]).unwrap();
        cursor.observe(2, 9, [2; 32]).unwrap();

        assert_eq!(
            cursor.observe(1, 10, [3; 32]),
            Err(DirectoryError::StaleAuthorityTerm)
        );
        assert_eq!(
            cursor.observe(2, 8, [3; 32]),
            Err(DirectoryError::RevisionRollback)
        );
        assert_eq!(
            cursor.observe(2, 9, [4; 32]),
            Err(DirectoryError::VersionEquivocation)
        );
        assert_eq!(cursor.current(), (2, 9));
    }

    #[test]
    fn rejects_malformed_signature_length_and_service_port_zero() {
        let key = signing_key();
        let trust = trust_for(&key);
        let mut malformed_signature = signed_node(&key);
        malformed_signature.signature.truncate(8);
        assert_eq!(
            trust.verify_node_record(&malformed_signature, 1_999),
            Err(DirectoryError::InvalidSignatureLength)
        );

        assert!(ServiceRecord::sign(
            MESH_ID,
            MESH_NAME,
            "api.dev.sbm",
            "node-01",
            ServiceProtocol::Udp,
            0,
            "service-owner",
            RecordState::Active,
            1,
            2_000,
            1,
            AUTHORITY_KEY_ID,
            &key,
        )
        .is_err());
    }
}
