use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

pub mod install;

pub const MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_DECLARED_SERVICES: usize = 256;
const MAX_REQUESTED_CAPABILITIES: usize = 1024;
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"SB-MAP-MANIFEST-V1\0";
const OPERATION_GRANT_DOMAIN: &[u8] = b"SB-MAP-OPERATION-GRANT-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    InvalidManifest(String),
    UnsupportedSchema(u16),
    ManifestTooLarge,
    UnknownPublisher(String),
    InvalidSignature,
    InvalidGrant(String),
    GrantDenied(&'static str),
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(message) | Self::InvalidGrant(message) => {
                formatter.write_str(message)
            }
            Self::UnsupportedSchema(version) => {
                write!(formatter, "Unsupported SB-MAP manifest schema {version}")
            }
            Self::ManifestTooLarge => formatter.write_str("SB-MAP manifest exceeds 1 MiB"),
            Self::UnknownPublisher(key_id) => {
                write!(formatter, "Publisher key '{key_id}' is not trusted")
            }
            Self::InvalidSignature => formatter.write_str("SB-MAP signature verification failed"),
            Self::GrantDenied(reason) => write!(formatter, "Service operation denied: {reason}"),
        }
    }
}

impl std::error::Error for ContractError {}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppManifest {
    pub schema_version: u16,
    pub app_id: String,
    pub version: String,
    pub publisher_key_id: String,
    pub client: ClientArtifact,
    pub services: Vec<ServiceDeclaration>,
    pub requested_capabilities: Vec<CapabilityRequest>,
    pub sandbox_profile: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientArtifact {
    pub target: String,
    pub artifact: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceDeclaration {
    pub service_id: String,
    pub api_version: u16,
    pub contract_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    pub service_id: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    manifest: AppManifest,
    publisher_key_id: String,
    manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuer {
    pub mesh_id: String,
    pub node_id: String,
    pub public_key: [u8; 32],
}

impl VerifiedManifest {
    pub fn manifest(&self) -> &AppManifest {
        &self.manifest
    }

    pub fn publisher_key_id(&self) -> &str {
        &self.publisher_key_id
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
}

pub fn verify_signed_manifest(
    manifest_bytes: &[u8],
    signature_hex: &str,
    trusted_publishers: &BTreeMap<String, [u8; 32]>,
) -> Result<VerifiedManifest, ContractError> {
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ContractError::ManifestTooLarge);
    }
    let envelope: serde_json::Value = serde_json::from_slice(manifest_bytes)
        .map_err(|error| ContractError::InvalidManifest(error.to_string()))?;
    let publisher_key_id = envelope
        .get("publisher_key_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ContractError::InvalidManifest("Missing publisher_key_id".into()))?;
    let public_key_bytes = trusted_publishers
        .get(publisher_key_id)
        .ok_or_else(|| ContractError::UnknownPublisher(publisher_key_id.to_string()))?;
    let public_key =
        VerifyingKey::from_bytes(public_key_bytes).map_err(|_| ContractError::InvalidSignature)?;
    let signature_bytes = decode_signature(signature_hex)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ContractError::InvalidSignature)?;
    let mut signed_message =
        Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + manifest_bytes.len());
    signed_message.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
    signed_message.extend_from_slice(manifest_bytes);
    public_key
        .verify_strict(&signed_message, &signature)
        .map_err(|_| ContractError::InvalidSignature)?;

    let manifest: AppManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| ContractError::InvalidManifest(error.to_string()))?;
    validate_manifest(&manifest)?;
    let digest = Sha256::digest(manifest_bytes);
    Ok(VerifiedManifest {
        publisher_key_id: manifest.publisher_key_id.clone(),
        manifest,
        manifest_digest: format!("sha256:{}", encode_lower_hex(&digest)),
    })
}

fn validate_manifest(manifest: &AppManifest) -> Result<(), ContractError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ContractError::UnsupportedSchema(manifest.schema_version));
    }
    validate_dns_id("app_id", &manifest.app_id)?;
    validate_dns_id("publisher_key_id", &manifest.publisher_key_id)?;
    let version = semver::Version::parse(&manifest.version)
        .map_err(|error| ContractError::InvalidManifest(format!("Invalid app version: {error}")))?;
    if version.to_string() != manifest.version {
        return Err(ContractError::InvalidManifest(
            "App version must use canonical semantic-version syntax".into(),
        ));
    }
    validate_token(
        "client target",
        &manifest.client.target,
        b"abcdefghijklmnopqrstuvwxyz0123456789-_",
    )?;
    validate_digest("client artifact", &manifest.client.artifact)?;
    validate_token(
        "sandbox profile",
        &manifest.sandbox_profile,
        b"abcdefghijklmnopqrstuvwxyz0123456789-",
    )?;
    if manifest.services.len() > MAX_DECLARED_SERVICES {
        return Err(ContractError::InvalidManifest(format!(
            "Manifest declares more than {MAX_DECLARED_SERVICES} services"
        )));
    }
    if manifest.requested_capabilities.len() > MAX_REQUESTED_CAPABILITIES {
        return Err(ContractError::InvalidManifest(format!(
            "Manifest requests more than {MAX_REQUESTED_CAPABILITIES} capabilities"
        )));
    }

    let mut service_ids = HashSet::new();
    for service in &manifest.services {
        validate_dns_id("service_id", &service.service_id)?;
        if service.api_version == 0 {
            return Err(ContractError::InvalidManifest(
                "Service API versions start at 1".into(),
            ));
        }
        validate_digest("service contract_digest", &service.contract_digest)?;
        if !service_ids.insert(service.service_id.as_str()) {
            return Err(ContractError::InvalidManifest(format!(
                "Duplicate service identifier '{}'",
                service.service_id
            )));
        }
    }

    let mut capabilities = HashSet::new();
    for capability in &manifest.requested_capabilities {
        validate_dns_id("capability service_id", &capability.service_id)?;
        validate_token(
            "capability operation",
            &capability.operation,
            b"abcdefghijklmnopqrstuvwxyz0123456789._-",
        )?;
        if !service_ids.contains(capability.service_id.as_str()) {
            return Err(ContractError::InvalidManifest(format!(
                "Capability references undeclared service '{}'",
                capability.service_id
            )));
        }
        if !capabilities.insert(capability) {
            return Err(ContractError::InvalidManifest(format!(
                "Duplicate capability for service '{}' and operation '{}'",
                capability.service_id, capability.operation
            )));
        }
    }
    Ok(())
}

fn validate_dns_id(field: &str, value: &str) -> Result<(), ContractError> {
    let labels: Vec<_> = value.split('.').collect();
    if value.len() > 253
        || labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
    {
        return Err(ContractError::InvalidManifest(format!(
            "{field} must be a lowercase reverse-domain identifier"
        )));
    }
    Ok(())
}

fn validate_token(field: &str, value: &str, allowed: &[u8]) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value.bytes().all(|byte| allowed.contains(&byte))
    {
        return Err(ContractError::InvalidManifest(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), ContractError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ContractError::InvalidManifest(format!(
            "{field} must use a sha256 digest"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::InvalidManifest(format!(
            "{field} must contain exactly 64 lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

fn decode_signature(signature_hex: &str) -> Result<[u8; 64], ContractError> {
    if signature_hex.len() != 128 || !signature_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ContractError::InvalidSignature);
    }
    let mut signature = [0u8; 64];
    for (index, pair) in signature_hex.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(ContractError::InvalidSignature)?;
        let low = decode_hex_nibble(pair[1]).ok_or(ContractError::InvalidSignature)?;
        signature[index] = (high << 4) | low;
    }
    Ok(signature)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationGrant {
    pub version: u16,
    pub grant_id: String,
    pub mesh_id: String,
    pub issuer_node_id: String,
    pub issuer_key_id: String,
    pub subject_node_id: String,
    pub app_id: String,
    pub client_digest: String,
    pub service_id: String,
    pub api_version: u16,
    pub operation: String,
    pub resource_id: String,
    pub policy_epoch: u64,
    pub valid_until: u64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantClaims {
    pub grant_id: String,
    pub mesh_id: String,
    pub issuer_node_id: String,
    pub issuer_key_id: String,
    pub subject_node_id: String,
    pub app_id: String,
    pub client_digest: String,
    pub service_id: String,
    pub api_version: u16,
    pub operation: String,
    pub resource_id: String,
    pub policy_epoch: u64,
    pub valid_until: u64,
}

impl OperationGrant {
    pub fn issue(claims: GrantClaims, signing_key: &SigningKey) -> Result<Self, ContractError> {
        validate_grant_claims(&claims)?;
        let mut grant = Self {
            version: 1,
            grant_id: claims.grant_id,
            mesh_id: claims.mesh_id,
            issuer_node_id: claims.issuer_node_id,
            issuer_key_id: claims.issuer_key_id,
            subject_node_id: claims.subject_node_id,
            app_id: claims.app_id,
            client_digest: claims.client_digest,
            service_id: claims.service_id,
            api_version: claims.api_version,
            operation: claims.operation,
            resource_id: claims.resource_id,
            policy_epoch: claims.policy_epoch,
            valid_until: claims.valid_until,
            signature_hex: String::new(),
        };
        grant.signature_hex =
            encode_lower_hex(&signing_key.sign(&grant.signing_bytes()).to_bytes());
        Ok(grant)
    }

    pub fn verify(
        &self,
        trusted_issuers: &BTreeMap<String, TrustedIssuer>,
        context: &InvocationContext<'_>,
    ) -> Result<(), ContractError> {
        if self.version != 1 {
            return Err(ContractError::InvalidGrant(
                "Unsupported operation grant version".into(),
            ));
        }
        validate_grant_claims(&self.claims())?;
        let trusted_issuer = trusted_issuers
            .get(&self.issuer_key_id)
            .ok_or_else(|| ContractError::UnknownPublisher(self.issuer_key_id.clone()))?;
        if trusted_issuer.mesh_id != self.mesh_id || trusted_issuer.node_id != self.issuer_node_id {
            return Err(ContractError::GrantDenied(
                "grant issuer is not trusted for this Mesh",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(&trusted_issuer.public_key)
            .map_err(|_| ContractError::InvalidSignature)?;
        let signature_bytes = decode_signature(&self.signature_hex)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ContractError::InvalidSignature)?;
        verifying_key
            .verify_strict(&self.signing_bytes(), &signature)
            .map_err(|_| ContractError::InvalidSignature)?;

        if self.valid_until <= context.now {
            return Err(ContractError::GrantDenied("grant expired"));
        }
        if self.mesh_id != context.mesh_id {
            return Err(ContractError::GrantDenied("wrong Mesh"));
        }
        if self.subject_node_id != context.subject_node_id {
            return Err(ContractError::GrantDenied("wrong subject"));
        }
        if self.app_id != context.app_id || self.client_digest != context.client_digest {
            return Err(ContractError::GrantDenied("wrong app or client artifact"));
        }
        if self.service_id != context.service_id {
            return Err(ContractError::GrantDenied("wrong service audience"));
        }
        if self.api_version != context.api_version {
            return Err(ContractError::GrantDenied("wrong API version"));
        }
        if self.operation != context.operation {
            return Err(ContractError::GrantDenied("operation not granted"));
        }
        if self.resource_id != context.resource_id {
            return Err(ContractError::GrantDenied("resource not granted"));
        }
        if self.policy_epoch != context.policy_epoch {
            return Err(ContractError::GrantDenied("stale policy epoch"));
        }
        Ok(())
    }

    pub fn authorize_operation(
        manifest: &VerifiedManifest,
        grant: &OperationGrant,
        trusted_issuers: &BTreeMap<String, TrustedIssuer>,
        context: &InvocationContext<'_>,
    ) -> Result<(), ContractError> {
        if context.app_id != manifest.manifest.app_id
            || context.client_digest != manifest.manifest.client.artifact
        {
            return Err(ContractError::GrantDenied(
                "invocation does not match the verified app artifact",
            ));
        }
        let service_is_declared = manifest.manifest.services.iter().any(|service| {
            service.service_id == context.service_id && service.api_version == context.api_version
        });
        if !service_is_declared {
            return Err(ContractError::GrantDenied(
                "service or API version is not declared by the app",
            ));
        }
        if !manifest
            .manifest
            .requested_capabilities
            .iter()
            .any(|capability| {
                capability.service_id == context.service_id
                    && capability.operation == context.operation
            })
        {
            return Err(ContractError::GrantDenied(
                "operation is not declared by the app",
            ));
        }
        grant.verify(trusted_issuers, context)
    }

    fn claims(&self) -> GrantClaims {
        GrantClaims {
            grant_id: self.grant_id.clone(),
            mesh_id: self.mesh_id.clone(),
            issuer_node_id: self.issuer_node_id.clone(),
            issuer_key_id: self.issuer_key_id.clone(),
            subject_node_id: self.subject_node_id.clone(),
            app_id: self.app_id.clone(),
            client_digest: self.client_digest.clone(),
            service_id: self.service_id.clone(),
            api_version: self.api_version,
            operation: self.operation.clone(),
            resource_id: self.resource_id.clone(),
            policy_epoch: self.policy_epoch,
            valid_until: self.valid_until,
        }
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let fields = [
            self.grant_id.as_str(),
            self.mesh_id.as_str(),
            self.issuer_node_id.as_str(),
            self.issuer_key_id.as_str(),
            self.subject_node_id.as_str(),
            self.app_id.as_str(),
            self.client_digest.as_str(),
            self.service_id.as_str(),
            self.operation.as_str(),
            self.resource_id.as_str(),
        ];
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(OPERATION_GRANT_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.api_version.to_be_bytes());
        bytes.extend_from_slice(&self.policy_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until.to_be_bytes());
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvocationContext<'a> {
    pub mesh_id: &'a str,
    pub subject_node_id: &'a str,
    pub app_id: &'a str,
    pub client_digest: &'a str,
    pub service_id: &'a str,
    pub api_version: u16,
    pub operation: &'a str,
    pub resource_id: &'a str,
    pub policy_epoch: u64,
    pub now: u64,
}

const MAX_TRACKED_GRANTS: usize = 4096;

/// Provider-side enforcement point: verifies a grant and additionally enforces the
/// provider's current policy epoch, revocations and single-use consumption.
// CVE-Threat: Grant replay, use after revocation, and unbounded replay-tracking memory.
// Analysis: A signature alone proves issuance, not freshness; a captured grant could be reused.
// Hardening: Epoch is taken from the provider, never from the caller; revoked IDs are rejected;
// each grant ID is consumed once until expiry; a full tracker fails closed instead of evicting.
#[derive(Debug)]
pub struct GrantGate {
    trusted_issuers: BTreeMap<String, TrustedIssuer>,
    policy_epoch: u64,
    revoked: HashSet<String>,
    consumed: BTreeMap<String, u64>,
}

impl GrantGate {
    pub fn new(trusted_issuers: BTreeMap<String, TrustedIssuer>, policy_epoch: u64) -> Self {
        Self {
            trusted_issuers,
            policy_epoch,
            revoked: HashSet::new(),
            consumed: BTreeMap::new(),
        }
    }

    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    pub fn revoke(&mut self, grant_id: &str) -> Result<(), ContractError> {
        if self.revoked.len() >= MAX_TRACKED_GRANTS {
            return Err(ContractError::GrantDenied("revocation list is full"));
        }
        self.revoked.insert(grant_id.to_string());
        Ok(())
    }

    /// Advancing the epoch invalidates every grant issued for an earlier epoch.
    pub fn advance_epoch(&mut self, epoch: u64) -> Result<(), ContractError> {
        if epoch <= self.policy_epoch {
            return Err(ContractError::GrantDenied("policy epoch must increase"));
        }
        self.policy_epoch = epoch;
        self.consumed.clear();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_once(
        &mut self,
        manifest: &VerifiedManifest,
        grant: &OperationGrant,
        mesh_id: &str,
        subject_node_id: &str,
        service_id: &str,
        api_version: u16,
        operation: &str,
        resource_id: &str,
        now: u64,
    ) -> Result<(), ContractError> {
        if self.revoked.contains(&grant.grant_id) {
            return Err(ContractError::GrantDenied("grant revoked"));
        }
        let context = InvocationContext {
            mesh_id,
            subject_node_id,
            app_id: &manifest.manifest.app_id,
            client_digest: &manifest.manifest.client.artifact,
            service_id,
            api_version,
            operation,
            resource_id,
            policy_epoch: self.policy_epoch,
            now,
        };
        OperationGrant::authorize_operation(manifest, grant, &self.trusted_issuers, &context)?;
        self.consumed.retain(|_, valid_until| *valid_until > now);
        if self.consumed.contains_key(&grant.grant_id) {
            return Err(ContractError::GrantDenied("grant already used"));
        }
        if self.consumed.len() >= MAX_TRACKED_GRANTS {
            return Err(ContractError::GrantDenied("replay tracker is full"));
        }
        self.consumed
            .insert(grant.grant_id.clone(), grant.valid_until);
        Ok(())
    }
}

fn validate_grant_claims(claims: &GrantClaims) -> Result<(), ContractError> {
    for (field, value) in [
        ("grant_id", claims.grant_id.as_str()),
        ("mesh_id", claims.mesh_id.as_str()),
        ("issuer_node_id", claims.issuer_node_id.as_str()),
        ("subject_node_id", claims.subject_node_id.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 256 {
            return Err(ContractError::InvalidGrant(format!(
                "{field} must contain 1-256 non-whitespace bytes"
            )));
        }
        validate_token(
            field,
            value,
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-",
        )
        .map_err(|error| ContractError::InvalidGrant(error.to_string()))?;
    }
    validate_dns_id("grant issuer_key_id", &claims.issuer_key_id)
        .map_err(|error| ContractError::InvalidGrant(error.to_string()))?;
    validate_dns_id("grant app_id", &claims.app_id)
        .map_err(|error| ContractError::InvalidGrant(error.to_string()))?;
    validate_dns_id("grant service_id", &claims.service_id)
        .map_err(|error| ContractError::InvalidGrant(error.to_string()))?;
    validate_digest("grant client_digest", &claims.client_digest)
        .map_err(|error| ContractError::InvalidGrant(error.to_string()))?;
    validate_token(
        "grant operation",
        &claims.operation,
        b"abcdefghijklmnopqrstuvwxyz0123456789._-",
    )
    .map_err(|error| ContractError::InvalidGrant(error.to_string()))?;
    validate_token(
        "grant resource_id",
        &claims.resource_id,
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-",
    )
    .map_err(|error| ContractError::InvalidGrant(error.to_string()))?;
    if claims.api_version == 0 || claims.valid_until == 0 {
        return Err(ContractError::InvalidGrant(
            "API version and expiry must be nonzero".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn manifest() -> AppManifest {
        AppManifest {
            schema_version: 1,
            app_id: "org.skullsandbones.notes".into(),
            version: "0.1.0".into(),
            publisher_key_id: "org.skullsandbones.publisher".into(),
            client: ClientArtifact {
                target: "windows-x86_64".into(),
                artifact: format!("sha256:{}", "a".repeat(64)),
            },
            services: vec![ServiceDeclaration {
                service_id: "org.skullsandbones.notes.api".into(),
                api_version: 1,
                contract_digest: format!("sha256:{}", "b".repeat(64)),
            }],
            requested_capabilities: vec![CapabilityRequest {
                service_id: "org.skullsandbones.notes.api".into(),
                operation: "notes.read".into(),
            }],
            sandbox_profile: "native-client-default".into(),
        }
    }

    fn signed_manifest(
        manifest: &AppManifest,
        key: &SigningKey,
    ) -> (Vec<u8>, String, BTreeMap<String, [u8; 32]>) {
        let bytes = serde_json::to_vec(manifest).unwrap();
        let mut message = MANIFEST_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&bytes);
        let signature = encode_lower_hex(&key.sign(&message).to_bytes());
        let trusted = BTreeMap::from([(
            manifest.publisher_key_id.clone(),
            key.verifying_key().to_bytes(),
        )]);
        (bytes, signature, trusted)
    }

    fn grant_claims() -> GrantClaims {
        GrantClaims {
            grant_id: "grant-01".into(),
            mesh_id: "mesh-public".into(),
            issuer_node_id: "node-issuer".into(),
            issuer_key_id: "org.skullsandbones.mesh-authority".into(),
            subject_node_id: "node-client".into(),
            app_id: "org.skullsandbones.notes".into(),
            client_digest: format!("sha256:{}", "a".repeat(64)),
            service_id: "org.skullsandbones.notes.api".into(),
            api_version: 1,
            operation: "notes.read".into(),
            resource_id: "notes.collection-1".into(),
            policy_epoch: 9,
            valid_until: 500,
        }
    }

    fn grant_context<'a>() -> InvocationContext<'a> {
        InvocationContext {
            mesh_id: "mesh-public",
            subject_node_id: "node-client",
            app_id: "org.skullsandbones.notes",
            client_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            service_id: "org.skullsandbones.notes.api",
            api_version: 1,
            operation: "notes.read",
            resource_id: "notes.collection-1",
            policy_epoch: 9,
            now: 100,
        }
    }

    #[test]
    fn grant_gate_enforces_replay_revocation_and_epoch() {
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let (bytes, signature, publishers) = signed_manifest(&manifest(), &publisher);
        let verified = verify_signed_manifest(&bytes, &signature, &publishers).unwrap();
        let issuer = SigningKey::from_bytes(&[11u8; 32]);
        let trusted = BTreeMap::from([(
            "org.skullsandbones.mesh-authority".into(),
            TrustedIssuer {
                mesh_id: "mesh-public".into(),
                node_id: "node-issuer".into(),
                public_key: issuer.verifying_key().to_bytes(),
            },
        )]);
        let grant = OperationGrant::issue(grant_claims(), &issuer).unwrap();
        let call = |gate: &mut GrantGate, grant: &OperationGrant| {
            gate.authorize_once(
                &verified,
                grant,
                "mesh-public",
                "node-client",
                "org.skullsandbones.notes.api",
                1,
                "notes.read",
                "notes.collection-1",
                100,
            )
        };

        let mut gate = GrantGate::new(trusted.clone(), 9);
        assert!(call(&mut gate, &grant).is_ok());
        assert_eq!(
            call(&mut gate, &grant),
            Err(ContractError::GrantDenied("grant already used"))
        );

        let mut gate = GrantGate::new(trusted.clone(), 9);
        gate.revoke("grant-01").unwrap();
        assert_eq!(
            call(&mut gate, &grant),
            Err(ContractError::GrantDenied("grant revoked"))
        );

        let mut gate = GrantGate::new(trusted.clone(), 9);
        gate.advance_epoch(10).unwrap();
        assert_eq!(
            call(&mut gate, &grant),
            Err(ContractError::GrantDenied("stale policy epoch"))
        );
        assert!(gate.advance_epoch(10).is_err());

        let mut gate = GrantGate::new(trusted, 9);
        let mut other = grant_claims();
        other.grant_id = "grant-02".into();
        other.operation = "notes.write".into();
        let other = OperationGrant::issue(other, &issuer).unwrap();
        assert!(call(&mut gate, &other).is_err());
    }

    #[test]
    fn signed_manifest_is_verified_against_explicit_publisher_trust() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (bytes, signature, trusted) = signed_manifest(&manifest(), &key);
        let verified = verify_signed_manifest(&bytes, &signature, &trusted).unwrap();
        assert_eq!(verified.manifest().app_id, "org.skullsandbones.notes");
        assert_eq!(verified.publisher_key_id(), "org.skullsandbones.publisher");
        assert!(verified.manifest_digest().starts_with("sha256:"));
    }

    #[test]
    fn manifest_signature_covers_exact_bytes_and_trusted_key() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (bytes, signature, trusted) = signed_manifest(&manifest(), &key);
        let mut changed = bytes.clone();
        changed.push(b' ');
        assert_eq!(
            verify_signed_manifest(&changed, &signature, &trusted),
            Err(ContractError::InvalidSignature)
        );

        let unknown = BTreeMap::new();
        assert!(matches!(
            verify_signed_manifest(&bytes, &signature, &unknown),
            Err(ContractError::UnknownPublisher(_))
        ));
    }

    #[test]
    fn manifest_rejects_undeclared_capabilities_and_ambiguous_services() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut invalid = manifest();
        invalid.requested_capabilities[0].service_id = "org.skullsandbones.other.api".into();
        let (bytes, signature, trusted) = signed_manifest(&invalid, &key);
        assert!(matches!(
            verify_signed_manifest(&bytes, &signature, &trusted),
            Err(ContractError::InvalidManifest(_))
        ));

        let mut duplicate = manifest();
        duplicate.services.push(duplicate.services[0].clone());
        let (bytes, signature, trusted) = signed_manifest(&duplicate, &key);
        assert!(matches!(
            verify_signed_manifest(&bytes, &signature, &trusted),
            Err(ContractError::InvalidManifest(_))
        ));
    }

    #[test]
    fn manifest_rejects_unknown_fields_bad_digests_and_unsupported_schema() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut value = serde_json::to_value(manifest()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut signed = MANIFEST_SIGNATURE_DOMAIN.to_vec();
        signed.extend_from_slice(&bytes);
        let signature = encode_lower_hex(&key.sign(&signed).to_bytes());
        let trusted = BTreeMap::from([(
            "org.skullsandbones.publisher".into(),
            key.verifying_key().to_bytes(),
        )]);
        assert!(matches!(
            verify_signed_manifest(&bytes, &signature, &trusted),
            Err(ContractError::InvalidManifest(_))
        ));

        let mut invalid = manifest();
        invalid.client.artifact = "sha256:ABC".into();
        let (bytes, signature, trusted) = signed_manifest(&invalid, &key);
        assert!(matches!(
            verify_signed_manifest(&bytes, &signature, &trusted),
            Err(ContractError::InvalidManifest(_))
        ));

        let mut invalid = manifest();
        invalid.schema_version = 2;
        let (bytes, signature, trusted) = signed_manifest(&invalid, &key);
        assert_eq!(
            verify_signed_manifest(&bytes, &signature, &trusted),
            Err(ContractError::UnsupportedSchema(2))
        );
    }

    #[test]
    fn oversized_manifest_is_rejected_before_parsing() {
        let bytes = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert_eq!(
            verify_signed_manifest(&bytes, "", &BTreeMap::new()),
            Err(ContractError::ManifestTooLarge)
        );
    }

    #[test]
    fn operation_grant_binds_every_authorization_dimension() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let grant = OperationGrant::issue(grant_claims(), &signing_key).unwrap();
        let trusted = BTreeMap::from([(
            "org.skullsandbones.mesh-authority".into(),
            TrustedIssuer {
                mesh_id: "mesh-public".into(),
                node_id: "node-issuer".into(),
                public_key: signing_key.verifying_key().to_bytes(),
            },
        )]);
        assert_eq!(grant.verify(&trusted, &grant_context()), Ok(()));

        let mut wrong_resource = grant_context();
        wrong_resource.resource_id = "notes.collection-2";
        assert_eq!(
            grant.verify(&trusted, &wrong_resource),
            Err(ContractError::GrantDenied("resource not granted"))
        );
        let mut stale_policy = grant_context();
        stale_policy.policy_epoch = 10;
        assert_eq!(
            grant.verify(&trusted, &stale_policy),
            Err(ContractError::GrantDenied("stale policy epoch"))
        );
        let mut wrong_service = grant_context();
        wrong_service.service_id = "org.skullsandbones.other.api";
        assert_eq!(
            grant.verify(&trusted, &wrong_service),
            Err(ContractError::GrantDenied("wrong service audience"))
        );
        let mut expired = grant_context();
        expired.now = 500;
        assert_eq!(
            grant.verify(&trusted, &expired),
            Err(ContractError::GrantDenied("grant expired"))
        );
    }

    #[test]
    fn operation_grant_rejects_tampering() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let mut grant = OperationGrant::issue(grant_claims(), &signing_key).unwrap();
        let trusted = BTreeMap::from([(
            "org.skullsandbones.mesh-authority".into(),
            TrustedIssuer {
                mesh_id: "mesh-public".into(),
                node_id: "node-issuer".into(),
                public_key: signing_key.verifying_key().to_bytes(),
            },
        )]);
        grant.operation = "notes.write".into();
        assert_eq!(
            grant.verify(&trusted, &grant_context()),
            Err(ContractError::InvalidSignature)
        );
    }

    #[test]
    fn operation_requires_both_signed_app_declaration_and_issuer_grant() {
        let publisher_key = SigningKey::from_bytes(&[7u8; 32]);
        let app = manifest();
        let (bytes, signature, trusted_publishers) = signed_manifest(&app, &publisher_key);
        let verified_app = verify_signed_manifest(&bytes, &signature, &trusted_publishers).unwrap();

        let issuer_key = SigningKey::from_bytes(&[11u8; 32]);
        let grant = OperationGrant::issue(grant_claims(), &issuer_key).unwrap();
        let trusted_issuers = BTreeMap::from([(
            "org.skullsandbones.mesh-authority".into(),
            TrustedIssuer {
                mesh_id: "mesh-public".into(),
                node_id: "node-issuer".into(),
                public_key: issuer_key.verifying_key().to_bytes(),
            },
        )]);
        assert_eq!(
            OperationGrant::authorize_operation(
                &verified_app,
                &grant,
                &trusted_issuers,
                &grant_context()
            ),
            Ok(())
        );

        let mut undeclared_operation = grant_context();
        undeclared_operation.operation = "notes.write";
        assert_eq!(
            OperationGrant::authorize_operation(
                &verified_app,
                &grant,
                &trusted_issuers,
                &undeclared_operation
            ),
            Err(ContractError::GrantDenied(
                "operation is not declared by the app"
            ))
        );
    }

    #[test]
    fn grant_issuer_key_must_be_trusted_for_the_claimed_mesh_and_node() {
        let issuer_key = SigningKey::from_bytes(&[11u8; 32]);
        let grant = OperationGrant::issue(grant_claims(), &issuer_key).unwrap();
        let trusted = BTreeMap::from([(
            "org.skullsandbones.mesh-authority".into(),
            TrustedIssuer {
                mesh_id: "another-mesh".into(),
                node_id: "node-issuer".into(),
                public_key: issuer_key.verifying_key().to_bytes(),
            },
        )]);
        assert_eq!(
            grant.verify(&trusted, &grant_context()),
            Err(ContractError::GrantDenied(
                "grant issuer is not trusted for this Mesh"
            ))
        );
    }

    #[test]
    fn grant_resource_is_an_identifier_not_a_filesystem_path() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let mut claims = grant_claims();
        claims.resource_id = "notes/collection-1".into();
        assert!(matches!(
            OperationGrant::issue(claims, &signing_key),
            Err(ContractError::InvalidGrant(_))
        ));
    }
}
