use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Version of the signed catalog membership contract.
pub const CATALOG_MEMBERSHIP_SCHEMA_VERSION: u16 = 1;
const MEMBERSHIP_STORE_SCHEMA_VERSION: u16 = 1;
const MAX_CATALOG_DCS: usize = 128;
const MAX_ADMIN_SIGNERS: usize = 128;
const MAX_MEMBERSHIP_STORE_BYTES: u64 = 1024 * 1024;
const MAX_QUORUM_LEASE_BYTES: u64 = 64 * 1024;
pub const CATALOG_QUORUM_LEASE_MAX_AGE_SECS: u64 = 30;
const CATALOG_QUORUM_LEASE_MAX_FUTURE_SKEW_SECS: u64 = 5;
const ADMIN_APPROVAL_DOMAIN: &[u8] = b"SB-CATALOG-MEMBERSHIP-ADMIN-V1\0";
const DC_COMMIT_DOMAIN: &[u8] = b"SB-CATALOG-MEMBERSHIP-DC-COMMIT-V1\0";
const QUORUM_LEASE_DOMAIN: &[u8] = b"SB-CATALOG-QUORUM-FRESHNESS-V1\0";
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogDcMember {
    pub dc_id: String,
    pub mesh_node_id: String,
    pub signing_public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthority {
    pub threshold: u16,
    pub signers: BTreeMap<String, [u8; 32]>,
}

impl AdminAuthority {
    pub fn validate(&self) -> Result<(), String> {
        if self.signers.is_empty() || self.signers.len() > MAX_ADMIN_SIGNERS {
            return Err(format!(
                "Admin signer count must be between 1 and {MAX_ADMIN_SIGNERS}"
            ));
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.signers.len() {
            return Err("Admin signature threshold is outside the configured signer set".into());
        }
        let mut public_keys = BTreeSet::new();
        for (signer_id, public_key) in &self.signers {
            validate_id(signer_id, "admin signer ID")?;
            validate_public_key(public_key, "admin signer")?;
            if !public_keys.insert(*public_key) {
                return Err("Admin signing keys must belong to distinct authority members".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogMembership {
    pub schema_version: u16,
    pub mesh_id: String,
    pub epoch: u64,
    pub dcs: BTreeMap<String, CatalogDcMember>,
    pub admin_authority: AdminAuthority,
}

impl CatalogMembership {
    pub fn bootstrap(
        mesh_id: impl Into<String>,
        initial_dc: CatalogDcMember,
        admin_authority: AdminAuthority,
    ) -> Result<Self, String> {
        let mesh_id = mesh_id.into();
        let membership = Self {
            schema_version: CATALOG_MEMBERSHIP_SCHEMA_VERSION,
            mesh_id,
            epoch: 1,
            dcs: BTreeMap::from([(initial_dc.dc_id.clone(), initial_dc)]),
            admin_authority,
        };
        membership.validate()?;
        Ok(membership)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != CATALOG_MEMBERSHIP_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported catalog membership schema version {}",
                self.schema_version
            ));
        }
        validate_id(&self.mesh_id, "mesh ID")?;
        if self.epoch == 0 {
            return Err("Catalog membership epoch must be non-zero".into());
        }
        if self.dcs.is_empty() || self.dcs.len() > MAX_CATALOG_DCS {
            return Err(format!(
                "Catalog DC count must be between 1 and {MAX_CATALOG_DCS}"
            ));
        }
        let mut mesh_nodes = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for (dc_id, dc) in &self.dcs {
            validate_id(dc_id, "catalog DC ID")?;
            validate_id(&dc.dc_id, "catalog DC ID")?;
            validate_id(&dc.mesh_node_id, "mesh node ID")?;
            if dc_id != &dc.dc_id {
                return Err(format!("DC map key {dc_id} does not match embedded ID"));
            }
            if !mesh_nodes.insert(dc.mesh_node_id.as_str()) {
                return Err(format!(
                    "Mesh node {} is assigned to more than one catalog DC",
                    dc.mesh_node_id
                ));
            }
            if !public_keys.insert(dc.signing_public_key) {
                return Err("A signing key cannot belong to multiple catalog DCs".into());
            }
            validate_public_key(&dc.signing_public_key, "catalog DC")?;
        }
        self.admin_authority.validate().and_then(|()| {
            if self.dcs.values().any(|dc| {
                self.admin_authority
                    .signers
                    .values()
                    .any(|admin_key| admin_key == &dc.signing_public_key)
            }) {
                return Err("Catalog DC and admin authority must use separate signing keys".into());
            }
            Ok(())
        })
    }

    pub fn propose(
        &self,
        next_dcs: BTreeMap<String, CatalogDcMember>,
        next_admin_authority: AdminAuthority,
    ) -> Result<CatalogMembershipProposal, String> {
        self.validate()?;
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| "Catalog membership epoch exhausted".to_string())?;
        let proposal = CatalogMembershipProposal {
            schema_version: CATALOG_MEMBERSHIP_SCHEMA_VERSION,
            mesh_id: self.mesh_id.clone(),
            base_epoch: self.epoch,
            next_epoch,
            next_dcs,
            next_admin_authority,
            admin_approvals: Vec::new(),
        };
        proposal.validate_payload()?;
        Ok(proposal)
    }

    pub fn apply_commit(
        &self,
        commit: &CatalogMembershipCommit,
    ) -> Result<CatalogMembership, String> {
        commit.verify_against(self)?;
        let proposal = &commit.proposal;
        let membership = Self {
            schema_version: CATALOG_MEMBERSHIP_SCHEMA_VERSION,
            mesh_id: proposal.mesh_id.clone(),
            epoch: proposal.next_epoch,
            dcs: proposal.next_dcs.clone(),
            admin_authority: proposal.next_admin_authority.clone(),
        };
        membership.validate()?;
        Ok(membership)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminApproval {
    pub signer_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcCommitApproval {
    pub dc_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipTransitionPayload {
    schema_version: u16,
    mesh_id: String,
    base_epoch: u64,
    next_epoch: u64,
    next_dcs: BTreeMap<String, CatalogDcMember>,
    next_admin_authority: AdminAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogMembershipProposal {
    pub schema_version: u16,
    pub mesh_id: String,
    pub base_epoch: u64,
    pub next_epoch: u64,
    pub next_dcs: BTreeMap<String, CatalogDcMember>,
    pub next_admin_authority: AdminAuthority,
    pub admin_approvals: Vec<AdminApproval>,
}

impl CatalogMembershipProposal {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_payload()?;
        let payload = self.transition_payload();
        let encoded = serde_json::to_vec(&payload)
            .map_err(|error| format!("Cannot encode membership proposal: {error}"))?;
        let mut message = Vec::with_capacity(ADMIN_APPROVAL_DOMAIN.len() + encoded.len());
        message.extend_from_slice(ADMIN_APPROVAL_DOMAIN);
        message.extend_from_slice(&encoded);
        Ok(message)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        let bytes = self.signing_bytes()?;
        Ok(Sha256::digest(bytes).into())
    }

    pub fn dc_commit_signing_bytes(&self) -> Result<Vec<u8>, String> {
        let digest = self.digest()?;
        let mut message = Vec::with_capacity(DC_COMMIT_DOMAIN.len() + digest.len());
        message.extend_from_slice(DC_COMMIT_DOMAIN);
        message.extend_from_slice(&digest);
        Ok(message)
    }

    pub fn verify_admin_approvals(&self, current_authority: &AdminAuthority) -> Result<(), String> {
        self.validate_payload()?;
        current_authority.validate()?;
        if self.admin_approvals.len() > MAX_ADMIN_SIGNERS {
            return Err(format!(
                "Admin approval count exceeds the limit of {MAX_ADMIN_SIGNERS}"
            ));
        }
        let message = self.signing_bytes()?;
        let mut accepted = BTreeSet::new();
        for approval in &self.admin_approvals {
            if !accepted.insert(approval.signer_id.as_str()) {
                return Err(format!(
                    "Duplicate admin approval from {}",
                    approval.signer_id
                ));
            }
            let key_bytes = current_authority
                .signers
                .get(&approval.signer_id)
                .ok_or_else(|| format!("Unknown admin signer {}", approval.signer_id))?;
            verify_signature(key_bytes, &message, &approval.signature)
                .map_err(|_| format!("Invalid admin approval from {}", approval.signer_id))?;
        }
        if accepted.len() < usize::from(current_authority.threshold) {
            return Err(format!(
                "Membership proposal needs {} valid admin approvals; received {}",
                current_authority.threshold,
                accepted.len()
            ));
        }
        Ok(())
    }

    fn validate_payload(&self) -> Result<(), String> {
        if self.schema_version != CATALOG_MEMBERSHIP_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported membership proposal schema version {}",
                self.schema_version
            ));
        }
        validate_id(&self.mesh_id, "mesh ID")?;
        if self.base_epoch == 0
            || self.next_epoch != self.base_epoch.checked_add(1).unwrap_or_default()
        {
            return Err("Membership proposal must advance exactly one epoch".into());
        }
        CatalogMembership {
            schema_version: self.schema_version,
            mesh_id: self.mesh_id.clone(),
            epoch: self.next_epoch,
            dcs: self.next_dcs.clone(),
            admin_authority: self.next_admin_authority.clone(),
        }
        .validate()
    }

    fn transition_payload(&self) -> MembershipTransitionPayload {
        MembershipTransitionPayload {
            schema_version: self.schema_version,
            mesh_id: self.mesh_id.clone(),
            base_epoch: self.base_epoch,
            next_epoch: self.next_epoch,
            next_dcs: self.next_dcs.clone(),
            next_admin_authority: self.next_admin_authority.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogMembershipCommit {
    pub proposal: CatalogMembershipProposal,
    pub dc_approvals: Vec<DcCommitApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumLeaseApproval {
    pub dc_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuorumLeasePayload {
    schema_version: u16,
    mesh_id: String,
    epoch: u64,
    membership_digest: [u8; 32],
    issued_at_unix: u64,
    expires_at_unix: u64,
}

/// Short-lived proof that a strict majority of the active DC set observed one membership epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogQuorumLease {
    pub schema_version: u16,
    pub mesh_id: String,
    pub epoch: u64,
    pub membership_digest: [u8; 32],
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub approvals: Vec<QuorumLeaseApproval>,
}

impl CatalogQuorumLease {
    pub fn for_membership(
        membership: &CatalogMembership,
        issued_at_unix: u64,
    ) -> Result<Self, String> {
        membership.validate()?;
        let expires_at_unix = issued_at_unix
            .checked_add(CATALOG_QUORUM_LEASE_MAX_AGE_SECS)
            .ok_or_else(|| "Catalog quorum lease expiration overflow".to_string())?;
        Ok(Self {
            schema_version: CATALOG_MEMBERSHIP_SCHEMA_VERSION,
            mesh_id: membership.mesh_id.clone(),
            epoch: membership.epoch,
            membership_digest: membership_digest(membership)?,
            issued_at_unix,
            expires_at_unix,
            approvals: Vec::new(),
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_payload()?;
        let payload = QuorumLeasePayload {
            schema_version: self.schema_version,
            mesh_id: self.mesh_id.clone(),
            epoch: self.epoch,
            membership_digest: self.membership_digest,
            issued_at_unix: self.issued_at_unix,
            expires_at_unix: self.expires_at_unix,
        };
        let encoded = serde_json::to_vec(&payload)
            .map_err(|error| format!("Cannot encode catalog quorum lease: {error}"))?;
        let mut message = Vec::with_capacity(QUORUM_LEASE_DOMAIN.len() + encoded.len());
        message.extend_from_slice(QUORUM_LEASE_DOMAIN);
        message.extend_from_slice(&encoded);
        Ok(message)
    }

    pub fn add_approval(
        &mut self,
        membership: &CatalogMembership,
        approval: QuorumLeaseApproval,
    ) -> Result<(), String> {
        self.verify_payload_against(membership)?;
        if !membership.dcs.contains_key(&approval.dc_id) {
            return Err(format!(
                "Non-member DC {} cannot approve catalog freshness",
                approval.dc_id
            ));
        }
        if self
            .approvals
            .iter()
            .any(|existing| existing.dc_id == approval.dc_id)
        {
            return Err(format!(
                "Duplicate catalog freshness approval from {}",
                approval.dc_id
            ));
        }
        self.approvals.push(approval);
        Ok(())
    }

    pub fn verify_against(
        &self,
        membership: &CatalogMembership,
        now_unix: u64,
    ) -> Result<(), String> {
        self.verify_payload_against(membership)?;
        if self.issued_at_unix > now_unix.saturating_add(CATALOG_QUORUM_LEASE_MAX_FUTURE_SKEW_SECS)
        {
            return Err("Catalog quorum lease was issued in the future".into());
        }
        if now_unix >= self.expires_at_unix {
            return Err("Catalog quorum lease has expired".into());
        }
        if now_unix.saturating_sub(self.issued_at_unix) > CATALOG_QUORUM_LEASE_MAX_AGE_SECS {
            return Err("Catalog quorum lease is stale".into());
        }
        let message = self.signing_bytes()?;
        let mut accepted = BTreeSet::new();
        for approval in &self.approvals {
            if !accepted.insert(approval.dc_id.as_str()) {
                return Err(format!(
                    "Duplicate catalog freshness approval from {}",
                    approval.dc_id
                ));
            }
            let member = membership
                .dcs
                .get(&approval.dc_id)
                .ok_or_else(|| format!("Non-member DC {} approved freshness", approval.dc_id))?;
            verify_signature(&member.signing_public_key, &message, &approval.signature).map_err(
                |_| format!("Invalid catalog freshness approval from {}", approval.dc_id),
            )?;
        }
        let read_quorum = membership.dcs.len() / 2 + 1;
        if accepted.len() < read_quorum {
            return Err(format!(
                "Catalog freshness needs {read_quorum} DC approvals; received {}",
                accepted.len()
            ));
        }
        Ok(())
    }

    pub fn load_fresh(
        path: &Path,
        membership: &CatalogMembership,
        now_unix: u64,
    ) -> Result<Self, String> {
        let file = File::open(path)
            .map_err(|error| format!("Cannot open catalog quorum lease {:?}: {error}", path))?;
        let mut contents = Vec::new();
        file.take(MAX_QUORUM_LEASE_BYTES + 1)
            .read_to_end(&mut contents)
            .map_err(|error| format!("Cannot read catalog quorum lease {:?}: {error}", path))?;
        if contents.len() as u64 > MAX_QUORUM_LEASE_BYTES {
            return Err(format!(
                "Catalog quorum lease {:?} exceeds {MAX_QUORUM_LEASE_BYTES} bytes",
                path
            ));
        }
        let lease: Self = serde_json::from_slice(&contents)
            .map_err(|error| format!("Invalid catalog quorum lease {:?}: {error}", path))?;
        lease.verify_against(membership, now_unix)?;
        Ok(lease)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        self.validate_payload()?;
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("Failed to serialize catalog quorum lease: {error}"))?;
        let parent = store_parent(path);
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create quorum lease directory {:?}: {error}",
                parent
            )
        })?;
        let filename = path
            .file_name()
            .ok_or_else(|| format!("Quorum lease path {:?} has no file name", path))?;
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary_path = parent.join(format!(
            ".{}.{}.{}.tmp",
            filename.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        let mut temporary_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| {
                format!(
                    "Failed to create temporary quorum lease {:?}: {error}",
                    temporary_path
                )
            })?;
        if let Err(error) = temporary_file
            .write_all(&encoded)
            .and_then(|()| temporary_file.sync_all())
        {
            drop(temporary_file);
            return Err(cleanup_temp_after_error(
                &temporary_path,
                format!("Failed to write temporary quorum lease: {error}"),
            ));
        }
        drop(temporary_file);
        if let Err(error) = fs::rename(&temporary_path, path) {
            return Err(cleanup_temp_after_error(
                &temporary_path,
                format!(
                    "Failed to atomically replace quorum lease {:?}: {error}",
                    path
                ),
            ));
        }
        Ok(())
    }

    fn verify_payload_against(&self, membership: &CatalogMembership) -> Result<(), String> {
        membership.validate()?;
        self.validate_payload()?;
        if self.mesh_id != membership.mesh_id
            || self.epoch != membership.epoch
            || self.membership_digest != membership_digest(membership)?
        {
            return Err("Catalog quorum lease does not match the current membership epoch".into());
        }
        Ok(())
    }

    fn validate_payload(&self) -> Result<(), String> {
        if self.schema_version != CATALOG_MEMBERSHIP_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported catalog quorum lease schema version {}",
                self.schema_version
            ));
        }
        validate_id(&self.mesh_id, "mesh ID")?;
        if self.epoch == 0 {
            return Err("Catalog quorum lease epoch must be non-zero".into());
        }
        if self.issued_at_unix == 0
            || self.expires_at_unix <= self.issued_at_unix
            || self.expires_at_unix - self.issued_at_unix > CATALOG_QUORUM_LEASE_MAX_AGE_SECS
        {
            return Err("Catalog quorum lease has invalid or excessive lifetime".into());
        }
        Ok(())
    }
}

pub fn membership_digest(membership: &CatalogMembership) -> Result<[u8; 32], String> {
    let encoded = serde_json::to_vec(membership)
        .map_err(|error| format!("Cannot encode catalog membership digest: {error}"))?;
    Ok(Sha256::digest(encoded).into())
}

impl CatalogMembershipCommit {
    pub fn verify_against(&self, current: &CatalogMembership) -> Result<(), String> {
        current.validate()?;
        let proposal = &self.proposal;
        if proposal.mesh_id != current.mesh_id || proposal.base_epoch != current.epoch {
            return Err("Membership proposal does not target the current mesh epoch".into());
        }
        proposal.verify_admin_approvals(&current.admin_authority)?;
        if self.dc_approvals.len() > current.dcs.len() {
            return Err("DC approval count exceeds the current membership size".into());
        }

        let message = proposal.dc_commit_signing_bytes()?;

        let mut accepted = BTreeSet::new();
        for approval in &self.dc_approvals {
            if !accepted.insert(approval.dc_id.as_str()) {
                return Err(format!(
                    "Duplicate DC commit approval from {}",
                    approval.dc_id
                ));
            }
            let member = current
                .dcs
                .get(&approval.dc_id)
                .ok_or_else(|| format!("Non-member DC {} approved transition", approval.dc_id))?;
            verify_signature(&member.signing_public_key, &message, &approval.signature)
                .map_err(|_| format!("Invalid DC commit approval from {}", approval.dc_id))?;
        }
        let write_quorum = current.dcs.len() / 2 + 1;
        if accepted.len() < write_quorum {
            return Err(format!(
                "Membership transition needs {write_quorum} DC commit approvals; received {}",
                accepted.len()
            ));
        }
        Ok(())
    }
}

/// Persistent, tamper-evident hash-chained journal entry for catalog membership transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipJournalEntry {
    pub index: u64,
    pub timestamp_unix: u64,
    pub action: String,
    pub epoch: u64,
    pub local_dc_id: String,
    pub digest: [u8; 32],
    pub prev_entry_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl MembershipJournalEntry {
    pub fn compute_hash(
        index: u64,
        timestamp_unix: u64,
        action: &str,
        epoch: u64,
        local_dc_id: &str,
        digest: &[u8; 32],
        prev_entry_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SB-CATALOG-MEMBERSHIP-JOURNAL-V1\0");
        hasher.update(index.to_be_bytes());
        hasher.update(timestamp_unix.to_be_bytes());
        hasher.update((action.len() as u32).to_be_bytes());
        hasher.update(action.as_bytes());
        hasher.update(epoch.to_be_bytes());
        hasher.update((local_dc_id.len() as u32).to_be_bytes());
        hasher.update(local_dc_id.as_bytes());
        hasher.update(digest);
        hasher.update(prev_entry_hash);
        hasher.finalize().into()
    }

    pub fn new(
        index: u64,
        timestamp_unix: u64,
        action: impl Into<String>,
        epoch: u64,
        local_dc_id: impl Into<String>,
        digest: [u8; 32],
        prev_entry_hash: [u8; 32],
    ) -> Self {
        let action = action.into();
        let local_dc_id = local_dc_id.into();
        let entry_hash = Self::compute_hash(
            index,
            timestamp_unix,
            &action,
            epoch,
            &local_dc_id,
            &digest,
            &prev_entry_hash,
        );
        Self {
            index,
            timestamp_unix,
            action,
            epoch,
            local_dc_id,
            digest,
            prev_entry_hash,
            entry_hash,
        }
    }

    pub fn verify(&self, expected_index: u64, expected_prev_hash: &[u8; 32]) -> Result<(), String> {
        if self.index != expected_index {
            return Err(format!(
                "Journal entry index mismatch: expected {expected_index}, got {}",
                self.index
            ));
        }
        if &self.prev_entry_hash != expected_prev_hash {
            return Err(format!(
                "Journal hash chain broken at entry index {}: prev_hash does not match previous entry_hash",
                self.index
            ));
        }
        let expected_hash = Self::compute_hash(
            self.index,
            self.timestamp_unix,
            &self.action,
            self.epoch,
            &self.local_dc_id,
            &self.digest,
            &self.prev_entry_hash,
        );
        if self.entry_hash != expected_hash {
            return Err(format!(
                "Journal entry hash tampering detected at index {}: stored hash differs from computed hash",
                self.index
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipBackupManifest {
    pub schema_version: u16,
    pub exported_at_unix: u64,
    pub mesh_id: String,
    pub epoch: u64,
    pub local_dc_id: String,
    pub journal_entries_count: usize,
    pub head_journal_hash: [u8; 32],
    pub state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipBackup {
    pub manifest: MembershipBackupManifest,
    pub state: MembershipStoreState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipStoreState {
    pub store_schema_version: u16,
    pub membership: CatalogMembership,
    pub local_dc_id: String,
    pub epoch_decisions: BTreeMap<u64, [u8; 32]>,
    #[serde(default)]
    pub journal: Vec<MembershipJournalEntry>,
}

impl MembershipStoreState {
    pub fn validate(&self) -> Result<(), String> {
        if self.store_schema_version != MEMBERSHIP_STORE_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported membership store schema version {}",
                self.store_schema_version
            ));
        }
        self.membership.validate()?;
        validate_id(&self.local_dc_id, "local catalog DC ID")?;
        if self
            .epoch_decisions
            .keys()
            .any(|epoch| *epoch == 0 || *epoch > self.membership.epoch)
        {
            return Err("Membership decision journal contains an invalid epoch".into());
        }
        let mut expected_prev_hash = [0u8; 32];
        for (i, entry) in self.journal.iter().enumerate() {
            entry.verify(i as u64, &expected_prev_hash)?;
            expected_prev_hash = entry.entry_hash;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CatalogMembershipStore {
    path: PathBuf,
}

impl CatalogMembershipStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn initialize(
        &self,
        membership: CatalogMembership,
        local_dc_id: impl Into<String>,
    ) -> Result<(), String> {
        membership.validate()?;
        let local_dc_id = local_dc_id.into();
        validate_id(&local_dc_id, "local catalog DC ID")?;
        if !membership.dcs.contains_key(&local_dc_id) {
            return Err(format!(
                "Local DC {local_dc_id} is not in the initial membership"
            ));
        }
        let _lock = self.lock_exclusive()?;
        if self.path.exists() {
            return Err(format!(
                "Membership store already exists at {:?}",
                self.path
            ));
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let initial_digest = membership_digest(&membership)?;
        let entry = MembershipJournalEntry::new(
            0,
            now,
            "bootstrap",
            membership.epoch,
            &local_dc_id,
            initial_digest,
            [0u8; 32],
        );
        let state = MembershipStoreState {
            store_schema_version: MEMBERSHIP_STORE_SCHEMA_VERSION,
            membership,
            local_dc_id,
            epoch_decisions: BTreeMap::new(),
            journal: vec![entry],
        };
        state.validate()?;
        self.write_state_atomically(&state)
    }

    pub fn membership(&self) -> Result<CatalogMembership, String> {
        let _lock = self.lock_exclusive()?;
        Ok(self.load_state()?.membership)
    }

    pub fn state(&self) -> Result<MembershipStoreState, String> {
        let _lock = self.lock_exclusive()?;
        self.load_state()
    }

    pub fn journal(&self) -> Result<Vec<MembershipJournalEntry>, String> {
        let state = self.state()?;
        Ok(state.journal)
    }

    pub fn local_dc_id(&self) -> Result<String, String> {
        let state = self.state()?;
        Ok(state.local_dc_id)
    }

    pub fn verify_journal_integrity(&self) -> Result<usize, String> {
        let state = self.state()?;
        Ok(state.journal.len())
    }

    pub fn sign_quorum_lease(
        &self,
        lease: &CatalogQuorumLease,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<QuorumLeaseApproval, String> {
        let _lock = self.lock_exclusive()?;
        let state = self.load_state()?;
        let membership = &state.membership;
        lease.verify_payload_against(membership)?;
        let local_dc = membership
            .dcs
            .get(&state.local_dc_id)
            .ok_or_else(|| format!("Local DC {} is no longer a member", state.local_dc_id))?;
        if signing_key.verifying_key().to_bytes() != local_dc.signing_public_key {
            return Err("Signing key does not match the local DC membership key".into());
        }
        let message = lease.signing_bytes()?;
        Ok(QuorumLeaseApproval {
            dc_id: state.local_dc_id,
            signature: signing_key.sign(&message).to_bytes().to_vec(),
        })
    }

    pub fn sign_commit_once(
        &self,
        proposal: &CatalogMembershipProposal,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<DcCommitApproval, String> {
        let _lock = self.lock_exclusive()?;
        let mut state = self.load_state()?;
        let current = &state.membership;
        if proposal.mesh_id != current.mesh_id || proposal.base_epoch != current.epoch {
            return Err("Membership proposal does not target the current mesh epoch".into());
        }
        proposal.verify_admin_approvals(&current.admin_authority)?;
        let local_dc = current
            .dcs
            .get(&state.local_dc_id)
            .ok_or_else(|| format!("Local DC {} is no longer a member", state.local_dc_id))?;
        if signing_key.verifying_key().to_bytes() != local_dc.signing_public_key {
            return Err("Signing key does not match the local DC membership key".into());
        }
        let digest = proposal.digest()?;
        if let Some(existing_digest) = state.epoch_decisions.get(&current.epoch) {
            if existing_digest != &digest {
                return Err(format!(
                    "Local DC already committed to a different membership transition at epoch {}",
                    current.epoch
                ));
            }
        } else {
            state.epoch_decisions.insert(current.epoch, digest);
            let next_index = state.journal.len() as u64;
            let prev_hash = state
                .journal
                .last()
                .map(|e| e.entry_hash)
                .unwrap_or([0u8; 32]);
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            let entry = MembershipJournalEntry::new(
                next_index,
                now,
                "sign_commit",
                current.epoch,
                &state.local_dc_id,
                digest,
                prev_hash,
            );
            state.journal.push(entry);
            state.validate()?;
            self.write_state_atomically(&state)?;
        }

        let signature = signing_key
            .sign(&proposal.dc_commit_signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(DcCommitApproval {
            dc_id: state.local_dc_id,
            signature,
        })
    }

    pub fn apply_commit(&self, commit: &CatalogMembershipCommit) -> Result<(), String> {
        let _lock = self.lock_exclusive()?;
        let mut state = self.load_state()?;
        commit.verify_against(&state.membership)?;
        let decision_epoch = commit.proposal.base_epoch;
        let digest = commit.proposal.digest()?;
        if let Some(existing_digest) = state.epoch_decisions.get(&decision_epoch) {
            if existing_digest != &digest {
                return Err(format!(
                    "Commit conflicts with the locally recorded transition at epoch {decision_epoch}"
                ));
            }
        }
        let updated_membership = state.membership.apply_commit(commit)?;
        state.epoch_decisions.insert(decision_epoch, digest);
        state.membership = updated_membership;
        let next_index = state.journal.len() as u64;
        let prev_hash = state
            .journal
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32]);
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let new_digest = membership_digest(&state.membership)?;
        let entry = MembershipJournalEntry::new(
            next_index,
            now,
            "apply_commit",
            state.membership.epoch,
            &state.local_dc_id,
            new_digest,
            prev_hash,
        );
        state.journal.push(entry);
        state.validate()?;
        self.write_state_atomically(&state)
    }

    pub fn export_backup(&self, target_path: &Path) -> Result<MembershipBackupManifest, String> {
        let _lock = self.lock_exclusive()?;
        let state = self.load_state()?;
        state.validate()?;

        let state_bytes = serde_json::to_vec(&state)
            .map_err(|error| format!("Failed to serialize membership state for backup: {error}"))?;
        let state_sha256 = format!("{:x}", Sha256::digest(&state_bytes));
        let head_journal_hash = state
            .journal
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32]);
        let manifest = MembershipBackupManifest {
            schema_version: MEMBERSHIP_STORE_SCHEMA_VERSION,
            exported_at_unix: chrono::Utc::now().timestamp().max(0) as u64,
            mesh_id: state.membership.mesh_id.clone(),
            epoch: state.membership.epoch,
            local_dc_id: state.local_dc_id.clone(),
            journal_entries_count: state.journal.len(),
            head_journal_hash,
            state_sha256,
        };

        let backup = MembershipBackup {
            manifest: manifest.clone(),
            state,
        };

        let encoded = serde_json::to_vec_pretty(&backup)
            .map_err(|error| format!("Failed to serialize backup bundle: {error}"))?;

        if let Some(parent) = target_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "Failed to create backup target directory {:?}: {error}",
                        parent
                    )
                })?;
            }
        }
        fs::write(target_path, &encoded)
            .map_err(|error| format!("Failed to write backup bundle {:?}: {error}", target_path))?;

        Ok(manifest)
    }

    pub fn restore_from_backup(
        &self,
        backup_path: &Path,
        force: bool,
    ) -> Result<MembershipBackupManifest, String> {
        let file = File::open(backup_path)
            .map_err(|error| format!("Cannot open backup file {:?}: {error}", backup_path))?;
        let mut contents = Vec::new();
        file.take(MAX_MEMBERSHIP_STORE_BYTES * 2)
            .read_to_end(&mut contents)
            .map_err(|error| format!("Cannot read backup file {:?}: {error}", backup_path))?;
        let backup: MembershipBackup = serde_json::from_slice(&contents).map_err(|error| {
            format!(
                "Invalid membership backup bundle {:?}: {error}",
                backup_path
            )
        })?;

        let state_bytes = serde_json::to_vec(&backup.state)
            .map_err(|error| format!("Failed to re-serialize backup state: {error}"))?;
        let computed_sha256 = format!("{:x}", Sha256::digest(&state_bytes));
        if computed_sha256 != backup.manifest.state_sha256 {
            return Err(
                "Backup integrity violation: payload SHA-256 does not match manifest".into(),
            );
        }

        backup.state.validate()?;

        let head_hash = backup
            .state
            .journal
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32]);
        if head_hash != backup.manifest.head_journal_hash {
            return Err("Backup manifest head journal hash does not match state".into());
        }

        let _lock = self.lock_exclusive()?;
        if self.path.exists() && !force {
            return Err(format!(
                "Membership store already exists at {:?}. Use force=true to overwrite.",
                self.path
            ));
        }

        self.write_state_atomically(&backup.state)?;
        Ok(backup.manifest)
    }

    fn lock_exclusive(&self) -> Result<File, String> {
        let parent = store_parent(&self.path);
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create membership store directory {:?}: {error}",
                parent
            )
        })?;
        let lock_path = self.lock_path()?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| format!("Failed to open membership lock {:?}: {error}", lock_path))?;
        lock_file.lock().map_err(|error| {
            format!(
                "Failed to acquire exclusive membership lock {:?}: {error}",
                lock_path
            )
        })?;
        Ok(lock_file)
    }

    fn load_state(&self) -> Result<MembershipStoreState, String> {
        let file = File::open(&self.path)
            .map_err(|error| format!("Failed to open membership store {:?}: {error}", self.path))?;
        let mut contents = Vec::new();
        file.take(MAX_MEMBERSHIP_STORE_BYTES + 1)
            .read_to_end(&mut contents)
            .map_err(|error| format!("Failed to read membership store {:?}: {error}", self.path))?;
        if contents.len() as u64 > MAX_MEMBERSHIP_STORE_BYTES {
            return Err(format!(
                "Membership store {:?} exceeds {MAX_MEMBERSHIP_STORE_BYTES} bytes",
                self.path
            ));
        }
        let state: MembershipStoreState = serde_json::from_slice(&contents).map_err(|error| {
            format!(
                "Membership store {:?} contains invalid JSON: {error}",
                self.path
            )
        })?;
        state
            .validate()
            .map_err(|error| format!("Membership store {:?} is invalid: {error}", self.path))?;
        Ok(state)
    }

    fn write_state_atomically(&self, state: &MembershipStoreState) -> Result<(), String> {
        state.validate()?;
        let serialized = serde_json::to_vec_pretty(state)
            .map_err(|error| format!("Failed to serialize membership state: {error}"))?;
        let temporary_path = self.temporary_path()?;
        let mut temporary_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| {
                format!(
                    "Failed to create temporary membership state {:?}: {error}",
                    temporary_path
                )
            })?;
        if let Err(error) = temporary_file
            .write_all(&serialized)
            .and_then(|()| temporary_file.sync_all())
        {
            drop(temporary_file);
            return Err(cleanup_temp_after_error(
                &temporary_path,
                format!("Failed to write temporary membership state: {error}"),
            ));
        }
        drop(temporary_file);
        if let Err(error) = fs::rename(&temporary_path, &self.path) {
            return Err(cleanup_temp_after_error(
                &temporary_path,
                format!(
                    "Failed to atomically replace membership store {:?}: {error}",
                    self.path
                ),
            ));
        }
        Ok(())
    }

    fn lock_path(&self) -> Result<PathBuf, String> {
        let filename = self
            .path
            .file_name()
            .ok_or_else(|| format!("Membership store path {:?} has no file name", self.path))?;
        Ok(store_parent(&self.path).join(format!(".{}.lock", filename.to_string_lossy())))
    }

    fn temporary_path(&self) -> Result<PathBuf, String> {
        let filename = self
            .path
            .file_name()
            .ok_or_else(|| format!("Membership store path {:?} has no file name", self.path))?;
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(store_parent(&self.path).join(format!(
            ".{}.{}.{}.tmp",
            filename.to_string_lossy(),
            std::process::id(),
            sequence
        )))
    }
}

fn store_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn cleanup_temp_after_error(temporary_path: &Path, message: String) -> String {
    match fs::remove_file(temporary_path) {
        Ok(()) => message,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => message,
        Err(error) => format!("{message}; failed to remove temporary file: {error}"),
    }
}

fn validate_id(value: &str, kind: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("Invalid {kind}: use 1-128 safe ASCII characters"));
    }
    Ok(())
}

fn validate_public_key(bytes: &[u8; 32], kind: &str) -> Result<(), String> {
    VerifyingKey::from_bytes(bytes)
        .map(|_| ())
        .map_err(|_| format!("Invalid Ed25519 public key for {kind}"))
}

fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|error| format!("Invalid Ed25519 public key: {error}"))?;
    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| "Ed25519 signature must be exactly 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(message, &signature)
        .map_err(|error| format!("Ed25519 signature verification failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn test_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sb-node-catalog-membership-{}-{nonce}",
            std::process::id()
        ))
    }

    fn dc(id: &str, seed: u8) -> (CatalogDcMember, SigningKey) {
        let key = signing_key(seed);
        (
            CatalogDcMember {
                dc_id: id.into(),
                mesh_node_id: format!("node-{id}"),
                signing_public_key: key.verifying_key().to_bytes(),
            },
            key,
        )
    }

    fn authority() -> (AdminAuthority, SigningKey) {
        let key = signing_key(240);
        (
            AdminAuthority {
                threshold: 1,
                signers: BTreeMap::from([("mesh-admin".into(), key.verifying_key().to_bytes())]),
            },
            key,
        )
    }

    fn proposal_for_four_dcs() -> (
        CatalogMembership,
        CatalogMembershipProposal,
        SigningKey,
        SigningKey,
        SigningKey,
        SigningKey,
        SigningKey,
    ) {
        let (dc_one, key_one) = dc("dc-1", 1);
        let (dc_two, key_two) = dc("dc-2", 2);
        let (dc_three, key_three) = dc("dc-3", 3);
        let (dc_four, key_four) = dc("dc-4", 4);
        let (admin_authority, admin_key) = authority();
        let current = CatalogMembership {
            schema_version: CATALOG_MEMBERSHIP_SCHEMA_VERSION,
            mesh_id: "engineering".into(),
            epoch: 7,
            dcs: BTreeMap::from([
                (dc_one.dc_id.clone(), dc_one.clone()),
                (dc_two.dc_id.clone(), dc_two.clone()),
                (dc_three.dc_id.clone(), dc_three.clone()),
            ]),
            admin_authority,
        };
        current.validate().unwrap();
        let next_dcs = BTreeMap::from([
            (dc_one.dc_id.clone(), dc_one),
            (dc_two.dc_id.clone(), dc_two),
            (dc_three.dc_id.clone(), dc_three),
            (dc_four.dc_id.clone(), dc_four),
        ]);
        let mut proposal = current
            .propose(next_dcs, current.admin_authority.clone())
            .unwrap();
        proposal.admin_approvals.push(AdminApproval {
            signer_id: "mesh-admin".into(),
            signature: admin_key
                .sign(&proposal.signing_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        });
        (
            current, proposal, key_one, key_two, key_three, key_four, admin_key,
        )
    }

    fn commit_with_keys(
        proposal: CatalogMembershipProposal,
        signers: &[(&str, &SigningKey)],
    ) -> CatalogMembershipCommit {
        let message = proposal.dc_commit_signing_bytes().unwrap();
        CatalogMembershipCommit {
            proposal,
            dc_approvals: signers
                .iter()
                .map(|(dc_id, key)| DcCommitApproval {
                    dc_id: (*dc_id).into(),
                    signature: key.sign(&message).to_bytes().to_vec(),
                })
                .collect(),
        }
    }

    fn proposal_adds_dc(
        current: &CatalogMembership,
        dc_id: &str,
        dc_seed: u8,
        admin_key: &SigningKey,
    ) -> CatalogMembershipProposal {
        let (new_dc, _) = dc(dc_id, dc_seed);
        let mut next_dcs = current.dcs.clone();
        next_dcs.insert(dc_id.to_string(), new_dc);
        let mut proposal = current
            .propose(next_dcs, current.admin_authority.clone())
            .unwrap();
        proposal.admin_approvals.push(AdminApproval {
            signer_id: "mesh-admin".into(),
            signature: admin_key
                .sign(&proposal.signing_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        });
        proposal
    }

    #[test]
    fn membership_change_requires_admin_signature_and_old_dc_quorum() {
        let (current, proposal, first_dc_key, second_dc_key, third_dc_key, _, _) =
            proposal_for_four_dcs();
        let insufficient = commit_with_keys(proposal.clone(), &[("dc-1", &first_dc_key)]);
        assert!(insufficient
            .verify_against(&current)
            .unwrap_err()
            .contains("needs 2 DC commit approvals"));

        let committed = commit_with_keys(
            proposal.clone(),
            &[
                ("dc-1", &first_dc_key),
                ("dc-1", &first_dc_key),
                ("dc-2", &second_dc_key),
            ],
        );
        assert!(committed.verify_against(&current).is_err());

        let commit = commit_with_keys(
            proposal,
            &[
                ("dc-1", &first_dc_key),
                ("dc-2", &second_dc_key),
                ("dc-3", &third_dc_key),
            ],
        );
        assert_eq!(current.apply_commit(&commit).unwrap().epoch, 8);
    }

    #[test]
    fn admin_approval_is_bound_to_the_exact_transition() {
        let (current, mut proposal, _, _, _, _, _) = proposal_for_four_dcs();
        proposal.next_dcs.remove("dc-2");
        assert!(proposal
            .verify_admin_approvals(&current.admin_authority)
            .is_err());
    }

    #[test]
    fn old_epoch_and_nonmember_dc_approvals_are_rejected() {
        let (current, proposal, first_dc_key, second_dc_key, third_dc_key, fourth_dc_key, _) =
            proposal_for_four_dcs();
        let committed = commit_with_keys(
            proposal,
            &[
                ("dc-1", &first_dc_key),
                ("dc-2", &second_dc_key),
                ("dc-3", &third_dc_key),
            ],
        );
        let updated = current.apply_commit(&committed).unwrap();
        assert!(updated.apply_commit(&committed).is_err());

        let forged_quorum = commit_with_keys(
            committed.proposal,
            &[("dc-1", &first_dc_key), ("dc-4", &fourth_dc_key)],
        );
        assert!(forged_quorum.verify_against(&current).is_err());
    }

    #[test]
    fn bootstrap_and_authority_thresholds_are_validated() {
        let (initial_dc, _) = dc("dc-1", 1);
        let (mut admin_authority, _) = authority();
        admin_authority.threshold = 2;
        assert!(CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).is_err());

        let (initial_dc, _) = dc("dc-1", 1);
        let (admin_authority, _) = authority();
        assert!(CatalogMembership::bootstrap("../mesh", initial_dc, admin_authority).is_err());
    }

    #[test]
    fn admin_threshold_cannot_be_met_by_duplicate_keys() {
        let key = signing_key(240).verifying_key().to_bytes();
        let admin_authority = AdminAuthority {
            threshold: 2,
            signers: BTreeMap::from([("admin-1".into(), key), ("admin-2".into(), key)]),
        };
        assert!(admin_authority.validate().is_err());
    }

    #[test]
    fn schema_and_membership_bounds_are_enforced() {
        let (initial_dc, _) = dc("dc-1", 1);
        let (authority, _) = authority();
        let mut membership =
            CatalogMembership::bootstrap("engineering", initial_dc, authority).unwrap();
        membership.schema_version += 1;
        assert!(membership.validate().is_err());
    }

    #[test]
    fn store_persists_membership_and_local_signing_decision() {
        let directory = test_directory();
        let path = directory.join("mesh-membership.json");
        let store = CatalogMembershipStore::new(&path);
        let (initial_dc, local_key) = dc("dc-1", 1);
        let (admin_authority, admin_key) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        store.initialize(membership.clone(), "dc-1").unwrap();

        let first_proposal = proposal_adds_dc(&membership, "dc-2", 2, &admin_key);
        let first_approval = store.sign_commit_once(&first_proposal, &local_key).unwrap();
        drop(store);

        let restarted = CatalogMembershipStore::new(&path);
        assert_eq!(restarted.membership().unwrap(), membership);
        assert_eq!(
            restarted
                .sign_commit_once(&first_proposal, &local_key)
                .unwrap(),
            first_approval
        );

        let competing_proposal = proposal_adds_dc(&membership, "dc-3", 3, &admin_key);
        assert!(restarted
            .sign_commit_once(&competing_proposal, &local_key)
            .unwrap_err()
            .contains("already committed to a different membership transition"));
        assert!(restarted.initialize(membership, "dc-1").is_err());

        drop(restarted);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn store_commit_is_persisted_and_stale_replay_is_rejected() {
        let directory = test_directory();
        let path = directory.join("mesh-membership.json");
        let store = CatalogMembershipStore::new(&path);
        let (initial_dc, local_key) = dc("dc-1", 1);
        let (admin_authority, admin_key) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        store.initialize(membership.clone(), "dc-1").unwrap();

        let proposal = proposal_adds_dc(&membership, "dc-2", 2, &admin_key);
        let approval = store.sign_commit_once(&proposal, &local_key).unwrap();
        let commit = CatalogMembershipCommit {
            proposal,
            dc_approvals: vec![approval],
        };
        store.apply_commit(&commit).unwrap();
        assert!(store.apply_commit(&commit).is_err());
        assert_eq!(
            CatalogMembershipStore::new(&path)
                .membership()
                .unwrap()
                .epoch,
            2
        );

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_competing_sign_requests_persist_only_one_decision() {
        let directory = test_directory();
        let path = directory.join("mesh-membership.json");
        let store = CatalogMembershipStore::new(&path);
        let (initial_dc, local_key) = dc("dc-1", 1);
        let (admin_authority, admin_key) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        store.initialize(membership.clone(), "dc-1").unwrap();

        let first_proposal = proposal_adds_dc(&membership, "dc-2", 2, &admin_key);
        let second_proposal = proposal_adds_dc(&membership, "dc-3", 3, &admin_key);
        let first_store = CatalogMembershipStore::new(&path);
        let second_store = CatalogMembershipStore::new(&path);
        let first_key = local_key.clone();
        let second_key = local_key;
        let first =
            std::thread::spawn(move || first_store.sign_commit_once(&first_proposal, &first_key));
        let second = std::thread::spawn(move || {
            second_store.sign_commit_once(&second_proposal, &second_key)
        });
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn store_rejects_a_valid_quorum_commit_conflicting_with_its_local_decision() {
        let directory = test_directory();
        let path = directory.join("mesh-membership.json");
        let store = CatalogMembershipStore::new(&path);
        let (initial_dc, local_key) = dc("dc-1", 1);
        let (admin_authority, admin_key) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        store.initialize(membership.clone(), "dc-1").unwrap();

        let first_proposal = proposal_adds_dc(&membership, "dc-2", 2, &admin_key);
        store.sign_commit_once(&first_proposal, &local_key).unwrap();

        let competing_proposal = proposal_adds_dc(&membership, "dc-3", 3, &admin_key);
        let conflicting_commit = commit_with_keys(competing_proposal, &[("dc-1", &local_key)]);
        assert!(store
            .apply_commit(&conflicting_commit)
            .unwrap_err()
            .contains("conflicts with the locally recorded transition"));
        assert_eq!(store.membership().unwrap().epoch, 1);

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn quorum_freshness_lease_requires_a_current_strict_majority() {
        let (dc_one, key_one) = dc("dc-1", 1);
        let (dc_two, key_two) = dc("dc-2", 2);
        let (dc_three, _) = dc("dc-3", 3);
        let (admin_authority, _) = authority();
        let membership = CatalogMembership {
            schema_version: CATALOG_MEMBERSHIP_SCHEMA_VERSION,
            mesh_id: "engineering".into(),
            epoch: 9,
            dcs: BTreeMap::from([
                (dc_one.dc_id.clone(), dc_one),
                (dc_two.dc_id.clone(), dc_two),
                (dc_three.dc_id.clone(), dc_three),
            ]),
            admin_authority,
        };
        let now = 1_800_000_000;
        let mut lease = CatalogQuorumLease::for_membership(&membership, now).unwrap();
        let signing_bytes = lease.signing_bytes().unwrap();
        lease
            .add_approval(
                &membership,
                QuorumLeaseApproval {
                    dc_id: "dc-1".into(),
                    signature: key_one.sign(&signing_bytes).to_bytes().to_vec(),
                },
            )
            .unwrap();
        assert!(lease.verify_against(&membership, now).is_err());

        lease
            .add_approval(
                &membership,
                QuorumLeaseApproval {
                    dc_id: "dc-2".into(),
                    signature: key_two.sign(&signing_bytes).to_bytes().to_vec(),
                },
            )
            .unwrap();
        lease.verify_against(&membership, now).unwrap();
        assert!(lease
            .add_approval(
                &membership,
                QuorumLeaseApproval {
                    dc_id: "dc-2".into(),
                    signature: key_two.sign(&signing_bytes).to_bytes().to_vec(),
                },
            )
            .is_err());
        assert!(lease
            .verify_against(&membership, now + CATALOG_QUORUM_LEASE_MAX_AGE_SECS)
            .unwrap_err()
            .contains("expired"));

        let mut next_epoch = membership.clone();
        next_epoch.epoch += 1;
        assert!(lease
            .verify_against(&next_epoch, now)
            .unwrap_err()
            .contains("current membership epoch"));

        let mut forged = lease;
        forged.approvals[0].signature[0] ^= 1;
        assert!(forged.verify_against(&membership, now).is_err());
    }

    #[test]
    fn quorum_lease_rejects_excessive_lifetime_and_future_issue_time() {
        let (initial_dc, _) = dc("dc-1", 1);
        let (admin_authority, _) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        let mut lease = CatalogQuorumLease::for_membership(&membership, 100).unwrap();
        lease.expires_at_unix += 1;
        assert!(lease.signing_bytes().is_err());

        let lease = CatalogQuorumLease::for_membership(&membership, 110).unwrap();
        let message = lease.signing_bytes().unwrap();
        let (dc, key) = dc("dc-1", 1);
        assert_eq!(
            dc.signing_public_key,
            membership.dcs["dc-1"].signing_public_key
        );
        let mut signed = lease.clone();
        signed.approvals.push(QuorumLeaseApproval {
            dc_id: "dc-1".into(),
            signature: key.sign(&message).to_bytes().to_vec(),
        });
        assert!(signed
            .verify_against(&membership, 100)
            .unwrap_err()
            .contains("future"));
    }

    #[test]
    fn membership_store_signs_only_its_current_local_dc_lease() {
        let directory = test_directory();
        let path = directory.join("membership.json");
        let store = CatalogMembershipStore::new(&path);
        let (initial_dc, local_key) = dc("dc-1", 1);
        let (admin_authority, _) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        store.initialize(membership.clone(), "dc-1").unwrap();
        let now = 1_800_000_000;
        let mut lease = CatalogQuorumLease::for_membership(&membership, now).unwrap();
        let approval = store.sign_quorum_lease(&lease, &local_key).unwrap();
        lease.add_approval(&membership, approval).unwrap();
        lease.verify_against(&membership, now).unwrap();

        let wrong_key = signing_key(77);
        let next_membership = CatalogMembership {
            epoch: membership.epoch + 1,
            ..membership.clone()
        };
        let stale_lease = CatalogQuorumLease::for_membership(&next_membership, now).unwrap();
        assert!(store.sign_quorum_lease(&stale_lease, &local_key).is_err());
        assert!(store
            .sign_quorum_lease(
                &CatalogQuorumLease::for_membership(&membership, now).unwrap(),
                &wrong_key
            )
            .is_err());

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn journal_records_every_transition_and_detects_hash_tampering() {
        let directory = test_directory();
        let path = directory.join("membership.json");
        let store = CatalogMembershipStore::new(&path);
        let (initial_dc, local_key) = dc("dc-1", 1);
        let (admin_authority, admin_key) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        store.initialize(membership.clone(), "dc-1").unwrap();

        // 1. Initial journal entry exists
        let entries = store.journal().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "bootstrap");
        assert_eq!(entries[0].epoch, 1);
        assert_eq!(entries[0].prev_entry_hash, [0u8; 32]);
        assert_eq!(store.verify_journal_integrity().unwrap(), 1);

        // 2. sign_commit appends entry
        let proposal = proposal_adds_dc(&membership, "dc-2", 2, &admin_key);
        let approval = store.sign_commit_once(&proposal, &local_key).unwrap();
        let entries_after_sign = store.journal().unwrap();
        assert_eq!(entries_after_sign.len(), 2);
        assert_eq!(entries_after_sign[1].action, "sign_commit");
        assert_eq!(entries_after_sign[1].prev_entry_hash, entries[0].entry_hash);

        // 3. apply_commit appends entry
        let commit = CatalogMembershipCommit {
            proposal,
            dc_approvals: vec![approval],
        };
        store.apply_commit(&commit).unwrap();
        let entries_after_apply = store.journal().unwrap();
        assert_eq!(entries_after_apply.len(), 3);
        assert_eq!(entries_after_apply[2].action, "apply_commit");
        assert_eq!(entries_after_apply[2].epoch, 2);
        assert_eq!(
            entries_after_apply[2].prev_entry_hash,
            entries_after_sign[1].entry_hash
        );
        assert_eq!(store.verify_journal_integrity().unwrap(), 3);

        // 4. Tampering detection: modify the file directly and verify rejection
        let raw = fs::read_to_string(&path).unwrap();
        let mut tampered_state: MembershipStoreState = serde_json::from_str(&raw).unwrap();
        tampered_state.journal[1].action = "forged_action".into();
        let tampered_json = serde_json::to_string_pretty(&tampered_state).unwrap();
        fs::write(&path, tampered_json).unwrap();

        let tampered_store = CatalogMembershipStore::new(&path);
        let err = tampered_store.membership().unwrap_err();
        assert!(err.contains("tampering detected") || err.contains("hash chain broken"));

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn backup_and_restore_preserves_membership_and_verifies_checksum() {
        let directory = test_directory();
        let path = directory.join("membership.json");
        let backup_path = directory.join("backup.json");
        let restore_path = directory.join("restored-membership.json");

        let store = CatalogMembershipStore::new(&path);
        let (initial_dc, local_key) = dc("dc-1", 1);
        let (admin_authority, admin_key) = authority();
        let membership =
            CatalogMembership::bootstrap("engineering", initial_dc, admin_authority).unwrap();
        store.initialize(membership.clone(), "dc-1").unwrap();

        let proposal = proposal_adds_dc(&membership, "dc-2", 2, &admin_key);
        let approval = store.sign_commit_once(&proposal, &local_key).unwrap();
        let commit = CatalogMembershipCommit {
            proposal,
            dc_approvals: vec![approval],
        };
        store.apply_commit(&commit).unwrap();

        // Export backup
        let manifest = store.export_backup(&backup_path).unwrap();
        assert_eq!(manifest.epoch, 2);
        assert_eq!(manifest.journal_entries_count, 3);
        assert!(backup_path.exists());

        // Restore to a new location
        let restored_store = CatalogMembershipStore::new(&restore_path);
        let restored_manifest = restored_store
            .restore_from_backup(&backup_path, false)
            .unwrap();
        assert_eq!(restored_manifest.epoch, manifest.epoch);
        assert_eq!(restored_manifest.state_sha256, manifest.state_sha256);

        let restored_membership = restored_store.membership().unwrap();
        assert_eq!(restored_membership.epoch, 2);
        assert_eq!(restored_store.journal().unwrap().len(), 3);
        assert_eq!(restored_store.verify_journal_integrity().unwrap(), 3);

        // Restoring without force to an existing location fails
        assert!(restored_store
            .restore_from_backup(&backup_path, false)
            .is_err());
        // Restoring with force succeeds
        assert!(restored_store
            .restore_from_backup(&backup_path, true)
            .is_ok());

        // Tampered backup payload is rejected
        let corrupt_backup_path = directory.join("corrupt-backup.json");
        let raw = fs::read_to_string(&backup_path).unwrap();
        let mut backup_obj: MembershipBackup = serde_json::from_str(&raw).unwrap();
        backup_obj.state.local_dc_id = "hacked-dc".into();
        fs::write(
            &corrupt_backup_path,
            serde_json::to_string_pretty(&backup_obj).unwrap(),
        )
        .unwrap();

        let target_store = CatalogMembershipStore::new(directory.join("tampered.json"));
        let err = target_store
            .restore_from_backup(&corrupt_backup_path, false)
            .unwrap_err();
        assert!(err.contains("checksum mismatch") || err.contains("integrity violation"));

        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
}
