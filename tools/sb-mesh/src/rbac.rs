//! S&B Sovereign Mesh — Tenant-Scoped Role-Based Access Control (Mesh-RBAC)
//!
//! Binds identities, roles, and granular capability tokens to specific mesh networks.
//! Cryptographically enforced via SBM-TEP tickets and dispatcher silent drops.

use base64::Engine;
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

const MAX_RBAC_FILE_BYTES: u64 = 4 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Capability Constants
// ─────────────────────────────────────────────────────────────────────────────

pub const CAP_TUNNEL_SSH: &str = "tunnel:ssh";
pub const CAP_TUNNEL_ANY: &str = "tunnel:any";
pub const CAP_STREAM_TRANSFER: &str = "stream:transfer";
pub const CAP_CATALOG_REPLICATE: &str = "catalog:replicate";
pub const CAP_CODE_SYNC: &str = "code:sync";
pub const CAP_CODE_VIEW: &str = "code:view";
pub const CAP_MESH_INVITE: &str = "mesh:invite";
pub const CAP_MESH_KRL: &str = "mesh:krl";
pub const CAP_MESH_MANAGE: &str = "mesh:manage";
pub const CAP_TELEMETRY_READ: &str = "telemetry:read";
pub const CAP_ARTIFACT_DOWNLOAD: &str = "artifact:download";

/// Checks if a list of capabilities permits access to a target TCP port
pub fn is_port_permitted(capabilities: &[String], target_port: u16) -> bool {
    let port_specific = format!("tunnel:port:{}", target_port);
    for cap in capabilities {
        if cap == CAP_TUNNEL_ANY {
            return true;
        }
        if target_port == 22 && cap == CAP_TUNNEL_SSH {
            return true;
        }
        if cap == &port_specific {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Roles
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshRole {
    Admin,
    Developer,
    Operator,
    Consumer,
    Auditor,
}

impl MeshRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            MeshRole::Admin => "Admin",
            MeshRole::Developer => "Developer",
            MeshRole::Operator => "Operator",
            MeshRole::Consumer => "Consumer",
            MeshRole::Auditor => "Auditor",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "admin" => Some(MeshRole::Admin),
            "developer" | "dev" => Some(MeshRole::Developer),
            "operator" | "ops" => Some(MeshRole::Operator),
            "consumer" | "client" => Some(MeshRole::Consumer),
            "auditor" | "audit" => Some(MeshRole::Auditor),
            _ => None,
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            MeshRole::Admin => "[ADMIN]",
            MeshRole::Developer => "[DEV]",
            MeshRole::Operator => "[OPS]",
            MeshRole::Consumer => "[CLIENT]",
            MeshRole::Auditor => "[AUDIT]",
        }
    }

    pub fn default_capabilities(&self) -> Vec<String> {
        match self {
            MeshRole::Admin => vec![
                CAP_TUNNEL_SSH.to_string(),
                CAP_STREAM_TRANSFER.to_string(),
                CAP_MESH_INVITE.to_string(),
                CAP_MESH_KRL.to_string(),
                CAP_MESH_MANAGE.to_string(),
                CAP_TELEMETRY_READ.to_string(),
                CAP_ARTIFACT_DOWNLOAD.to_string(),
            ],
            MeshRole::Developer => vec![
                CAP_TUNNEL_SSH.to_string(),
                CAP_STREAM_TRANSFER.to_string(),
                CAP_TELEMETRY_READ.to_string(),
                CAP_ARTIFACT_DOWNLOAD.to_string(),
            ],
            MeshRole::Operator => vec![
                CAP_STREAM_TRANSFER.to_string(),
                CAP_TELEMETRY_READ.to_string(),
                CAP_ARTIFACT_DOWNLOAD.to_string(),
            ],
            MeshRole::Consumer => vec![
                CAP_TELEMETRY_READ.to_string(),
                CAP_ARTIFACT_DOWNLOAD.to_string(),
            ],
            MeshRole::Auditor => vec![CAP_TELEMETRY_READ.to_string()],
        }
    }
}

impl std::fmt::Display for MeshRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh Groups (Active Directory-style Security Groups)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshGroup {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub created_at: u64,
}

impl MeshGroup {
    pub fn new(name: &str, description: &str, capabilities: Vec<String>) -> Self {
        Self {
            name: name.trim().to_lowercase(),
            description: description.to_string(),
            capabilities,
            created_at: Utc::now().timestamp() as u64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit Log (AD-style Event Logging for Security Auditing)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshAuditEntry {
    pub timestamp: u64,
    pub action: String, // e.g. "member_added", "member_revoked", "joined_via_invite", "ticket_issued"
    pub actor: String,  // Who triggered the action
    pub target: String, // Target user / node
    pub details: String,
}

impl MeshAuditEntry {
    pub fn new(action: &str, actor: &str, target: &str, details: &str) -> Self {
        Self {
            timestamp: Utc::now().timestamp() as u64,
            action: action.to_string(),
            actor: actor.to_string(),
            target: target.to_string(),
            details: details.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NTFS-inspired Sovereign ACL & Machine Privilege Model
// ─────────────────────────────────────────────────────────────────────────────

/// Granulare Rechte-Maske für Ressourcen & Files (inspiriert von NTFS File Rights)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignPermissions {
    pub read: bool,           // Datei lesen / Verzeichnis auflisten / Telemetrie abfragen
    pub write: bool,          // Schreiben, Überschreiben, Anhängen
    pub execute: bool,        // Skripte / Binaries ausführen
    pub delete: bool,         // Datei, Verzeichnis oder Ressource löschen
    pub take_ownership: bool, // Rechte an Dritte delegieren / ACL verwalten
}

impl SovereignPermissions {
    pub fn none() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
            delete: false,
            take_ownership: false,
        }
    }

    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
            delete: false,
            take_ownership: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            delete: false,
            take_ownership: false,
        }
    }

    pub fn modify() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            delete: true,
            take_ownership: false,
        }
    }

    pub fn full_control() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            delete: true,
            take_ownership: true,
        }
    }

    pub fn allows(&self, required: &SovereignPermissions) -> bool {
        (!required.read || self.read)
            && (!required.write || self.write)
            && (!required.execute || self.execute)
            && (!required.delete || self.delete)
            && (!required.take_ownership || self.take_ownership)
    }
}

/// Art des ACE-Eintrags: Gewähren (Allow) oder Explizites Verbot (Deny)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AceType {
    Allow,
    Deny, // Explizites Verbot (hat immer Vorrang vor Allow!)
}

/// Ein einzelner Access Control Entry (ACE)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SovereignAce {
    pub principal: String, // z. B. "@alice" (User) oder "@developers" (Group)
    pub ace_type: AceType, // Allow oder Deny
    pub permissions: SovereignPermissions,
    pub inherit: bool, // Vererbung an untergeordnete Pfade aktiv?
}

/// Die Access Control List (ACL) für Pfade, Shares und Ressourcen
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SovereignAcl {
    pub inherit_from_parent: bool,
    pub entries: Vec<SovereignAce>,
}

impl SovereignAcl {
    pub fn new(inherit_from_parent: bool) -> Self {
        Self {
            inherit_from_parent,
            entries: Vec::new(),
        }
    }

    pub fn add_ace(
        &mut self,
        principal: &str,
        ace_type: AceType,
        permissions: SovereignPermissions,
        inherit: bool,
    ) {
        let clean = principal.trim().to_lowercase();
        self.entries.push(SovereignAce {
            principal: clean,
            ace_type,
            permissions,
            inherit,
        });
    }

    /// Evaluiert Zugriffsrechte nach kanonischer NTFS-Regel:
    /// 1. Explizites Deny schlägt ALLES -> sofortiger Abbruch (Access Denied).
    /// 2. Explizites Allow des Nutzers wird kumuliert.
    /// 3. Gruppen-Allows werden kumuliert.
    /// 4. Falls geforderte Rechte erfüllt sind -> Allow, sonst Deny (Default-Deny).
    pub fn check_access(
        &self,
        user_name: &str,
        user_groups: &[String],
        required: &SovereignPermissions,
    ) -> bool {
        let u_clean = format!(
            "@{}",
            user_name.trim().trim_start_matches('@').to_lowercase()
        );
        let g_cleans: Vec<String> = user_groups
            .iter()
            .map(|g| format!("@{}", g.trim().trim_start_matches('@').to_lowercase()))
            .collect();

        // 1. PHASE: DENY CHECK (Hat ein Deny-Eintrag für User oder eine Gruppe Relevanz?)
        for ace in &self.entries {
            if ace.ace_type == AceType::Deny {
                let matches_principal =
                    ace.principal == u_clean || g_cleans.contains(&ace.principal);
                if matches_principal
                    && ((required.read && ace.permissions.read)
                        || (required.write && ace.permissions.write)
                        || (required.execute && ace.permissions.execute)
                        || (required.delete && ace.permissions.delete)
                        || (required.take_ownership && ace.permissions.take_ownership))
                    {
                        return false; // Hard Deny!
                    }
            }
        }

        // 2. PHASE: ALLOW ACCUMULATION
        let mut accumulated = SovereignPermissions::none();
        for ace in &self.entries {
            if ace.ace_type == AceType::Allow {
                let matches_principal =
                    ace.principal == u_clean || g_cleans.contains(&ace.principal);
                if matches_principal {
                    accumulated.read |= ace.permissions.read;
                    accumulated.write |= ace.permissions.write;
                    accumulated.execute |= ace.permissions.execute;
                    accumulated.delete |= ace.permissions.delete;
                    accumulated.take_ownership |= ace.permissions.take_ownership;
                }
            }
        }

        accumulated.allows(required)
    }
}

/// Host- und Rechner-Privilegien für Compute, Steuerung und Schatten-PC
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MachinePrivilege {
    /// Read-Only: Logs ansehen, Systemstatus abfragen, keine Prozesse modifizieren
    View,
    /// Unprivilegierter App-Nutzer: Build-Tasks, Entwicklung, lokale User-Workspace Rechte
    User,
    /// Service-Operator: Dienste neustarten (systemd / sc.exe), Container steuern, Deployments
    Operator,
    /// Vollzugriff: Volle Administrator-/Root-Rechte, ConPTY-Takeover, Schatten-PC Fernsteuerung
    Full,
}

impl MachinePrivilege {
    pub fn as_str(&self) -> &'static str {
        match self {
            MachinePrivilege::View => "View",
            MachinePrivilege::User => "User",
            MachinePrivilege::Operator => "Operator",
            MachinePrivilege::Full => "Full",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "view" | "read" | "audit" => Some(MachinePrivilege::View),
            "user" | "standard" => Some(MachinePrivilege::User),
            "operator" | "ops" | "service" => Some(MachinePrivilege::Operator),
            "full" | "root" | "admin" => Some(MachinePrivilege::Full),
            _ => None,
        }
    }

    pub fn allows(&self, required: MachinePrivilege) -> bool {
        *self >= required
    }
}

impl std::fmt::Display for MachinePrivilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Dedizierte Berechtigung eines Nutzers oder einer Gruppe auf einer bestimmten Maschine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostGrant {
    pub principal: String,  // z. B. "@alice" oder "@developers"
    pub machine_id: String, // z. B. "node-prod-db" oder Callsign "prod-db"
    pub privilege: MachinePrivilege,
    pub created_at: u64,
    pub expires_at: Option<u64>, // Optionales ephemeres Zeitlimit
}

// ─────────────────────────────────────────────────────────────────────────────
// Sovereign Invite Token (Administrator-Approved Onboarding)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshInviteToken {
    pub token_id: String,
    pub mesh_name: String,
    pub user_name: String,
    pub role: MeshRole,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub server_endpoint: String,
    pub server_pubkey: String,
    pub swarm_topic: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_uses: u32,
    pub current_uses: u32,
    pub revoked: bool,
    pub signature: String, // Invite: 256-bit hex secret. Stored server-side: SHA-256 digest of it.
}

impl MeshInviteToken {
    /// Persists an invite URI to `~/.sb-mesh/invites/<token_id>.uri` (0600 on Unix, never overwritten).
    // CVE-Threat: Secret disclosure via terminal scrollback, CI logs, chat transcripts.
    // Analysis: The URI is a bearer credential; stdout is routinely captured.
    // Hardening: Write to an owner-only file (create_new => no symlink/TOCTOU clobber) instead.
    pub fn write_uri_file(&self, uri: &str) -> Result<std::path::PathBuf, String> {
        use std::io::Write;
        let dir = dirs::home_dir()
            .map(|h| h.join(".sb-mesh").join("invites"))
            .ok_or("Home-Verzeichnis nicht gefunden")?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("{}.uri", self.token_id));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(|e| e.to_string())?;
        f.write_all(uri.as_bytes()).map_err(|e| e.to_string())?;
        Ok(path)
    }
    /// 256-bit invite secret (hex). Carried only inside the URI handed to the invitee.
    pub fn new_secret() -> String {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// SHA-256 digest (hex) of an invite secret; this is all the server persists.
    pub fn secret_digest(secret: &str) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(secret.as_bytes())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Copy for server-side storage: the secret in `signature` is replaced by its digest.
    pub fn to_stored(&self) -> Self {
        let mut stored = self.clone();
        stored.signature = Self::secret_digest(&self.signature);
        stored
    }

    // CVE-Threat: Invite forgery / brute force of token ids; timing oracle on secret comparison.
    // Analysis: token_id has only 32 bits; the former `sig-<id>` was derivable by anyone.
    // Hardening: Redemption requires the 256-bit secret; server stores only its digest and
    //            compares in constant time (digest-vs-digest, no early exit).
    pub fn secret_matches(&self, presented_secret: &str) -> bool {
        let a = Self::secret_digest(presented_secret);
        let b = self.signature.as_bytes();
        a.len() == b.len()
            && a.as_bytes()
                .iter()
                .zip(b)
                .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                == 0
    }

    pub fn is_valid(&self, now: u64) -> bool {
        if self.revoked {
            return false;
        }
        if now >= self.expires_at {
            return false;
        }
        if self.max_uses > 0 && self.current_uses >= self.max_uses {
            return false;
        }
        true
    }

    /// Encode as compact base64 URL-safe invite string with sbm-invite:// schema
    pub fn encode_uri(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let b64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("sbm-invite://{}", b64)
    }

    /// Decode from URI string or raw base64
    pub fn decode_uri(uri: &str) -> Result<Self, String> {
        let clean = uri.trim();
        let payload = if let Some(stripped) = clean.strip_prefix("sbm-invite://") {
            stripped
        } else {
            clean
        };
        let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::prelude::BASE64_STANDARD.decode(payload))
            .map_err(|e| format!("Ungültiges Invite-Format (Base64 Fehler): {}", e))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("Ungültiges Invite-JSON: {}", e))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh Member
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshMember {
    pub name: String,
    pub pubkey: String,
    pub node_id: String,
    pub mesh_name: String,
    pub role: MeshRole,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_reason: Option<String>,
}

impl MeshMember {
    pub fn new(name: &str, pubkey: &str, node_id: &str, mesh_name: &str, role: MeshRole) -> Self {
        let now = Utc::now().timestamp() as u64;
        let capabilities = role.default_capabilities();
        Self {
            name: name.to_string(),
            pubkey: pubkey.trim().to_string(),
            node_id: node_id.to_string(),
            mesh_name: mesh_name.to_string(),
            role,
            groups: Vec::new(),
            capabilities,
            created_at: now,
            expires_at: None,
            revoked: false,
            revoked_reason: None,
        }
    }

    pub fn is_active(&self, now: u64) -> bool {
        if self.revoked {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if now >= exp {
                return false;
            }
        }
        true
    }

    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }

    pub fn can_access_port(&self, target_port: u16) -> bool {
        is_port_permitted(&self.capabilities, target_port)
    }

    pub fn revoke(&mut self, reason: &str) {
        self.revoked = true;
        self.revoked_reason = Some(reason.to_string());
    }

    pub fn restore(&mut self) {
        self.revoked = false;
        self.revoked_reason = None;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh RBAC Store
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinRequestStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshJoinRequest {
    pub request_id: String,
    pub name: String,
    pub pubkey: String,
    pub node_id: String,
    pub mesh_name: String,
    pub role: MeshRole,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub created_at: u64,
    pub status: JoinRequestStatus,
    #[serde(default)]
    pub decided_at: Option<u64>,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub denial_reason: Option<String>,
}

impl MeshJoinRequest {
    pub fn new(
        name: &str,
        pubkey: &str,
        node_id: &str,
        mesh_name: &str,
        role: MeshRole,
        groups: Vec<String>,
        capabilities: Vec<String>,
    ) -> Self {
        let mut random_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random_id);
        Self {
            request_id: random_id.iter().map(|byte| format!("{byte:02x}")).collect(),
            name: name.to_string(),
            pubkey: pubkey.trim().to_string(),
            node_id: node_id.to_string(),
            mesh_name: mesh_name.to_string(),
            role,
            groups,
            capabilities,
            created_at: Utc::now().timestamp() as u64,
            status: JoinRequestStatus::Pending,
            decided_at: None,
            decided_by: None,
            denial_reason: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeshRbacStore {
    pub mesh_name: String,
    #[serde(default)]
    pub members: Vec<MeshMember>,
    #[serde(default)]
    pub groups: Vec<MeshGroup>,
    #[serde(default)]
    pub invites: Vec<MeshInviteToken>,
    #[serde(default)]
    pub audit_log: Vec<MeshAuditEntry>,
    #[serde(default)]
    pub host_grants: Vec<HostGrant>,
    #[serde(default)]
    pub resource_acls: std::collections::HashMap<String, SovereignAcl>,
    #[serde(default)]
    pub join_requests: Vec<MeshJoinRequest>,
}

impl MeshRbacStore {
    pub fn new(mesh_name: &str) -> Self {
        Self {
            mesh_name: mesh_name.to_string(),
            members: Vec::new(),
            groups: Self::default_groups(),
            invites: Vec::new(),
            audit_log: Vec::new(),
            host_grants: Vec::new(),
            resource_acls: std::collections::HashMap::new(),
            join_requests: Vec::new(),
        }
    }

    pub fn default_groups() -> Vec<MeshGroup> {
        vec![
            MeshGroup::new(
                "developers",
                "Software engineers & developers with SSH and local dev port access",
                vec![CAP_TUNNEL_SSH.to_string(), CAP_STREAM_TRANSFER.to_string()],
            ),
            MeshGroup::new(
                "operators",
                "Operations staff with stream transfer, telemetry and artifact access",
                vec![
                    CAP_STREAM_TRANSFER.to_string(),
                    CAP_TELEMETRY_READ.to_string(),
                    CAP_ARTIFACT_DOWNLOAD.to_string(),
                ],
            ),
            MeshGroup::new(
                "auditors",
                "Compliance & security auditors with read-only telemetry access",
                vec![CAP_TELEMETRY_READ.to_string()],
            ),
        ]
    }

    pub fn storage_path(mesh_name: &str) -> Result<PathBuf, String> {
        Ok(crate::state::MeshStatePaths::for_mesh(mesh_name)?.rbac)
    }

    pub fn load_existing_at(path: &std::path::Path, expected_mesh: &str) -> Result<Self, String> {
        // CVE-Threat: Stale or substituted RBAC state could preserve access after revocation.
        // Analysis: The authorization path must not create defaults or accept linked/oversized files.
        // Hardening: Read one bounded regular file, reject symlinks, and verify its mesh binding.
        crate::state::normalize_mesh_name(expected_mesh)?;
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("Mesh-RBAC-Datei konnte nicht geprüft werden: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("Mesh-RBAC-Datei darf kein symbolischer Link sein".to_string());
        }
        if !metadata.is_file() {
            return Err("Mesh-RBAC-Pfad muss eine reguläre Datei sein".to_string());
        }
        if metadata.len() > MAX_RBAC_FILE_BYTES {
            return Err(format!(
                "Mesh-RBAC-Datei überschreitet das Limit von {MAX_RBAC_FILE_BYTES} Bytes"
            ));
        }

        let mut file = fs::File::open(path)
            .map_err(|error| format!("Mesh-RBAC-Datei konnte nicht geöffnet werden: {error}"))?;
        let mut content = Vec::new();
        file.by_ref()
            .take(MAX_RBAC_FILE_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|error| format!("Mesh-RBAC-Datei konnte nicht gelesen werden: {error}"))?;
        if content.len() as u64 > MAX_RBAC_FILE_BYTES {
            return Err(format!(
                "Mesh-RBAC-Datei überschreitet das Limit von {MAX_RBAC_FILE_BYTES} Bytes"
            ));
        }

        let store: Self = serde_json::from_slice(&content)
            .map_err(|error| format!("Mesh-RBAC-Datei enthält ungültiges JSON: {error}"))?;
        if store.mesh_name != expected_mesh {
            return Err("Mesh-RBAC-Datei gehört zu einem anderen Mesh".to_string());
        }
        Ok(store)
    }

    pub fn has_active_member_for_key(
        &self,
        expected_mesh: &str,
        public_key: &str,
        now: u64,
    ) -> Result<bool, String> {
        // CVE-Threat: Duplicate or cross-mesh member records could make revocation ambiguous.
        // Analysis: Authorization must match one identity record in this mesh and honor expiry.
        // Hardening: Reject ambiguity or mismatched bindings and evaluate revoked/expiry state.
        if self.mesh_name != expected_mesh {
            return Err("Mesh-RBAC-Speicher gehört zu einem anderen Mesh".to_string());
        }
        let mut matching_members = self
            .members
            .iter()
            .filter(|member| member.pubkey == public_key || member.pubkey.trim() == public_key);
        let Some(member) = matching_members.next() else {
            return Ok(false);
        };
        if matching_members.next().is_some() {
            return Err(
                "Mesh-RBAC enthält mehrere Mitglieder mit demselben Public Key".to_string(),
            );
        }
        if member.mesh_name != expected_mesh
            || crate::identity::NodeIdentity::derive_node_id_from_pubkey(public_key)
                != member.node_id
        {
            return Err(
                "Mesh-RBAC-Mitglied ist nicht an diese Mesh-Identität gebunden".to_string(),
            );
        }
        Ok(member.is_active(now))
    }

    pub fn load_or_create(mesh_name: &str) -> Result<Self, String> {
        let paths = crate::state::MeshStatePaths::for_mesh(mesh_name)?;
        paths.ensure()?;
        let path = Self::storage_path(mesh_name)?;
        if path.exists() {
            let data = fs::read_to_string(&path)
                .map_err(|e| format!("Fehler beim Lesen von {:?}: {}", path, e))?;
            let mut store: Self = serde_json::from_str(&data)
                .map_err(|e| format!("Ungültiges RBAC-JSON in {:?}: {}", path, e))?;
            if store.groups.is_empty() {
                store.groups = Self::default_groups();
            }
            Ok(store)
        } else {
            let store = Self::new(mesh_name);
            store.save()?;
            Ok(store)
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let paths = crate::state::MeshStatePaths::for_mesh(&self.mesh_name)?;
        paths.ensure()?;
        let path = Self::storage_path(&self.mesh_name)?;
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Fehler beim Serialisieren von RBAC: {}", e))?;
        fs::write(&path, data).map_err(|e| format!("Fehler beim Schreiben von {:?}: {}", path, e))
    }

    pub fn log_event(&mut self, action: &str, actor: &str, target: &str, details: &str) {
        self.audit_log
            .push(MeshAuditEntry::new(action, actor, target, details));
        // Keep audit log to last 500 entries
        if self.audit_log.len() > 500 {
            self.audit_log.drain(0..self.audit_log.len() - 500);
        }
    }

    pub fn add_or_update(&mut self, mut member: MeshMember) {
        // Automatically merge capabilities from member's assigned groups
        let group_caps = self.effective_group_capabilities(&member.groups);
        for cap in group_caps {
            if !member.capabilities.contains(&cap) {
                member.capabilities.push(cap);
            }
        }

        if let Some(idx) = self
            .members
            .iter()
            .position(|m| m.pubkey == member.pubkey || m.name == member.name)
        {
            self.members[idx] = member;
        } else {
            self.members.push(member);
        }
    }

    pub fn effective_group_capabilities(&self, group_names: &[String]) -> Vec<String> {
        let mut caps = Vec::new();
        for g_name in group_names {
            let clean = g_name.trim().to_lowercase();
            if let Some(g) = self.groups.iter().find(|grp| grp.name == clean) {
                for c in &g.capabilities {
                    if !caps.contains(c) {
                        caps.push(c.clone());
                    }
                }
            }
        }
        caps
    }

    pub fn remove(&mut self, identifier: &str) -> bool {
        let clean = identifier.trim();
        let initial_len = self.members.len();
        self.members
            .retain(|m| m.name != clean && m.pubkey != clean && m.node_id != clean);
        let removed = self.members.len() < initial_len;
        if removed {
            self.log_event("member_removed", "admin", clean, "Member removed from mesh");
        }
        removed
    }

    pub fn revoke(&mut self, identifier: &str, reason: &str) -> bool {
        let clean = identifier.trim();
        if let Some(m) = self
            .members
            .iter_mut()
            .find(|m| m.name == clean || m.pubkey == clean || m.node_id == clean)
        {
            m.revoke(reason);
            self.log_event("member_revoked", "admin", clean, reason);
            true
        } else {
            false
        }
    }

    pub fn find(&self, identifier: &str) -> Option<&MeshMember> {
        let clean = identifier.trim();
        self.members
            .iter()
            .find(|m| m.name == clean || m.pubkey == clean || m.node_id == clean)
    }

    pub fn find_by_pubkey(&self, pubkey: &str) -> Option<&MeshMember> {
        let clean = pubkey.trim();
        self.members.iter().find(|m| m.pubkey == clean)
    }

    pub fn active_members(&self) -> Vec<&MeshMember> {
        let now = Utc::now().timestamp() as u64;
        self.members.iter().filter(|m| m.is_active(now)).collect()
    }

    // ──────────────────────────────── Group Methods ────────────────────────────────

    pub fn add_or_update_group(&mut self, group: MeshGroup) {
        if let Some(idx) = self.groups.iter().position(|g| g.name == group.name) {
            self.groups[idx] = group;
        } else {
            self.groups.push(group);
        }
    }

    pub fn remove_group(&mut self, group_name: &str) -> bool {
        let clean = group_name.trim().to_lowercase();
        let init_len = self.groups.len();
        self.groups.retain(|g| g.name != clean);
        self.groups.len() < init_len
    }

    // ──────────────────────────────── Invite Methods ───────────────────────────────

    pub fn add_invite(&mut self, invite: MeshInviteToken) {
        self.log_event(
            "invite_created",
            "admin",
            &invite.user_name,
            &format!("Token ID: {}", invite.token_id),
        );
        self.invites.push(invite);
    }

    pub fn find_invite_mut(&mut self, token_id: &str) -> Option<&mut MeshInviteToken> {
        self.invites.iter_mut().find(|i| i.token_id == token_id)
    }

    pub fn add_join_request(&mut self, request: MeshJoinRequest) -> bool {
        if self.join_requests.iter().any(|existing| {
            existing.pubkey == request.pubkey && existing.status == JoinRequestStatus::Pending
        }) {
            return false;
        }

        self.log_event(
            "join_requested",
            &request.name,
            &request.pubkey,
            &format!("Request ID: {}", request.request_id),
        );
        self.join_requests.push(request);
        true
    }

    pub fn approve_join_request(&mut self, request_id: &str, actor: &str) -> Result<bool, String> {
        let Some(index) = self
            .join_requests
            .iter()
            .position(|request| request.request_id == request_id)
        else {
            return Ok(false);
        };
        let request = self.join_requests[index].clone();
        if request.status != JoinRequestStatus::Pending {
            return Ok(false);
        }
        if request.mesh_name != self.mesh_name
            || crate::identity::NodeIdentity::derive_node_id_from_pubkey(&request.pubkey)
                != request.node_id
        {
            return Err("Join request identity or mesh binding is invalid".to_string());
        }

        let mut member = MeshMember::new(
            &request.name,
            &request.pubkey,
            &request.node_id,
            &request.mesh_name,
            request.role,
        );
        member.capabilities = request.capabilities.clone();
        member.groups = request.groups.clone();
        self.add_or_update(member);

        let decision_time = Utc::now().timestamp() as u64;
        let stored_request = &mut self.join_requests[index];
        stored_request.status = JoinRequestStatus::Approved;
        stored_request.decided_at = Some(decision_time);
        stored_request.decided_by = Some(actor.to_string());
        self.log_event(
            "join_approved",
            actor,
            &request.pubkey,
            &format!("Request ID: {}", request.request_id),
        );
        Ok(true)
    }

    pub fn deny_join_request(&mut self, request_id: &str, actor: &str, reason: &str) -> bool {
        let Some(request) = self
            .join_requests
            .iter_mut()
            .find(|request| request.request_id == request_id)
        else {
            return false;
        };
        if request.status != JoinRequestStatus::Pending {
            return false;
        }
        let pubkey = request.pubkey.clone();
        request.status = JoinRequestStatus::Denied;
        request.decided_at = Some(Utc::now().timestamp() as u64);
        request.decided_by = Some(actor.to_string());
        request.denial_reason = Some(reason.to_string());
        self.log_event("join_denied", actor, &pubkey, reason);
        true
    }

    pub fn revoke_invite(&mut self, token_id: &str) -> bool {
        let user_name_opt =
            if let Some(inv) = self.invites.iter_mut().find(|i| i.token_id == token_id) {
                inv.revoked = true;
                Some(inv.user_name.clone())
            } else {
                None
            };

        if let Some(user_name) = user_name_opt {
            self.log_event(
                "invite_revoked",
                "admin",
                &user_name,
                &format!("Token: {}", token_id),
            );
            true
        } else {
            false
        }
    }

    // ──────────────────────────── Host Grants (Machine Access) ───────────────────────────

    pub fn grant_host_access(
        &mut self,
        principal: &str,
        machine_id: &str,
        privilege: MachinePrivilege,
        ttl_seconds: Option<u64>,
    ) {
        let clean_p = format!(
            "@{}",
            principal.trim().trim_start_matches('@').to_lowercase()
        );
        let clean_m = machine_id.trim().to_lowercase();
        let now = Utc::now().timestamp() as u64;
        let expires_at = ttl_seconds.map(|s| now + s);

        self.host_grants
            .retain(|g| !(g.principal == clean_p && g.machine_id == clean_m));
        self.host_grants.push(HostGrant {
            principal: clean_p.clone(),
            machine_id: clean_m.clone(),
            privilege,
            created_at: now,
            expires_at,
        });

        self.log_event(
            "host_grant_added",
            "admin",
            &clean_m,
            &format!("Principal {} -> Privilege {}", clean_p, privilege),
        );
    }

    pub fn revoke_host_access(&mut self, principal: &str, machine_id: &str) -> bool {
        let clean_p = format!(
            "@{}",
            principal.trim().trim_start_matches('@').to_lowercase()
        );
        let clean_m = machine_id.trim().to_lowercase();
        let initial_len = self.host_grants.len();
        self.host_grants
            .retain(|g| !(g.principal == clean_p && g.machine_id == clean_m));
        let removed = self.host_grants.len() < initial_len;
        if removed {
            self.log_event(
                "host_grant_revoked",
                "admin",
                &clean_m,
                &format!("Principal {}", clean_p),
            );
        }
        removed
    }

    /// Prüft das effektive MachinePrivilege eines Nutzers auf einer bestimmten Maschine
    pub fn evaluate_machine_privilege(
        &self,
        user_name: &str,
        user_groups: &[String],
        machine_id: &str,
    ) -> Option<MachinePrivilege> {
        let u_clean = format!(
            "@{}",
            user_name.trim().trim_start_matches('@').to_lowercase()
        );
        let g_cleans: Vec<String> = user_groups
            .iter()
            .map(|g| format!("@{}", g.trim().trim_start_matches('@').to_lowercase()))
            .collect();
        let m_clean = machine_id.trim().to_lowercase();
        let now = Utc::now().timestamp() as u64;

        let mut max_privilege: Option<MachinePrivilege> = None;

        for grant in &self.host_grants {
            if grant.machine_id == m_clean {
                if let Some(exp) = grant.expires_at {
                    if now >= exp {
                        continue; // Grant expired
                    }
                }

                if grant.principal == u_clean || g_cleans.contains(&grant.principal) {
                    if let Some(cur) = max_privilege {
                        if grant.privilege > cur {
                            max_privilege = Some(grant.privilege);
                        }
                    } else {
                        max_privilege = Some(grant.privilege);
                    }
                }
            }
        }

        max_privilege
    }

    // ──────────────────────────── Resource ACLs (Files & Shares) ───────────────────────────

    pub fn set_resource_acl(&mut self, resource_path: &str, acl: SovereignAcl) {
        let clean = resource_path.trim().to_lowercase();
        self.resource_acls.insert(clean.clone(), acl);
        self.log_event("acl_updated", "admin", &clean, "Updated resource ACL");
    }

    pub fn get_resource_acl(&self, resource_path: &str) -> Option<&SovereignAcl> {
        let clean = resource_path.trim().to_lowercase();
        self.resource_acls.get(&clean)
    }

    pub fn check_resource_access(
        &self,
        resource_path: &str,
        user_name: &str,
        user_groups: &[String],
        required: &SovereignPermissions,
    ) -> bool {
        let clean = resource_path.trim().to_lowercase();
        if let Some(acl) = self.resource_acls.get(&clean) {
            acl.check_access(user_name, user_groups, required)
        } else {
            false // Default-Deny: Kein ACL-Eintrag = Kein Zugriff
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_secret_roundtrip() {
        let secret = MeshInviteToken::new_secret();
        assert_eq!(secret.len(), 64);
        let mut t = MeshInviteToken::decode_uri(
            &MeshInviteToken {
                token_id: "inv-1".into(),
                mesh_name: "m".into(),
                user_name: "u".into(),
                role: MeshRole::Developer,
                groups: vec![],
                capabilities: vec![],
                server_endpoint: "e".into(),
                server_pubkey: "k".into(),
                swarm_topic: "s".into(),
                created_at: 0,
                expires_at: 1,
                max_uses: 1,
                current_uses: 0,
                revoked: false,
                signature: secret.clone(),
            }
            .encode_uri(),
        )
        .unwrap();
        let stored = t.to_stored();
        assert!(stored.secret_matches(&secret));
        assert!(!stored.secret_matches("sig-inv-1"));
        t.signature = "x".into();
        assert!(!stored.secret_matches(&t.signature));
    }

    #[test]
    fn test_role_default_capabilities() {
        let admin = MeshRole::Admin;
        assert!(admin
            .default_capabilities()
            .contains(&CAP_TUNNEL_SSH.to_string()));
        assert!(admin
            .default_capabilities()
            .contains(&CAP_MESH_KRL.to_string()));
        assert!(!admin
            .default_capabilities()
            .contains(&CAP_TUNNEL_ANY.to_string()));

        let dev = MeshRole::Developer;
        assert!(dev
            .default_capabilities()
            .contains(&CAP_TUNNEL_SSH.to_string()));
        assert!(!dev
            .default_capabilities()
            .contains(&CAP_MESH_KRL.to_string()));
        assert!(!dev
            .default_capabilities()
            .contains(&CAP_TUNNEL_ANY.to_string()));

        let consumer = MeshRole::Consumer;
        assert!(!consumer
            .default_capabilities()
            .contains(&CAP_TUNNEL_SSH.to_string()));
        assert!(consumer
            .default_capabilities()
            .contains(&CAP_ARTIFACT_DOWNLOAD.to_string()));
    }

    #[test]
    fn test_port_permission_matrix() {
        let dev_caps = vec![CAP_TUNNEL_SSH.to_string(), "tunnel:port:8080".to_string()];
        assert!(is_port_permitted(&dev_caps, 22));
        assert!(is_port_permitted(&dev_caps, 8080));
        assert!(!is_port_permitted(&dev_caps, 5432));

        let admin_caps = vec![CAP_TUNNEL_ANY.to_string()];
        assert!(is_port_permitted(&admin_caps, 22));
        assert!(is_port_permitted(&admin_caps, 5432));
        assert!(is_port_permitted(&admin_caps, 9000));
    }

    #[test]
    fn test_member_lifecycle_and_revocation() {
        let mut member = MeshMember::new(
            "alice",
            "alice_pubkey_123",
            "sbm-0x123",
            "dev-mesh",
            MeshRole::Developer,
        );

        let now = Utc::now().timestamp() as u64;
        assert!(member.is_active(now));
        assert!(member.can_access_port(22));

        // Revoke
        member.revoke("Compromised key");
        assert!(!member.is_active(now));

        // Restore
        member.restore();
        assert!(member.is_active(now));

        // Expiration
        member.expires_at = Some(now - 10);
        assert!(!member.is_active(now));
    }

    #[test]
    fn object_access_membership_uses_fresh_mesh_bound_rbac_state() {
        let identity = crate::identity::NodeIdentity::generate();
        let mesh_name = "access-test";
        let mut store = MeshRbacStore::new(mesh_name);
        store.add_or_update(MeshMember::new(
            "peer",
            &identity.wireguard_pubkey,
            &identity.node_id,
            mesh_name,
            MeshRole::Consumer,
        ));

        let test_dir = std::env::temp_dir().join(format!(
            "sbm_rbac_access_{}_{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&test_dir).unwrap();
        let path = test_dir.join("rbac.json");
        fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();

        let loaded = MeshRbacStore::load_existing_at(&path, mesh_name).unwrap();
        let now = Utc::now().timestamp() as u64;
        assert!(loaded
            .has_active_member_for_key(mesh_name, &identity.wireguard_pubkey, now)
            .unwrap());

        store.revoke(&identity.node_id, "test revocation");
        fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();
        let reloaded = MeshRbacStore::load_existing_at(&path, mesh_name).unwrap();
        assert!(!reloaded
            .has_active_member_for_key(mesh_name, &identity.wireguard_pubkey, now)
            .unwrap());
        assert!(reloaded
            .has_active_member_for_key("another-mesh", &identity.wireguard_pubkey, now)
            .is_err());

        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_store_operations() {
        let mut store = MeshRbacStore::new("test-mesh");
        let member = MeshMember::new(
            "bob",
            "bob_pubkey_456",
            "sbm-0x456",
            "test-mesh",
            MeshRole::Operator,
        );

        store.add_or_update(member);
        assert_eq!(store.members.len(), 1);
        assert!(store.find("bob").is_some());
        assert!(store.find_by_pubkey("bob_pubkey_456").is_some());

        assert!(store.revoke("bob", "Left project"));
        assert!(!store
            .find("bob")
            .unwrap()
            .is_active(Utc::now().timestamp() as u64));

        assert!(store.remove("bob"));
        assert_eq!(store.members.len(), 0);
    }

    #[test]
    fn join_request_stays_unprivileged_until_approved() {
        let identity = crate::identity::NodeIdentity::generate();
        let mut store = MeshRbacStore::new("test-mesh");
        let request = MeshJoinRequest::new(
            "alice",
            &identity.wireguard_pubkey,
            &identity.node_id,
            "test-mesh",
            MeshRole::Developer,
            vec!["developers".to_string()],
            vec!["tunnel:ssh".to_string()],
        );
        let request_id = request.request_id.clone();

        assert!(store.add_join_request(request.clone()));
        assert!(!store.add_join_request(request));
        assert!(store.find_by_pubkey(&identity.wireguard_pubkey).is_none());
        assert!(store
            .approve_join_request(&request_id, "mesh-admin")
            .unwrap());

        let member = store
            .find_by_pubkey(&identity.wireguard_pubkey)
            .expect("approved peer becomes a member");
        assert_eq!(member.node_id, identity.node_id);
        assert_eq!(member.groups, vec!["developers".to_string()]);
        assert_eq!(
            member.capabilities,
            vec!["tunnel:ssh".to_string(), "stream:transfer".to_string()]
        );
        assert_eq!(store.join_requests[0].status, JoinRequestStatus::Approved);
        assert!(!store
            .approve_join_request(&request_id, "mesh-admin")
            .unwrap());
    }

    #[test]
    fn join_request_approval_rejects_identity_mismatch_and_denial_is_terminal() {
        let identity = crate::identity::NodeIdentity::generate();
        let mut store = MeshRbacStore::new("test-mesh");
        let mut invalid_request = MeshJoinRequest::new(
            "mallory",
            &identity.wireguard_pubkey,
            "sbm-0x00000000",
            "test-mesh",
            MeshRole::Admin,
            Vec::new(),
            Vec::new(),
        );
        let invalid_id = invalid_request.request_id.clone();
        store.add_join_request(invalid_request.clone());
        assert!(store
            .approve_join_request(&invalid_id, "mesh-admin")
            .is_err());
        assert!(store.members.is_empty());

        invalid_request.name = "bob".to_string();
        invalid_request.node_id = identity.node_id.clone();
        let mut denied_store = MeshRbacStore::new("test-mesh");
        let denied_id = invalid_request.request_id.clone();
        denied_store.add_join_request(invalid_request);
        assert!(denied_store.deny_join_request(&denied_id, "mesh-admin", "Not recognized"));
        assert!(!denied_store
            .approve_join_request(&denied_id, "mesh-admin")
            .unwrap());
        assert!(denied_store.members.is_empty());
    }

    #[test]
    fn test_mesh_group_capability_inheritance() {
        let mut store = MeshRbacStore::new("test-mesh");
        let custom_group = MeshGroup::new(
            "database-admins",
            "DB Team",
            vec!["tunnel:port:5432".to_string()],
        );
        store.add_or_update_group(custom_group);

        let mut member = MeshMember::new(
            "carol",
            "carol_pk",
            "sbm-0x999",
            "test-mesh",
            MeshRole::Consumer,
        );
        member.groups.push("database-admins".to_string());
        store.add_or_update(member);

        let carol = store.find("carol").expect("carol exists");
        assert!(carol.can_access_port(5432)); // inherited from database-admins group!
        assert!(!carol.can_access_port(22)); // Consumer has no SSH
        assert!(!carol.can_access_port(3306)); // ungranted port
    }

    #[test]
    fn test_invite_token_lifecycle_and_encode_decode() {
        let now = Utc::now().timestamp() as u64;
        let invite = MeshInviteToken {
            token_id: "inv-test-123".to_string(),
            mesh_name: "dev-mesh".to_string(),
            user_name: "dave".to_string(),
            role: MeshRole::Developer,
            groups: vec!["developers".to_string()],
            capabilities: vec![],
            server_endpoint: "145.223.83.235:58888".to_string(),
            server_pubkey: "some_server_pk".to_string(),
            swarm_topic: "sbm-swarm-dev".to_string(),
            created_at: now,
            expires_at: now + 3600,
            max_uses: 1,
            current_uses: 0,
            revoked: false,
            signature: "sig123".to_string(),
        };

        assert!(invite.is_valid(now));
        let uri = invite.encode_uri();
        assert!(uri.starts_with("sbm-invite://"));

        let decoded = MeshInviteToken::decode_uri(&uri).expect("decode success");
        assert_eq!(decoded.token_id, "inv-test-123");
        assert_eq!(decoded.user_name, "dave");
        assert_eq!(decoded.role, MeshRole::Developer);
    }

    #[test]
    fn test_sovereign_ntfs_acl_evaluation_and_deny_priority() {
        let mut acl = SovereignAcl::new(false);
        // @developers group has Read and Write
        acl.add_ace(
            "@developers",
            AceType::Allow,
            SovereignPermissions::read_write(),
            true,
        );
        // @alice has Full Control
        acl.add_ace(
            "@alice",
            AceType::Allow,
            SovereignPermissions::full_control(),
            true,
        );
        // @mallory has explicit Deny for Write
        acl.add_ace(
            "@mallory",
            AceType::Deny,
            SovereignPermissions {
                read: false,
                write: true,
                execute: false,
                delete: false,
                take_ownership: false,
            },
            true,
        );

        let dev_groups = vec!["developers".to_string()];

        // Alice (not in mallory, has full control)
        assert!(acl.check_access("alice", &dev_groups, &SovereignPermissions::full_control()));

        // Normal dev Bob (has read and write, but not delete)
        assert!(acl.check_access("bob", &dev_groups, &SovereignPermissions::read_only()));
        assert!(acl.check_access("bob", &dev_groups, &SovereignPermissions::read_write()));
        assert!(!acl.check_access("bob", &dev_groups, &SovereignPermissions::modify())); // no delete!

        // Mallory is in @developers (which allows write), but has EXPLICIT DENY for write!
        assert!(acl.check_access("mallory", &dev_groups, &SovereignPermissions::read_only())); // read is allowed
        assert!(!acl.check_access("mallory", &dev_groups, &SovereignPermissions::read_write())); // WRITE IS DENIED BY NTFS PRIORITY!

        // Stranger with no matching ACE gets Implicit Deny
        assert!(!acl.check_access("stranger", &[], &SovereignPermissions::read_only()));
    }

    #[test]
    fn test_host_grants_and_machine_privilege_evaluation() {
        let mut store = MeshRbacStore::new("corp-mesh");

        // Grant @developers User rights on build-worker
        store.grant_host_access("@developers", "build-worker", MachinePrivilege::User, None);

        // Grant @alice Operator rights on build-worker
        store.grant_host_access("@alice", "build-worker", MachinePrivilege::Operator, None);

        // Grant @admin Full rights on all machines
        store.grant_host_access("@admins", "build-worker", MachinePrivilege::Full, None);

        let dev_groups = vec!["developers".to_string()];
        let admin_groups = vec!["admins".to_string()];

        // Bob as developer gets User privilege
        let bob_priv = store.evaluate_machine_privilege("bob", &dev_groups, "build-worker");
        assert_eq!(bob_priv, Some(MachinePrivilege::User));
        assert!(bob_priv.unwrap().allows(MachinePrivilege::View));
        assert!(bob_priv.unwrap().allows(MachinePrivilege::User));
        assert!(!bob_priv.unwrap().allows(MachinePrivilege::Operator));

        // Alice has direct Operator grant, which supersedes her group's User grant
        let alice_priv = store.evaluate_machine_privilege("alice", &dev_groups, "build-worker");
        assert_eq!(alice_priv, Some(MachinePrivilege::Operator));
        assert!(alice_priv.unwrap().allows(MachinePrivilege::Operator));
        assert!(!alice_priv.unwrap().allows(MachinePrivilege::Full));

        // Eve from admins gets Full privilege
        let eve_priv = store.evaluate_machine_privilege("eve", &admin_groups, "build-worker");
        assert_eq!(eve_priv, Some(MachinePrivilege::Full));

        // Unknown machine gets None
        assert_eq!(
            store.evaluate_machine_privilege("alice", &dev_groups, "unknown-server"),
            None
        );
    }
}
