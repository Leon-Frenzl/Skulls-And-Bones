//! Sovereign User & Group Directory (`~/.sb/domain/users.json`) and OpenSSH User
//! Certificate issuance for `sb-node`.

use chrono::{Duration, Utc};
use sb_ca::SshCa;
use sb_core::domain::local_domain_dir;
use sb_core::identity::{
    validate_openssh_pubkey, validate_username, DomainGroup, DomainUser, SshUserCertResponse,
    MAX_SSH_CERT_TTL_SECONDS, MIN_SSH_CERT_TTL_SECONDS,
};
use sb_core::policy::validate_policy_id;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Persistent domain user and group directory (`~/.sb/domain/users.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityDirectory {
    pub domain: String,
    pub users: BTreeMap<String, DomainUser>,
    pub groups: BTreeMap<String, DomainGroup>,
}

/// Returns the default path for the domain user/group directory.
pub fn default_users_path() -> PathBuf {
    local_domain_dir().join("users.json")
}

impl IdentityDirectory {
    /// Loads an existing directory from `path` or creates an empty one for `domain`.
    pub fn load_or_create(path: &Path, domain: &str) -> Result<Self, String> {
        if path.exists() {
            let raw = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read user directory {}: {e}", path.display()))?;
            let dir: Self = serde_json::from_str(&raw)
                .map_err(|e| format!("Invalid user directory JSON {}: {e}", path.display()))?;
            return Ok(dir);
        }
        Ok(Self {
            domain: domain.to_string(),
            users: BTreeMap::new(),
            groups: BTreeMap::new(),
        })
    }

    /// Persists the user/group directory atomically to `path`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create user directory dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize user directory: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp user directory: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit user directory: {e}"))?;
        Ok(())
    }

    /// Creates or updates a domain user and synchronizes their group memberships.
    pub fn upsert_user(&mut self, mut user: DomainUser) -> Result<DomainUser, String> {
        user.username = validate_username(&user.username)?;
        user.validate()?;
        let now = Utc::now().to_rfc3339();
        if let Some(existing) = self.users.get(&user.username) {
            user.created_at = existing.created_at.clone();
        } else if user.created_at.is_empty() {
            user.created_at = now.clone();
        }
        user.updated_at = now.clone();

        // Remove user from any groups they no longer belong to, then add to target groups
        for group in self.groups.values_mut() {
            group.members.retain(|m| m != &user.username);
        }
        for group_name in &user.groups {
            let entry = self
                .groups
                .entry(group_name.clone())
                .or_insert_with(|| DomainGroup {
                    name: group_name.clone(),
                    description: String::new(),
                    members: Vec::new(),
                    updated_at: now.clone(),
                });
            if !entry.members.contains(&user.username) {
                entry.members.push(user.username.clone());
                entry.updated_at = now.clone();
            }
        }

        self.users.insert(user.username.clone(), user.clone());
        Ok(user)
    }

    /// Disables a domain user immediately (fail-closed for future SSH/login requests).
    pub fn disable_user(&mut self, username: &str) -> Result<DomainUser, String> {
        let clean = validate_username(username)?;
        let user = self
            .users
            .get_mut(&clean)
            .ok_or_else(|| format!("User '{clean}' not found"))?;
        user.enabled = false;
        user.updated_at = Utc::now().to_rfc3339();
        Ok(user.clone())
    }

    /// Deletes a domain user and removes them from all groups.
    pub fn delete_user(&mut self, username: &str) -> Result<bool, String> {
        let clean = validate_username(username)?;
        let removed = self.users.remove(&clean).is_some();
        if removed {
            for group in self.groups.values_mut() {
                group.members.retain(|m| m != &clean);
            }
        }
        Ok(removed)
    }

    /// Creates or updates a domain group.
    pub fn upsert_group(&mut self, mut group: DomainGroup) -> Result<DomainGroup, String> {
        group.name = validate_policy_id(&group.name)?;
        group.validate()?;
        group.updated_at = Utc::now().to_rfc3339();
        self.groups.insert(group.name.clone(), group.clone());
        Ok(group)
    }

    /// Issues a short-lived OpenSSH user certificate for an active domain user.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** Disabled or deleted employee obtaining SSH access, or
    ///   unbounded certificate TTLs allowing indefinite offline access.
    /// - **CVE / CWE Mapping:** CWE-287 (Improper Authentication), CWE-613 (Insufficient
    ///   Session Expiration).
    /// - **Likelihood & Exploitability:** High (8/10) on remote/SSH-accessible infrastructure.
    /// - **Applied Mitigation:** Fails closed if `!user.enabled`, validates the OpenSSH public
    ///   key against control/argument injection, clamps TTL to `60..=86400` seconds, and binds
    ///   principals strictly to `[username, ...user.groups]`.
    ///
    /// # Standards Compliance
    /// - Conforms to OpenSSH `PROTOCOL.certkeys` user certificates.
    pub fn issue_user_ssh_cert(
        &self,
        username: &str,
        ssh_pubkey_override: Option<&str>,
        ttl_seconds: u64,
    ) -> Result<SshUserCertResponse, String> {
        let clean = validate_username(username)?;
        let user = self
            .users
            .get(&clean)
            .ok_or_else(|| format!("User '{clean}' not found in directory"))?;
        if !user.enabled {
            return Err(format!("User '{clean}' is disabled"));
        }

        let raw_pubkey = ssh_pubkey_override
            .or(user.ssh_public_key.as_deref())
            .ok_or_else(|| format!("User '{clean}' has no SSH public key registered"))?;
        let validated_pubkey = validate_openssh_pubkey(raw_pubkey)?;

        let clamped_ttl = ttl_seconds.clamp(MIN_SSH_CERT_TTL_SECONDS, MAX_SSH_CERT_TTL_SECONDS);
        let mut principals = vec![user.username.clone()];
        for g in &user.groups {
            if !principals.contains(g) {
                principals.push(g.clone());
            }
        }
        let key_id = format!("{}@{}", user.username, self.domain);
        let cert = SshCa::issue_user_certificate(
            &validated_pubkey,
            &key_id,
            &principals,
            clamped_ttl,
            None,
        )
        .map_err(|e| format!("Failed to issue SSH user certificate: {e}"))?;

        let expires_at = (Utc::now() + Duration::seconds(clamped_ttl as i64)).to_rfc3339();
        Ok(SshUserCertResponse {
            username: user.username.clone(),
            principals,
            ttl_seconds: clamped_ttl,
            certificate_openssh: cert,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_directory_crud_and_ssh_cert_respects_enabled_flag() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_users_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let path = temp.join("users.json");

        let mut dir = IdentityDirectory::load_or_create(&path, "corp.eu").unwrap();
        let user = dir
            .upsert_user(DomainUser {
                username: "anna.admin".into(),
                display_name: "Anna Admin".into(),
                email: "anna@corp.eu".into(),
                groups: vec!["engineering".into(), "admins".into()],
                ssh_public_key: Some(
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyDataHere123456 anna@corp.eu"
                        .into(),
                ),
                enabled: true,
                created_at: String::new(),
                updated_at: String::new(),
            })
            .unwrap();
        assert_eq!(user.username, "anna.admin");
        assert!(dir.groups["engineering"]
            .members
            .contains(&"anna.admin".to_string()));

        // Disabled user cannot get an SSH cert (fail-closed)
        dir.disable_user("anna.admin").unwrap();
        assert!(dir.issue_user_ssh_cert("anna.admin", None, 3600).is_err());

        // Delete cleans up group membership
        assert!(dir.delete_user("anna.admin").unwrap());
        assert!(!dir.groups["engineering"]
            .members
            .contains(&"anna.admin".to_string()));
        dir.save(&path).unwrap();

        let _ = fs::remove_dir_all(&temp);
    }
}
