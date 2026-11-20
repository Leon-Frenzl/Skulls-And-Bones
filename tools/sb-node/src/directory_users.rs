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

/// Organizational Unit (OU) in the sovereign directory without LDAP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationalUnit {
    pub path: String,
    #[serde(default)]
    pub description: String,
    pub updated_at: String,
}

/// Fine-grained delegated administration permission for non-root operators (Helpdesk, SecOps, etc.).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedPermission {
    UserManage,
    UserResetPassword,
    LapsReveal,
    MachineManage,
    PolicyManage,
    GroupManage,
    AuditRead,
    OidcClientManage,
}

/// Persistent domain user and group directory (`~/.sb/domain/users.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityDirectory {
    pub domain: String,
    pub users: BTreeMap<String, DomainUser>,
    pub groups: BTreeMap<String, DomainGroup>,
    #[serde(default)]
    pub ous: BTreeMap<String, OrganizationalUnit>,
    /// Delegated permissions keyed by `"group:<name>"` or `"ou:<path>"`.
    #[serde(default)]
    pub delegations: BTreeMap<String, Vec<DelegatedPermission>>,
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
            ous: BTreeMap::new(),
            delegations: BTreeMap::new(),
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
                    ou: "/".to_string(),
                    is_local_admin: group_name == "admins",
                    allowed_machines: Vec::new(),
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
        group.ou = sb_core::identity::validate_ou_path(&group.ou)?;
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

    /// Creates or updates an Organizational Unit (`path` e.g. `"/Engineering/Backend"`).
    pub fn upsert_ou(
        &mut self,
        path: &str,
        description: &str,
    ) -> Result<OrganizationalUnit, String> {
        let clean = sb_core::identity::validate_ou_path(path)?;
        let ou = OrganizationalUnit {
            path: clean.clone(),
            description: description.trim().to_string(),
            updated_at: Utc::now().to_rfc3339(),
        };
        self.ous.insert(clean, ou.clone());
        Ok(ou)
    }

    /// Deletes an Organizational Unit by path (`"/"` cannot be deleted).
    pub fn delete_ou(&mut self, path: &str) -> Result<bool, String> {
        let clean = sb_core::identity::validate_ou_path(path)?;
        if clean == "/" {
            return Err("Root OU '/' cannot be deleted".into());
        }
        Ok(self.ous.remove(&clean).is_some())
    }

    /// Deletes a security group and removes it from all user memberships.
    pub fn delete_group(&mut self, name: &str) -> Result<bool, String> {
        let clean_name = validate_policy_id(name)?;
        if clean_name == "admins" {
            return Err("Built-in 'admins' group cannot be deleted".into());
        }
        let removed = self.groups.remove(&clean_name).is_some();
        if removed {
            for user in self.users.values_mut() {
                user.groups.retain(|g| g != &clean_name);
            }
        }
        Ok(removed)
    }

    /// Grants delegated permissions to `"group:<name>"` or `"ou:<path>"`.
    pub fn set_delegations(
        &mut self,
        principal: &str,
        permissions: Vec<DelegatedPermission>,
    ) -> Result<(), String> {
        let trimmed = principal.trim();
        let valid = if let Some(grp) = trimmed.strip_prefix("group:") {
            validate_policy_id(grp).map(|g| format!("group:{g}"))?
        } else if let Some(ou) = trimmed.strip_prefix("ou:") {
            sb_core::identity::validate_ou_path(ou).map(|o| format!("ou:{o}"))?
        } else {
            return Err("Delegation principal must start with 'group:' or 'ou:'".into());
        };
        self.delegations.insert(valid, permissions);
        Ok(())
    }

    /// Evaluates whether `username` holds `perm` via admin membership, group delegation, or OU delegation.
    // [SECURITY-HYPOTHESIS] CWE-284 / CWE-863: Disabled users or unprivileged groups gaining delegated admin actions.
    // [SECURITY-VERIFIED] Fails closed if user is missing/disabled; checks explicit group/OU delegation mappings.
    pub fn has_delegated_permission(&self, username: &str, perm: DelegatedPermission) -> bool {
        let Ok(clean) = validate_username(username) else {
            return false;
        };
        let Some(user) = self.users.get(&clean) else {
            return false;
        };
        if !user.enabled {
            return false;
        }
        if user.groups.iter().any(|g| {
            g == "admins"
                || self
                    .groups
                    .get(g)
                    .map(|grp| grp.is_local_admin)
                    .unwrap_or(false)
        }) {
            return true;
        }
        for grp in &user.groups {
            if let Some(perms) = self.delegations.get(&format!("group:{grp}")) {
                if perms.contains(&perm) {
                    return true;
                }
            }
        }
        for (principal, perms) in &self.delegations {
            if let Some(ou_prefix) = principal.strip_prefix("ou:") {
                let matches_ou = if ou_prefix == "/" {
                    true
                } else {
                    user.ou == ou_prefix || user.ou.starts_with(&format!("{ou_prefix}/"))
                };
                if matches_ou && perms.contains(&perm) {
                    return true;
                }
            }
        }
        false
    }

    /// Evaluates whether `username` may log into `machine_id` / `fqdn` and whether they
    /// hold local administrator privileges on that machine.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** Disabled users or unauthorized cross-OU users logging into sensitive nodes.
    /// - **CWE Mapping:** CWE-284 (Improper Access Control).
    /// - **Likelihood & Exploitability:** High (8/10) on domain OS login endpoints.
    /// - **Applied Mitigation:** Fails closed when user is missing/disabled; evaluates group `allowed_machines`
    ///   and aggregates `is_local_admin` across active group memberships.
    pub fn evaluate_machine_login(
        &self,
        username: &str,
        machine_id: &str,
        fqdn: &str,
    ) -> Result<(DomainUser, bool), String> {
        let clean = validate_username(username)?;
        let user = self
            .users
            .get(&clean)
            .ok_or_else(|| format!("User '{clean}' not found in directory"))?;
        if !user.enabled {
            return Err(format!("User '{clean}' is disabled"));
        }

        let mut is_local_admin = false;
        let mut has_restricted_group = false;
        let mut allowed_by_group = false;

        for gname in &user.groups {
            if gname == "admins" {
                is_local_admin = true;
            }
            if let Some(grp) = self.groups.get(gname) {
                if grp.is_local_admin {
                    is_local_admin = true;
                }
                if grp.allowed_machines.is_empty() {
                    allowed_by_group = true;
                } else {
                    has_restricted_group = true;
                    if grp.allowed_machines.iter().any(|target| {
                        target == "*" || target == machine_id || target.eq_ignore_ascii_case(fqdn)
                    }) {
                        allowed_by_group = true;
                    }
                }
            }
        }

        if has_restricted_group && !allowed_by_group && !is_local_admin {
            return Err(format!(
                "User '{clean}' is not authorized to log into machine '{fqdn}'"
            ));
        }

        Ok((user.clone(), is_local_admin))
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
                ou: "/".into(),
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

    #[test]
    fn groups_ous_and_delegated_permissions_enforce_scoped_access() {
        let mut dir = IdentityDirectory {
            domain: "corp.eu".into(),
            ..Default::default()
        };
        dir.upsert_ou("/eu/support", "EU Helpdesk").unwrap();
        dir.upsert_group(DomainGroup {
            name: "helpdesk".into(),
            description: "Support Team".into(),
            ou: "/eu/support".into(),
            is_local_admin: false,
            allowed_machines: vec![],
            members: vec![],
            updated_at: String::new(),
        })
        .unwrap();
        dir.set_delegations(
            "group:helpdesk",
            vec![
                DelegatedPermission::LapsReveal,
                DelegatedPermission::UserResetPassword,
            ],
        )
        .unwrap();

        dir.upsert_user(DomainUser {
            username: "max.support".into(),
            display_name: "Max".into(),
            email: "max@corp.eu".into(),
            ou: "/eu/support".into(),
            groups: vec!["helpdesk".into()],
            ssh_public_key: None,
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        })
        .unwrap();

        assert!(dir.has_delegated_permission("max.support", DelegatedPermission::LapsReveal));
        assert!(
            dir.has_delegated_permission("max.support", DelegatedPermission::UserResetPassword)
        );
        assert!(!dir.has_delegated_permission("max.support", DelegatedPermission::PolicyManage));

        dir.disable_user("max.support").unwrap();
        assert!(!dir.has_delegated_permission("max.support", DelegatedPermission::LapsReveal));
    }
}
