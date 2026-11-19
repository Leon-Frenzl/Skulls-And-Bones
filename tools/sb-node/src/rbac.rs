//! Domain RBAC, Just-in-Time (JIT) Privilege Elevation, and Group-Scoped Company App Portal.
//!
//! Ensures privilege elevation is strictly fail-closed: only users or groups explicitly listed
//! in an admin-defined `ElevationRule` may elevate for a bounded TTL with a mandatory reason
//! and audit trail.

use chrono::{DateTime, Duration, Utc};
use sb_core::domain::local_domain_dir;
use sb_core::identity::DomainUser;
use sb_core::policy::validate_policy_id;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Maximum allowed JIT elevation duration (2 hours).
pub const MAX_ELEVATION_TTL_SECONDS: u64 = 2 * 3600;
pub const MIN_ELEVATION_TTL_SECONDS: u64 = 60;

/// Admin-configured rule defining who is eligible to elevate to which capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElevationRule {
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub eligible_users: Vec<String>,
    #[serde(default)]
    pub eligible_groups: Vec<String>,
    pub granted_capabilities: Vec<String>,
    pub max_ttl_seconds: u64,
    #[serde(default = "default_true")]
    pub require_reason: bool,
}

fn default_true() -> bool {
    true
}

impl ElevationRule {
    /// Validates rule ID, capability list, and TTL bounds.
    pub fn validate(&self) -> Result<(), String> {
        validate_policy_id(&self.id)?;
        if self.granted_capabilities.is_empty() {
            return Err("granted_capabilities cannot be empty".into());
        }
        if !(MIN_ELEVATION_TTL_SECONDS..=MAX_ELEVATION_TTL_SECONDS).contains(&self.max_ttl_seconds)
        {
            return Err(format!(
                "max_ttl_seconds must be within {MIN_ELEVATION_TTL_SECONDS}..={MAX_ELEVATION_TTL_SECONDS}"
            ));
        }
        Ok(())
    }

    /// Returns `true` only if `user` is enabled and explicitly listed by username or group.
    pub fn is_user_eligible(&self, user: &DomainUser) -> bool {
        if !user.enabled {
            return false;
        }
        self.eligible_users.iter().any(|u| u == &user.username)
            || self
                .eligible_groups
                .iter()
                .any(|g| user.groups.iter().any(|ug| ug == g))
    }
}

/// Active time-bounded privilege elevation granted to a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveElevation {
    pub elevation_id: String,
    pub username: String,
    pub rule_id: String,
    pub granted_capabilities: Vec<String>,
    pub reason: String,
    pub issued_at: String,
    pub expires_at: String,
}

/// Company application entry shown in the user's App Launcher based on group membership.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompanyApp {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: String,
    /// Empty or `["all"]` means all active domain users can see this app.
    #[serde(default)]
    pub allowed_groups: Vec<String>,
}

impl CompanyApp {
    /// Validates app ID, name, and HTTP(S) URL.
    pub fn validate(&self) -> Result<(), String> {
        validate_policy_id(&self.id)?;
        if self.name.trim().is_empty() || self.name.len() > 80 {
            return Err("App name must be 1..=80 characters".into());
        }
        let u = self.url.trim();
        if !(u.starts_with("https://") || u.starts_with("http://"))
            || u.contains(char::is_whitespace)
        {
            return Err(format!("Invalid app URL '{}'", self.url));
        }
        Ok(())
    }

    /// Returns `true` if `user` is allowed to access this company app.
    pub fn is_visible_to(&self, user: &DomainUser, is_admin: bool) -> bool {
        if !user.enabled {
            return false;
        }
        if is_admin
            || self.allowed_groups.is_empty()
            || self.allowed_groups.iter().any(|g| g == "all")
        {
            return true;
        }
        self.allowed_groups
            .iter()
            .any(|g| user.groups.iter().any(|ug| ug == g))
    }
}

/// Persistent RBAC, JIT Elevation, and Company App store (`~/.sb/domain/rbac.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RbacStore {
    pub rules: BTreeMap<String, ElevationRule>,
    pub elevations: Vec<ActiveElevation>,
    pub apps: BTreeMap<String, CompanyApp>,
}

/// Returns the default RBAC store path (`~/.sb/domain/rbac.json`).
pub fn default_rbac_path() -> PathBuf {
    local_domain_dir().join("rbac.json")
}

impl RbacStore {
    /// Loads an existing RBAC store or returns an empty default store.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read RBAC store {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid RBAC store JSON {}: {e}", path.display()))
    }

    /// Atomically persists the RBAC store to `path`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create RBAC dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize RBAC store: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp RBAC store: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit RBAC store: {e}"))?;
        Ok(())
    }

    /// Creates or updates a validated JIT elevation rule.
    pub fn upsert_rule(&mut self, mut rule: ElevationRule) -> Result<ElevationRule, String> {
        rule.id = validate_policy_id(&rule.id)?;
        rule.validate()?;
        self.rules.insert(rule.id.clone(), rule.clone());
        Ok(rule)
    }

    /// Evaluates eligibility and grants a bounded-TTL JIT privilege elevation.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** Privilege escalation by unauthorized or disabled users,
    ///   or permanent elevation via unbounded TTLs.
    /// - **CVE / CWE Mapping:** CWE-269 (Improper Privilege Management), CWE-862 (Missing
    ///   Authorization).
    /// - **Likelihood & Exploitability:** High (8/10) if elevation is self-service without
    ///   an explicit eligibility allowlist.
    /// - **Applied Mitigation:** Fails closed unless `user.enabled` AND `user` matches
    ///   `rule.eligible_users` or `rule.eligible_groups`; enforces non-empty audit reason when
    ///   `require_reason` is set and clamps TTL to `60..=rule.max_ttl_seconds`.
    pub fn request_elevation(
        &mut self,
        user: &DomainUser,
        rule_id: &str,
        reason: &str,
        requested_ttl_seconds: u64,
    ) -> Result<ActiveElevation, String> {
        let clean_rule = validate_policy_id(rule_id)?;
        let rule = self
            .rules
            .get(&clean_rule)
            .cloned()
            .ok_or_else(|| format!("Elevation rule '{clean_rule}' not found"))?;
        if !rule.is_user_eligible(user) {
            return Err(format!(
                "User '{}' is not eligible for elevation rule '{clean_rule}'",
                user.username
            ));
        }
        let clean_reason = reason.trim();
        if rule.require_reason && clean_reason.len() < 5 {
            return Err("Elevation requires a justification reason (min 5 characters)".into());
        }

        let now = Utc::now();
        self.prune_expired(now);

        let ttl = requested_ttl_seconds.clamp(MIN_ELEVATION_TTL_SECONDS, rule.max_ttl_seconds);
        let mut hasher = Sha256::new();
        hasher.update(user.username.as_bytes());
        hasher.update(b":");
        hasher.update(clean_rule.as_bytes());
        hasher.update(now.to_rfc3339().as_bytes());
        let digest = hasher.finalize();
        let elevation_id = format!(
            "elev-{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        );

        let elev = ActiveElevation {
            elevation_id,
            username: user.username.clone(),
            rule_id: clean_rule,
            granted_capabilities: rule.granted_capabilities.clone(),
            reason: clean_reason.chars().take(256).collect(),
            issued_at: now.to_rfc3339(),
            expires_at: (now + Duration::seconds(ttl as i64)).to_rfc3339(),
        };
        self.elevations.push(elev.clone());
        Ok(elev)
    }

    /// Removes expired elevations and returns active elevations for `username`.
    pub fn active_elevations_for(&mut self, username: &str) -> Vec<ActiveElevation> {
        let now = Utc::now();
        self.prune_expired(now);
        self.elevations
            .iter()
            .filter(|e| e.username == username)
            .cloned()
            .collect()
    }

    /// Revokes all active elevations for `username` (called during offboarding).
    pub fn revoke_user_elevations(&mut self, username: &str) -> usize {
        let before = self.elevations.len();
        self.elevations.retain(|e| e.username != username);
        before.saturating_sub(self.elevations.len())
    }

    /// Creates or updates a company app entry.
    pub fn upsert_app(&mut self, mut app: CompanyApp) -> Result<CompanyApp, String> {
        app.id = validate_policy_id(&app.id)?;
        app.validate()?;
        self.apps.insert(app.id.clone(), app.clone());
        Ok(app)
    }

    fn prune_expired(&mut self, now: DateTime<Utc>) {
        self.elevations.retain(|e| {
            DateTime::parse_from_rfc3339(&e.expires_at)
                .map(|dt| dt.with_timezone(&Utc) > now)
                .unwrap_or(false)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user(username: &str, groups: Vec<&str>, enabled: bool) -> DomainUser {
        DomainUser {
            username: username.into(),
            display_name: username.into(),
            email: format!("{username}@corp.eu"),
            ou: "/".into(),
            groups: groups.into_iter().map(String::from).collect(),
            ssh_public_key: None,
            enabled,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn jit_elevation_enforces_explicit_eligibility_and_company_app_visibility() {
        let mut store = RbacStore::default();
        store
            .upsert_rule(ElevationRule {
                id: "jit-domain-admin".into(),
                description: "Temporary domain admin for on-call SREs".into(),
                eligible_users: vec![],
                eligible_groups: vec!["sre".into()],
                granted_capabilities: vec!["domain:admin".into()],
                max_ttl_seconds: 1800,
                require_reason: true,
            })
            .unwrap();

        let ordinary = sample_user("bob.sales", vec!["sales"], true);
        let sre = sample_user("alice.sre", vec!["sre"], true);

        // Ordinary user cannot elevate
        assert!(store
            .request_elevation(&ordinary, "jit-domain-admin", "Deploying fix", 900)
            .is_err());

        // Eligible SRE without reason is rejected
        assert!(store
            .request_elevation(&sre, "jit-domain-admin", "no", 900)
            .is_err());

        // Eligible SRE with reason succeeds and TTL is clamped to rule.max_ttl_seconds
        let elev = store
            .request_elevation(&sre, "jit-domain-admin", "Incident #42 DNS fix", 9999)
            .unwrap();
        assert_eq!(elev.granted_capabilities, vec!["domain:admin"]);
        assert_eq!(store.active_elevations_for("alice.sre").len(), 1);

        // Offboarding revokes active elevations
        assert_eq!(store.revoke_user_elevations("alice.sre"), 1);
        assert!(store.active_elevations_for("alice.sre").is_empty());

        // Company app visibility
        let app = store
            .upsert_app(CompanyApp {
                id: "grafana".into(),
                name: "Grafana Monitoring".into(),
                url: "https://grafana.corp.eu".into(),
                description: "Metrics".into(),
                allowed_groups: vec!["sre".into()],
            })
            .unwrap();
        assert!(app.is_visible_to(&sre, false));
        assert!(!app.is_visible_to(&ordinary, false));
    }
}
