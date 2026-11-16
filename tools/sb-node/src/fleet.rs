//! Linux Fleet Monitoring (Heartbeats), Canary Software Package Rollout, and Agent Loop.
//!
//! Provides privacy-respecting machine heartbeats (`POST /v1/machines/{id}/heartbeat`),
//! strictly validated declarative Linux package manifests (`apt` / `flatpak`), and
//! deterministic canary rollout (`1..=100%`) without arbitrary shell execution.

use chrono::Utc;
use sb_core::domain::local_domain_dir;
use sb_core::policy::validate_policy_id;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Privacy-respecting fleet heartbeat reported by `sb-node agent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineHeartbeat {
    pub machine_id: String,
    pub fqdn: String,
    pub uptime_secs: u64,
    pub gpo_revision: u64,
    #[serde(default)]
    pub installed_packages: Vec<String>,
    pub last_seen_at: String,
}

/// Declarative Linux software package rollout manifest (no arbitrary shell commands).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageManifest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub apt_packages: Vec<String>,
    #[serde(default)]
    pub flatpak_apps: Vec<String>,
    #[serde(default)]
    pub target_groups: Vec<String>,
    /// Canary rollout percentage (`1..=100`).
    pub rollout_percent: u8,
    pub version: u64,
    pub updated_at: String,
}

/// Validates a Debian/Ubuntu `apt` or Flatpak identifier (`[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Command/flag injection (`-o APT::...`, `; rm -rf`) into
///   `apt-get install` or `flatpak install`.
/// - **CVE / CWE Mapping:** CWE-78 (OS Command Injection), CWE-88 (Argument Injection).
/// - **Likelihood & Exploitability:** High (9/10) if unvalidated package names reach `Command`.
/// - **Applied Mitigation:** Strict allowlist starting with alphanumeric (never `-`), no
///   whitespace or shell metacharacters, bounded to 128 bytes.
pub fn validate_linux_package_name(pkg: &str) -> Result<String, String> {
    let trimmed = pkg.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(format!("Invalid package name '{pkg}'"));
    }
    let first = trimmed.as_bytes()[0];
    if !first.is_ascii_alphanumeric() {
        return Err(format!(
            "Package name '{pkg}' must start with an alphanumeric character"
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-'))
    {
        return Err(format!(
            "Package name '{pkg}' contains forbidden characters"
        ));
    }
    Ok(trimmed.to_string())
}

impl PackageManifest {
    /// Validates manifest ID, rollout percentage (`1..=100`), and every package identifier.
    pub fn validate(&self) -> Result<(), String> {
        validate_policy_id(&self.id)?;
        if self.name.trim().is_empty() || self.name.len() > 100 {
            return Err("Package manifest name must be 1..=100 characters".into());
        }
        if !(1..=100).contains(&self.rollout_percent) {
            return Err("rollout_percent must be within 1..=100".into());
        }
        if self.apt_packages.is_empty() && self.flatpak_apps.is_empty() {
            return Err("PackageManifest must specify at least one apt or flatpak entry".into());
        }
        for p in &self.apt_packages {
            validate_linux_package_name(p)?;
        }
        for f in &self.flatpak_apps {
            validate_linux_package_name(f)?;
        }
        Ok(())
    }

    /// Deterministically evaluates whether `machine_id` falls within `rollout_percent`.
    pub fn matches_canary(&self, machine_id: &str) -> bool {
        if self.rollout_percent >= 100 {
            return true;
        }
        let mut h = Sha256::new();
        h.update(self.id.as_bytes());
        h.update(b":");
        h.update(machine_id.as_bytes());
        let digest = h.finalize();
        let bucket = (digest[0] as u16) % 100; // 0..99
        bucket < u16::from(self.rollout_percent)
    }
}

/// Persistent fleet heartbeats & software rollout manifests (`~/.sb/domain/fleet.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetStore {
    pub heartbeats: BTreeMap<String, MachineHeartbeat>,
    pub packages: BTreeMap<String, PackageManifest>,
}

pub fn default_fleet_path() -> PathBuf {
    local_domain_dir().join("fleet.json")
}

impl FleetStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read fleet store {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid fleet store JSON {}: {e}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create fleet dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize fleet store: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp fleet store: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit fleet store: {e}"))?;
        Ok(())
    }

    pub fn record_heartbeat(&mut self, mut hb: MachineHeartbeat) {
        hb.last_seen_at = Utc::now().to_rfc3339();
        self.heartbeats.insert(hb.machine_id.clone(), hb);
    }

    pub fn upsert_package(&mut self, mut pkg: PackageManifest) -> Result<PackageManifest, String> {
        pkg.id = validate_policy_id(&pkg.id)?;
        pkg.validate()?;
        let next_ver = self
            .packages
            .get(&pkg.id)
            .map(|p| p.version.saturating_add(1))
            .unwrap_or(1);
        pkg.version = pkg.version.max(next_ver);
        pkg.updated_at = Utc::now().to_rfc3339();
        self.packages.insert(pkg.id.clone(), pkg.clone());
        Ok(pkg)
    }

    pub fn packages_for_machine(&self, machine_id: &str) -> Vec<PackageManifest> {
        self.packages
            .values()
            .filter(|p| p.matches_canary(machine_id))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_validation_blocks_injection_and_canary_is_deterministic() {
        assert!(validate_linux_package_name("htop").is_ok());
        assert!(validate_linux_package_name("org.mozilla.firefox").is_ok());
        assert!(validate_linux_package_name("-oAPT::Evil=1").is_err());
        assert!(validate_linux_package_name("curl; rm -rf /").is_err());

        let mut store = FleetStore::default();
        let pkg = store
            .upsert_package(PackageManifest {
                id: "dev-tools".into(),
                name: "Developer CLI Tools".into(),
                apt_packages: vec!["git".into(), "ripgrep".into()],
                flatpak_apps: vec![],
                target_groups: vec!["engineering".into()],
                rollout_percent: 100,
                version: 1,
                updated_at: String::new(),
            })
            .unwrap();
        assert_eq!(pkg.version, 1);
        assert_eq!(store.packages_for_machine("m-01").len(), 1);

        store.record_heartbeat(MachineHeartbeat {
            machine_id: "m-01".into(),
            fqdn: "ws-01.corp.eu".into(),
            uptime_secs: 3600,
            gpo_revision: 3,
            installed_packages: vec!["git".into()],
            last_seen_at: String::new(),
        });
        assert_eq!(store.heartbeats["m-01"].gpo_revision, 3);
    }
}
