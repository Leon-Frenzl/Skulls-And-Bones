//! Cross-platform, Ed25519-signed Group Policy Object (GPO) engine for `sb-node`.
//!
//! Provides DC-side policy storage & bundle signing as well as machine-side cryptographic
//! verification, anti-rollback enforcement, dry-run diffing, and OS-specific rendering for
//! Linux, Windows, and macOS.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sb_core::domain::{local_domain_dir, validate_domain_name, OsKind};
use sb_core::policy::{
    validate_policy_id, PolicyApplyReport, PolicyDocument, PolicyRule, PolicyRuleResult,
    SignedPolicyBundle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Persisted DC-side policy repository (`~/.sb/domain/policies.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStore {
    pub domain: String,
    pub revision: u64,
    pub policies: BTreeMap<String, PolicyDocument>,
}

/// Persisted machine-side anti-rollback state (`~/.sb/domain/applied_policy_state.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppliedPolicyState {
    pub domain: String,
    pub last_applied_revision: u64,
    pub last_applied_at: String,
}

/// Returns the default path for the DC policy store.
pub fn default_policy_store_path() -> PathBuf {
    local_domain_dir().join("policies.json")
}

/// Returns the default path for the Ed25519 policy authority signing key.
pub fn default_policy_authority_key_path() -> PathBuf {
    local_domain_dir().join("policy_authority.key")
}

/// Returns the default path for the Ed25519 policy authority public key.
pub fn default_policy_authority_pub_path() -> PathBuf {
    local_domain_dir().join("policy_authority.pub")
}

/// Returns the default path for machine-side applied policy anti-rollback state.
pub fn default_applied_state_path() -> PathBuf {
    local_domain_dir().join("applied_policy_state.json")
}

/// Returns the default path for the locally cached signed policy bundle (for offline Mobile Work).
pub fn default_cached_bundle_path() -> PathBuf {
    local_domain_dir().join("cached_policy_bundle.json")
}

/// Target context used to evaluate OS and scope (`Domain` / `Ou` / `Machine`) filters.
#[derive(Debug, Clone, Copy)]
pub struct PolicyTargetContext<'a> {
    pub machine_id: &'a str,
    pub fqdn: Option<&'a str>,
    pub ou: Option<&'a str>,
    pub os: OsKind,
}

/// Generates or loads an Ed25519 Policy Authority signing keypair.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Forged GPO bundles pushing unauthorized SSH keys or firewall rules.
/// - **CVE / CWE Mapping:** CWE-345 (Insufficient Verification of Data Authenticity).
/// - **Likelihood & Exploitability:** High (8/10) without asymmetric signing of policy bundles.
/// - **Applied Mitigation:** Generates a 256-bit Ed25519 keypair using OS CSPRNG (`OsRng`) and
///   restricts private key file permissions to `0600` on Unix.
///
/// # Standards Compliance
/// - Conforms to RFC 8032 (Ed25519).
pub fn ensure_policy_authority_keypair(
    key_path: &Path,
    pub_path: &Path,
) -> Result<SigningKey, String> {
    if key_path.exists() {
        let raw = fs::read_to_string(key_path)
            .map_err(|e| format!("Failed to read policy authority key: {e}"))?;
        let bytes = B64
            .decode(raw.trim())
            .map_err(|e| format!("Invalid base64 policy authority key: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Policy authority key must be 32 bytes".to_string())?;
        return Ok(SigningKey::from_bytes(&arr));
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create policy authority dir: {e}"))?;
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    let priv_b64 = B64.encode(signing_key.to_bytes());
    let pub_b64 = B64.encode(signing_key.verifying_key().to_bytes());

    fs::write(key_path, priv_b64)
        .map_err(|e| format!("Failed to write policy authority key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
    }
    fs::write(pub_path, pub_b64)
        .map_err(|e| format!("Failed to write policy authority public key: {e}"))?;
    Ok(signing_key)
}

impl PolicyStore {
    /// Loads an existing policy store or creates a new one for `domain`.
    pub fn load_or_create(path: &Path, domain: &str) -> Result<Self, String> {
        let clean_domain = validate_domain_name(domain)?;
        if path.exists() {
            let raw = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read policy store {}: {e}", path.display()))?;
            let store: Self = serde_json::from_str(&raw)
                .map_err(|e| format!("Invalid policy store JSON {}: {e}", path.display()))?;
            if store.domain != clean_domain {
                return Err(format!(
                    "Policy store domain '{}' does not match '{clean_domain}'",
                    store.domain
                ));
            }
            return Ok(store);
        }
        Ok(Self {
            domain: clean_domain,
            revision: 0,
            policies: BTreeMap::new(),
        })
    }

    /// Loads an existing policy store without requiring a domain argument.
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Policy store not found at {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid policy store JSON {}: {e}", path.display()))
    }

    /// Persists the policy store atomically to disk.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create policy dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize policy store: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp policy store: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit policy store: {e}"))?;
        Ok(())
    }

    /// Validates and inserts/updates a policy document, bumping the store revision.
    pub fn upsert_policy(&mut self, mut doc: PolicyDocument) -> Result<PolicyDocument, String> {
        doc.id = validate_policy_id(&doc.id)?;
        doc.validate()?;
        let next_ver = self
            .policies
            .get(&doc.id)
            .map(|existing| existing.version.saturating_add(1))
            .unwrap_or(1);
        doc.version = doc.version.max(next_ver);
        doc.updated_at = Utc::now().to_rfc3339();
        self.revision = self.revision.saturating_add(1);
        self.policies.insert(doc.id.clone(), doc.clone());
        Ok(doc)
    }

    /// Deletes a policy by ID and bumps the store revision.
    pub fn delete_policy(&mut self, id: &str) -> Result<bool, String> {
        let clean = validate_policy_id(id)?;
        let existed = self.policies.remove(&clean).is_some();
        if existed {
            self.revision = self.revision.saturating_add(1);
        }
        Ok(existed)
    }

    /// Lists policies, optionally filtered by operating system.
    pub fn list_policies(&self, os_filter: Option<OsKind>) -> Vec<PolicyDocument> {
        self.policies
            .values()
            .filter(|p| os_filter.map(|os| p.applies_to_os(os)).unwrap_or(true))
            .cloned()
            .collect()
    }

    /// Builds and signs a `SignedPolicyBundle` valid for `ttl_hours`.
    pub fn sign_bundle(
        &self,
        ttl_hours: i64,
        signing_key: &SigningKey,
    ) -> Result<SignedPolicyBundle, String> {
        let clamped_ttl = ttl_hours.clamp(1, 24 * 30);
        let now = Utc::now();
        let issued_at = now.to_rfc3339();
        let expires_at = (now + Duration::hours(clamped_ttl)).to_rfc3339();
        let policies: Vec<PolicyDocument> = self.policies.values().cloned().collect();
        let payload = SignedPolicyBundle::canonical_payload_bytes(
            &self.domain,
            self.revision,
            &issued_at,
            &expires_at,
            &policies,
        )?;
        let sig = signing_key.sign(&payload);
        Ok(SignedPolicyBundle {
            domain: self.domain.clone(),
            revision: self.revision,
            issued_at,
            expires_at,
            policies,
            authority_pubkey_b64: B64.encode(signing_key.verifying_key().to_bytes()),
            signature_b64: B64.encode(sig.to_bytes()),
        })
    }
}

/// Cryptographically verifies a `SignedPolicyBundle` against pinned authority key, domain,
/// expiration timestamp, and monotonic anti-rollback revision.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Replay of stale/vulnerable GPO bundles (rollback attack),
///   domain confusion, or forged policy payloads.
/// - **CVE / CWE Mapping:** CWE-347 (Improper Verification of Cryptographic Signature),
///   CWE-294 (Authentication Bypass by Capture-replay).
/// - **Likelihood & Exploitability:** High (8/10) on untrusted networks (Mobile/Remote Work).
/// - **Applied Mitigation:** Verifies Ed25519 signature over canonical JSON against the pinned
///   authority public key, checks `expires_at > now`, enforces `domain == expected_domain`, and
///   rejects `bundle.revision < min_revision`.
///
/// # Standards Compliance
/// - Conforms to RFC 8032 (Ed25519) and RFC 3339 (timestamps).
pub fn verify_policy_bundle(
    bundle: &SignedPolicyBundle,
    expected_domain: &str,
    pinned_authority_pubkey_b64: &str,
    min_revision: u64,
) -> Result<(), String> {
    let clean_domain = validate_domain_name(expected_domain)?;
    if bundle.domain != clean_domain {
        return Err(format!(
            "Policy bundle domain '{}' does not match expected '{clean_domain}'",
            bundle.domain
        ));
    }
    if bundle.authority_pubkey_b64.trim() != pinned_authority_pubkey_b64.trim() {
        return Err("Policy bundle authority public key does not match pinned key".into());
    }
    if bundle.revision < min_revision {
        return Err(format!(
            "Policy bundle revision {} rejected (anti-rollback minimum is {min_revision})",
            bundle.revision
        ));
    }

    let pub_bytes = B64
        .decode(pinned_authority_pubkey_b64.trim())
        .map_err(|e| format!("Invalid pinned authority public key base64: {e}"))?;
    let pub_arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| "Pinned authority public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|e| format!("Invalid Ed25519 authority public key: {e}"))?;

    let sig_bytes = B64
        .decode(bundle.signature_b64.trim())
        .map_err(|e| format!("Invalid policy signature base64: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Policy signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);

    let payload = SignedPolicyBundle::canonical_payload_bytes(
        &bundle.domain,
        bundle.revision,
        &bundle.issued_at,
        &bundle.expires_at,
        &bundle.policies,
    )?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| "Policy bundle Ed25519 signature verification failed".to_string())?;

    let expires_at = DateTime::parse_from_rfc3339(&bundle.expires_at)
        .map_err(|e| format!("Invalid policy bundle expires_at timestamp: {e}"))?
        .with_timezone(&Utc);
    if expires_at <= Utc::now() {
        return Err("Policy bundle has expired".into());
    }

    for doc in &bundle.policies {
        doc.validate()?;
    }
    Ok(())
}

/// Applies (or dry-run previews) a verified `SignedPolicyBundle` for `target_os`.
pub fn apply_policy_bundle(
    bundle: &SignedPolicyBundle,
    machine_id: &str,
    target_os: OsKind,
    sys_root: &Path,
    dry_run: bool,
) -> Result<PolicyApplyReport, String> {
    apply_policy_bundle_for_target(
        bundle,
        PolicyTargetContext {
            machine_id,
            fqdn: None,
            ou: None,
            os: target_os,
        },
        sys_root,
        dry_run,
    )
}

/// Applies (or dry-run previews) a verified `SignedPolicyBundle` for a full `PolicyTargetContext`
/// including OS, machine ID, FQDN, and Organizational Unit (OU) scope matching.
///
/// Renders declarative OS-native configuration files under `sys_root`:
/// - Linux: `etc/ssh/sshd_config.d/90-sb-gpo.conf`, `etc/sysctl.d/90-sb-gpo.conf`,
///   `etc/systemd/resolved.conf.d/90-sb-gpo.conf`, `etc/sb-gpo/firewall-baseline.json`
/// - Windows: `ProgramData/SkullsAndBones/gpo/sb-gpo-windows.json`
/// - macOS: `Library/Application Support/SkullsAndBones/gpo/sb-gpo-macos.mobileconfig`
pub fn apply_policy_bundle_for_target(
    bundle: &SignedPolicyBundle,
    target: PolicyTargetContext<'_>,
    sys_root: &Path,
    dry_run: bool,
) -> Result<PolicyApplyReport, String> {
    let machine_id = target.machine_id;
    let target_os = target.os;
    let mut ssh_lines = vec![
        "# Managed by Skulls & Bones GPO Engine (Ed25519 verified)".to_string(),
        format!(
            "# Domain: {} | Revision: {}",
            bundle.domain, bundle.revision
        ),
    ];
    let mut sysctl_lines =
        vec!["# Managed by Skulls & Bones GPO Engine (Ed25519 verified)".to_string()];
    let mut dns_domains: Vec<String> = Vec::new();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut firewall_rules: Vec<serde_json::Value> = Vec::new();
    let mut firewall_default_deny: Option<bool> = None;
    let mut firewall_allow_ports: Vec<u16> = Vec::new();
    let mut screen_locks: Vec<serde_json::Value> = Vec::new();
    let mut screen_lock_cfg: Option<(u32, bool)> = None;

    let mut applied = Vec::new();
    let mut skipped = Vec::new();

    for policy in &bundle.policies {
        if !policy.applies_to_os(target_os) {
            skipped.push(PolicyRuleResult {
                policy_id: policy.id.clone(),
                rule_kind: "policy".into(),
                action: format!(
                    "skipped (targets {:?}, host is {:?})",
                    policy.target_os, target_os
                ),
                target_path: None,
            });
            continue;
        }
        if !policy.applies_to_scope(machine_id, target.fqdn, target.ou) {
            skipped.push(PolicyRuleResult {
                policy_id: policy.id.clone(),
                rule_kind: "policy".into(),
                action: format!("skipped (scope {:?} does not match target)", policy.scope),
                target_path: None,
            });
            continue;
        }

        for rule in &policy.rules {
            rule.validate()?;
            match rule {
                PolicyRule::SshHardening {
                    password_auth,
                    permit_root_login,
                    trusted_user_ca_keys,
                } => {
                    ssh_lines.push(format!(
                        "PasswordAuthentication {}",
                        if *password_auth { "yes" } else { "no" }
                    ));
                    ssh_lines.push(format!(
                        "PermitRootLogin {}",
                        if *permit_root_login { "yes" } else { "no" }
                    ));
                    if *trusted_user_ca_keys {
                        let ca_path = if target_os == OsKind::Windows {
                            "C:/ProgramData/ssh/sb_user_ca.pub"
                        } else {
                            "/etc/ssh/sb_user_ca.pub"
                        };
                        ssh_lines.push(format!("TrustedUserCAKeys {ca_path}"));
                    }
                    applied.push(PolicyRuleResult {
                        policy_id: policy.id.clone(),
                        rule_kind: "ssh_hardening".into(),
                        action: "render_ssh_hardening".into(),
                        target_path: Some(match target_os {
                            OsKind::Linux => "etc/ssh/sshd_config.d/90-sb-gpo.conf".into(),
                            OsKind::Windows => "ProgramData/SkullsAndBones/gpo/sb-gpo-windows.json".into(),
                            OsKind::MacOs => "Library/Application Support/SkullsAndBones/gpo/sb-gpo-macos.mobileconfig".into(),
                        }),
                    });
                }
                PolicyRule::SysctlSetting { key, value } => {
                    if target_os == OsKind::Windows {
                        skipped.push(PolicyRuleResult {
                            policy_id: policy.id.clone(),
                            rule_kind: "sysctl_setting".into(),
                            action: "skipped (sysctl is Unix-only)".into(),
                            target_path: None,
                        });
                    } else {
                        sysctl_lines.push(format!("{key} = {value}"));
                        applied.push(PolicyRuleResult {
                            policy_id: policy.id.clone(),
                            rule_kind: "sysctl_setting".into(),
                            action: format!("set {key}={value}"),
                            target_path: Some("etc/sysctl.d/90-sb-gpo.conf".into()),
                        });
                    }
                }
                PolicyRule::DnsSplitZone {
                    domains,
                    nameservers,
                } => {
                    dns_domains.extend(domains.iter().cloned());
                    dns_servers.extend(nameservers.iter().cloned());
                    applied.push(PolicyRuleResult {
                        policy_id: policy.id.clone(),
                        rule_kind: "dns_split_zone".into(),
                        action: format!("configure split-dns ({})", domains.join(", ")),
                        target_path: Some(match target_os {
                            OsKind::Linux => "etc/systemd/resolved.conf.d/90-sb-gpo.conf".into(),
                            OsKind::Windows => "ProgramData/SkullsAndBones/gpo/sb-gpo-windows.json".into(),
                            OsKind::MacOs => "Library/Application Support/SkullsAndBones/gpo/sb-gpo-macos.mobileconfig".into(),
                        }),
                    });
                }
                PolicyRule::FirewallBaseline {
                    default_deny_inbound,
                    allow_ports,
                } => {
                    firewall_default_deny =
                        Some(firewall_default_deny.unwrap_or(false) || *default_deny_inbound);
                    for port in allow_ports {
                        if *port > 0 && !firewall_allow_ports.contains(port) {
                            firewall_allow_ports.push(*port);
                        }
                    }
                    firewall_rules.push(serde_json::json!({
                        "policy_id": policy.id,
                        "default_deny_inbound": default_deny_inbound,
                        "allow_ports": allow_ports,
                    }));
                    applied.push(PolicyRuleResult {
                        policy_id: policy.id.clone(),
                        rule_kind: "firewall_baseline".into(),
                        action: format!("firewall default_deny={default_deny_inbound}"),
                        target_path: Some(match target_os {
                            OsKind::Windows => {
                                "ProgramData/SkullsAndBones/gpo/sb-gpo-windows.json".into()
                            }
                            _ => "etc/sb-gpo/firewall-baseline.json".into(),
                        }),
                    });
                }
                PolicyRule::ScreenLock {
                    idle_timeout_seconds,
                    require_password,
                } => {
                    let clamped = (*idle_timeout_seconds).clamp(30, 86400);
                    screen_lock_cfg = Some((clamped, *require_password));
                    screen_locks.push(serde_json::json!({
                        "policy_id": policy.id,
                        "idle_timeout_seconds": idle_timeout_seconds,
                        "require_password": require_password,
                    }));
                    applied.push(PolicyRuleResult {
                        policy_id: policy.id.clone(),
                        rule_kind: "screen_lock".into(),
                        action: format!("screen_lock={}s", idle_timeout_seconds),
                        target_path: Some(match target_os {
                            OsKind::Linux => "etc/sb-gpo/screen-lock.json".into(),
                            OsKind::Windows => "ProgramData/SkullsAndBones/gpo/sb-gpo-windows.json".into(),
                            OsKind::MacOs => "Library/Application Support/SkullsAndBones/gpo/sb-gpo-macos.mobileconfig".into(),
                        }),
                    });
                }
            }
        }
    }

    if !dry_run {
        match target_os {
            OsKind::Linux => {
                if ssh_lines.len() > 2 {
                    write_rendered(
                        &sys_root.join("etc/ssh/sshd_config.d/90-sb-gpo.conf"),
                        &(ssh_lines.join("\n") + "\n"),
                    )?;
                }
                if sysctl_lines.len() > 1 {
                    write_rendered(
                        &sys_root.join("etc/sysctl.d/90-sb-gpo.conf"),
                        &(sysctl_lines.join("\n") + "\n"),
                    )?;
                }
                if !dns_domains.is_empty() {
                    let resolved = format!(
                        "[Resolve]\nDNS={}\nDomains={}\n",
                        dns_servers.join(" "),
                        dns_domains
                            .iter()
                            .map(|d| format!("~{d}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                    write_rendered(
                        &sys_root.join("etc/systemd/resolved.conf.d/90-sb-gpo.conf"),
                        &resolved,
                    )?;
                }
                if !firewall_rules.is_empty() {
                    let fw_json = serde_json::to_string_pretty(&firewall_rules)
                        .map_err(|e| format!("Failed to serialize firewall baseline: {e}"))?;
                    write_rendered(
                        &sys_root.join("etc/sb-gpo/firewall-baseline.json"),
                        &fw_json,
                    )?;
                }
                if !screen_locks.is_empty() {
                    let sl_json = serde_json::to_string_pretty(&screen_locks)
                        .map_err(|e| format!("Failed to serialize screen lock config: {e}"))?;
                    write_rendered(&sys_root.join("etc/sb-gpo/screen-lock.json"), &sl_json)?;
                }
            }
            OsKind::Windows => {
                let win_intent = serde_json::json!({
                    "schema": "sb.gpo.windows.v1",
                    "domain": bundle.domain,
                    "revision": bundle.revision,
                    "dns_split": { "domains": dns_domains, "nameservers": dns_servers },
                    "firewall": firewall_rules,
                    "screen_lock": screen_locks,
                    "ssh_hardening": ssh_lines,
                });
                let json = serde_json::to_string_pretty(&win_intent)
                    .map_err(|e| format!("Failed to serialize Windows GPO intent: {e}"))?;
                write_rendered(
                    &sys_root.join("ProgramData/SkullsAndBones/gpo/sb-gpo-windows.json"),
                    &json,
                )?;
                if ssh_lines.len() > 2 {
                    write_rendered(
                        &sys_root.join("ProgramData/ssh/sshd_config.d/90-sb-gpo.conf"),
                        &(ssh_lines.join("\n") + "\n"),
                    )?;
                }
                let ps_script = render_windows_gpo_ps(
                    &bundle.domain,
                    bundle.revision,
                    &dns_domains,
                    &dns_servers,
                    firewall_default_deny,
                    &firewall_allow_ports,
                    screen_lock_cfg,
                    ssh_lines.len() > 2,
                )?;
                write_rendered(
                    &sys_root.join("ProgramData/SkullsAndBones/gpo/apply-sb-gpo.ps1"),
                    &ps_script,
                )?;
                #[cfg(target_os = "windows")]
                if is_live_windows_root(sys_root) {
                    execute_windows_gpo_ps(&ps_script)?;
                }
            }
            OsKind::MacOs => {
                let domain_esc = escape_xml(&bundle.domain);
                let dns_block = if !dns_domains.is_empty() {
                    let servers_xml: String = dns_servers
                        .iter()
                        .map(|s| format!("      <string>{}</string>\n", escape_xml(s)))
                        .collect();
                    let domains_xml: String = dns_domains
                        .iter()
                        .map(|d| format!("      <string>{}</string>\n", escape_xml(d)))
                        .collect();
                    format!(
                        "    <dict>\n\
                               <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>\n\
                               <key>DNSSettings</key><dict>\n\
                                 <key>ServerAddresses</key><array>\n{servers_xml}        </array>\n\
                                 <key>SupplementalMatchDomains</key><array>\n{domains_xml}        </array>\n\
                               </dict>\n\
                             </dict>\n"
                    )
                } else {
                    String::new()
                };
                let mobileconfig = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                     <!-- Skulls & Bones GPO Profile | Domain: {domain_esc} | Rev: {} -->\n\
                     <plist version=\"1.0\">\n\
                     <dict>\n\
                       <key>PayloadType</key><string>Configuration</string>\n\
                       <key>PayloadVersion</key><integer>1</integer>\n\
                       <key>PayloadIdentifier</key><string>eu.skullsandbones.gpo.{domain_esc}</string>\n\
                       <key>PayloadContent</key>\n\
                       <array>\n{dns_block}  </array>\n\
                     </dict>\n\
                     </plist>\n",
                    bundle.revision
                );
                write_rendered(
                    &sys_root.join(
                        "Library/Application Support/SkullsAndBones/gpo/sb-gpo-macos.mobileconfig",
                    ),
                    &mobileconfig,
                )?;
            }
        }
    }

    Ok(PolicyApplyReport {
        machine_id: machine_id.to_string(),
        os: target_os,
        bundle_revision: bundle.revision,
        dry_run,
        applied,
        skipped,
        applied_at: Utc::now().to_rfc3339(),
    })
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn write_rendered(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create dir {}: {e}", parent.display()))?;
    }
    fs::write(path, content)
        .map_err(|e| format!("Failed to write GPO artifact {}: {e}", path.display()))
}

/// Renders an idempotent, injection-safe PowerShell script that applies Windows GPOs:
/// NRPT Split-DNS, Windows Defender Firewall (`sb-gpo-` prefix), ScreenLock registry policies,
/// and OpenSSH `sshd` reload.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** PowerShell command injection via untrusted domain names, DNS IPs,
///   or firewall parameters inside a signed policy bundle.
/// - **CVE / CWE Mapping:** CWE-78 (OS Command Injection), CWE-20 (Improper Input Validation).
/// - **Likelihood & Exploitability:** High (8/10) if unvalidated policy strings are interpolated.
/// - **Applied Mitigation:** Validates every domain via `validate_domain_name`, parses every
///   nameserver via `std::net::IpAddr`, bounds ports to `1..=65535` (`u16`) and lock timeouts
///   to `30..=86400`, and executes via stdin without shell interpolation.
#[allow(clippy::too_many_arguments)]
pub fn render_windows_gpo_ps(
    domain: &str,
    revision: u64,
    dns_domains: &[String],
    dns_servers: &[String],
    firewall_default_deny: Option<bool>,
    firewall_allow_ports: &[u16],
    screen_lock: Option<(u32, bool)>,
    has_ssh_hardening: bool,
) -> Result<String, String> {
    let clean_domain = validate_domain_name(domain)?;
    let mut lines = vec![
        "# Managed by Skulls & Bones GPO Engine (Ed25519 verified)".to_string(),
        format!("# Domain: {clean_domain} | Revision: {revision}"),
        "$ErrorActionPreference = 'Stop'".to_string(),
    ];

    if !dns_domains.is_empty() && !dns_servers.is_empty() {
        let mut valid_ips = Vec::with_capacity(dns_servers.len());
        for ip in dns_servers {
            let parsed: std::net::IpAddr = ip
                .trim()
                .parse()
                .map_err(|e| format!("Invalid DNS server IP '{ip}': {e}"))?;
            valid_ips.push(format!("'{parsed}'"));
        }
        let servers_array = format!("@({})", valid_ips.join(", "));
        lines.push("Get-DnsClientNrptRule | Where-Object { $_.Comment -like 'sb-gpo-*' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue".to_string());
        for d in dns_domains {
            let clean_d = validate_domain_name(d)?;
            lines.push(format!(
                "Add-DnsClientNrptRule -Namespace '.{clean_d}' -NameServers {servers_array} -Comment 'sb-gpo-split-dns' | Out-Null"
            ));
        }
    }

    if firewall_default_deny.is_some() || !firewall_allow_ports.is_empty() {
        lines.push("Get-NetFirewallRule -DisplayName 'sb-gpo-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue".to_string());
        if firewall_default_deny == Some(true) {
            lines.push(
                "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block"
                    .to_string(),
            );
        }
        for port in firewall_allow_ports {
            if *port > 0 {
                lines.push(format!(
                    "New-NetFirewallRule -DisplayName 'sb-gpo-allow-tcp-{port}' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow -Profile Any | Out-Null"
                ));
            }
        }
    }

    if let Some((timeout_secs, require_pw)) = screen_lock {
        let clamped = timeout_secs.clamp(30, 86400);
        let secure_flag = if require_pw { "1" } else { "0" };
        lines.push("New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Force | Out-Null".to_string());
        lines.push(format!(
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value {clamped}"
        ));
        lines.push("Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveActive' -Type String -Value '1'".to_string());
        lines.push(format!(
            "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveTimeOut' -Type String -Value '{clamped}'"
        ));
        lines.push(format!(
            "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaverIsSecure' -Type String -Value '{secure_flag}'"
        ));
    }

    if has_ssh_hardening {
        lines.push("if (Get-Service -Name 'sshd' -ErrorAction SilentlyContinue) { Restart-Service -Name 'sshd' -ErrorAction SilentlyContinue }".to_string());
    }

    Ok(lines.join("\n") + "\n")
}

#[cfg(target_os = "windows")]
fn is_live_windows_root(sys_root: &Path) -> bool {
    let raw = sys_root.to_string_lossy();
    raw == "/" || raw == "\\" || raw.eq_ignore_ascii_case("C:\\") || raw.eq_ignore_ascii_case("C:/")
}

#[cfg(target_os = "windows")]
fn execute_windows_gpo_ps(script: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn powershell.exe for Windows GPO: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("Failed writing GPO script to powershell.exe stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("powershell.exe wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Windows GPO PowerShell execution failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_core::policy::PolicyScope;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sb_node_policy_test_{label}_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn signed_policy_bundle_verifies_rejects_tampering_and_rollback_and_renders_linux_dry_run() {
        let dir = temp_dir("gpo");
        let key_path = dir.join("policy_authority.key");
        let pub_path = dir.join("policy_authority.pub");
        let store_path = dir.join("policies.json");

        let signing_key = ensure_policy_authority_keypair(&key_path, &pub_path).unwrap();
        let pub_b64 = fs::read_to_string(&pub_path).unwrap();

        let mut store = PolicyStore::load_or_create(&store_path, "corp.eu").unwrap();
        let doc = PolicyDocument {
            id: "baseline-ssh".into(),
            name: "Baseline SSH & Split DNS".into(),
            description: "Disable password SSH and route corp.eu over mesh DNS".into(),
            version: 1,
            scope: PolicyScope::Domain,
            target_os: vec![OsKind::Linux],
            rules: vec![
                PolicyRule::SshHardening {
                    password_auth: false,
                    permit_root_login: false,
                    trusted_user_ca_keys: true,
                },
                PolicyRule::DnsSplitZone {
                    domains: vec!["corp.eu".into()],
                    nameservers: vec!["10.42.0.1".into()],
                },
            ],
            updated_at: String::new(),
            updated_by: "admin".into(),
        };
        store.upsert_policy(doc).unwrap();
        store.save(&store_path).unwrap();

        let bundle = store.sign_bundle(24, &signing_key).unwrap();
        assert!(verify_policy_bundle(&bundle, "corp.eu", &pub_b64, 1).is_ok());

        // Anti-rollback check rejects older revision when min_revision is higher
        assert!(verify_policy_bundle(&bundle, "corp.eu", &pub_b64, 2).is_err());

        // Tampered policy must fail Ed25519 signature verification
        let mut tampered = bundle.clone();
        tampered.policies[0].name = "Evil".into();
        assert!(verify_policy_bundle(&tampered, "corp.eu", &pub_b64, 1).is_err());

        // Dry-run does not create files
        let sys_root = dir.join("sysroot");
        let dry_report =
            apply_policy_bundle(&bundle, "m-01", OsKind::Linux, &sys_root, true).unwrap();
        assert!(dry_report.dry_run);
        assert_eq!(dry_report.applied.len(), 2);
        assert!(!sys_root
            .join("etc/ssh/sshd_config.d/90-sb-gpo.conf")
            .exists());

        // Real apply writes deterministic Linux config files
        let real_report =
            apply_policy_bundle(&bundle, "m-01", OsKind::Linux, &sys_root, false).unwrap();
        assert!(!real_report.dry_run);
        let ssh_cfg =
            fs::read_to_string(sys_root.join("etc/ssh/sshd_config.d/90-sb-gpo.conf")).unwrap();
        assert!(ssh_cfg.contains("PasswordAuthentication no"));
        assert!(ssh_cfg.contains("TrustedUserCAKeys /etc/ssh/sb_user_ca.pub"));

        let resolved_cfg =
            fs::read_to_string(sys_root.join("etc/systemd/resolved.conf.d/90-sb-gpo.conf"))
                .unwrap();
        assert!(resolved_cfg.contains("DNS=10.42.0.1"));
        assert!(resolved_cfg.contains("Domains=~corp.eu"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_platform_windows_macos_and_scope_filtering() {
        let dir = temp_dir("xplat");
        let key_path = dir.join("policy_authority.key");
        let pub_path = dir.join("policy_authority.pub");
        let store_path = dir.join("policies.json");

        let signing_key = ensure_policy_authority_keypair(&key_path, &pub_path).unwrap();
        let mut store = PolicyStore::load_or_create(&store_path, "corp.eu").unwrap();

        // Policy 1: Domain-wide split DNS + screen lock
        store
            .upsert_policy(PolicyDocument {
                id: "workstation-baseline".into(),
                name: "Workstation Baseline".into(),
                description: "Split DNS and Screen Lock".into(),
                version: 1,
                scope: PolicyScope::Domain,
                target_os: vec![],
                rules: vec![
                    PolicyRule::DnsSplitZone {
                        domains: vec!["corp.eu".into()],
                        nameservers: vec!["10.42.0.1".into()],
                    },
                    PolicyRule::ScreenLock {
                        idle_timeout_seconds: 300,
                        require_password: true,
                    },
                ],
                updated_at: String::new(),
                updated_by: "admin".into(),
            })
            .unwrap();

        // Policy 2: OU-scoped policy (engineering only)
        store
            .upsert_policy(PolicyDocument {
                id: "eng-firewall".into(),
                name: "Engineering Firewall".into(),
                description: "Allow SSH".into(),
                version: 1,
                scope: PolicyScope::Ou("engineering".into()),
                target_os: vec![],
                rules: vec![PolicyRule::FirewallBaseline {
                    default_deny_inbound: true,
                    allow_ports: vec![22],
                }],
                updated_at: String::new(),
                updated_by: "admin".into(),
            })
            .unwrap();

        let bundle = store.sign_bundle(24, &signing_key).unwrap();

        // Apply on Windows in "sales" OU -> eng-firewall must be skipped!
        let win_root = dir.join("win");
        let win_report = apply_policy_bundle_for_target(
            &bundle,
            PolicyTargetContext {
                machine_id: "win-01",
                fqdn: Some("win-01.corp.eu"),
                ou: Some("sales"),
                os: OsKind::Windows,
            },
            &win_root,
            false,
        )
        .unwrap();
        assert_eq!(win_report.applied.len(), 2);
        assert_eq!(win_report.skipped.len(), 1);
        assert_eq!(win_report.skipped[0].policy_id, "eng-firewall");
        let win_json =
            fs::read_to_string(win_root.join("ProgramData/SkullsAndBones/gpo/sb-gpo-windows.json"))
                .unwrap();
        assert!(win_json.contains("sb.gpo.windows.v1"));
        assert!(win_json.contains("10.42.0.1"));

        // Apply on macOS in "engineering" OU -> all 3 rules apply
        let mac_root = dir.join("mac");
        let mac_report = apply_policy_bundle_for_target(
            &bundle,
            PolicyTargetContext {
                machine_id: "mac-01",
                fqdn: Some("mac-01.corp.eu"),
                ou: Some("engineering"),
                os: OsKind::MacOs,
            },
            &mac_root,
            false,
        )
        .unwrap();
        assert_eq!(mac_report.applied.len(), 3);
        assert!(mac_report.skipped.is_empty());
        let mobileconfig = fs::read_to_string(
            mac_root
                .join("Library/Application Support/SkullsAndBones/gpo/sb-gpo-macos.mobileconfig"),
        )
        .unwrap();
        assert!(mobileconfig.contains("com.apple.dnsSettings.managed"));
        assert!(mobileconfig.contains("<string>corp.eu</string>"));

        // Delete policy
        assert!(store.delete_policy("eng-firewall").unwrap());
        assert!(!store.delete_policy("eng-firewall").unwrap());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_gpo_renders_nrpt_firewall_screenlock_and_openssh() {
        let dir = std::env::temp_dir().join(format!(
            "sb_node_win_gpo_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&dir);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut store = PolicyStore::load_or_create(&dir.join("policies.json"), "corp.eu").unwrap();
        store
            .upsert_policy(PolicyDocument {
                id: "win-baseline".into(),
                name: "Windows Baseline".into(),
                description: "Windows NRPT, Firewall, ScreenLock and OpenSSH".into(),
                target_os: vec![OsKind::Windows],
                scope: PolicyScope::Domain,
                version: 1,
                updated_at: String::new(),
                updated_by: "admin".into(),
                rules: vec![
                    PolicyRule::DnsSplitZone {
                        domains: vec!["corp.eu".into()],
                        nameservers: vec!["10.42.0.1".into()],
                    },
                    PolicyRule::FirewallBaseline {
                        default_deny_inbound: true,
                        allow_ports: vec![22, 443],
                    },
                    PolicyRule::ScreenLock {
                        idle_timeout_seconds: 300,
                        require_password: true,
                    },
                    PolicyRule::SshHardening {
                        password_auth: false,
                        permit_root_login: false,
                        trusted_user_ca_keys: true,
                    },
                ],
            })
            .unwrap();

        let bundle = store.sign_bundle(24, &signing_key).unwrap();
        let win_root = dir.join("win_root");
        let report = apply_policy_bundle_for_target(
            &bundle,
            PolicyTargetContext {
                machine_id: "win-01",
                fqdn: Some("win-01.corp.eu"),
                ou: None,
                os: OsKind::Windows,
            },
            &win_root,
            false,
        )
        .unwrap();
        assert_eq!(report.applied.len(), 4);

        let ps =
            fs::read_to_string(win_root.join("ProgramData/SkullsAndBones/gpo/apply-sb-gpo.ps1"))
                .unwrap();
        assert!(ps.contains("Add-DnsClientNrptRule -Namespace '.corp.eu' -NameServers @('10.42.0.1') -Comment 'sb-gpo-split-dns'"));
        assert!(ps.contains("New-NetFirewallRule -DisplayName 'sb-gpo-allow-tcp-22'"));
        assert!(ps.contains("New-NetFirewallRule -DisplayName 'sb-gpo-allow-tcp-443'"));
        assert!(ps.contains(
            "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block"
        ));
        assert!(ps.contains("InactivityTimeoutSecs' -Type DWord -Value 300"));
        assert!(ps.contains("Restart-Service -Name 'sshd'"));

        let sshd =
            fs::read_to_string(win_root.join("ProgramData/ssh/sshd_config.d/90-sb-gpo.conf"))
                .unwrap();
        assert!(sshd.contains("PasswordAuthentication no"));
        assert!(sshd.contains("TrustedUserCAKeys C:/ProgramData/ssh/sb_user_ca.pub"));

        let _ = fs::remove_dir_all(&dir);
    }
}
