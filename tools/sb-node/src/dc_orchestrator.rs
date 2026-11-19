//! Zero-Docker One-Command Domain Controller (`sb-node dc up`).
//!
//! Idempotently bootstraps `sb-auth`, `sb-ca`, `sb-dns` SRV discovery, `PolicyStore`,
//! initial admin account + JIT RBAC rule, issues a single-use browser login code, and
//! launches both the DC API (`sb-node`) and the Open Graph Gateway + Console (`sb-proxy`).

use crate::directory_users::IdentityDirectory;
use crate::domain_join::{serve_domain_join, DomainRegistry};
use crate::oidc::LoginCodeStore;
use crate::policy_engine::{
    default_policy_authority_key_path, default_policy_authority_pub_path,
    default_policy_store_path, ensure_policy_authority_keypair, PolicyStore,
};
use crate::rbac::{ElevationRule, RbacStore};
use sb_core::domain::{local_domain_dir, validate_domain_name};
use sb_core::identity::{validate_username, DomainUser};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Configuration for `sb-node dc up`.
#[derive(Debug, Clone)]
pub struct DcBootstrapConfig {
    pub domain: String,
    pub admin_username: String,
    pub dc_bind: SocketAddr,
    pub graph_bind: SocketAddr,
    pub console_dir: PathBuf,
}

/// Summary produced after bootstrapping all DC subsystems.
#[derive(Debug, Clone)]
pub struct DcBootstrapReport {
    pub domain: String,
    pub admin_username: String,
    pub login_code: String,
    pub dc_bind: SocketAddr,
    pub graph_bind: SocketAddr,
}

/// Idempotently initializes all Domain Controller state on disk (no Docker required).
pub fn bootstrap_dc_state(
    cfg: &DcBootstrapConfig,
    sb_home_dir: Option<&Path>,
    domain_dir_override: Option<&Path>,
    register_dns: bool,
) -> Result<DcBootstrapReport, String> {
    let clean_domain = validate_domain_name(&cfg.domain)?;
    let clean_admin = validate_username(&cfg.admin_username)?;
    let sb_home = sb_home_dir
        .map(PathBuf::from)
        .unwrap_or_else(sb_core::paths::sb_home);
    let domain_dir = domain_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(local_domain_dir);
    fs::create_dir_all(&domain_dir)
        .map_err(|e| format!("Failed to create domain dir {}: {e}", domain_dir.display()))?;

    // 1. Bootstrap sb-auth keypair & revocation store if missing
    let auth_dir = sb_home.join("auth");
    fs::create_dir_all(&auth_dir)
        .map_err(|e| format!("Failed to create auth dir {}: {e}", auth_dir.display()))?;
    let key_path = auth_dir.join("auth.key");
    let pub_path = auth_dir.join("auth.pub");
    if !key_path.exists() || !pub_path.exists() {
        let kp = sb_auth::crypto::Keypair::generate();
        fs::write(&key_path, kp.to_secret_base64())
            .map_err(|e| format!("Failed to write auth.key: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
        fs::write(&pub_path, kp.to_public_base64())
            .map_err(|e| format!("Failed to write auth.pub: {e}"))?;
    }
    let rev_path = auth_dir.join("revocations.json");
    let _ = sb_auth::FileRevocationStore::open(&rev_path)
        .map_err(|e| format!("Failed to initialize revocation store: {e}"))?;

    // 2. Bootstrap sb-ca (X.509 & SSH CA) if running against default home
    if sb_home_dir.is_none() {
        sb_ca::init_all(false).map_err(|e| format!("Failed to initialize sb-ca: {e}"))?;
    }

    // 3. Bootstrap DomainRegistry & AD-DNS SRV records
    let reg_path = domain_dir.join("machines.json");
    let reg = if domain_dir_override.is_some() {
        DomainRegistry::load_from_path(&reg_path, &clean_domain)?
    } else {
        DomainRegistry::load_or_create(&clean_domain)?
    };
    reg.save_to_path(&reg_path)?;
    if register_dns {
        let dc_fqdn = format!("dc.{clean_domain}");
        let srv_name = format!("_dc._tcp.{clean_domain}");
        sb_dns::config::ConfigManager::add_a_record(
            &dc_fqdn,
            std::net::Ipv4Addr::new(10, 42, 0, 1),
        )?;
        sb_dns::config::ConfigManager::add_srv_record(
            &srv_name,
            10,
            0,
            cfg.dc_bind.port(),
            &dc_fqdn,
        )?;
    }

    // 4. Bootstrap GPO Policy Authority & PolicyStore
    let policy_key = if domain_dir_override.is_some() {
        domain_dir.join("policy_authority.key")
    } else {
        default_policy_authority_key_path()
    };
    let policy_pub = if domain_dir_override.is_some() {
        domain_dir.join("policy_authority.pub")
    } else {
        default_policy_authority_pub_path()
    };
    let _ = ensure_policy_authority_keypair(&policy_key, &policy_pub)?;
    let policy_store_path = if domain_dir_override.is_some() {
        domain_dir.join("policies.json")
    } else {
        default_policy_store_path()
    };
    let policy_store = PolicyStore::load_or_create(&policy_store_path, &clean_domain)?;
    policy_store.save(&policy_store_path)?;

    // 5. Bootstrap Initial Admin User & RBAC JIT Rule
    let users_path = domain_dir.join("users.json");
    let mut users_dir = IdentityDirectory::load_or_create(&users_path, &clean_domain)?;
    if !users_dir.users.contains_key(&clean_admin) {
        users_dir.upsert_user(DomainUser {
            username: clean_admin.clone(),
            display_name: format!("{clean_admin} (Domain Admin)"),
            email: format!("{clean_admin}@{clean_domain}"),
            ou: "/".into(),
            groups: vec!["admins".into()],
            ssh_public_key: None,
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        })?;
        users_dir.save(&users_path)?;
    }

    let rbac_path = domain_dir.join("rbac.json");
    let mut rbac = RbacStore::load(&rbac_path)?;
    if !rbac.rules.contains_key("jit-domain-admin") {
        rbac.upsert_rule(ElevationRule {
            id: "jit-domain-admin".into(),
            description: "Temporary Domain Admin elevation for members of 'admins'".into(),
            eligible_users: Vec::new(),
            eligible_groups: vec!["admins".into()],
            granted_capabilities: vec![
                "domain:admin".into(),
                "policy:write".into(),
                "directory:write".into(),
            ],
            max_ttl_seconds: 3600,
            require_reason: true,
        })?;
        rbac.save(&rbac_path)?;
    }

    // 6. Issue a single-use browser login code for immediate Console sign-in
    let codes_path = domain_dir.join("login_codes.json");
    let mut code_store = LoginCodeStore::load(&codes_path)?;
    let login_code = code_store.issue_code(
        &clean_admin,
        vec![
            "domain:admin".into(),
            "domain:read".into(),
            "domain:join".into(),
            "directory:read".into(),
            "directory:write".into(),
            "policy:write".into(),
            "audit:read".into(),
            "dns:write".into(),
            "vault:write".into(),
        ],
        900,
    );
    code_store.save(&codes_path)?;

    Ok(DcBootstrapReport {
        domain: clean_domain,
        admin_username: clean_admin,
        login_code,
        dc_bind: cfg.dc_bind,
        graph_bind: cfg.graph_bind,
    })
}

fn spawn_sb_proxy_graph(cfg: &DcBootstrapConfig) -> Result<Child, String> {
    let exe_name = if cfg!(windows) {
        "sb-proxy.exe"
    } else {
        "sb-proxy"
    };
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(exe_name)));
    let bin = sibling
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("sb-proxy"));

    Command::new(&bin)
        .arg("graph")
        .arg("--bind")
        .arg(cfg.graph_bind.to_string())
        .arg("--dc")
        .arg(cfg.dc_bind.to_string())
        .arg("--console-dir")
        .arg(&cfg.console_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            format!(
                "Failed to spawn '{}' graph gateway (build with `cargo build -p sb-proxy` first): {e}",
                bin.display()
            )
        })
}

/// Runs the full One-Command Domain Controller (`sb-node` + `sb-proxy graph`) without Docker.
pub async fn run_one_command_dc(cfg: DcBootstrapConfig) -> Result<(), String> {
    let report = bootstrap_dc_state(&cfg, None, None, true)?;
    let verifier = crate::load_local_auth_verifier()?;

    let mut proxy_child = spawn_sb_proxy_graph(&cfg)?;

    println!("\n=== SKULLS & BONES — SOVEREIGN DOMAIN CONTROLLER ACTIVE (NO DOCKER) ===");
    println!("  ► Domain:          {}", report.domain);
    println!("  ► DC API:          http://{}", report.dc_bind);
    println!("  ► Web Console:     http://{}/", report.graph_bind);
    println!("  ► Public Enroll:   http://{}/enroll", report.graph_bind);
    println!(
        "  ► OpenAPI 3.1:     http://{}/v1/openapi.json",
        report.graph_bind
    );
    println!("  ► Admin User:      {}", report.admin_username);
    println!(
        "  ► Login-Code (1x): {}  (15 Min gültig)",
        report.login_code
    );
    println!("========================================================================\n");

    let res = serve_domain_join(cfg.dc_bind, verifier, None, true).await;
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
    res
}

/// Encrypted, integrity-checked Domain Controller backup envelope (`.sb-bak`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DcBackupEnvelope {
    pub format_version: u32,
    pub created_at: String,
    pub file_count: usize,
    pub ciphertext: String,
    pub nonce: String,
    pub salt: String,
    pub sha256: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DcSnapshotPayload {
    format_version: u32,
    created_at: String,
    files: std::collections::BTreeMap<String, String>,
}

/// Summary returned after creating a DC backup.
#[derive(Debug, Clone)]
pub struct DcBackupReport {
    pub out_path: PathBuf,
    pub file_count: usize,
    pub sha256: String,
}

/// Summary returned after restoring a DC backup.
#[derive(Debug, Clone)]
pub struct DcRestoreReport {
    pub restored_files: usize,
    pub created_at: String,
}

fn collect_dir_files(
    base_dir: &Path,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    if !base_dir.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(base_dir)
        .map_err(|e| format!("Failed reading {}: {e}", base_dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let rel = format!("{prefix}/{name}");
        if path.is_dir() {
            collect_dir_files(&path, &rel, out)?;
        } else if path.is_file() {
            let bytes =
                fs::read(&path).map_err(|e| format!("Failed reading {}: {e}", path.display()))?;
            out.insert(rel, B64.encode(bytes));
        }
    }
    Ok(())
}

fn validate_backup_rel_path(rel: &str) -> Result<(), String> {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.contains("..")
        || rel.contains('\\')
        || rel.contains('\0')
    {
        return Err(format!("Unsafe relative path in backup: '{rel}'"));
    }
    let allowed = ["auth/", "ca/", "dns/", "domain/"];
    if !allowed.iter().any(|p| rel.starts_with(p)) {
        return Err(format!("Unexpected top-level directory in backup: '{rel}'"));
    }
    Ok(())
}

fn compute_envelope_sha256(
    format_version: u32,
    created_at: &str,
    file_count: usize,
    ciphertext: &str,
    nonce: &str,
    salt: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(format_version.to_le_bytes());
    h.update(b"|");
    h.update(created_at.as_bytes());
    h.update(b"|");
    h.update(file_count.to_le_bytes());
    h.update(b"|");
    h.update(ciphertext.as_bytes());
    h.update(b"|");
    h.update(nonce.as_bytes());
    h.update(b"|");
    h.update(salt.as_bytes());
    hex::encode(h.finalize())
}

/// Creates an encrypted (Argon2id + AES-256-GCM) and SHA-256 integrity-protected backup of the DC.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Exfiltration of CA private keys, auth signing keys, or LAPS
///   vaults from unencrypted backup files, or silent backup corruption.
/// - **CVE / CWE Mapping:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-353
///   (Missing Support for Integrity Check).
/// - **Likelihood & Exploitability:** High (8/10) for DC backups containing root keys.
/// - **Applied Mitigation:** Encrypts the entire snapshot via `sb_core::vault::VaultSession`
///   (Argon2id + AES-256-GCM) and binds a SHA-256 integrity digest over the envelope.
pub fn create_dc_backup(
    out_path: &Path,
    passphrase: &str,
    sb_home_override: Option<&Path>,
) -> Result<DcBackupReport, String> {
    if passphrase.len() < 8 {
        return Err("Backup passphrase must be at least 8 characters".into());
    }
    let sb_home = sb_home_override
        .map(PathBuf::from)
        .unwrap_or_else(sb_core::paths::sb_home);
    let mut files = std::collections::BTreeMap::new();
    for sub in ["auth", "ca", "dns", "domain"] {
        collect_dir_files(&sb_home.join(sub), sub, &mut files)?;
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    let file_count = files.len();
    let payload = DcSnapshotPayload {
        format_version: 1,
        created_at: created_at.clone(),
        files,
    };
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| format!("Failed to serialize DC backup payload: {e}"))?;

    let session = sb_core::vault::VaultSession::new(passphrase);
    let (ciphertext, nonce, salt) = session.encrypt(&payload_json)?;
    let sha256 = compute_envelope_sha256(1, &created_at, file_count, &ciphertext, &nonce, &salt);
    let envelope = DcBackupEnvelope {
        format_version: 1,
        created_at,
        file_count,
        ciphertext,
        nonce,
        salt,
        sha256: sha256.clone(),
    };

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create backup output dir: {e}"))?;
        }
    }
    let env_json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| format!("Failed to serialize backup envelope: {e}"))?;
    fs::write(out_path, env_json)
        .map_err(|e| format!("Failed to write backup {}: {e}", out_path.display()))?;

    Ok(DcBackupReport {
        out_path: out_path.to_path_buf(),
        file_count,
        sha256,
    })
}

/// Verifies, decrypts, and restores a `.sb-bak` Domain Controller backup into `sb_home`.
pub fn restore_dc_backup(
    backup_path: &Path,
    passphrase: &str,
    sb_home_override: Option<&Path>,
) -> Result<DcRestoreReport, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let raw = fs::read_to_string(backup_path)
        .map_err(|e| format!("Failed to read backup {}: {e}", backup_path.display()))?;
    let envelope: DcBackupEnvelope =
        serde_json::from_str(&raw).map_err(|e| format!("Invalid backup envelope JSON: {e}"))?;
    if envelope.format_version != 1 {
        return Err(format!(
            "Unsupported backup format_version {}",
            envelope.format_version
        ));
    }

    let expected_sha = compute_envelope_sha256(
        envelope.format_version,
        &envelope.created_at,
        envelope.file_count,
        &envelope.ciphertext,
        &envelope.nonce,
        &envelope.salt,
    );
    if expected_sha != envelope.sha256 {
        return Err(
            "Backup integrity check (SHA-256) failed — file may be corrupted or tampered".into(),
        );
    }

    let session = sb_core::vault::VaultSession::new(passphrase);
    let entry = sb_core::vault::VaultSecretEntry {
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        salt: envelope.salt,
        updated_at: envelope.created_at.clone(),
        updated_by: "backup".into(),
        version: 1,
        project: "dc-backup".into(),
    };
    let payload_json = session.decrypt(&entry)?;
    let payload: DcSnapshotPayload = serde_json::from_str(&payload_json)
        .map_err(|e| format!("Invalid decrypted DC snapshot JSON: {e}"))?;

    for rel in payload.files.keys() {
        validate_backup_rel_path(rel)?;
    }

    let sb_home = sb_home_override
        .map(PathBuf::from)
        .unwrap_or_else(sb_core::paths::sb_home);
    let mut restored = 0usize;
    for (rel, b64) in &payload.files {
        let bytes = B64
            .decode(b64)
            .map_err(|e| format!("Invalid base64 for '{rel}': {e}"))?;
        let dest = sb_home.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create dir {}: {e}", parent.display()))?;
        }
        fs::write(&dest, bytes)
            .map_err(|e| format!("Failed to restore {}: {e}", dest.display()))?;
        #[cfg(unix)]
        if rel.ends_with(".key") || rel.ends_with("ca_key") {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o600));
        }
        restored += 1;
    }

    Ok(DcRestoreReport {
        restored_files: restored,
        created_at: payload.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_dc_state_is_idempotent_and_creates_working_login_code() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_dc_boot_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&temp);
        let sb_home = temp.join("home");
        let domain_dir = temp.join("domain");

        let cfg = DcBootstrapConfig {
            domain: "corp.eu".into(),
            admin_username: "anna.admin".into(),
            dc_bind: "127.0.0.1:8443".parse().unwrap(),
            graph_bind: "127.0.0.1:8090".parse().unwrap(),
            console_dir: PathBuf::from("console/dist"),
        };

        let r1 = bootstrap_dc_state(&cfg, Some(&sb_home), Some(&domain_dir), false).unwrap();
        assert!(r1.login_code.starts_with("sbc_"));
        assert!(sb_home.join("auth/auth.key").exists());
        assert!(domain_dir.join("users.json").exists());
        assert!(domain_dir.join("rbac.json").exists());

        // Second run is idempotent and does not fail
        let r2 = bootstrap_dc_state(&cfg, Some(&sb_home), Some(&domain_dir), false).unwrap();
        assert!(r2.login_code.starts_with("sbc_"));
        assert_ne!(r1.login_code, r2.login_code);

        // Backup & Restore roundtrip
        let backup_file = temp.join("corp.sb-bak");
        let bak_rep =
            create_dc_backup(&backup_file, "super-backup-secret", Some(&sb_home)).unwrap();
        assert!(bak_rep.file_count >= 2);

        // Wrong passphrase must fail
        let restore_home = temp.join("restored_home");
        assert!(restore_dc_backup(&backup_file, "wrong-pass", Some(&restore_home)).is_err());

        // Correct passphrase restores files cleanly
        let res_rep =
            restore_dc_backup(&backup_file, "super-backup-secret", Some(&restore_home)).unwrap();
        assert_eq!(res_rep.restored_files, bak_rep.file_count);
        assert!(restore_home.join("auth/auth.key").exists());

        // Tampered envelope fails SHA-256 check
        let raw_bak = fs::read_to_string(&backup_file).unwrap();
        let tampered = raw_bak.replacen(&bak_rep.sha256, &"f".repeat(64), 1);
        fs::write(&backup_file, tampered).unwrap();
        assert!(
            restore_dc_backup(&backup_file, "super-backup-secret", Some(&restore_home)).is_err()
        );

        let _ = fs::remove_dir_all(&temp);
    }
}
