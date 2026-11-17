//! Cross-platform Local Administrator Password Solution (LAPS) for `sb-node`.
//!
//! Generates per-machine emergency local admin passwords using `OsRng`, stores them
//! encrypted via `sb_core::vault` (Argon2id + AES-256-GCM), applies the password
//! locally on Linux (`chpasswd`) or Windows (`NetUserSetInfo` / `NetUserAdd` + local
//! Administrators membership), and flags `rotate_pending` after every admin reveal.

use chrono::{Duration, Utc};
use rand::RngCore;
use sb_core::policy::validate_policy_id;
use sb_core::vault::{VaultFile, VaultSecretEntry, VaultSession, VaultStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Metadata for a machine's LAPS emergency password (safe to return without passphrase).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LapsMetadata {
    pub machine_id: String,
    pub local_account: String,
    pub rotated_at: String,
    pub expires_at: String,
    pub rotate_pending: bool,
    pub version: u32,
}

/// Persistent LAPS metadata index (`~/.sb/domain/laps_meta.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LapsMetaStore {
    pub entries: BTreeMap<String, LapsMetadata>,
}

/// Generates a strong 24-character password using OS CSPRNG (`OsRng`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Predictable or shared emergency admin passwords across
///   domain-joined Linux hosts.
/// - **CVE / CWE Mapping:** CWE-330 (Use of Insufficiently Random Values), CWE-798
///   (Use of Hard-coded Credentials).
/// - **Likelihood & Exploitability:** High (8/10) if static or weak rescue passwords are used.
/// - **Applied Mitigation:** Uses 24 rejection-free random selections from a 64-char alphabet
///   (`64^24 = 2^144` bits of entropy) backed by `OsRng`.
pub fn generate_laps_password() -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&";
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[(b & 63) as usize] as char)
        .collect()
}

/// Validates a Linux local rescue account name (`[a-z_][a-z0-9_-]{0,31}`).
pub fn validate_linux_account(account: &str) -> Result<String, String> {
    let trimmed = account.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err("Linux account name must be 1..=32 characters".into());
    }
    let first = trimmed.as_bytes()[0];
    if !first.is_ascii_lowercase() && first != b'_' {
        return Err("Linux account must start with lowercase letter or '_'".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("Linux account contains invalid characters".into());
    }
    Ok(trimmed.to_string())
}

/// Validates a Windows local SAM account name (`1..=20` safe ASCII characters).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Malicious account names containing path/SAM delimiters or
///   control characters passed to Win32 `NetUserAdd` / `NetUserSetInfo`.
/// - **CVE / CWE Mapping:** CWE-20 (Improper Input Validation), CWE-287 (Improper Authentication).
/// - **Likelihood & Exploitability:** Medium (5/10) if untrusted account strings reach Win32 APIs.
/// - **Applied Mitigation:** Restricts to `1..=20` ASCII `[A-Za-z0-9._-]`, requires leading
///   alphanumeric or `_`, forbids trailing `.` and NUL/control characters.
pub fn validate_windows_account(account: &str) -> Result<String, String> {
    let trimmed = account.trim();
    if trimmed.is_empty() || trimmed.len() > 20 {
        return Err("Windows SAM account name must be 1..=20 characters".into());
    }
    if trimmed.ends_with('.') {
        return Err("Windows account name cannot end with '.'".into());
    }
    let first = trimmed.as_bytes()[0];
    if !first.is_ascii_alphanumeric() && first != b'_' {
        return Err("Windows account must start with ASCII letter, digit, or '_'".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("Windows account contains invalid characters".into());
    }
    Ok(trimmed.to_string())
}

/// Validates a LAPS local account name across Linux and Windows targets.
pub fn validate_laps_account(account: &str) -> Result<String, String> {
    let trimmed = account.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err("LAPS account name must be 1..=32 characters".into());
    }
    if trimmed.ends_with('.') {
        return Err("LAPS account name cannot end with '.'".into());
    }
    let first = trimmed.as_bytes()[0];
    if !first.is_ascii_alphanumeric() && first != b'_' {
        return Err("LAPS account must start with ASCII letter, digit, or '_'".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("LAPS account contains invalid characters".into());
    }
    Ok(trimmed.to_string())
}

pub fn default_laps_meta_path() -> PathBuf {
    sb_core::domain::local_domain_dir().join("laps_meta.json")
}

pub fn default_laps_vault_dir() -> PathBuf {
    sb_core::domain::local_domain_dir()
        .join("vaults")
        .join("laps")
}

impl LapsMetaStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read LAPS metadata {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid LAPS metadata JSON {}: {e}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create LAPS dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize LAPS metadata: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp LAPS metadata: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit LAPS metadata: {e}"))?;
        Ok(())
    }
}

/// Encrypts and stores a rotated LAPS password for `machine_id`, updating metadata.
pub fn store_laps_password(
    machine_id: &str,
    local_account: &str,
    password: &str,
    passphrase: &str,
    ttl_days: i64,
    vault_dir: &Path,
    meta_path: &Path,
) -> Result<LapsMetadata, String> {
    let clean_id = validate_policy_id(machine_id)?;
    let clean_acct = validate_laps_account(local_account)?;
    if passphrase.is_empty() || password.len() < 12 {
        return Err("LAPS passphrase cannot be empty and password must be >= 12 chars".into());
    }

    let store = VaultStore::new(vault_dir);
    let session = VaultSession::new(passphrase);
    let mut vault: VaultFile = store.load("laps")?;
    if vault.verifier.is_none() {
        session.initialize(&mut vault)?;
    } else {
        session.verify_vault(&vault)?;
    }

    let (ciphertext, nonce, salt) = session.encrypt(password)?;
    let mut meta_store = LapsMetaStore::load(meta_path)?;
    let next_ver = meta_store
        .entries
        .get(&clean_id)
        .map(|m| m.version.saturating_add(1))
        .unwrap_or(1);

    let now = Utc::now();
    let clamped_days = ttl_days.clamp(1, 90);
    let rotated_at = now.to_rfc3339();
    let expires_at = (now + Duration::days(clamped_days)).to_rfc3339();

    vault.secrets.insert(
        clean_id.clone(),
        VaultSecretEntry {
            ciphertext,
            nonce,
            salt,
            updated_at: rotated_at.clone(),
            updated_by: clean_acct.clone(),
            version: next_ver,
            project: "laps".into(),
        },
    );
    store.save("laps", &vault)?;

    let meta = LapsMetadata {
        machine_id: clean_id.clone(),
        local_account: clean_acct,
        rotated_at,
        expires_at,
        rotate_pending: false,
        version: next_ver,
    };
    meta_store.entries.insert(clean_id, meta.clone());
    meta_store.save(meta_path)?;
    Ok(meta)
}

/// Decrypts a machine's LAPS password and marks `rotate_pending = true` so it rotates next.
pub fn reveal_laps_password(
    machine_id: &str,
    passphrase: &str,
    vault_dir: &Path,
    meta_path: &Path,
) -> Result<(String, LapsMetadata), String> {
    let clean_id = validate_policy_id(machine_id)?;
    if passphrase.is_empty() {
        return Err("LAPS passphrase cannot be empty".into());
    }
    let store = VaultStore::new(vault_dir);
    let session = VaultSession::new(passphrase);
    let vault = store.load("laps")?;
    session.verify_vault(&vault)?;
    let entry = vault
        .secrets
        .get(&clean_id)
        .ok_or_else(|| format!("No LAPS password stored for machine '{clean_id}'"))?;
    let password = session.decrypt(entry)?;

    let mut meta_store = LapsMetaStore::load(meta_path)?;
    let meta = meta_store
        .entries
        .get_mut(&clean_id)
        .ok_or_else(|| format!("Missing LAPS metadata for '{clean_id}'"))?;
    meta.rotate_pending = true;
    let updated_meta = meta.clone();
    meta_store.save(meta_path)?;
    Ok((password, updated_meta))
}

/// Applies the LAPS password locally on Linux via `chpasswd` (unless `dry_run` is true).
#[cfg(target_os = "linux")]
pub fn apply_linux_chpasswd(account: &str, password: &str, dry_run: bool) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let clean_acct = validate_linux_account(account)?;
    if password.contains('\n') || password.contains('\r') || password.contains(':') {
        return Err("Password contains forbidden chpasswd delimiter".into());
    }
    if dry_run {
        return Ok(());
    }
    let mut child = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn chpasswd: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{clean_acct}:{password}")
            .map_err(|e| format!("Failed writing to chpasswd stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("chpasswd wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chpasswd exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_linux_chpasswd(account: &str, _password: &str, dry_run: bool) -> Result<(), String> {
    let _ = validate_linux_account(account)?;
    if dry_run {
        return Ok(());
    }
    Err("apply_linux_chpasswd requires a Linux host (use --dry-run on non-Linux)".into())
}

/// Applies or rotates a LAPS emergency admin password natively on Windows using Win32
/// `NetUserSetInfo` / `NetUserAdd` and ensures membership in the localized local
/// Administrators group (`S-1-5-32-544`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Exposing plaintext LAPS passwords in process command lines
///   (e.g. `net user ... <pw>`) or failing on non-English Windows group names (`Administratoren`).
/// - **CVE / CWE Mapping:** CWE-214 (Invocation of Process Using Visible Sensitive Information),
///   CWE-259 / CWE-798 (Password Management), CWE-20 (Improper Input Validation).
/// - **Likelihood & Exploitability:** High (8/10) if `net user` CLI is spawned with secrets.
/// - **Applied Mitigation:** Uses Win32 `NetUserSetInfo` / `NetUserAdd` directly in memory
///   (no child process or command-line exposure), resolves `S-1-5-32-544` via `LookupAccountSidW`,
///   and zeroes the UTF-16 password buffer immediately after the Win32 call.
// Conforms to NIST SP 800-63B §5.1.1.2 (memorized secret length >= 12) and Microsoft MS-SAMR.
#[cfg(target_os = "windows")]
pub fn apply_windows_laps(account: &str, password: &str, dry_run: bool) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_MEMBER_IN_ALIAS};
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NERR_Success, NetLocalGroupAddMembers, NetUserAdd, NetUserSetInfo,
        LOCALGROUP_MEMBERS_INFO_3, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_INFO_1003,
        USER_PRIV_USER,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};

    let clean_acct = validate_windows_account(account)?;
    if password.len() < 12 || password.contains('\0') {
        return Err("Windows LAPS password must be >= 12 chars and NUL-free".into());
    }
    if dry_run {
        return Ok(());
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    const NERR_USER_NOT_FOUND: u32 = 2221;
    let mut acct_w = to_wide(&clean_acct);
    let mut pw_w = to_wide(password);

    // SAFETY: `acct_w` and `pw_w` are valid NUL-terminated UTF-16 buffers alive across the call.
    let status = unsafe {
        let info = USER_INFO_1003 {
            usri1003_password: pw_w.as_mut_ptr(),
        };
        NetUserSetInfo(
            null(),
            acct_w.as_ptr(),
            1003,
            (&info as *const USER_INFO_1003).cast::<u8>(),
            null_mut(),
        )
    };

    if status == NERR_USER_NOT_FOUND {
        // SAFETY: `acct_w` and `pw_w` are valid NUL-terminated UTF-16 buffers alive across `NetUserAdd`.
        let add_status = unsafe {
            let mut comment_w = to_wide("Skulls & Bones LAPS Emergency Admin");
            let user_info = USER_INFO_1 {
                usri1_name: acct_w.as_mut_ptr(),
                usri1_password: pw_w.as_mut_ptr(),
                usri1_password_age: 0,
                usri1_priv: USER_PRIV_USER,
                usri1_home_dir: null_mut(),
                usri1_comment: comment_w.as_mut_ptr(),
                usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
                usri1_script_path: null_mut(),
            };
            let mut parm_err: u32 = 0;
            NetUserAdd(
                null(),
                1,
                (&user_info as *const USER_INFO_1).cast::<u8>(),
                &mut parm_err,
            )
        };
        if add_status != NERR_Success {
            pw_w.fill(0);
            return Err(format!("NetUserAdd failed with Win32 status {add_status}"));
        }
    } else if status != NERR_Success {
        pw_w.fill(0);
        return Err(format!("NetUserSetInfo failed with Win32 status {status}"));
    }

    // Zeroize UTF-16 password buffer immediately after NetUserAdd / NetUserSetInfo.
    pw_w.fill(0);

    // Ensure the LAPS account is a member of the localized local Administrators group (S-1-5-32-544).
    let sid_str = to_wide("S-1-5-32-544");
    let mut sid: PSID = null_mut();
    // SAFETY: `sid_str` is a NUL-terminated UTF-16 SID literal; `sid` is freed with `LocalFree`.
    let sid_ok = unsafe { ConvertStringSidToSidW(sid_str.as_ptr(), &mut sid) };
    if sid_ok == 0 || sid.is_null() {
        return Err("ConvertStringSidToSidW failed for S-1-5-32-544".into());
    }

    let mut name_buf = vec![0u16; 256];
    let mut name_len = name_buf.len() as u32;
    let mut dom_buf = vec![0u16; 256];
    let mut dom_len = dom_buf.len() as u32;
    let mut sid_use: SID_NAME_USE = 0;

    // SAFETY: Buffers and lengths are valid; `sid` is freed right after `LookupAccountSidW`.
    let lookup_ok = unsafe {
        let ok = LookupAccountSidW(
            null(),
            sid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            dom_buf.as_mut_ptr(),
            &mut dom_len,
            &mut sid_use,
        );
        LocalFree(sid);
        ok
    };
    if lookup_ok == 0 {
        return Err("LookupAccountSidW failed for S-1-5-32-544".into());
    }

    // SAFETY: `name_buf` and `acct_w` are NUL-terminated UTF-16 strings.
    let grp_status = unsafe {
        let member = LOCALGROUP_MEMBERS_INFO_3 {
            lgrmi3_domainandname: acct_w.as_mut_ptr(),
        };
        NetLocalGroupAddMembers(
            null(),
            name_buf.as_ptr(),
            3,
            (&member as *const LOCALGROUP_MEMBERS_INFO_3).cast::<u8>(),
            1,
        )
    };
    if grp_status != NERR_Success && grp_status != ERROR_MEMBER_IN_ALIAS {
        return Err(format!(
            "NetLocalGroupAddMembers failed with Win32 status {grp_status}"
        ));
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn apply_windows_laps(account: &str, password: &str, dry_run: bool) -> Result<(), String> {
    let _ = validate_windows_account(account)?;
    if password.len() < 12 || password.contains('\0') {
        return Err("Windows LAPS password must be >= 12 chars and NUL-free".into());
    }
    if dry_run {
        return Ok(());
    }
    Err("apply_windows_laps requires a Windows host (use --dry-run on non-Windows)".into())
}

/// Applies the LAPS password natively on the current host OS (Linux or Windows).
pub fn apply_local_laps(account: &str, password: &str, dry_run: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        apply_linux_chpasswd(account, password, dry_run)
    }
    #[cfg(target_os = "windows")]
    {
        apply_windows_laps(account, password, dry_run)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (account, password);
        if dry_run {
            return Ok(());
        }
        Err("Local LAPS password application is supported on Linux and Windows only".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laps_rotates_encrypts_and_marks_rotate_pending_on_reveal() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_laps_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&temp);
        let vault_dir = temp.join("vault");
        let meta_path = temp.join("laps_meta.json");

        let pw = generate_laps_password();
        assert_eq!(pw.len(), 24);
        assert!(validate_linux_account("sb-rescue").is_ok());
        assert!(validate_linux_account("Root").is_err());

        let meta = store_laps_password(
            "m-app-01",
            "sb-rescue",
            &pw,
            "laps-master-secret",
            30,
            &vault_dir,
            &meta_path,
        )
        .unwrap();
        assert!(!meta.rotate_pending);
        assert_eq!(meta.version, 1);

        // Wrong passphrase must fail
        assert!(reveal_laps_password("m-app-01", "wrong", &vault_dir, &meta_path).is_err());

        // Correct passphrase decrypts and sets rotate_pending = true
        let (revealed, updated_meta) =
            reveal_laps_password("m-app-01", "laps-master-secret", &vault_dir, &meta_path).unwrap();
        assert!(revealed == pw);
        assert!(updated_meta.rotate_pending);

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn windows_laps_validates_account_and_supports_dry_run() {
        assert!(validate_windows_account("sb-rescue").is_ok());
        assert!(validate_windows_account("Admin_01").is_ok());
        assert!(validate_windows_account("too-long-sam-account-name").is_err());
        assert!(validate_windows_account("bad.name.").is_err());
        assert!(validate_windows_account("bad;name").is_err());

        let pw = generate_laps_password();
        assert!(apply_windows_laps("sb-rescue", &pw, true).is_ok());
        assert!(apply_windows_laps("sb-rescue", "short", true).is_err());
        assert!(apply_local_laps("sb-rescue", &pw, true).is_ok());
    }
}
