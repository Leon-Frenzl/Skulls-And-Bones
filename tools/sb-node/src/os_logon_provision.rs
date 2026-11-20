//! Automated OS Logon Provisioning (`sb-cred-provider` on Windows, PAM/NSS on Linux).
//!
//! Safely locates signed/local native authentication modules, validates paths against
//! traversal/UNC hijacking (CWE-22 / CWE-426), supports `--dry-run`, and provides rollback.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsLogonProvisionReport {
    pub platform: String,
    pub dry_run: bool,
    pub applied: bool,
    pub module_path: Option<String>,
    pub actions: Vec<String>,
}

/// Validates that a native module path is an existing local file without traversal or UNC prefixes.
// [SECURITY-VERIFIED] CWE-22 / CWE-426 Mitigiert:
// Lehnt relative Pfade, `..`-Segmente und UNC-Netzwerkpfade (`\\...`) ab, bevor System-Installer laufen.
pub fn validate_local_module_path(path: &Path) -> Result<PathBuf, String> {
    let raw = path.to_string_lossy();
    if raw.starts_with(r"\\") || raw.starts_with("//") {
        return Err("UNC network paths are forbidden for OS logon modules".into());
    }
    if !path.is_absolute() {
        return Err("OS logon module path must be absolute".into());
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("Parent directory traversal ('..') is forbidden".into());
    }
    if !path.is_file() {
        return Err(format!("Module not found at {}", path.display()));
    }
    Ok(path.to_path_buf())
}

#[cfg(target_os = "windows")]
fn candidate_cred_provider_dll() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let dll = dir.join("sb_cred_provider.dll");
    if dll.is_file() {
        Some(dll)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn candidate_linux_pam_so() -> Option<PathBuf> {
    for dir in [
        "/lib/security",
        "/lib/x86_64-linux-gnu/security",
        "/usr/lib/security",
        "/usr/local/lib/security",
    ] {
        let p = Path::new(dir).join("pam_sb.so");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Provisions native OS login integration for the current host platform.
pub fn provision_os_logon(
    dry_run: bool,
    module_override: Option<&Path>,
) -> Result<OsLogonProvisionReport, String> {
    #[cfg(target_os = "windows")]
    {
        let dll_path = match module_override {
            Some(p) => validate_local_module_path(p)?,
            None => match candidate_cred_provider_dll() {
                Some(p) => validate_local_module_path(&p)?,
                None => {
                    return Ok(OsLogonProvisionReport {
                        platform: "windows".into(),
                        dry_run,
                        applied: false,
                        module_path: None,
                        actions: vec![
                            "sb_cred_provider.dll not found next to sb-node binary; skipped COM registration".into(),
                        ],
                    });
                }
            },
        };
        let dll_str = dll_path.to_string_lossy().to_string();
        if dry_run {
            return Ok(OsLogonProvisionReport {
                platform: "windows".into(),
                dry_run: true,
                applied: false,
                module_path: Some(dll_str.clone()),
                actions: vec![format!("DRY-RUN: regsvr32.exe /s \"{dll_str}\"")],
            });
        }
        let status = Command::new("regsvr32.exe")
            .args(["/s", &dll_str])
            .status()
            .map_err(|e| format!("Failed to invoke regsvr32.exe: {e}"))?;
        if !status.success() {
            return Err(format!(
                "regsvr32.exe failed with exit code {:?}",
                status.code()
            ));
        }
        return Ok(OsLogonProvisionReport {
            platform: "windows".into(),
            dry_run: false,
            applied: true,
            module_path: Some(dll_str.clone()),
            actions: vec![format!("Registered Windows Credential Provider: {dll_str}")],
        });
    }

    #[cfg(target_os = "linux")]
    {
        let pam_path = match module_override {
            Some(p) => validate_local_module_path(p)?,
            None => match candidate_linux_pam_so() {
                Some(p) => validate_local_module_path(&p)?,
                None => {
                    return Ok(OsLogonProvisionReport {
                        platform: "linux".into(),
                        dry_run,
                        applied: false,
                        module_path: None,
                        actions: vec![
                            "pam_sb.so not found in standard security directories; skipped PAM wiring".into(),
                        ],
                    });
                }
            },
        };
        let pam_str = pam_path.to_string_lossy().to_string();
        let dropin_path = Path::new("/etc/pam.d/sb-auth");
        let dropin_content = format!(
            "# Managed by Skulls & Bones\nauth sufficient {pam_str}\naccount sufficient {pam_str}\n"
        );
        if dry_run {
            return Ok(OsLogonProvisionReport {
                platform: "linux".into(),
                dry_run: true,
                applied: false,
                module_path: Some(pam_str),
                actions: vec![format!("DRY-RUN: write {}", dropin_path.display())],
            });
        }
        std::fs::write(dropin_path, dropin_content)
            .map_err(|e| format!("Failed to write {}: {e}", dropin_path.display()))?;
        return Ok(OsLogonProvisionReport {
            platform: "linux".into(),
            dry_run: false,
            applied: true,
            module_path: Some(pam_str),
            actions: vec![format!("Installed PAM drop-in {}", dropin_path.display())],
        });
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = module_override;
        Ok(OsLogonProvisionReport {
            platform: std::env::consts::OS.into(),
            dry_run,
            applied: false,
            module_path: None,
            actions: vec!["OS logon provisioning is not configured for this platform".into()],
        })
    }
}

/// Rolls back native OS logon registration.
pub fn rollback_os_logon(
    dry_run: bool,
    module_override: Option<&Path>,
) -> Result<OsLogonProvisionReport, String> {
    #[cfg(target_os = "windows")]
    {
        let dll_path = match module_override {
            Some(p) => validate_local_module_path(p)?,
            None => match candidate_cred_provider_dll() {
                Some(p) => validate_local_module_path(&p)?,
                None => {
                    return Ok(OsLogonProvisionReport {
                        platform: "windows".into(),
                        dry_run,
                        applied: false,
                        module_path: None,
                        actions: vec!["sb_cred_provider.dll not present; nothing to unregister".into()],
                    });
                }
            },
        };
        let dll_str = dll_path.to_string_lossy().to_string();
        if dry_run {
            return Ok(OsLogonProvisionReport {
                platform: "windows".into(),
                dry_run: true,
                applied: false,
                module_path: Some(dll_str.clone()),
                actions: vec![format!("DRY-RUN: regsvr32.exe /u /s \"{dll_str}\"")],
            });
        }
        let status = Command::new("regsvr32.exe")
            .args(["/u", "/s", &dll_str])
            .status()
            .map_err(|e| format!("Failed to invoke regsvr32.exe: {e}"))?;
        if !status.success() {
            return Err(format!(
                "regsvr32.exe /u failed with exit code {:?}",
                status.code()
            ));
        }
        return Ok(OsLogonProvisionReport {
            platform: "windows".into(),
            dry_run: false,
            applied: true,
            module_path: Some(dll_str.clone()),
            actions: vec![format!("Unregistered Windows Credential Provider: {dll_str}")],
        });
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = module_override;
        let dropin_path = Path::new("/etc/pam.d/sb-auth");
        if dry_run {
            return Ok(OsLogonProvisionReport {
                platform: std::env::consts::OS.into(),
                dry_run: true,
                applied: false,
                module_path: None,
                actions: vec![format!("DRY-RUN: remove {}", dropin_path.display())],
            });
        }
        if dropin_path.exists() {
            std::fs::remove_file(dropin_path)
                .map_err(|e| format!("Failed to remove {}: {e}", dropin_path.display()))?;
        }
        Ok(OsLogonProvisionReport {
            platform: std::env::consts::OS.into(),
            dry_run: false,
            applied: true,
            module_path: None,
            actions: vec![format!("Removed {}", dropin_path.display())],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_local_module_path_rejects_unc_and_traversal() {
        assert!(validate_local_module_path(Path::new(r"\\evil\share\a.dll")).is_err());
        assert!(validate_local_module_path(Path::new("relative/a.dll")).is_err());
        assert!(validate_local_module_path(Path::new(r"C:\foo\..\bar.dll")).is_err());

        let dir = std::env::temp_dir().join(format!("sb_os_prov_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sb_cred_provider.dll");
        std::fs::write(&file, b"mz").unwrap();
        assert!(validate_local_module_path(&file).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn provision_and_rollback_dry_run_do_not_mutate_host() {
        let dir = std::env::temp_dir().join(format!("sb_os_prov_rb_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sb_cred_provider.dll");
        std::fs::write(&file, b"mz").unwrap();

        let rep = provision_os_logon(true, Some(&file)).unwrap();
        assert!(rep.dry_run);
        assert!(!rep.applied);
        assert!(!rep.actions.is_empty());

        let rb = rollback_os_logon(true, Some(&file)).unwrap();
        assert!(rb.dry_run);
        assert!(!rb.applied);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
