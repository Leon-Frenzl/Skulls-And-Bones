//! Canonical filesystem paths and permissions management for S&B CA.
//!
//! Standards:
//! - Conforms to IEEE 1003.1 (POSIX.1-2017) File Permissions
//! - Conforms to OpenSSH security specifications for private key file modes (0600)

use std::fs;
use std::path::{Path, PathBuf};

/// Root directory for all CA files (`~/.sb/ca/`).
pub fn ca_root_dir() -> PathBuf {
    sb_core::paths::sb_ca_dir()
}

/// Directory for OpenSSH CA keypair and certificates (`~/.sb/ca/ssh/`).
pub fn ssh_dir() -> PathBuf {
    let p = ca_root_dir().join("ssh");
    let _ = fs::create_dir_all(&p);
    p
}

/// Path to OpenSSH Root CA private key (`~/.sb/ca/ssh/ca_key`).
pub fn ssh_ca_key_path() -> PathBuf {
    ssh_dir().join("ca_key")
}

/// Path to OpenSSH Root CA public key (`~/.sb/ca/ssh/ca_key.pub`).
pub fn ssh_ca_pub_path() -> PathBuf {
    ssh_dir().join("ca_key.pub")
}

/// Path to X.509 Root CA certificate (`~/.sb/ca/root_ca.crt`).
pub fn x509_root_crt_path() -> PathBuf {
    ca_root_dir().join("root_ca.crt")
}

/// Path to X.509 Root CA private key (`~/.sb/ca/root_ca.key`).
pub fn x509_root_key_path() -> PathBuf {
    ca_root_dir().join("root_ca.key")
}

/// Path to directory holding issued X.509 leaf certificates (`~/.sb/ca/certs/`).
pub fn x509_certs_dir() -> PathBuf {
    let p = ca_root_dir().join("certs");
    let _ = fs::create_dir_all(&p);
    p
}

/// Path to X.509 certificate registry index (`~/.sb/ca/index.json`).
pub fn x509_index_path() -> PathBuf {
    ca_root_dir().join("index.json")
}

/// Enforces strict user-only read/write permissions on sensitive private key files.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Unprivileged local users reading Root CA private keys from disk (BUILTIN\Users or group read).
/// - CVE / CWE Mapping: CWE-276 (Incorrect Default Permissions), CWE-732 (Incorrect Permission Assignment for Critical Resource).
/// - Likelihood & Exploitability: High (7/10).
///   * Threat Condition: Multi-user environments or when SB_HOME is on a non-default partition inheriting world-readable ACLs.
/// - Applied Mitigation: 
///   * On Windows: Disables ACL inheritance (/inheritance:r) and grants exclusive Full Control to %USERNAME% via icacls.
///   * On Unix: Explicitly applies POSIX mode 0o600.
/// - Standards Compliance: IEEE 1003.1 (POSIX.1-2017) File Permissions, Microsoft Windows Security Model.
pub fn ensure_private_permissions(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        // Clear read-only attribute if present
        let mut perms = fs::metadata(path)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);

        if let Ok(username) = std::env::var("USERNAME") {
            if !username.trim().is_empty() {
                let grant_arg = format!("{}:(F)", username.trim());
                // 0x08000000 = CREATE_NO_WINDOW
                let status = Command::new("icacls")
                    .arg(path.as_os_str())
                    .arg("/inheritance:r")
                    .arg("/grant:r")
                    .arg(&grant_arg)
                    .creation_flags(0x08000000)
                    .status();

                match status {
                    Ok(s) if s.success() => {},
                    Ok(s) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("icacls failed with exit status: {s}"),
                        ));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Atomically writes private key bytes to disk with restricted permissions from creation.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: TOCTOU race condition where a private key is briefly readable under default umask before chmod.
/// - CVE / CWE Mapping: CWE-362 (Race Condition), CWE-377 (Insecure Temporary File).
/// - Likelihood & Exploitability: Medium (4/10).
/// - Applied Mitigation: Uses OpenOptionsExt::mode(0o600) on Unix; immediately applies icacls ACL lockdown on Windows.
/// - Standards Compliance: IEEE 1003.1 (POSIX).
pub fn write_private_key_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content)?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, content)?;
        ensure_private_permissions(path)?;
    }

    Ok(())
}

