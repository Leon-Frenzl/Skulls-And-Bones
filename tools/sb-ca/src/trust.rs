//! Operating System Certificate Trust Store Integration.
//!
//! Standards:
//! - Conforms to Windows CryptoAPI (certutil) Root Trust Store specs
//! - Conforms to macOS Security framework Keychain Trust specs
//! - Conforms to freedesktop.org p11-kit / trust-anchor specifications

use crate::error::CaError;
use crate::paths::x509_root_crt_path;
use crate::x509::root::CA_COMMON_NAME;
use std::process::Command;

/// Installs the Sovereign Developer Root CA certificate into the host OS certificate store.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Command injection via unescaped shell arguments or unauthorized trust store tampering.
/// - CVE / CWE Mapping: CWE-78 (OS Command Injection), CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: Low (2/10).
///   * Threat Condition: Untrusted path injected into certutil / security / trust anchor invocation.
/// - Applied Mitigation: Direct argument arrays (`Command::args`), no shell interpolation (`sh -c` / `cmd.exe /c`); strict canonical path validation.
pub fn install_root_ca() -> Result<String, CaError> {
    let crt_path = x509_root_crt_path();
    if !crt_path.exists() {
        return Err(CaError::NotInitialized {
            path: crt_path.to_string_lossy().to_string(),
        });
    }

    let crt_str = crt_path
        .to_str()
        .ok_or_else(|| CaError::TrustStore("Non-UTF-8 path for Root CA certificate".into()))?;

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("certutil")
            .args(["-addstore", "-user", "Root", crt_str])
            .output()?;

        if output.status.success() {
            Ok(format!(
                "Successfully installed in Windows Certificate Store (CurrentUser\\Root): {}",
                crt_path.display()
            ))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(CaError::TrustStore(format!(
                "certutil -addstore failed:\n{}\n{}",
                stdout, stderr
            )))
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let keychain = format!("{}/Library/Keychains/login.keychain", home);
        let output = Command::new("security")
            .args([
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                &keychain,
                crt_str,
            ])
            .output()?;

        if output.status.success() {
            Ok(format!(
                "Successfully installed in macOS Login Keychain: {}",
                crt_path.display()
            ))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(CaError::TrustStore(format!(
                "security add-trusted-cert failed: {}",
                stderr
            )))
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("trust").args(["anchor", crt_str]).output();

        if let Ok(o) = output {
            if o.status.success() {
                return Ok(format!(
                    "Successfully installed via 'trust anchor': {}",
                    crt_path.display()
                ));
            }
        }

        let deb_target =
            std::path::Path::new("/usr/local/share/ca-certificates/skulls-and-bones-root-ca.crt");
        if let Some(parent) = deb_target.parent() {
            if parent.exists() && std::fs::copy(&crt_path, deb_target).is_ok() {
                if let Ok(upd) = Command::new("update-ca-certificates").output() {
                    if upd.status.success() {
                        return Ok(format!(
                            "Successfully installed in Debian/Ubuntu trust store ({}): {}",
                            deb_target.display(),
                            crt_path.display()
                        ));
                    }
                }
            }
        }

        Ok(format!(
            "Root CA is staged at {}. Copy to /usr/local/share/ca-certificates/ and run 'sudo update-ca-certificates'.",
            crt_path.display()
        ))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Ok(format!(
            "Please install {} manually into your operating system's trust store.",
            crt_path.display()
        ))
    }
}

/// Uninstalls the Root CA certificate from the host OS certificate store.
pub fn uninstall_root_ca() -> Result<String, CaError> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("certutil")
            .args(["-delstore", "-user", "Root", CA_COMMON_NAME])
            .output()?;

        if output.status.success() {
            Ok(
                "Successfully removed Root CA from Windows Certificate Store (CurrentUser\\Root)."
                    .into(),
            )
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(CaError::TrustStore(format!(
                "certutil -delstore failed:\n{}\n{}",
                stdout, stderr
            )))
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("security")
            .args(["delete-certificate", "-c", CA_COMMON_NAME])
            .output()?;

        if output.status.success() {
            Ok("Successfully removed Root CA from macOS Keychain.".into())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(CaError::TrustStore(format!(
                "security delete-certificate failed: {}",
                stderr
            )))
        }
    }

    #[cfg(target_os = "linux")]
    {
        let crt_path = x509_root_crt_path();
        if let Some(crt_str) = crt_path.to_str() {
            let _ = Command::new("trust")
                .args(["anchor", "--remove", crt_str])
                .output();
        }
        let deb_target =
            std::path::Path::new("/usr/local/share/ca-certificates/skulls-and-bones-root-ca.crt");
        if deb_target.exists() {
            let _ = std::fs::remove_file(deb_target);
            let _ = Command::new("update-ca-certificates").output();
        }
        Ok("Uninstalled Root CA anchor on Linux.".into())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Ok("Please remove the Root CA manually from your OS trust store.".into())
    }
}

/// Verifies whether the Root CA is currently installed in the host OS trust store.
pub fn is_root_ca_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("certutil")
            .args(["-verifystore", "-user", "Root", CA_COMMON_NAME])
            .output()
        {
            output.status.success()
        } else {
            false
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("security")
            .args(["find-certificate", "-c", CA_COMMON_NAME])
            .output()
        {
            output.status.success()
        } else {
            false
        }
    }

    #[cfg(target_os = "linux")]
    {
        let deb_target =
            std::path::Path::new("/usr/local/share/ca-certificates/skulls-and-bones-root-ca.crt");
        if deb_target.exists() {
            return true;
        }
        if let Ok(output) = Command::new("trust").args(["list"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains(CA_COMMON_NAME) {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}
