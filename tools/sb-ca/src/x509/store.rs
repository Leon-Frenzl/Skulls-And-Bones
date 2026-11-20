//! Storage and registry index for issued X.509 certificates.
//!
//! Standards:
//! - Conforms to IETF RFC 5280
//! - Conforms to ISO 8601 (Timestamps)

use crate::error::CaError;
use crate::paths::x509_index_path;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroize;

/// Global process-level mutex serializing all DevCertIndex disk reads and writes.
pub static INDEX_MUTEX: Mutex<()> = Mutex::new(());

/// Complete pair of issued certificate, private key, and serialized DER representations.
///
/// Interface contract for `sb-proxy` and cryptographic consumers.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Plaintext disclosure of private keys via debug logs; sensitive key lingering in heap memory.
/// - CVE / CWE Mapping: CWE-532 (Insertion of Sensitive Information into Log File), CWE-316 (Cleartext Storage of Sensitive Information in Memory).
/// - Likelihood & Exploitability: High (8/10).
/// - Applied Mitigation: Redacts key_pem and key_der in fmt::Debug; implements Zeroize and Drop to wipe heap buffers.
/// - Standards Compliance: FIPS 140-3 §7.9 (Zeroization of CSPs), ISO/IEC 15408.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuedCertPair {
    /// Full-chain certificate in PEM encoding (Leaf certificate + Root CA certificate).
    pub cert_pem: String,
    /// Private key in PEM encoding.
    pub key_pem: String,
    /// Leaf certificate in DER binary encoding.
    pub cert_der: Vec<u8>,
    /// Private key in DER binary encoding.
    pub key_der: Vec<u8>,
    /// Filesystem path to the stored certificate file.
    pub cert_path: PathBuf,
    /// Filesystem path to the stored private key file.
    pub key_path: PathBuf,
    /// List of SAN domain names and IP addresses covered by this certificate.
    pub domains: Vec<String>,
    /// RFC 3339 timestamp of expiration.
    pub expires_at: String,
}

impl fmt::Debug for IssuedCertPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCertPair")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("domains", &self.domains)
            .field("expires_at", &self.expires_at)
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"[REDACTED PRIVATE KEY]")
            .field("cert_der_len", &self.cert_der.len())
            .field("key_der", &"[REDACTED PRIVATE KEY DER]")
            .finish()
    }
}

impl Zeroize for IssuedCertPair {
    fn zeroize(&mut self) {
        self.key_pem.zeroize();
        self.key_der.zeroize();
    }
}

impl Drop for IssuedCertPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Metadata catalog entry for an issued certificate in `~/.sb/ca/index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevCertMetadata {
    pub primary_domain: String,
    pub alt_names: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
    pub issued_at: String,
    pub expires_at: String,
}

/// Registry index containing all issued certificates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevCertIndex {
    pub certs: Vec<DevCertMetadata>,
}

impl DevCertIndex {
    fn load_internal() -> Self {
        let path = x509_index_path();
        if let Ok(data) = fs::read_to_string(&path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Loads the index from `~/.sb/ca/index.json` under mutex synchronization.
    pub fn load() -> Self {
        let _guard = INDEX_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        Self::load_internal()
    }

    fn save_internal(&self) -> Result<(), CaError> {
        let path = x509_index_path();
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let _ = fs::create_dir_all(parent);

        let json = serde_json::to_string_pretty(self)?;
        let rand_suffix: u64 = rand::random();
        let tmp_path = parent.join(format!(
            ".index.json.{}.{}.tmp",
            std::process::id(),
            rand_suffix
        ));

        fs::write(&tmp_path, json.as_bytes())?;

        // Atomic file replacement via rename with retries for Windows file lock release
        for attempt in 0..5 {
            match fs::rename(&tmp_path, &path) {
                Ok(_) => return Ok(()),
                Err(_) if attempt < 4 => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(CaError::Io(e));
                }
            }
        }
        Ok(())
    }

    /// Atomically persists the index to `~/.sb/ca/index.json` under mutex synchronization.
    pub fn save(&self) -> Result<(), CaError> {
        let _guard = INDEX_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        self.save_internal()
    }

    /// Atomically records or updates an issued certificate in the index,
    /// reloading current on-disk state to eliminate lost updates (CWE-362).
    pub fn upsert(&mut self, meta: DevCertMetadata) -> Result<(), CaError> {
        let _guard = INDEX_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let mut disk_index = Self::load_internal();
        disk_index
            .certs
            .retain(|c| c.primary_domain != meta.primary_domain);
        disk_index.certs.push(meta);
        disk_index.save_internal()?;
        self.certs = disk_index.certs;
        Ok(())
    }

    /// Finds metadata for a domain if previously issued and index entry exists.
    pub fn find(&self, domain: &str) -> Option<&DevCertMetadata> {
        let needle = domain.trim().to_ascii_lowercase();
        self.certs
            .iter()
            .find(|c| c.primary_domain == needle || c.alt_names.iter().any(|a| a == &needle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issued_cert_pair_debug_redaction_and_zeroize() {
        let mut pair = IssuedCertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nMIGH...".into(),
            cert_der: vec![1, 2, 3],
            key_der: vec![4, 5, 6],
            cert_path: PathBuf::from("leaf.crt"),
            key_path: PathBuf::from("leaf.key"),
            domains: vec!["test.sbm".into()],
            expires_at: "2026-10-27T00:00:00Z".into(),
        };

        let debug_repr = format!("{:?}", pair);
        assert!(
            !debug_repr.contains("MIGH"),
            "Debug output must not leak key_pem"
        );
        assert!(
            debug_repr.contains("[REDACTED"),
            "Debug output must mark redacted keys"
        );

        pair.zeroize();
        assert!(pair.key_pem.is_empty() || pair.key_pem.chars().all(|c| c == '\0'));
        assert!(pair.key_der.is_empty() || pair.key_der.iter().all(|&b| b == 0));
    }
}
