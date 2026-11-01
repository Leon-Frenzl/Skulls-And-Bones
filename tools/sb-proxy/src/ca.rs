//! S&B Developer Certificate Authority Manager
//!
//! Standards Compliance:
//! - Conforms to IETF RFC 5280 (Internet X.509 Public Key Infrastructure Certificate and CRL Profile)
//! - Conforms to IETF RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3)
//!
//! Delegates core cryptographic operations and storage to `sb-ca::x509`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const CA_COMMON_NAME: &str = sb_ca::x509::CA_COMMON_NAME;
pub const CA_ORG: &str = sb_ca::x509::CA_ORG;
pub const CA_OU: &str = sb_ca::x509::CA_OU;

pub use sb_ca::x509::{DevCertIndex, DevCertMetadata};

/// Status report summarizing the state of the Developer CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaStatusReport {
    pub initialized: bool,
    pub ca_cert_path: Option<String>,
    pub ca_key_path: Option<String>,
    pub subject: Option<String>,
    pub expires_at: Option<String>,
    pub is_installed_in_os: bool,
    pub issued_certs_count: usize,
}

impl From<sb_ca::x509::X509CaStatus> for CaStatusReport {
    fn from(s: sb_ca::x509::X509CaStatus) -> Self {
        CaStatusReport {
            initialized: s.initialized,
            ca_cert_path: if s.initialized {
                Some(s.crt_path)
            } else {
                None
            },
            ca_key_path: if s.initialized {
                Some(s.key_path)
            } else {
                None
            },
            subject: if s.initialized {
                Some(format!("CN={}, O={}, OU={}", s.common_name, s.organization, CA_OU))
            } else {
                None
            },
            expires_at: if s.initialized {
                Some("10 Jahre nach Initialisierung".into())
            } else {
                None
            },
            is_installed_in_os: s.is_installed_in_os,
            issued_certs_count: s.issued_certs_count,
        }
    }
}

/// S&B Developer Certificate Authority Manager
pub struct DeveloperCa;

impl DeveloperCa {
    /// Root directory for CA files (~/.sb/ca)
    pub fn ca_dir() -> PathBuf {
        sb_ca::paths::ca_root_dir()
    }

    /// Path to Root CA certificate (~/.sb/ca/root_ca.crt)
    pub fn root_ca_crt_path() -> PathBuf {
        sb_ca::paths::x509_root_crt_path()
    }

    /// Path to Root CA private key (~/.sb/ca/root_ca.key)
    pub fn root_ca_key_path() -> PathBuf {
        sb_ca::paths::x509_root_key_path()
    }

    /// Path to directory holding issued leaf certificates (~/.sb/ca/certs)
    pub fn certs_dir() -> PathBuf {
        sb_ca::paths::x509_certs_dir()
    }

    /// Path to certificate index file (~/.sb/ca/index.json)
    pub fn index_path() -> PathBuf {
        sb_ca::paths::x509_index_path()
    }

    /// Initializes the Sovereign Developer Root CA (ECDSA P-256 with SHA-256).
    ///
    /// SECURITY AUDIT:
    /// - Dynamic Threat Vector: Accidental overwrite of active Root CA keying material or concurrency race conditions.
    /// - CVE / CWE Mapping: CWE-312 (Cleartext Storage of Sensitive Information), CWE-362 (Race Condition).
    /// - Likelihood & Exploitability: Low (2/10).
    ///   * Threat Condition: Re-initialization attempt while proxy is running without explicit --force flag.
    /// - Applied Mitigation: Gated by existence check; delegates to synchronized ROOT_INIT_MUTEX in `sb-ca`.
    /// - Standards Compliance: RFC 5280, RFC 8446.
    pub fn init_root_ca(force: bool) -> Result<CaStatusReport, String> {
        let crt_path = Self::root_ca_crt_path();
        let key_path = Self::root_ca_key_path();

        if crt_path.exists() && key_path.exists() && !force {
            return Err(format!(
                "Developer Root CA existiert bereits unter {:?}. Verwende --force zum Überschreiben.",
                crt_path
            ));
        }

        sb_ca::x509::init_root_ca(force)
            .map(CaStatusReport::from)
            .map_err(|e| e.to_string())
    }

    /// Installs the Root CA into the local OS certificate trust store.
    pub fn install_root_ca() -> Result<String, String> {
        let crt_path = Self::root_ca_crt_path();
        if !crt_path.exists() {
            return Err(
                "Developer Root CA ist noch nicht initialisiert. Bitte führe zuerst 'sb ca init' aus."
                    .into(),
            );
        }
        sb_ca::trust::install_root_ca().map_err(|e| e.to_string())
    }

    /// Uninstalls the Root CA from the local OS certificate trust store.
    pub fn uninstall_root_ca() -> Result<String, String> {
        sb_ca::trust::uninstall_root_ca().map_err(|e| e.to_string())
    }

    /// Checks whether the Root CA is currently installed and trusted in the OS.
    pub fn is_ca_installed() -> bool {
        sb_ca::trust::is_root_ca_installed()
    }

    /// Issues a leaf certificate signed by the Developer Root CA.
    ///
    /// SECURITY AUDIT:
    /// - Dynamic Threat Vector: Domain spoofing, invalid SAN formatting, or issuing without Root CA present.
    /// - CVE / CWE Mapping: CWE-295 (Improper Certificate Validation), CWE-20 (Improper Input Validation).
    /// - Likelihood & Exploitability: Medium (4/10).
    ///   * Threat Condition: Requesting issuance with unvalidated domains or missing CA assets.
    /// - Applied Mitigation: Enforces root CA presence check; delegates to strict domain validation and ECDSA P-256 signing in `sb-ca`.
    /// - Standards Compliance: RFC 5280 §4.2.1.6, RFC 8446.
    pub fn issue_certificate(domains: &[String], ttl_days: u32) -> Result<DevCertMetadata, String> {
        if domains.is_empty() {
            return Err("Mindestens eine Domain oder IP-Adresse muss angegeben werden.".into());
        }

        let crt_path = Self::root_ca_crt_path();
        let key_path = Self::root_ca_key_path();

        if !crt_path.exists() || !key_path.exists() {
            return Err(
                "Developer Root CA nicht gefunden. Bitte führe zuerst 'sb ca init' aus.".into(),
            );
        }

        let pair = sb_ca::x509::issue_leaf_certificate(domains, ttl_days)
            .map_err(|e| e.to_string())?;

        let primary_domain = pair
            .domains
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        Ok(DevCertMetadata {
            primary_domain,
            alt_names: pair.domains.clone(),
            cert_path: pair.cert_path.to_string_lossy().to_string(),
            key_path: pair.key_path.to_string_lossy().to_string(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            expires_at: pair.expires_at.clone(),
        })
    }

    /// Loads the index of all issued certificates.
    pub fn load_index() -> DevCertIndex {
        DevCertIndex::load()
    }

    /// Saves the index of all issued certificates.
    pub fn save_index(index: &DevCertIndex) -> Result<(), String> {
        index.save().map_err(|e| e.to_string())
    }

    /// Lists all issued developer certificates.
    pub fn list_certificates() -> Vec<DevCertMetadata> {
        sb_ca::x509::X509Ca::list_certificates()
    }

    /// Returns a comprehensive status report of the Developer CA.
    pub fn get_ca_status() -> CaStatusReport {
        let crt_path = Self::root_ca_crt_path();
        let key_path = Self::root_ca_key_path();
        let initialized = crt_path.exists() && key_path.exists();

        if !initialized {
            return CaStatusReport {
                initialized: false,
                ca_cert_path: None,
                ca_key_path: None,
                subject: None,
                expires_at: None,
                is_installed_in_os: false,
                issued_certs_count: 0,
            };
        }

        sb_ca::x509::get_ca_status()
            .map(CaStatusReport::from)
            .unwrap_or_else(|_| CaStatusReport {
                initialized: false,
                ca_cert_path: None,
                ca_key_path: None,
                subject: None,
                expires_at: None,
                is_installed_in_os: false,
                issued_certs_count: 0,
            })
    }

    /// Finds a certificate pair for a given domain in the Developer CA cert store.
    pub fn find_dev_certificate(query_domain: &str) -> Option<(PathBuf, PathBuf)> {
        let q = query_domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let index = Self::load_index();

        for cert in index.certs {
            if cert.primary_domain.trim_end_matches('.').eq_ignore_ascii_case(&q)
                || cert.alt_names.iter().any(|d| d.trim_end_matches('.').eq_ignore_ascii_case(&q))
            {
                let crt = PathBuf::from(&cert.cert_path);
                let key = PathBuf::from(&cert.key_path);
                if crt.exists() && key.exists() {
                    return Some((crt, key));
                }
            }
        }

        // Direct fallback: check files in certs directory
        let safe_name = sb_ca::x509::domain_to_safe_filename(&q);
        let crt = Self::certs_dir().join(format!("{}.crt", safe_name));
        let key = Self::certs_dir().join(format!("{}.key", safe_name));
        if crt.exists() && key.exists() {
            return Some((crt, key));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    };

    #[test]
    fn test_rcgen_api() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).unwrap();
        let pem = cert.pem();
        assert!(!pem.is_empty());
    }

    #[test]
    fn test_rcgen_ca_pem_signing() {
        let ca_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = ca_key_pair.serialize_pem();

        let loaded_key = KeyPair::from_pem(&ca_key_pem).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, loaded_key).unwrap();

        let leaf_key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key_pair, &issuer).unwrap();
        let leaf_pem = leaf_cert.pem();
        assert!(!leaf_pem.is_empty());
    }

    #[test]
    fn test_developer_ca_status_report_serialization() {
        let report = CaStatusReport {
            initialized: true,
            ca_cert_path: Some("/test/root_ca.crt".into()),
            ca_key_path: Some("/test/root_ca.key".into()),
            subject: Some("CN=Test".into()),
            expires_at: Some("2036-01-01".into()),
            is_installed_in_os: true,
            issued_certs_count: 3,
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: CaStatusReport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.initialized);
        assert_eq!(deserialized.issued_certs_count, 3);
    }
}
