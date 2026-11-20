//! X.509 Root Certificate Authority management using ECDSA P-256.
//!
//! Standards:
//! - Conforms to IETF RFC 5280 (X.509 PKI Certificate and CRL Profile)
//! - Conforms to IETF RFC 8446 (TLS 1.3)
//! - Conforms to ISO 8601 (Timestamps)

use crate::error::CaError;
use crate::paths::{
    write_private_key_file, x509_certs_dir, x509_index_path, x509_root_crt_path, x509_root_key_path,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroize;

pub const CA_COMMON_NAME: &str = "Skulls & Bones Sovereign Developer Root CA";
pub const CA_ORG: &str = "Skulls & Bones Lab";
pub const CA_OU: &str = "Developer CA";
pub const CA_VALIDITY_DAYS: i64 = 3650; // 10 years

static ROOT_INIT_MUTEX: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CaStatus {
    pub initialized: bool,
    pub crt_path: String,
    pub key_path: String,
    pub common_name: String,
    pub organization: String,
    pub is_installed_in_os: bool,
    pub issued_certs_count: usize,
}

/// Initializes the Sovereign Developer Root CA (ECDSA P-256 with SHA-256).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Compromise or silent overwrite of Root CA key material; weak RSA keys or curve subversion; split-brain race conditions during concurrent initializations.
/// - CVE / CWE Mapping: CWE-312 (Cleartext Storage of Sensitive Information at Rest), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-362 (Concurrent Execution using Shared Resource).
/// - Likelihood & Exploitability: Low to Medium (3/10).
///   * Threat Condition: Unprivileged process overwriting CA certificate or concurrent threads racing to create disparate root keys.
/// - Applied Mitigation: Synchronized via ROOT_INIT_MUTEX; enforces ECDSA NIST P-256 (mandatory-to-implement in TLS 1.3 RFC 8446); checks existing keys to prevent accidental overwrite unless `--force` is specified; secures file mode 0o600 / Windows ACLs; zeroizes in-memory PEM key buffers.
pub fn init_root_ca(force: bool) -> Result<X509CaStatus, CaError> {
    let _guard = ROOT_INIT_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let crt_path = x509_root_crt_path();
    let key_path = x509_root_key_path();

    if crt_path.exists() && key_path.exists() && !force {
        return get_ca_status();
    }

    // Generate ECDSA P-256 keypair for Root CA
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, CA_ORG);
    dn.push(DnType::OrganizationalUnitName, CA_OU);
    ca_params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    // Backdate 1 day for clock drift tolerance
    ca_params.not_before = now - Duration::days(1);
    ca_params.not_after = now + Duration::days(CA_VALIDITY_DAYS);

    let cert = ca_params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let mut key_pem = key_pair.serialize_pem();

    fs::write(&crt_path, cert_pem.as_bytes())?;
    write_private_key_file(&key_path, key_pem.as_bytes())?;
    key_pem.zeroize();

    // Ensure certs directory and index exist
    let _ = fs::create_dir_all(x509_certs_dir());
    let index_file = x509_index_path();
    if !index_file.exists() {
        let _ = fs::write(&index_file, "{\"certs\":[]}");
    }

    get_ca_status()
}

/// Returns the status report of the X.509 Root CA.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: State desynchronization between filesystem artifacts and reported CA status.
/// - CVE / CWE Mapping: CWE-398 (Indicator of Poor Code Quality), CWE-345 (Insufficient Verification of Data Authenticity).
/// - Likelihood & Exploitability: Low (1/10).
/// - Applied Mitigation: Checks both root certificate and key path existence; verifies trust store presence via native platform checks.
/// - Standards Compliance: IETF RFC 5280.
pub fn get_ca_status() -> Result<X509CaStatus, CaError> {
    let crt_path = x509_root_crt_path();
    let key_path = x509_root_key_path();
    let initialized = crt_path.exists() && key_path.exists();

    let issued_count = if let Ok(data) = fs::read_to_string(x509_index_path()) {
        serde_json::from_str::<crate::x509::store::DevCertIndex>(&data)
            .map(|idx| idx.certs.len())
            .unwrap_or(0)
    } else {
        0
    };

    let is_installed_in_os = crate::trust::is_root_ca_installed();

    Ok(X509CaStatus {
        initialized,
        crt_path: crt_path.display().to_string(),
        key_path: key_path.display().to_string(),
        common_name: CA_COMMON_NAME.to_string(),
        organization: CA_ORG.to_string(),
        is_installed_in_os,
        issued_certs_count: issued_count,
    })
}
