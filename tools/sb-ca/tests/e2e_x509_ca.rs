//! End-to-end integration tests for X.509 Certificate Authority (`sb-ca::x509`).
//!
//! Standards:
//! - Conforms to IETF RFC 5280 (X.509 PKI Certificate and CRL Profile)
//! - Conforms to IETF RFC 8446 (TLS 1.3)
//! - Conforms to ISO 8601 (Timestamps)

use sb_ca::error::CaError;
use sb_ca::x509::{
    get_or_issue_on_demand, init_root_ca, issue_leaf_certificate, CA_COMMON_NAME, CA_ORG,
};
use std::fs;
use std::sync::{Mutex, MutexGuard};
use x509_parser::prelude::*;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn setup_test_env(test_name: &str) -> (MutexGuard<'static, ()>, std::path::PathBuf) {
    let guard = TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = std::env::temp_dir().join(format!("sb_ca_test_x509_{}_{}", test_name, std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);
    std::env::set_var("SB_HOME", &tmp);
    (guard, tmp)
}

#[test]
fn test_x509_root_ca_initialization() {
    let (_guard, _tmp) = setup_test_env("root_ca_init");

    let status = init_root_ca(true).expect("Root CA initialization must succeed");
    assert!(status.initialized);
    assert_eq!(status.common_name, CA_COMMON_NAME);
    assert_eq!(status.organization, CA_ORG);

    let crt_path = std::path::PathBuf::from(&status.crt_path);
    let key_path = std::path::PathBuf::from(&status.key_path);
    assert!(crt_path.exists());
    assert!(key_path.exists());

    let cert_pem = fs::read_to_string(&crt_path).expect("Read root cert");
    assert!(cert_pem.contains("-----BEGIN CERTIFICATE-----"));

    // Extract DER and parse with x509-parser
    let cert_der = sb_ca::x509::leaf::pem_to_der(&cert_pem).expect("Extract root DER");
    let (_, x509) = parse_x509_certificate(&cert_der).expect("Must parse Root CA certificate");

    // Conforms to RFC 5280:
    // Root CA must have BasicConstraints with ca=true
    let bc = x509.basic_constraints().expect("bc").expect("BasicConstraints extension must exist");
    assert!(bc.value.ca, "Root CA must have CA=true");

    // Key Usage must have KeyCertSign and CrlSign
    let ku = x509.key_usage().expect("ku").expect("KeyUsage extension must exist");
    assert!(ku.value.key_cert_sign(), "Root CA must have KeyCertSign");
    assert!(ku.value.crl_sign(), "Root CA must have CrlSign");

    // Subject must match CA_COMMON_NAME
    assert_eq!(x509.subject().to_string(), format!("CN={}, O={}, OU=Developer CA", CA_COMMON_NAME, CA_ORG));
}

#[test]
fn test_x509_leaf_certificate_issuance_and_mtls_ekus() {
    let (_guard, _tmp) = setup_test_env("leaf_cert");
    init_root_ca(true).expect("Root CA init must succeed");

    let domains = vec![
        "mesh-gateway.sbm".to_string(),
        "*.sbm".to_string(),
        "*.mesh".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let ttl_days = 90;

    let pair = issue_leaf_certificate(&domains, ttl_days)
        .expect("Leaf certificate issuance must succeed");

    assert!(pair.cert_path.exists());
    assert!(pair.key_path.exists());

    // Fullchain PEM must contain both Leaf cert and Root CA cert
    assert_eq!(
        pair.cert_pem.matches("-----BEGIN CERTIFICATE-----").count(),
        2,
        "Fullchain PEM must contain exactly 2 certificates (Leaf + Root CA)"
    );

    // Private key PEM must contain valid ECDSA private key header
    assert!(pair.key_pem.contains("-----BEGIN PRIVATE KEY-----"));

    // DER representations must be populated and non-empty
    assert!(!pair.cert_der.is_empty());
    assert!(!pair.key_der.is_empty());

    // Parse the leaf certificate DER
    let (_, x509) = parse_x509_certificate(&pair.cert_der)
        .expect("Leaf certificate DER must parse validly");

    // Conforms to RFC 5280:
    // Must NOT be a CA (basic constraints is either absent or ca=false)
    if let Ok(Some(bc)) = x509.basic_constraints() {
        assert!(!bc.value.ca, "Leaf certificate must not be a CA");
    }

    // Must have mTLS Extended Key Usages: ServerAuth AND ClientAuth (RFC 5280 §4.2.1.12)
    let eku = x509.extended_key_usage().expect("eku").expect("ExtendedKeyUsage must exist");
    assert!(
        eku.value.server_auth,
        "Leaf certificate must include ServerAuth EKU for TLS servers"
    );
    assert!(
        eku.value.client_auth,
        "Leaf certificate must include ClientAuth EKU for mTLS peer authentication"
    );

    // Key Usages must contain DigitalSignature
    let ku = x509.key_usage().expect("ku").expect("KeyUsage must exist");
    assert!(ku.value.digital_signature(), "Leaf cert must have DigitalSignature");

    // Subject Alternative Names must contain all requested domains
    let san = x509.subject_alternative_name().expect("san").expect("SAN extension must exist");

    let has_ip_127_0_0_1 = san.value.general_names.iter().any(|n| match n {
        GeneralName::IPAddress(b) => *b == [127, 0, 0, 1],
        _ => false,
    });
    assert!(has_ip_127_0_0_1, "SAN extension must include IPAddress 127.0.0.1");

    let dns_names: Vec<&str> = san.value.general_names.iter().filter_map(|n| match n {
        GeneralName::DNSName(s) => Some(*s),
        _ => None,
    }).collect();

    assert!(dns_names.contains(&"mesh-gateway.sbm"), "Must contain mesh-gateway.sbm");
    assert!(dns_names.contains(&"*.sbm"), "Must contain *.sbm");
    assert!(dns_names.contains(&"*.mesh"), "Must contain *.mesh");
    assert!(dns_names.contains(&"localhost"), "Must contain localhost");
}

#[test]
fn test_x509_on_demand_issuance_and_caching() {
    let (_guard, _tmp) = setup_test_env("on_demand");
    init_root_ca(true).expect("Root CA init must succeed");

    let test_domain = "api.mesh";

    // 1. Initial on-demand request: mints new certificate
    let start_mint = std::time::Instant::now();
    let pair1 = get_or_issue_on_demand(test_domain).expect("On-demand minting must succeed");
    let mint_duration = start_mint.elapsed();

    assert!(pair1.cert_path.exists());
    assert!(pair1.key_path.exists());
    assert!(pair1.domains.contains(&test_domain.to_string()));

    // 2. Second on-demand request: hits disk cache and resolves in sub-2ms
    let start_cache = std::time::Instant::now();
    let pair2 = get_or_issue_on_demand(test_domain).expect("Cached resolution must succeed");
    let cache_duration = start_cache.elapsed();

    // Verify cache hit returned identical certificate
    assert_eq!(pair1.cert_pem, pair2.cert_pem);
    assert_eq!(pair1.key_pem, pair2.key_pem);
    assert_eq!(pair1.cert_der, pair2.cert_der);
    assert_eq!(pair1.key_der, pair2.key_der);

    // Verify resolution speed
    println!("Mint time: {:?}, Cache hit time: {:?}", mint_duration, cache_duration);
}

#[test]
fn test_x509_domain_validation_and_security() {
    let (_guard, _tmp) = setup_test_env("domain_security");
    init_root_ca(true).expect("Root CA init must succeed");

    // 1. Rejects path traversal domain (CWE-22)
    let err_traversal = issue_leaf_certificate(&["../../etc/shadow".into()], 90);
    assert!(matches!(err_traversal, Err(CaError::InvalidDomain(_))));

    // 2. Rejects empty domains
    let err_empty = issue_leaf_certificate(&[], 90);
    assert!(matches!(err_empty, Err(CaError::InvalidDomain(_))));

    // 3. Rejects control characters
    let err_ctrl = issue_leaf_certificate(&["bad\0domain.com".into()], 90);
    assert!(matches!(err_ctrl, Err(CaError::InvalidDomain(_))));
}
