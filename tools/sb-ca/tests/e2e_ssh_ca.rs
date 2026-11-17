//! End-to-end integration tests for OpenSSH Certificate Authority (`sb-ca::ssh`).
//!
//! Standards:
//! - Conforms to OpenSSH PROTOCOL.certkeys
//! - Conforms to IETF RFC 4251 (SSH Protocol Architecture)
//! - Conforms to IETF RFC 8709 (Ed25519 for SSH)

use sb_ca::error::CaError;
use sb_ca::ssh::{
    ca_public_key_openssh, init_ssh_ca, issue_host_certificate, issue_user_certificate,
    parse_public_key, MAX_HOST_CERT_TTL_SECONDS, MAX_USER_CERT_TTL_SECONDS,
};
use ssh_key::certificate::CertType;
use ssh_key::{Algorithm, Certificate, PrivateKey};
use std::fs;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn setup_test_env(test_name: &str) -> (MutexGuard<'static, ()>, std::path::PathBuf) {
    let guard = TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = std::env::temp_dir().join(format!("sb_ca_test_ssh_{}_{}", test_name, std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);
    std::env::set_var("SB_HOME", &tmp);
    (guard, tmp)
}

#[test]
fn test_openssh_ca_init_and_rfc4251_wire_format() {
    let (_guard, _tmp) = setup_test_env("init_wire");

    let ca_pub_line = init_ssh_ca(true).expect("CA initialization must succeed");

    // Conforms to RFC 4251: OpenSSH public key line structure:
    // <key-type> <base64-wire> <comment>
    let parts: Vec<&str> = ca_pub_line.split_whitespace().collect();
    assert_eq!(parts.len(), 3, "CA public key must have 3 whitespace-separated parts");
    assert_eq!(parts[0], "ssh-ed25519");
    assert_eq!(parts[2], "sovereign-swarm-ca@local");

    // RFC 4251 base64 string must start with ssh-ed25519 wire prefix "AAAAC3NzaC1lZDI1NTE5AAAAI"
    assert!(
        parts[1].starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI"),
        "OpenSSH wire format must start with standard Ed25519 wire prefix"
    );
    // 51 wire bytes -> exactly 68 Base64 characters without padding
    assert_eq!(parts[1].len(), 68, "Wire format base64 string must be exactly 68 characters");

    // ca_public_key_openssh() must return identical wire string
    let retrieved_pub = ca_public_key_openssh().expect("Retrieval must succeed");
    assert_eq!(retrieved_pub, ca_pub_line);
}

#[test]
fn test_openssh_user_certificate_issuance_and_verification() {
    let (_guard, _tmp) = setup_test_env("user_cert");
    init_ssh_ca(true).expect("CA init must succeed");

    // Generate ephemeral client subject keypair
    let mut rng = rand::rngs::OsRng;
    let subject_priv = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    let subject_pub_line = subject_priv.public_key().to_openssh().unwrap();

    let key_id = "operator-alice-test";
    let principals = vec!["alice".to_string(), "sbadmin".to_string(), "deploy".to_string()];
    let ttl = 3600;
    let serial = 10042u64;

    let cert_str = issue_user_certificate(
        &subject_pub_line,
        key_id,
        &principals,
        ttl,
        Some(serial),
    )
    .expect("User certificate issuance must succeed");

    // Must start with OpenSSH certificate identifier
    assert!(
        cert_str.starts_with("ssh-ed25519-cert-v01@openssh.com "),
        "Must be standard OpenSSH v01 certificate format"
    );

    // Parse certificate using upstream ssh-key parser
    let cert = Certificate::from_str(&cert_str).expect("Certificate must parse validly");

    assert_eq!(cert.cert_type(), CertType::User);
    assert_eq!(cert.key_id(), key_id);
    assert_eq!(cert.serial(), serial);
    assert_eq!(cert.valid_principals(), &principals);

    // Verify clock drift margin: valid_after was backdated 60s
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(cert.valid_after() <= now);
    assert!(cert.valid_before() > now);

    // Verify standard interactive shell extensions
    assert!(cert.extensions().contains_key("permit-pty"));
    assert!(cert.extensions().contains_key("permit-X11-forwarding"));
    assert!(cert.extensions().contains_key("permit-agent-forwarding"));
    assert!(cert.extensions().contains_key("permit-port-forwarding"));
    assert!(cert.extensions().contains_key("permit-user-rc"));

    // Cryptographic signature verification against the CA
    assert!(
        cert.verify_signature().is_ok(),
        "Certificate signature must cryptographically verify against the CA key"
    );
}

#[test]
fn test_openssh_host_certificate_issuance_and_verification() {
    let (_guard, _tmp) = setup_test_env("host_cert");
    init_ssh_ca(true).expect("CA init must succeed");

    // Generate ephemeral host subject keypair
    let mut rng = rand::rngs::OsRng;
    let host_priv = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    let host_pub_line = host_priv.public_key().to_openssh().unwrap();

    let hostname = "edge-node-01.sbm";
    let ttl = 86400 * 7; // 7 days

    let cert_str = issue_host_certificate(&host_pub_line, hostname, ttl, None)
        .expect("Host certificate issuance must succeed");

    let cert = Certificate::from_str(&cert_str).expect("Host certificate must parse validly");

    assert_eq!(cert.cert_type(), CertType::Host);
    assert_eq!(cert.valid_principals(), &[hostname.to_string()]);
    assert!(cert.verify_signature().is_ok());
}

#[test]
fn test_openssh_certificate_security_enforcement() {
    let (_guard, _tmp) = setup_test_env("security");
    init_ssh_ca(true).expect("CA init must succeed");

    let mut rng = rand::rngs::OsRng;
    let subject_priv = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    let subject_pub_line = subject_priv.public_key().to_openssh().unwrap();

    // 1. Reject TTL exceeding maximum permitted 8 hours (CWE-613)
    let err_ttl = issue_user_certificate(
        &subject_pub_line,
        "test",
        &["user".into()],
        MAX_USER_CERT_TTL_SECONDS + 1,
        None,
    );
    assert!(matches!(err_ttl, Err(CaError::TtlExceeded { .. })));

    // 2. Reject empty principals
    let err_empty = issue_user_certificate(&subject_pub_line, "test", &[], 3600, None);
    assert!(matches!(err_empty, Err(CaError::InvalidPrincipal(_))));

    // 3. Reject invalid characters in principal (CWE-20)
    let err_char = issue_user_certificate(
        &subject_pub_line,
        "test",
        &["admin;rm -rf /".into()],
        3600,
        None,
    );
    assert!(matches!(err_char, Err(CaError::InvalidPrincipal(_))));

    // 4. Reject malformed public key
    let err_pub = issue_user_certificate(
        "ssh-ed25519 NOT_VALID_BASE64",
        "test",
        &["admin".into()],
        3600,
        None,
    );
    assert!(matches!(err_pub, Err(CaError::InvalidPublicKey(_))));

    // 5. Reject host certificate TTL exceeding MAX_HOST_CERT_TTL_SECONDS
    let err_host_ttl = issue_host_certificate(
        &subject_pub_line,
        "node1.sbm",
        MAX_HOST_CERT_TTL_SECONDS + 1,
        None,
    );
    assert!(matches!(err_host_ttl, Err(CaError::TtlExceeded { .. })));

    // 6. Verify whitespace and trailing newline trimming in user cert principals
    let cert_trimmed_str = issue_user_certificate(
        &subject_pub_line,
        "test",
        &["  alice  ".into(), "deploy\n".into()],
        3600,
        None,
    ).expect("Padded principals must be sanitized");
    let cert_trimmed = Certificate::from_str(&cert_trimmed_str).unwrap();
    assert_eq!(cert_trimmed.valid_principals(), &["alice".to_string(), "deploy".to_string()]);

    // 7. Verify library parse_public_key rejects file paths
    let temp_key = _tmp.join("dummy.pub");
    fs::write(&temp_key, &subject_pub_line).unwrap();
    assert!(parse_public_key(temp_key.to_str().unwrap()).is_err());
}
