//! Comprehensive Adversarial Challenge & Stress-Test Suite for OpenSSH CA (`sb_ca::ssh`).
//!
//! Standards & Verification:
//! - RFC 4251 (SSH Protocol Architecture wire format)
//! - RFC 8709 (Ed25519 wire format)
//! - OpenSSH PROTOCOL.certkeys
//! - CWE-20 (Improper Input Validation)
//! - CWE-287 (Improper Authentication)
//! - CWE-613 (Insufficient Session Expiration)
//! - CWE-345 (Insufficient Verification of Data Authenticity)

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sb_ca::error::CaError;
use sb_ca::ssh::cert::CLOCK_DRIFT_MARGIN_SECONDS;
use sb_ca::ssh::{
    ca_public_key_openssh, init_ssh_ca, issue_host_certificate, issue_user_certificate,
    parse_public_key, DEFAULT_HOST_CERT_TTL_SECONDS, DEFAULT_USER_CERT_TTL_SECONDS,
    MAX_USER_CERT_TTL_SECONDS, SSH_CA_COMMENT,
};
use ssh_key::{Algorithm, Certificate, PrivateKey};
use std::collections::HashSet;
use std::fs;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn setup_probe_env(name: &str) -> (MutexGuard<'static, ()>, std::path::PathBuf) {
    let guard = TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = std::env::temp_dir().join(format!("sb_ca_adv_ssh_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);
    std::env::set_var("SB_HOME", &tmp);
    (guard, tmp)
}

fn generate_subject_key() -> (PrivateKey, String) {
    let mut rng = rand::rngs::OsRng;
    let priv_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    let pub_str = priv_key.public_key().to_openssh().unwrap();
    (priv_key, pub_str)
}

/// 1. EMPIRICAL PROBE: OpenSSH Public Key Wire Format Encoding & Decoding
#[test]
fn test_wire_format_strict_rfc4251_and_decoding() {
    let (_guard, _tmp) = setup_probe_env("wire_rfc4251");
    let ca_pub = init_ssh_ca(true).expect("CA init must succeed");
    let ca_pub_retrieved = ca_public_key_openssh().expect("CA public key query must succeed");
    assert_eq!(ca_pub, ca_pub_retrieved);

    // 1.1 Line structure check: <type> <wire-base64> <comment>
    let parts: Vec<&str> = ca_pub.split_whitespace().collect();
    assert_eq!(
        parts.len(),
        3,
        "Wire format line must contain exactly 3 whitespace-separated tokens"
    );
    assert_eq!(parts[0], "ssh-ed25519");
    assert_eq!(parts[2], SSH_CA_COMMENT);

    // 1.2 Base64 prefix check: must start with RFC 4251 Ed25519 prefix
    let b64_wire = parts[1];
    assert!(
        b64_wire.starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI"),
        "Base64 wire representation must start with 'AAAAC3NzaC1lZDI1NTE5AAAAI', got: {}",
        b64_wire
    );

    // 1.3 Exact length check: exactly 68 characters (51 bytes binary)
    assert_eq!(
        b64_wire.len(),
        68,
        "Base64 wire representation must be exactly 68 characters without padding"
    );

    // 1.4 Binary decoding & internal wire inspection
    let wire_bytes = BASE64
        .decode(b64_wire)
        .expect("Base64 decoding must succeed");
    assert_eq!(
        wire_bytes.len(),
        51,
        "Raw wire payload must be exactly 51 bytes"
    );

    let algo_len = u32::from_be_bytes(wire_bytes[0..4].try_into().unwrap()) as usize;
    assert_eq!(algo_len, 11, "Algorithm string length must be 11");
    assert_eq!(&wire_bytes[4..15], b"ssh-ed25519");

    let key_len = u32::from_be_bytes(wire_bytes[15..19].try_into().unwrap()) as usize;
    assert_eq!(key_len, 32, "Ed25519 public key length must be 32");
    assert_eq!(wire_bytes[19..51].len(), 32);

    // 1.5 Adversarial input decoding via parse_public_key
    assert!(
        parse_public_key("").is_err(),
        "Empty string must be rejected"
    );
    assert!(
        parse_public_key("   \t\n  ").is_err(),
        "Whitespace string must be rejected"
    );
    assert!(
        parse_public_key("ssh-ed25519").is_err(),
        "Missing key body must be rejected"
    );
    assert!(
        parse_public_key("ssh-ed25519 AAAAC3").is_err(),
        "Truncated base64 must be rejected"
    );
    assert!(
        parse_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI!!!!").is_err(),
        "Invalid base64 chars must be rejected"
    );
    assert!(
        parse_public_key(&format!(
            "ssh-ed25519 {} extra_comment extra_token",
            b64_wire
        ))
        .is_ok(),
        "OpenSSH parser allows standard comments and extra trailing annotations"
    );

    // Oversized public key input (1MB buffer) — must not panic or hang
    let huge_input = "ssh-ed25519 ".to_string() + &"A".repeat(1_000_000);
    assert!(
        parse_public_key(&huge_input).is_err(),
        "1MB malformed key must be cleanly rejected"
    );

    // File paths must NOT be probed or read by the library parser (security hardening)
    let temp_key_file = _tmp.join("test_key.pub");
    fs::write(&temp_key_file, &ca_pub).unwrap();
    assert!(
        parse_public_key(temp_key_file.to_str().unwrap()).is_err(),
        "Library parse_public_key must reject file paths without probing disk"
    );

    // Reading from disk is caller/CLI responsibility
    let key_content = fs::read_to_string(&temp_key_file).unwrap();
    let parsed_from_file =
        parse_public_key(&key_content).expect("Parsing raw string from file content must succeed");
    assert_eq!(parsed_from_file.to_openssh().unwrap(), ca_pub);

    // Non-existent file path falls through to parse_openssh and fails cleanly
    assert!(parse_public_key("C:\\non_existent_key_file.pub").is_err());

    // 1.6 Interoperability Probe: fleet.rs wire encoding vs ssh-key wire encoding
    // fleet.rs encodes 32 bytes as: [0,0,0,11] + "ssh-ed25519" + [0,0,0,32] + pubkey_bytes
    // Let's verify that this exact algorithm produces the identical base64 string as ssh-key library
    for _ in 0..10 {
        let mut rng = rand::rngs::OsRng;
        let priv_k = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let pub_k = priv_k.public_key();
        let pub_line = pub_k.to_openssh().unwrap();
        let tokens: Vec<&str> = pub_line.split_whitespace().collect();
        let ssh_key_b64 = tokens[1];

        // Extract raw 32 bytes from Ed25519 public key
        let ed25519_pub = pub_k.key_data().ed25519().unwrap();
        let raw_32_bytes = ed25519_pub.as_ref();

        // Replicate fleet.rs wire encoding algorithm
        let key_type = b"ssh-ed25519";
        let mut fleet_wire = Vec::with_capacity(4 + key_type.len() + 4 + 32);
        fleet_wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        fleet_wire.extend_from_slice(key_type);
        fleet_wire.extend_from_slice(&(raw_32_bytes.len() as u32).to_be_bytes());
        fleet_wire.extend_from_slice(raw_32_bytes);
        let fleet_b64 = BASE64.encode(&fleet_wire);

        assert_eq!(
            fleet_b64, ssh_key_b64,
            "fleet.rs wire encoding algorithm must produce bit-identical base64 output as ssh-key"
        );
        assert_eq!(fleet_b64.len(), 68);
        assert!(fleet_b64.starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI"));
    }
}

/// 2. EMPIRICAL PROBE: User Certificate Signing with Extreme Principals
#[test]
fn test_user_cert_extreme_principals() {
    let (_guard, _tmp) = setup_probe_env("principals");
    init_ssh_ca(true).expect("CA init must succeed");
    let (_priv, pub_line) = generate_subject_key();

    // 2.1 Empty principal list
    let res_empty_list = issue_user_certificate(&pub_line, "id1", &[], 3600, None);
    assert!(
        matches!(res_empty_list, Err(CaError::InvalidPrincipal(_))),
        "Empty principal list must be rejected"
    );

    // 2.2 Principals with empty or whitespace-only elements
    let res_empty_str = issue_user_certificate(&pub_line, "id1", &["".into()], 3600, None);
    assert!(
        matches!(res_empty_str, Err(CaError::InvalidPrincipal(_))),
        "Empty principal string must be rejected"
    );

    let res_ws = issue_user_certificate(&pub_line, "id1", &["   ".into()], 3600, None);
    assert!(
        matches!(res_ws, Err(CaError::InvalidPrincipal(_))),
        "Whitespace-only principal must be rejected"
    );

    // 2.3 Length boundary checks: 64 characters (max allowed) vs 65 characters
    let p64 = "a".repeat(64);
    let res_p64 = issue_user_certificate(&pub_line, "id1", &[p64.clone()], 3600, None);
    assert!(res_p64.is_ok(), "64-character principal must be accepted");

    let p65 = "a".repeat(65);
    let res_p65 = issue_user_certificate(&pub_line, "id1", &[p65], 3600, None);
    assert!(
        matches!(res_p65, Err(CaError::InvalidPrincipal(_))),
        "65-character principal must be rejected"
    );

    let p_massive = "a".repeat(10_000);
    let res_massive = issue_user_certificate(&pub_line, "id1", &[p_massive], 3600, None);
    assert!(
        matches!(res_massive, Err(CaError::InvalidPrincipal(_))),
        "Massive principal must be rejected"
    );

    // 2.4 Injection attacks & forbidden characters
    let dangerous_principals = vec![
        "alice;rm -rf /",
        "alice && whoami",
        "alice|sh",
        "alice`id`",
        "alice$(whoami)",
        "alice\nroot",
        "alice\rroot",
        "alice\0root",
        "../../root",
        "alice bob",
        "alice@corp",
        "alice:admin",
        "alice#comment",
        "alice' OR '1'='1",
        "аlice", // Cyrillic homograph
        "alice🚀",
    ];

    for dangerous in &dangerous_principals {
        let res = issue_user_certificate(&pub_line, "id1", &[dangerous.to_string()], 3600, None);
        assert!(
            matches!(res, Err(CaError::InvalidPrincipal(_))),
            "Dangerous principal '{}' MUST be rejected",
            dangerous
        );
    }

    // 2.5 Whitespace padding and newline leakage remediation verification
    let res_padded = issue_user_certificate(&pub_line, "id1", &["  alice  ".into()], 3600, None);
    assert!(
        res_padded.is_ok(),
        "Padded principal must be accepted and sanitized"
    );
    let cert = Certificate::from_str(&res_padded.unwrap()).unwrap();
    assert_eq!(
        cert.valid_principals(),
        &["alice".to_string()],
        "Padded principal MUST be trimmed before being signed into certificate"
    );

    // Probe trailing newline: "alice\n"
    let res_newline = issue_user_certificate(&pub_line, "id1", &["alice\n".into()], 3600, None);
    assert!(
        res_newline.is_ok(),
        "Trailing newline must be trimmed and sanitized"
    );
    let cert_nl = Certificate::from_str(&res_newline.unwrap()).unwrap();
    assert_eq!(
        cert_nl.valid_principals(),
        &["alice".to_string()],
        "Trailing newline MUST be trimmed away and not present in emitted certificate"
    );

    // 2.6 Valid characters: alphanumeric, '.', '-', '_'
    let valid_principals = vec![
        "alice-01".to_string(),
        "bob.service".to_string(),
        "charlie_admin".to_string(),
        "NODE-99.SUB-DOMAIN_01".to_string(),
    ];
    let res_valid = issue_user_certificate(&pub_line, "id1", &valid_principals, 3600, None);
    assert!(
        res_valid.is_ok(),
        "Valid principals with '.', '-', '_' must be accepted"
    );

    // 2.7 Mixed batch: 1 invalid among 10 valid must fail the entire operation
    let mut mixed = valid_principals.clone();
    mixed.push("evil;user".to_string());
    assert!(
        issue_user_certificate(&pub_line, "id1", &mixed, 3600, None).is_err(),
        "Batch containing any invalid principal must be rejected"
    );

    // 2.8 Empty key_id
    assert!(
        issue_user_certificate(&pub_line, "", &["alice".into()], 3600, None).is_err(),
        "Empty key_id must be rejected"
    );
    assert!(
        issue_user_certificate(&pub_line, "   ", &["alice".into()], 3600, None).is_err(),
        "Whitespace key_id must be rejected"
    );
}

/// 3. EMPIRICAL PROBE: Validity Period Boundaries & Clock Drift Absorption
#[test]
fn test_validity_boundaries_and_clock_drift() {
    let (_guard, _tmp) = setup_probe_env("validity");
    init_ssh_ca(true).expect("CA init must succeed");
    let (_priv, pub_line) = generate_subject_key();

    let now_before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 3.1 Zero TTL -> Should fallback to DEFAULT_USER_CERT_TTL_SECONDS (3600s)
    let cert_str_default =
        issue_user_certificate(&pub_line, "id_default", &["alice".into()], 0, None)
            .expect("Zero TTL must succeed with default lifetime");
    let cert_default = Certificate::from_str(&cert_str_default).unwrap();
    let expected_before_min = now_before + DEFAULT_USER_CERT_TTL_SECONDS - 5;
    let expected_before_max = now_before + DEFAULT_USER_CERT_TTL_SECONDS + 5;
    assert!(
        cert_default.valid_before() >= expected_before_min
            && cert_default.valid_before() <= expected_before_max,
        "Zero TTL must default to 3600 seconds"
    );

    // 3.2 Clock drift absorption: valid_after backdated by 60s
    assert!(
        cert_default.valid_after() <= now_before - CLOCK_DRIFT_MARGIN_SECONDS + 2,
        "valid_after must be backdated by 60 seconds (CLOCK_DRIFT_MARGIN_SECONDS) for drift absorption"
    );
    assert!(
        cert_default.valid_after() < cert_default.valid_before(),
        "valid_after must be strictly less than valid_before"
    );

    // 3.3 Minimal TTL: 1 second
    let cert_str_min = issue_user_certificate(&pub_line, "id_min", &["alice".into()], 1, None)
        .expect("1 second TTL must succeed");
    let cert_min = Certificate::from_str(&cert_str_min).unwrap();
    assert!(cert_min.valid_before() > cert_min.valid_after());

    // 3.4 Maximum TTL boundary: 28,800s (8h)
    let cert_str_max = issue_user_certificate(
        &pub_line,
        "id_max",
        &["alice".into()],
        MAX_USER_CERT_TTL_SECONDS,
        None,
    )
    .expect("Exact MAX_USER_CERT_TTL_SECONDS must succeed");
    let cert_max = Certificate::from_str(&cert_str_max).unwrap();
    assert!(cert_max.valid_before() >= now_before + MAX_USER_CERT_TTL_SECONDS - 5);

    // 3.5 Maximum TTL exceeded: 28,801s (8h + 1s)
    let res_exceeded = issue_user_certificate(
        &pub_line,
        "id_exceeded",
        &["alice".into()],
        MAX_USER_CERT_TTL_SECONDS + 1,
        None,
    );
    assert!(
        matches!(res_exceeded, Err(CaError::TtlExceeded { requested, max }) if requested == MAX_USER_CERT_TTL_SECONDS + 1 && max == MAX_USER_CERT_TTL_SECONDS),
        "TTL exceeding MAX must be strictly rejected with CaError::TtlExceeded"
    );

    // 3.6 Far-future user cert: u64::MAX
    let res_u64_max =
        issue_user_certificate(&pub_line, "id_inf", &["alice".into()], u64::MAX, None);
    assert!(
        matches!(res_u64_max, Err(CaError::TtlExceeded { .. })),
        "u64::MAX TTL must be rejected by user cert cap"
    );

    // 3.7 Host certificate TTL boundaries
    let host_default_str = issue_host_certificate(&pub_line, "host1.sbm", 0, None)
        .expect("Host certificate default TTL must succeed");
    let host_default = Certificate::from_str(&host_default_str).unwrap();
    assert!(host_default.valid_before() >= now_before + DEFAULT_HOST_CERT_TTL_SECONDS - 5);

    // 3.8 Host certificate with u64::MAX (far-future) — must be rejected by MAX_HOST_CERT_TTL_SECONDS
    let res_host_max = issue_host_certificate(&pub_line, "host1.sbm", u64::MAX, None);
    assert!(
        matches!(res_host_max, Err(CaError::TtlExceeded { requested, max }) if requested == u64::MAX && max == sb_ca::ssh::MAX_HOST_CERT_TTL_SECONDS),
        "Host cert TTL exceeding MAX_HOST_CERT_TTL_SECONDS must be rejected"
    );
}

/// 4. EMPIRICAL PROBE: Serial Number Uniqueness and Monotonicity Behavior
#[test]
fn test_serial_number_behavior_and_monotonicity() {
    let (_guard, _tmp) = setup_probe_env("serials");
    init_ssh_ca(true).expect("CA init must succeed");
    let (_priv, pub_line) = generate_subject_key();

    // 4.1 Explicit serial numbers: 0, 1, 0x7FFFFFFFFFFFFFFF, u64::MAX
    let test_serials = vec![0u64, 1u64, 42u64, i64::MAX as u64, u64::MAX];
    for s in test_serials {
        let cert_str =
            issue_user_certificate(&pub_line, "id_serial", &["alice".into()], 3600, Some(s))
                .expect(&format!("Explicit serial {} must succeed", s));
        let cert = Certificate::from_str(&cert_str).unwrap();
        assert_eq!(
            cert.serial(),
            s,
            "Certificate must embed exact explicit serial {}",
            s
        );
    }

    // 4.2 Auto-generated serials (`serial: None`): Test Uniqueness and Monotonicity
    let sample_count = 200;
    let mut serials = Vec::with_capacity(sample_count);
    let mut set = HashSet::with_capacity(sample_count);

    for i in 0..sample_count {
        let cert_str = issue_user_certificate(
            &pub_line,
            &format!("id_{}", i),
            &["alice".into()],
            3600,
            None,
        )
        .expect("Auto-generated serial issuance must succeed");
        let cert = Certificate::from_str(&cert_str).unwrap();
        let s = cert.serial();
        serials.push(s);
        set.insert(s);
    }

    // Uniqueness assertion: No collisions in 200 random samples
    assert_eq!(
        set.len(),
        sample_count,
        "Serial numbers must be 100% unique across {} issuances (found collision!)",
        sample_count
    );

    // Monotonicity analysis:
    // Check if auto-generated serials are monotonic or CSPRNG random
    let mut strictly_increasing = true;
    for window in serials.windows(2) {
        if window[0] >= window[1] {
            strictly_increasing = false;
            break;
        }
    }

    eprintln!(
        "[OBSERVATION] Auto-generated serial sequence: strictly_increasing = {}",
        strictly_increasing
    );
    eprintln!("[OBSERVATION] First 5 auto serials: {:?}", &serials[0..5]);
}

/// 5. EMPIRICAL PROBE: High Concurrency & Multi-Threaded Stress Test
#[test]
fn test_concurrent_issuance_stress() {
    let (_guard, _tmp) = setup_probe_env("concurrency");
    init_ssh_ca(true).expect("CA init must succeed");

    let thread_count = 8;
    let certs_per_thread = 25;
    let total_certs = thread_count * certs_per_thread;

    let issued_certs = Arc::new(Mutex::new(Vec::with_capacity(total_certs)));
    let mut handles = Vec::new();

    for t in 0..thread_count {
        let issued_clone = Arc::clone(&issued_certs);
        let handle = thread::spawn(move || {
            let mut local_certs = Vec::with_capacity(certs_per_thread);
            for c in 0..certs_per_thread {
                let mut rng = rand::rngs::OsRng;
                let priv_k = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
                let pub_s = priv_k.public_key().to_openssh().unwrap();

                let cert_str = issue_user_certificate(
                    &pub_s,
                    &format!("t{}_c{}", t, c),
                    &[format!("user_{}_{}", t, c)],
                    1800,
                    None,
                )
                .expect("Concurrent certificate issuance must not panic or error");

                local_certs.push(cert_str);
            }
            let mut guard = issued_clone.lock().unwrap();
            guard.extend(local_certs);
        });
        handles.push(handle);
    }

    for h in handles {
        h.join()
            .expect("All worker threads must complete without panic");
    }

    let all_certs = issued_certs.lock().unwrap();
    assert_eq!(all_certs.len(), total_certs);

    // Cryptographically verify every single certificate signature against the Root CA key
    for (i, c_str) in all_certs.iter().enumerate() {
        let cert = Certificate::from_str(c_str).expect("Emitted certificate must be parseable");
        assert!(
            cert.verify_signature().is_ok(),
            "Certificate #{} must pass cryptographic signature verification",
            i
        );
    }
}
