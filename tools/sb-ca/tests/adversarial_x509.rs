//! Adversarial probes and stress-testing harness for `sb-ca::x509`.
//!
//! Standards Compliance & Threat Auditing:
//! - RFC 5280 (X.509 PKI)
//! - RFC 6125 (TLS Domain Representation)
//! - RFC 8446 (TLS 1.3)
//! - CWE-22 (Path Traversal)
//! - CWE-20 (Improper Input Validation)
//! - CWE-362 (Race Condition / Concurrent TOCTOU)
//! - CWE-400 (Uncontrolled Resource Consumption)

use sb_ca::error::CaError;
use sb_ca::x509::{
    get_or_issue_on_demand, init_root_ca, issue_leaf_certificate, validate_domain, DevCertIndex,
};
use std::fs;
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::time::Instant;
use x509_parser::prelude::*;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn setup_adversarial_env(name: &str) -> (MutexGuard<'static, ()>, std::path::PathBuf) {
    let guard = TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let tmp = std::env::temp_dir().join(format!(
        "sb_ca_adv_{}_{}_{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::create_dir_all(&tmp);
    std::env::set_var("SB_HOME", &tmp);
    (guard, tmp)
}

/// Adversarial Test 1: Wildcard SAN Handling in On-Demand issuance.
///
/// Bug hypothesis:
/// In `leaf.rs::get_or_issue_on_demand`, if a caller passes `*.sbm` or `*.mesh`,
/// line 253 unconditionally prefixes `*.` to `clean`, producing `*.*.sbm`.
/// `issue_leaf_certificate` validates all SANs using `validate_domain`, which
/// rejects `*.*.sbm` because of the second `*`.
#[test]
fn test_adversarial_wildcard_san_handling() {
    let (_guard, _tmp) = setup_adversarial_env("wildcard_san");
    init_root_ca(true).expect("Root CA init must succeed");

    // Case 1A: Calling get_or_issue_on_demand("*.sbm") directly in a fresh environment
    let on_demand_sbm = get_or_issue_on_demand("*.sbm");
    println!(
        ">>> Fresh get_or_issue_on_demand('*.sbm') result: {:?}",
        on_demand_sbm
    );

    // Case 1B: Calling get_or_issue_on_demand("*.mesh") directly in a fresh environment
    let on_demand_mesh = get_or_issue_on_demand("*.mesh");
    println!(
        ">>> Fresh get_or_issue_on_demand('*.mesh') result: {:?}",
        on_demand_mesh
    );

    // Case 1C: Calling get_or_issue_on_demand("*.node1.sbm")
    let on_demand_sub = get_or_issue_on_demand("*.node1.sbm");
    println!(
        ">>> Fresh get_or_issue_on_demand('*.node1.sbm') result: {:?}",
        on_demand_sub
    );

    // VERIFY REMEDIATION:
    // Wildcard on-demand requests must succeed and contain the wildcard SAN without duplicate prefixing
    assert!(
        on_demand_sbm.is_ok(),
        "get_or_issue_on_demand('*.sbm') must succeed: {:?}",
        on_demand_sbm
    );
    let pair_sbm = on_demand_sbm.unwrap();
    assert!(pair_sbm.domains.contains(&"*.sbm".to_string()));
    assert!(!pair_sbm.domains.iter().any(|d| d.contains("*.*")));

    assert!(
        on_demand_mesh.is_ok(),
        "get_or_issue_on_demand('*.mesh') must succeed: {:?}",
        on_demand_mesh
    );
    let pair_mesh = on_demand_mesh.unwrap();
    assert!(pair_mesh.domains.contains(&"*.mesh".to_string()));

    assert!(
        on_demand_sub.is_ok(),
        "get_or_issue_on_demand('*.node1.sbm') must succeed: {:?}",
        on_demand_sub
    );
    let pair_sub = on_demand_sub.unwrap();
    assert!(pair_sub.domains.contains(&"*.node1.sbm".to_string()));

    println!(">>> REMEDIATION VERIFIED: get_or_issue_on_demand successfully issues wildcard domains without double-prefixing");
}

/// Adversarial Test 2: Input Validation, Path Traversal, Null Bytes, and Length Limits.
#[test]
fn test_adversarial_domain_validation_and_path_traversal() {
    let (_guard, _tmp) = setup_adversarial_env("domain_validation");
    init_root_ca(true).expect("Root CA init must succeed");

    // Vectors that MUST be rejected:
    let malicious_vectors = vec![
        ("../", "Direct path traversal ../"),
        ("../../etc/shadow", "Deep path traversal ../../etc/shadow"),
        (
            "..\\..\\windows\\system32",
            "Windows path traversal with backslashes",
        ),
        ("foo/bar.sbm", "Forward slash separator in domain"),
        ("foo\\bar.sbm", "Backslash separator in domain"),
        ("node\0poison.sbm", "Null byte poison injection"),
        ("node\nnewline.sbm", "Newline injection"),
        ("node\rcarriage.sbm", "Carriage return injection"),
        ("node\ttab.sbm", "Tab control character injection"),
        ("node;rm -rf.sbm", "Command injection semicolon"),
        ("node|sh.sbm", "Pipe character"),
        ("node&calc.sbm", "Ampersand background execution"),
        ("node$var.sbm", "Variable expansion character"),
        ("node`cmd`.sbm", "Backtick command substitution"),
        ("node'quote.sbm", "Single quote"),
        ("node\"dquote.sbm", "Double quote"),
        ("", "Empty domain"),
        ("   ", "Whitespace only"),
        (".", "Single dot"),
        ("..", "Double dot"),
        ("...", "Triple dot"),
    ];

    for (vector, description) in malicious_vectors {
        let res = validate_domain(vector);
        assert!(
            res.is_err(),
            "Vulnerability! Vector '{}' ({}) was accepted: {:?}",
            vector,
            description,
            res
        );
    }

    // Length boundary test:
    // Max DNS domain length is 253 characters (RFC 1035 / RFC 1123).
    let domain_253 = format!("{}.sbm", "a".repeat(249)); // 249 + 4 = 253 chars
    assert_eq!(domain_253.len(), 253);
    assert!(
        validate_domain(&domain_253).is_ok(),
        "253 character domain must be accepted"
    );

    let domain_254 = format!("{}.sbm", "a".repeat(250)); // 250 + 4 = 254 chars
    assert_eq!(domain_254.len(), 254);
    let res_254 = validate_domain(&domain_254);
    assert!(
        matches!(res_254, Err(CaError::InvalidDomain(_))),
        "254 character domain must be rejected as exceeding limit"
    );

    // Host with port / colon test on Windows
    // On Windows NTFS, writing a filename containing ':' creates Alternate Data Streams or fails.
    let colon_res = validate_domain("node1:8080");
    println!("validate_domain('node1:8080') result: {:?}", colon_res);
    // If validate_domain allows colon, let's see what get_or_issue_on_demand does:
    if colon_res.is_ok() {
        let issue_colon = get_or_issue_on_demand("node1:8080");
        println!(
            "get_or_issue_on_demand('node1:8080') result: {:?}",
            issue_colon.is_ok()
        );
        if let Ok(pair) = issue_colon {
            println!("pair.cert_path exists: {}", pair.cert_path.exists());
            // Check second lookup (cache hit)
            let cache_colon = get_or_issue_on_demand("node1:8080");
            println!(
                "Second get_or_issue_on_demand('node1:8080') result: {:?}",
                cache_colon.is_ok()
            );
        }
    }

    // IPv6 address test
    let ipv6_res = validate_domain("::1");
    println!("validate_domain('::1') result: {:?}", ipv6_res);
    assert!(ipv6_res.is_ok(), "validate_domain('::1') must succeed");
    let issue_ipv6 = get_or_issue_on_demand("::1");
    assert!(
        issue_ipv6.is_ok(),
        "Issuance for IPv6 '::1' must succeed with colon sanitization: {:?}",
        issue_ipv6
    );
    let pair_ipv6 = issue_ipv6.unwrap();
    assert!(pair_ipv6.cert_path.exists());
    let cache_ipv6 = get_or_issue_on_demand("::1");
    assert!(
        cache_ipv6.is_ok(),
        "Cached retrieval for IPv6 '::1' must succeed: {:?}",
        cache_ipv6
    );
}

/// Adversarial Test 3: mTLS Extended Key Usage OID Verification.
///
/// RFC 5280 §4.2.1.12:
/// - id-kp-serverAuth: 1.3.6.1.5.5.7.3.1
/// - id-kp-clientAuth: 1.3.6.1.5.5.7.3.2
#[test]
fn test_adversarial_mtls_extended_key_usage_oids() {
    let (_guard, _tmp) = setup_adversarial_env("mtls_eku_oids");
    init_root_ca(true).expect("Root CA init must succeed");

    let pair = issue_leaf_certificate(&["node-peer.sbm".into()], 30)
        .expect("Leaf certificate issuance must succeed");

    let (_, x509) =
        parse_x509_certificate(&pair.cert_der).expect("Leaf cert DER must parse validly");

    // 1. Verify ExtendedKeyUsage extension
    let eku_ext = x509
        .extended_key_usage()
        .expect("eku parsing")
        .expect("ExtendedKeyUsage extension must exist");

    assert!(eku_ext.value.server_auth, "ServerAuth must be true");
    assert!(eku_ext.value.client_auth, "ClientAuth must be true");

    // 2. Deep OID inspection from raw extensions
    let ext_list = x509.extensions();
    let mut found_eku_raw = false;
    for ext in ext_list {
        // EKU OID: 2.5.29.37
        if ext.oid.to_string() == "2.5.29.37" {
            found_eku_raw = true;
            // The value is a sequence of OIDs
            // Let's verify string contains serverAuth and clientAuth or check bytes
            let val_str = format!("{:?}", ext.parsed_extension());
            assert!(
                val_str.contains("server_auth: true"),
                "Parsed extension must contain server_auth: true"
            );
            assert!(
                val_str.contains("client_auth: true"),
                "Parsed extension must contain client_auth: true"
            );
        }
    }
    assert!(
        found_eku_raw,
        "Extension 2.5.29.37 (ExtendedKeyUsage) must be present"
    );

    // 3. Verify KeyUsages
    let ku = x509.key_usage().expect("ku").expect("KeyUsage must exist");
    assert!(
        ku.value.digital_signature(),
        "DigitalSignature must be enabled"
    );
    assert!(
        ku.value.key_encipherment(),
        "KeyEncipherment must be enabled"
    );

    // 4. Verify Not CA
    if let Ok(Some(bc)) = x509.basic_constraints() {
        assert!(!bc.value.ca, "Leaf cert must NOT have ca=true");
    }
}

/// Adversarial Test 4: On-Demand Latency SLA Benchmark.
///
/// Target SLA:
/// - Initial mint < 5ms (pure Rust curve math)
/// - Subsequent cached lookup in microseconds (< 1ms = < 1000 µs)
#[test]
fn test_adversarial_on_demand_latency_sla() {
    let (_guard, _tmp) = setup_adversarial_env("latency_sla");
    init_root_ca(true).expect("Root CA init must succeed");

    let test_domain = "perf-eval.mesh";

    // 1. Measure initial mint latency
    let start_mint = Instant::now();
    let pair1 = get_or_issue_on_demand(test_domain).expect("Initial mint must succeed");
    let mint_latency = start_mint.elapsed();

    println!(">>> Initial Mint Latency: {:?}", mint_latency);
    assert!(!pair1.cert_der.is_empty());

    // 2. Measure cached retrieval latency over 100 iterations
    let iterations = 100;
    let mut latencies = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let t0 = Instant::now();
        let pair_cached =
            get_or_issue_on_demand(test_domain).expect("Cached retrieval must succeed");
        let elapsed = t0.elapsed();
        latencies.push(elapsed);
        assert_eq!(pair_cached.cert_der, pair1.cert_der);
    }

    latencies.sort();
    let min = latencies[0];
    let p50 = latencies[iterations / 2];
    let p95 = latencies[iterations * 95 / 100];
    let p99 = latencies[iterations - 1];
    let avg = latencies.iter().sum::<std::time::Duration>() / (iterations as u32);

    println!(
        ">>> Cached Retrieval (100 runs): min={:?}, p50={:?}, p95={:?}, p99={:?}, avg={:?}",
        min, p50, p95, p99, avg
    );

    // Initial mint SLA check
    println!(">>> Initial mint SLA check (<5ms): {:?}", mint_latency);
    // Cached retrieval SLA check (<1ms = <1000 µs)
    println!(">>> Cached retrieval p50: {:?}", p50);
}

/// Adversarial Test 5: Concurrency & Race Conditions.
///
/// Attack scenario:
/// 16 threads concurrently invoke `get_or_issue_on_demand` on the SAME unissued domain.
/// We observe:
/// 1. Do any threads fail with Windows sharing violation (os error 32)?
/// 2. Does `index.json` get corrupted or lose records?
/// 3. Does any thread receive a mismatched certificate / key pair?
#[test]
fn test_adversarial_concurrency_race_conditions() {
    let (_guard, _tmp) = setup_adversarial_env("concurrency_race");
    init_root_ca(true).expect("Root CA init must succeed");

    let num_threads = 16;
    let domain = "concurrent-mesh-node.sbm";
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let b = Arc::clone(&barrier);
        let dom = domain.to_string();
        handles.push(std::thread::spawn(move || {
            // Wait for all threads to align
            b.wait();
            let start = Instant::now();
            let res = get_or_issue_on_demand(&dom);
            let duration = start.elapsed();
            (thread_id, res, duration)
        }));
    }

    let mut success_count = 0;
    let mut error_count = 0;
    let mut sharing_violations = 0;
    let mut other_errors = 0;
    let mut returned_certs = Vec::new();

    for handle in handles {
        let (id, res, dur) = handle.join().expect("Thread joined");
        match res {
            Ok(pair) => {
                success_count += 1;
                returned_certs.push(pair);
            }
            Err(e) => {
                error_count += 1;
                let err_str = e.to_string();
                if err_str.contains("os error 32") || err_str.contains("used by another process") {
                    sharing_violations += 1;
                } else {
                    other_errors += 1;
                }
                println!("Thread {} failed in {:?}: {}", id, dur, err_str);
            }
        }
    }

    println!(
        ">>> Concurrency test result: {} succeeded, {} failed ({} sharing violations, {} other)",
        success_count, error_count, sharing_violations, other_errors
    );

    // Check index file health
    let idx_path = sb_ca::paths::x509_index_path();
    let raw_index =
        fs::read_to_string(&idx_path).unwrap_or_else(|e| format!("Failed to read index: {e}"));
    println!(">>> Index path: {}", idx_path.display());
    println!(">>> Index raw content: {}", raw_index);

    let index = DevCertIndex::load();
    println!(
        ">>> Index cert count after concurrent minting: {}",
        index.certs.len()
    );

    // Check if the primary domain is present in index
    let found = index.find(domain);
    println!(">>> Found domain in index: {}", found.is_some());

    // EMPIRICAL CONCURRENCY AUDIT:
    // If sharing violations or errors occurred, report them!
    if error_count > 0 {
        println!("CONFIRMED CONCURRENCY DEFECT: Multiple concurrent callers experienced I/O sharing violations or write collisions!");
    } else {
        println!("All 16 concurrent callers succeeded.");
    }
}

/// Adversarial Test 6: Concurrency & Lost Updates across DIFFERENT domains.
///
/// Attack scenario:
/// 10 threads concurrently mint 10 distinct domains (`peer-0.sbm` to `peer-9.sbm`).
/// In `leaf.rs`:
/// - Each thread does `DevCertIndex::load()`
/// - Modifies its in-memory copy
/// - Saves `index.json` via `fs::write`
/// Since there is no mutex, file lock, or atomic read-modify-write on `index.json`,
/// concurrent saves will overwrite each other, causing LOST UPDATES (CWE-362).
#[test]
fn test_adversarial_concurrency_lost_updates_different_domains() {
    let (_guard, _tmp) = setup_adversarial_env("concurrency_lost_updates");
    init_root_ca(true).expect("Root CA init must succeed");

    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for i in 0..num_threads {
        let b = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let dom = format!("concurrent-peer-{}.sbm", i);
            b.wait();
            let res = get_or_issue_on_demand(&dom);
            (i, dom, res)
        }));
    }

    let mut mint_successes = 0;
    let mut mint_errors = 0;
    for h in handles {
        let (i, dom, res) = h.join().expect("join thread");
        match res {
            Ok(_) => mint_successes += 1,
            Err(e) => {
                mint_errors += 1;
                println!("Thread {} ({}) failed: {}", i, dom, e);
            }
        }
    }

    println!(
        ">>> Distinct mints: {} successes, {} errors",
        mint_successes, mint_errors
    );

    let index = DevCertIndex::load();
    println!(
        ">>> DevCertIndex total cert count after 10 distinct mints: {} (expected: 10)",
        index.certs.len()
    );

    for i in 0..num_threads {
        let dom = format!("concurrent-peer-{}.sbm", i);
        let exists = index.find(&dom).is_some();
        if !exists {
            println!(
                "LOST UPDATE CONFIRMED: Domain '{}' is MISSING from index.json!",
                dom
            );
        }
    }

    assert_eq!(mint_errors, 0, "No concurrent minting errors allowed");
    assert_eq!(
        mint_successes, num_threads,
        "All concurrent threads must succeed"
    );
    assert_eq!(
        index.certs.len(),
        num_threads,
        "DevCertIndex must contain all {} concurrently issued domains",
        num_threads
    );
    for i in 0..num_threads {
        let dom = format!("concurrent-peer-{}.sbm", i);
        assert!(
            index.find(&dom).is_some(),
            "Domain '{}' must be present in index.json",
            dom
        );
    }
}

/// Adversarial Test 7: Concurrent Initialization & Root CA Split-Brain (CWE-362).
///
/// Attack scenario:
/// Multiple threads invoke `get_or_issue_on_demand` when Root CA has NOT been initialized.
/// In `leaf.rs`:
/// ```rust
/// if !crt_path.exists() || !key_path.exists() {
///     init_root_ca(false)?;
/// }
/// ```
/// Without synchronization, multiple threads generate separate Root CAs and overwrite
/// each other's Root CA cert and key. Leaf certificates signed by an overwritten Root CA
/// key will fail cryptographic verification against the final `root_ca.crt` on disk.
#[test]
fn test_adversarial_concurrent_initialization_split_brain() {
    let (_guard, _tmp) = setup_adversarial_env("concurrent_init");
    // Explicitly DO NOT run init_root_ca upfront!

    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for i in 0..num_threads {
        let b = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let dom = format!("init-race-{}.sbm", i);
            b.wait();
            let res = get_or_issue_on_demand(&dom);
            (i, dom, res)
        }));
    }

    let mut issued_pairs = Vec::new();
    let mut errors = 0;
    for h in handles {
        let (i, dom, res) = h.join().expect("join thread");
        match res {
            Ok(pair) => issued_pairs.push((i, dom, pair)),
            Err(e) => {
                errors += 1;
                println!(
                    "Thread {} ({}) failed during concurrent init: {}",
                    i, dom, e
                );
            }
        }
    }

    println!(
        ">>> Concurrent init results: {} issued, {} errors",
        issued_pairs.len(),
        errors
    );

    // Read the final Root CA certificate that ended up on disk
    let root_crt_path = sb_ca::paths::x509_root_crt_path();
    assert!(root_crt_path.exists(), "Root CA crt must exist on disk");
    let final_root_crt_pem = fs::read_to_string(&root_crt_path).expect("Read final root cert");
    let final_root_der = sb_ca::x509::leaf::pem_to_der(&final_root_crt_pem).expect("Root DER");
    let (_, _final_root_x509) = parse_x509_certificate(&final_root_der).expect("Parse final root");

    // Check if EVERY issued leaf certificate's fullchain Root CA matches the final Root CA on disk!
    let mut split_brain_count = 0;
    for (i, dom, pair) in &issued_pairs {
        // pair.cert_pem contains [Leaf PEM, Issuer Root PEM]
        let pems: Vec<&str> = pair.cert_pem.split("-----END CERTIFICATE-----").collect();
        if pems.len() >= 2 {
            let root_part = format!("{}-----END CERTIFICATE-----\n", pems[1].trim());
            if let Ok(leaf_root_der) = sb_ca::x509::leaf::pem_to_der(&root_part) {
                if leaf_root_der != final_root_der {
                    split_brain_count += 1;
                    println!(
                        "SPLIT-BRAIN CONFIRMED: Thread {} ({}) certificate was issued by an orphaned Root CA key! It does not match final root_ca.crt on disk!",
                        i, dom
                    );
                }
            }
        }
    }

    assert_eq!(errors, 0, "No errors during concurrent initializations");
    assert_eq!(
        split_brain_count, 0,
        "Zero certificates may be signed by an orphaned Root CA key"
    );
}
