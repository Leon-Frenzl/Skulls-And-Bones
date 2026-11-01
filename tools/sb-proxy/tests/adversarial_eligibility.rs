//! Adversarial test battery for domain eligibility gate and SNI parsing in sb-proxy.
//!
//! Standards Compliance:
//! - IETF RFC 6066 §3 (TLS Server Name Indication)
//! - IETF RFC 1035 / RFC 1123 (Domain Name Syntax and Length Limits)
//! - IETF RFC 8446 (TLS 1.3)
//! - IETF RFC 5280 (X.509 PKI Profile)

use sb_code::escape::EscapeSpaceStore;
use sb_proxy::ca::DeveloperCa;
use sb_proxy::proxy::DynamicSniResolver;
use std::sync::{Arc, RwLock};

static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ensure_ca_initialized() {
    let _ = sb_ca::x509::init_root_ca(false);
}

fn create_clean_resolver() -> DynamicSniResolver {
    let store = EscapeSpaceStore { spaces: vec![] };
    let routes = Arc::new(RwLock::new(store));
    DynamicSniResolver::new(None, routes, None)
}

#[test]
fn test_adversarial_trailing_dots() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();
    let resolver = create_clean_resolver();

    // 1. Single dot '.'
    assert!(!resolver.is_eligible_for_on_demand("."));
    assert!(resolver.resolve_for_server_name(".").is_none());
    assert!(!resolver.is_cached("."));

    // 2. Multi-dot ellipsis '...'
    assert!(!resolver.is_eligible_for_on_demand("..."));
    assert!(resolver.resolve_for_server_name("...").is_none());
    assert!(!resolver.is_cached("..."));

    // 3. Double dot '..'
    assert!(!resolver.is_eligible_for_on_demand(".."));
    assert!(resolver.resolve_for_server_name("..").is_none());
    assert!(!resolver.is_cached(".."));

    // 4. Consecutive dots inside domain: 'test..sbm'
    assert!(!resolver.is_eligible_for_on_demand("test..sbm"));
    assert!(resolver.resolve_for_server_name("test..sbm").is_none());

    // 5. Bare TLD with dot prefix: '.sbm' and '.sbm.'
    assert!(!resolver.is_eligible_for_on_demand(".sbm"), "Bare '.sbm' must not be eligible");
    assert!(resolver.resolve_for_server_name(".sbm").is_none(), "Bare '.sbm' must not resolve");
    assert!(!resolver.is_eligible_for_on_demand(".sbm."), "Bare '.sbm.' must not be eligible");
    assert!(resolver.resolve_for_server_name(".sbm.").is_none(), "Bare '.sbm.' must not resolve");

    // 6. Valid mesh domain with trailing dot: 'valid-test-node.sbm.'
    // RFC 1035 allows trailing dot indicating root in FQDN notation.
    let trailing_dot_domain = "valid-test-trailing-dot.sbm.";
    assert!(resolver.is_eligible_for_on_demand(trailing_dot_domain));
    let cert = resolver.resolve_for_server_name(trailing_dot_domain);
    assert!(cert.is_some(), "Valid domain with trailing dot should resolve successfully");
    assert!(resolver.is_cached("valid-test-trailing-dot.sbm"));
}

#[test]
fn test_adversarial_wildcards() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();
    let resolver = create_clean_resolver();

    // 1. Bare wildcard '*'
    assert!(!resolver.is_eligible_for_on_demand("*"));
    assert!(resolver.resolve_for_server_name("*").is_none());

    // 2. Double wildcard '*.*.sbm'
    let double_wildcard = "*.*.sbm";
    assert!(!resolver.is_eligible_for_on_demand(double_wildcard), "*.*.sbm must not be eligible");
    let res = resolver.resolve_for_server_name(double_wildcard);
    assert!(res.is_none(), "*.*.sbm must NOT mint or resolve a certificate");

    // 3. Embedded wildcard 'foo.*.sbm'
    let embedded_wildcard = "foo.*.sbm";
    assert!(!resolver.is_eligible_for_on_demand(embedded_wildcard), "foo.*.sbm must not be eligible");
    let embedded_res = resolver.resolve_for_server_name(embedded_wildcard);
    assert!(embedded_res.is_none(), "foo.*.sbm must NOT mint a certificate");

    // 4. Single wildcard '*.sbm'
    let wildcard_sbm = "*.sbm";
    assert!(!resolver.is_eligible_for_on_demand(wildcard_sbm), "*.sbm must not be eligible");
    let wildcard_res = resolver.resolve_for_server_name(wildcard_sbm);
    assert!(wildcard_res.is_none(), "*.sbm must NOT mint or resolve a certificate");
}


#[test]
fn test_adversarial_extreme_lengths() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();
    let resolver = create_clean_resolver();

    // 1. Empty string
    assert!(!resolver.is_eligible_for_on_demand(""));
    assert!(resolver.resolve_for_server_name("").is_none());

    // 2. Length 254 chars (e.g. 250 'a's + ".sbm" = 254 chars)
    let domain_254 = format!("{}.sbm", "a".repeat(250));
    assert_eq!(domain_254.len(), 254);
    assert!(
        !resolver.is_eligible_for_on_demand(&domain_254),
        "Domain of length 254 must exceed max RFC 1035 length (253) and be rejected"
    );
    assert!(resolver.resolve_for_server_name(&domain_254).is_none());

    // 3. Length 255 chars (e.g. 251 'a's + ".sbm" = 255 chars)
    let domain_255 = format!("{}.sbm", "a".repeat(251));
    assert_eq!(domain_255.len(), 255);
    assert!(!resolver.is_eligible_for_on_demand(&domain_255));
    assert!(resolver.resolve_for_server_name(&domain_255).is_none());

    // 4. Extreme length 10,000 chars (Buffer overflow / DoS attack vector)
    let domain_10000 = format!("{}.sbm", "b".repeat(9996));
    assert_eq!(domain_10000.len(), 10000);
    assert!(!resolver.is_eligible_for_on_demand(&domain_10000));
    assert!(resolver.resolve_for_server_name(&domain_10000).is_none());

    // 5. Boundary check: Length 253 chars (249 'a's + ".sbm" = 253 chars)
    // RFC 1035 max FQDN representation length
    let domain_253 = format!("{}.sbm", "c".repeat(249));
    assert_eq!(domain_253.len(), 253);
    let eligible_253 = resolver.is_eligible_for_on_demand(&domain_253);
    println!("Diagnostic: domain length 253 eligibility: {}", eligible_253);
}

#[test]
fn test_adversarial_path_traversals() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();
    let resolver = create_clean_resolver();

    let traversal_vectors = vec![
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "../../../etc/shadow.sbm",
        "..\\..\\windows\\system32.sbm",
        "../domain.sbm",
        "..\\domain.sbm",
        "/etc/passwd.sbm",
        "\\windows\\system32.sbm",
        "c:/windows/system32.sbm",
        "c:\\windows\\system32.sbm",
        "foo/bar.sbm",
        "foo\\bar.sbm",
        "....//....//etc/passwd",
        "....\\\\....\\\\windows\\system32",
    ];

    for vector in traversal_vectors {
        assert!(
            !resolver.is_eligible_for_on_demand(vector),
            "Path traversal vector '{}' MUST be rejected by eligibility gate",
            vector
        );
        assert!(
            resolver.resolve_for_server_name(vector).is_none(),
            "Path traversal vector '{}' MUST NOT resolve",
            vector
        );
        assert!(!resolver.is_cached(vector));
        assert!(
            DeveloperCa::find_dev_certificate(vector).is_none(),
            "Path traversal vector '{}' MUST NOT have created on-disk cert",
            vector
        );
    }
}

#[test]
fn test_adversarial_ipv6_colons_null_and_non_ascii() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();
    let resolver = create_clean_resolver();

    // 1. IPv6 literals (RFC 6066 §3 forbids IP literals in SNI host_name)
    let ipv6_inputs = vec![
        "[::1]",
        "::1",
        "fe80::1",
        "[2001:db8::1]",
        "[::1].sbm",
        "::1.sbm",
    ];
    for ip in ipv6_inputs {
        assert!(!resolver.is_eligible_for_on_demand(ip), "IPv6 input '{}' must not be eligible", ip);
        assert!(resolver.resolve_for_server_name(ip).is_none(), "IPv6 input '{}' must not resolve", ip);
    }

    // 2. Colons / port attachments
    let colon_inputs = vec![
        "service.sbm:8080",
        "service.sbm:443",
        "foo:bar.sbm",
    ];
    for col in colon_inputs {
        assert!(!resolver.is_eligible_for_on_demand(col), "Colon input '{}' must not be eligible", col);
        assert!(resolver.resolve_for_server_name(col).is_none(), "Colon input '{}' must not resolve", col);
    }

    // 3. Null bytes
    let null_inputs = vec![
        "domain\0evil.sbm",
        "domain.sbm\0",
        "\0.sbm",
        "\0",
    ];
    for nb in null_inputs {
        assert!(!resolver.is_eligible_for_on_demand(nb), "Null byte in '{}' must be rejected", nb);
        assert!(resolver.resolve_for_server_name(nb).is_none());
    }

    // 4. Non-ASCII characters / Unicode / Control characters
    let non_ascii_inputs = vec![
        "日本語.sbm",
        "üñîçødë.sbm",
        "domain\r\n.sbm",
        "domain .sbm",
        "domain\t.sbm",
    ];
    for na in non_ascii_inputs {
        assert!(!resolver.is_eligible_for_on_demand(na), "Non-ASCII / control input '{}' must not be eligible", na);
        assert!(resolver.resolve_for_server_name(na).is_none(), "Non-ASCII / control input '{}' must not resolve", na);
    }
}

#[test]
fn test_adversarial_ineligible_public_domains() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();
    let resolver = create_clean_resolver();

    let ineligible_domains = vec![
        "google.com",
        "evil.org.sbm.evil.com",
        "attacker.org",
        "example.com",
        "sbm",
        "mesh",
        "local",
        "fake.sbm.com",
        "sbm.com",
        "mesh.org",
        "not-sbm",
        "subdomain.google.com",
        "evil-sbm",
        "evil_sbm",
        "cloudflare.com",
        "amazon.aws",
    ];

    for domain in ineligible_domains {
        assert!(
            !resolver.is_eligible_for_on_demand(domain),
            "Public or ineligible domain '{}' MUST NOT be eligible",
            domain
        );
        assert!(
            resolver.resolve_for_server_name(domain).is_none(),
            "Public or ineligible domain '{}' MUST NOT resolve a certificate",
            domain
        );
        assert!(!resolver.is_cached(domain));
        assert!(
            DeveloperCa::find_dev_certificate(domain).is_none(),
            "Public or ineligible domain '{}' MUST NOT create on-disk certificate",
            domain
        );
    }
}

#[test]
fn test_adversarial_sni_resolution_matrix() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();
    let resolver = create_clean_resolver();

    let test_matrix = vec![
        // (input, category, expected_eligible)
        // Category 1: Trailing dots
        ("valid-trailing.sbm.", "Trailing dots", true),
        ("...", "Trailing dots", false),
        (".", "Trailing dots", false),
        (".sbm", "Trailing dots / bare TLD", false),
        (".sbm.", "Trailing dots / bare TLD", false),

        // Category 2: Wildcards
        ("*.sbm", "Wildcards", false),
        ("*.*.sbm", "Wildcards", false),
        ("*", "Wildcards", false),
        ("foo.*.sbm", "Wildcards", false),

        // Category 3: Extreme lengths
        // 254 chars
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sbm", "Extreme length 254", false),

        // Category 4: Path traversals
        ("../../etc/passwd", "Path traversal", false),
        ("..\\..\\windows\\system32", "Path traversal", false),
        ("../../../etc/shadow.sbm", "Path traversal", false),

        // Category 5: IPv6 literals, colons, null bytes, non-ASCII
        ("[::1]", "IPv6 literal", false),
        ("::1", "IPv6 literal", false),
        ("domain.sbm:8080", "Colon / Port", false),
        ("foo:bar.sbm", "Colon / Port", false),
        ("::1.sbm", "Colon / IPv6", false),
        ("domain\0evil.sbm", "Null byte", false),
        ("日本語.sbm", "Non-ASCII", false),
        ("domain\r\n.sbm", "Control chars", false),

        // Category 6: Ineligible public domains
        ("google.com", "Public domain", false),
        ("evil.org.sbm.evil.com", "Public domain", false),
    ];

    println!("\n=== ADVERSARIAL MATRIX EXECUTION ===");
    let mut findings = Vec::new();

    for (input, category, expected_eligible) in test_matrix {
        let is_eligible = resolver.is_eligible_for_on_demand(input);
        let resolved = resolver.resolve_for_server_name(input);
        let was_resolved = resolved.is_some();
        let was_minted = DeveloperCa::find_dev_certificate(input.trim_end_matches('.')).is_some();

        println!(
            "[{}] input='{}' => eligible={}, resolved={}, minted={}, expected_eligible={}",
            category, input, is_eligible, was_resolved, was_minted, expected_eligible
        );

        if is_eligible != expected_eligible {
            findings.push((input, category, is_eligible, was_resolved, was_minted, expected_eligible));
        }
    }

    println!("=== TOTAL MISMATCH FINDINGS: {} ===", findings.len());
    for (input, cat, actual_elig, res, minted, exp) in &findings {
        println!("FAIL: [{}] '{}' actual_eligible={} (resolved={}, minted={}) vs expected_eligible={}",
            cat, input, actual_elig, res, minted, exp);
    }
    assert_eq!(
        findings.len(),
        0,
        "Expected 0 adversarial matrix mismatches, found {}",
        findings.len()
    );
}

