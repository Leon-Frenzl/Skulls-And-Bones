//! Integration tests for sb-proxy On-Demand TLS Integration with sb-ca.
//!
//! Standards Compliance:
//! - Conforms to IETF RFC 5280 (Internet X.509 PKI Profile)
//! - Conforms to IETF RFC 8446 (TLS 1.3)
//! - Conforms to IETF RFC 6066 §3 (TLS Server Name Indication)

use sb_code::escape::{EscapeSpace, EscapeSpaceStore, EscapeStatus};
use sb_proxy::ca::DeveloperCa;
use sb_proxy::proxy::DynamicSniResolver;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Helper to ensure Root CA is initialized.
fn ensure_ca_initialized() {
    let _ = sb_ca::x509::init_root_ca(false);
}

/// Generates an isolated domain name guaranteed unique per test run.
fn unique_domain(prefix: &str, suffix: &str) -> String {
    format!("{}-{}.{}", prefix, uuid::Uuid::new_v4().simple(), suffix)
}

#[tokio::test]
async fn test_on_demand_tls_resolution_and_in_memory_caching() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let store = EscapeSpaceStore { spaces: vec![] };
    let routes = Arc::new(RwLock::new(store));
    let resolver = DynamicSniResolver::new(None, routes, None);

    let test_domain = unique_domain("on-demand-test", "sbm");

    // Pre-condition: cache must be empty
    assert_eq!(resolver.cached_certs_count(), 0);
    assert!(!resolver.is_cached(&test_domain));

    // Request 1: Dynamic on-demand issuance
    let cert1 = resolver.resolve_for_server_name(&test_domain);
    assert!(cert1.is_some(), "Dynamic on-demand resolution for .sbm must succeed");
    assert!(
        resolver.is_cached(&test_domain),
        "Domain must be cached in in-memory RAM cache"
    );
    assert_eq!(resolver.cached_certs_count(), 1);

    // Verify on-disk persistence by DeveloperCa
    let on_disk = DeveloperCa::find_dev_certificate(&test_domain);
    assert!(on_disk.is_some(), "Certificate must be persisted to disk");
    let (crt_path, key_path) = on_disk.unwrap();
    assert!(crt_path.exists());
    assert!(key_path.exists());

    // Request 2: Sub-microsecond In-Memory Cache hit
    let cert2 = resolver.resolve_for_server_name(&test_domain);
    assert!(cert2.is_some(), "Second resolution must succeed from cache");
    assert!(
        Arc::ptr_eq(&cert1.unwrap(), &cert2.unwrap()),
        "Subsequent requests must return the exact same Arc pointer from RAM cache"
    );
}

#[test]
fn test_ineligible_domains_do_not_trigger_on_demand_generation() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let store = EscapeSpaceStore { spaces: vec![] };
    let routes = Arc::new(RwLock::new(store));
    let resolver = DynamicSniResolver::new(None, routes, None);

    // Ineligible external/public domains
    let ineligible = unique_domain("arbitrary-attacker", "com");
    assert!(
        resolver.resolve_for_server_name(&ineligible).is_none(),
        "Ineligible domain must not trigger on-demand generation"
    );
    assert!(!resolver.is_cached(&ineligible));
    assert!(DeveloperCa::find_dev_certificate(&ineligible).is_none());

    // Adversarial inputs: path traversals and control characters
    assert!(resolver.resolve_for_server_name("../../etc/shadow").is_none());
    assert!(resolver.resolve_for_server_name("attack\0domain.sbm").is_none());
    assert!(resolver.resolve_for_server_name("..\\windows\\system32").is_none());
}

#[tokio::test]
async fn test_active_route_dynamic_tls_issuance() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let route_domain = unique_domain("cluster-service", "local");
    let alias_domain = unique_domain("cluster-alias", "local");
    let store = EscapeSpaceStore {
        spaces: vec![EscapeSpace {
            id: "route-cluster-01".to_string(),
            domain: route_domain.clone(),
            node_callsign: "node-cluster".to_string(),
            target_port: 8080,
            public_port: 443,
            tls_enabled: true,
            status: EscapeStatus::Active,
            mesh_isolated: false,
            rate_limit_rpm: 120,
            created_at: "2026-10-27T00:00:00Z".to_string(),
            aliases: vec![alias_domain.clone()],
            maintenance_msg: None,
            expires_at: None,
            custom_cert_path: None,
            custom_key_path: None,
            cert_expires_at: None,
            is_tunnel: false,
            tunnel_peer: None,
            static_root: None,
        }],
    };
    let routes = Arc::new(RwLock::new(store));
    let resolver = DynamicSniResolver::new(None, routes, None);

    // Primary domain resolution
    let cert = resolver.resolve_for_server_name(&route_domain);
    assert!(cert.is_some(), "Active route must be eligible for TLS issuance");
    assert!(resolver.is_cached(&route_domain));

    // Alias domain resolution
    let alias_cert = resolver.resolve_for_server_name(&alias_domain);
    assert!(alias_cert.is_some(), "Alias of active route must be eligible for TLS issuance");
    assert!(resolver.is_cached(&alias_domain));
}

#[tokio::test]
async fn test_e2e_tls13_handshake_with_on_demand_sni_resolution() {
    let _guard = TEST_MUTEX.lock().unwrap();
    ensure_ca_initialized();

    let target_sni = unique_domain("live-handshake", "mesh");

    // 1. Build server TLS config with DynamicSniResolver
    let store = EscapeSpaceStore { spaces: vec![] };
    let routes = Arc::new(RwLock::new(store));
    let dynamic_resolver = Arc::new(DynamicSniResolver::new(None, routes, None));

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(dynamic_resolver.clone());
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Bind random loopback port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // 2. Server task accepting one TLS connection
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING");

        tls_stream.write_all(b"PONG").await.unwrap();
        tls_stream.flush().await.unwrap();
    });

    // 3. Client task connecting with dynamic SNI
    let client_sni = target_sni.clone();
    let client_handle = tokio::spawn(async move {
        let root_crt_path = sb_ca::paths::x509_root_crt_path();
        let root_crt_pem = std::fs::read(&root_crt_path).unwrap();

        let mut root_store = RootCertStore::empty();
        let certs = rustls_pemfile::certs(&mut &root_crt_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for cert in certs {
            root_store.add(cert).unwrap();
        }

        let mut client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(server_addr).await.unwrap();

        let server_name = ServerName::try_from(client_sni.as_str()).unwrap().to_owned();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        tls_stream.write_all(b"PING").await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG");
    });

    // 4. Await both sides
    tokio::try_join!(server_handle, client_handle).unwrap();

    // 5. Verify the certificate was dynamically minted, cached in RAM, and verified by Root CA
    assert!(
        dynamic_resolver.is_cached(&target_sni),
        "SNI target must be cached in resolver memory after successful TLS handshake"
    );
}
