use crate::acme::AcmeChallengeStore;
use crate::http_server::{serve_connection_with_auth, SecurityHeaders};
use crate::ipc::ProxyTelemetry;
use crate::ratelimit::IpRateLimiter;
use crate::escape::{validate_target_port, EscapeSpaceStore, EscapeStatus};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use std::io::BufReader;
use std::path::Path;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use tokio_rustls::rustls::server::ClientHello;
use tokio_rustls::rustls::sign::CertifiedKey;

/// Loads a rustls CertifiedKey from PEM-encoded fullchain certificate and private key.
pub fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error + Send + Sync>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err("Keine Zertifikate in der PEM-Datei gefunden".into());
    }

    let key_file = std::fs::File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Kein privater Schlüssel in PEM-Datei gefunden",
            )
        })?;

    let signing_key = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("Fehler beim Parsen des privaten Schlüssels: {e}"))?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Loads a rustls CertifiedKey directly from PEM-encoded certificate and private key strings.
///
/// Standards Compliance:
/// - Conforms to IETF RFC 7468 (Textual Encodings of PKIX, PKCS, and CMS Structures)
/// - Conforms to IETF RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3)
pub fn certified_key_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error + Send + Sync>> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err("Keine Zertifikate in der PEM-Zeichenkette gefunden".into());
    }

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Kein privater Schlüssel in PEM-Zeichenkette gefunden",
            )
        })?;

    let signing_key = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("Fehler beim Parsen des privaten Schlüssels: {e}"))?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Dynamic SNI Certificate Resolver supporting hybrid ACME, in-memory caching,
/// custom EscapeSpace routes, and sovereign on-demand X.509 TLS issuance.
///
/// Standards Compliance:
/// - Conforms to IETF RFC 6066 §3 (Server Name Indication)
/// - Conforms to IETF RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3)
/// - Conforms to IETF RFC 5280 (Internet X.509 Public Key Infrastructure Certificate and CRL Profile)
#[derive(Debug)]
pub struct DynamicSniResolver {
    acme_resolver: Option<Arc<rustls_acme::ResolvesServerCertAcme>>,
    routes: Arc<RwLock<EscapeSpaceStore>>,
    fallback_cert: Option<Arc<CertifiedKey>>,
    cert_cache: Arc<std::sync::RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl DynamicSniResolver {
    /// Creates a new DynamicSniResolver with an empty in-memory certificate cache.
    pub fn new(
        acme_resolver: Option<Arc<rustls_acme::ResolvesServerCertAcme>>,
        routes: Arc<RwLock<EscapeSpaceStore>>,
        fallback_cert: Option<Arc<CertifiedKey>>,
    ) -> Self {
        Self {
            acme_resolver,
            routes,
            fallback_cert,
            cert_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Returns the number of cached certificates currently held in RAM memory.
    pub fn cached_certs_count(&self) -> usize {
        self.cert_cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Checks if a certificate for `domain` is cached in RAM memory.
    pub fn is_cached(&self, domain: &str) -> bool {
        let clean = domain.trim_end_matches('.').to_ascii_lowercase();
        self.cert_cache
            .read()
            .map(|c| c.contains_key(&clean))
            .unwrap_or(false)
    }

    /// Exposes a clone of the in-memory certificate cache Arc for inspection.
    pub fn cert_cache(&self) -> Arc<std::sync::RwLock<HashMap<String, Arc<CertifiedKey>>>> {
        self.cert_cache.clone()
    }

    /// Checks whether a domain name is eligible for on-demand TLS certificate minting.
    ///
    /// SECURITY AUDIT:
    /// - Dynamic Threat Vector: CA stampede & resource exhaustion via high-volume arbitrary or malformed SNIs (CWE-400),
    ///   certificate misissuance / wildcard confusion (CWE-295), path traversal injection in SNI (CWE-22),
    ///   and hidden dotfile / ADS filesystem corruption (CWE-20).
    /// - CVE / CWE Mapping: CWE-400 (Uncontrolled Resource Consumption), CWE-295 (Improper Certificate Validation),
    ///   CWE-22 (Path Traversal), CWE-20 (Improper Input Validation).
    /// - Likelihood & Exploitability: High (Score: 8/10) without strict RFC 6066 / RFC 1035 structural pre-filtering.
    ///   * Threat Condition: Untrusted TLS client sends malformed SNI (e.g. `*.sbm`, `.sbm`, `::1.sbm`, `foo:bar.sbm`,
    ///     non-ASCII, or control characters) forcing downstream CA mutex acquisition, ECDSA key generation, and disk I/O.
    /// - Applied Mitigation:
    ///   1. RFC 1035 §2.3.4 length enforcement: Overall FQDN <= 253 octets, non-empty, individual labels 1..=63 octets.
    ///   2. RFC 6066 §3 enforcement: Strict rejection of wildcards ('*'), IP literals / colons (':', '[', ']'),
    ///      whitespace, control characters, and non-ASCII octets.
    ///   3. Label syntax validation: No leading dots or consecutive dots (rejects bare `.sbm`, `.mesh`), each label consists solely of
    ///      ASCII alphanumeric, hyphen, or underscore.
    ///   4. Authoritative scope check: Restricts issuance strictly to sanctioned suffixes (`.sbm`, `.mesh`, `.local`),
    ///      loopback (`localhost`, `127.0.0.1`), or registered active routes in `EscapeSpaceStore`.
    ///
    /// Standards Compliance:
    /// - IETF RFC 6066 §3 (TLS Server Name Indication - syntax & wildcard prohibition)
    /// - IETF RFC 1035 §2.3.1 / §2.3.4 (Domain Name Syntax & Size Limits: max 253 FQDN, max 63 label)
    /// - IETF RFC 1123 §2.1 (Host Names and Numbers - digits in labels)
    /// - IETF RFC 8446 (TLS 1.3)
    /// - IETF RFC 5280 (X.509 PKI Profile)
    pub fn is_eligible_for_on_demand(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        // Tier 1: RFC 1035 §2.3.4: FQDN presentation length max 253 octets; cannot be empty
        if d.is_empty() || d.len() > 253 {
            return false;
        }

        // Tier 2: RFC 6066 §3: Hostname is not a wildcard, literal IP addresses (IPv6 colons/brackets) are not permitted.
        // Rejects directory traversal ('/', '\\', ".."), null bytes ('\0'), and control/whitespace characters.
        if d.contains('/')
            || d.contains('\\')
            || d.contains('\0')
            || d.contains("..")
            || d.contains('*')
            || d.contains(':')
            || d.contains('[')
            || d.contains(']')
            || d.chars()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return false;
        }

        // Tier 3: RFC 1035 / RFC 1123: Must not start with a dot (rejects bare ".sbm" or ".mesh" without host label)
        if d.starts_with('.') {
            return false;
        }

        // Hostname labels must consist solely of valid ASCII alphanumeric, hyphen, underscore, and dots
        if !d
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return false;
        }

        // RFC 1035 §2.3.4: Each label must be between 1 and 63 octets inclusive
        for label in d.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
        }

        // Tier 4: Sanctioned mesh / sovereign local domain suffixes and localhost/loopback
        if d.ends_with(".sbm")
            || d.ends_with(".mesh")
            || d.ends_with(".local")
            || d == "localhost"
            || d == "127.0.0.1"
        {
            return true;
        }

        // Check if registered in EscapeSpaceStore active routes (and does not specify custom PEM files)
        if let Ok(store) = self.routes.read() {
            for space in &store.spaces {
                if space.status == EscapeStatus::Active {
                    let matches_primary = space.domain.eq_ignore_ascii_case(&d);
                    let matches_alias = space
                        .aliases
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(&d));
                    if (matches_primary || matches_alias) && space.custom_cert_path.is_none() {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn check_custom_route_certs(&self, name_clean: &str) -> Option<Arc<CertifiedKey>> {
        if let Ok(store) = self.routes.read() {
            for space in &store.spaces {
                let matches_primary = space.domain.eq_ignore_ascii_case(name_clean);
                let matches_alias = space
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name_clean));
                if matches_primary || matches_alias {
                    if let (Some(ref cert_str), Some(ref key_str)) =
                        (&space.custom_cert_path, &space.custom_key_path)
                    {
                        let cp = Path::new(cert_str);
                        let kp = Path::new(key_str);
                        if cp.exists() && kp.exists() {
                            if let Ok(key) = load_certified_key(cp, kp) {
                                return Some(key);
                            }
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    fn check_disk_certs(&self, name_clean: &str) -> Option<Arc<CertifiedKey>> {
        if let Some((cp, kp)) = crate::ca::DeveloperCa::find_dev_certificate(name_clean) {
            if let Ok(key) = load_certified_key(&cp, &kp) {
                return Some(key);
            }
        }
        None
    }

    /// Resolves certificate for a given server name (domain).
    ///
    /// SECURITY AUDIT:
    /// - Dynamic Threat Vector: CA stampede & resource exhaustion via high-volume arbitrary SNIs (CWE-400),
    ///   improper certificate validation or wildcard confusion (CWE-295), path traversal injection in SNI (CWE-22),
    ///   and unauthenticated disk I/O / lock contention (CWE-400).
    /// - CVE / CWE Mapping: CWE-400 (Uncontrolled Resource Consumption), CWE-295 (Improper Certificate Validation), CWE-22 (Path Traversal).
    /// - Likelihood & Exploitability: High (Score: 8/10) without early pre-filtering under denial-of-service attempts.
    ///   * Threat Condition: Untrusted client initiates rapid TLS handshakes specifying malformed, wildcard, or traversal hostnames
    ///     to force repeated disk checks, mutex contention, and certificate resolution.
    /// - Applied Mitigation:
    ///   1. Early fail-closed SNI pre-filtering rejecting wildcards ('*'), colons (':'), traversal ('/', '\\', ".."), null bytes ('\0'),
    ///      whitespace, control characters, leading dots, and invalid labels before RAM cache, route store, or disk inspection.
    ///   2. Sub-microsecond RAM cache (RwLock<HashMap>) short-circuits repeatedly resolved domains.
    ///   3. Strict eligibility gate strictly restricts on-demand generation to .sbm, .mesh, .local, localhost, and active registered routes.
    ///   4. Rejects path separators ('/', '\\'), null bytes, and domains > 253 chars.
    /// - Standards Compliance:
    ///   - IETF RFC 6066 §3 (TLS Server Name Indication - syntax & wildcard prohibition)
    ///   - IETF RFC 1035 §2.3.1 / §2.3.4 (Domain Name Syntax & Size Limits: max 253 FQDN, max 63 label)
    ///   - IETF RFC 1123 §2.1 (Host Names and Numbers - digits in labels)
    ///   - IETF RFC 8446 (TLS 1.3)
    ///   - IETF RFC 5280 (X.509 PKI Profile)
    pub fn resolve_for_server_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let name_clean = server_name.trim_end_matches('.').to_ascii_lowercase();
        // RFC 6066 §3 / RFC 1035 fail-closed pre-validation:
        // Do not query RAM cache or filesystem for structurally invalid SNIs
        if name_clean.is_empty()
            || name_clean.len() > 253
            || name_clean.contains('*')
            || name_clean.contains(':')
            || name_clean.contains('[')
            || name_clean.contains(']')
            || name_clean.contains('/')
            || name_clean.contains('\\')
            || name_clean.contains('\0')
            || name_clean.contains("..")
            || name_clean.starts_with('.')
            || name_clean
                .chars()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
            || !name_clean
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return self.fallback_cert.clone();
        }

        for label in name_clean.split('.') {
            if label.is_empty() || label.len() > 63 {
                return self.fallback_cert.clone();
            }
        }

        // Fast-Path 1: In-memory RAM cache (sub-microsecond lookup)
        if let Ok(cache) = self.cert_cache.read() {
            if let Some(cert) = cache.get(&name_clean) {
                return Some(cert.clone());
            }
        }

        // Fast-Path 2: Check custom route certs / escape spaces
        if let Some(cert) = self.check_custom_route_certs(&name_clean) {
            if let Ok(mut cache) = self.cert_cache.write() {
                cache.insert(name_clean.clone(), cert.clone());
            }
            return Some(cert);
        }

        // Fast-Path 3: Check on-disk S&B CA certs
        if let Some(cert) = self.check_disk_certs(&name_clean) {
            if let Ok(mut cache) = self.cert_cache.write() {
                cache.insert(name_clean.clone(), cert.clone());
            }
            return Some(cert);
        }

        // Fast-Path 4: On-Demand TLS Issuance with Eligibility Gate
        if self.is_eligible_for_on_demand(&name_clean) {
            match sb_ca::x509::get_or_issue_on_demand(&name_clean) {
                Ok(pair) => {
                    match certified_key_from_pem(&pair.cert_pem, &pair.key_pem)
                        .or_else(|_| load_certified_key(&pair.cert_path, &pair.key_path))
                    {
                        Ok(cert) => {
                            if let Ok(mut cache) = self.cert_cache.write() {
                                cache.insert(name_clean.clone(), cert.clone());
                            }
                            return Some(cert);
                        }
                        Err(err) => {
                            log::error!(
                                "Failed to parse newly issued certificate for {}: {}",
                                name_clean,
                                err
                            );
                        }
                    }
                }
                Err(err) => {
                    log::warn!("On-demand CA issuance failed for {}: {}", name_clean, err);
                }
            }
        }

        // Fallback: Return fallback cert
        self.fallback_cert.clone()
    }
}

impl tokio_rustls::rustls::server::ResolvesServerCert for DynamicSniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Priority 1: Custom domain PEM certificates or Developer CA certificates via SNI
        if let Some(server_name) = client_hello.server_name() {
            if let Some(cert) = self.resolve_for_server_name(server_name) {
                return Some(cert);
            }
        }

        // Priority 2: ACME ALPN challenge and ACME-managed certificates
        if let Some(ref acme) = self.acme_resolver {
            if let Some(cert) = acme.resolve(client_hello) {
                return Some(cert);
            }
        }

        // Priority 3: Fallback certificate
        self.fallback_cert.clone()
    }
}

/// Loads a TLS Acceptor from PEM-encoded fullchain certificate and private key.
pub fn load_tls_acceptor(
    cert_path: &Path,
    key_path: &Path,
) -> Result<tokio_rustls::TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err("Keine Zertifikate in der PEM-Datei gefunden".into());
    }

    let key_file = std::fs::File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Kein privater Schlüssel in PEM-Datei gefunden",
            )
        })?;

    let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

/// Automatically searches and loads the active TLS certificate:
/// 1. Explicit CLI arguments (--cert, --key)
/// 2. EscapeSpaceStore custom cert paths
/// 3. Standard Let's Encrypt live path (/etc/letsencrypt/live/skulls-and-bones.org/)
pub fn find_or_load_tls_acceptor(
    cert_arg: Option<&str>,
    key_arg: Option<&str>,
) -> Option<tokio_rustls::TlsAcceptor> {
    if let (Some(c), Some(k)) = (cert_arg, key_arg) {
        let cp = Path::new(c);
        let kp = Path::new(k);
        if cp.exists() && kp.exists() {
            match load_tls_acceptor(cp, kp) {
                Ok(acc) => {
                    log::info!("global TLS certificate loaded: {}", cp.display());
                    return Some(acc);
                }
                Err(e) => log::error!("failed to load TLS certificate {}: {}", cp.display(), e),
            }
        }
    }

    // Check EscapeSpaceStore
    let store = EscapeSpaceStore::load();
    for space in &store.spaces {
        if let (Some(ref c), Some(ref k)) = (&space.custom_cert_path, &space.custom_key_path) {
            let cp = Path::new(c);
            let kp = Path::new(k);
            if cp.exists() && kp.exists() {
                match load_tls_acceptor(cp, kp) {
                    Ok(acc) => {
                        log::info!(
                            "TLS certificate loaded for {}: {}",
                            space.domain,
                            cp.display()
                        );
                        return Some(acc);
                    }
                    Err(e) => {
                        log::error!("failed to load TLS certificate for {}: {}", space.domain, e)
                    }
                }
            }
        }
    }

    // Check Let's Encrypt standard location
    let le_cert = Path::new("/etc/letsencrypt/live/skulls-and-bones.org/fullchain.pem");
    let le_key = Path::new("/etc/letsencrypt/live/skulls-and-bones.org/privkey.pem");
    if le_cert.exists() && le_key.exists() {
        match load_tls_acceptor(le_cert, le_key) {
            Ok(acc) => {
                log::info!(
                    "Let's Encrypt TLS certificate loaded: {}",
                    le_cert.display()
                );
                return Some(acc);
            }
            Err(e) => log::error!("failed to load Let's Encrypt certificate: {}", e),
        }
    }

    None
}

/// Runs the single-bind S&B Proxy server (defaulting to dual-capable configuration).
pub async fn run_proxy_server(
    bind_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acme_store = AcmeChallengeStore::new();
    let rate_limiter = IpRateLimiter::new();
    run_dual_proxy_server(
        "127.0.0.1:8080",
        bind_addr,
        acme_store,
        rate_limiter,
        None,
        None,
    )
    .await
}

/// Runs the S&B Proxy edge gateway with both HTTP (port 80 redirect + ACME) and Main Gateway (port 443 / configurable).
pub async fn run_dual_proxy_server(
    http_bind: &str,
    gateway_bind: &str,
    acme_store: AcmeChallengeStore,
    rate_limiter: IpRateLimiter,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let security_headers = SecurityHeaders::from_env()?;
    let acme_email = std::env::var("SB_ACME_EMAIL").ok();
    let acme_production = std::env::var("SB_ACME_PRODUCTION")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    run_dual_proxy_server_with_acme(
        http_bind,
        gateway_bind,
        acme_store,
        rate_limiter,
        cert_path,
        key_path,
        acme_email,
        acme_production,
        security_headers,
    )
    .await
}

pub async fn run_dual_proxy_server_with_acme(
    http_bind: &str,
    gateway_bind: &str,
    acme_store: AcmeChallengeStore,
    rate_limiter: IpRateLimiter,
    cert_path: Option<String>,
    key_path: Option<String>,
    acme_email: Option<String>,
    acme_production: bool,
    security_headers: SecurityHeaders,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    initialize_json_logger();
    let telemetry = Arc::new(RwLock::new(ProxyTelemetry::new()));
    let routes = Arc::new(RwLock::new(EscapeSpaceStore::load()));

    if cert_path.is_some() != key_path.is_some() {
        return Err("--cert und --key müssen gemeinsam angegeben werden.".into());
    }
    let fallback_key = if let (Some(cert), Some(key)) = (&cert_path, &key_path) {
        Some(load_certified_key(Path::new(cert), Path::new(key))?)
    } else {
        None
    };

    let has_any_tls_config = acme_email.is_some()
        || fallback_key.is_some()
        || routes
            .read()
            .map(|store| {
                store.spaces.iter().any(|s| {
                    s.tls_enabled
                        || s.custom_cert_path.is_some()
                        || crate::ca::DeveloperCa::find_dev_certificate(&s.domain).is_some()
                })
            })
            .unwrap_or(false)
        || find_or_load_tls_acceptor(None, None).is_some();

    if !has_any_tls_config {
        let bind: SocketAddr = gateway_bind
            .parse()
            .map_err(|error| format!("Ungültige Gateway-Bind-Adresse '{gateway_bind}': {error}"))?;
        if !bind.ip().is_loopback() {
            return Err("Öffentliches Gateway ohne TLS-Zertifikat verweigert. Nutze --acme-email oder --cert/--key.".into());
        }
    }

    println!("🛡️  S&B Proxy Dual-Port Gateway aktiv!");
    println!("  🌐 HTTP / ACME Port:     http://{}", http_bind);
    if acme_email.is_some() && fallback_key.is_some() {
        println!(
            "  🔐 HTTPS / Gateway Port: https://{} [Hybrid: ACME TLS-ALPN-01 + Custom PEM Fallback]",
            gateway_bind
        );
    } else if acme_email.is_some() {
        println!(
            "  🔐 HTTPS / Gateway Port: https://{} [ACME TLS-ALPN-01 + dynamisches SNI aktiv]",
            gateway_bind
        );
    } else if has_any_tls_config {
        println!(
            "  🔒 HTTPS / Gateway Port: https://{} [TLS + HTTP/2 aktiv (Custom PEM / Dev CA)]",
            gateway_bind
        );
    } else {
        println!(
            "  ⚠️  Lokaler HTTP-Entwicklungsmodus: http://{} [TLS deaktiviert]",
            gateway_bind
        );
    }
    println!("  📡 Studio IPC Control:   http://127.0.0.1:58900");
    println!(
        "  ⚡ Sovereign Tunnel Hub: 127.0.0.1:58910 (Loopback-only, Mesh-Access via UDP:58888)"
    );
    println!("  🛡️  Airgap-Schutz:         Ausschließlich Loopback 127.0.0.1:PORT");

    async fn bind_with_diagnostics(
        addr: &str,
        service_name: &str,
    ) -> Result<TcpListener, Box<dyn std::error::Error + Send + Sync>> {
        match TcpListener::bind(addr).await {
            Ok(l) => Ok(l),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let port = addr.rsplit(':').next().unwrap_or("80");
                let port_num: u16 = port.parse().unwrap_or(0);
                if port_num < 1024 {
                    Err(format!(
                        "Fehlende Berechtigung fuer Port {} ({})!\n  Tipp: Privilegierte Ports (<1024) erfordern Root-Rechte oder 'cap_net_bind_service'.\n  Fuehren Sie auf Linux aus:\n    sudo setcap 'cap_net_bind_service=+ep' $(which sb-proxy)\n  Oder starten Sie mit sudo bzw. nutzen Sie unprivilegierte Ports (--http-bind 127.0.0.1:8080 --bind 127.0.0.1:8443). (Detail: {})",
                        port, service_name, e
                    ).into())
                } else {
                    Err(format!(
                        "Zugriff verweigert beim Binden von {} an {}: {}",
                        service_name, addr, e
                    )
                    .into())
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                let port = addr.rsplit(':').next().unwrap_or("80");
                Err(format!(
                    "Port {} ({}) ist bereits belegt! Pruefen Sie, ob ein anderer Webserver (Nginx/Apache/Caddy) oder eine andere sb-proxy Instanz laeuft.\n  Tipp: Port freigeben mit 'sb-ports kill {}' oder alternativen Port konfigurieren. (Detail: {})",
                    port, service_name, port, e
                ).into())
            }
            Err(e) => {
                Err(format!("Fehler beim Binden von {} an {}: {}", service_name, addr, e).into())
            }
        }
    }

    let http_listener = bind_with_diagnostics(http_bind, "HTTP / ACME Gateway").await?;
    let gateway_listener = bind_with_diagnostics(gateway_bind, "HTTPS / Routing Gateway").await?;

    let acme_domains = if acme_email.is_some() {
        let store = routes
            .read()
            .map_err(|_| "Route state is unavailable while configuring ACME.")?;
        let domains = store
            .spaces
            .iter()
            .filter(|space| {
                space.tls_enabled
                    && space.custom_cert_path.is_none()
                    && space.custom_key_path.is_none()
                    && crate::ca::DeveloperCa::find_dev_certificate(&space.domain).is_none()
            })
            .flat_map(|space| {
                std::iter::once(space.domain.clone()).chain(space.aliases.iter().cloned())
            })
            .filter(|domain| is_acme_dns_name(domain))
            .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if domains.is_empty() {
            None
        } else {
            Some(domains)
        }
    } else {
        None
    };
    let acme_cache = if let Some(email) = &acme_email {
        if !is_acme_email(email) || email.contains('\n') || email.contains('\r') {
            return Err("Ungültige ACME-Kontaktadresse.".into());
        }
        let path = dirs::home_dir()
            .ok_or("ACME benötigt ein auflösbares Benutzer-Home-Verzeichnis.")?
            .join(".sb")
            .join("acme");
        std::fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Some(path)
    } else {
        None
    };

    // Background watcher for external configuration updates on escape_spaces.json
    let routes_watcher = routes.clone();
    let watcher_task = tokio::spawn(async move {
        let store_path = dirs::home_dir().map(|h| h.join(".sb").join("escape_spaces.json"));
        let mut last_modified = store_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Some(ref p) = store_path {
                if let Ok(meta) = std::fs::metadata(p) {
                    if let Ok(mod_time) = meta.modified() {
                        if Some(mod_time) != last_modified {
                            last_modified = Some(mod_time);
                            let reloaded = EscapeSpaceStore::load();
                            if let Ok(mut w) = routes_watcher.write() {
                                *w = reloaded;
                            }
                        }
                    }
                }
            }
        }
    });

    let tele_for_ipc = telemetry.clone();
    let routes_for_ipc = routes.clone();
    let ipc_task = tokio::spawn(async move {
        if let Err(e) =
            crate::ipc::run_ipc_server("127.0.0.1:58900", tele_for_ipc, routes_for_ipc).await
        {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "ipc_server_failed",
                    "error": e.to_string(),
                })
            );
        }
    });

    let tunnel_hub = crate::tunnel::SovereignTunnelHub::global();
    let tunnel_task = tokio::spawn(async move {
        // Bind on loopback ONLY — access exclusively via encrypted sb-mesh Stealth tunnel (UDP:58888).
        // Direct WAN access to port 58910 is intentionally blocked.
        let bind_addr = "127.0.0.1:58910";
        if let Err(e) = tunnel_hub.run_server(bind_addr).await {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "tunnel_hub_failed",
                    "error": e.to_string(),
                })
            );
        }
    });

    let acme_clone = acme_store.clone();
    let http_task = tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((stream, addr)) => {
                    let store = acme_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_http_redirect_connection(stream, addr, store).await {
                            eprintln!(
                                "{}",
                                serde_json::json!({
                                    "event": "http_redirect_failed",
                                    "client_ip": addr.ip().to_string(),
                                    "error": e.to_string(),
                                })
                            );
                        }
                    });
                }
                Err(e) => eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "http_listener_failed",
                        "error": e.to_string(),
                    })
                ),
            }
        }
    });

    let tele_for_gateway = telemetry.clone();
    let routes_for_gateway = routes.clone();
    let auth_verifier = load_auth_verifier();
    if let Some(email) = &acme_email {
        println!(
            "  🔐 ACME TLS-ALPN-01: {} ({}; Cache: {})",
            email,
            if acme_production {
                "Let's Encrypt Produktion"
            } else {
                "Let's Encrypt Staging"
            },
            acme_cache
                .as_ref()
                .expect("ACME cache initialized")
                .display()
        );
        let domains_display = acme_domains
            .as_ref()
            .map(|d| d.join(", "))
            .unwrap_or_else(|| {
                "Keine rein automatischen ACME-Domains (alle besitzen eigene PEMs)".into()
            });
        println!("  🌐 ACME-Domains: {}", domains_display);
    }

    let gateway_task = tokio::spawn(async move {
        // Build the TLS ServerConfig with DynamicSniResolver if TLS is configured
        if let (Some(email), Some(cache_path)) = (acme_email, acme_cache) {
            use tokio_rustls::LazyConfigAcceptor;
            use tokio_stream::StreamExt;

            let contact = format!("mailto:{}", email.trim());
            let domains = acme_domains.unwrap_or_default();
            let mut state = rustls_acme::AcmeConfig::new(domains)
                .contact([contact])
                .cache(rustls_acme::caches::DirCache::new(cache_path))
                .directory_lets_encrypt(acme_production)
                .state();

            let challenge_rustls_config = state.challenge_rustls_config();
            let acme_resolver = state.resolver();

            let dynamic_resolver = Arc::new(DynamicSniResolver::new(
                Some(acme_resolver),
                routes_for_gateway.clone(),
                fallback_key,
            ));

            let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(dynamic_resolver);
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let default_rustls_config = Arc::new(server_config);

            // Spawn background task driving the ACME state machine
            tokio::spawn(async move {
                loop {
                    match state.next().await {
                        Some(Ok(event)) => log::info!("ACME event: {:?}", event),
                        Some(Err(err)) => log::error!("ACME error: {:?}", err),
                        None => break,
                    }
                }
            });

            loop {
                match gateway_listener.accept().await {
                    Ok((stream, addr)) => {
                        let limiter = rate_limiter.clone();
                        let tele = tele_for_gateway.clone();
                        let rts = routes_for_gateway.clone();
                        let headers = security_headers.clone();
                        let challenge_config = challenge_rustls_config.clone();
                        let default_config = default_rustls_config.clone();
                        let auth = auth_verifier.clone();

                        tokio::spawn(async move {
                            match LazyConfigAcceptor::new(Default::default(), stream).await {
                                Ok(start_handshake) => {
                                    if rustls_acme::is_tls_alpn_challenge(
                                        &start_handshake.client_hello(),
                                    ) {
                                        if let Ok(mut tls) =
                                            start_handshake.into_stream(challenge_config).await
                                        {
                                            let _ = tls.shutdown().await;
                                        }
                                    } else {
                                        match start_handshake.into_stream(default_config).await {
                                            Ok(tls_stream) => {
                                                if let Err(error) = serve_connection_with_auth(
                                                    tls_stream, addr, true, limiter, tele, rts,
                                                    headers, auth,
                                                )
                                                .await
                                                {
                                                    eprintln!(
                                                        "{}",
                                                        serde_json::json!({
                                                            "event": "https_connection_failed",
                                                            "client_ip": addr.ip().to_string(),
                                                            "error": error.to_string(),
                                                        })
                                                    );
                                                }
                                            }
                                            Err(error) => eprintln!(
                                                "{}",
                                                serde_json::json!({
                                                    "event": "tls_handshake_failed",
                                                    "client_ip": addr.ip().to_string(),
                                                    "error": error.to_string(),
                                                })
                                            ),
                                        }
                                    }
                                }
                                Err(error) => eprintln!(
                                    "{}",
                                    serde_json::json!({
                                        "event": "tls_acceptor_failed",
                                        "client_ip": addr.ip().to_string(),
                                        "error": error.to_string(),
                                    })
                                ),
                            }
                        });
                    }
                    Err(error) => eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "gateway_listener_failed",
                            "error": error.to_string(),
                        })
                    ),
                }
            }
        } else if has_any_tls_config {
            let dynamic_resolver = Arc::new(DynamicSniResolver::new(
                None,
                routes_for_gateway.clone(),
                fallback_key,
            ));
            let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(dynamic_resolver);
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            loop {
                match gateway_listener.accept().await {
                    Ok((stream, addr)) => {
                        let limiter = rate_limiter.clone();
                        let tele = tele_for_gateway.clone();
                        let rts = routes_for_gateway.clone();
                        let acc = tls_acceptor.clone();
                        let headers = security_headers.clone();
                        let auth = auth_verifier.clone();
                        tokio::spawn(async move {
                            match acc.accept(stream).await {
                                Ok(tls_stream) => {
                                    if let Err(error) = serve_connection_with_auth(
                                        tls_stream, addr, true, limiter, tele, rts, headers, auth,
                                    )
                                    .await
                                    {
                                        eprintln!(
                                            "{}",
                                            serde_json::json!({
                                                "event": "https_connection_failed",
                                                "client_ip": addr.ip().to_string(),
                                                "error": error.to_string(),
                                            })
                                        );
                                    }
                                }
                                Err(error) => eprintln!(
                                    "{}",
                                    serde_json::json!({
                                        "event": "tls_handshake_failed",
                                        "client_ip": addr.ip().to_string(),
                                        "error": error.to_string(),
                                    })
                                ),
                            }
                        });
                    }
                    Err(error) => eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "gateway_listener_failed",
                            "error": error.to_string(),
                        })
                    ),
                }
            }
        } else {
            loop {
                match gateway_listener.accept().await {
                    Ok((stream, addr)) => {
                        let limiter = rate_limiter.clone();
                        let tele = tele_for_gateway.clone();
                        let rts = routes_for_gateway.clone();
                        let headers = security_headers.clone();
                        let auth = auth_verifier.clone();
                        tokio::spawn(async move {
                            if let Err(error) = serve_connection_with_auth(
                                stream, addr, false, limiter, tele, rts, headers, auth,
                            )
                            .await
                            {
                                eprintln!(
                                    "{}",
                                    serde_json::json!({
                                        "event": "http_connection_failed",
                                        "client_ip": addr.ip().to_string(),
                                        "error": error.to_string(),
                                    })
                                );
                            }
                        });
                    }
                    Err(error) => eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "gateway_listener_failed",
                            "error": error.to_string(),
                        })
                    ),
                }
            }
        }
    });

    tokio::select! {
        res = http_task => res?,
        res = gateway_task => res?,
        res = ipc_task => res?,
        res = tunnel_task => res?,
        _ = watcher_task => {},
    }

    Ok(())
}

fn is_acme_dns_name(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    !domain.is_empty()
        && domain.len() <= 253
        && domain.parse::<std::net::IpAddr>().is_err()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
}

fn is_acme_email(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !local.contains('@')
        && !domain.contains('@')
        && !email.bytes().any(|byte| byte.is_ascii_whitespace())
        && domain.contains('.')
        && is_acme_dns_name(domain)
}

fn initialize_json_logger() {
    use std::io::Write;

    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"));
    builder.format(|buffer, record| {
        let entry = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "level": record.level().to_string(),
            "target": record.target(),
            "message": record.args().to_string(),
        });
        writeln!(buffer, "{entry}")
    });
    let _ = builder.try_init();
}

/// Handles manual HTTP-01 challenge responses and redirects other traffic to HTTPS.
async fn handle_http_redirect_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    acme_store: AcmeChallengeStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = std::time::Instant::now();
    let mut buffer = [0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_secs(10), client.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };
    if n == 0 {
        return Ok(());
    }

    let raw_header = String::from_utf8_lossy(&buffer[..n]);

    // Extract Request Path
    let request_line = raw_header.lines().next().unwrap_or("");
    let request_path = request_line.split_whitespace().nth(1).unwrap_or("/");

    // 1. ACME HTTP-01 Challenge Interception: /.well-known/acme-challenge/{token}
    if let Some(token) = request_path.strip_prefix("/.well-known/acme-challenge/") {
        let clean_token = token.split('?').next().unwrap_or("").trim();
        // Check in-memory store
        if let Some(ka) = acme_store.get(clean_token) {
            let clean_ka = ka.trim().to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                clean_ka.len(),
                clean_ka
            );
            client.write_all(resp.as_bytes()).await?;
            eprintln!(
                "{}",
                serde_json::json!({
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "event": "http_access",
                    "client_ip": client_addr.ip().to_string(),
                    "method": request_line.split_whitespace().next().unwrap_or(""),
                    "host": "",
                    "path": "/.well-known/acme-challenge",
                    "protocol": "HTTP/1.1",
                    "status": 200,
                    "latency_ms": started.elapsed().as_millis(),
                })
            );
            return Ok(());
        }
    }

    // 2. Extract Host for 301 Redirect to HTTPS
    let host = raw_header
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, val)| {
            val.trim()
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase()
        })
        .unwrap_or_else(|| "skulls-and-bones.org".to_string());

    // Canonical redirect: normalize IP or www to primary domain
    let suite_cfg = sb_core::config::SuiteConfig::load();
    let is_node_ip = suite_cfg
        .network
        .expected_node_ip
        .as_deref()
        .map(|ip| host == ip)
        .unwrap_or(false);
    let target_host = if is_node_ip || host == "www.skulls-and-bones.org" {
        "skulls-and-bones.org".to_string()
    } else {
        host.clone()
    };

    let target_url = format!("https://{}{}", target_host, request_path);
    let location = hyper::header::HeaderValue::from_str(&target_url)?;
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nConnection: close\r\n\r\n",
        location.to_str()?
    );
    client.write_all(resp.as_bytes()).await?;
    eprintln!(
        "{}",
        serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event": "http_access",
            "client_ip": client_addr.ip().to_string(),
            "method": request_line.split_whitespace().next().unwrap_or(""),
            "host": host,
            "path": request_path.split('?').next().unwrap_or("/"),
            "protocol": "HTTP/1.1",
            "status": 301,
            "latency_ms": started.elapsed().as_millis(),
        })
    );
    Ok(())
}

/// Handles incoming gateway connections (Egress Routing, Slowloris protection, Rate Limiting, Graceful Deploying).
#[allow(dead_code)]
async fn handle_gateway_connection<S>(
    mut client: S,
    client_addr: SocketAddr,
    rate_limiter: IpRateLimiter,
    telemetry: Arc<RwLock<ProxyTelemetry>>,
    routes: Arc<RwLock<EscapeSpaceStore>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin + Send + 'static,
{
    if let Ok(mut t) = telemetry.write() {
        t.increment_requests();
    }

    let mut buffer = [0u8; 8192];
    // Slowloris timeout protection (10 seconds)
    let n = match tokio::time::timeout(Duration::from_secs(10), client.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };
    if n == 0 {
        return Ok(());
    }

    let raw_header = String::from_utf8_lossy(&buffer[..n]);

    // Extract Host header
    let host = raw_header
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, val)| {
            val.trim()
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase()
        })
        .unwrap_or_default();

    // Extract Request Path
    let request_line = raw_header.lines().next().unwrap_or("");
    let method = request_line.split_whitespace().next().unwrap_or("");
    let request_path = request_line.split_whitespace().nth(1).unwrap_or("/");

    // Check ACME Challenge Interception
    if let Some(token) = request_path.strip_prefix("/.well-known/acme-challenge/") {
        let clean_token = token.split('?').next().unwrap_or("").trim();
        let candidate_paths = [
            format!(
                "/home/leonf/website/out/.well-known/acme-challenge/{}",
                clean_token
            ),
            format!(
                "/var/www/skulls-and-bones/.well-known/acme-challenge/{}",
                clean_token
            ),
            format!("/tmp/.well-known/acme-challenge/{}", clean_token),
            format!(".well-known/acme-challenge/{}", clean_token),
        ];
        if let Some(ka) = candidate_paths
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
        {
            let clean_ka = ka.trim().to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                clean_ka.len(),
                clean_ka
            );
            client.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    }

    // Lookup route in In-Memory Route Cache (zero disk I/O)
    let matched_space = {
        let store = routes.read().unwrap();
        store
            .spaces
            .iter()
            .find(|s| {
                s.domain.to_lowercase() == host
                    || s.aliases.iter().any(|a| a.to_lowercase() == host)
                    || (host.is_empty() && s.target_port == 3000)
            })
            .cloned()
    };

    let space = match matched_space {
        Some(s) => s,
        None => {
            if let Ok(mut t) = telemetry.write() {
                t.record_status(404, 1.0);
            }
            let body = format!(
                "<!DOCTYPE html><html><body style='font-family:sans-serif;background:#0f0f15;color:#eee;padding:3rem;text-align:center;'>\
                <h1 style='color:#ef4444;'>404 - Kein Escape Space konfiguriert</h1>\
                <p>Für die Domain <b>{}</b> existiert im S&B Mesh kein aktiver Escape Space.</p>\
                <small style='color:#888;'>S&B Sovereign Proxy Gateway</small>\
                </body></html>",
                host
            );
            let resp = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            client.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    };

    // 1. IP Rate Limiting Check
    if let Err(retry_after) = rate_limiter.check_and_consume(client_addr.ip(), space.rate_limit_rpm)
    {
        if let Ok(mut t) = telemetry.write() {
            t.increment_rate_limited();
        }
        let body = format!(
            "<!DOCTYPE html><html><body style='font-family:sans-serif;background:#0f0f15;color:#eee;padding:3rem;text-align:center;'>\
            <h1 style='color:#f59e0b;'>429 - Zu viele Anfragen (Rate Limit)</h1>\
            <p>Die Anfrage-Rate für diese IP wurde überschritten (Limit: {} RPM).</p>\
            <p style='color:#888;'>Bitte warte {} Sekunden.</p>\
            </body></html>",
            space.rate_limit_rpm, retry_after
        );
        let resp = format!(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/html; charset=utf-8\r\nRetry-After: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            retry_after,
            body.len(),
            body
        );
        client.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // 2. Canonical Redirect: If requested via alias, redirect 301 to primary domain
    if space.aliases.iter().any(|a| a.to_lowercase() == host) && space.domain.to_lowercase() != host
    {
        let scheme = if space.tls_enabled { "https" } else { "http" };
        let location = format!("{}://{}{}", scheme, space.domain, request_path);
        let resp = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nConnection: close\r\n\r\n",
            location
        );
        client.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // 3. Check Expiration for Preview Subdomains
    if let Some(ref exp_str) = space.expires_at {
        if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(exp_str) {
            if chrono::Utc::now() > exp_time {
                if let Ok(mut t) = telemetry.write() {
                    t.record_status(410, 1.0);
                }
                let body = format!(
                    "<!DOCTYPE html><html><body style='font-family:sans-serif;background:#0f0f15;color:#eee;padding:3rem;text-align:center;'>\
                    <h1 style='color:#f59e0b;'>410 - Preview-Link Abgelaufen</h1>\
                    <p>Der temporäre Preview-Space für <b>{}</b> ist abgelaufen.</p>\
                    <small style='color:#888;'>S&B Ephemeral Preview Engine</small>\
                    </body></html>",
                    space.domain
                );
                let resp = format!(
                    "HTTP/1.1 410 Gone\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                client.write_all(resp.as_bytes()).await?;
                return Ok(());
            }
        }
    }

    // 4. Maintenance Mode Handling (HTTP 503 + Retry-After)
    if space.status == EscapeStatus::Maintenance {
        if let Ok(mut t) = telemetry.write() {
            t.record_status(503, 1.0);
        }
        let msg = space.maintenance_msg.clone().unwrap_or_else(|| {
            "Wartungsarbeiten im Gange. Bitte versuche es in Kürze erneut.".to_string()
        });
        let body = format!(
            "<!DOCTYPE html><html><head><title>Wartungsmodus</title></head>\
            <body style='font-family:system-ui,sans-serif;background:#0b0b10;color:#f3f4f6;padding:4rem 2rem;text-align:center;'>\
            <div style='max-width:550px;margin:0 auto;background:#15151e;border:1px solid rgba(255,255,255,0.1);border-radius:16px;padding:2.5rem;box-shadow:0 10px 30px rgba(0,0,0,0.5);'>\
            <div style='font-size:42px;margin-bottom:1rem;'>🛠️</div>\
            <h1 style='color:#facc15;font-size:22px;margin-bottom:0.5rem;'>Wartungsmodus aktiv</h1>\
            <p style='color:#9ca3af;font-size:14px;line-height:1.6;'>{}</p>\
            <div style='margin-top:2rem;padding-top:1.5rem;border-top:1px solid rgba(255,255,255,0.06);font-size:12px;color:#6b7280;'>\
            Domain: <span style='color:#38bdf8;font-family:monospace;'>{}</span> • S&B Proxy Guard\
            </div></div></body></html>",
            msg, space.domain
        );
        let resp = format!(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\nRetry-After: 300\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // 5. Check Status: If Paused, return 503
    if space.status == EscapeStatus::Paused {
        if let Ok(mut t) = telemetry.write() {
            t.record_status(503, 1.0);
        }
        let body = format!(
            "<!DOCTYPE html><html><body style='font-family:sans-serif;background:#0f0f15;color:#eee;padding:3rem;text-align:center;'>\
            <h1 style='color:#f59e0b;'>503 - Escape Space Pausiert</h1>\
            <p>Die Domain <b>{}</b> wurde über das S&B Cockpit temporär stummgeschaltet.</p>\
            <small style='color:#888;'>S&B Sovereign Proxy Gateway</small>\
            </body></html>",
            space.domain
        );
        let resp = format!(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if let Some(root) = &space.static_root {
        let status =
            crate::static_files::serve(&mut client, Path::new(root), method, request_path).await?;
        if let Ok(mut t) = telemetry.write() {
            t.record_status(status, 0.0);
        }
        return Ok(());
    }

    // Determine routing mode: Sovereign Mesh Tunnel vs. direct loopback
    let hub = crate::tunnel::SovereignTunnelHub::global();
    let is_tunnel_route = space.is_tunnel || hub.is_tunnel_active(&space.domain).await;

    // Airgap Security Check: Verify target port is not in PROTECTED_PORTS.
    // Tunnel routes (is_tunnel=true, target_port=0) are exempt because they
    // don't connect to a local port directly — traffic is handled by SovereignTunnelHub.
    if !is_tunnel_route {
        if let Err(err) = validate_target_port(space.target_port) {
            if let Ok(mut t) = telemetry.write() {
                t.record_status(500, 1.0);
            }
            let body = format!("500 Airgap Violation: {}", err);
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            client.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    }

    // Check if this EscapeSpace routes over Sovereign Tunnel or local loopback
    let mut upstream = if is_tunnel_route {
        match hub.open_stream(&space.domain, Duration::from_secs(5)).await {
            Ok(stream) => stream,
            Err(e) => {
                if let Ok(mut t) = telemetry.write() {
                    t.record_status(503, 1.0);
                }
                let body = format!(
                    "<!DOCTYPE html><html><head><title>Warte auf Sovereign Tunnel...</title>\
                    <meta http-equiv='refresh' content='2'>\
                    <script>\
                    setInterval(async () => {{\
                        try {{\
                            const r = await fetch(window.location.href, {{ method: 'HEAD', cache: 'no-store' }});\
                            if (r.status !== 502 && r.status !== 503) {{ window.location.reload(); }}\
                        }} catch(e) {{}}\
                    }}, 1500);\
                    </script>\
                    </head>\
                    <body style='font-family:system-ui,-apple-system,sans-serif;background:#09090d;color:#f3f4f6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'>\
                    <div style='max-width:520px;text-align:center;padding:2.5rem;background:#12121a;border:1px solid rgba(56,189,248,0.25);border-radius:20px;box-shadow:0 20px 40px rgba(0,0,0,0.6);'>\
                    <div style='font-size:42px;margin-bottom:1rem;'>⚡</div>\
                    <h2 style='color:#38bdf8;font-size:22px;margin:0 0 0.5rem 0;'>Sovereign Tunnel wartet auf Verbindung</h2>\
                    <p style='color:#9ca3af;font-size:14px;line-height:1.6;margin-bottom:1.5rem;'>\
                    Für <code style='color:#38bdf8;background:#1e1e28;padding:2px 6px;border-radius:4px;'>{}</code> ist der Sovereign Tunnel aktiv, aber noch kein lokaler Entwickler-Client verbunden.<br><br>\
                    Starte auf deinem Rechner:<br>\
                    <code style='color:#fbbf24;background:#181822;padding:6px 12px;border-radius:6px;display:inline-block;margin-top:8px;font-family:monospace;'>sb escape share {} --as {}</code>\
                    </p>\
                    <div style='font-size:11px;color:#6b7280;'>\
                    Status: {} • S&B Cloudflare/ngrok Killer\
                    </div></div></body></html>",
                    space.domain, space.target_port, space.domain, e
                );
                let resp = format!(
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\nRetry-After: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                client.write_all(resp.as_bytes()).await?;
                return Ok(());
            }
        }
    } else {
        // Connect strictly to 127.0.0.1:<target_port>
        let upstream_addr = format!("127.0.0.1:{}", space.target_port);
        match TcpStream::connect(&upstream_addr).await {
            Ok(stream) => stream,
            Err(_) => {
                if let Ok(mut t) = telemetry.write() {
                    t.record_status(502, 1.0);
                }
                // 6. Graceful Deploying / Hot-Reload Fallback Page with Auto-Polling
                let body = format!(
                    "<!DOCTYPE html><html><head><title>Dienst wird aktualisiert...</title>\
                    <meta http-equiv='refresh' content='2'>\
                    <script>\
                    setInterval(async () => {{\
                        try {{\
                            const r = await fetch(window.location.href, {{ method: 'HEAD', cache: 'no-store' }});\
                            if (r.status !== 502 && r.status !== 503) {{ window.location.reload(); }}\
                        }} catch(e) {{}}\
                    }}, 1000);\
                    </script>\
                    </head>\
                    <body style='font-family:system-ui,-apple-system,sans-serif;background:#09090d;color:#f3f4f6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'>\
                    <div style='max-width:480px;text-align:center;padding:2.5rem;background:#12121a;border:1px solid rgba(255,255,255,0.08);border-radius:20px;box-shadow:0 20px 40px rgba(0,0,0,0.6);'>\
                    <div style='font-size:40px;margin-bottom:1rem;animation:pulse 1.5s infinite;'>⚡</div>\
                    <h2 style='color:#38bdf8;font-size:20px;margin:0 0 0.5rem 0;'>Dienst wird aktualisiert...</h2>\
                    <p style='color:#9ca3af;font-size:14px;line-height:1.6;margin-bottom:1.5rem;'>\
                    Dein lokaler Server auf <code style='color:#fbbf24;background:#1e1e28;padding:2px 6px;border-radius:4px;'>127.0.0.1:{}</code> startet gerade neu. Sobald der Dienst bereit ist, lädt diese Seite automatisch neu.\
                    </p>\
                    <div style='font-size:11px;color:#6b7280;display:flex;align-items:center;justify-content:center;gap:6px;'>\
                    <span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:#38bdf8;'></span>\
                    S&B Proxy Graceful Deploying Guard\
                    </div></div></body></html>",
                    space.target_port
                );
                let resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nRetry-After: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                client.write_all(resp.as_bytes()).await?;
                return Ok(());
            }
        }
    };

    // Inject Proxy Headers
    let header_chunk = &buffer[..n];
    let header_str = String::from_utf8_lossy(header_chunk);
    let mut modified_headers = String::new();
    let mut lines = header_str.lines();

    if let Some(first_line) = lines.next() {
        modified_headers.push_str(first_line);
        modified_headers.push_str("\r\n");
    }

    for line in lines {
        if line.is_empty() {
            // End of headers -> inject X-Forwarded headers
            modified_headers.push_str(&format!("X-Forwarded-For: {}\r\n", client_addr.ip()));
            modified_headers.push_str("X-Forwarded-Proto: https\r\n");
            modified_headers.push_str(&format!("X-Real-IP: {}\r\n", client_addr.ip()));
            modified_headers.push_str("\r\n");
            break;
        } else if !line.to_ascii_lowercase().starts_with("x-forwarded-")
            && !line.to_ascii_lowercase().starts_with("x-real-ip:")
        {
            modified_headers.push_str(line);
            modified_headers.push_str("\r\n");
        }
    }

    let start_proxy = std::time::Instant::now();
    // Send modified headers to upstream
    upstream.write_all(modified_headers.as_bytes()).await?;

    // Bidirectional Streaming (Supports WebSockets, Chunked, Long-running streams)
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    let elapsed_ms = start_proxy.elapsed().as_millis() as f32;
    if let Ok(mut t) = telemetry.write() {
        t.record_status(200, elapsed_ms);
    }

    Ok(())
}

/// Loads the `sb-auth` public-key-only verifier from `SB_AUTH_PUBLIC_KEY` or `~/.sb/auth/auth.pub`
/// together with the local revocation store (`SB_AUTH_REVOCATIONS` or `~/.sb/auth/revocations.json`).
fn load_auth_verifier() -> Option<Arc<sb_auth::AuthVerifier>> {
    let pub_key = std::env::var("SB_AUTH_PUBLIC_KEY").ok().or_else(|| {
        let path = dirs::home_dir()?.join(".sb").join("auth").join("auth.pub");
        std::fs::read_to_string(path).ok()
    })?;
    let pub_key = pub_key.trim();
    if pub_key.is_empty() {
        return None;
    }

    let revocation_path = std::env::var("SB_AUTH_REVOCATIONS")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            dirs::home_dir().map(|h| h.join(".sb").join("auth").join("revocations.json"))
        })?;
    let store = match sb_auth::FileRevocationStore::open(&revocation_path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!("  ⚠ sb-auth RevocationStore konnte nicht geöffnet werden: {error}");
            return None;
        }
    };

    match sb_auth::AuthVerifier::from_public_base64(pub_key, store) {
        Ok(verifier) => Some(Arc::new(verifier)),
        Err(error) => {
            eprintln!("  ⚠ sb-auth Public Key ungültig: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escape::EscapeSpace;

    #[test]
    fn test_dynamic_sni_resolver_fallback_and_route_matching() {
        let store = EscapeSpaceStore {
            spaces: vec![EscapeSpace {
                id: "route-custom".to_string(),
                domain: "custom.example.org".to_string(),
                node_callsign: "node-1".to_string(),
                target_port: 8080,
                public_port: 443,
                tls_enabled: true,
                status: EscapeStatus::Active,
                mesh_isolated: false,
                rate_limit_rpm: 120,
                created_at: "2026-10-08T00:00:00Z".to_string(),
                aliases: vec!["alias.example.org".to_string()],
                maintenance_msg: None,
                expires_at: None,
                custom_cert_path: Some("/nonexistent/cert.pem".to_string()),
                custom_key_path: Some("/nonexistent/key.pem".to_string()),
                cert_expires_at: None,
                is_tunnel: false,
                tunnel_peer: None,
                static_root: None,
                auth_required: false,
                required_role: None,
                required_capability: None,
            }],
        };
        let routes = Arc::new(RwLock::new(store));
        let resolver = DynamicSniResolver::new(None, routes, None);

        // Server without existing PEM files or ACME falls back to None safely
        assert!(resolver.resolve_for_server_name("unknown.org").is_none());
        assert!(resolver
            .resolve_for_server_name("custom.example.org")
            .is_none());
    }

    static TEST_PROXY_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_dynamic_sni_resolver_on_demand_and_ram_cache() {
        let _guard = TEST_PROXY_MUTEX.lock().unwrap();
        let _ = sb_ca::x509::init_root_ca(false);
        let store = EscapeSpaceStore { spaces: vec![] };
        let routes = Arc::new(RwLock::new(store));
        let resolver = DynamicSniResolver::new(None, routes, None);

        let domain = format!("unit-node-{}.sbm", uuid::Uuid::new_v4().simple());
        assert_eq!(resolver.cached_certs_count(), 0);
        assert!(!resolver.is_cached(&domain));

        // First resolution: On-Demand minting
        let cert1 = resolver.resolve_for_server_name(&domain);
        assert!(
            cert1.is_some(),
            "Should dynamically issue cert for .sbm domain"
        );
        assert!(
            resolver.is_cached(&domain),
            "Domain must now be cached in RAM"
        );
        assert_eq!(resolver.cached_certs_count(), 1);

        // Second resolution: Sub-microsecond RAM Cache hit
        let cert2 = resolver.resolve_for_server_name(&domain);
        assert!(cert2.is_some(), "Cached certificate must resolve");
        assert!(
            Arc::ptr_eq(&cert1.unwrap(), &cert2.unwrap()),
            "Second resolution must return the identical Arc pointer from RAM cache"
        );
    }

    #[test]
    fn test_dynamic_sni_resolver_ineligible_domains_rejected() {
        let store = EscapeSpaceStore { spaces: vec![] };
        let routes = Arc::new(RwLock::new(store));
        let resolver = DynamicSniResolver::new(None, routes, None);

        // Public/unregistered domains must not trigger on-demand generation
        assert!(resolver
            .resolve_for_server_name("evil-attacker.com")
            .is_none());
        assert!(!resolver.is_cached("evil-attacker.com"));

        // Path traversals and control characters must be rejected by eligibility gate
        assert!(resolver
            .resolve_for_server_name("../../etc/shadow")
            .is_none());
        assert!(resolver.resolve_for_server_name("bad\\node.sbm").is_none());
    }

    #[test]
    fn test_dynamic_sni_resolver_active_route_without_custom_cert() {
        let _guard = TEST_PROXY_MUTEX.lock().unwrap();
        let _ = sb_ca::x509::init_root_ca(false);
        let route_domain = format!("mesh-svc-{}.local", uuid::Uuid::new_v4().simple());
        let store = EscapeSpaceStore {
            spaces: vec![EscapeSpace {
                id: "route-auto-tls".to_string(),
                domain: route_domain.clone(),
                node_callsign: "node-local".to_string(),
                target_port: 8080,
                public_port: 443,
                tls_enabled: true,
                status: EscapeStatus::Active,
                mesh_isolated: false,
                rate_limit_rpm: 120,
                created_at: "2026-10-08T00:00:00Z".to_string(),
                aliases: vec![],
                maintenance_msg: None,
                expires_at: None,
                custom_cert_path: None,
                custom_key_path: None,
                cert_expires_at: None,
                is_tunnel: false,
                tunnel_peer: None,
                static_root: None,
                auth_required: false,
                required_role: None,
                required_capability: None,
            }],
        };
        let routes = Arc::new(RwLock::new(store));
        let resolver = DynamicSniResolver::new(None, routes, None);

        let cert = resolver.resolve_for_server_name(&route_domain);
        assert!(
            cert.is_some(),
            "Active route without custom certs must be eligible for on-demand TLS"
        );
        assert!(resolver.is_cached(&route_domain));
    }

    #[test]
    fn accepts_dns_names_and_rejects_ip_or_malformed_names() {
        assert!(is_acme_dns_name("skulls-and-bones.org"));
        assert!(is_acme_dns_name("www.example.com."));
        assert!(!is_acme_dns_name("127.0.0.1"));
        assert!(!is_acme_dns_name("*.example.com"));
        assert!(!is_acme_dns_name("-invalid.example"));
        assert!(!is_acme_dns_name("example..com"));
    }

    #[test]
    fn validates_acme_contact_email() {
        assert!(is_acme_email("ops@example.org"));
        assert!(!is_acme_email("ops@"));
        assert!(!is_acme_email("ops@@example.org"));
        assert!(!is_acme_email("ops@example.org\r\nmalicious"));
    }
}
