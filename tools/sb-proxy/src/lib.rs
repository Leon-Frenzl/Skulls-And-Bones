pub mod acme;
pub mod ca;
pub mod config;
pub mod discovery;
pub mod http_server;
pub mod ipc;
pub mod link;
pub mod proxy;
pub mod ratelimit;
pub mod static_files;
pub mod tui;
pub mod tunnel;

pub use acme::{
    import_custom_certificate, preflight_dns_check, validate_pem_certificate,
    validate_pem_private_key, AcmeChallengeStore, CertificateMetadata,
};
pub use ca::{CaStatusReport, DevCertMetadata, DeveloperCa};
pub use config::ProxyConfig;
pub use discovery::discover_active_services;
pub use ipc::{run_ipc_server, ProxyTelemetry, ProxyTelemetryDto};
pub use link::{default_callsign, run_escape_link, MESH_TUNNEL_HUB_FORWARD_PORT};
pub use proxy::{run_dual_proxy_server, run_proxy_server};
pub use ratelimit::IpRateLimiter;
pub use tunnel::{SovereignTunnelHub, TunnelMetadataDto};

#[cfg(test)]
mod tests {
    use super::*;
    use sb_code::escape::validate_target_port;

    #[test]
    fn test_airgap_protected_ports_cannot_be_proxied() {
        // Protected mesh & system ports must fail
        assert!(validate_target_port(22).is_err());
        assert!(validate_target_port(58888).is_err());
        assert!(validate_target_port(4001).is_err());
        assert!(validate_target_port(8008).is_err());
        assert!(validate_target_port(9090).is_err());
        assert!(validate_target_port(0).is_err());

        // Legitimate app ports must succeed
        assert!(validate_target_port(3000).is_ok());
        assert!(validate_target_port(8080).is_ok());
        assert!(validate_target_port(5173).is_ok());
    }

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_proxy_config_validation() {
        assert!(ProxyConfig::add_route("invalid domain with spaces", 3000, "node").is_err());
        assert!(ProxyConfig::add_route("valid.example.com", 58888, "node").is_err());
    }

    #[test]
    fn test_preview_creation_and_fields() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let domain = format!("preview-{}.example.com", ts);
        let preview_res = ProxyConfig::add_preview(&domain, 5173, "dev-node", 24);
        assert!(
            preview_res.is_ok(),
            "preview creation failed: {:?}",
            preview_res.err()
        );
        let space = preview_res.unwrap();
        assert_eq!(space.domain, domain);
        assert_eq!(space.target_port, 5173);
        assert!(space.expires_at.is_some());
    }

    #[test]
    fn test_maintenance_mode_toggle() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let unique_domain = format!("maint-{}.example.com", ts);
        let add_res = ProxyConfig::add_route(&unique_domain, 8080, "prod-node");
        assert!(add_res.is_ok(), "add_route failed: {:?}", add_res.err());

        let status =
            ProxyConfig::set_maintenance(&unique_domain, Some("Wartung aktiv".into()), true);
        assert!(status.is_ok(), "set_maintenance failed: {:?}", status.err());
        assert_eq!(status.unwrap(), sb_code::escape::EscapeStatus::Maintenance);

        // Turn off maintenance mode
        let resume = ProxyConfig::set_maintenance(&unique_domain, None, false);
        assert!(resume.is_ok(), "resume failed: {:?}", resume.err());
        assert_eq!(resume.unwrap(), sb_code::escape::EscapeStatus::Active);
    }

    #[test]
    fn test_canonical_alias() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let unique_domain = format!("alias-{}.example.com", ts);
        let add_res = ProxyConfig::add_route(&unique_domain, 3000, "main-node");
        assert!(add_res.is_ok(), "add_route failed: {:?}", add_res.err());

        let alias_domain = format!("www.{}", unique_domain);
        let alias_res = ProxyConfig::add_alias(&unique_domain, &alias_domain);
        assert!(alias_res.is_ok(), "add_alias failed: {:?}", alias_res.err());

        let space = ProxyConfig::find_space(&unique_domain).expect("Space should exist");
        assert!(space.aliases.contains(&alias_domain));
    }

    #[test]
    fn test_discover_active_services_format() {
        let detected = discover_active_services();
        for svc in detected {
            assert!(svc.port > 0);
            assert!(!svc.hint.is_empty());
        }
    }

    #[test]
    fn test_switch_port_blue_green() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let domain = format!("switch-{}.example.com", ts);
        let add_res = ProxyConfig::add_route(&domain, 3000, "node");
        assert!(add_res.is_ok());

        // Switch to port 3001
        let switch_res = ProxyConfig::switch_port(&domain, 3001);
        assert!(switch_res.is_ok());
        assert_eq!(switch_res.unwrap().target_port, 3001);

        // Attempt invalid switch to protected port (e.g. 58888)
        let invalid_switch = ProxyConfig::switch_port(&domain, 58888);
        assert!(invalid_switch.is_err());
    }

    #[test]
    fn test_acme_challenge_store() {
        let store = AcmeChallengeStore::new();
        let token = "test-token-acme";
        let key_auth = "test-token-acme.secret-key-auth-12345";

        store.register(token, key_auth);
        assert_eq!(store.get(token), Some(key_auth.to_string()));
        assert_eq!(store.get("non-existent"), None);

        let removed = store.remove(token);
        assert_eq!(removed, Some(key_auth.to_string()));
        assert_eq!(store.get(token), None);
    }

    #[test]
    fn test_ip_rate_limiting() {
        let limiter = IpRateLimiter::new();
        let ip = "127.0.0.1".parse().unwrap();
        let rpm = 2;

        // 2 requests allowed
        assert!(limiter.check_and_consume(ip, rpm).is_ok());
        assert!(limiter.check_and_consume(ip, rpm).is_ok());

        // 3rd request blocked with retry_after
        let blocked = limiter.check_and_consume(ip, rpm);
        assert!(blocked.is_err());
        assert!(blocked.unwrap_err() >= 1);
    }

    #[test]
    fn test_validate_pem_helpers() {
        let cert_ok = b"-----BEGIN CERTIFICATE-----\nMIIB...==\n-----END CERTIFICATE-----";
        let key_ok = b"-----BEGIN PRIVATE KEY-----\nMIIE...==\n-----END PRIVATE KEY-----";
        assert!(validate_pem_certificate(cert_ok).is_ok());
        assert!(validate_pem_private_key(key_ok).is_ok());

        let invalid = b"INVALID NOT PEM";
        assert!(validate_pem_certificate(invalid).is_err());
        assert!(validate_pem_private_key(invalid).is_err());
    }

    #[test]
    fn test_certificate_metadata_list() {
        let certs = ProxyConfig::list_certificates();
        for c in certs {
            assert!(!c.domain.is_empty());
            assert!(!c.issuer.is_empty());
        }
    }

    #[test]
    fn test_ipc_telemetry_dto() {
        let mut telemetry = ProxyTelemetry::new();
        telemetry.increment_requests();
        telemetry.increment_rate_limited();

        let dto = telemetry.to_dto(2);
        assert_eq!(dto.status, "online");
        assert_eq!(dto.total_requests, 1);
        assert_eq!(dto.rate_limited_count, 1);
        assert_eq!(dto.active_spaces_count, 2);
    }

    #[test]
    fn test_developer_ca_flow() {
        let _lock = TEST_MUTEX.lock().unwrap();
        // Test CA initialization with force=true
        let ca_res = DeveloperCa::init_root_ca(true);
        assert!(ca_res.is_ok(), "init_root_ca failed: {:?}", ca_res.err());
        let status = ca_res.unwrap();
        assert!(status.initialized);
        assert!(DeveloperCa::root_ca_crt_path().exists());
        assert!(DeveloperCa::root_ca_key_path().exists());

        // Test leaf certificate issuance
        let domains = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "app.local".to_string(),
        ];
        let cert_res = DeveloperCa::issue_certificate(&domains, 30);
        assert!(
            cert_res.is_ok(),
            "issue_certificate failed: {:?}",
            cert_res.err()
        );
        let meta = cert_res.unwrap();
        assert_eq!(meta.primary_domain, "localhost");
        assert_eq!(meta.alt_names.len(), 3);
        assert!(std::path::Path::new(&meta.cert_path).exists());
        assert!(std::path::Path::new(&meta.key_path).exists());

        // Verify index tracking
        let list = DeveloperCa::list_certificates();
        assert!(list.iter().any(|c| c.primary_domain == "localhost"));

        // Verify find_dev_certificate
        let found = DeveloperCa::find_dev_certificate("app.local");
        assert!(found.is_some());
    }
}
