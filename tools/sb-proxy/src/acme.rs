#[cfg(test)]
use chrono::Duration as ChronoDuration;
use chrono::{DateTime, Utc};
use crate::escape::EscapeSpaceStore;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// In-Memory ACME Challenge Store for zero-disk, zero-leak HTTP-01 validations.
#[derive(Clone, Default)]
pub struct AcmeChallengeStore {
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl AcmeChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a token and its key authorization for HTTP-01 challenge.
    pub fn register(&self, token: &str, key_auth: &str) {
        if let Ok(mut map) = self.challenges.write() {
            map.insert(token.to_string(), key_auth.to_string());
        }
    }

    /// Retrieves the key authorization for a given challenge token.
    pub fn get(&self, token: &str) -> Option<String> {
        if let Ok(map) = self.challenges.read() {
            map.get(token).cloned()
        } else {
            None
        }
    }

    /// Removes a token once validated.
    pub fn remove(&self, token: &str) -> Option<String> {
        if let Ok(mut map) = self.challenges.write() {
            map.remove(token)
        } else {
            None
        }
    }
}

/// Preflight DNS check to protect against Let's Encrypt rate-limit bans.
/// Let's Encrypt limits failed validations to 5 per hour per account/domain.
pub fn preflight_dns_check(domain: &str, expected_ip: &str) -> Result<(), String> {
    let clean_domain = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let query = format!("{}:80", clean_domain);

    match query.to_socket_addrs() {
        Ok(addrs) => {
            let matches = addrs
                .into_iter()
                .any(|addr| addr.ip().to_string() == expected_ip);
            if matches {
                Ok(())
            } else {
                Err(format!(
                    "DNS Preflight fehlgeschlagen: '{}' zeigt noch nicht auf die Server-IP '{}'",
                    domain, expected_ip
                ))
            }
        }
        Err(e) => Err(format!(
            "DNS-Auflösung für '{}' fehlgeschlagen: {}",
            domain, e
        )),
    }
}

/// Validates PEM formatted certificate bytes.
pub fn validate_pem_certificate(cert_bytes: &[u8]) -> Result<(), String> {
    let content = String::from_utf8_lossy(cert_bytes);
    if content.contains("-----BEGIN CERTIFICATE-----")
        && content.contains("-----END CERTIFICATE-----")
    {
        Ok(())
    } else {
        Err(
            "Ungültiges Zertifikatsformat: PEM-Header '-----BEGIN CERTIFICATE-----' fehlt"
                .to_string(),
        )
    }
}

/// Validates PEM formatted private key bytes (PKCS#8 or RSA/EC).
pub fn validate_pem_private_key(key_bytes: &[u8]) -> Result<(), String> {
    let content = String::from_utf8_lossy(key_bytes);
    if (content.contains("-----BEGIN PRIVATE KEY-----")
        && content.contains("-----END PRIVATE KEY-----"))
        || (content.contains("-----BEGIN RSA PRIVATE KEY-----")
            && content.contains("-----END RSA PRIVATE KEY-----"))
        || (content.contains("-----BEGIN EC PRIVATE KEY-----")
            && content.contains("-----END EC PRIVATE KEY-----"))
    {
        Ok(())
    } else {
        Err(
            "Ungültiges Schlüsselformat: PEM-Header '-----BEGIN PRIVATE KEY-----' fehlt"
                .to_string(),
        )
    }
}

/// Metadata about a domain's TLS Certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateMetadata {
    pub domain: String,
    pub issuer: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub custom_cert_path: Option<String>,
    pub custom_key_path: Option<String>,
    pub is_custom: bool,
}

impl CertificateMetadata {
    /// Days remaining until expiration.
    pub fn days_remaining(&self) -> Option<i64> {
        self.expires_at.map(|exp| (exp - Utc::now()).num_days())
    }

    /// Whether this certificate requires automated ACME renewal.
    pub fn needs_renewal(&self, threshold_days: i64) -> bool {
        if self.is_custom {
            return false;
        }
        match self.days_remaining() {
            Some(days) => days <= threshold_days,
            None => true,
        }
    }
}

/// Imports and verifies custom PEM certificate files from disk.
pub fn import_custom_certificate(
    domain: &str,
    cert_path_str: &str,
    key_path_str: &str,
) -> Result<(), String> {
    let cert_path = Path::new(cert_path_str);
    let key_path = Path::new(key_path_str);

    if !cert_path.exists() {
        return Err(format!(
            "Zertifikatsdatei nicht gefunden: {}",
            cert_path_str
        ));
    }
    if !key_path.exists() {
        return Err(format!("Schlüsseldatei nicht gefunden: {}", key_path_str));
    }

    let cert_bytes = std::fs::read(cert_path)
        .map_err(|e| format!("Fehler beim Lesen des Zertifikats: {}", e))?;
    let key_bytes =
        std::fs::read(key_path).map_err(|e| format!("Fehler beim Lesen des Schlüssels: {}", e))?;

    validate_pem_certificate(&cert_bytes)?;
    validate_pem_private_key(&key_bytes)?;

    let mut store = EscapeSpaceStore::load();
    store.set_custom_cert(domain, cert_path_str, key_path_str)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_store_roundtrip() {
        let store = AcmeChallengeStore::new();
        assert_eq!(store.get("token123"), None);

        store.register("token123", "token123.authkey987");
        assert_eq!(
            store.get("token123"),
            Some("token123.authkey987".to_string())
        );

        assert_eq!(
            store.remove("token123"),
            Some("token123.authkey987".to_string())
        );
        assert_eq!(store.get("token123"), None);
    }

    #[test]
    fn test_pem_validation() {
        let valid_cert = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----";
        let invalid_cert = b"THIS IS NOT A VALID CERT";
        assert!(validate_pem_certificate(valid_cert).is_ok());
        assert!(validate_pem_certificate(invalid_cert).is_err());

        let valid_key = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----";
        let invalid_key = b"RANDOM DATA";
        assert!(validate_pem_private_key(valid_key).is_ok());
        assert!(validate_pem_private_key(invalid_key).is_err());
    }

    #[test]
    fn test_certificate_metadata_renewal_calculation() {
        let now = Utc::now();

        // Expiring in 10 days -> needs renewal with 30-day threshold
        let soon_expiring = CertificateMetadata {
            domain: "app.example.com".to_string(),
            issuer: "Let's Encrypt".to_string(),
            expires_at: Some(now + ChronoDuration::days(10)),
            custom_cert_path: None,
            custom_key_path: None,
            is_custom: false,
        };
        assert!(soon_expiring.needs_renewal(30));

        // Expiring in 60 days -> does not need renewal
        let fresh_cert = CertificateMetadata {
            domain: "fresh.example.com".to_string(),
            issuer: "Let's Encrypt".to_string(),
            expires_at: Some(now + ChronoDuration::days(60)),
            custom_cert_path: None,
            custom_key_path: None,
            is_custom: false,
        };
        assert!(!fresh_cert.needs_renewal(30));

        // Custom cert expiring in 5 days -> NOT renewed automatically via ACME
        let custom_cert = CertificateMetadata {
            domain: "custom.example.com".to_string(),
            issuer: "Custom Corporate CA".to_string(),
            expires_at: Some(now + ChronoDuration::days(5)),
            custom_cert_path: Some("/etc/ssl/cert.pem".to_string()),
            custom_key_path: Some("/etc/ssl/key.pem".to_string()),
            is_custom: true,
        };
        assert!(!custom_cert.needs_renewal(30));
    }
}
