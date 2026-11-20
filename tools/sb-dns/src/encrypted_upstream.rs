//! Encrypted Upstream DNS Transports: DNS-over-TLS (RFC 7858) & DNS-over-HTTPS (RFC 8484).

use hickory_proto::op::Message;
use rustls_pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const ENCRYPTED_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ENCRYPTED_DNS_BYTES: usize = 4096;
const MAX_HTTP_RESPONSE_BYTES: usize = 32 * 1024;

fn shared_tls_connector() -> TlsConnector {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let cfg = CONFIG.get_or_init(|| {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    });
    TlsConnector::from(cfg.clone())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedDohUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Validates and parses an RFC 8484 `https://` DoH endpoint URL.
// [SECURITY-HYPOTHESIS] CWE-918 / CWE-93: Insecure `http://` scheme or CRLF header injection in DoH URL.
// [SECURITY-VERIFIED] Strictly requires `https://`, rejects whitespace/control chars, and parses host/port/path.
pub(crate) fn parse_doh_url(url: &str) -> Result<ParsedDohUrl, String> {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| format!("DoH URL must use https:// ('{trimmed}')"))?;
    if rest.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("DoH URL contains invalid whitespace or control characters".into());
    }
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/dns-query".to_string()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("Invalid DoH URL authority".into());
    }
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port_num) = p.parse::<u16>() {
            (h.to_string(), port_num)
        } else {
            (authority.to_string(), 443)
        }
    } else {
        (authority.to_string(), 443)
    };
    if host.is_empty() {
        return Err("DoH URL host cannot be empty".into());
    }
    Ok(ParsedDohUrl { host, port, path })
}

/// Forwards a DNS query over DNS-over-TLS (RFC 7858, port 853).
pub async fn forward_query_dot(
    addr: SocketAddr,
    server_name: &str,
    query: &Message,
) -> Result<Message, String> {
    let payload = query
        .to_vec()
        .map_err(|e| format!("Failed to encode DNS query: {e}"))?;
    if payload.len() > MAX_ENCRYPTED_DNS_BYTES {
        return Err("DNS query exceeds maximum size".into());
    }

    let sni = ServerName::try_from(server_name.to_string())
        .map_err(|_| format!("Invalid DoT server_name '{server_name}'"))?;

    let tcp = tokio::time::timeout(ENCRYPTED_UPSTREAM_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| "DoT TCP connect timed out".to_string())?
        .map_err(|e| format!("DoT TCP connect failed: {e}"))?;

    let mut tls = tokio::time::timeout(
        ENCRYPTED_UPSTREAM_TIMEOUT,
        shared_tls_connector().connect(sni, tcp),
    )
    .await
    .map_err(|_| "DoT TLS handshake timed out".to_string())?
    .map_err(|e| format!("DoT TLS handshake failed: {e}"))?;

    let len_prefix = (payload.len() as u16).to_be_bytes();
    tls.write_all(&len_prefix)
        .await
        .map_err(|e| format!("DoT write prefix failed: {e}"))?;
    tls.write_all(&payload)
        .await
        .map_err(|e| format!("DoT write payload failed: {e}"))?;
    tls.flush()
        .await
        .map_err(|e| format!("DoT flush failed: {e}"))?;

    let mut resp_prefix = [0u8; 2];
    tokio::time::timeout(ENCRYPTED_UPSTREAM_TIMEOUT, tls.read_exact(&mut resp_prefix))
        .await
        .map_err(|_| "DoT read prefix timed out".to_string())?
        .map_err(|e| format!("DoT read prefix failed: {e}"))?;
    let resp_len = u16::from_be_bytes(resp_prefix) as usize;
    if resp_len == 0 || resp_len > MAX_ENCRYPTED_DNS_BYTES {
        return Err(format!("DoT response length {resp_len} out of bounds"));
    }
    let mut resp_bytes = vec![0u8; resp_len];
    tokio::time::timeout(ENCRYPTED_UPSTREAM_TIMEOUT, tls.read_exact(&mut resp_bytes))
        .await
        .map_err(|_| "DoT read payload timed out".to_string())?
        .map_err(|e| format!("DoT read payload failed: {e}"))?;

    Message::from_vec(&resp_bytes).map_err(|e| format!("Invalid DoT DNS response: {e}"))
}

/// Forwards a DNS query over DNS-over-HTTPS (RFC 8484 `POST /dns-query`).
pub async fn forward_query_doh(url: &str, query: &Message) -> Result<Message, String> {
    let parsed = parse_doh_url(url)?;
    let payload = query
        .to_vec()
        .map_err(|e| format!("Failed to encode DNS query: {e}"))?;
    if payload.len() > MAX_ENCRYPTED_DNS_BYTES {
        return Err("DNS query exceeds maximum size".into());
    }

    let sni = ServerName::try_from(parsed.host.clone())
        .map_err(|_| format!("Invalid DoH server_name '{}'", parsed.host))?;

    let tcp = tokio::time::timeout(
        ENCRYPTED_UPSTREAM_TIMEOUT,
        TcpStream::connect((parsed.host.as_str(), parsed.port)),
    )
    .await
    .map_err(|_| "DoH TCP connect timed out".to_string())?
    .map_err(|e| format!("DoH TCP connect failed: {e}"))?;

    let mut tls = tokio::time::timeout(
        ENCRYPTED_UPSTREAM_TIMEOUT,
        shared_tls_connector().connect(sni, tcp),
    )
    .await
    .map_err(|_| "DoH TLS handshake timed out".to_string())?
    .map_err(|e| format!("DoH TLS handshake failed: {e}"))?;

    let req_head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        parsed.path,
        parsed.host,
        payload.len()
    );
    tls.write_all(req_head.as_bytes())
        .await
        .map_err(|e| format!("DoH write headers failed: {e}"))?;
    tls.write_all(&payload)
        .await
        .map_err(|e| format!("DoH write body failed: {e}"))?;
    tls.flush()
        .await
        .map_err(|e| format!("DoH flush failed: {e}"))?;

    let mut raw_resp = Vec::with_capacity(2048);
    let mut buf = [0u8; 2048];
    loop {
        let n = tokio::time::timeout(ENCRYPTED_UPSTREAM_TIMEOUT, tls.read(&mut buf))
            .await
            .map_err(|_| "DoH read timed out".to_string())?
            .map_err(|e| format!("DoH read failed: {e}"))?;
        if n == 0 {
            break;
        }
        if raw_resp.len() + n > MAX_HTTP_RESPONSE_BYTES {
            return Err("DoH HTTP response exceeded maximum size".into());
        }
        raw_resp.extend_from_slice(&buf[..n]);
    }

    let split_pos = raw_resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed DoH HTTP response".to_string())?;
    let head = std::str::from_utf8(&raw_resp[..split_pos])
        .map_err(|_| "Non-UTF8 DoH response headers".to_string())?;
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Err(format!("DoH upstream returned HTTP error: {status_line}"));
    }

    let body = &raw_resp[split_pos + 4..];
    let dns_bytes = if head
        .lines()
        .any(|l| l.to_ascii_lowercase().contains("transfer-encoding: chunked"))
    {
        decode_http_chunked(body)?
    } else {
        body.to_vec()
    };

    if dns_bytes.len() > MAX_ENCRYPTED_DNS_BYTES {
        return Err("DoH DNS payload exceeds maximum size".into());
    }
    Message::from_vec(&dns_bytes).map_err(|e| format!("Invalid DoH DNS response: {e}"))
}

fn decode_http_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(pos) = input.windows(2).position(|w| w == b"\r\n") {
        let size_str = std::str::from_utf8(&input[..pos])
            .map_err(|_| "Invalid chunk size".to_string())?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| format!("Invalid hex chunk size '{size_str}'"))?;
        input = &input[pos + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 || out.len() + size > MAX_ENCRYPTED_DNS_BYTES {
            return Err("Truncated or oversized chunked DoH response".into());
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_url_validation_accepts_https_and_rejects_insecure_or_crlf() {
        let parsed = parse_doh_url("https://cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(parsed.host, "cloudflare-dns.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/dns-query");

        assert!(parse_doh_url("http://1.1.1.1/dns-query").is_err());
        assert!(parse_doh_url("https://1.1.1.1/dns-query\r\nEvil: 1").is_err());
    }

    #[test]
    fn chunked_decoder_parses_rfc8484_body() {
        let chunked = b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n";
        assert_eq!(decode_http_chunked(chunked).unwrap(), b"abcdef");
    }
}
