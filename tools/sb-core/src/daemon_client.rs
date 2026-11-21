use crate::daemon_auth::read_default_token;
use crate::ports::DEFAULT_DAEMON_API_PORT;
use crate::rpc::{
    RpcRequest, RpcResponse, MAX_RPC_HTTP_HEADER_BYTES, MAX_RPC_HTTP_RESPONSE_BYTES,
    MAX_RPC_REQUEST_BYTES, MAX_RPC_RESPONSE_BYTES, RPC_API_VERSION,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DaemonClient {
    endpoint: SocketAddr,
    token: Zeroizing<String>,
    next_id: AtomicU64,
}

impl DaemonClient {
    pub fn connect_default() -> Result<Self, String> {
        let token = read_default_token()?;
        Ok(Self::with_token(
            SocketAddr::from(([127, 0, 0, 1], DEFAULT_DAEMON_API_PORT)),
            token.to_string(),
        ))
    }

    pub fn try_connect_default() -> Result<Option<Self>, String> {
        let token_path = crate::paths::sb_run_dir().join("daemon.token");
        match token_path.try_exists() {
            Ok(false) => return Ok(None),
            Ok(true) => {}
            Err(error) => {
                return Err(format!(
                    "Daemon-Token-Datei konnte nicht geprüft werden: {error}"
                ))
            }
        }
        let token = read_default_token()?;
        let endpoint = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DAEMON_API_PORT));
        if TcpStream::connect_timeout(&endpoint, CONNECT_TIMEOUT).is_err() {
            return Ok(None);
        }
        Ok(Some(Self::with_token(endpoint, token.to_string())))
    }

    pub fn with_token(endpoint: SocketAddr, token: String) -> Self {
        Self {
            endpoint,
            token: Zeroizing::new(token),
            next_id: AtomicU64::new(1),
        }
    }

    // CVE-Threat: Secret leakage through serialized IPC buffers or token-bearing headers.
    // Analysis: RPC calls can carry the vault password and decrypted Secret payloads.
    // Hardening: Request JSON, HTTP headers and response bytes are bounded and zeroized.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let mut params = params;
        let id = match self
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            }) {
            Ok(id) => id,
            Err(_) => {
                zeroize_json(&mut params);
                return Err("RPC request ID space exhausted".to_string());
            }
        };
        let mut request = RpcRequest::new(id, method, params);
        let serialized = serde_json::to_vec(&request)
            .map_err(|error| format!("RPC request serialization failed: {error}"));
        zeroize_json(&mut request.params);
        let mut body = serialized?;
        if body.len() > MAX_RPC_REQUEST_BYTES {
            body.zeroize();
            return Err("RPC request exceeds the local size limit".to_string());
        }

        let mut headers = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.token.as_str(),
            body.len()
        );
        let result = self.exchange(&headers, &mut body, id);
        headers.zeroize();
        body.zeroize();
        result
    }

    // CVE-Threat: Malformed or oversized local HTTP responses could exhaust memory or confuse RPC parsing.
    // Analysis: The loopback peer is not inherently trusted merely because it is local.
    // Hardening: Apply socket timeouts and a strict response-size limit before parsing.
    fn exchange(&self, headers: &str, body: &mut [u8], expected_id: u64) -> Result<Value, String> {
        let mut stream = TcpStream::connect_timeout(&self.endpoint, CONNECT_TIMEOUT)
            .map_err(|error| format!("Suite-Daemon nicht erreichbar: {error}"))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|error| {
                format!("Daemon socket timeout konnte nicht gesetzt werden: {error}")
            })?;

        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.shutdown(Shutdown::Write))
            .map_err(|error| format!("RPC request konnte nicht gesendet werden: {error}"))?;

        let mut response = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let read = match stream.read(&mut chunk) {
                Ok(read) => read,
                Err(error) => {
                    response.zeroize();
                    chunk.zeroize();
                    return Err(format!("RPC response konnte nicht gelesen werden: {error}"));
                }
            };
            if read == 0 {
                break;
            }
            if response.len().saturating_add(read) > MAX_RPC_HTTP_RESPONSE_BYTES {
                response.zeroize();
                chunk.zeroize();
                return Err("RPC response exceeds the local size limit".to_string());
            }
            response.extend_from_slice(&chunk[..read]);
            chunk[..read].zeroize();
        }
        chunk.zeroize();

        let result = parse_response(&response, expected_id);
        response.zeroize();
        result
    }
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => values.values_mut().for_each(zeroize_json),
        _ => {}
    }
}

// CVE-Threat: Content-Length or JSON-RPC response confusion could bind a response to the wrong call.
// Analysis: Response bytes come from a local TCP peer and may be truncated or malformed.
// Hardening: Enforce exact body length, HTTP success, JSON-RPC version and matching request ID.
fn parse_response(response: &[u8], expected_id: u64) -> Result<Value, String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response from daemon".to_string())?;
    if header_end + 4 > MAX_RPC_HTTP_HEADER_BYTES {
        return Err("Daemon response headers exceed the local size limit".to_string());
    }
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("Invalid HTTP headers from daemon: {error}"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| "Invalid HTTP status from daemon".to_string())?;
    if status != 200 {
        return Err(format!("Daemon returned HTTP status {status}"));
    }
    let mut content_length = None;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("Daemon response uses unsupported Transfer-Encoding".to_string());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("Daemon response has duplicate Content-Length headers".to_string());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|error| format!("Invalid daemon Content-Length: {error}"))?,
            );
        }
    }
    let content_length =
        content_length.ok_or_else(|| "Daemon response is missing Content-Length".to_string())?;
    if content_length > MAX_RPC_RESPONSE_BYTES {
        return Err("Daemon response body exceeds the local size limit".to_string());
    }
    let body_start = header_end + 4;
    let body_end = body_start
        .checked_add(content_length)
        .filter(|&end| end == response.len())
        .ok_or_else(|| "Daemon response Content-Length does not match its body".to_string())?;

    let rpc: RpcResponse = serde_json::from_slice(&response[body_start..body_end])
        .map_err(|error| format!("Invalid JSON-RPC response from daemon: {error}"))?;
    if rpc.jsonrpc != "2.0" || rpc.api_version != RPC_API_VERSION {
        return Err(format!(
            "Daemon API version mismatch: client supports {}, daemon replied with {}",
            RPC_API_VERSION, rpc.api_version
        ));
    }
    if rpc.id != serde_json::json!(expected_id) {
        return Err("Daemon response does not match the requested JSON-RPC call".to_string());
    }
    if let Some(error) = rpc.error {
        return Err(format!(
            "Daemon RPC error {}: {}",
            error.code, error.message
        ));
    }
    rpc.result
        .ok_or_else(|| "Daemon RPC response has no result".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn rpc_client_sends_authenticated_request_and_reads_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            let request_text = String::from_utf8_lossy(&request);
            assert!(request_text.contains("Authorization: Bearer test-token"));
            assert!(request_text.contains("\"method\":\"suite.status\""));
            request.zeroize();

            let body = serde_json::to_vec(&RpcResponse::success(
                json!(1),
                json!({"status": "healthy"}),
            ))
            .unwrap();
            let response_header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response_header.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        });
        let client = DaemonClient::with_token(endpoint, "test-token".to_string());

        let result = client.call("suite.status", json!({})).unwrap();
        assert_eq!(result["status"], "healthy");
        server.join().unwrap();
    }

    #[test]
    fn response_parser_rejects_inconsistent_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert!(parse_response(response, 1).is_err());
    }

    #[test]
    fn response_parser_rejects_duplicate_lengths_and_version_mismatch() {
        let duplicate = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        assert!(parse_response(duplicate, 1)
            .unwrap_err()
            .contains("duplicate Content-Length"));

        let mut response = RpcResponse::success(1.into(), json!({}));
        response.api_version = RPC_API_VERSION + 1;
        let body = serde_json::to_vec(&response).unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8(body).unwrap()
        );
        assert!(parse_response(response.as_bytes(), 1)
            .unwrap_err()
            .contains("API version mismatch"));
    }
}
