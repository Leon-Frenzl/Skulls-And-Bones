//! Unified Open Graph API Gateway (`/v1/*`) & Web Console host for `sb-proxy`.
//!
//! Aggregates `sb-node` (Domain, Machines, GPOs), `sb-dns`, `sb-ca`, `sb-auth`, and `sb-proxy`
//! behind a single, developer-friendly REST + OpenAPI 3.1 interface.

use crate::config::ProxyConfig;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sb_auth::AuthVerifier;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Maximum request body size accepted by the Graph API Gateway (128 KiB).
pub const MAX_GRAPH_BODY_BYTES: usize = 128 * 1024;

/// Configuration for the Open Graph API Gateway.
#[derive(Debug, Clone)]
pub struct GraphGatewayConfig {
    pub bind: SocketAddr,
    pub dc_addr: SocketAddr,
    pub console_dist_dir: Option<PathBuf>,
}

impl Default for GraphGatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8090".parse().expect("valid default bind"),
            dc_addr: "127.0.0.1:8443".parse().expect("valid default dc"),
            console_dist_dir: Some(PathBuf::from("console/dist")),
        }
    }
}

/// Starts the Open Graph API Gateway on `config.bind`.
pub async fn serve_graph_gateway(
    config: GraphGatewayConfig,
    verifier: Option<Arc<AuthVerifier>>,
) -> Result<(), String> {
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|e| format!("Failed to bind Graph API Gateway on {}: {e}", config.bind))?;
    serve_graph_gateway_on_listener(listener, Arc::new(config), verifier).await
}

/// Serves the Open Graph API Gateway on an already-bound `TcpListener` (useful for tests).
pub async fn serve_graph_gateway_on_listener(
    listener: TcpListener,
    config: Arc<GraphGatewayConfig>,
    verifier: Option<Arc<AuthVerifier>>,
) -> Result<(), String> {
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|e| format!("Graph Gateway accept failed: {e}"))?;
        let io = TokioIo::new(stream);
        let cfg = config.clone();
        let ver = verifier.clone();
        tokio::spawn(async move {
            let service =
                service_fn(move |req| handle_graph_request(req, cfg.clone(), ver.clone()));
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });
    }
}

/// Routes `/v1/*` Open Graph API calls and serves the `console/dist` Web UI.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Path traversal on static console assets, oversized request bodies
///   (DoS), and unauthorized enrollment/mutation requests.
/// - **CVE / CWE Mapping:** CWE-22 (Path Traversal), CWE-400 (Resource Exhaustion),
///   CWE-306 (Missing Authentication for Critical Function).
/// - **Likelihood & Exploitability:** Medium-High (7/10) on network-exposed gateway ports.
/// - **Applied Mitigation:** Canonicalizes static file paths against `console_dist_dir`, enforces
///   `MAX_GRAPH_BODY_BYTES`, requires `sb-auth` Bearer tokens on enrollment/mutation routes, and
///   sets `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY`.
///
/// # Standards Compliance
/// - Conforms to RFC 9110 (HTTP Semantics) and OpenAPI Specification 3.1.0.
async fn handle_graph_request(
    req: Request<Incoming>,
    config: Arc<GraphGatewayConfig>,
    verifier: Option<Arc<AuthVerifier>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri_path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if method == Method::OPTIONS {
        return Ok(json_response(StatusCode::NO_CONTENT, ""));
    }

    // 1. Unified Health & OpenAPI 3.1 Discovery
    if method == Method::GET && uri_path == "/enroll" {
        return Ok(html_response(StatusCode::OK, PUBLIC_ENROLL_HTML));
    }

    if method == Method::GET && uri_path == "/v1/health" {
        let body = serde_json::json!({
            "status": "ok",
            "service": "sb-graph-gateway",
            "api_version": "v1",
            "dc_upstream": config.dc_addr.to_string(),
        })
        .to_string();
        return Ok(json_response(StatusCode::OK, &body));
    }

    if method == Method::GET && uri_path == "/v1/openapi.json" {
        let spec = build_openapi_spec();
        return Ok(json_response(StatusCode::OK, &spec.to_string()));
    }

    // 2. Local Read-Only Aggregations (DNS, CA, Proxy Routes)
    if method == Method::GET && uri_path == "/v1/dns/records" {
        let body = read_dns_records_json().to_string();
        return Ok(json_response(StatusCode::OK, &body));
    }

    if method == Method::GET && uri_path == "/v1/ca/status" {
        let body = read_ca_status_json().to_string();
        return Ok(json_response(StatusCode::OK, &body));
    }

    if method == Method::GET && uri_path == "/v1/proxy/routes" {
        let routes = ProxyConfig::load_spaces();
        let body = serde_json::json!({ "routes": routes }).to_string();
        return Ok(json_response(StatusCode::OK, &body));
    }

    if method == Method::GET && uri_path == "/v1/ipam/subnets" {
        let body = read_ipam_json().to_string();
        return Ok(json_response(StatusCode::OK, &body));
    }

    // 3. Mobile / Remote Enrollment Ticket Helper (Protected by sb-auth)
    if method == Method::POST && uri_path == "/v1/enrollments" {
        let Some(ref ver) = verifier else {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"sb-auth verifier not configured"}"#,
            ));
        };
        let Some(token) = auth_header
            .as_deref()
            .and_then(|h| {
                h.strip_prefix("Bearer ")
                    .or_else(|| h.strip_prefix("bearer "))
            })
            .map(str::trim)
        else {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"missing bearer token"}"#,
            ));
        };
        let claims = match ver.verify_token(token) {
            Ok(c) => c,
            Err(e) => {
                let msg = serde_json::json!({ "error": format!("authentication failed: {e}") })
                    .to_string();
                return Ok(json_response(StatusCode::UNAUTHORIZED, &msg));
            }
        };
        if !claims
            .capabilities
            .iter()
            .any(|c| c == "domain:join" || c == "domain:admin")
        {
            return Ok(json_response(
                StatusCode::FORBIDDEN,
                r#"{"error":"token lacks domain:join or domain:admin capability"}"#,
            ));
        }

        let body_bytes = match collect_bounded_body(req.into_body()).await {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };
        let payload: serde_json::Value =
            serde_json::from_slice(&body_bytes).unwrap_or_else(|_| serde_json::json!({}));
        let domain = payload["domain"].as_str().unwrap_or("corp.eu");
        let command = format!(
            "sb-node domain join {domain} --dc {} --token <YOUR_TOKEN>",
            config.dc_addr
        );
        let enrollment_package = sb_core::domain::EnrollmentPackage {
            version: 1,
            domain: domain.to_string(),
            dc_addr: config.dc_addr.to_string(),
            issued_for: claims.subject.clone(),
            join_token: token.to_string(),
            issued_at: chrono::Utc::now().to_rfc3339(),
        };
        let resp = serde_json::json!({
            "domain": domain,
            "dc": config.dc_addr.to_string(),
            "issued_for": claims.subject,
            "cli_command": command,
            "api_endpoint": "/v1/machines/join",
            "enrollment_package": enrollment_package,
        })
        .to_string();
        return Ok(json_response(StatusCode::OK, &resp));
    }

    // 4. Upstream DC Forwarding (/v1/me*, /v1/vault*, /v1/apps*, /v1/rbac*, /v1/machines*, /v1/policies*, /v1/users*, /v1/groups*, /v1/audit*)
    if uri_path.starts_with("/v1/me")
        || uri_path.starts_with("/v1/vault")
        || uri_path.starts_with("/v1/apps")
        || uri_path.starts_with("/v1/rbac")
        || uri_path.starts_with("/v1/machines")
        || uri_path.starts_with("/v1/policies")
        || uri_path.starts_with("/v1/users")
        || uri_path.starts_with("/v1/groups")
        || uri_path.starts_with("/v1/audit")
    {
        let body_bytes = match collect_bounded_body(req.into_body()).await {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };
        let target_path = match &query {
            Some(q) if !q.is_empty() => format!("{uri_path}?{q}"),
            _ => uri_path,
        };
        return match forward_to_dc(
            config.dc_addr,
            method.as_str(),
            &target_path,
            auth_header.as_deref(),
            &body_bytes,
        )
        .await
        {
            Ok((status, resp_body)) => Ok(json_response(status, &resp_body)),
            Err(err) => {
                let msg = serde_json::json!({ "error": err }).to_string();
                Ok(json_response(StatusCode::BAD_GATEWAY, &msg))
            }
        };
    }

    // 5. Static Web Management Console (`console/dist`)
    if method == Method::GET {
        if let Some(ref dist_dir) = config.console_dist_dir {
            if let Some(resp) = try_serve_console_asset(dist_dir, &uri_path) {
                return Ok(resp);
            }
        }
    }

    Ok(json_response(
        StatusCode::NOT_FOUND,
        r#"{"error":"endpoint not found"}"#,
    ))
}

async fn collect_bounded_body(body: Incoming) -> Result<Vec<u8>, Response<Full<Bytes>>> {
    let collected = body.collect().await.map_err(|_| {
        json_response(
            StatusCode::BAD_REQUEST,
            r#"{"error":"failed to read request body"}"#,
        )
    })?;
    let bytes = collected.to_bytes();
    if bytes.len() > MAX_GRAPH_BODY_BYTES {
        return Err(json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            r#"{"error":"request body exceeds 128 KiB limit"}"#,
        ));
    }
    Ok(bytes.to_vec())
}

async fn forward_to_dc(
    dc_addr: SocketAddr,
    method: &str,
    path_and_query: &str,
    auth_header: Option<&str>,
    body: &[u8],
) -> Result<(StatusCode, String), String> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(dc_addr),
    )
    .await
    .map_err(|_| format!("Timed out connecting to DC {dc_addr}"))?
    .map_err(|e| format!("DC {dc_addr} unreachable: {e}"))?;

    let mut req_head =
        format!("{method} {path_and_query} HTTP/1.1\r\nHost: {dc_addr}\r\nConnection: close\r\n");
    if let Some(auth) = auth_header {
        req_head.push_str(&format!("Authorization: {auth}\r\n"));
    }
    if !body.is_empty() {
        req_head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    req_head.push_str("\r\n");

    stream
        .write_all(req_head.as_bytes())
        .await
        .map_err(|e| format!("Failed writing to DC: {e}"))?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .map_err(|e| format!("Failed writing body to DC: {e}"))?;
    }

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("Failed reading DC response: {e}"))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > 512 * 1024 {
            return Err("DC response exceeded 512 KiB".into());
        }
    }

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response from DC".to_string())?;
    let head = std::str::from_utf8(&raw[..header_end]).unwrap_or("");
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_body = String::from_utf8_lossy(&raw[header_end + 4..]).to_string();
    Ok((code, resp_body))
}

fn try_serve_console_asset(dist_dir: &Path, uri_path: &str) -> Option<Response<Full<Bytes>>> {
    let canonical_root = std::fs::canonicalize(dist_dir).ok()?;
    let rel = if uri_path == "/" {
        "index.html"
    } else {
        uri_path.trim_start_matches('/')
    };
    if rel.contains("..") || rel.contains('\\') {
        return None;
    }
    let candidate = canonical_root.join(rel);
    let target = if candidate.is_file() {
        candidate
    } else {
        canonical_root.join("index.html")
    };
    let canonical_target = std::fs::canonicalize(&target).ok()?;
    if !canonical_target.starts_with(&canonical_root) {
        return None;
    }
    let bytes = std::fs::read(&canonical_target).ok()?;
    let mime = mime_guess::from_path(&canonical_target)
        .first_or_octet_stream()
        .to_string();
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime)
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .body(Full::new(Bytes::from(bytes)))
            .unwrap(),
    )
}

fn read_dns_records_json() -> serde_json::Value {
    let path = sb_core::paths::sb_home().join("dns").join("records.json");
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            return val;
        }
    }
    serde_json::json!({ "a": {}, "aaaa": {}, "cname": {}, "txt": {}, "srv": {} })
}

fn read_ipam_json() -> serde_json::Value {
    let path = sb_core::paths::sb_home().join("dns").join("ipam.json");
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            return val;
        }
    }
    serde_json::json!({ "subnets": {}, "leases": [] })
}

fn read_ca_status_json() -> serde_json::Value {
    let root_crt = sb_ca::paths::x509_root_crt_path();
    let ssh_ca_pub = sb_ca::paths::ssh_ca_pub_path();
    serde_json::json!({
        "x509_root_initialized": root_crt.exists(),
        "x509_root_path": root_crt.display().to_string(),
        "ssh_ca_initialized": ssh_ca_pub.exists(),
        "ssh_ca_pubkey": std::fs::read_to_string(&ssh_ca_pub).ok().map(|s| s.trim().to_string()),
    })
}

/// Builds the live OpenAPI 3.1.0 JSON specification for the Skulls & Bones Open Graph API.
pub fn build_openapi_spec() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Skulls & Bones Open Graph API",
            "version": "1.0.0",
            "description": "Developer-friendly, sovereign domain, DNS, CA, GPO & mesh management API."
        },
        "paths": {
            "/v1/health": { "get": { "summary": "Gateway & DC upstream health" } },
            "/v1/openapi.json": { "get": { "summary": "OpenAPI 3.1.0 specification" } },
            "/v1/me": { "get": { "summary": "Self-service profile and joined machines" } },
            "/v1/me/ssh-key": { "put": { "summary": "Register or update own OpenSSH public key" } },
            "/v1/me/ssh-cert": { "post": { "summary": "Issue own short-lived OpenSSH user certificate" } },
            "/v1/me/elevate": { "post": { "summary": "Request bounded-TTL JIT privilege elevation (RBAC-enforced)" } },
            "/v1/me/elevations": { "get": { "summary": "List active JIT elevations for current user" } },
            "/v1/rbac/rules": { "get": { "summary": "List JIT elevation eligibility rules (admin)" } },
            "/v1/rbac/rules/{id}": { "put": { "summary": "Create or update JIT elevation rule (admin)" } },
            "/v1/apps": { "get": { "summary": "List company apps visible to current user" } },
            "/v1/apps/{id}": {
                "put": { "summary": "Create or update a company app (admin)" },
                "delete": { "summary": "Delete a company app (admin)" }
            },
            "/v1/me/vault": { "get": { "summary": "List personal encrypted vault entries" } },
            "/v1/me/vault/{key}": {
                "put": { "summary": "Store encrypted personal secret" },
                "delete": { "summary": "Delete personal secret" }
            },
            "/v1/me/vault/{key}/reveal": { "post": { "summary": "Decrypt personal secret" } },
            "/v1/vault/team": { "get": { "summary": "List group-scoped team vault entries" } },
            "/v1/vault/team/{group}/{key}": { "put": { "summary": "Store encrypted team secret (RBAC + audit)" } },
            "/v1/vault/team/{group}/{key}/reveal": { "post": { "summary": "Decrypt team secret (RBAC + audit)" } },
            "/v1/machines": { "get": { "summary": "List domain-joined machines" } },
            "/v1/machines/join": { "post": { "summary": "Join a machine to the domain" } },
            "/v1/users": { "get": { "summary": "List domain users" } },
            "/v1/users/{username}": {
                "put": { "summary": "Create or update a domain user" },
                "delete": { "summary": "Delete a domain user" }
            },
            "/v1/users/{username}/ssh-cert": { "post": { "summary": "Issue short-lived OpenSSH user certificate" } },
            "/v1/users/{username}/offboard": { "post": { "summary": "1-click offboard user and revoke machines" } },
            "/v1/groups": { "get": { "summary": "List domain groups and memberships" } },
            "/v1/audit/events": { "get": { "summary": "Read tamper-evident hash-chained audit log" } },
            "/v1/policies": { "get": { "summary": "List cross-platform GPO policies" } },
            "/v1/policies/{id}": {
                "get": { "summary": "Get a GPO policy by ID" },
                "put": { "summary": "Create or update a GPO policy (supports ?dry_run=true)" },
                "delete": { "summary": "Delete a GPO policy (supports ?dry_run=true)" }
            },
            "/v1/policies/bundle": { "get": { "summary": "Download Ed25519-signed GPO bundle" } },
            "/v1/dns/records": { "get": { "summary": "List sovereign DNS zone records" } },
            "/v1/ipam/subnets": { "get": { "summary": "List IPAM subnets and DHCP leases" } },
            "/v1/ca/status": { "get": { "summary": "Inspect X.509 and SSH CA status" } },
            "/v1/proxy/routes": { "get": { "summary": "List active reverse-proxy routes" } },
            "/v1/enrollments": { "post": { "summary": "Generate a remote/mobile join command" } }
        }
    })
}

fn html_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

const PUBLIC_ENROLL_HTML: &str = r#"<!doctype html>
<html lang="de"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Skulls &amp; Bones — Gerät verbinden</title>
<style>body{margin:0;font-family:system-ui,sans-serif;background:#0b1113;color:#e6f1f0;display:grid;place-items:center;min-height:100vh}
.card{background:#121b1e;border:1px solid #24353a;border-radius:12px;padding:24px;max-width:460px;width:92%}
input,button{width:100%;padding:10px 12px;border-radius:8px;margin-top:10px;font-size:14px;box-sizing:border-box}
input{background:#0b1113;border:1px solid #24353a;color:#e6f1f0}
button{background:#52c7bd;color:#062120;border:0;font-weight:700;cursor:pointer}
pre{background:#080d0e;padding:10px;border-radius:8px;overflow:auto;font-size:12px;display:none}</style></head>
<body><div class="card"><h2 style="margin-top:0">Gerät mit Domäne verbinden</h2>
<p style="color:#8ea6aa;font-size:13px">Öffentliches Enrollment-Portal (keine internen Daten sichtbar). Gib dein Einmal-Token ein, um die <code>.sb-enroll</code> Datei herunterzuladen.</p>
<input id="dom" value="corp.eu" placeholder="Domäne (z. B. corp.eu)"/>
<input id="tok" type="password" placeholder="Enrollment-Token (sbt....)"/>
<button onclick="enroll()">.sb-enroll Paket erzeugen &amp; laden</button>
<pre id="out"></pre></div>
<script>async function enroll(){const d=document.getElementById('dom').value.trim(),t=document.getElementById('tok').value.trim(),o=document.getElementById('out');
const r=await fetch('/v1/enrollments',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({domain:d})});
const j=await r.json();o.style.display='block';o.textContent=JSON.stringify(j,null,2);
if(r.ok&&j.enrollment_package){const b=new Blob([JSON.stringify(j.enrollment_package,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=d+'.sb-enroll';a.click();}}</script>
</body></html>"#;

fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type",
        )
        .header(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        )
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn graph_gateway_serves_health_openapi_and_blocks_path_traversal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = Arc::new(GraphGatewayConfig {
            bind: addr,
            dc_addr: "127.0.0.1:1".parse().unwrap(),
            console_dist_dir: None,
        });
        tokio::spawn(async move {
            let _ = serve_graph_gateway_on_listener(listener, cfg, None).await;
        });

        // GET /v1/openapi.json
        let (status, body) = forward_to_dc(addr, "GET", "/v1/openapi.json", None, &[])
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        let spec: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["paths"]["/v1/policies/{id}"].is_object());

        // GET /v1/health
        let (status, body) = forward_to_dc(addr, "GET", "/v1/health", None, &[])
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("sb-graph-gateway"));

        // Path traversal check on static helper
        let temp = std::env::temp_dir();
        assert!(try_serve_console_asset(&temp, "/../../etc/passwd").is_none());
    }
}
