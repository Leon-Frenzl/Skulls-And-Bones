use crate::escape::{validate_target_port, EscapeSpaceStore, EscapeStatus};
use crate::ipc::ProxyTelemetry;
use crate::ratelimit::IpRateLimiter;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{
    HeaderName, HeaderValue, ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HOST, LOCATION,
    RETRY_AFTER, WWW_AUTHENTICATE,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::io::ReaderStream;

type BoxError = Box<dyn Error + Send + Sync>;
type HttpBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Clone, Debug)]
pub struct SecurityHeaders {
    pub hsts: Option<HeaderValue>,
    pub content_security_policy: Option<HeaderValue>,
    pub x_content_type_options: Option<HeaderValue>,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            hsts: None,
            content_security_policy: None,
            x_content_type_options: Some(HeaderValue::from_static("nosniff")),
        }
    }
}

impl SecurityHeaders {
    pub fn from_env() -> Result<Self, BoxError> {
        fn configured_header(name: &str) -> Result<Option<HeaderValue>, BoxError> {
            let value = match std::env::var(name) {
                Ok(value) => value,
                Err(std::env::VarError::NotPresent) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if value.is_empty() {
                return Ok(None);
            }
            Ok(Some(HeaderValue::from_str(&value).map_err(|error| {
                format!("Ungültiger HTTP-Headerwert in {name}: {error}")
            })?))
        }

        let x_content_type_options = match std::env::var("SB_PROXY_X_CONTENT_TYPE_OPTIONS") {
            Ok(value) if value.is_empty() => None,
            Ok(value) => Some(HeaderValue::from_str(&value).map_err(|error| {
                format!("Ungültiger HTTP-Headerwert in SB_PROXY_X_CONTENT_TYPE_OPTIONS: {error}")
            })?),
            Err(std::env::VarError::NotPresent) => Some(HeaderValue::from_static("nosniff")),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            hsts: configured_header("SB_PROXY_HSTS")?,
            content_security_policy: configured_header("SB_PROXY_CSP")?,
            x_content_type_options,
        })
    }
}

#[derive(Clone)]
struct RequestState {
    client_addr: SocketAddr,
    is_tls: bool,
    rate_limiter: IpRateLimiter,
    telemetry: Arc<RwLock<ProxyTelemetry>>,
    routes: Arc<RwLock<EscapeSpaceStore>>,
    security_headers: SecurityHeaders,
    auth_verifier: Option<Arc<sb_auth::AuthVerifier>>,
}

pub async fn serve_connection<S>(
    stream: S,
    client_addr: SocketAddr,
    is_tls: bool,
    rate_limiter: IpRateLimiter,
    telemetry: Arc<RwLock<ProxyTelemetry>>,
    routes: Arc<RwLock<EscapeSpaceStore>>,
    security_headers: SecurityHeaders,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_connection_with_auth(
        stream,
        client_addr,
        is_tls,
        rate_limiter,
        telemetry,
        routes,
        security_headers,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_connection_with_auth<S>(
    stream: S,
    client_addr: SocketAddr,
    is_tls: bool,
    rate_limiter: IpRateLimiter,
    telemetry: Arc<RwLock<ProxyTelemetry>>,
    routes: Arc<RwLock<EscapeSpaceStore>>,
    security_headers: SecurityHeaders,
    auth_verifier: Option<Arc<sb_auth::AuthVerifier>>,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = RequestState {
        client_addr,
        is_tls,
        rate_limiter,
        telemetry,
        routes,
        security_headers,
        auth_verifier,
    };
    let service = service_fn(move |request| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle_request(request, state).await) }
    });

    // CVE-Threat: Slowloris-style header drips could retain connection tasks.
    // Analysis: Hyper owns parsing; the explicit header deadline bounds incomplete requests.
    // Hardening: Keep HTTP/1 persistent while limiting header-read time to ten seconds.
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(Some(std::time::Duration::from_secs(10)));
    builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

async fn handle_request(request: Request<Incoming>, state: RequestState) -> Response<HttpBody> {
    let started = Instant::now();
    if let Ok(mut telemetry) = state.telemetry.write() {
        telemetry.increment_requests();
    }

    let method = request.method().as_str().to_owned();
    let version = match request.version() {
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_11 => "HTTP/1.1",
        _ => "HTTP",
    };
    let host = request_host(&request);
    let safe_path = request.uri().path().to_owned();

    let mut response = route_request(request, &state, &host).await;
    let status = response.status().as_u16();
    add_security_headers(&mut response, &state.security_headers, state.is_tls);
    if let Ok(mut telemetry) = state.telemetry.write() {
        telemetry.record_status(status, started.elapsed().as_secs_f32() * 1000.0);
    }

    eprintln!(
        "{}",
        serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event": "http_access",
            "client_ip": state.client_addr.ip().to_string(),
            "method": method,
            "host": host,
            "path": safe_path,
            "protocol": version,
            "status": status,
            "latency_ms": started.elapsed().as_millis(),
        })
    );
    response
}

async fn route_request(
    request: Request<Incoming>,
    state: &RequestState,
    host: &str,
) -> Response<HttpBody> {
    // CVE-Threat: Host-based routing and static paths cross the untrusted HTTP boundary.
    // Analysis: Hosts are parsed by Hyper; static paths are decoded and canonicalized in resolve_file.
    // Hardening: Unknown hosts fail closed and static files remain constrained to their publish root.
    let space = {
        let store = match state.routes.read() {
            Ok(store) => store,
            Err(_) => {
                return plain_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Route state unavailable.\n",
                )
            }
        };
        store
            .spaces
            .iter()
            .find(|space| {
                space.domain.eq_ignore_ascii_case(host)
                    || space
                        .aliases
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(host))
                    || (host.is_empty() && space.target_port == 3000)
            })
            .cloned()
    };
    let Some(space) = space else {
        return plain_response(
            StatusCode::NOT_FOUND,
            "No active S&B route is configured for this host.\n",
        );
    };

    let retry_after = match state
        .rate_limiter
        .check_and_consume(state.client_addr.ip(), space.rate_limit_rpm)
    {
        Ok(()) => None,
        Err(seconds) => Some(seconds),
    };
    if let Some(seconds) = retry_after {
        if let Ok(mut telemetry) = state.telemetry.write() {
            telemetry.increment_rate_limited();
        }
        let mut response = plain_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Request rate limit exceeded.\n",
        );
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
        return response;
    }

    if space
        .aliases
        .iter()
        .any(|alias| alias.eq_ignore_ascii_case(host))
        && !space.domain.eq_ignore_ascii_case(host)
    {
        let location = format!(
            "{}://{}{}",
            if space.tls_enabled { "https" } else { "http" },
            space.domain,
            request.uri()
        );
        let mut response = empty_response(StatusCode::MOVED_PERMANENTLY);
        if let Ok(value) = HeaderValue::from_str(&location) {
            response.headers_mut().insert(LOCATION, value);
        }
        return response;
    }

    if space
        .expires_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|expires| chrono::Utc::now() > expires)
    {
        return plain_response(StatusCode::GONE, "This preview route has expired.\n");
    }
    match space.status {
        EscapeStatus::Maintenance => {
            let mut response = plain_response(
                StatusCode::SERVICE_UNAVAILABLE,
                space
                    .maintenance_msg
                    .as_deref()
                    .unwrap_or("Service maintenance is in progress.\n"),
            );
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("300"));
            return response;
        }
        EscapeStatus::Paused => {
            return plain_response(StatusCode::SERVICE_UNAVAILABLE, "This route is paused.\n");
        }
        _ => {}
    }

    let authenticated_claims = match authorize_route_request(&request, &space, &state) {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    if let Some(root) = &space.static_root {
        let spa_mode = std::env::var("SB_PROXY_SPA")
            .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        return serve_static(&request, Path::new(root), spa_mode, state.client_addr).await;
    }

    let hub = crate::tunnel::SovereignTunnelHub::global();
    let tunnel_route = space.is_tunnel || hub.is_tunnel_active(&space.domain).await;
    if !tunnel_route {
        if validate_target_port(space.target_port).is_err() {
            return plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Upstream port is not allowed.\n",
            );
        }
    }
    let upstream = if tunnel_route {
        match hub
            .open_stream(&space.domain, std::time::Duration::from_secs(5))
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                log_error("tunnel_unavailable", &error.to_string(), state.client_addr);
                return plain_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Sovereign tunnel is not connected.\n",
                );
            }
        }
    } else {
        match TcpStream::connect(("127.0.0.1", space.target_port)).await {
            Ok(stream) => stream,
            Err(error) => {
                log_error(
                    "upstream_unavailable",
                    &error.to_string(),
                    state.client_addr,
                );
                return plain_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream service is unavailable.\n",
                );
            }
        }
    };
    proxy_upstream(
        request,
        upstream,
        state.client_addr,
        state.is_tls,
        authenticated_claims.as_ref(),
    )
    .await
}

/// Enforces `sb-auth` Sovereign Token authentication and role/capability authorization
/// for protected routes before forwarding or serving static files.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unauthenticated or unauthorized HTTP clients accessing protected
///   mesh/edge routes, or forging `X-SB-Auth-*` identity headers.
/// - **CVE / CWE Mapping:** CWE-306 (Missing Authentication for Critical Function) / CWE-863.
/// - **Likelihood & Exploitability:** High (8/10) on edge-exposed proxy routes.
/// - **Applied Mitigation:** Fails closed (`503`) if no `AuthVerifier` is configured on a protected
///   route; verifies Ed25519 signature, expiration, and multi-tier revocation (`401`/`403`).
// Conforms to RFC 9110 §11.6.1 and RFC 6750 §3 (Bearer WWW-Authenticate).
#[allow(clippy::result_large_err)]
fn authorize_route_request(
    request: &Request<Incoming>,
    space: &crate::escape::EscapeSpace,
    state: &RequestState,
) -> Result<Option<sb_auth::claims::SovereignClaims>, Response<HttpBody>> {
    let requires_auth =
        space.auth_required || space.required_role.is_some() || space.required_capability.is_some();
    if !requires_auth {
        return Ok(None);
    }

    let Some(verifier) = &state.auth_verifier else {
        return Err(plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication is required for this route, but no verifier is configured.\n",
        ));
    };

    let Some(auth_header) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        let mut response = plain_response(StatusCode::UNAUTHORIZED, "Authentication required.\n");
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"sb-proxy\""),
        );
        return Err(response);
    };

    match sb_auth::middleware::authorize_header_with_verifier(
        verifier,
        auth_header,
        space.required_role.as_deref(),
        space.required_capability.as_deref(),
    ) {
        Ok(claims) => Ok(Some(claims)),
        Err(sb_auth::error::AuthError::MissingRole(_))
        | Err(sb_auth::error::AuthError::MissingCapability(_)) => Err(plain_response(
            StatusCode::FORBIDDEN,
            "Insufficient permissions for this route.\n",
        )),
        Err(_) => {
            let mut response = plain_response(
                StatusCode::UNAUTHORIZED,
                "Invalid, expired, or revoked token.\n",
            );
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"sb-proxy\", error=\"invalid_token\""),
            );
            Err(response)
        }
    }
}

async fn serve_static(
    request: &Request<Incoming>,
    root: &Path,
    spa_fallback: bool,
    client_addr: SocketAddr,
) -> Response<HttpBody> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let mut response = plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Only GET and HEAD are supported.\n",
        );
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let options = crate::static_files::StaticFileOptions { spa_fallback };
    let file_path = match crate::static_files::resolve_file_with_options(
        root,
        &request.uri().to_string(),
        options,
    ) {
        Ok(path) => path,
        Err(crate::static_files::ResolveError::BadRequest) => {
            return plain_response(StatusCode::BAD_REQUEST, "Invalid request path.\n");
        }
        Err(crate::static_files::ResolveError::NotFound) => {
            return plain_response(StatusCode::NOT_FOUND, "Not found.\n");
        }
        Err(crate::static_files::ResolveError::Forbidden) => {
            return plain_response(StatusCode::FORBIDDEN, "Forbidden.\n");
        }
    };
    let mut file = match tokio::fs::File::open(&file_path).await {
        Ok(file) => file,
        Err(error) => {
            log_error("static_file_open_failed", &error.to_string(), client_addr);
            return plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to read published file.\n",
            );
        }
    };
    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(error) => {
            log_error(
                "static_file_metadata_failed",
                &error.to_string(),
                client_addr,
            );
            return plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to read published file metadata.\n",
            );
        }
    };
    let size = metadata.len();
    let mtime_nanos = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let etag = format!("\"{:x}-{:x}\"", size, mtime_nanos);

    let cache_control = if matches!(
        file_path.file_name().and_then(|name| name.to_str()),
        Some("release-manifest.json" | "release-manifest.json.ed25519")
    ) {
        "no-cache"
    } else {
        "public, max-age=300"
    };

    // CVE-Threat: Unconditional re-downloads cause bandwidth exhaustion and latency spikes.
    // Analysis: ETag uniquely tracks file size and modification timestamp.
    // Hardening: Return 304 Not Modified when client provides matching If-None-Match.
    if let Some(if_none_match) = request.headers().get(hyper::header::IF_NONE_MATCH) {
        if if_none_match.as_bytes() == etag.as_bytes()
            || if_none_match.as_bytes() == b"*"
            || if_none_match
                .to_str()
                .ok()
                .map(|val| val.split(',').any(|part| part.trim() == etag))
                .unwrap_or(false)
        {
            let mut response = empty_response(StatusCode::NOT_MODIFIED);
            if let Ok(value) = HeaderValue::from_str(&etag) {
                response.headers_mut().insert(hyper::header::ETAG, value);
            }
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
            return response;
        }
    }

    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .essence_str()
        .to_owned();
    let content_type = if content_type.starts_with("text/") && content_type != "text/event-stream" {
        format!("{content_type}; charset=utf-8")
    } else {
        content_type
    };

    let is_compressible = content_type.starts_with("text/")
        || content_type.contains("javascript")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("svg+xml");

    let client_accepts_gzip = request
        .headers()
        .get(hyper::header::ACCEPT_ENCODING)
        .and_then(|val| val.to_str().ok())
        .map(|enc| enc.contains("gzip"))
        .unwrap_or(false);

    let compress_gzip = is_compressible && client_accepts_gzip && size > 256;

    let body = if request.method() == Method::HEAD {
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed_unsync()
    } else if compress_gzip {
        // Stream compressed file using flate2
        use std::io::Read;
        let mut uncompressed_bytes = Vec::with_capacity(size as usize);
        use tokio::io::AsyncReadExt;
        let _ = file.read_to_end(&mut uncompressed_bytes).await;

        let mut encoder =
            flate2::read::GzEncoder::new(&uncompressed_bytes[..], flate2::Compression::default());
        let mut compressed_bytes = Vec::new();
        if encoder.read_to_end(&mut compressed_bytes).is_ok()
            && compressed_bytes.len() < uncompressed_bytes.len()
        {
            Full::new(Bytes::from(compressed_bytes))
                .map_err(|never| match never {})
                .boxed_unsync()
        } else {
            Full::new(Bytes::from(uncompressed_bytes))
                .map_err(|never| match never {})
                .boxed_unsync()
        }
    } else {
        let stream = ReaderStream::new(file)
            .map_err(|error| Box::new(error) as BoxError)
            .map_ok(Frame::data);
        StreamBody::new(stream).boxed_unsync()
    };

    let mut response = Response::new(body);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(hyper::header::ETAG, value);
    }
    if compress_gzip {
        response.headers_mut().insert(
            hyper::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        response.headers_mut().insert(
            hyper::header::VARY,
            HeaderValue::from_static("Accept-Encoding"),
        );
    } else if let Ok(value) = HeaderValue::from_str(&size.to_string()) {
        response
            .headers_mut()
            .insert(hyper::header::CONTENT_LENGTH, value);
    }
    response
}

async fn proxy_upstream(
    mut request: Request<Incoming>,
    upstream: TcpStream,
    client_addr: SocketAddr,
    is_tls: bool,
    authenticated_claims: Option<&sb_auth::claims::SovereignClaims>,
) -> Response<HttpBody> {
    // CVE-Threat: Client-controlled forwarding or identity headers could spoof source/auth upstream.
    // Analysis: Only allow-listed loopback ports or registered mesh tunnels are selected above.
    // Hardening: Forwarding and X-SB-Auth-* headers are stripped and re-injected from verified state.
    let is_upgrade = request.headers().contains_key(hyper::header::UPGRADE);
    let client_upgrade = is_upgrade.then(|| hyper::upgrade::on(&mut request));
    strip_hop_by_hop(request.headers_mut(), is_upgrade);
    request.headers_mut().remove("x-forwarded-for");
    request.headers_mut().remove("x-forwarded-proto");
    request.headers_mut().remove("x-real-ip");
    request.headers_mut().remove("x-sb-auth-subject");
    request.headers_mut().remove("x-sb-auth-roles");
    if let Some(claims) = authenticated_claims {
        if let Ok(subject) = HeaderValue::from_str(&claims.subject) {
            request.headers_mut().insert("x-sb-auth-subject", subject);
        }
        if !claims.roles.is_empty() {
            if let Ok(roles) = HeaderValue::from_str(&claims.roles.join(",")) {
                request.headers_mut().insert("x-sb-auth-roles", roles);
            }
        }
    }
    if let Ok(value) = HeaderValue::from_str(&client_addr.ip().to_string()) {
        request
            .headers_mut()
            .insert("x-forwarded-for", value.clone());
        request.headers_mut().insert("x-real-ip", value);
    }
    request.headers_mut().insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if is_tls { "https" } else { "http" }),
    );
    *request.version_mut() = Version::HTTP_11;
    if !request.uri().path().starts_with('/') {
        let path = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        *request.uri_mut() = match path.parse::<Uri>() {
            Ok(uri) => uri,
            Err(_) => {
                return plain_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid upstream request target.\n",
                )
            }
        };
    }

    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await {
            Ok(parts) => parts,
            Err(error) => {
                log_error("upstream_handshake_failed", &error.to_string(), client_addr);
                return plain_response(
                    StatusCode::BAD_GATEWAY,
                    "Unable to connect to upstream service.\n",
                );
            }
        };
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            log_error(
                "upstream_connection_failed",
                &error.to_string(),
                client_addr,
            );
        }
    });

    let mut upstream_response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            log_error("upstream_request_failed", &error.to_string(), client_addr);
            return plain_response(StatusCode::BAD_GATEWAY, "Upstream request failed.\n");
        }
    };
    if let Some(client_upgrade) = client_upgrade {
        if upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
            tokio::spawn(async move {
                match tokio::try_join!(client_upgrade, upstream_upgrade) {
                    Ok((client, upstream)) => {
                        let mut client = TokioIo::new(client);
                        let mut upstream = TokioIo::new(upstream);
                        if let Err(error) =
                            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                        {
                            log_error("websocket_tunnel_failed", &error.to_string(), client_addr);
                        }
                    }
                    Err(error) => {
                        log_error("websocket_upgrade_failed", &error.to_string(), client_addr)
                    }
                }
            });
        }
    }
    strip_hop_by_hop(upstream_response.headers_mut(), is_upgrade);
    upstream_response.map(|body| {
        body.map_err(|error| Box::new(error) as BoxError)
            .boxed_unsync()
    })
}

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap, allow_upgrade: bool) {
    let connection_tokens = headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .filter(|name| !allow_upgrade || name != hyper::header::UPGRADE)
        .collect::<Vec<_>>();
    for name in connection_tokens {
        headers.remove(name);
    }
    for name in [
        hyper::header::PROXY_AUTHENTICATE,
        hyper::header::PROXY_AUTHORIZATION,
        hyper::header::TE,
        hyper::header::TRAILER,
        hyper::header::TRANSFER_ENCODING,
    ] {
        headers.remove(name);
    }
    headers.remove(HeaderName::from_static("keep-alive"));
    if allow_upgrade {
        if let Some(value) = headers.get(hyper::header::CONNECTION).cloned() {
            headers.insert(hyper::header::CONNECTION, value);
        }
    } else {
        headers.remove(hyper::header::CONNECTION);
        headers.remove(hyper::header::UPGRADE);
    }
}

fn request_host(request: &Request<Incoming>) -> String {
    let authority = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<hyper::http::uri::Authority>().ok())
        .or_else(|| request.uri().authority().cloned());
    authority
        .map(|authority| authority.host().to_ascii_lowercase())
        .unwrap_or_default()
}

fn add_security_headers(
    response: &mut Response<HttpBody>,
    headers: &SecurityHeaders,
    is_tls: bool,
) {
    if is_tls {
        if let Some(value) = &headers.hsts {
            response
                .headers_mut()
                .insert(hyper::header::STRICT_TRANSPORT_SECURITY, value.clone());
        }
    }
    if let Some(value) = &headers.content_security_policy {
        response
            .headers_mut()
            .insert(hyper::header::CONTENT_SECURITY_POLICY, value.clone());
    }
    if let Some(value) = &headers.x_content_type_options {
        response
            .headers_mut()
            .insert(hyper::header::X_CONTENT_TYPE_OPTIONS, value.clone());
    }
}

fn plain_response(status: StatusCode, message: &str) -> Response<HttpBody> {
    let body = Full::new(Bytes::copy_from_slice(message.as_bytes()))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn empty_response(status: StatusCode) -> Response<HttpBody> {
    let mut response = Response::new(
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

fn log_error(event: &str, message: &str, client_addr: SocketAddr) {
    eprintln!(
        "{}",
        serde_json::json!({
            "event": event,
            "client_ip": client_addr.ip().to_string(),
            "error": message,
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Empty};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn static_routes(root: &Path) -> EscapeSpaceStore {
        let mut routes = EscapeSpaceStore::default();
        routes.spaces[0].static_root = Some(root.to_string_lossy().into_owned());
        routes
    }

    fn temp_root() -> std::path::PathBuf {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "sb-http-test-{}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    async fn request_body(body: Incoming) -> Bytes {
        body.collect().await.unwrap().to_bytes()
    }

    #[tokio::test]
    async fn http1_connection_reuses_keep_alive_for_static_requests() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.html"), b"home").unwrap();
        fs::write(root.join("app.js"), b"bundle").unwrap();
        let routes = static_routes(&root);
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            serve_connection(
                server_io,
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                false,
                IpRateLimiter::new(),
                Arc::new(RwLock::new(ProxyTelemetry::new())),
                Arc::new(RwLock::new(routes)),
                SecurityHeaders::default(),
            )
            .await
            .unwrap();
        });
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_io))
                .await
                .unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });

        for (path, expected) in [("/", "home"), ("/app.js", "bundle")] {
            let request = Request::builder()
                .method(Method::GET)
                .uri(path)
                .header(HOST, "preview.sbm.network")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response
                .headers()
                .contains_key(hyper::header::STRICT_TRANSPORT_SECURITY));
            assert_eq!(
                response
                    .headers()
                    .get(hyper::header::X_CONTENT_TYPE_OPTIONS)
                    .unwrap(),
                "nosniff"
            );
            assert_eq!(request_body(response.into_body()).await, expected);
        }

        drop(sender);
        client.await.unwrap();
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn http2_serves_static_files_and_applies_security_headers() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("app.js"), b"bundle").unwrap();
        let routes = static_routes(&root);
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let mut headers = SecurityHeaders::default();
        headers.hsts = Some(HeaderValue::from_static("max-age=31536000"));
        let server = tokio::spawn(async move {
            serve_connection(
                server_io,
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                true,
                IpRateLimiter::new(),
                Arc::new(RwLock::new(ProxyTelemetry::new())),
                Arc::new(RwLock::new(routes)),
                headers,
            )
            .await
            .unwrap();
        });
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });
        let request = Request::builder()
            .method(Method::GET)
            .uri("/app.js")
            .header(HOST, "preview.sbm.network")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000"
        );
        assert_eq!(request_body(response.into_body()).await, "bundle");

        drop(sender);
        client.await.unwrap();
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn http2_requests_are_streamed_to_loopback_upstreams() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let count = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..count]).starts_with("GET /api HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream",
                )
                .await
                .unwrap();
        });

        let mut routes = EscapeSpaceStore::default();
        routes.spaces[0].target_port = upstream_port;
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            serve_connection(
                server_io,
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                true,
                IpRateLimiter::new(),
                Arc::new(RwLock::new(ProxyTelemetry::new())),
                Arc::new(RwLock::new(routes)),
                SecurityHeaders::default(),
            )
            .await
            .unwrap();
        });
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api")
            .header(HOST, "preview.sbm.network")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(request_body(response.into_body()).await, "upstream");

        drop(sender);
        client.await.unwrap();
        server.await.unwrap();
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn static_requests_return_etag_and_respond_with_304_on_if_none_match() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let root = std::env::temp_dir().join(format!(
            "sb-http-etag-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.html"), b"hello etag cache").unwrap();

        let mut routes = EscapeSpaceStore::default();
        routes.spaces[0].static_root = Some(root.to_string_lossy().to_string());

        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            serve_connection(
                server_io,
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                false,
                IpRateLimiter::new(),
                Arc::new(RwLock::new(ProxyTelemetry::new())),
                Arc::new(RwLock::new(routes)),
                SecurityHeaders::default(),
            )
            .await
            .unwrap();
        });

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_io))
                .await
                .unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });

        // 1. Initial GET: Expects 200 OK + ETag
        let request1 = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(HOST, "preview.sbm.network")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response1 = sender.send_request(request1).await.unwrap();
        assert_eq!(response1.status(), StatusCode::OK);
        let etag = response1
            .headers()
            .get(hyper::header::ETAG)
            .expect("ETag must be present")
            .clone();
        assert_eq!(
            request_body(response1.into_body()).await,
            "hello etag cache"
        );

        // 2. Conditional GET with If-None-Match: Expects 304 Not Modified
        let request2 = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(HOST, "preview.sbm.network")
            .header(hyper::header::IF_NONE_MATCH, etag.clone())
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response2 = sender.send_request(request2).await.unwrap();
        assert_eq!(response2.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(response2.headers().get(hyper::header::ETAG), Some(&etag));
        assert_eq!(request_body(response2.into_body()).await, "");

        drop(sender);
        client.await.unwrap();
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn static_requests_compressed_with_gzip_when_accepted() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let root = std::env::temp_dir().join(format!(
            "sb-http-gzip-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        // Repeating text larger than 256 bytes so compression triggers
        let large_content =
            "This is a compressible payload for skulls and bones edge proxy test. ".repeat(10);
        fs::write(root.join("bundle.js"), &large_content).unwrap();

        let mut routes = EscapeSpaceStore::default();
        routes.spaces[0].static_root = Some(root.to_string_lossy().to_string());

        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            serve_connection(
                server_io,
                SocketAddr::from(([127, 0, 0, 1], 12345)),
                false,
                IpRateLimiter::new(),
                Arc::new(RwLock::new(ProxyTelemetry::new())),
                Arc::new(RwLock::new(routes)),
                SecurityHeaders::default(),
            )
            .await
            .unwrap();
        });

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_io))
                .await
                .unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });

        let request = Request::builder()
            .method(Method::GET)
            .uri("/bundle.js")
            .header(HOST, "preview.sbm.network")
            .header(hyper::header::ACCEPT_ENCODING, "gzip, deflate")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(hyper::header::CONTENT_ENCODING),
            Some(&HeaderValue::from_static("gzip"))
        );
        assert_eq!(
            response.headers().get(hyper::header::VARY),
            Some(&HeaderValue::from_static("Accept-Encoding"))
        );

        // Decompress response body with flate2 to verify payload integrity
        use std::io::Read;
        let compressed_body = request_body(response.into_body()).await;
        let mut decoder = flate2::read::GzDecoder::new(compressed_body.as_ref());
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, large_content);

        drop(sender);
        client.await.unwrap();
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
