use sb_auth::{AuthEngine, AuthVerifier, Keypair, MemoryRevocationStore};
use sb_proxy::escape::{EscapeSpace, EscapeSpaceStore, EscapeStatus};
use sb_proxy::http_server::{serve_connection_with_auth, SecurityHeaders};
use sb_proxy::ipc::ProxyTelemetry;
use sb_proxy::ratelimit::IpRateLimiter;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn protected_route(
    domain: &str,
    target_port: u16,
    role: Option<&str>,
    cap: Option<&str>,
) -> EscapeSpace {
    EscapeSpace {
        id: "esc-auth-test".to_string(),
        domain: domain.to_string(),
        node_callsign: "test-node".to_string(),
        target_port,
        public_port: 443,
        tls_enabled: false,
        status: EscapeStatus::Active,
        mesh_isolated: true,
        rate_limit_rpm: 600,
        created_at: "2026-11-16T00:00:00Z".to_string(),
        aliases: vec![],
        maintenance_msg: None,
        expires_at: None,
        custom_cert_path: None,
        custom_key_path: None,
        cert_expires_at: None,
        is_tunnel: false,
        tunnel_peer: None,
        static_root: None,
        auth_required: true,
        required_role: role.map(str::to_string),
        required_capability: cap.map(str::to_string),
    }
}

async fn send_raw_http(addr: std::net::SocketAddr, raw: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(raw.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

#[tokio::test]
async fn protected_route_enforces_sb_auth_tokens_roles_revocation_and_header_sanitization() {
    // 1. Setup upstream echo server that returns received headers
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    req.len(),
                    req
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });

    // 2. Setup AuthEngine (issuer) and public-key-only AuthVerifier (proxy)
    let keypair = Keypair::generate();
    let store = Arc::new(MemoryRevocationStore::new());
    let engine = AuthEngine::new(keypair.clone(), store.clone());
    let verifier = Arc::new(
        AuthVerifier::from_public_base64(&engine.public_key_base64(), store.clone()).unwrap(),
    );

    let routes = Arc::new(RwLock::new(EscapeSpaceStore {
        spaces: vec![protected_route(
            "secret.sbm",
            upstream_port,
            Some("operator"),
            Some("mesh:read"),
        )],
    }));

    // 3. Start proxy listener with AuthVerifier
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let limiter = IpRateLimiter::new();
    let telemetry = Arc::new(RwLock::new(ProxyTelemetry::default()));

    tokio::spawn(async move {
        while let Ok((stream, addr)) = proxy.accept().await {
            let l = limiter.clone();
            let t = telemetry.clone();
            let r = routes.clone();
            let v = verifier.clone();
            tokio::spawn(async move {
                let _ = serve_connection_with_auth(
                    stream,
                    addr,
                    false,
                    l,
                    t,
                    r,
                    SecurityHeaders::default(),
                    Some(v),
                )
                .await;
            });
        }
    });

    // Case A: Missing Authorization header -> 401 Unauthorized + WWW-Authenticate
    let res_unauth = send_raw_http(
        proxy_addr,
        "GET / HTTP/1.1\r\nHost: secret.sbm\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(res_unauth.starts_with("HTTP/1.1 401 Unauthorized"));
    assert!(res_unauth
        .to_ascii_lowercase()
        .contains("www-authenticate: bearer"));

    // Case B: Valid token without required role -> 403 Forbidden
    let guest_tokens = engine
        .issue_session(
            "alice",
            vec!["guest".into()],
            vec!["mesh:read".into()],
            serde_json::json!({}),
        )
        .unwrap();
    let res_forbidden = send_raw_http(
        proxy_addr,
        &format!(
            "GET / HTTP/1.1\r\nHost: secret.sbm\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            guest_tokens.access_token
        ),
    )
    .await;
    assert!(res_forbidden.starts_with("HTTP/1.1 403 Forbidden"));

    // Case C: Authorized token + spoofed X-SB-Auth-Subject -> 200 OK with real subject injected
    let op_tokens = engine
        .issue_session(
            "bob",
            vec!["operator".into()],
            vec!["mesh:read".into()],
            serde_json::json!({}),
        )
        .unwrap();
    let res_ok = send_raw_http(
        proxy_addr,
        &format!(
            "GET / HTTP/1.1\r\nHost: secret.sbm\r\nAuthorization: Bearer {}\r\nX-SB-Auth-Subject: evil-spoof\r\nConnection: close\r\n\r\n",
            op_tokens.access_token
        ),
    )
    .await;
    assert!(res_ok.starts_with("HTTP/1.1 200 OK"));
    let lower = res_ok.to_ascii_lowercase();
    assert!(lower.contains("x-sb-auth-subject: bob"));
    assert!(!lower.contains("evil-spoof"));

    // Case D: Revoked token -> 401 Unauthorized
    engine
        .revoke_token(
            &op_tokens.access_token_id,
            op_tokens.expires_at,
            "compromised",
        )
        .unwrap();
    let res_revoked = send_raw_http(
        proxy_addr,
        &format!(
            "GET / HTTP/1.1\r\nHost: secret.sbm\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            op_tokens.access_token
        ),
    )
    .await;
    assert!(res_revoked.starts_with("HTTP/1.1 401 Unauthorized"));
}

#[tokio::test]
async fn protected_route_fails_closed_without_verifier() {
    let routes = Arc::new(RwLock::new(EscapeSpaceStore {
        spaces: vec![protected_route("secret.sbm", 8080, None, None)],
    }));
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let limiter = IpRateLimiter::new();
    let telemetry = Arc::new(RwLock::new(ProxyTelemetry::default()));

    tokio::spawn(async move {
        if let Ok((stream, addr)) = proxy.accept().await {
            let _ = serve_connection_with_auth(
                stream,
                addr,
                false,
                limiter,
                telemetry,
                routes,
                SecurityHeaders::default(),
                None,
            )
            .await;
        }
    });

    let res = send_raw_http(
        proxy_addr,
        "GET / HTTP/1.1\r\nHost: secret.sbm\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(res.starts_with("HTTP/1.1 503 Service Unavailable"));
}
