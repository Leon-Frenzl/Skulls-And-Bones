//! Extended DC HTTP routes: Passkey MFA (WebAuthn), full OIDC IdP (PKCE + id_token),
//! real-time revocation SSE stream, and Groups / OUs / Delegated Administration.

use crate::directory_users::{DelegatedPermission, IdentityDirectory};
use crate::domain_join::{
    extract_bearer_token, load_local_auth_engine, read_http_body, revocation_hub,
    session_tokens_json, write_http_json,
};
use crate::oidc::{
    sign_oidc_id_token, OidcAuthCodeStore, OidcClientRegistry,
};
use crate::passkey::PasskeyStore;
use sb_auth::AuthVerifier;
use sb_core::domain::local_domain_dir;
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

fn verify_bearer(headers: &[&str]) -> Result<sb_auth::SovereignClaims, (u16, &'static str, String)> {
    let token = extract_bearer_token(headers).ok_or_else(|| {
        (
            401,
            "Unauthorized",
            r#"{"error":"missing bearer token"}"#.to_string(),
        )
    })?;
    let pub_b64 = std::fs::read_to_string(sb_core::paths::sb_home().join("auth").join("auth.pub"))
        .map_err(|e| (500, "Internal Server Error", serde_json::json!({ "error": e.to_string() }).to_string()))?;
    let verifier = AuthVerifier::from_public_base64(&pub_b64, Arc::new(sb_auth::MemoryRevocationStore::default()))
        .map_err(|e| (500, "Internal Server Error", serde_json::json!({ "error": e.to_string() }).to_string()))?;
    verifier.verify_token(token).map_err(|e| {
        (
            401,
            "Unauthorized",
            serde_json::json!({ "error": format!("authentication failed: {e}") }).to_string(),
        )
    })
}

fn host_from_headers(headers: &[&str]) -> String {
    headers
        .iter()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("host").then(|| v.trim())
        })
        .unwrap_or("console.skulls-and-bones.org")
        .to_string()
}

fn rp_id_from_headers(headers: &[&str]) -> String {
    host_from_headers(headers)
        .split(':')
        .next()
        .unwrap_or("console.skulls-and-bones.org")
        .to_string()
}

fn load_auth_keypair() -> Result<sb_auth::crypto::Keypair, String> {
    let key_b64 = std::fs::read_to_string(sb_core::paths::sb_home().join("auth").join("auth.key"))
        .map_err(|e| format!("Missing auth.key: {e}"))?;
    sb_auth::crypto::Keypair::from_secret_base64(key_b64.trim())
        .map_err(|e| format!("Invalid auth.key: {e}"))
}

fn grant_user_capabilities(dir: &IdentityDirectory, username: &str) -> Vec<String> {
    let mut caps = vec!["domain:read".to_string(), "directory:read".to_string()];
    let Some(user) = dir.users.get(username) else {
        return caps;
    };
    if user.groups.iter().any(|g| g == "admins") {
        caps.extend([
            "domain:admin".into(),
            "domain:join".into(),
            "directory:write".into(),
            "policy:write".into(),
            "audit:read".into(),
            "dns:write".into(),
            "vault:write".into(),
            "laps:read".into(),
        ]);
    } else {
        if dir.has_delegated_permission(username, DelegatedPermission::LapsReveal) {
            caps.push("laps:read".into());
        }
        if dir.has_delegated_permission(username, DelegatedPermission::PolicyManage) {
            caps.push("policy:write".into());
        }
        if dir.has_delegated_permission(username, DelegatedPermission::UserManage)
            || dir.has_delegated_permission(username, DelegatedPermission::GroupManage)
        {
            caps.push("directory:write".into());
        }
        if dir.has_delegated_permission(username, DelegatedPermission::AuditRead) {
            caps.push("audit:read".into());
        }
    }
    caps
}

/// Handles Passkey MFA, OIDC IdP, Real-Time Revocation SSE, and Groups/OUs/Delegations routes.
/// Returns `Ok(true)` if the route was handled and a response was written.
#[allow(clippy::too_many_arguments)]
pub async fn handle_dc_extended_routes(
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    header_lines: &[&str],
    buf: &mut Vec<u8>,
    chunk: &mut [u8],
    header_end: usize,
    registry_path: Option<&Path>,
) -> Result<bool, String> {
    let base_dir = registry_path
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(local_domain_dir);

    // 1. Passkey MFA (W3C WebAuthn)
    if method == "POST" && path == "/v1/auth/passkey/register/start" {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        let pk_path = base_dir.join("passkeys.json");
        let mut store = PasskeyStore::load(&pk_path).unwrap_or_default();
        let rp_id = rp_id_from_headers(header_lines);
        match store.start_registration(&claims.subject, &rp_id, "Skulls & Bones") {
            Ok(opts) => {
                let _ = store.save(&pk_path);
                write_http_json(stream, 200, "OK", &opts.to_string()).await?;
            }
            Err(e) => {
                write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
            }
        }
        return Ok(true);
    }

    if method == "POST" && path == "/v1/auth/passkey/register/finish" {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
            return Ok(true);
        };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let cred_id = payload["credential_id"].as_str().unwrap_or("");
        let client_data = payload["client_data_json"].as_str().unwrap_or("");
        let auth_data = payload["auth_data"].as_str().unwrap_or("");
        let public_key = payload["public_key"].as_str().unwrap_or("");
        let alg = payload["alg"].as_i64().unwrap_or(-7) as i32;
        let label = payload["label"].as_str().unwrap_or("Passkey");

        let pk_path = base_dir.join("passkeys.json");
        let mut store = PasskeyStore::load(&pk_path).unwrap_or_default();
        match store.finish_registration(cred_id, client_data, auth_data, public_key, alg, label, None) {
            Ok(cred) => {
                let _ = store.save(&pk_path);
                let _ = crate::audit_log::append_audit_event(
                    &base_dir.join("audit.jsonl"),
                    &claims.subject,
                    "auth.passkey.register",
                    &cred.credential_id_b64,
                    "ok",
                    serde_json::json!({ "label": cred.label }),
                );
                write_http_json(stream, 200, "OK", &serde_json::to_string(&cred).unwrap_or_default()).await?;
            }
            Err(e) => {
                write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
            }
        }
        return Ok(true);
    }

    if method == "POST" && path == "/v1/auth/passkey/login/start" {
        let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
            return Ok(true);
        };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let username = payload["username"].as_str().unwrap_or("").trim();
        let pk_path = base_dir.join("passkeys.json");
        let mut store = PasskeyStore::load(&pk_path).unwrap_or_default();
        let rp_id = rp_id_from_headers(header_lines);
        match store.start_authentication(username, &rp_id) {
            Ok(opts) => {
                let _ = store.save(&pk_path);
                write_http_json(stream, 200, "OK", &opts.to_string()).await?;
            }
            Err(e) => {
                write_http_json(stream, 404, "Not Found", &serde_json::json!({ "error": e }).to_string()).await?;
            }
        }
        return Ok(true);
    }

    if method == "POST" && path == "/v1/auth/passkey/login/finish" {
        let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
            return Ok(true);
        };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let cred_id = payload["credential_id"].as_str().unwrap_or("");
        let client_data = payload["client_data_json"].as_str().unwrap_or("");
        let auth_data = payload["authenticator_data"].as_str().unwrap_or("");
        let sig = payload["signature"].as_str().unwrap_or("");

        let pk_path = base_dir.join("passkeys.json");
        let mut store = PasskeyStore::load(&pk_path).unwrap_or_default();
        let username = match store.finish_authentication(cred_id, client_data, auth_data, sig, None) {
            Ok(u) => {
                let _ = store.save(&pk_path);
                u
            }
            Err(e) => {
                write_http_json(stream, 401, "Unauthorized", &serde_json::json!({ "error": e }).to_string()).await?;
                return Ok(true);
            }
        };

        let dir = IdentityDirectory::load_or_create(&base_dir.join("users.json"), "skulls-and-bones.sb")
            .unwrap_or_default();
        let Some(user) = dir.users.get(&username) else {
            write_http_json(stream, 401, "Unauthorized", r#"{"error":"user not found"}"#).await?;
            return Ok(true);
        };
        if !user.enabled {
            write_http_json(stream, 403, "Forbidden", r#"{"error":"user account is disabled"}"#).await?;
            return Ok(true);
        }
        let engine = match load_local_auth_engine() {
            Ok(e) => e,
            Err(e) => {
                write_http_json(stream, 500, "Internal Server Error", &serde_json::json!({ "error": e }).to_string()).await?;
                return Ok(true);
            }
        };
        let caps = grant_user_capabilities(&dir, &username);
        match engine.issue_session(
            &user.username,
            user.groups.clone(),
            caps,
            serde_json::json!({ "amr": ["hwk", "mfa"] }),
        ) {
            Ok(tokens) => {
                let _ = crate::audit_log::append_audit_event(
                    &base_dir.join("audit.jsonl"),
                    &user.username,
                    "auth.login.passkey",
                    "passkey",
                    "ok",
                    serde_json::json!({ "amr": ["hwk", "mfa"] }),
                );
                write_http_json(stream, 200, "OK", &session_tokens_json(&tokens)).await?;
            }
            Err(e) => {
                write_http_json(stream, 500, "Internal Server Error", &serde_json::json!({ "error": e.to_string() }).to_string()).await?;
            }
        }
        return Ok(true);
    }

    if method == "GET" && path == "/v1/auth/passkey/list" {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        let store = PasskeyStore::load(&base_dir.join("passkeys.json")).unwrap_or_default();
        let creds = store.list_for_user(&claims.subject);
        write_http_json(stream, 200, "OK", &serde_json::json!({ "passkeys": creds }).to_string()).await?;
        return Ok(true);
    }

    // 2. Full OIDC IdP (/oauth2/clients, /oauth2/authorize, /oauth2/token)
    if path == "/oauth2/clients" && (method == "GET" || method == "POST") {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        if !claims.capabilities.iter().any(|c| c == "domain:admin") {
            write_http_json(stream, 403, "Forbidden", r#"{"error":"domain:admin required"}"#).await?;
            return Ok(true);
        }
        let clients_path = base_dir.join("oidc_clients.json");
        let mut reg = OidcClientRegistry::load(&clients_path).unwrap_or_default();
        if method == "GET" {
            write_http_json(stream, 200, "OK", &serde_json::to_string(&reg).unwrap_or_default()).await?;
        } else {
            let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
                return Ok(true);
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let cid = payload["client_id"].as_str().unwrap_or("");
            let cname = payload["client_name"].as_str().unwrap_or("");
            let redirects: Vec<String> = payload["redirect_uris"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let secret = payload["client_secret"].as_str();
            match reg.register_client(cid, cname, redirects, secret) {
                Ok(entry) => {
                    let _ = reg.save(&clients_path);
                    write_http_json(stream, 200, "OK", &serde_json::to_string(&entry).unwrap_or_default()).await?;
                }
                Err(e) => {
                    write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
                }
            }
        }
        return Ok(true);
    }

    if method == "POST" && path == "/oauth2/authorize" {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
            return Ok(true);
        };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let client_id = payload["client_id"].as_str().unwrap_or("");
        let redirect_uri = payload["redirect_uri"].as_str().unwrap_or("");
        let scope = payload["scope"].as_str().unwrap_or("openid profile groups");
        let nonce = payload["nonce"].as_str().map(String::from);
        let code_challenge = payload["code_challenge"].as_str().unwrap_or("");
        let method_pkce = payload["code_challenge_method"].as_str().unwrap_or("S256");

        let reg = OidcClientRegistry::load(&base_dir.join("oidc_clients.json")).unwrap_or_default();
        if let Err(e) = reg.validate_redirect(client_id, redirect_uri) {
            write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
            return Ok(true);
        }
        let codes_path = base_dir.join("oidc_auth_codes.json");
        let mut codes: OidcAuthCodeStore = std::fs::read_to_string(&codes_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        match codes.issue_authorization_code(
            client_id,
            redirect_uri,
            &claims.subject,
            scope,
            nonce,
            code_challenge,
            method_pkce,
            vec!["pwd".into()],
        ) {
            Ok(code) => {
                if let Ok(json) = serde_json::to_string_pretty(&codes) {
                    let _ = std::fs::write(&codes_path, json);
                }
                write_http_json(
                    stream,
                    200,
                    "OK",
                    &serde_json::json!({ "code": code, "redirect_uri": redirect_uri }).to_string(),
                )
                .await?;
            }
            Err(e) => {
                write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
            }
        }
        return Ok(true);
    }

    if method == "POST" && path == "/oauth2/token" {
        let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
            return Ok(true);
        };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let code = payload["code"].as_str().unwrap_or("");
        let client_id = payload["client_id"].as_str().unwrap_or("");
        let redirect_uri = payload["redirect_uri"].as_str().unwrap_or("");
        let code_verifier = payload["code_verifier"].as_str().unwrap_or("");

        let codes_path = base_dir.join("oidc_auth_codes.json");
        let mut codes: OidcAuthCodeStore = std::fs::read_to_string(&codes_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let entry = match codes.consume_authorization_code(code, client_id, redirect_uri, code_verifier) {
            Ok(e) => {
                if let Ok(json) = serde_json::to_string_pretty(&codes) {
                    let _ = std::fs::write(&codes_path, json);
                }
                e
            }
            Err(e) => {
                write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
                return Ok(true);
            }
        };

        let dir = IdentityDirectory::load_or_create(&base_dir.join("users.json"), "skulls-and-bones.sb")
            .unwrap_or_default();
        let Some(user) = dir.users.get(&entry.username) else {
            write_http_json(stream, 401, "Unauthorized", r#"{"error":"user not found"}"#).await?;
            return Ok(true);
        };
        let engine = match load_local_auth_engine() {
            Ok(e) => e,
            Err(e) => {
                write_http_json(stream, 500, "Internal Server Error", &serde_json::json!({ "error": e }).to_string()).await?;
                return Ok(true);
            }
        };
        let kp = match load_auth_keypair() {
            Ok(k) => k,
            Err(e) => {
                write_http_json(stream, 500, "Internal Server Error", &serde_json::json!({ "error": e }).to_string()).await?;
                return Ok(true);
            }
        };
        let host = host_from_headers(header_lines);
        let scheme = if host.starts_with("127.0.0.1") || host.starts_with("localhost") {
            "http"
        } else {
            "https"
        };
        let issuer = format!("{scheme}://{host}");
        let id_token = sign_oidc_id_token(
            &kp,
            &issuer,
            &entry.client_id,
            &user.username,
            &user.groups,
            &user.ou,
            &entry.amr,
            entry.nonce.as_deref(),
            3600,
        )
        .unwrap_or_default();

        let caps = grant_user_capabilities(&dir, &user.username);
        match engine.issue_session(&user.username, user.groups.clone(), caps, serde_json::json!({})) {
            Ok(tokens) => {
                let resp = serde_json::json!({
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token,
                    "id_token": id_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": entry.scope,
                })
                .to_string();
                write_http_json(stream, 200, "OK", &resp).await?;
            }
            Err(e) => {
                write_http_json(stream, 500, "Internal Server Error", &serde_json::json!({ "error": e.to_string() }).to_string()).await?;
            }
        }
        return Ok(true);
    }

    // 3. Real-Time Revocation SSE Stream
    if method == "GET" && path == "/v1/events/revocations" {
        if let Err((code, reason, body)) = verify_bearer(header_lines) {
            write_http_json(stream, code, reason, &body).await?;
            return Ok(true);
        }
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n: connected\n\n";
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| format!("SSE write failed: {e}"))?;
        let mut rx = revocation_hub().subscribe();
        while let Ok(ev) = rx.recv().await {
            if stream.write_all(ev.to_sse_frame().as_bytes()).await.is_err() {
                break;
            }
        }
        return Ok(true);
    }

    // 4. Groups, OUs & Delegated Administration
    if path == "/v1/groups" && method == "GET" {
        if let Err((code, reason, body)) = verify_bearer(header_lines) {
            write_http_json(stream, code, reason, &body).await?;
            return Ok(true);
        }
        let dir = IdentityDirectory::load_or_create(&base_dir.join("users.json"), "skulls-and-bones.sb")
            .unwrap_or_default();
        write_http_json(stream, 200, "OK", &serde_json::json!({ "groups": dir.groups }).to_string()).await?;
        return Ok(true);
    }

    if (method == "PUT" || method == "DELETE") && path.starts_with("/v1/groups/") {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        if !claims.capabilities.iter().any(|c| c == "directory:write" || c == "domain:admin") {
            write_http_json(stream, 403, "Forbidden", r#"{"error":"directory:write required"}"#).await?;
            return Ok(true);
        }
        let group_name = path.trim_start_matches("/v1/groups/");
        let users_path = base_dir.join("users.json");
        let mut dir = IdentityDirectory::load_or_create(&users_path, "skulls-and-bones.sb")
            .unwrap_or_default();
        if method == "DELETE" {
            match dir.delete_group(group_name) {
                Ok(removed) => {
                    let _ = dir.save(&users_path);
                    write_http_json(stream, 200, "OK", &serde_json::json!({ "deleted": removed }).to_string()).await?;
                }
                Err(e) => {
                    write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
                }
            }
        } else {
            let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
                return Ok(true);
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let desc = payload["description"].as_str().unwrap_or("");
            let ou = payload["ou"].as_str().unwrap_or("/");
            let is_local_admin = payload["is_local_admin"].as_bool().unwrap_or(false);
            let allowed_machines: Vec<String> = payload["allowed_machines"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            match dir.upsert_group(sb_core::identity::DomainGroup {
                name: group_name.to_string(),
                description: desc.to_string(),
                ou: ou.to_string(),
                is_local_admin,
                allowed_machines,
                members: Vec::new(),
                updated_at: String::new(),
            }) {
                Ok(grp) => {
                    let _ = dir.save(&users_path);
                    write_http_json(stream, 200, "OK", &serde_json::to_string(&grp).unwrap_or_default()).await?;
                }
                Err(e) => {
                    write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
                }
            }
        }
        return Ok(true);
    }

    if path == "/v1/ous" && (method == "GET" || method == "PUT" || method == "DELETE") {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        let users_path = base_dir.join("users.json");
        let mut dir = IdentityDirectory::load_or_create(&users_path, "skulls-and-bones.sb")
            .unwrap_or_default();
        if method == "GET" {
            write_http_json(stream, 200, "OK", &serde_json::json!({ "ous": dir.ous }).to_string()).await?;
            return Ok(true);
        }
        if !claims.capabilities.iter().any(|c| c == "directory:write" || c == "domain:admin") {
            write_http_json(stream, 403, "Forbidden", r#"{"error":"directory:write required"}"#).await?;
            return Ok(true);
        }
        let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
            return Ok(true);
        };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let ou_path = payload["path"].as_str().unwrap_or("");
        if method == "DELETE" {
            match dir.delete_ou(ou_path) {
                Ok(deleted) => {
                    let _ = dir.save(&users_path);
                    write_http_json(stream, 200, "OK", &serde_json::json!({ "deleted": deleted }).to_string()).await?;
                }
                Err(e) => {
                    write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
                }
            }
        } else {
            let desc = payload["description"].as_str().unwrap_or("");
            match dir.upsert_ou(ou_path, desc) {
                Ok(ou) => {
                    let _ = dir.save(&users_path);
                    write_http_json(stream, 200, "OK", &serde_json::to_string(&ou).unwrap_or_default()).await?;
                }
                Err(e) => {
                    write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
                }
            }
        }
        return Ok(true);
    }

    if path == "/v1/rbac/delegations" && (method == "GET" || method == "PUT") {
        let claims = match verify_bearer(header_lines) {
            Ok(c) => c,
            Err((code, reason, body)) => {
                write_http_json(stream, code, reason, &body).await?;
                return Ok(true);
            }
        };
        let users_path = base_dir.join("users.json");
        let mut dir = IdentityDirectory::load_or_create(&users_path, "skulls-and-bones.sb")
            .unwrap_or_default();
        if method == "GET" {
            write_http_json(stream, 200, "OK", &serde_json::json!({ "delegations": dir.delegations }).to_string()).await?;
            return Ok(true);
        }
        if !claims.capabilities.iter().any(|c| c == "domain:admin") {
            write_http_json(stream, 403, "Forbidden", r#"{"error":"domain:admin required"}"#).await?;
            return Ok(true);
        }
        let Some(body) = read_http_body(stream, buf, chunk, header_end, header_lines).await? else {
            return Ok(true);
        };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let principal = payload["principal"].as_str().unwrap_or("");
        let perms: Vec<DelegatedPermission> = serde_json::from_value(payload["permissions"].clone())
            .unwrap_or_default();
        match dir.set_delegations(principal, perms) {
            Ok(()) => {
                let _ = dir.save(&users_path);
                write_http_json(stream, 200, "OK", &serde_json::json!({ "updated": principal }).to_string()).await?;
            }
            Err(e) => {
                write_http_json(stream, 400, "Bad Request", &serde_json::json!({ "error": e }).to_string()).await?;
            }
        }
        return Ok(true);
    }

    Ok(false)
}
