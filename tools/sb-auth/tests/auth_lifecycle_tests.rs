use base64::Engine;
use chrono::Utc;
use std::sync::Arc;

use sb_auth::prelude::*;
use sb_auth::token::CURRENT_VERSION;

#[test]
fn test_keygen_and_signature_verification() {
    let keypair = Keypair::generate();
    let message = b"Sovereign Auth Message";
    let sig = keypair.sign(message);

    assert!(keypair.verify(message, &sig).is_ok());

    // Fälschung erkennen
    let tampered = b"Tampered Auth Message";
    assert!(keypair.verify(tampered, &sig).is_err());
}

#[test]
fn test_token_encoding_decoding_and_tampering() {
    let keypair = Keypair::generate();
    let now = Utc::now().timestamp();

    let claims = SovereignClaims {
        token_id: "sbt_test_1".to_string(),
        token_type: TokenType::Access,
        subject: "alice".to_string(),
        session_id: Some("sbs_1".to_string()),
        user_epoch: 0,
        roles: vec!["developer".to_string()],
        capabilities: vec!["code:write".to_string(), "stream:read".to_string()],
        audience: Some("api.skulls-and-bones.org".to_string()),
        issuer: "sb-auth-test".to_string(),
        issued_at: now,
        not_before: now,
        expires_at: now + 300,
        metadata: serde_json::json!({ "team": "core" }),
    };

    let token_str = TokenEncoder::encode(&claims, &keypair).expect("Encode failed");
    assert!(token_str.starts_with("sbt."));

    let (header, decoded) =
        TokenDecoder::decode_and_verify(&token_str, &keypair.verifying_key).expect("Verify failed");

    assert_eq!(header.ver, CURRENT_VERSION);
    assert_eq!(decoded.subject, "alice");
    assert_eq!(decoded.roles, vec!["developer"]);
    assert!(decoded.has_capability("code:write"));
    assert!(!decoded.has_capability("admin:delete"));

    // Manipulation am Payload-Segment erkennen
    let mut parts: Vec<&str> = token_str.split('.').collect();
    parts[2] = "eyJyYW5kb20iOiJmYWtlIn0"; // gefälschter Payload
    let tampered_token = parts.join(".");
    assert!(TokenDecoder::decode_and_verify(&tampered_token, &keypair.verifying_key).is_err());
}

#[test]
fn test_token_expiration() {
    let keypair = Keypair::generate();
    let now = Utc::now().timestamp();

    let claims = SovereignClaims {
        token_id: "sbt_expired_1".to_string(),
        token_type: TokenType::Access,
        subject: "bob".to_string(),
        session_id: None,
        user_epoch: 0,
        roles: vec![],
        capabilities: vec![],
        audience: None,
        issuer: "sb-auth-test".to_string(),
        issued_at: now - 1000,
        not_before: now - 1000,
        expires_at: now - 100, // bereits abgelaufen!
        metadata: serde_json::Value::Null,
    };

    let token_str = TokenEncoder::encode(&claims, &keypair).unwrap();
    let (_, decoded) = TokenDecoder::decode_and_verify(&token_str, &keypair.verifying_key).unwrap();

    let err = decoded.validate_time(now, 0).unwrap_err();
    assert!(matches!(err, AuthError::ExpiredToken { .. }));
}

#[test]
fn test_multi_tier_revocation() {
    let keypair = Keypair::generate();
    let store = Arc::new(MemoryRevocationStore::new());
    let engine = AuthEngine::new(keypair, store.clone());

    // 1. Session ausstellen
    let session = engine
        .issue_session(
            "charlie",
            vec!["user".to_string()],
            vec!["read".to_string()],
            serde_json::Value::Null,
        )
        .expect("Session issue failed");

    // Token ist anfangs voll gültig
    assert!(engine.verify_token(&session.access_token).is_ok());

    // 2. Token-Level Revocation
    engine
        .revoke_token(&session.access_token_id, session.expires_at, "Compromised")
        .expect("Token revocation failed");

    let err = engine.verify_token(&session.access_token).unwrap_err();
    assert!(matches!(err, AuthError::RevokedToken { .. }));

    // 3. Neue Tokens für neue Session ausstellen
    let session2 = engine
        .issue_session(
            "charlie",
            vec!["user".to_string()],
            vec!["read".to_string()],
            serde_json::Value::Null,
        )
        .expect("Session2 issue failed");
    assert!(engine.verify_token(&session2.access_token).is_ok());

    // Session-Level Revocation
    engine
        .revoke_session(&session2.session_id, session2.expires_at, "User logged out")
        .expect("Session revocation failed");

    let err2 = engine.verify_token(&session2.access_token).unwrap_err();
    assert!(matches!(err2, AuthError::RevokedSession { .. }));

    // 4. User-Level Epoch Bump ("Überall abmelden")
    let session3 = engine
        .issue_session(
            "dave",
            vec!["user".to_string()],
            vec![],
            serde_json::Value::Null,
        )
        .expect("Session3 issue failed");
    assert!(engine.verify_token(&session3.access_token).is_ok());

    engine
        .revoke_all_user_sessions("dave")
        .expect("Bump epoch failed");

    let err3 = engine.verify_token(&session3.access_token).unwrap_err();
    assert!(matches!(err3, AuthError::RevokedUserEpoch { .. }));
}

#[test]
fn test_refresh_token_rotation() {
    let keypair = Keypair::generate();
    let store = Arc::new(MemoryRevocationStore::new());
    let engine = AuthEngine::new(keypair, store);

    let session1 = engine
        .issue_session(
            "eve",
            vec!["dev".to_string()],
            vec!["code:sync".to_string()],
            serde_json::Value::Null,
        )
        .unwrap();

    // Session mit Refresh-Token erneuern
    let session2 = engine
        .refresh_session(&session1.refresh_token)
        .expect("Refresh failed");

    // Der neue Access-Token funktioniert
    assert!(engine.verify_token(&session2.access_token).is_ok());

    // Der ALTE Refresh-Token wurde widerrufen und schlägt bei Wiederverwendung fehl!
    let replay_err = engine.refresh_session(&session1.refresh_token).unwrap_err();
    assert!(matches!(replay_err, AuthError::RevokedToken { .. }));
}

#[test]
fn test_checksummed_api_keys() {
    let key = ApiKey::generate(ApiKeyEnv::Live);
    assert!(key.raw.starts_with("sba_live_"));

    // Valider Key parst erfolgreich
    let parsed = ApiKey::parse(&key.raw).expect("Parse failed");
    assert_eq!(parsed.env, ApiKeyEnv::Live);
    assert_eq!(parsed.checksum, key.checksum);

    // Tippfehler am Key-Ende oder im Payload schlägt sofort fehl
    let mut bad_key = key.raw.clone();
    let replacement = if &bad_key[10..11] == "X" { "Y" } else { "X" };
    bad_key.replace_range(10..11, replacement);
    assert!(matches!(
        ApiKey::parse(&bad_key).unwrap_err(),
        AuthError::InvalidApiKey
    ));
}

#[test]
fn test_argon2id_passwords() {
    let pw = "s0v3r31gn_P@ssw0rd!";
    let hash = hash_password(pw).expect("Hash failed");

    assert!(verify_password(pw, &hash).is_ok());
    assert!(verify_password("wrong_password", &hash).is_err());
}

#[test]
fn test_totp_rfc6238() {
    let secret_b64 = generate_totp_secret();
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&secret_b64)
        .unwrap();

    let now = 1_700_000_000i64;
    let code = generate_totp_code(&secret, now, 30).expect("TOTP code failed");
    assert_eq!(code.len(), 6);

    // Exakte Zeit bestätigt
    assert!(verify_totp_code(&secret, &code, now, 30, 1).is_ok());

    // Drift innerhalb von 30s bestätigt
    assert!(verify_totp_code(&secret, &code, now + 25, 30, 1).is_ok());

    // Zu weiter Zeitabstand schlägt fehl
    assert!(verify_totp_code(&secret, &code, now + 300, 30, 1).is_err());
}

#[test]
fn test_middleware_bearer_extraction_and_wildcard_capability() {
    let keypair = Keypair::generate();
    let store = Arc::new(MemoryRevocationStore::new());
    let engine = AuthEngine::new(keypair, store);

    let session = engine
        .issue_session(
            "frank",
            vec!["admin".to_string()],
            vec!["code:*".to_string()], // Wildcard!
            serde_json::Value::Null,
        )
        .unwrap();

    let header = format!("Bearer {}", session.access_token);

    // Wildcard 'code:*' muss 'code:write' und 'code:read' autorisieren
    let claims = authorize_header(&engine, &header, Some("admin"), Some("code:write"))
        .expect("Auth header failed");
    assert_eq!(claims.subject, "frank");

    // Fehlende Rolle schlägt fehl
    assert!(authorize_header(&engine, &header, Some("superadmin"), None).is_err());

    // Fehlende Capability schlägt fehl
    assert!(authorize_header(&engine, &header, None, Some("db:drop")).is_err());
}
