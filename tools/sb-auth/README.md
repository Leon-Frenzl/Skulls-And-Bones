# S&B Auth (`sb-auth`) — Sovereign Authentication Kit

> **Souveräne Authentifizierung. Multi-Tier Revocation. Keine externen Cloud-Abhängigkeiten.**

`sb-auth` ist ein modernes, manipulationssicheres Authentifizierungs- und Identitäts-Kit für die Skulls & Bones Suite sowie externe Rust-Dienste. Es verzichtet bewusst auf fehleranfällige JWT-Libraries und bietet stattdessen eine deterministische, kryptografisch verifizierte Token-Architektur mit echter **Multi-Tier Revocation**.

---

## 1. Kernmerkmale

- **Sovereign Tokens (`sbt.*`)**:
  - Asymmetrisch signiert mit Ed25519 (`ed25519-dalek`).
  - Kein Algorithmus-Downgrade (`alg: none` oder RSA/HMAC-Confusion ist architektonisch unmöglich).
  - Deterministische Struktur: `sbt.<header_b64>.<claims_b64>.<sig_b64>`.
- **Multi-Tier Revocation**:
  - **Token-Ebene**: Gezieltes Sperren eines kompromittierten Tokens (`token_id`).
  - **Session-Ebene**: Gezieltes Beenden einer Sitzung (`session_id`).
  - **User-Epoch-Ebene**: Inkrementieren der Benutzer-Epoche macht sofort **alle Tokens dieses Nutzers auf allen Geräten ungültig** (z. B. nach Passwort-Reset).
  - **TTL-Pruning**: Automatische Bereinigung abgelaufener Sperreinträge verhindert unbegrenztes Speicherwachstum.
- **Rotierende Refresh-Tokens**:
  - Refresh-Tokens werden bei jeder Nutzung sofort widerrufen (Single-Use Token Rotation gegen Replay-Angriffe).
- **Prüfsummen-geschützte API-Keys (`sba_*`)**:
  - Format: `sba_{env}_{entropy}_{crc32_hex}` (z. B. `sba_live_..._9f2a41bc`).
  - Erlaubt sofortige Integritäts- und Tippfehlerprüfung in $O(1)$ ohne Datenbankabfrage.
- **Argon2id Passwort-Hashing**:
  - Speicherharter Schutz nach aktuellem BSI- und OWASP-Standard.
- **TOTP / MFA (RFC 6238)**:
  - 6-stellige zeitbasierte Einmalpasswörter mit Zeittoleranz und Schutz vor Wiederverwendung.

---

## 2. Verwendung in Rust-Projekten

### Abhängigkeit hinzufügen
```toml
[dependencies]
sb-auth = { path = "../sb-auth" }
```

### Initialisierung & Session-Ausstellung
```rust
use std::sync::Arc;
use sb_auth::prelude::*;

// 1. Schlüsselpaar & Revocation Store laden
let keypair = Keypair::generate();
let store = Arc::new(MemoryRevocationStore::new()); // oder FileRevocationStore::open("~/.sb/auth.json")?
let engine = AuthEngine::new(keypair, store);

// 2. Sitzung für Benutzer ausstellen (Access + Refresh Token)
let session = engine.issue_session(
    "alice",
    vec!["developer".to_string()],
    vec!["code:write".to_string(), "stream:*".to_string()],
    serde_json::json!({ "team": "core" }),
)?;

println!("Access Token: {}", session.access_token);
println!("Refresh Token: {}", session.refresh_token);
```

### Token-Verifikation & Autorisierung
```rust
// Verifikation mit Signaturprüfung & mehrstufigem Revocation-Check
let claims = engine.authorize(&session.access_token, Some("developer"), Some("code:write"))?;
println!("Angemeldet als: {}", claims.subject);

// Token gezielt widerrufen:
engine.revoke_token(&claims.token_id, claims.expires_at, "Manuell beendet")?;

// Oder alle Geräte von Alice abmelden:
engine.revoke_all_user_sessions("alice")?;
```

### HTTP-Middleware Helper
```rust
use sb_auth::middleware::authorize_header;

// Extrahiert 'Bearer sbt....' aus dem Header und prüft Rechte:
let claims = authorize_header(&engine, "Bearer sbt....", None, Some("code:write"))?;
```

---

## 3. CLI Cheatsheet (`sb-auth`)

```bash
# Schlüsselpaar erzeugen:
sb-auth keygen --out private.key

# Token ausstellen:
sb-auth token issue --sub alice --roles admin,dev --caps code:write --ttl 900

# Token inspizieren:
sb-auth token inspect sbt....

# Token mit Public Key verifizieren:
sb-auth token verify sbt.... --pubkey <base64-pubkey>

# Token oder Session widerrufen:
sb-auth revoke token sbt_acc_123 --reason "Compromised"
sb-auth revoke session sbs_456
sb-auth revoke user alice

# API-Key erzeugen und validieren:
sb-auth apikey issue --env live
sb-auth apikey verify sba_live_...

# Passwort hashen / prüfen:
sb-auth hash password "MeinGeheimesPasswort"
sb-auth hash verify "MeinGeheimesPasswort" "$argon2id$v=19$..."

# TOTP / 2FA:
sb-auth totp generate-secret
sb-auth totp generate <secret>
sb-auth totp verify <secret> 123456

# UI-Formulare Vorschau & Export:
sb-auth ui preview --port 3030 --primary "#00f0ff"
sb-auth ui export --out login.html
```

---

## 4. UI-Formulare & Frontend-Integration

`sb-auth` liefert fertige, anpassbare Auth-Formulare sowohl für reine Rust-Backends als auch für moderne React/TypeScript-Webapps:

### Option A: Embedded HTML (Zero-Setup in Rust)
Für Entwickler, die kein Node.js/Frontend bauen möchten:
```rust
use sb_auth::ui::{render_login_page, UiConfig};

let mut cfg = UiConfig::default();
cfg.title = "MEIN SOVEREIGN SERVICE".to_string();
cfg.primary_color = "#00f0ff".to_string();

// In Axum, Actix oder Rocket direkt als HTML ausliefern:
let html_response = render_login_page(&cfg);
```

### Option B: REST / JSON API Integration
Für Single-Page-Applications und externe Web-Frontends stellt `sb-auth` standardisierte JSON-Endpunkte bereit:
```json
POST /api/auth/login
{
  "username": "alice",
  "password": "..."
}

// Response:
{
  "token": "...",
  "requires_mfa": false,
  "expires_at": 1729000000
}
```
*(Hinweis: Frühere UI-Pakete wie `@skulls-and-bones/ui` wurden als separates externes Satelliten-Paket ausgelagert).*


