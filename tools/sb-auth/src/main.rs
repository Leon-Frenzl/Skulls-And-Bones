use base64::Engine;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

use sb_auth::prelude::*;

#[derive(Parser)]
#[command(
    name = "sb-auth",
    about = "S&B Auth — Sovereign Authentication, Multi-Tier Revocation & Identity CLI",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialisiert ~/.sb/auth/ (Ed25519 Keypair + Public Key + Revocation Store) für sb-auth und sb-proxy
    Init {
        /// Überschreibt bestehende Schlüssel in ~/.sb/auth/
        #[arg(long)]
        force: bool,
    },

    /// Generiert ein neues kryptografisches Ed25519-Schlüsselpaar
    Keygen {
        #[arg(short, long, help = "Optionaler Pfad zum Speichern des Secret Keys")]
        out: Option<PathBuf>,
    },

    /// Befehle zur Arbeit mit Sovereign Tokens (sbt.*)
    Token {
        #[command(subcommand)]
        cmd: TokenCommands,
    },

    /// Befehle zur Verwaltung von Widerrufen (Revocations)
    Revoke {
        #[command(subcommand)]
        cmd: RevokeCommands,
    },

    /// Befehle zur Erzeugung und Prüfung von prüfsummen-geschützten API-Keys
    Apikey {
        #[command(subcommand)]
        cmd: ApiKeyCommands,
    },

    /// Befehle für Argon2id Passwort-Hashing
    Hash {
        #[command(subcommand)]
        cmd: HashCommands,
    },

    /// Befehle für TOTP / Zwei-Faktor-Authentifizierung (RFC 6238)
    Totp {
        #[command(subcommand)]
        cmd: TotpCommands,
    },

    /// Befehle für anpassbare Login- und Auth-Webformulare
    Ui {
        #[command(subcommand)]
        cmd: UiCommands,
    },

    /// Zeigt den vereinheitlichten Identitäts-, Revocation- und PKI-Status (sb-ca)
    Status {
        /// Maschinenlesbare JSON-Ausgabe (RFC 8259)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum UiCommands {
    /// Startet einen lokalen Vorschau-Server im Browser
    Preview {
        #[arg(
            short,
            long,
            default_value = "3030",
            help = "HTTP Port (Standard: 3030)"
        )]
        port: u16,
        #[arg(
            long,
            default_value = "#00f0ff",
            help = "Primärfarbe (Hex, z. B. #00f0ff)"
        )]
        primary: String,
        #[arg(long, default_value = "SKULLS & BONES", help = "Titel")]
        title: String,
    },

    /// Exportiert das anpassbare Login-HTML in eine eigenständige Datei
    Export {
        #[arg(short, long, default_value = "login.html", help = "Zieldatei")]
        out: PathBuf,
        #[arg(long, default_value = "#00f0ff", help = "Primärfarbe (Hex)")]
        primary: String,
        #[arg(long, default_value = "SKULLS & BONES", help = "Titel")]
        title: String,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Stellt einen neuen signierten Sovereign Token aus
    Issue {
        #[arg(short, long, help = "Subjekt / Benutzerkennung")]
        sub: String,
        #[arg(long, help = "Kommaseparierte Rollen (z. B. 'admin,developer')")]
        roles: Option<String>,
        #[arg(
            long,
            help = "Kommaseparierte Berechtigungen (z. B. 'code:write,mesh:connect')"
        )]
        caps: Option<String>,
        #[arg(
            long,
            default_value = "900",
            help = "Gültigkeitsdauer in Sekunden (Standard: 900 = 15 Min)"
        )]
        ttl: i64,
        #[arg(
            long,
            help = "Secret Key im URL-Safe Base64 Format (falls ausgelassen wird ein ephemerer Key generiert)"
        )]
        secret_key: Option<String>,
    },

    /// Zeigt den Inhalt eines Tokens an (ohne Signaturprüfung)
    Inspect {
        #[arg(help = "Sovereign Token String (sbt....)")]
        token: String,
    },

    /// Verifiziert die kryptografische Signatur und Gültigkeit eines Tokens
    Verify {
        #[arg(help = "Sovereign Token String (sbt....)")]
        token: String,
        #[arg(short, long, help = "Public Key im URL-Safe Base64 Format")]
        pubkey: String,
    },
}

#[derive(Subcommand)]
enum RevokeCommands {
    /// Widerruft einen einzelnen Token über seine Token-ID (jti)
    Token {
        #[arg(help = "Token-ID (z. B. sbt_acc_...)")]
        token_id: String,
        #[arg(
            long,
            default_value = "86400",
            help = "TTL für die Revocation in Sekunden"
        )]
        ttl: i64,
        #[arg(
            long,
            default_value = "Admin revocation",
            help = "Begründung für den Widerruf"
        )]
        reason: String,
        #[arg(
            long,
            help = "Pfad zur Revocation-Datenbank (Standard: ~/.sb/auth_revocations.json)"
        )]
        db: Option<PathBuf>,
    },

    /// Widerruft eine gesamte Session
    Session {
        #[arg(help = "Session-ID (z. B. sbs_...)")]
        session_id: String,
        #[arg(
            long,
            default_value = "604800",
            help = "TTL für die Revocation in Sekunden"
        )]
        ttl: i64,
        #[arg(
            long,
            default_value = "Session terminated",
            help = "Begründung für den Widerruf"
        )]
        reason: String,
        #[arg(
            long,
            help = "Pfad zur Revocation-Datenbank (Standard: ~/.sb/auth_revocations.json)"
        )]
        db: Option<PathBuf>,
    },

    /// Inkrementiert die Benutzer-Epoche (macht alle bisherigen Sessions des Benutzers ungültig)
    User {
        #[arg(help = "Benutzerkennung / Subject")]
        user_id: String,
        #[arg(
            long,
            help = "Pfad zur Revocation-Datenbank (Standard: ~/.sb/auth_revocations.json)"
        )]
        db: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ApiKeyCommands {
    /// Generiert einen neuen prüfsummen-geschützten API-Key
    Issue {
        #[arg(long, default_value = "live", help = "Umgebung: live, test oder dev")]
        env: String,
    },

    /// Prüft Format und Integritäts-Prüfsumme eines API-Keys
    Verify {
        #[arg(help = "API-Key (sba_...)")]
        key: String,
    },
}

#[derive(Subcommand)]
enum HashCommands {
    /// Hasht ein Passwort mit Argon2id
    Password {
        #[arg(help = "Klartext-Passwort")]
        password: String,
    },

    /// Verifiziert ein Passwort gegen einen Argon2id Hash
    Verify {
        #[arg(help = "Klartext-Passwort")]
        password: String,
        #[arg(help = "Argon2id Hash-String")]
        hash: String,
    },
}

#[derive(Subcommand)]
enum TotpCommands {
    /// Generiert ein neues zufälliges TOTP-Secret
    GenerateSecret,

    /// Berechnet den aktuellen 6-stelligen TOTP-Code für ein Secret
    Generate {
        #[arg(help = "Base64 Secret")]
        secret: String,
    },

    /// Verifiziert einen 6-stelligen TOTP-Code gegen ein Secret
    Verify {
        #[arg(help = "Base64 Secret")]
        secret: String,
        #[arg(help = "6-stelliger Code")]
        code: String,
    },
}

/// Resolves the canonical revocation database path via `sb_core::paths::sb_home()`.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Revocation bypass when `SB_HOME` is overridden but `sb-auth` writes to an uncoupled home path.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path), CWE-613 (Insufficient Session Expiration).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Resolves default revocation database strictly inside `sb_core::paths::sb_home()`.
/// - Standards Compliance: Conforms to IETF RFC 8259 (JSON).
fn resolve_db_path(custom: Option<PathBuf>) -> PathBuf {
    if let Some(p) = custom {
        p
    } else {
        sb_core::paths::sb_home().join("auth_revocations.json")
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { force } => {
            let auth_dir = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".sb")
                .join("auth");
            std::fs::create_dir_all(&auth_dir)?;
            let key_path = auth_dir.join("auth.key");
            let pub_path = auth_dir.join("auth.pub");
            let rev_path = auth_dir.join("revocations.json");

            if key_path.exists() && !force {
                return Err(format!(
                    "Auth-Schlüssel existiert bereits unter {}. Nutze --force zum Überschreiben.",
                    key_path.display()
                )
                .into());
            }

            let keypair = Keypair::generate();
            std::fs::write(&key_path, keypair.to_secret_base64())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            std::fs::write(&pub_path, keypair.to_public_base64())?;
            let _store = FileRevocationStore::open(&rev_path)?;

            println!(
                "{}",
                "═══ S&B AUTH // INITIALISIERT ═══".bright_cyan().bold()
            );
            println!("  ► Key ID (KID):    {}", keypair.key_id.yellow());
            println!(
                "  ► Secret Key:      {}",
                key_path.display().to_string().bright_black()
            );
            println!(
                "  ► Public Key:      {}",
                pub_path.display().to_string().green()
            );
            println!(
                "  ► Revocation DB:   {}",
                rev_path.display().to_string().cyan()
            );
        }

        Commands::Keygen { out } => {
            let keypair = Keypair::generate();
            let secret_b64 = keypair.to_secret_base64();
            let public_b64 = keypair.to_public_base64();

            println!(
                "{}",
                "═══ S&B AUTH // ED25519 SCHLÜSSELPAAR ═══"
                    .bright_cyan()
                    .bold()
            );
            println!("  ► Key ID (KID):   {}", keypair.key_id.yellow());
            println!("  ► Public Key:     {}", public_b64.green());
            println!("  ► Secret Key:     {}", secret_b64.bright_black());

            if let Some(path) = out {
                std::fs::write(&path, &secret_b64)?;
                println!(
                    "  ✓ Secret Key gespeichert in: {}",
                    path.display().to_string().cyan()
                );
            }
        }

        Commands::Token { cmd } => match cmd {
            TokenCommands::Issue {
                sub,
                roles,
                caps,
                ttl,
                secret_key,
            } => {
                let keypair = if let Some(sk) = secret_key {
                    Keypair::from_secret_base64(&sk)?
                } else if let Some(default_key) = dirs::home_dir()
                    .map(|h| h.join(".sb").join("auth").join("auth.key"))
                    .filter(|p| p.exists())
                {
                    let sk = std::fs::read_to_string(&default_key)?;
                    Keypair::from_secret_base64(sk.trim())?
                } else {
                    let kp = Keypair::generate();
                    eprintln!(
                        "  {} Kein Secret Key übergeben — verwende temporären Schlüssel (Tipp: 'sb-auth init').",
                        "i".bright_yellow()
                    );
                    eprintln!(
                        "  ► Temporärer Public Key: {}",
                        kp.to_public_base64().green()
                    );
                    kp
                };

                let roles_vec = roles
                    .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();
                let caps_vec = caps
                    .map(|c| c.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();

                let now = chrono::Utc::now().timestamp();
                let claims = SovereignClaims {
                    token_id: format!("sbt_{}_{:08x}", now, rand::random::<u32>()),
                    token_type: TokenType::Access,
                    subject: sub,
                    session_id: Some(format!("sbs_{}_{:08x}", now, rand::random::<u32>())),
                    user_epoch: 0,
                    roles: roles_vec,
                    capabilities: caps_vec,
                    audience: None,
                    issuer: "sb-auth-cli".to_string(),
                    issued_at: now,
                    not_before: now,
                    expires_at: now + ttl,
                    metadata: serde_json::Value::Null,
                };

                let token = TokenEncoder::encode(&claims, &keypair)?;
                println!(
                    "{}",
                    "═══ S&B SOVEREIGN TOKEN AUSGESTELLT ═══"
                        .bright_green()
                        .bold()
                );
                println!("  ► Token ID:    {}", claims.token_id.yellow());
                println!("  ► Subject:     {}", claims.subject.cyan());
                println!(
                    "  ► Gültig bis:  {}",
                    chrono::DateTime::from_timestamp(claims.expires_at, 0).unwrap_or_default()
                );
                println!();
                println!("{}", token.bright_white().bold());
            }

            TokenCommands::Inspect { token } => {
                let (header, claims) = TokenDecoder::inspect(&token)?;
                println!("{}", "═══ S&B TOKEN INSPEKTION ═══".bright_cyan().bold());
                println!("  ► Version:     {}", header.ver);
                println!("  ► Algorithmus: {}", header.alg);
                println!("  ► Key ID:      {}", header.kid.yellow());
                println!("  ──────────────────────────────────────────");
                println!("  ► Token ID:    {}", claims.token_id.yellow());
                println!("  ► Typ:         {:?}", claims.token_type);
                println!("  ► Subject:     {}", claims.subject.cyan());
                if let Some(session) = &claims.session_id {
                    println!("  ► Session:     {}", session);
                }
                println!("  ► User Epoch:  {}", claims.user_epoch);
                println!("  ► Rollen:      {:?}", claims.roles);
                println!("  ► Caps:        {:?}", claims.capabilities);
                println!(
                    "  ► Gültig ab:   {}",
                    chrono::DateTime::from_timestamp(claims.not_before, 0).unwrap_or_default()
                );
                println!(
                    "  ► Ablauf:      {}",
                    chrono::DateTime::from_timestamp(claims.expires_at, 0).unwrap_or_default()
                );
                let now = chrono::Utc::now().timestamp();
                if claims.expires_at < now {
                    println!("  ► Status:      {}", "ABGELAUFEN".red().bold());
                } else {
                    println!("  ► Status:      {}", "GÜLTIG".green().bold());
                }
            }

            TokenCommands::Verify { token, pubkey } => {
                let verifying_key = sb_auth::crypto::parse_public_key(&pubkey)?;
                match TokenDecoder::decode_and_verify(&token, &verifying_key) {
                    Ok((_header, claims)) => {
                        let now = chrono::Utc::now().timestamp();
                        if let Err(e) = claims.validate_time(now, 5) {
                            println!(
                                "  ✗ {}",
                                format!(
                                    "Signatur gültig, aber Zeitvalidierung fehlgeschlagen: {e}"
                                )
                                .red()
                            );
                        } else {
                            println!(
                                "  ✓ {}",
                                "Token-Signatur und Zeitfenster ERFOLGREICH verifiziert!"
                                    .bright_green()
                                    .bold()
                            );
                            println!("  ► Subjekt: {}", claims.subject.cyan());
                            println!("  ► Rollen:  {:?}", claims.roles);
                        }
                    }
                    Err(e) => {
                        println!(
                            "  ✗ {}",
                            format!("Verifikation FEHLGESCHLAGEN: {e}").red().bold()
                        );
                    }
                }
            }
        },

        Commands::Revoke { cmd } => match cmd {
            RevokeCommands::Token {
                token_id,
                ttl,
                reason,
                db,
            } => {
                let db_path = resolve_db_path(db);
                let store = FileRevocationStore::open(&db_path)?;
                let expires_at = chrono::Utc::now().timestamp() + ttl;
                store.revoke_token(&token_id, expires_at, &reason)?;
                println!("  ✓ Token '{}' erfolgreich widerrufen.", token_id.yellow());
                println!(
                    "  ► Gespeichert in: {}",
                    db_path.display().to_string().cyan()
                );
            }

            RevokeCommands::Session {
                session_id,
                ttl,
                reason,
                db,
            } => {
                let db_path = resolve_db_path(db);
                let store = FileRevocationStore::open(&db_path)?;
                let expires_at = chrono::Utc::now().timestamp() + ttl;
                store.revoke_session(&session_id, expires_at, &reason)?;
                println!(
                    "  ✓ Session '{}' erfolgreich widerrufen.",
                    session_id.yellow()
                );
                println!(
                    "  ► Gespeichert in: {}",
                    db_path.display().to_string().cyan()
                );
            }

            RevokeCommands::User { user_id, db } => {
                let db_path = resolve_db_path(db);
                let store = FileRevocationStore::open(&db_path)?;
                let new_epoch = store.bump_user_epoch(&user_id)?;
                println!(
                    "  ✓ Epoch für Benutzer '{}' auf {} inkrementiert.",
                    user_id.cyan(),
                    new_epoch
                );
                println!(
                    "  ► Alle vorherigen Tokens von '{}' sind ab sofort ungültig!",
                    user_id.yellow()
                );
            }
        },

        Commands::Apikey { cmd } => match cmd {
            ApiKeyCommands::Issue { env } => {
                let e = ApiKeyEnv::from_str(&env).unwrap_or(ApiKeyEnv::Live);
                let key = ApiKey::generate(e);
                println!("{}", "═══ S&B API-KEY GENERIERT ═══".bright_green().bold());
                println!("  ► Umgebung:   {}", key.env.as_str().cyan());
                println!("  ► Prüfsumme:  {:08x}", key.checksum);
                println!();
                println!("{}", key.raw.bright_white().bold());
            }

            ApiKeyCommands::Verify { key } => match ApiKey::parse(&key) {
                Ok(parsed) => {
                    println!(
                        "  ✓ {}",
                        "API-Key Integrität und Prüfsumme BESTÄTIGT!"
                            .bright_green()
                            .bold()
                    );
                    println!("  ► Umgebung:  {}", parsed.env.as_str().cyan());
                    println!("  ► Prüfsumme: {:08x}", parsed.checksum);
                }
                Err(e) => {
                    println!("  ✗ {}", format!("API-Key UNGÜLTIG: {e}").red().bold());
                }
            },
        },

        Commands::Hash { cmd } => match cmd {
            HashCommands::Password { password } => {
                let hash = hash_password(&password)?;
                println!(
                    "{}",
                    "═══ S&B ARGON2ID PASSWORT-HASH ═══".bright_cyan().bold()
                );
                println!("{}", hash.bright_white());
            }

            HashCommands::Verify { password, hash } => match verify_password(&password, &hash) {
                Ok(()) => {
                    println!(
                        "  ✓ {}",
                        "Passwort stimmt mit Hash überein!".bright_green().bold()
                    );
                }
                Err(_) => {
                    println!(
                        "  ✗ {}",
                        "Passwort stimmt NICHT mit Hash überein!".red().bold()
                    );
                }
            },
        },

        Commands::Totp { cmd } => match cmd {
            TotpCommands::GenerateSecret => {
                let secret = generate_totp_secret();
                println!(
                    "{}",
                    "═══ S&B TOTP SECRET GENERIERT ═══".bright_cyan().bold()
                );
                println!("  ► Secret (Base64): {}", secret.bright_green().bold());
            }

            TotpCommands::Generate { secret } => {
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&secret)?;
                let now = chrono::Utc::now().timestamp();
                let code = generate_totp_code(&bytes, now, 30)?;
                println!("{}", "═══ AKTUELLER TOTP CODE ═══".bright_green().bold());
                println!("  Code: {}", code.bright_white().bold());
            }

            TotpCommands::Verify { secret, code } => {
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&secret)?;
                let now = chrono::Utc::now().timestamp();
                match verify_totp_code(&bytes, &code, now, 30, 1) {
                    Ok(step) => {
                        println!(
                            "  ✓ {}",
                            "TOTP-Code ERFOLGREICH bestätigt!".bright_green().bold()
                        );
                        println!("  ► Zeitschritt: {}", step);
                    }
                    Err(e) => {
                        println!("  ✗ {}", format!("TOTP-Code ABGEWIESEN: {e}").red().bold());
                    }
                }
            }
        },

        Commands::Ui { cmd } => match cmd {
            UiCommands::Preview {
                port,
                primary,
                title,
            } => {
                let mut cfg = UiConfig::default();
                cfg.primary_color = primary;
                cfg.title = title;
                println!(
                    "{}",
                    "═══ S&B AUTH // FORMULAR-VORSCHAU ═══".bright_cyan().bold()
                );
                println!("  Auth-UI auf http://127.0.0.1:{port}");
                sb_auth::ui::serve_preview(port, &cfg)?;
            }

            UiCommands::Export {
                out,
                primary,
                title,
            } => {
                let mut cfg = UiConfig::default();
                cfg.primary_color = primary;
                cfg.title = title;
                let html = render_login_page(&cfg);
                std::fs::write(&out, html)?;
                println!(
                    "  ✓ Login-Formular erfolgreich exportiert nach: {}",
                    out.display().to_string().cyan()
                );
            }
        },

        Commands::Status { json } => {
            let status = inspect_node_trust_status();
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            println!(
                "{}",
                "═══ S&B AUTH // IDENTITÄTS- & PKI-STATUS (sb-ca) ═══"
                    .bright_cyan()
                    .bold()
            );
            println!("  ► Sovereign Home:  {}", status.sb_home.bright_black());
            match (&status.identity_callsign, &status.node_fingerprint) {
                (Some(callsign), Some(fp)) => {
                    println!(
                        "  ► Node-Identität:  {} ({})",
                        callsign.bright_green().bold(),
                        fp.yellow()
                    );
                }
                _ => {
                    println!(
                        "  ► Node-Identität:  {}",
                        "NICHT INITIALISIERT ('sb identity')".bright_yellow()
                    );
                }
            }
            if status.ssh_ca_active {
                println!(
                    "  ► OpenSSH Root-CA: {} ({})",
                    "AKTIV".bright_green().bold(),
                    status.ssh_ca_pub_path.cyan()
                );
            } else {
                println!(
                    "  ► OpenSSH Root-CA: {} ('sb-ca init')",
                    "INAKTIV".bright_yellow()
                );
            }
            if status.x509_ca_active {
                println!(
                    "  ► X.509 Root-CA:   {} ({})",
                    "AKTIV".bright_green().bold(),
                    status.x509_root_crt_path.cyan()
                );
            } else {
                println!(
                    "  ► X.509 Root-CA:   {} ('sb-ca init')",
                    "INAKTIV".bright_yellow()
                );
            }
            println!(
                "  ► Revocation-DB:   {} ({})",
                if status.revocation_db_exists {
                    "AKTIV".bright_green()
                } else {
                    "BEREIT".bright_cyan()
                },
                status.revocation_db_path.bright_black()
            );
            if status.identity_callsign.is_none() || !status.ssh_ca_active || !status.x509_ca_active
            {
                println!(
                    "  ► Fix with:        {}",
                    "sb up --fix".bright_cyan().bold()
                );
            }
        }
    }

    Ok(())
}
