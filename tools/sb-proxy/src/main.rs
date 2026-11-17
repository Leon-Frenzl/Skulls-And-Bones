use clap::{Parser, Subcommand};
use colored::*;
use sb_proxy::ca::DeveloperCa;
use sb_proxy::config::ProxyConfig;
use sb_proxy::escape::verify_domain_dns;
use sb_proxy::tui::run_tui;

#[derive(Parser)]
#[command(
    name = "sb-proxy",
    author = "Skulls & Bones Lab <dev@skulls-and-bones.org>",
    version = "0.1.0",
    about = "S&B Proxy — Sovereign Pure-Rust Reverse-Proxy & Edge Gateway",
    long_about = "Sovereign Pure-Rust Reverse-Proxy und Edge Gateway für Skulls & Bones. Verbindet gekaufte Domains mit lokalen Node-Ports ohne P2P-Mesh Leaks."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Listet alle registrierten Escape Spaces und Egress-Routen auf
    List,

    /// Bindet eine neue Domain an einen lokalen Dienst-Port (mit automatischer Dienst-Erkennung)
    Add {
        /// Öffentliche Domain (z. B. app.meinedomain.de)
        domain: String,
        /// Lokaler Port des Dienstes (z. B. 3000). Wenn weggelassen, wird 127.0.0.1 automatisch gescannt.
        target_port: Option<u16>,
        /// Optionaler Alias (z. B. www.meinedomain.de) für automatischen 301-Redirect
        #[arg(long)]
        alias: Option<String>,
        /// Node Callsign (Standard: hostinger-node)
        #[arg(short, long, default_value = "hostinger-node")]
        node: String,
        /// Erzwingt sb-auth Sovereign Token Authentisierung für diese Route
        #[arg(long)]
        auth: bool,
        /// Erforderliche sb-auth Rolle (impliziert --auth)
        #[arg(long)]
        role: Option<String>,
        /// Erforderliche sb-auth Capability (impliziert --auth)
        #[arg(long)]
        capability: Option<String>,
    },

    /// Konfiguriert sb-auth Zugriffsschutz (Token, Rolle, Capability) für eine bestehende Route
    Protect {
        /// Domain oder ID der Route
        target: String,
        /// Erforderliche sb-auth Rolle
        #[arg(long)]
        role: Option<String>,
        /// Erforderliche sb-auth Capability
        #[arg(long)]
        capability: Option<String>,
        /// Deaktiviert den Auth-Schutz wieder (macht die Route öffentlich)
        #[arg(long)]
        disable: bool,
    },

    /// Veröffentlicht ein statisches Verzeichnis auf einer Domain (ohne Upstream-Prozess)
    Static {
        /// Öffentliche Domain
        domain: String,
        /// Explizit freizugebendes Verzeichnis (Index: index.html)
        directory: String,
        /// Node Callsign
        #[arg(short, long, default_value = "hostinger-node")]
        node: String,
    },

    /// Erzeugt eine temporäre Preview-Subdomain mit automatischer Ablaufzeit (TTL)
    Preview {
        /// Öffentliche Preview-Domain (z. B. pr-42.meinedomain.de)
        domain: String,
        /// Lokaler Port des Preview-Servers (z. B. 3001)
        target_port: u16,
        /// Gültigkeitsdauer in Stunden (Standard: 48h)
        #[arg(long, default_value_t = 48)]
        ttl: u64,
        /// Node Callsign
        #[arg(short, long, default_value = "hostinger-node")]
        node: String,
    },

    /// Schaltet den Wartungsmodus ein oder aus (liefert HTTP 503 mit Retry-After)
    Maintenance {
        /// Domain oder ID der Route
        target: String,
        /// Optionale Wartungsnachricht
        #[arg(short, long, alias = "msg")]
        message: Option<String>,
        /// Deaktiviert den Wartungsmodus wieder
        #[arg(long)]
        disable: bool,
    },

    /// Fügt einer bestehenden Route einen Alias mit automatischem 301-Redirect hinzu
    Alias {
        /// Hauptdomain oder ID
        target: String,
        /// Neuer Alias (z. B. www.meinedomain.de)
        alias: String,
    },

    /// Entfernt eine Route anhand ihrer Domain oder ID
    Remove {
        /// Domain oder ID der Route
        target: String,
    },

    /// Pausiert eine Route (Instant Killswitch: liefert sofort 503)
    Pause {
        /// Domain oder ID der Route
        target: String,
    },

    /// Startet das einheitliche Open Graph API Gateway (/v1/*) & die Web-Management-Konsole
    Graph {
        /// Bind-Adresse für API & Console (Standard: 127.0.0.1:8090)
        #[arg(long, default_value = "127.0.0.1:8090")]
        bind: std::net::SocketAddr,
        /// Upstream Domain Controller Adresse (Standard: 127.0.0.1:8443)
        #[arg(long, default_value = "127.0.0.1:8443")]
        dc: std::net::SocketAddr,
        /// Verzeichnis der gebauten Web-Console (Standard: console/dist)
        #[arg(long, default_value = "console/dist")]
        console_dir: std::path::PathBuf,
    },

    /// Reaktiviert eine pausierte Route
    Resume {
        /// Domain oder ID der Route
        target: String,
    },

    /// Legt eine öffentliche Domain für einen Mesh-Website-Tunnel auf diesem Gateway an
    TunnelRoute {
        #[command(subcommand)]
        action: TunnelRouteAction,
    },

    /// Veröffentlicht einen lokalen Produktionsserver durch den Mesh-Tunnel zum Gateway
    Link {
        /// Domain der zuvor auf dem Gateway eingerichteten Tunnel-Route
        domain: String,
        /// Lokaler Produktionsport
        local_port: u16,
        /// Entwickler-Callsign für die Tunnel-Verbindung
        #[arg(long)]
        callsign: Option<String>,
        /// Callsign des Gateway-Nodes
        #[arg(short, long, default_value = "hostinger-node")]
        node: String,
    },

    /// Überprüft den DNS A-Record einer Domain gegen die Node-IP
    Check {
        /// Zu prüfende Domain
        domain: String,
        /// Erwartete Node IP (Standard: 192.0.2.1)
        #[arg(long, default_value = "192.0.2.1")]
        ip: String,
    },

    /// Schaltet den Zielport einer Route im laufenden Betrieb unterbrechungsfrei um (Blue-Green Deployment)
    Switch {
        /// Domain oder ID der Route
        target: String,
        /// Neuer lokaler Zielport (z. B. 3001)
        port: u16,
    },

    /// Startet das Gateway (HTTP:80 -> HTTPS:443 und optional ACME TLS-ALPN-01)
    Start {
        /// HTTP-Bind-Adresse für den automatischen 301-HTTPS-Redirect
        #[arg(long, default_value = "0.0.0.0:80")]
        http_bind: String,

        /// Gateway Bind-Adresse (Haupt-Gateway für Traffic)
        #[arg(short, long, default_value = "0.0.0.0:443")]
        bind: String,

        /// Optionaler Pfad zu einem globalen Fallback-PEM-Zertifikat
        #[arg(long, requires = "key")]
        cert: Option<String>,

        /// Optionaler Pfad zu einem globalen privaten Fallback-PEM-Schlüssel
        #[arg(long, requires = "cert")]
        key: Option<String>,

        /// Aktiviert Let's Encrypt ACME TLS-ALPN-01 für alle TLS-Routen
        #[arg(long)]
        acme_email: Option<String>,

        /// Verwendet die produktive Let's-Encrypt-CA statt Staging
        #[arg(long, requires = "acme_email")]
        acme_production: bool,
    },

    /// Listet TLS-Zertifikate und importiert eigene PEMs; ACME-Erneuerung läuft im Gateway
    Certs {
        #[command(subcommand)]
        action: CertCommands,
    },

    /// Verwaltet die lokale S&B Developer Root-CA für Zero-Warning HTTPS (mkcert-Alternative)
    Ca {
        #[command(subcommand)]
        action: CaCommands,
    },

    /// Öffnet das interaktive Ratatui Terminal-Cockpit
    Tui,
}

#[derive(Subcommand)]
enum TunnelRouteAction {
    /// Erlaubt die Domain auf diesem Gateway für eingehende sb proxy link Tunnel
    Add {
        /// Öffentliche Domain
        domain: String,
        /// Callsign des Gateway-Nodes
        #[arg(short, long, default_value = "hostinger-node")]
        node: String,
    },
}

#[derive(Subcommand)]
pub enum CaCommands {
    /// Initialisiert die Sovereign Developer Root-CA (~/.sb/ca/root_ca.crt)
    Init {
        /// Überschreibt eine bereits existierende Root-CA
        #[arg(short, long)]
        force: bool,
    },
    /// Installiert die Root-CA im lokalen OS-Trust-Store (Windows CurrentUser, macOS Keychain, Linux)
    Install,
    /// Entfernt die Root-CA aus dem lokalen OS-Trust-Store
    Uninstall,
    /// Stellt ein lokales TLS-Zertifikat für Entwicklungs-Domains oder IP-Adressen aus
    Issue {
        /// Eine oder mehrere Domains oder IPs (z. B. localhost 127.0.0.1 app.local *.test)
        #[arg(required = true)]
        domains: Vec<String>,
        /// Gültigkeitsdauer in Tagen (Standard: 365)
        #[arg(short, long, default_value_t = 365)]
        days: u32,
    },
    /// Listet alle ausgestellten Entwickler-Zertifikate auf
    List,
    /// Zeigt den Diagnose-Status der Developer Root-CA an
    Status,
}

#[derive(Subcommand)]
pub enum CertCommands {
    /// Listet alle Zertifikate mit Restlaufzeit, Aussteller und Gültigkeit auf
    List,
    /// Importiert ein eigenes Zertifikat und privaten Schlüssel (PEM)
    Import {
        /// Domain oder ID der Route
        domain: String,
        /// Pfad zum PEM-Zertifikat (.crt / .pem / fullchain.pem)
        #[arg(short, long)]
        cert: String,
        /// Pfad zum privaten PEM-Schlüssel (.key / privkey.pem)
        #[arg(short, long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Tui) => {
            if let Err(e) = run_tui() {
                eprintln!("{} {}", "Fehler im TUI Cockpit:".red().bold(), e);
            }
        }
        Some(Commands::List) => {
            let spaces = ProxyConfig::load_spaces();
            println!(
                "\n{}",
                "🛡️  S&B PROXY — REGISTRIERTE EGRESS-ROUTEN".cyan().bold()
            );
            println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
            if spaces.is_empty() {
                println!(
                    "{}",
                    "Keine aktiven Escape Spaces vorhanden. Lege einen an mit:".yellow()
                );
                println!("  sb proxy add <domain> [port]");
            } else {
                println!(
                    "{:<30} {:<18} {:<22} {:<15}",
                    "DOMAIN & ALIASES".bold(),
                    "AIRGAP-ZIEL".bold(),
                    "STATUS".bold(),
                    "NODE".bold()
                );
                println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                for s in spaces {
                    let status_str = match s.status {
                        sb_proxy::escape::EscapeStatus::Active => {
                            if let Some(ref exp) = s.expires_at {
                                format!("⏳ PREVIEW (bis {})", &exp[11..16]).bright_cyan()
                            } else {
                                "🟢 LIVE (200 OK)".green()
                            }
                        }
                        sb_proxy::escape::EscapeStatus::Paused => "⏸️ PAUSED (503)".yellow(),
                        sb_proxy::escape::EscapeStatus::Maintenance => {
                            "🛠️ WARTUNG (503)".bright_magenta()
                        }
                        sb_proxy::escape::EscapeStatus::DnsPending => {
                            "⏳ DNS PENDING".bright_yellow()
                        }
                        sb_proxy::escape::EscapeStatus::Error(e) => {
                            format!("❌ FEHLER: {}", e).red()
                        }
                    };

                    let domain_display = if s.aliases.is_empty() {
                        s.domain.white().bold().to_string()
                    } else {
                        format!(
                            "{} (+{})",
                            s.domain.white().bold(),
                            s.aliases.join(", ").dimmed()
                        )
                    };
                    let target_display = s.static_root.as_ref().map_or_else(
                        || format!("127.0.0.1:{}", s.target_port),
                        |root| format!("static: {}", root),
                    );

                    let auth_badge = if s.auth_required
                        || s.required_role.is_some()
                        || s.required_capability.is_some()
                    {
                        let mut parts = Vec::new();
                        if let Some(ref r) = s.required_role {
                            parts.push(format!("role={r}"));
                        }
                        if let Some(ref c) = s.required_capability {
                            parts.push(format!("cap={c}"));
                        }
                        if parts.is_empty() {
                            " [AUTH]".bright_yellow().to_string()
                        } else {
                            format!(" [AUTH: {}]", parts.join(", "))
                                .bright_yellow()
                                .to_string()
                        }
                    } else {
                        String::new()
                    };

                    println!(
                        "{:<30} {:<36} {:<22} {:<15}{}",
                        domain_display,
                        target_display.cyan(),
                        status_str,
                        s.node_callsign.dimmed(),
                        auth_badge
                    );
                }
            }
            println!();
        }
        Some(Commands::Add {
            domain,
            target_port,
            alias,
            node,
            auth,
            role,
            capability,
        }) => {
            let resolved_port = match target_port {
                Some(p) => p,
                None => {
                    println!("🔍 Scanne 127.0.0.1 nach aktiven Webdiensten...");
                    let discovered = sb_proxy::discovery::discover_active_services();
                    if discovered.is_empty() {
                        println!("Kein aktiver Dev-Server erkannt. Nutze Standardport 3000.");
                        3000
                    } else {
                        println!("Erkannte aktive Dienste:");
                        for (i, d) in discovered.iter().enumerate() {
                            println!("  [{}] Port {} ({})", i + 1, d.port, d.hint);
                        }
                        let selected = discovered[0].port;
                        println!(
                            "Wähle automatisch: Port {}",
                            selected.to_string().cyan().bold()
                        );
                        selected
                    }
                }
            };

            match ProxyConfig::add_route(&domain, resolved_port, &node) {
                Ok(mut space) => {
                    if auth || role.is_some() || capability.is_some() {
                        match ProxyConfig::set_auth(
                            &space.domain,
                            true,
                            role.clone(),
                            capability.clone(),
                        ) {
                            Ok(updated) => space = updated,
                            Err(e) => {
                                eprintln!(
                                    "{} Auth-Schutz konnte nicht gesetzt werden: {}",
                                    "❌ Fehler:".red().bold(),
                                    e
                                );
                                std::process::exit(1);
                            }
                        }
                    }
                    println!(
                        "\n{}",
                        "✅ Escape Space erfolgreich angelegt!".green().bold()
                    );
                    println!("  Domain:       {}", space.domain.cyan().bold());
                    println!(
                        "  Airgap Ziel:  {}",
                        format!("127.0.0.1:{}", space.target_port).yellow()
                    );
                    if space.auth_required {
                        println!(
                            "  Auth-Schutz:  {} (role={:?}, cap={:?})",
                            "AKTIV (sb-auth)".green().bold(),
                            space.required_role.as_deref().unwrap_or("-"),
                            space.required_capability.as_deref().unwrap_or("-")
                        );
                    }
                    println!("  Node:         {}", space.node_callsign);
                    println!("  Status:       {}", "DnsPending".bright_yellow());

                    if let Some(ref a) = alias {
                        let _ = ProxyConfig::add_alias(&space.domain, a);
                        println!(
                            "  Alias:        {} (301 Canonical Redirect)",
                            a.white().bold()
                        );
                    }

                    println!("\n{}", "DNS-Konfiguration bei deinem Registrar:".bold());
                    println!("  Typ:   A");
                    println!("  Host:  @");
                    println!("  Ziel:  <DEINE_SERVER_IP>\n");
                }
                Err(err) => {
                    eprintln!("\n{} {}\n", "❌ Fehler beim Anlegen:".red().bold(), err);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Protect {
            target,
            role,
            capability,
            disable,
        }) => match ProxyConfig::set_auth(&target, !disable, role, capability) {
            Ok(space) => {
                if space.auth_required {
                    println!(
                        "{} sb-auth Schutz für {} aktiviert (role={}, cap={}).",
                        "🔒".green(),
                        space.domain.cyan().bold(),
                        space.required_role.as_deref().unwrap_or("-"),
                        space.required_capability.as_deref().unwrap_or("-")
                    );
                } else {
                    println!(
                        "{} sb-auth Schutz für {} deaktiviert (Route ist öffentlich).",
                        "🔓".yellow(),
                        space.domain.cyan().bold()
                    );
                }
            }
            Err(e) => {
                eprintln!("{} {}", "❌ Fehler:".red().bold(), e);
                std::process::exit(1);
            }
        },
        Some(Commands::Static {
            domain,
            directory,
            node,
        }) => {
            match ProxyConfig::add_static_site(&domain, std::path::Path::new(&directory), &node) {
                Ok(space) => {
                    println!("\n{} Statische Route angelegt.", "✓".green().bold());
                    println!("  Domain: {}", space.domain.cyan().bold());
                    println!(
                        "  Verzeichnis: {}",
                        space.static_root.as_deref().unwrap_or_default()
                    );
                    println!("  Node: {}", space.node_callsign);
                }
                Err(error) => {
                    eprintln!("Statische Route konnte nicht angelegt werden: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Preview {
            domain,
            target_port,
            ttl,
            node,
        }) => match ProxyConfig::add_preview(&domain, target_port, &node, ttl) {
            Ok(space) => {
                println!(
                    "\n{}",
                    "🚀 Ephemeral Preview Space aktiviert!".bright_cyan().bold()
                );
                println!("  Preview Domain: {}", space.domain.cyan().bold());
                println!(
                    "  Airgap Ziel:    {}",
                    format!("127.0.0.1:{}", space.target_port).yellow()
                );
                println!(
                    "  Gültig für:     {} Stunden",
                    ttl.to_string().white().bold()
                );
                println!(
                    "  Läuft ab um:    {}\n",
                    space.expires_at.unwrap_or_default()
                );
            }
            Err(err) => {
                eprintln!(
                    "\n{} {}\n",
                    "❌ Fehler beim Preview-Anlegen:".red().bold(),
                    err
                );
                std::process::exit(1);
            }
        },
        Some(Commands::Maintenance {
            target,
            message,
            disable,
        }) => {
            let enable = !disable;
            match ProxyConfig::set_maintenance(&target, message.clone(), enable) {
                Ok(_) => {
                    if enable {
                        println!(
                            "\n{} Wartungsmodus für '{}' aktiviert (HTTP 503 + Retry-After).",
                            "🛠️".yellow(),
                            target.bold()
                        );
                        if let Some(m) = message {
                            println!("  Nachricht: \"{}\"", m.dimmed());
                        }
                    } else {
                        println!(
                            "\n{} Wartungsmodus für '{}' beendet (Route wieder 200 OK).",
                            "🟢".green(),
                            target.bold()
                        );
                    }
                    println!();
                }
                Err(err) => {
                    eprintln!("\n{} {}\n", "❌ Fehler:".red().bold(), err);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Alias { target, alias }) => match ProxyConfig::add_alias(&target, &alias) {
            Ok(clean_alias) => {
                println!(
                    "\n{} Alias '{}' für Hauptdomain '{}' eingerichtet (301 Redirect).\n",
                    "🔗".green(),
                    clean_alias.bold(),
                    target
                );
            }
            Err(err) => {
                eprintln!(
                    "\n{} {}\n",
                    "❌ Fehler beim Hinzufügen des Alias:".red().bold(),
                    err
                );
                std::process::exit(1);
            }
        },
        Some(Commands::Remove { target }) => match ProxyConfig::remove_route(&target) {
            Ok(_) => {
                println!(
                    "\n{} Route '{}' wurde erfolgreich gelöscht.\n",
                    "🗑️".red(),
                    target
                );
            }
            Err(err) => {
                eprintln!("\n{} {}\n", "❌ Fehler:".red().bold(), err);
                std::process::exit(1);
            }
        },
        Some(Commands::Pause { target }) => match ProxyConfig::set_status(&target, false) {
            Ok(_) => {
                println!(
                    "\n{} Route '{}' wurde pausiert (Liefert ab sofort 503).\n",
                    "⏸️".yellow().bold(),
                    target
                );
            }
            Err(err) => {
                eprintln!("\n{} {}\n", "❌ Fehler:".red().bold(), err);
                std::process::exit(1);
            }
        },
        Some(Commands::Resume { target }) => match ProxyConfig::set_status(&target, true) {
            Ok(_) => {
                println!(
                    "\n{} Route '{}' ist wieder aktiv (200 OK).\n",
                    "🟢".green().bold(),
                    target
                );
            }
            Err(err) => {
                eprintln!("\n{} {}\n", "❌ Fehler:".red().bold(), err);
                std::process::exit(1);
            }
        },
        Some(Commands::TunnelRoute { action }) => match action {
            TunnelRouteAction::Add { domain, node } => {
                match ProxyConfig::add_tunnel_route(&domain, &node) {
                    Ok(space) => {
                        println!("\n{} Mesh-Tunnel-Route angelegt.", "✓".green().bold());
                        println!("  Domain: {}", space.domain.cyan().bold());
                        println!("  Gateway-Node: {}", space.node_callsign);
                        println!(
                            "\n{} DNS muss auf dieses Gateway zeigen; TLS wird durch sb-proxy verwaltet.",
                            "Hinweis:".yellow().bold()
                        );
                    }
                    Err(error) => {
                        eprintln!("Tunnel-Route konnte nicht angelegt werden: {error}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Some(Commands::Link {
            domain,
            local_port,
            callsign,
            node,
        }) => {
            let callsign = callsign.unwrap_or_else(sb_proxy::default_callsign);
            sb_proxy::run_escape_link(&domain, local_port, &callsign, &node).await?;
        }
        Some(Commands::Check { domain, ip }) => {
            println!("\n{} Löse DNS für '{}' auf...", "🔍".cyan(), domain);
            let is_match = verify_domain_dns(&domain, &ip);
            if is_match {
                println!(
                    "{} Die Domain '{}' zeigt korrekt auf Node-IP {}\n",
                    "✅ SUCCESS:".green().bold(),
                    domain,
                    ip
                );
            } else {
                println!(
                    "{} Die Domain '{}' zeigt noch nicht auf {} (DNS-Propagation abwarten).\n",
                    "⚠️ PENDING:".yellow().bold(),
                    domain,
                    ip
                );
            }
        }
        Some(Commands::Switch { target, port }) => match ProxyConfig::switch_port(&target, port) {
            Ok(space) => {
                println!(
                    "\n{} Zero-Downtime Port Switch erfolgreich!",
                    "🔄".cyan().bold()
                );
                println!("  Domain:       {}", space.domain.green().bold());
                println!(
                    "  Neues Ziel:   {}\n",
                    format!("127.0.0.1:{}", space.target_port).yellow().bold()
                );
            }
            Err(err) => {
                eprintln!("\n{} {}\n", "❌ Fehler beim Port-Switch:".red().bold(), err);
                std::process::exit(1);
            }
        },
        Some(Commands::Start {
            http_bind,
            bind,
            cert,
            key,
            acme_email,
            acme_production,
        }) => {
            if let (Some(c), Some(k)) = (&cert, &key) {
                println!("🔒 Explizite TLS-Zertifikatspfade: {} | {}", c, k);
            }
            let acme_store = sb_proxy::AcmeChallengeStore::new();
            let rate_limiter = sb_proxy::IpRateLimiter::new();
            let security_headers = sb_proxy::http_server::SecurityHeaders::from_env()?;
            let acme_email = acme_email.or_else(|| std::env::var("SB_ACME_EMAIL").ok());
            let acme_production = acme_production
                || std::env::var("SB_ACME_PRODUCTION")
                    .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
                    .unwrap_or(false);
            sb_proxy::proxy::run_dual_proxy_server_with_acme(
                &http_bind,
                &bind,
                acme_store,
                rate_limiter,
                cert,
                key,
                acme_email,
                acme_production,
                security_headers,
            )
            .await?;
        }
        Some(Commands::Certs { action }) => match action {
            CertCommands::List => {
                let certs = ProxyConfig::list_certificates();
                println!(
                    "\n{}",
                    "🔒 S&B PROXY — TLS-ZERTIFIKATE & ACME STATUS".cyan().bold()
                );
                println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                if certs.is_empty() {
                    println!(
                        "{}",
                        "Keine aktiven Escape Spaces mit TLS vorhanden.".yellow()
                    );
                } else {
                    println!(
                        "{:<30} {:<28} {:<28}",
                        "DOMAIN".bold(),
                        "STATUS / RESTTAGE".bold(),
                        "AUSSTELLER".bold()
                    );
                    println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                    for c in certs {
                        let status_str = match c.days_remaining() {
                            Some(days) if days > 30 => format!("🟢 {} Tage gültig", days).green(),
                            Some(days) if days > 0 => {
                                format!("⏳ {} Tage (Erneuerung bald)", days).yellow()
                            }
                            Some(_) => "❌ Abgelaufen".red().bold(),
                            None => "⚠️ Initial / Unbekannt".yellow(),
                        };
                        println!(
                            "{:<30} {:<28} {:<28}",
                            c.domain.white().bold(),
                            status_str,
                            c.issuer.bright_black()
                        );
                    }
                    println!();
                }
            }
            CertCommands::Import { domain, cert, key } => {
                match ProxyConfig::import_cert(&domain, &cert, &key) {
                    Ok(()) => {
                        println!(
                            "\n{} Eigenes PEM-Zertifikat für '{}' erfolgreich importiert!",
                            "✅".green().bold(),
                            domain
                        );
                        println!("  Zertifikat: {}", cert.cyan());
                        println!("  Schlüssel:  {}\n", key.cyan());
                    }
                    Err(err) => {
                        eprintln!("\n{} {}\n", "❌ Fehler beim Importieren:".red().bold(), err);
                        std::process::exit(1);
                    }
                }
            }
        },
        Some(Commands::Ca { action }) => {
            match action {
                CaCommands::Init { force } => match DeveloperCa::init_root_ca(force) {
                    Ok(status) => {
                        println!(
                            "\n{}",
                            "🔏 S&B DEVELOPER ROOT-CA ERFOLGREICH INITIALISIERT"
                                .green()
                                .bold()
                        );
                        println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                        println!(
                            "  Zertifikat: {}",
                            status.ca_cert_path.unwrap_or_default().cyan()
                        );
                        println!(
                            "  Schlüssel:  {}",
                            status.ca_key_path.unwrap_or_default().cyan()
                        );
                        println!(
                            "  Subject:    {}",
                            status.subject.unwrap_or_default().white()
                        );
                        println!("  Gültigkeit: 10 Jahre (ECDSA P-256 / SHA-256)\n");
                        println!("{}", "👉 Führe nun 'sb ca install' (oder 'sb proxy ca install') aus, um das Zertifikat im OS zu aktivieren.".yellow());
                    }
                    Err(err) => {
                        eprintln!(
                            "\n{} {}\n",
                            "❌ Fehler bei CA-Initialisierung:".red().bold(),
                            err
                        );
                        std::process::exit(1);
                    }
                },
                CaCommands::Install => match DeveloperCa::install_root_ca() {
                    Ok(msg) => {
                        println!("\n{} {}", "✅".green().bold(), msg.green().bold());
                        println!("  Alle von S&B signierten lokalen Domains (z. B. localhost, app.local) haben nun");
                        println!("  ein vertrauenswürdiges grünes Schloss im Browser ohne Warnhinweise!\n");
                    }
                    Err(err) => {
                        eprintln!("\n{} {}\n", "❌ Fehler bei Installation:".red().bold(), err);
                        std::process::exit(1);
                    }
                },
                CaCommands::Uninstall => match DeveloperCa::uninstall_root_ca() {
                    Ok(msg) => {
                        println!("\n{} {}\n", "✅".green().bold(), msg.green());
                    }
                    Err(err) => {
                        eprintln!(
                            "\n{} {}\n",
                            "❌ Fehler bei Deinstallation:".red().bold(),
                            err
                        );
                        std::process::exit(1);
                    }
                },
                CaCommands::Issue { domains, days } => {
                    match DeveloperCa::issue_certificate(&domains, days) {
                        Ok(meta) => {
                            println!(
                                "\n{}",
                                "🎉 NEUES ENTWICKLER-TLS-ZERTIFIKAT AUSGESTELLT"
                                    .green()
                                    .bold()
                            );
                            println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                            println!("  Hauptdomain: {}", meta.primary_domain.white().bold());
                            println!("  SANs / IPs:  {}", meta.alt_names.join(", ").cyan());
                            println!(
                                "  Gültig bis:  {} ({} Tage)",
                                meta.expires_at.yellow(),
                                days
                            );
                            println!("  Fullchain:   {}", meta.cert_path.cyan());
                            println!("  Schlüssel:   {}\n", meta.key_path.cyan());
                        }
                        Err(err) => {
                            eprintln!(
                                "\n{} {}\n",
                                "❌ Fehler beim Ausstellen des Zertifikats:".red().bold(),
                                err
                            );
                            std::process::exit(1);
                        }
                    }
                }
                CaCommands::List => {
                    let certs = DeveloperCa::list_certificates();
                    println!(
                        "\n{}",
                        "🔏 S&B DEVELOPER CA — AUSGESTELLTE ZERTIFIKATE"
                            .cyan()
                            .bold()
                    );
                    println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                    if certs.is_empty() {
                        println!("{}", "Noch keine Entwickler-Zertifikate ausgestellt. Nutze 'sb ca issue <domain>'.".yellow());
                    } else {
                        println!(
                            "{:<24} {:<34} {:<24}",
                            "PRIMARY DOMAIN".bold(),
                            "SUBJECT ALTERNATIVE NAMES (SAN)".bold(),
                            "GÜLTIG BIS".bold()
                        );
                        println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                        for c in certs {
                            println!(
                                "{:<24} {:<34} {:<24}",
                                c.primary_domain.white().bold(),
                                c.alt_names.join(", ").bright_black(),
                                c.expires_at.green()
                            );
                        }
                        println!();
                    }
                }
                CaCommands::Status => {
                    let status = DeveloperCa::get_ca_status();
                    println!(
                        "\n{}",
                        "🔏 S&B DEVELOPER CA — STATUS & DIAGNOSE".cyan().bold()
                    );
                    println!("{}", "──────────────────────────────────────────────────────────────────────────────────────────".bright_black());
                    let init_badge = if status.initialized {
                        "🟢 Initialisiert".green().bold()
                    } else {
                        "❌ Nicht initialisiert (Führe 'sb ca init' aus)"
                            .red()
                            .bold()
                    };
                    let os_badge = if status.is_installed_in_os {
                        "🟢 Im OS-Trust-Store installiert".green().bold()
                    } else {
                        "⚠️ Nicht im OS-Trust-Store (Führe 'sb ca install' aus)"
                            .yellow()
                            .bold()
                    };

                    println!("  CA Status:      {}", init_badge);
                    println!("  OS Trust Store: {}", os_badge);
                    if let Some(subject) = status.subject {
                        println!("  Subject:        {}", subject.white());
                    }
                    if let Some(crt) = status.ca_cert_path {
                        println!("  Zertifikat:     {}", crt.cyan());
                    }
                    println!(
                        "  Zertifikate:    {} ausgestellt\n",
                        status.issued_certs_count.to_string().yellow().bold()
                    );
                }
            }
        }
        Some(Commands::Graph {
            bind,
            dc,
            console_dir,
        }) => {
            let auth_dir = sb_core::paths::sb_home().join("auth");
            let verifier = std::fs::read_to_string(auth_dir.join("auth.pub"))
                .ok()
                .and_then(|pub_b64| {
                    sb_auth::FileRevocationStore::open(auth_dir.join("revocations.json"))
                        .ok()
                        .and_then(|rev| {
                            sb_auth::AuthVerifier::from_public_base64(
                                &pub_b64,
                                std::sync::Arc::new(rev),
                            )
                            .ok()
                        })
                })
                .map(std::sync::Arc::new);

            println!(
                "\n{} Open Graph API Gateway & Console läuft auf http://{}",
                "✓".green().bold(),
                bind
            );
            println!("  ► OpenAPI 3.1:  http://{}/v1/openapi.json", bind);
            println!("  ► DC Upstream:  {}", dc);
            println!("  ► Console Dir:  {}\n", console_dir.display());

            let cfg = sb_proxy::graph_api::GraphGatewayConfig {
                bind,
                dc_addr: dc,
                console_dist_dir: Some(console_dir),
            };
            if let Err(err) = sb_proxy::graph_api::serve_graph_gateway(cfg, verifier).await {
                eprintln!("{} Graph Gateway Fehler: {err}", "✗".red().bold());
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
