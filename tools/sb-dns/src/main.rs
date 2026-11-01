use clap::{Parser, Subcommand};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use sb_dns::client::query_server;
use sb_dns::config::ConfigManager;
use sb_dns::os_integration::OsIntegration;
use sb_dns::resolver::DnsResolver;
use sb_dns::server::DnsServer;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Parser)]
#[command(name = "sb-dns")]
#[command(
    about = "ðŸ’€ Sovereign Mesh DNS â€” System-wide .sbm Split-DNS Resolver & Mesh Router",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the sovereign DNS server listener
    Serve {
        /// Custom socket address to bind (e.g. 127.0.0.1:53 or 127.0.0.1:58853)
        #[arg(short, long)]
        bind: Option<SocketAddr>,
    },

    /// Run a DNS query against the local resolver or specified server (dig/nslookup replacement)
    Query {
        /// Domain name to resolve (e.g. gateway.sbm or google.com)
        domain: String,

        /// DNS server address to query (default: 127.0.0.1:53 with fallback 127.0.0.1:58853)
        #[arg(short, long)]
        server: Option<SocketAddr>,

        /// Record type to query (A, AAAA, TXT, CNAME, PTR)
        #[arg(short = 't', long, default_value = "A")]
        rtype: String,
    },

    /// Add a static A-record mapping to sovereign records table
    Add {
        /// Domain name (e.g. myapp.sbm)
        domain: String,

        /// IPv4 address (e.g. 10.42.0.15)
        ip: Ipv4Addr,
    },

    /// Remove a domain mapping from sovereign records table
    Remove {
        /// Domain name to remove
        domain: String,
    },

    /// List all registered sovereign records
    List,

    /// Install OS-level split-DNS routing for .sbm namespace (Windows NRPT / Linux systemd-resolved)
    Setup {
        /// DNS server IP to route .sbm queries to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        ip: String,
    },

    /// Remove OS-level split-DNS routing
    Teardown,

    /// Show current Sovereign DNS configuration, records and OS integration status
    Status,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Status) {
        Commands::Serve { bind } => {
            println!(
                "\x1b[1;36mðŸ’€ SKULLS & BONES // SOVEREIGN DNS SERVER v{}\x1b[0m",
                env!("CARGO_PKG_VERSION")
            );
            let config = match ConfigManager::load_config_checked() {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("\x1b[31mDNS Configuration Error: {error}\x1b[0m");
                    std::process::exit(1);
                }
            };
            let authorities = match load_authorities(config.authority_trust.clone()) {
                Ok(authorities) => authorities,
                Err(error) => {
                    eprintln!("\x1b[31mDNS Authority Trust Error: {error}\x1b[0m");
                    std::process::exit(1);
                }
            };
            let authority_count = authorities.len();
            let records = ConfigManager::load_records();
            let resolver = DnsResolver::new(config, records);
            for authority in authorities {
                resolver.add_authority(authority).await;
            }
            let snapshots = match ConfigManager::load_directory_snapshots_checked() {
                Ok(snapshots) => snapshots,
                Err(error) => {
                    eprintln!("\x1b[31mDNS Directory Snapshot Error: {error}\x1b[0m");
                    std::process::exit(1);
                }
            };
            let mut loaded_meshes = std::collections::HashSet::new();
            for snapshot in snapshots {
                let mesh_id = snapshot.mesh_id.clone();
                if !loaded_meshes.insert(mesh_id.clone()) {
                    eprintln!(
                        "\x1b[31mDNS Directory Snapshot Error: duplicate snapshot for mesh '{mesh_id}'\x1b[0m"
                    );
                    std::process::exit(1);
                }
                if let Err(error) = resolver
                    .apply_snapshot(snapshot, chrono::Utc::now().timestamp().max(0) as u64)
                    .await
                {
                    eprintln!(
                        "\x1b[31mDNS Directory Snapshot for mesh '{mesh_id}' was rejected: {error}\x1b[0m"
                    );
                    std::process::exit(1);
                }
            }
            if authority_count == 0 {
                eprintln!(
                    "DNS warning: no mesh authority keys are pinned; private mesh names will not resolve."
                );
            } else {
                println!("Loaded pinned authority keys for {authority_count} mesh(es).");
            }
            if loaded_meshes.is_empty() {
                eprintln!(
                    "DNS warning: no signed directory snapshots are installed; private mesh names will not resolve."
                );
            } else {
                println!(
                    "Loaded verified directory snapshots for {} mesh(es).",
                    loaded_meshes.len()
                );
            }
            let server = DnsServer::new(resolver);

            if let Err(e) = server.run(bind).await {
                eprintln!("\x1b[31mDNS Server Error: {}\x1b[0m", e);
                std::process::exit(1);
            }
        }

        Commands::Query {
            domain,
            server,
            rtype,
        } => {
            let record_type = match rtype.to_uppercase().as_str() {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                "TXT" => RecordType::TXT,
                "CNAME" => RecordType::CNAME,
                "PTR" => RecordType::PTR,
                other => {
                    eprintln!("Unsupported DNS record type: {other}");
                    std::process::exit(2);
                }
            };
            let name = match Name::from_ascii(&domain) {
                Ok(name) => name,
                Err(error) => {
                    eprintln!("Invalid DNS name '{domain}': {error}");
                    std::process::exit(2);
                }
            };
            let mut question = Query::new();
            question
                .set_name(name)
                .set_query_type(record_type)
                .set_query_class(DNSClass::IN);
            let mut request = Message::new();
            request
                .set_id(rand::random())
                .set_message_type(MessageType::Query)
                .set_op_code(OpCode::Query)
                .set_recursion_desired(true)
                .add_query(question);
            let target_server = server.unwrap_or_else(|| "127.0.0.1:53".parse().unwrap());
            println!(
                "\x1b[1;36m[?] Querying {} for '{}' ({:?})...\x1b[0m",
                target_server, domain, record_type
            );

            let response = match query_server(target_server, &request).await {
                Ok(response) => Ok((target_server, response)),
                Err(primary_error) if server.is_none() && target_server.port() == 53 => {
                    let fallback = "127.0.0.1:58853".parse().unwrap();
                    query_server(fallback, &request)
                        .await
                        .map(|response| (fallback, response))
                        .map_err(|fallback_error| {
                            format!(
                                "default DNS server failed ({primary_error}); fallback failed ({fallback_error})"
                            )
                        })
                }
                Err(error) => Err(error),
            };
            match response {
                Ok((from, response)) => {
                    println!(
                        "\x1b[1;32m[âœ“] Response from {} (RCODE: {:?}, Auth: {}):\x1b[0m",
                        from,
                        response.response_code(),
                        response.authoritative()
                    );
                    if response.answers().is_empty() {
                        println!("    (No answers returned)");
                    } else {
                        for answer in response.answers() {
                            println!(
                                "    {} \t{} \tIN \t{:?} \t{:?}",
                                answer.name(),
                                answer.ttl(),
                                answer.record_type(),
                                answer.data()
                            );
                        }
                    }
                }
                Err(error) => eprintln!("DNS query failed: {error}"),
            }
        }

        Commands::Add { domain, ip } => match ConfigManager::add_a_record(&domain, ip) {
            Ok(_) => println!("\x1b[1;32m[+] Record added: {} -> {}\x1b[0m", domain, ip),
            Err(e) => eprintln!("\x1b[31m[!] Error saving record: {}\x1b[0m", e),
        },

        Commands::Remove { domain } => match ConfigManager::remove_record(&domain) {
            Ok(true) => println!("\x1b[1;32m[+] Record removed: {}\x1b[0m", domain),
            Ok(false) => println!("\x1b[1;33m[-] Record not found: {}\x1b[0m", domain),
            Err(e) => eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e),
        },

        Commands::List => {
            let records = ConfigManager::load_records();
            println!("\x1b[1;36mðŸ’€ SOVEREIGN DNS RECORDS (~/.sb/dns/records.toml)\x1b[0m");
            println!("{:<28} {:<8} {:<24}", "DOMAIN", "TYPE", "DESTINATION");
            println!("{}", "â”€".repeat(60));

            for (k, v) in &records.a {
                println!("{:<28} {:<8} {:<24}", k, "A", v.to_string());
            }
            for (k, v) in &records.aaaa {
                println!("{:<28} {:<8} {:<24}", k, "AAAA", v.to_string());
            }
            for (k, v) in &records.cname {
                println!("{:<28} {:<8} {:<24}", k, "CNAME", v);
            }
            for (k, v) in &records.txt {
                println!("{:<28} {:<8} {:<24}", k, "TXT", format!("\"{}\"", v));
            }
        }

        Commands::Setup { ip } => {
            println!("\x1b[1;36m[*] Configuring OS Split-DNS for .sbm namespace...\x1b[0m");
            match OsIntegration::install_split_dns(&ip) {
                Ok(msg) => println!("\x1b[1;32m[âœ“] {}\x1b[0m", msg),
                Err(e) => eprintln!("\x1b[31m[!] {}\x1b[0m", e),
            }
        }

        Commands::Teardown => {
            println!("\x1b[1;36m[*] Removing OS Split-DNS configuration...\x1b[0m");
            match OsIntegration::uninstall_split_dns() {
                Ok(msg) => println!("\x1b[1;32m[âœ“] {}\x1b[0m", msg),
                Err(e) => eprintln!("\x1b[31m[!] {}\x1b[0m", e),
            }
        }

        Commands::Status => {
            let cfg = match ConfigManager::load_config_checked() {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("\x1b[31mDNS Configuration Error: {error}\x1b[0m");
                    std::process::exit(1);
                }
            };
            if let Err(error) = load_authorities(cfg.authority_trust.clone()) {
                eprintln!("\x1b[31mDNS Authority Trust Error: {error}\x1b[0m");
                std::process::exit(1);
            }
            let records = ConfigManager::load_records();
            let nrpt_active = OsIntegration::is_split_dns_active();
            let snapshot_count = match ConfigManager::load_directory_snapshots_checked() {
                Ok(snapshots) => snapshots.len(),
                Err(error) => {
                    eprintln!("\x1b[31mDNS Directory Snapshot Error: {error}\x1b[0m");
                    std::process::exit(1);
                }
            };

            println!("\x1b[1;36mâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\x1b[0m");
            println!("\x1b[1;36m  SKULLS & BONES // SOVEREIGN DNS STATUS HUD\x1b[0m");
            println!("\x1b[1;36mâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\x1b[0m");
            println!(
                "  Primary Sockets:      UDP/TCP {}:{}",
                cfg.listen_ip, cfg.listen_port
            );
            println!("  Fallback Sockets:     UDP/TCP 127.0.0.1:58853");
            println!(
                "  Sovereign Suffixes:   {}",
                cfg.sovereign_suffixes.join(", ")
            );
            println!(
                "  Upstream Servers:     {:?}",
                cfg.upstream_servers
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            );
            println!(
                "  Upstream Forwarding:  {}",
                if cfg.enable_upstream_forwarding {
                    "\x1b[32mENABLED\x1b[0m"
                } else {
                    "\x1b[31mDISABLED\x1b[0m"
                }
            );
            println!(
                "  Registered Records:   {} custom mappings",
                records.a.len() + records.aaaa.len() + records.cname.len() + records.txt.len()
            );
            println!("  Pinned Mesh Authorities: {}", cfg.authority_trust.len());
            println!("  Directory Snapshot Entries (on disk): {snapshot_count}");
            println!(
                "  OS Split-DNS (NRPT):  {}",
                if nrpt_active {
                    "\x1b[1;32mACTIVE (.sbm -> 127.0.0.1)\x1b[0m"
                } else {
                    "\x1b[33mNOT CONFIGURED ('sb-dns setup')\x1b[0m"
                }
            );
            println!("\n  Schnellbefehle: 'sb-dns serve' Â· 'sb-dns list' Â· 'sb-dns add <domain> <ip>' Â· 'sb-dns query <domain>'\n");
        }
    }
}

fn load_authorities(
    trust_configs: Vec<sb_dns::config::AuthorityTrustConfig>,
) -> Result<Vec<sb_dns::directory::AuthorityTrust>, String> {
    let mut mesh_ids = std::collections::HashSet::new();
    trust_configs
        .into_iter()
        .map(|trust_config| {
            if !mesh_ids.insert(trust_config.mesh_id.clone()) {
                return Err(format!(
                    "duplicate authority trust configuration for mesh '{}'",
                    trust_config.mesh_id
                ));
            }
            trust_config.into_authority_trust()
        })
        .collect()
}
