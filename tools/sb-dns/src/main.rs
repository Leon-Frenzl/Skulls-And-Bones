use clap::{Parser, Subcommand};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
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

    /// Add a static SRV record (RFC 2782) for service / DC discovery
    AddSrv {
        /// Service domain name (e.g. _dc._tcp.corp.sbm)
        domain: String,
        /// Target hostname (e.g. dc.corp.sbm)
        target: String,
        /// Target TCP/UDP port (e.g. 8443)
        port: u16,
        /// SRV priority (lower is preferred, default 10)
        #[arg(long, default_value_t = 10)]
        priority: u16,
        /// SRV weight (default 0)
        #[arg(long, default_value_t = 0)]
        weight: u16,
    },

    /// Add a static CNAME record
    AddCname { domain: String, target: String },

    /// Add a static TXT record
    AddTxt { domain: String, text: String },

    /// Remove a domain mapping from sovereign records table
    Remove {
        /// Domain name to remove
        domain: String,
    },

    /// List all registered sovereign records
    List,

    /// Manage DHCP pools, IPAM subnets, and automatic DDNS leases
    Ipam {
        #[command(subcommand)]
        sub: IpamCommands,
    },

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

#[derive(Subcommand, Debug)]
enum IpamCommands {
    /// Create or update an IPAM subnet & DHCP pool
    InitSubnet {
        #[arg(long)]
        id: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        cidr: String,
        #[arg(long)]
        gateway: std::net::Ipv4Addr,
        #[arg(long)]
        start: std::net::Ipv4Addr,
        #[arg(long)]
        end: std::net::Ipv4Addr,
        #[arg(long, default_value = "10.42.0.1")]
        dns: std::net::Ipv4Addr,
        #[arg(long, default_value_t = 3600)]
        lease_seconds: u32,
    },
    /// Allocate or renew a DHCP lease (auto-registers DDNS A record)
    Lease {
        #[arg(long)]
        subnet: String,
        #[arg(long)]
        mac: String,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        ip: Option<std::net::Ipv4Addr>,
        #[arg(long)]
        static_reservation: bool,
    },
    /// Release a DHCP lease by MAC or IP (removes DDNS A record)
    Release { mac_or_ip: String },
    /// List IPAM subnets and active DHCP leases
    List,
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
                    let e = error.to_string();
                    sb_core::logfmt::error("ERR_DNS_CONFIG", "dns.serve", "DNS configuration error", &[("error", &e)]);
                    std::process::exit(1);
                }
            };
            let authorities = match load_authorities(config.authority_trust.clone()) {
                Ok(authorities) => authorities,
                Err(error) => {
                    let e = error.to_string();
                    sb_core::logfmt::error("ERR_DNS_AUTHORITY", "dns.serve", "DNS authority trust error", &[("error", &e)]);
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
                    let e = error.to_string();
                    sb_core::logfmt::error("ERR_DNS_SNAPSHOT", "dns.serve", "DNS directory snapshot error", &[("error", &e)]);
                    std::process::exit(1);
                }
            };
            let mut loaded_meshes = std::collections::HashSet::new();
            for snapshot in snapshots {
                let mesh_id = snapshot.mesh_id.clone();
                if !loaded_meshes.insert(mesh_id.clone()) {
                    sb_core::logfmt::error("ERR_DNS_DUPLICATE_SNAPSHOT", "dns.serve", "Duplicate DNS directory snapshot", &[("mesh_id", &mesh_id)]);
                    std::process::exit(1);
                }
                if let Err(error) = resolver
                    .apply_snapshot(snapshot, chrono::Utc::now().timestamp().max(0) as u64)
                    .await
                {
                    let e = error.to_string();
                    sb_core::logfmt::error("ERR_DNS_SNAPSHOT_REJECTED", "dns.serve", "DNS directory snapshot rejected", &[("mesh_id", &mesh_id), ("error", &e)]);
                    std::process::exit(1);
                }
            }
            if authority_count == 0 {
                sb_core::logfmt::warn("DNS_NO_AUTHORITY_KEYS", "dns.serve", "No mesh authority keys pinned", &[]);
            } else {
                let cnt = authority_count.to_string();
                sb_core::logfmt::info("DNS_AUTHORITIES_LOADED", "dns.serve", "Loaded pinned authority keys", &[("count", &cnt)]);
            }
            if loaded_meshes.is_empty() {
                sb_core::logfmt::warn("DNS_NO_SNAPSHOTS", "dns.serve", "No signed directory snapshots installed", &[]);
            } else {
                let cnt = loaded_meshes.len().to_string();
                sb_core::logfmt::info("DNS_SNAPSHOTS_LOADED", "dns.serve", "Loaded verified directory snapshots", &[("count", &cnt)]);
            }
            let server = DnsServer::new(resolver);

            if let Err(e) = server.run(bind).await {
                let err = e.to_string();
                sb_core::logfmt::error("ERR_DNS_SERVER", "dns.serve", "DNS server exited with error", &[("error", &err)]);
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
                    sb_core::logfmt::error("ERR_DNS_RECORD_TYPE", "dns.cli", "Unsupported DNS record type", &[("rtype", other)]);
                    std::process::exit(2);
                }
            };
            let name = match Name::from_ascii(&domain) {
                Ok(name) => name,
                Err(error) => {
                    let e = error.to_string();
                    sb_core::logfmt::error("ERR_DNS_INVALID_NAME", "dns.cli", "Invalid DNS name", &[("domain", &domain), ("error", &e)]);
                    std::process::exit(2);
                }
            };
            let question = Query::query(name, record_type);
            let request = Message::new(rand::random(), MessageType::Query, OpCode::Query);
            let mut request = request;
            request.metadata.recursion_desired = true;
            request.add_query(question);
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
                        from, response.metadata.response_code, response.metadata.authoritative
                    );
                    if response.answers.is_empty() {
                        println!("    (No answers returned)");
                    } else {
                        for answer in &response.answers {
                            println!(
                                "{} \t{}\tIN \t{:?} \t{:?}",
                                answer.name,
                                answer.ttl,
                                answer.record_type(),
                                answer.data
                            );
                        }
                    }
                }
                Err(error) => {
                    let e = error.to_string();
                    sb_core::logfmt::error("ERR_DNS_QUERY", "dns.cli", "DNS query failed", &[("error", &e)]);
                }
            }
        }

        Commands::Add { domain, ip } => match ConfigManager::add_a_record(&domain, ip) {
            Ok(_) => println!("\x1b[1;32m[+] Record added: {} -> {}\x1b[0m", domain, ip),
            Err(e) => {
                let err = e.to_string();
                sb_core::logfmt::error("ERR_DNS_SAVE", "dns.cli", "Error saving A record", &[("error", &err)]);
            }
        },

        Commands::AddSrv {
            domain,
            target,
            port,
            priority,
            weight,
        } => match ConfigManager::add_srv_record(&domain, priority, weight, port, &target) {
            Ok(_) => println!(
                "\x1b[1;32m[+] SRV record added: {} -> {} {} {} {}\x1b[0m",
                domain, priority, weight, port, target
            ),
            Err(e) => {
                let err = e.to_string();
                sb_core::logfmt::error("ERR_DNS_SAVE_SRV", "dns.cli", "Error saving SRV record", &[("error", &err)]);
            }
        },

        Commands::AddCname { domain, target } => {
            match ConfigManager::add_cname_record(&domain, &target) {
                Ok(_) => println!("\x1b[1;32m[+] CNAME added: {} -> {}\x1b[0m", domain, target),
                Err(e) => {
                    let err = e.to_string();
                    sb_core::logfmt::error("ERR_DNS_SAVE_CNAME", "dns.cli", "Error saving CNAME record", &[("error", &err)]);
                }
            }
        }

        Commands::AddTxt { domain, text } => match ConfigManager::add_txt_record(&domain, &text) {
            Ok(_) => println!("\x1b[1;32m[+] TXT added: {} -> \"{}\"\x1b[0m", domain, text),
            Err(e) => {
                let err = e.to_string();
                sb_core::logfmt::error("ERR_DNS_SAVE_TXT", "dns.cli", "Error saving TXT record", &[("error", &err)]);
            }
        },

        Commands::Remove { domain } => match ConfigManager::remove_record(&domain) {
            Ok(true) => println!("\x1b[1;32m[+] Record removed: {}\x1b[0m", domain),
            Ok(false) => println!("\x1b[1;33m[-] Record not found: {}\x1b[0m", domain),
            Err(e) => {
                let err = e.to_string();
                sb_core::logfmt::error("ERR_DNS_REMOVE", "dns.cli", "Error removing DNS record", &[("error", &err)]);
            }
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
            for (k, entries) in &records.srv {
                for entry in entries {
                    println!(
                        "{:<28} {:<8} {} {} {} {}",
                        k, "SRV", entry.priority, entry.weight, entry.port, entry.target
                    );
                }
            }
        }

        Commands::Ipam { sub } => {
            use sb_core::ipam::IpamSubnet;
            use sb_dns::ipam::IpamStore;
            let path = IpamStore::default_path();
            let mut store = match IpamStore::load_from_path(&path) {
                Ok(s) => s,
                Err(e) => {
                    let err = e.to_string();
                    sb_core::logfmt::error("ERR_DNS_IPAM", "dns.ipam", "IPAM store error", &[("error", &err)]);
                    return;
                }
            };
            match sub {
                IpamCommands::InitSubnet {
                    id,
                    domain,
                    cidr,
                    gateway,
                    start,
                    end,
                    dns,
                    lease_seconds,
                } => {
                    let subnet = IpamSubnet {
                        id,
                        domain,
                        cidr,
                        gateway,
                        dns_servers: vec![dns],
                        pool_start: start,
                        pool_end: end,
                        default_lease_seconds: lease_seconds,
                    };
                    match store.upsert_subnet(subnet).and_then(|s| {
                        store.save_to_path(&path)?;
                        Ok(s)
                    }) {
                        Ok(s) => println!(
                            "\x1b[1;32m[+] Subnet '{}' ({}) saved: {}..={}\x1b[0m",
                            s.id, s.cidr, s.pool_start, s.pool_end
                        ),
                        Err(e) => sb_core::logfmt::error("ERR_DNS_IPAM_SUBNET", "dns.ipam", "Failed to save subnet", &[("error", &e.to_string())]),
                    }
                }
                IpamCommands::Lease {
                    subnet,
                    mac,
                    hostname,
                    ip,
                    static_reservation,
                } => {
                    match store
                        .allocate_lease(&subnet, &mac, &hostname, ip, static_reservation, None)
                        .and_then(|l| {
                            store.save_to_path(&path)?;
                            Ok(l)
                        }) {
                        Ok(l) => println!(
                            "\x1b[1;32m[+] Lease {}: {} ({}) -> {} [DDNS synced]\x1b[0m",
                            l.lease_id, l.fqdn, l.mac_address, l.ip_address
                        ),
                        Err(e) => sb_core::logfmt::error("ERR_DNS_IPAM_LEASE", "dns.ipam", "Failed to allocate lease", &[("error", &e.to_string())]),
                    }
                }
                IpamCommands::Release { mac_or_ip } => {
                    match store.release_lease(&mac_or_ip, None).and_then(|l| {
                        store.save_to_path(&path)?;
                        Ok(l)
                    }) {
                        Ok(l) => println!(
                            "\x1b[1;32m[+] Released {} ({}) -> {} [DDNS removed]\x1b[0m",
                            l.fqdn, l.mac_address, l.ip_address
                        ),
                        Err(e) => sb_core::logfmt::error("ERR_DNS_IPAM_RELEASE", "dns.ipam", "Failed to release lease", &[("error", &e.to_string())]),
                    }
                }
                IpamCommands::List => {
                    println!(
                        "\x1b[1;36m=== IPAM SUBNETS ({}) ===\x1b[0m",
                        store.subnets.len()
                    );
                    for s in store.subnets.values() {
                        println!(
                            "  {:<16} {:<16} pool={}..={} gw={} domain={}",
                            s.id, s.cidr, s.pool_start, s.pool_end, s.gateway, s.domain
                        );
                    }
                    println!(
                        "\x1b[1;36m=== DHCP LEASES ({}) ===\x1b[0m",
                        store.leases.len()
                    );
                    for l in &store.leases {
                        println!(
                            "  {:<15} {:<18} {:<24} static={} exp={}",
                            l.ip_address, l.mac_address, l.fqdn, l.static_reservation, l.expires_at
                        );
                    }
                }
            }
        }

        Commands::Setup { ip } => {
            println!("\x1b[1;36m[*] Configuring OS Split-DNS for .sbm namespace...\x1b[0m");
            match OsIntegration::install_split_dns(&ip) {
                Ok(msg) => println!("\x1b[1;32m[âœ“] {}\x1b[0m", msg),
                Err(e) => sb_core::logfmt::error("ERR_DNS_SETUP", "dns.setup", "Failed to install split-DNS", &[("error", &e.to_string())]),
            }
        }

        Commands::Teardown => {
            println!("\x1b[1;36m[*] Removing OS Split-DNS configuration...\x1b[0m");
            match OsIntegration::uninstall_split_dns() {
                Ok(msg) => println!("\x1b[1;32m[âœ“] {}\x1b[0m", msg),
                Err(e) => sb_core::logfmt::error("ERR_DNS_TEARDOWN", "dns.teardown", "Failed to uninstall split-DNS", &[("error", &e.to_string())]),
            }
        }

        Commands::Status => {
            let cfg = match ConfigManager::load_config_checked() {
                Ok(config) => config,
                Err(error) => {
                    sb_core::logfmt::error("ERR_DNS_CONFIG", "dns.status", "DNS configuration error", &[("error", &error.to_string())]);
                    std::process::exit(1);
                }
            };
            if let Err(error) = load_authorities(cfg.authority_trust.clone()) {
                sb_core::logfmt::error("ERR_DNS_AUTHORITY", "dns.status", "DNS authority trust error", &[("error", &error.to_string())]);
                std::process::exit(1);
            }
            let records = ConfigManager::load_records();
            let nrpt_active = OsIntegration::is_split_dns_active();
            let snapshot_count = match ConfigManager::load_directory_snapshots_checked() {
                Ok(snapshots) => snapshots.len(),
                Err(error) => {
                    sb_core::logfmt::error("ERR_DNS_SNAPSHOT", "dns.status", "DNS directory snapshot error", &[("error", &error.to_string())]);
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
