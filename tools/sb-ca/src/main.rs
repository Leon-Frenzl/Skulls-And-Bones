//! `sb-ca` CLI — Sovereign PKI & Certificate Authority Command Line Tool.
//!
//! Standards:
//! - Conforms to OpenSSH PROTOCOL.certkeys
//! - Conforms to IETF RFC 4251
//! - Conforms to IETF RFC 5280
//! - Conforms to IETF RFC 8446 (TLS 1.3)

use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use sb_ca::error::CaError;
use sb_ca::ssh::{SshCa, DEFAULT_HOST_CERT_TTL_SECONDS, DEFAULT_USER_CERT_TTL_SECONDS};
use sb_ca::x509::{X509Ca, DEFAULT_LEAF_CERT_TTL_DAYS};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sb-ca",
    author = "Skulls & Bones Lab <dev@skulls-and-bones.org>",
    version = "0.1.0",
    about = "S&B Sovereign Unified PKI & Certificate Authority Engine (OpenSSH & X.509 mTLS)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize OpenSSH and X.509 Certificate Authorities
    Init {
        /// Force re-generation of existing CA keys
        #[arg(long, short)]
        force: bool,
        /// Initialize only OpenSSH CA
        #[arg(long)]
        ssh_only: bool,
        /// Initialize only X.509 Root CA
        #[arg(long)]
        x509_only: bool,
    },

    /// Show unified PKI and trust store status
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Install X.509 Root CA into local operating system trust store
    InstallRoot,

    /// Uninstall X.509 Root CA from local operating system trust store
    UninstallRoot,

    /// OpenSSH CA commands (user & host certificates)
    Ssh {
        #[command(subcommand)]
        command: SshCommands,
    },

    /// X.509 TLS and mTLS CA commands
    X509 {
        #[command(subcommand)]
        command: X509Commands,
    },
}

#[derive(Subcommand)]
enum SshCommands {
    /// Issue short-lived OpenSSH user certificate
    IssueUser(SshIssueUserArgs),

    /// Issue OpenSSH host certificate
    IssueHost(SshIssueHostArgs),

    /// Display OpenSSH Root CA public key line for /etc/ssh/trusted_user_ca_keys
    CaPubkey,
}

#[derive(Args)]
struct SshIssueUserArgs {
    /// Subject OpenSSH public key (raw string or path to .pub file)
    #[arg(long, short = 'k')]
    pubkey: String,

    /// Certificate Key ID / operator identifier
    #[arg(long, short = 'i')]
    key_id: String,

    /// Principals (comma-separated usernames, e.g. "root,sbadmin,deploy")
    #[arg(long, short = 'p', value_delimiter = ',')]
    principals: Vec<String>,

    /// Certificate validity duration in seconds (default: 3600, max: 28800)
    #[arg(long, default_value_t = DEFAULT_USER_CERT_TTL_SECONDS)]
    ttl: u64,

    /// Explicit 64-bit serial number (optional)
    #[arg(long)]
    serial: Option<u64>,

    /// Output file path to write certificate (prints to stdout if omitted)
    #[arg(long, short = 'o')]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct SshIssueHostArgs {
    /// Subject OpenSSH public key (raw string or path to .pub file)
    #[arg(long, short = 'k')]
    pubkey: String,

    /// Hostname principal (e.g. "node1.sbm" or "server.local")
    #[arg(long, short = 'H')]
    hostname: String,

    /// Certificate validity duration in seconds (default: 30 days)
    #[arg(long, default_value_t = DEFAULT_HOST_CERT_TTL_SECONDS)]
    ttl: u64,

    /// Explicit 64-bit serial number (optional)
    #[arg(long)]
    serial: Option<u64>,

    /// Output file path to write certificate (prints to stdout if omitted)
    #[arg(long, short = 'o')]
    out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum X509Commands {
    /// Issue X.509 leaf certificate with SANs and mTLS EKUs
    Issue(X509IssueArgs),

    /// Dynamically resolve or issue certificate on-demand
    OnDemand {
        /// Primary domain name (e.g. "app.sbm")
        #[arg(long, short = 'd')]
        domain: String,
    },

    /// List previously issued certificates
    List,
}

#[derive(Args)]
struct X509IssueArgs {
    /// Domain names / SANs (comma-separated, e.g. "*.sbm,*.mesh,localhost")
    #[arg(long, short = 'd', value_delimiter = ',')]
    domains: Vec<String>,

    /// Validity in days (default: 90)
    #[arg(long, default_value_t = DEFAULT_LEAF_CERT_TTL_DAYS)]
    ttl_days: u32,

    /// Output file path for fullchain certificate PEM
    #[arg(long)]
    out_cert: Option<PathBuf>,

    /// Output file path for private key PEM
    #[arg(long)]
    out_key: Option<PathBuf>,
}

/// Resolves public key input from either a filesystem path or raw OpenSSH wire format string.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: File traversal or unauthorized file read via command-line `--pubkey` argument.
/// - CVE / CWE Mapping: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), CWE-200 (Information Disclosure).
/// - Likelihood & Exploitability: Low (2/10).
///   * Threat Condition: CLI user executes sb-ca with a path to a key file.
/// - Applied Mitigation: Confined exclusively to user-driven CLI interface; reads local file if it exists, otherwise falls back to parsing raw string.
fn resolve_public_key_arg(input: &str) -> Result<String, CaError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CaError::InvalidPublicKey("Empty public key input".into()));
    }

    let candidate = std::path::Path::new(trimmed);
    if candidate.exists() && candidate.is_file() {
        let content = fs::read_to_string(candidate)?;
        let content_trimmed = content.trim();
        if content_trimmed.is_empty() {
            return Err(CaError::InvalidPublicKey(format!(
                "Public key file '{}' is empty",
                candidate.display()
            )));
        }
        Ok(content_trimmed.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        let err_str = e.to_string();
        sb_core::logfmt::error(
            "ERR_CA_CLI",
            "ca.cli",
            "CA command failed",
            &[("error", &err_str)],
        );
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), CaError> {
    match cli.command {
        Commands::Init {
            force,
            ssh_only,
            x509_only,
        } => {
            println!("{}", "► Initializing Skulls & Bones Sovereign PKI...".bold());
            if !x509_only {
                let ssh_status = SshCa::init_ca(force)?;
                println!(
                    "  {} OpenSSH Root CA initialized:\n     Key: {}\n     Pub: {}",
                    "✓".bright_green(),
                    ssh_status.ca_key_path.cyan(),
                    ssh_status.ca_pub_path.cyan()
                );
                if let Some(pub_str) = ssh_status.public_key {
                    println!("     Entry: {}", pub_str.bright_black());
                }
            }

            if !ssh_only {
                let x509_status = X509Ca::init_root_ca(force)?;
                println!(
                    "  {} X.509 Root CA initialized:\n     Cert: {}\n     Key:  {}",
                    "✓".bright_green(),
                    x509_status.crt_path.cyan(),
                    x509_status.key_path.cyan()
                );
            }
            println!("{} All CA engines initialized successfully.", "✓".bright_green().bold());
        }

        Commands::Status { json } => {
            let status = sb_ca::status()?;
            if json {
                let s = serde_json::to_string_pretty(&status)?;
                println!("{}", s);
            } else {
                println!("{}", "════════════════════════════════════════════════════════".bright_cyan());
                println!("{}", "  SKULLS & BONES SOVEREIGN PKI STATUS".bold());
                println!("{}", "════════════════════════════════════════════════════════".bright_cyan());
                println!("  [OpenSSH CA Engine]");
                println!("    Initialized: {}", if status.ssh.initialized { "Yes".bright_green() } else { "No".bright_red() });
                println!("    Private Key: {}", status.ssh.ca_key_path);
                println!("    Public Key:  {}", status.ssh.ca_pub_path);
                if let Some(ref pk) = status.ssh.public_key {
                    println!("    Entry:       {}", pk.bright_black());
                }

                println!("\n  [X.509 CA Engine]");
                println!("    Initialized: {}", if status.x509.initialized { "Yes".bright_green() } else { "No".bright_red() });
                println!("    Common Name: {}", status.x509.common_name);
                println!("    Certificate: {}", status.x509.crt_path);
                println!("    Private Key: {}", status.x509.key_path);
                println!("    OS Trusted:  {}", if status.x509.is_installed_in_os { "Yes".bright_green() } else { "No (Run 'sb-ca install-root')".bright_yellow() });
                println!("    Issued Certs:{}", status.x509.issued_certs_count);
                if !status.ssh.initialized || !status.x509.initialized || !status.x509.is_installed_in_os {
                    println!("\n  ► Fix with: {}", "sb up --fix (or 'sb-ca init && sb-ca install-root')".bright_cyan().bold());
                }
                println!("{}", "════════════════════════════════════════════════════════".bright_cyan());
            }
        }

        Commands::InstallRoot => {
            println!("{}", "► Installing X.509 Root CA into local OS trust store...".bold());
            let msg = X509Ca::install_root_ca()?;
            println!("  {} {}", "✓".bright_green(), msg);
        }

        Commands::UninstallRoot => {
            println!("{}", "► Removing X.509 Root CA from local OS trust store...".bold());
            let msg = X509Ca::uninstall_root_ca()?;
            println!("  {} {}", "✓".bright_green(), msg);
        }

        Commands::Ssh { command } => match command {
            SshCommands::CaPubkey => {
                let pub_line = SshCa::ca_public_key_openssh()?;
                println!("{}", pub_line);
            }

            SshCommands::IssueUser(args) => {
                let pubkey_str = resolve_public_key_arg(&args.pubkey)?;
                let cert_str = SshCa::issue_user_certificate(
                    &pubkey_str,
                    &args.key_id,
                    &args.principals,
                    args.ttl,
                    args.serial,
                )?;

                if let Some(out_path) = args.out {
                    fs::write(&out_path, cert_str.as_bytes())?;
                    println!(
                        "{} OpenSSH User Certificate written to: {}",
                        "✓".bright_green(),
                        out_path.display()
                    );
                } else {
                    println!("{}", cert_str);
                }
            }

            SshCommands::IssueHost(args) => {
                let pubkey_str = resolve_public_key_arg(&args.pubkey)?;
                let cert_str = SshCa::issue_host_certificate(
                    &pubkey_str,
                    &args.hostname,
                    args.ttl,
                    args.serial,
                )?;

                if let Some(out_path) = args.out {
                    fs::write(&out_path, cert_str.as_bytes())?;
                    println!(
                        "{} OpenSSH Host Certificate written to: {}",
                        "✓".bright_green(),
                        out_path.display()
                    );
                } else {
                    println!("{}", cert_str);
                }
            }
        },

        Commands::X509 { command } => match command {
            X509Commands::Issue(args) => {
                let pair = X509Ca::issue_leaf_certificate(&args.domains, args.ttl_days)?;
                if let Some(ref cert_out) = args.out_cert {
                    fs::write(cert_out, pair.cert_pem.as_bytes())?;
                }
                if let Some(ref key_out) = args.out_key {
                    fs::write(key_out, pair.key_pem.as_bytes())?;
                }

                println!(
                    "{} X.509 Certificate issued successfully for: {:?}",
                    "✓".bright_green(),
                    pair.domains
                );
                println!("  Certificate: {}", pair.cert_path.display().to_string().cyan());
                println!("  Private Key: {}", pair.key_path.display().to_string().cyan());
                println!("  Expires At:  {}", pair.expires_at.bright_black());
            }

            X509Commands::OnDemand { domain } => {
                let pair = X509Ca::get_or_issue_on_demand(&domain)?;
                println!(
                    "{} Valid On-Demand Certificate resolved for '{}':\n  Cert: {}\n  Key:  {}",
                    "✓".bright_green(),
                    domain.bold(),
                    pair.cert_path.display(),
                    pair.key_path.display()
                );
            }

            X509Commands::List => {
                let list = X509Ca::list_certificates();
                if list.is_empty() {
                    println!("No leaf certificates issued yet.");
                } else {
                    println!("Found {} issued certificate(s):", list.len());
                    for c in list {
                        println!(
                            "  • {} -> {} (expires: {})",
                            c.primary_domain.bold(),
                            c.cert_path.cyan(),
                            c.expires_at.bright_black()
                        );
                    }
                }
            }
        },
    }

    Ok(())
}
