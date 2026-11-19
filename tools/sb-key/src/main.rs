use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

use sb_key::{
    default_identity_path, get_lease_status, init_identity, inspect_identity, inspect_unified_ca,
    lock_lease, mint_lease, print_banner,
};

#[derive(Parser, Debug)]
#[command(
    name = "sb-key",
    author = "Skulls & Bones Lab <dev@skulls-and-bones.org>",
    version = "0.1.0",
    about = "S&B Sovereign Key & Ephemeral RAM Lease Engine",
    long_about = "S&B Key (sb-key) ersetzt Betriebssystem-Keychains und Hardware-Tokens durch eine reine dateibasierte Root-Identität (identity.sbkey) und flüchtige 8-Stunden Ephemeral Leases im RAM."
)]
struct Cli {
    /// Maschinenlesbare JSON-Ausgabe (RFC 8259)
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Erzeugt eine neue Sovereign Root Identity (identity.sbkey)
    Init {
        /// Optionaler Callsign / Alias für diesen Knoten (Standard: sb-<hostname>)
        #[arg(short, long)]
        callsign: Option<String>,

        /// Ausgabepfad (Standard: ~/.sb/identity.sbkey)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Überschreibt eine bestehende Schlüsseldatei
        #[arg(short, long)]
        force: bool,
    },

    /// Zeigt öffentliche Metadaten und Fingerprints einer identity.sbkey Datei
    Inspect {
        /// Pfad zur Schlüsseldatei (Standard: ~/.sb/identity.sbkey)
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// Prägt ein frisches, flüchtiges Ephemeral Lease für die Suite (SSH, Mesh, Forge)
    Lease {
        /// Gültigkeitsdauer in Stunden (Standard: 8 Stunden)
        #[arg(short = 'H', long, default_value_t = 8)]
        ttl_hours: u64,

        /// Pfad zur Root-Schlüsseldatei (Standard: ~/.sb/identity.sbkey)
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// Beendet die aktive Sitzung sofort und schreddert das Lease im RAM
    Lock,

    /// Zeigt den aktuellen Status des Ephemeral Leases und die verbleibende Gültigkeit
    Status {
        /// Maschinenlesbare JSON-Ausgabe (RFC 8259)
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init {
            callsign,
            out,
            force,
        }) => {
            print_banner();
            match init_identity(callsign, out.clone(), force) {
                Ok(key) => {
                    let out_path = out.unwrap_or_else(default_identity_path);
                    println!(
                        "  {} Neue Sovereign Root Identity erfolgreich erzeugt!",
                        "✓".bright_green().bold()
                    );
                    println!("  ► ID:           {}", key.id.bright_yellow().bold());
                    println!("  ► Callsign:     {}", key.callsign.bright_white().bold());
                    println!("  ► Public Key:   {}", key.public_key.bright_black());
                    println!(
                        "  ► Speicherort:  {}",
                        out_path.display().to_string().bright_cyan()
                    );
                    println!(
                        "\n  i Starte deine Arbeitssitzung mit: {}",
                        "sb-key lease".bright_yellow().bold()
                    );
                }
                Err(e) => {
                    let err_str = e.to_string();
                    sb_core::logfmt::error(
                        "ERR_KEY_INIT",
                        "key.cli",
                        "Failed to initialize identity",
                        &[("error", &err_str)],
                    );
                    std::process::exit(1);
                }
            }
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
        }

        Some(Commands::Inspect { file }) => {
            print_banner();
            match inspect_identity(file.clone()) {
                Ok(key) => {
                    let target_path = file.unwrap_or_else(default_identity_path);
                    let (ssh_ca, mesh_node) =
                        sb_key::derive_subkeys(&key.payload_b64).unwrap_or_default();

                    println!(
                        "  {} Sovereign Root Identity geladen:\n",
                        "✓".bright_green().bold()
                    );
                    println!("  ► ID:           {}", key.id.bright_yellow().bold());
                    println!("  ► Callsign:     {}", key.callsign.bright_white().bold());
                    println!("  ► Version:      {}", key.version);
                    println!("  ► Erstellt am:  {}", key.created_at.bright_black());
                    println!("  ► Public Key:   {}", key.public_key.bright_black());
                    println!("  ► Dateipfad:    {}", target_path.display());
                    println!("\n  i Abgeleitete Subkey-Fingerprints:");
                    println!("    • SSH-CA PubKey:   {}", ssh_ca.bright_green());
                    println!(
                        "    • Mesh Node-ID:    {}",
                        format!("sbm-{}", &mesh_node[..16]).bright_yellow()
                    );
                }
                Err(e) => {
                    let err_str = e.to_string();
                    sb_core::logfmt::error(
                        "ERR_KEY_INSPECT",
                        "key.cli",
                        "Failed to inspect identity",
                        &[("error", &err_str)],
                    );
                    std::process::exit(1);
                }
            }
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
        }

        Some(Commands::Lease { ttl_hours, file }) => {
            print_banner();
            match mint_lease(file, ttl_hours) {
                Ok(lease) => {
                    let lease_path = sb_key::default_lease_path();
                    let rem = lease
                        .remaining_duration()
                        .map(|d| {
                            let total_secs = d.num_seconds();
                            let hours = total_secs / 3600;
                            let mins = (total_secs % 3600) / 60;
                            let secs = total_secs % 60;
                            format!("{:02}h {:02}m {:02}s", hours, mins, secs)
                        })
                        .unwrap_or_else(|| "00h 00m 00s".to_string());

                    println!(
                        "  {} Ephemeres Sitzungs-Lease erfolgreich geprägt!",
                        "✓".bright_green().bold()
                    );
                    println!(
                        "  ► Lease-ID:     {}",
                        lease.lease_id.bright_yellow().bold()
                    );
                    println!("  ► Callsign:     {}", lease.callsign.bright_white().bold());
                    println!(
                        "  ► Gültig bis:   {} ({}h)",
                        lease.expires_at.bright_black(),
                        ttl_hours
                    );
                    println!("  ► Restzeit:     {}", rem.bright_green().bold());
                    println!("  ► Ablageort:    {}", lease_path.display());
                    println!("\n  i Suite-Aktivierung:");
                    println!("    • NetGate (sb-ssh):  8h OpenSSH Zertifikate aktiv");
                    println!("    • Mesh (sb-mesh):    8h WireGuard Capability Token aktiv");
                    println!("    • Forge (sb-forge):  In-Memory Secret Key aktiv");
                    println!(
                        "\n  Session vorzeitig beenden mit: {}",
                        "sb-key lock".bright_yellow().bold()
                    );
                }
                Err(e) => {
                    let err_str = e.to_string();
                    sb_core::logfmt::error(
                        "ERR_KEY_LEASE",
                        "key.cli",
                        "Failed to mint session lease",
                        &[("error", &err_str)],
                    );
                    std::process::exit(1);
                }
            }
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
        }

        Some(Commands::Lock) => {
            print_banner();
            if let Err(e) = lock_lease() {
                let err_str = e.to_string();
                sb_core::logfmt::error(
                    "ERR_KEY_LOCK",
                    "key.cli",
                    "Failed to lock session lease",
                    &[("error", &err_str)],
                );
                std::process::exit(1);
            }
            println!(
                "  {} Sitzung sofort beendet! Ephemeres Lease vernichtet.",
                "✓".bright_green().bold()
            );
            println!("  i Der flüchtige Schlüssel im Arbeitsspeicher wurde mit Nullen überschrieben (zeroize).");
            println!(
                "  ► Erneutes Entsperren mit: {}",
                "sb-key lease".bright_yellow().bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
        }

        Some(Commands::Status { json }) => {
            render_key_status(cli.json || json);
        }
        None => {
            render_key_status(cli.json);
        }
    }
}

/// Renders the `sb-key` identity, Unified CA binding, and ephemeral RAM lease status.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Secret material exposure if raw private key or session token is emitted in status JSON.
/// - CVE / CWE Mapping: CWE-200 (Exposure of Sensitive Information), CWE-532 (Insertion of Sensitive Information into Log File).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Serializes only public identity metadata (`id`, `callsign`, `public_key`), CA public paths, and lease expiration metadata; never emits `payload_b64` or `session_secret_b64`.
/// - Standards Compliance: Conforms to IETF RFC 8259 (JSON) and ISO 8601 / RFC 3339 timestamps.
fn render_key_status(json: bool) {
    let key_opt = inspect_identity(None).ok();
    let ca_binding = inspect_unified_ca();
    let lease_opt = get_lease_status();

    let all_ready = key_opt.is_some()
        && ca_binding.ssh_ca_initialized
        && ca_binding.x509_ca_initialized
        && lease_opt.is_some();

    if json {
        let rem_secs = lease_opt
            .as_ref()
            .and_then(|l| l.remaining_duration())
            .map(|d| d.num_seconds().max(0))
            .unwrap_or(0);
        let payload = serde_json::json!({
            "ready": all_ready,
            "identity_initialized": key_opt.is_some(),
            "identity_id": key_opt.as_ref().map(|k| k.id.clone()),
            "callsign": key_opt.as_ref().map(|k| k.callsign.clone()),
            "public_key": key_opt.as_ref().map(|k| k.public_key.clone()),
            "unified_ca": ca_binding,
            "lease_active": lease_opt.is_some(),
            "lease_id": lease_opt.as_ref().map(|l| l.lease_id.clone()),
            "lease_expires_at": lease_opt.as_ref().map(|l| l.expires_at.clone()),
            "lease_remaining_seconds": rem_secs,
            "fix_hint": if all_ready { serde_json::Value::Null } else { serde_json::Value::String("sb up --fix".to_string()) }
        });
        if let Ok(s) = serde_json::to_string_pretty(&payload) {
            println!("{}", s);
        }
        return;
    }

    print_banner();
    if let Some(key) = key_opt {
        println!(
            "  {} Root Identity:   {} ({})",
            "✓".bright_green(),
            key.callsign.bold(),
            key.id.bright_yellow()
        );
    } else {
        println!(
            "  {} Root Identity:   NICHT INITIALISIERT ('sb-key init')",
            "○".bright_black()
        );
    }

    if ca_binding.ssh_ca_initialized {
        println!(
            "  {} Unified SSH-CA:  AKTIV ({})",
            "✓".bright_green(),
            ca_binding.ssh_ca_pub_path.bright_cyan()
        );
    } else {
        println!(
            "  {} Unified SSH-CA:  INAKTIV ('sb-ca init')",
            "○".bright_black()
        );
    }
    if ca_binding.x509_ca_initialized {
        println!(
            "  {} Unified X.509:   AKTIV ({})",
            "✓".bright_green(),
            ca_binding.x509_root_crt_path.bright_cyan()
        );
    } else {
        println!(
            "  {} Unified X.509:   INAKTIV ('sb-ca init')",
            "○".bright_black()
        );
    }

    if let Some(lease) = lease_opt {
        let rem = lease
            .remaining_duration()
            .map(|d| {
                let total_secs = d.num_seconds();
                let hours = total_secs / 3600;
                let mins = (total_secs % 3600) / 60;
                let secs = total_secs % 60;
                format!("{:02}h {:02}m {:02}s", hours, mins, secs)
            })
            .unwrap_or_else(|| "00h 00m 00s".to_string());

        println!(
            "\n  {} Ephemeral Lease: AKTIV ({})",
            "✓".bright_green().bold(),
            lease.lease_id.bright_yellow()
        );
        println!("    • Verbleibend:    {}", rem.bright_green().bold());
        println!("    • Läuft ab um:    {}", lease.expires_at.bright_black());
        if let Some(ref ca_path) = lease.unified_ssh_ca_path {
            println!("    • CA-Bindung:     {}", ca_path.bright_cyan());
        }
    } else {
        println!(
            "\n  {} Ephemeral Lease: INAKTIV / GESPERRT",
            "!".bright_yellow().bold()
        );
        println!(
            "  ► Fix with: {} (oder '{}')",
            "sb up --fix".bright_cyan().bold(),
            "sb lease".bright_yellow()
        );
    }
    if !all_ready {
        println!(
            "  ► Self-Healing: Führe '{}' aus, um Identity, CA & Lease in 1 Schritt zu aktivieren.",
            "sb up --fix".bright_cyan().bold()
        );
    }
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}
