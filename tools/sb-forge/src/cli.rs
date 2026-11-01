use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sb-forge",
    about = "S&B Forge — Pipeline Runner, Secret Manager & Deployment Tool\nDas CI/CD-Tool das sb-ssh als Basis nutzt.",
    version = "0.1.0"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Lokale Secret-Verwaltung (set, get, list, rotate)
    Secret(SecretArgs),

    /// Environment-Verwaltung (activate, revoke; legacy seal ist deaktiviert)
    #[command(name = "env")]
    Env(EnvArgs),

    /// Recipe oder Pipeline ausführen
    Run(RunArgs),

    /// Prozess mit injizierten Secrets starten (forge exec -- binary)
    Exec(ExecArgs),

    /// Secrets und Dateien auf Secret-Leaks scannen
    Scan(ScanArgs),

    /// Audit-Log anzeigen
    Audit(AuditArgs),

    /// S&B Forge im aktuellen Projekt initialisieren
    Init,

    /// Live Pipeline-Monitor TUI öffnen
    Watch,

    /// Produktionsfertige systemd-Service-Unit generieren
    #[command(name = "systemd-unit")]
    SystemdUnit(SystemdUnitArgs),

    /// Projekt- & Secret-Lifecycle prüfen (Rotation-Status)
    Check(CheckArgs),

    /// Automatische Fehlerkorrektur & Workspace-Formatierung (cargo fmt, oxlint, prettier)
    Fix(FixArgs),

    /// Mesh Swarm Spezifikation & P2P-Code-Streams (FORGE_MESH.toml)
    Mesh(MeshArgs),

    /// Führt eine Forge-Pipeline direkt remote auf einem Flotten-Server aus
    Remote(RemotePipelineArgs),

    /// Shell-Completions generieren (bash, zsh, fish, powershell, elvish)
    Completions { shell: clap_complete::Shell },
}

#[derive(clap::Args, Debug)]
pub struct MeshArgs {
    #[command(subcommand)]
    pub action: Option<MeshAction>,
}

#[derive(Subcommand, Debug)]
pub enum MeshAction {
    /// Zeigt Informationen über die FORGE_MESH.toml im aktuellen Projekt
    Info,

    /// Validiert FORGE_MESH.toml gegen Forge.toml
    Check,

    /// Initialisiert eine neue FORGE_MESH.toml im aktuellen Ordner
    Init {
        /// Optionaler Projektname
        name: Option<String>,
    },
}

#[derive(clap::Args, Debug)]
pub struct FixArgs {
    /// Nur Formatierer ausführen (cargo fmt / prettier)
    #[arg(long)]
    pub fmt: bool,
    /// Nur Linter-Fixes anwenden (oxlint / clippy --fix)
    #[arg(long)]
    pub lint: bool,
    /// Trockenlauf ohne Änderungen
    #[arg(long)]
    pub dry_run: bool,
}

// ── SECRET ────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub action: SecretAction,
}

#[derive(Subcommand)]
pub enum SecretAction {
    /// Secret setzen (interaktiver Prompt, Stdin oder --value)
    Set {
        /// Secret-Name (wie in Forge.toml definiert)
        name: String,
        /// Ziel-Environment
        #[arg(long, short)]
        env: String,
        /// Wert direkt übergeben (optional, für CI / Skripte)
        #[arg(long)]
        value: Option<String>,
        /// Zugehöriges Projekt (Standard: Name aus Forge.toml oder 'global')
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Secret-Wert anzeigen (nur mit aktivem Login)
    Get {
        name: String,
        #[arg(long, short)]
        env: String,
        /// Projektfilter (optional)
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Alle Secrets eines Environments auflisten
    List {
        #[arg(long, short)]
        env: Option<String>,
        /// Nach Projekt filtern (optional)
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Secret rotieren (altes bleibt Grace-Period aktiv)
    Rotate {
        name: String,
        #[arg(long, short)]
        env: String,
        /// Neuer Wert (optional)
        #[arg(long)]
        value: Option<String>,
        /// Grace Period bevor altes Secret deaktiviert wird (z.B. "15m")
        #[arg(long, default_value = "10m")]
        grace: String,
        /// Zugehöriges Projekt
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Secret löschen
    Delete {
        name: String,
        #[arg(long, short)]
        env: String,
        /// Zugehöriges Projekt
        #[arg(long, short = 'p')]
        project: Option<String>,
    },
    /// Wer hat wann auf welche Secrets zugegriffen
    Audit {
        #[arg(long, short)]
        env: Option<String>,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// AONT Secret Sharding: Zerlegt ein Secret in n Shards mit Threshold k (k-aus-n)
    Shard {
        /// Secret-Name
        name: String,
        /// Ziel-Environment (Standard: 'prod')
        #[arg(long, short, default_value = "prod")]
        env: String,
        /// Schwellwert k (z.B. 3 für 3-aus-5)
        #[arg(long, short = 'k', default_value_t = 3)]
        threshold: usize,
        /// Gesamtanzahl n Shards (z.B. 5)
        #[arg(long, short = 'n', default_value_t = 5)]
        total: usize,
        /// Ausgabeverzeichnis für die Shard-Dateien (.json)
        #[arg(long, short = 'o', default_value = "./shards")]
        out_dir: String,
        /// Secret-Wert direkt übergeben (optional, sonst aus dem Vault geladen)
        #[arg(long)]
        value: Option<String>,
    },
    /// AONT Rekonstruktion: Setzt das Secret aus mindestens k Shard-Dateien zusammen
    Assemble {
        /// Pfade zu den Shard-Dateien (kommagetrennt oder mehrfach)
        #[arg(long, short = 's', value_delimiter = ',')]
        shards: Vec<String>,
        /// In den lokalen Vault unter diesem Namen speichern
        #[arg(long)]
        save_as: Option<String>,
        /// Ziel-Environment falls --save-as verwendet wird
        #[arg(long, short, default_value = "prod")]
        env: String,
    },
    /// Proactive Secret Sharing (PSS): Rotiert Shards bei Member-Revocation ohne Decryption
    Reshare {
        /// Pfade zu den verbleibenden aktiven Shards
        #[arg(long, short = 's', value_delimiter = ',')]
        shards: Vec<String>,
        /// ID des kompromittierten / ausgeschlossenen Shards (z.B. 3)
        #[arg(long, short = 'r')]
        revoke: u8,
        /// Ausgabeverzeichnis für die erneuerten Epochen-Shards
        #[arg(long, short = 'o', default_value = "./reshared_shards")]
        out_dir: String,
    },
}

// ── ENV ───────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct EnvArgs {
    #[command(subcommand)]
    pub action: EnvAction,
}

#[derive(Subcommand)]
pub enum EnvAction {
    /// Environment aktivieren (lädt Secrets in Session-Kontext)
    Activate { env: String },
    /// Legacy env.sealed (aus Sicherheitsgründen deaktiviert)
    Seal {
        /// Legacy-Option, derzeit nicht verwendet
        env: String,
        /// Legacy-Option, derzeit nicht verwendet
        #[arg(long, short)]
        server: Option<String>,
        /// Legacy-Option, derzeit nicht verwendet
        #[arg(long)]
        deploy: bool,
        /// Legacy-Option, derzeit nicht verwendet
        #[arg(long, default_value = "/etc/forge/env.sealed")]
        remote_path: String,
        /// Legacy-Option, derzeit nicht verwendet
        #[arg(long, short, default_value = "env.sealed")]
        output: String,
    },
    /// Versiegeltes Environment invalidieren
    Revoke { env: String },
    /// Alle konfigurierten Environments anzeigen
    List,
}

// ── SYSTEMD UNIT ──────────────────────────────────────────

#[derive(clap::Args)]
pub struct SystemdUnitArgs {
    /// Recipe-Name aus Forge.toml
    pub recipe: String,
    /// Environment (z.B. prod)
    #[arg(long, short, default_value = "prod")]
    pub env: String,
    /// Linux-Benutzer für den Service
    #[arg(long, short, default_value = "root")]
    pub user: String,
    /// Arbeitsverzeichnis auf dem Server
    #[arg(long)]
    pub workdir: Option<String>,
}

// ── RUN ───────────────────────────────────────────────────

#[derive(clap::Args, Clone)]
pub struct RunArgs {
    /// Recipe-Name oder --pipeline <name>
    pub recipe: Option<String>,

    /// Pipeline ausführen statt einzelnem Recipe
    #[arg(long)]
    pub pipeline: Option<String>,

    /// Environment (überschreibt Forge.toml)
    #[arg(long, short)]
    pub env: Option<String>,

    /// Zeige was ausgeführt würde, ohne es zu tun
    #[arg(long)]
    pub dry_run: bool,

    /// Verbose Output mit allen Befehlen
    #[arg(long, short)]
    pub verbose: bool,

    /// Dateiänderungen überwachen und automatisch neu ausführen
    #[arg(long, short = 'w')]
    pub watch: bool,

    /// Remote-Ausführung auf Zielserver über S&B NetGate / Mesh
    #[arg(long, short = 'r')]
    pub remote: Option<String>,

    /// Arbeitsverzeichnis vor Ausführung via SFTP synchronisieren (Standard: true)
    #[arg(long, default_value_t = true)]
    pub sync: bool,

    /// Erzwingt das Überschreiben eines bestehenden Remote-Deployment-Locks
    #[arg(long)]
    pub force_lock: bool,
}

// ── REMOTE PIPELINE ───────────────────────────────────────

#[derive(clap::Args, Clone)]
pub struct RemotePipelineArgs {
    /// Zielserver (z. B. 'hostinger-node', 'hetzner-01' oder IP)
    pub server: String,

    /// Name der Pipeline oder des Recipes (z. B. 'deploy', 'build')
    pub target: String,

    /// Environment (Standard: 'prod')
    #[arg(long, short, default_value = "prod")]
    pub env: String,

    /// Arbeitsverzeichnis vor Ausführung via SFTP synchronisieren
    #[arg(long, default_value_t = true)]
    pub sync: bool,

    /// Zeige was getan werden würde
    #[arg(long)]
    pub dry_run: bool,

    /// Ausführliche Ausgabe
    #[arg(long, short)]
    pub verbose: bool,

    /// Erzwingt das Überschreiben eines bestehenden Remote-Deployment-Locks
    #[arg(long)]
    pub force_lock: bool,
}

// ── EXEC ──────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct ExecArgs {
    /// Environment dessen Secrets injiziert werden (Fallback: aktives Environment)
    #[arg(long, short)]
    pub env: Option<String>,

    /// Deaktiviertes Legacy-Format (wird aus Sicherheitsgründen abgelehnt)
    #[arg(long)]
    pub sealed: Option<String>,

    /// Binärer Pfad und Argumente nach "--"
    #[arg(last = true)]
    pub command: Vec<String>,
}

// ── SCAN ──────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Pfad manuell angeben
    pub path: Option<String>,

    /// Einmal erlauben trotz Fund (für bewusste Ausnahmen)
    #[arg(long)]
    pub allow_once: bool,
}

// ── AUDIT ─────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct AuditArgs {
    /// Was soll angezeigt werden: "runs" (Standard) oder "secrets"
    #[arg(long, default_value = "runs")]
    pub target: String,

    /// Anzahl der letzten Einträge
    #[arg(long, default_value = "20")]
    pub limit: usize,

    /// Pipeline filtern
    #[arg(long)]
    pub pipeline: Option<String>,

    /// Environment filtern
    #[arg(long, short)]
    pub env: Option<String>,

    /// Als JSON-Lines ausgeben (für SIEM-Forwarding / Compliance)
    #[arg(long)]
    pub json: bool,
}

// ── CHECK ─────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct CheckArgs {
    /// Environment prüfen (Standard: alle oder aktives Environment)
    #[arg(long, short)]
    pub env: Option<String>,
}
