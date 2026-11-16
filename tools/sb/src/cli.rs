use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sb",
    author = "Skulls & Bones Lab <dev@skulls-and-bones.org>",
    version,
    about = "S&B Suite Master CLI — Unified Command Center for Sovereign Developer Tools",
    long_about = "S&B Master CLI (sb) steuert das modulare Skulls & Bones-Ökosystem: Produktinventar, signierte Suite-Installationen, zentrale Updates und Delegation an eigenständige Tools. NetGate/SSH bleibt eine Prototypfunktion und historische Produktnamen sind keine installierbaren Release-Binaries."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Taktisches System-HUD über alle installierten S&B-Komponenten und Daemons
    #[command(alias = "s")]
    Status {
        /// Maschinenlesbare JSON-Ausgabe
        #[arg(long)]
        json: bool,
    },

    /// Idempotenter 1-Befehl Workstation- & Session-Bringup (Identity + Dual-CA + 8h RAM-Lease + Context)
    #[command(alias = "bringup")]
    Up {
        /// Behebt Berechtigungen und verankert die X.509 Root-CA automatisch im OS-Trust-Store
        #[arg(long)]
        fix: bool,

        /// Maschinenlesbare JSON-Ausgabe (RFC 8259)
        #[arg(long)]
        json: bool,
    },

    /// Persistenter OS- & Systemd-Daemon-Orchestrator für die 4 S&B-Kerndienste (sb-node, sb-mesh, sb-proxy, sb-dns)
    #[command(alias = "svc")]
    Service {
        #[command(subcommand)]
        action: Option<ServiceAction>,

        /// Maschinenlesbare JSON-Ausgabe (RFC 8259)
        #[arg(long)]
        json: bool,
    },

    /// 1-Befehl Bidirektionale Workstation-zu-Server-Kopplung (OpenSSH Dual-CA + Host-Cert + WireGuard Mesh-Peers)
    #[command(alias = "pair")]
    Link {
        /// Zielserver (z. B. 'root@145.223.83.235' oder registrierter Alias)
        target: String,

        /// Optionaler Aliasname für ~/.sb/servers.toml und <alias>.sbm
        #[arg(short, long)]
        name: Option<String>,

        /// Lokales Mesh-Netz, in das der Server als Peer eingetragen wird (Standard: aktives Netz)
        #[arg(short, long)]
        mesh: Option<String>,

        /// Maschinenlesbare JSON-Ausgabe (RFC 8259)
        #[arg(long)]
        json: bool,
    },
    /// Zeigt das kanonische Suite-Produktinventar über den lokalen Daemon an
    Catalog {
        /// Ausgabe des vollständigen Inventars als JSON
        #[arg(long)]
        json: bool,
    },

    /// Zeigt aktive S&B Hintergrund-Dienste und Tunnels (sb ps)
    #[command(alias = "p")]
    Ps,

    /// Beendet laufende S&B Hintergrund-Dienste (sb stop <NAME|PID|all>)
    Stop {
        /// Name, PID oder 'all' (Standard: 'all')
        target: Option<String>,
    },

    /// Verwaltet oder erneuert das flüchtige 8-Stunden Ephemeral Lease (sb lease [--ttl <hours>])
    #[command(alias = "l")]
    Lease {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Beendet die aktive Sitzung sofort, schreddert das Lease im RAM und sperrt das System
    #[command(alias = "k")]
    Lock,

    /// Delegiert an S&B Key (sb-key) — Sovereign Root Identity & Ephemeral RAM Leases
    Key {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// 1-Befehl Projekt-Bootstrap: Erzeugt Forge.toml und erkennt den Tech-Stack
    Init {
        /// Überschreibt bestehende Konfigurationen (--force)
        #[arg(short, long)]
        force: bool,

        /// Optional: Spezifisches Template erzwingen (rust, node, python, go, generic)
        #[arg(short, long)]
        template: Option<String>,
    },

    /// Direkter 1-Klick Shortcut: Startet Prozess mit im RAM injizierten Secrets (sb run -- <cmd...>)
    #[command(alias = "r")]
    Run {
        /// Ziel-Environment (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,

        /// Auszuführender Befehl samt Parametern (z.B. 'sb run -- npm run dev')
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Sovereign Dotenv & Memory Secret Injection: Startet Prozesse ohne Klartext-Dateien auf Disk
    #[command(alias = "e")]
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },

    /// Signierte, vorgebaute S&B-Releases installieren (ohne Cargo auf dem Zielsystem)
    Install {
        /// Werkzeuge: drive, forge, mesh, ports, node, key, code, proxy, shell, securenet, dns, db, sb, all
        #[arg(num_args = 0..)]
        tools: Vec<String>,

        /// Erzwingt die Neuinstallation (--force)
        #[arg(short, long)]
        force: bool,

        /// Erlaubt ausdrücklich die Installation einer älteren signierten Version
        #[arg(long)]
        allow_downgrade: bool,

        /// Lokales Verzeichnis mit signierten Release-Archiven (.tar.gz/.zip + .sig)
        #[arg(long, value_name = "DIR")]
        from_dir: Option<PathBuf>,

        /// Basis-URL für HTTP(S)-Release-Mirrors
        #[arg(long, value_name = "URL")]
        from_url: Option<String>,

        /// Installation aus einem lokalen/verbundenen Mesh-Netzwerk (z.B. public oder dev)
        #[arg(long, value_name = "MESH")]
        from_mesh: Option<String>,
    },

    /// Modular ein oder mehrere S&B-Werkzeuge deinstallieren (z.B. 'sb uninstall vault')
    Uninstall {
        /// Werkzeuge zum Deinstallieren: ssh, forge, mesh, vault, all
        #[arg(num_args = 0..)]
        tools: Vec<String>,
    },

    /// Aktualisiert installierte S&B-Binaries aus signierten Releases
    Update {
        /// Optional spezifische Werkzeuge aktualisieren (z.B. 'sb update mesh')
        #[arg(num_args = 0..)]
        tools: Vec<String>,

        /// Erlaubt ausdrücklich das Update auf eine ältere signierte Version
        #[arg(long)]
        allow_downgrade: bool,

        /// Lokales Verzeichnis mit signierten Release-Archiven (.tar.gz/.zip + .sig)
        #[arg(long, value_name = "DIR")]
        from_dir: Option<PathBuf>,

        /// Basis-URL für HTTP(S)-Release-Mirrors
        #[arg(long, value_name = "URL")]
        from_url: Option<String>,

        /// Update aus einem lokalen/verbundenen Mesh-Netzwerk (z.B. public oder dev)
        #[arg(long, value_name = "MESH")]
        from_mesh: Option<String>,
    },

    /// Erstellt und signiert verifizierbare S&B-Releases
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },

    /// Zeigt oder erzeugt die gemeinsame kryptographische Identität (~/.sb/identity.json)
    Identity,

    /// Führt einen 360-Grad Integritäts- und Sicherheits-Check der S&B Suite durch
    Doctor {
        /// Behebt erkannte Probleme und Berechtigungsfehler automatisch
        #[arg(long)]
        fix: bool,

        /// Gibt das Diagnose-Ergebnis als maschinenlesbares JSON aus
        #[arg(long)]
        json: bool,
    },

    /// Generiert Shell-Autovervollständigungen (powershell, bash, zsh, fish, elvish)
    Completions {
        /// Ziel-Shell: powershell, bash, zsh, fish, elvish
        shell: clap_complete::Shell,
    },

    /// Teilt einen lokalen Entwicklungs-Port Ende-zu-Ende verschlüsselt über das S&B Mesh (Ngrok-Alternative)
    Share {
        /// Lokaler Port zum Teilen (z.B. 3000, 8080). Erkennt automatisch aktive Dev-Server, wenn weggelassen.
        port: Option<u16>,

        /// Optionales Label / Subdomain (z.B. 'dev-api')
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Delegiert an S&B NetGate (sb-ssh)
    Ssh {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Delegiert an S&B Mesh (sb-mesh)
    Mesh {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Delegiert an S&B Vault (sb-vault Desktop) oder startet das Terminal-Cockpit (--tui)
    Vault {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Interaktives Terminal-Cockpit & Operator HUD (sb cockpit / sb hud) für Daemons, Mesh & Audit
    #[command(alias = "hud")]
    Cockpit {
        /// Headless Snapshot-Modus: Gibt den aktuellen HUD-Status non-interaktiv auf stdout aus und beendet sich mit 0
        #[arg(
            long,
            help = "Headless Snapshot-Modus: Gibt den aktuellen HUD-Status non-interaktiv auf stdout aus und beendet sich mit 0"
        )]
        snapshot: bool,

        /// Aktualisierungsintervall in Millisekunden
        #[arg(
            short,
            long,
            default_value_t = 1000,
            help = "Aktualisierungsintervall in Millisekunden"
        )]
        poll_interval: u64,
    },

    /// Delegiert an S&B Server Agent (sb-node) — Headless Daemon & Port Watchdog, oder führt Node-Bootstrap aus
    Node {
        #[command(subcommand)]
        action: Option<NodeAction>,
    },

    /// Delegiert an S&B Proxy (sb-proxy) — Sovereign Pure-Rust Reverse-Proxy & Edge Gateway
    #[command(alias = "px")]
    Proxy {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Delegiert an S&B Unified PKI & CA (sb-ca) — OpenSSH (RFC 4251) & X.509 (RFC 5280) Certificate Authority
    Ca {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Delegiert an S&B Auth (sb-auth) — Sovereign Authentication, Multi-Tier Revocation & Identity CLI
    Auth {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Delegiert an S&B Sovereign DNS (sb-dns) — Systemweiter .sbm Split-DNS Resolver & Mesh Router
    Dns {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Veröffentlicht das aktuelle Projekt als P2P Code-Stream im Swarm (sb publish [project])
    Publish {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Abonniert einen P2P Code-Stream aus dem Mesh Swarm (sb subscribe <project>)
    Subscribe {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Server-Management & Flotten-Bootstrap (sb server init <target>, sb server token)
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },

    /// Team-Onboarding mit 4-Augen-Prinzip (sb invite client <name>, sb invite list)
    Invite {
        #[command(subcommand)]
        action: InviteAction,
    },

    /// Tritt einem Sovereign Mesh via Einladungs-Token bei (sb join <token>)
    Join {
        /// Pairing-Token (sbm-pair://...)
        token: String,

        /// Optionaler Name des Entwicklers (Standard: im Token kodiert)
        #[arg(short, long)]
        name: Option<String>,
    },

    /// 4-Augen-Prinzip: Gibt eine ausstehende Beitrittsanfrage frei (sb approve <request_id>)
    Approve {
        /// ID der Beitrittsanfrage (z. B. 'req-3a8f')
        request_id: String,

        /// Approver-Identität überschreiben (für Tests/Simulations-Zwecke)
        #[arg(long)]
        approver: Option<String>,
    },

    /// Atomarer Hardware- & Identitäts-Rauswurf (sb revoke <name>)
    Revoke {
        /// Name des zu entfernenden Entwicklers / Knotens
        name: String,

        /// Grund für den Rauswurf (z. B. 'offboarding', 'lost-device')
        #[arg(short, long, default_value = "admin-revocation")]
        reason: String,
    },

    /// Sovereign Egress & Tunnel: Gibt lokale Webdienste ohne Port-Forwarding über das S&B Gateway frei
    Escape {
        #[command(subcommand)]
        action: EscapeAction,
    },

    /// Baut eine Web-App und veröffentlicht sie über den S&B Proxy aus dem Mesh
    Web {
        #[command(subcommand)]
        action: WebAction,
    },

    /// Verwaltet Isolations- und Projekt-Kontexte (sb context list|use|create|remove)
    #[command(alias = "ctx")]
    Context {
        #[command(subcommand)]
        action: Option<ContextAction>,
    },

    /// Blitzschneller Shortcut zum Umschalten des aktiven Kontexts (sb use <name>)
    #[command(alias = "u")]
    Use {
        /// Name des zu aktivierenden Kontexts (z. B. 'acme-corp', 'homelab')
        name: String,
    },

    /// Live-Log-Streaming und Smart Crash Inspector von Flottenknoten und lokalen Diensten (sb logs)
    #[command(alias = "log")]
    Logs {
        /// Server-Name oder .sbm Domain (optional, z. B. 'web01', Standard: lokales Log)
        server: Option<String>,

        /// Dienst- oder Service-Name (z.B. 'nginx', 'api', 'docker')
        service: Option<String>,

        /// Logs kontinuierlich im Stream verfolgen (-f / --follow)
        #[arg(short, long)]
        follow: bool,

        /// Anzahl der anzuzeigenden Zeilen (Standard: 50)
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,

        /// Nur lokale Logs anzeigen
        #[arg(long)]
        local: bool,
    },

    /// Flotten-Telemetrie & Watchdog Alerts (sb trace [server])
    Trace {
        /// Optionaler Server-Name oder .sbm Domain (Standard: lokaler Knoten & Edge-Proxy)
        server: Option<String>,

        /// Live-Monitoring kontinuierlich im Terminal aktualisieren (-w / --watch)
        #[arg(short, long)]
        watch: bool,

        /// Aktualisierungs-Intervall in Sekunden (Standard: 2s)
        #[arg(short, long, default_value_t = 2)]
        interval: u64,
    },

    /// Kryptographisches 4-Augen Quorum Gate für Code-Merges, Secrets und Flottenaktionen (sb quorum)
    #[command(alias = "q")]
    Quorum {
        #[command(subcommand)]
        action: QuorumAction,
    },

    /// Startet den Sovereign Headless Daemon & Loopback JSON-RPC API Server (sb daemon [--port <p>] [--api])
    Daemon {
        /// Port für die lokale JSON-RPC API (Standard: 58905)
        #[arg(short, long)]
        port: Option<u16>,

        /// Führt den Daemon als API-Server für GUI & externe Clients aus
        #[arg(long, default_value_t = true)]
        api: bool,

        /// Startet den Daemon im Hintergrund (Detached Service)
        #[arg(short = 'd', long)]
        detach: bool,
    },

    /// Zentrale Suite-Konfiguration anzeigen oder anpassen (~/.sb/config.toml)
    #[command(alias = "cfg")]
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[derive(Subcommand, Debug)]
pub enum WebAction {
    /// Baut das Projekt, startet den Produktionsserver und verbindet ihn mit sb-proxy
    Publish {
        /// Öffentliche Domain, die auf den S&B Proxy zeigt
        domain: String,

        /// Projektverzeichnis (Standard: aktuelles Verzeichnis)
        #[arg(short = 'd', long, default_value = ".")]
        project_dir: PathBuf,

        /// Lokaler Port des Produktionsservers
        #[arg(short, long, default_value_t = 3000)]
        port: u16,

        /// Callsign des Nodes auf dem öffentlichen sb-proxy Gateway
        #[arg(long, default_value = "hostinger-node")]
        node: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReleaseAction {
    /// Packt Binaries in ein Plattformarchiv und aktualisiert das Release-Manifest
    Pack {
        #[arg(long)]
        version: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        input_dir: PathBuf,
        #[arg(long, default_value = "dist")]
        output_dir: PathBuf,
        #[arg(long, default_value = "tar.gz", value_parser = ["tar.gz", "zip"])]
        format: String,
    },
    /// Packt alle für das Plattformziel erforderlichen Suite-Binaries und signiert optional direkt das Manifest
    PackAll {
        #[arg(long)]
        version: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value = "target/release")]
        input_dir: PathBuf,
        #[arg(long, default_value = "dist")]
        output_dir: PathBuf,
        #[arg(long, default_value = "tar.gz", value_parser = ["tar.gz", "zip"])]
        format: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Signiert die exakten Manifest-Bytes mit dem Release-Ed25519-Key (32-Byte-Seed oder 64 Hex-Zeichen)
    Sign {
        #[arg(long, default_value = "dist/release-manifest.json")]
        manifest: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Prüft die kryptographische Integrität und Ed25519-Signatur installierter Suite-Binaries
    Verify {
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// Erzeugt ein neues kryptographisches Ed25519 Release-Schlüsselpaar
    GenKey {
        #[arg(long, default_value = "release.key")]
        output: PathBuf,
    },
    /// Prüft einen Release-Schlüssel oder ein Backup auf Gültigkeit und Abgleich mit dem gepinnten Installer-Key
    VerifyKey {
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Publiziert ein signiertes Release-Paket in einen Mesh-Objekt-Namespace (Publish)
    Publish {
        /// Pfad zum signierten Release-Manifest (Standard: dist/release-manifest.json)
        #[arg(long, default_value = "dist/release-manifest.json")]
        manifest: PathBuf,
        /// Optionaler Signing-Key zur Signierung/Verifikation vor dem Publizieren
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Mesh-Netzwerkname (z.B. public oder dev, Standard: public)
        #[arg(long, default_value = "public")]
        mesh: String,
        /// Namespace innerhalb des Meshes (Standard: releases)
        #[arg(long, default_value = "releases")]
        namespace: String,
    },
    /// Lädt ein signiertes Release-Paket aus dem Mesh herunter und verifiziert Hash & Ed25519-Signatur (Fetch)
    Fetch {
        /// Release-Version (z.B. 0.2.1)
        #[arg(long)]
        version: String,
        /// Ziel-Plattform (Standard: aktuelle Host-Plattform)
        #[arg(long)]
        target: Option<String>,
        /// Mesh-Netzwerkname (Standard: public)
        #[arg(long, default_value = "public")]
        mesh: String,
        /// Namespace innerhalb des Meshes (Standard: releases)
        #[arg(long, default_value = "releases")]
        namespace: String,
        /// Ausgabe-Verzeichnis für heruntergeladene und verifizierte Release-Artefakte
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigAction {
    /// Konfigurationswert abfragen oder gesamte Konfiguration anzeigen (sb config get [key])
    #[command(alias = "show")]
    Get {
        /// Konfigurationsschlüssel (z. B. 'ports.mesh_udp', 'network.default_server')
        key: Option<String>,
    },

    /// Konfigurationswert persistent setzen (sb config set <key> <value>)
    Set {
        /// Konfigurationsschlüssel (z. B. 'ports.mesh_udp', 'network.default_server')
        key: String,

        /// Neuer Wert
        value: String,
    },

    /// Zeigt den Pfad zur aktiven Konfigurationsdatei an
    Path,
}

#[derive(Subcommand, Debug)]
pub enum QuorumAction {
    /// Listet offene Quorum-Anfragen auf (sb quorum list [--all] [--category <cat>])
    #[command(alias = "ls")]
    List {
        /// Zeigt auch vergangene, abgelehnte und ausgeführte Anfragen an
        #[arg(short, long)]
        all: bool,

        /// Filter nach Kategorie (code-merge, secret-unlock, infra-config, fleet-destruct, generic)
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Erstellt eine neue 4-Augen Quorum-Anfrage (sb quorum create <category> <target> <description>)
    Create {
        /// Kategorie: code-merge, secret-unlock, infra-config, fleet-destruct, generic
        category: String,

        /// Ziel der Aktion (z. B. 'branch:main', 'secret:stripe-prod', 'host:gpu-01')
        target: String,

        /// Begründung / Beschreibung der geschützten Aktion
        description: String,

        /// Anzahl erforderlicher Genehmigungen (Standard: 2)
        #[arg(short, long)]
        required: Option<u32>,

        /// Gültigkeitsdauer in Minuten (Standard: 60)
        #[arg(short, long)]
        ttl: Option<u64>,

        /// Optionaler Payload (Befehl / Pfad / Metadaten)
        #[arg(long)]
        payload: Option<String>,

        /// Optional: Initiator-Name überschreiben (für Tests)
        #[arg(long)]
        initiator: Option<String>,
    },

    /// Genehmigt und signiert eine ausstehende Quorum-Anfrage mit aktiver Lease (sb quorum approve <id>)
    Approve {
        /// Proposal-ID (z. B. 'qrm-3a8f9b2c')
        id: String,

        /// Optional: Approver-Identität überschreiben (für Tests)
        #[arg(long)]
        approver: Option<String>,
    },

    /// Lehnt eine ausstehende Quorum-Anfrage ab (sb quorum reject <id>)
    Reject {
        /// Proposal-ID (z. B. 'qrm-3a8f9b2c')
        id: String,

        /// Optionaler Grund für die Ablehnung
        #[arg(short, long)]
        reason: Option<String>,

        /// Optional: Rejecter-Identität überschreiben (für Tests)
        #[arg(long)]
        rejecter: Option<String>,
    },

    /// Zeigt Details und verifizierte Signaturen einer Quorum-Anfrage an (sb quorum show <id>)
    Show {
        /// Proposal-ID (z. B. 'qrm-3a8f9b2c')
        id: String,
    },

    /// Führt eine vollständig genehmigte Quorum-Aktion aus (sb quorum execute <id>)
    Execute {
        /// Proposal-ID (z. B. 'qrm-3a8f9b2c')
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ContextAction {
    /// Listet alle gespeicherten Kontexte auf
    #[command(alias = "ls")]
    List,

    /// Zeigt den aktuell aktiven Kontext an
    Current,

    /// Schaltet den aktiven Kontext um
    #[command(alias = "switch")]
    Use {
        /// Name des Kontexts
        name: String,
    },

    /// Erstellt einen neuen Kontext
    Create {
        /// Eindeutiger Name des Kontexts (z. B. 'acme-corp')
        name: String,

        /// Beschreibung des Kunden oder Projekts
        #[arg(short, long)]
        desc: Option<String>,

        /// Standard-Environment (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,

        /// Optionaler Arbeitsordner / Projektpfad
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Standard-Server für Remote-Operationen
        #[arg(short, long)]
        server: Option<String>,

        /// Mesh Swarm Namespace
        #[arg(long)]
        swarm: Option<String>,
    },

    /// Löscht einen bestehenden Kontext
    #[command(alias = "rm")]
    Remove {
        /// Name des zu löschenden Kontexts
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum EscapeAction {
    /// Gibt einen lokalen Port über einen Sovereign Tunnel an ein Escape Space Gateway frei
    Share {
        /// Lokaler Port (z.B. 3000, 5173, 8080)
        port: u16,

        /// Öffentliche Domain des Escape Spaces (z.B. 'preview.myteam.io')
        #[arg(long = "as")]
        domain: String,

        /// Gateway Tunnel-Port-Adresse (Standard: 127.0.0.1:58910 oder IP:58910)
        #[arg(short, long, default_value = "127.0.0.1:58910")]
        gateway: String,
    },

    /// Listet alle registrierten Escape Spaces und ihren Tunnel-Status auf
    List,

    /// Aktiviert oder deaktiviert den Sovereign-Tunnel-Modus für einen Escape Space
    Tunnel {
        /// Space ID oder Domain
        space: String,

        /// Tunnel-Modus aktivieren (--enable) oder deaktivieren (--disable)
        #[arg(long)]
        enable: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum EnvAction {
    /// Startet einen Prozess mit flüchtig in den RAM injizierten Secrets (ohne .env-Dateien auf Disk)
    Run {
        /// Ziel-Environment (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,

        /// Auszuführender Befehl samt Argumenten (z.B. 'sb env run -- npm run dev')
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Setzt ein Secret oder eine Umgebungsvariable im verschlüsselten Vault
    Set {
        /// Name des Secrets (z.B. DATABASE_URL)
        name: String,

        /// Wert des Secrets (optional; falls weggelassen, wird sicher interaktiv abgefragt)
        #[arg(long)]
        value: Option<String>,

        /// Ziel-Environment (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,
    },

    /// Zeigt den entschlüsselten Wert eines Secrets an (erfordert aktives Lease)
    Get {
        /// Name des Secrets
        name: String,

        /// Ziel-Environment (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,
    },

    /// Listet alle gespeicherten Secrets im Vault auf (maskiert)
    List {
        /// Optional: Spezifisches Environment filtern (dev, staging, prod)
        #[arg(short, long)]
        env: Option<String>,
    },

    /// Importiert eine bestehende .env-Datei in den verschlüsselten Vault
    Import {
        /// Pfad zur .env Datei (z.B. .env oder .env.local)
        file: PathBuf,

        /// Ziel-Environment (Standard: dev)
        #[arg(short, long, default_value = "dev")]
        env: String,

        /// Löscht die unsichere Klartext-Quelldatei nach erfolgreichem Import
        #[arg(short = 'd', long)]
        delete_source: bool,
    },

    /// Repliziert den verschlüsselten lokalen Secret-Vault sicher auf einen Remote-Server (mit SHA-256 Verifikation)
    Sync {
        /// Zielserver (Name aus ~/.sb/servers.toml oder user@host)
        server: String,

        /// Ziel-Environment (Standard: dev)
        #[arg(short, long, default_value = "dev")]
        env: String,

        /// Maschinenlesbare JSON-Ausgabe (RFC 8259)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServiceAction {
    /// Installiert und aktiviert die 4 S&B-Kerndienste als persistente OS-/Systemd-Units
    Install {
        /// Maschinenlesbare JSON-Ausgabe
        #[arg(long)]
        json: bool,
    },

    /// Startet alle 4 S&B-Kerndienste (sb-node, sb-mesh, sb-proxy, sb-dns)
    Start {
        /// Maschinenlesbare JSON-Ausgabe
        #[arg(long)]
        json: bool,
    },

    /// Beendet alle 4 S&B-Kerndienste
    Stop {
        /// Maschinenlesbare JSON-Ausgabe
        #[arg(long)]
        json: bool,
    },

    /// Startet alle 4 S&B-Kerndienste neu
    Restart {
        /// Maschinenlesbare JSON-Ausgabe
        #[arg(long)]
        json: bool,
    },

    /// Zeigt den Live-Status aller 4 S&B-Kerndienste an
    Status {
        /// Maschinenlesbare JSON-Ausgabe
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum InviteAction {
    /// Lädt einen neuen Entwickler-Client ein (4-Augen-Prinzip bei Team-Swarms)
    Client {
        /// Name des Entwicklers (z. B. 'bob')
        name: String,

        /// Zugewiesene Rolle ('dev', 'admin', 'deploy')
        #[arg(short, long, default_value = "dev")]
        role: String,

        /// Gültigkeitsdauer des Tokens in Minuten
        #[arg(short, long, default_value = "15")]
        ttl: u64,
    },

    /// Zeigt offene Beitrittsanfragen zur 4-Augen-Prüfung
    List,
}

#[derive(Subcommand, Debug)]
pub enum ServerAction {
    /// 1-Befehl Server Bootstrap: Verankert Swarm-CA, installiert sb-node und bindet Server ins Mesh ein
    Init {
        /// Zielserver (z. B. 'root@188.40.1.2' oder '188.40.1.2')
        target: String,

        /// Name des Knotens im Mesh (z. B. 'web01', Standard: Hostname)
        #[arg(short, long)]
        name: Option<String>,

        /// SSH-Port für den Initial-Connect (Standard: 22)
        #[arg(short, long, default_value = "22")]
        port: u16,

        /// SSH Identity-File für den Initial-Connect
        #[arg(short, long)]
        identity: Option<PathBuf>,

        /// Optionales SSH-Passwort für den Initial-Connect (Standard: fragt interaktiv ab)
        #[arg(long)]
        password: Option<String>,

        /// Ziel-Benutzer der eingerichtet werden soll (Standard: lokaler Benutzername)
        #[arg(short, long)]
        user: Option<String>,

        /// Gibt nur Token & Installationsbefehle aus, ohne direkte SSH-Ausführung (Dry-Run)
        #[arg(long)]
        dry_run: bool,
    },

    /// Generiert einen kryptographischen 1-Zeilen Pairing-Token für sb-node
    Token {
        /// Name des Server-Knotens (z. B. 'web01')
        #[arg(short, long, default_value = "server-node")]
        name: String,
    },

    /// Zeigt den Status bekannter Flotten-Server im Mesh
    List,

    /// Frische VPS -> gehärteter, mesh-bereiter Knoten (Key-Login, Admin-User, SSH/UFW, Units)
    Provision {
        /// Zielserver (Hostname oder IP)
        host: String,
        /// Initialer Login-Benutzer (Standard: root)
        #[arg(long, default_value = "root")]
        login: String,
        /// Admin-Benutzer, der angelegt wird und danach als einziger per SSH zugelassen ist
        #[arg(short, long, default_value = "sbadmin")]
        admin: String,
        /// Öffentlicher SSH-Schlüssel (Standard: ~/.ssh/id_ed25519.pub)
        #[arg(long)]
        pubkey: Option<PathBuf>,
        /// SSH-Port
        #[arg(short, long, default_value = "22")]
        port: u16,
        /// Mesh-Namen, die per Bootstrap angelegt werden (mehrfach angebbar)
        #[arg(long = "mesh")]
        meshes: Vec<String>,
        /// Verzeichnis mit vorgebauten Linux-Binaries (sb-node, sb-mesh, sb-code ...), per scp hochgeladen
        #[arg(long)]
        binaries: Option<PathBuf>,
        /// Nur das Provisioning-Skript ausgeben, nichts ausführen
        #[arg(long)]
        print_script: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum NodeAction {
    /// 1-Befehl Remote Server Provisioning via SSH & Swarm-CA
    Bootstrap(BootstrapArgs),

    /// Delegiert alle sonstigen Befehle transparent an den sb-node Agenten
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Args, Debug, Clone)]
pub struct BootstrapArgs {
    /// Zielserver (z. B. 'root@145.223.83.235' oder '145.223.83.235')
    pub target: String,

    /// SSH-Port für den Initial-Connect (Standard: 22)
    #[arg(short, long, default_value = "22")]
    pub port: u16,

    /// SSH Identity-File für den Initial-Connect
    #[arg(short = 'k', long = "key", alias = "identity", short_alias = 'i')]
    pub key: Option<PathBuf>,

    /// Optionales SSH-Passwort für den Initial-Connect
    #[arg(long)]
    pub password: Option<String>,

    /// Name des einzurichtenden unprivilegierten Admin-Benutzers (Standard: sbadmin)
    #[arg(short = 'a', long = "admin", default_value = "sbadmin")]
    pub admin: String,

    /// Swarm-CA Public Key in RFC 4251 Wire-Format (Standard: auto-detect via sb-ca)
    #[arg(long = "ca-key")]
    pub ca_key: Option<String>,

    /// Optionaler Pairing-Token (Standard: auto-generiert via Swarm-CA)
    #[arg(long = "mesh-token")]
    pub mesh_token: Option<String>,

    /// Mesh-Netzwerke, denen der Knoten beitreten soll (mehrfach angebbar)
    #[arg(short = 'm', long = "mesh")]
    pub mesh: Vec<String>,

    /// Verzeichnis mit vorgebauten Linux-Binaries (sb-node, sb-mesh ...)
    #[arg(short = 'b', long = "binaries")]
    pub binaries: Option<PathBuf>,

    /// Überschreibt bestehende Konfigurationen und Services
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Simuliert den Vorgang und gibt Ausführungsplan & Konfigurationen aus
    #[arg(short = 'n', long = "dry-run")]
    pub dry_run: bool,
}
