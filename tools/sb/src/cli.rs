use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sb",
    author = "Skulls & Bones Lab <dev@skulls-and-bones.org>",
    version,
    about = "S&B Suite Master CLI — Unified Command Center for Sovereign Developer Tools",
    long_about = "S&B Master CLI (sb) steuert das modulare Skulls & Bones-Ökosystem: Produktinventar, signierte Suite-Installationen, zentrale Updates und Delegation an eigenständige Tools. NetGate/SSH bleibt eine Prototypfunktion und historische Produktnamen sind keine installierbaren Release-Binaries.",
    after_help = "ERST-EINRICHTUNG (SCHNELLSTART):\n  1. Workstation vorbereiten:      sb up\n  2. Domain Controller aufsetzen:    sb server dc-init --target root@<VPS-IP> --domain <domain>\n  3. Einer Domäne beitreten:         sb join <domain> --dc https://console.<domain>\n  4. Systemstatus & Diagnose:        sb status  |  sb doctor --fix"
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

        /// Selbst-Update direkt über GitHub Releases (Standard bei 'sb update' ohne Argumente)
        #[arg(long)]
        github: bool,

        /// Bestimmtes Release-Tag für GitHub-Update (z. B. v0.2.2)
        #[arg(long, value_name = "TAG")]
        tag: Option<String>,

        /// Aktualisiert einen registrierten Remote-Server aus ~/.sb/servers.toml (z. B. 'srv490042')
        #[arg(long, value_name = "SERVER")]
        server: Option<String>,

        /// Baut und installiert Release-Binaries direkt aus dem lokalen Cargo-Workspace nach ~/.sb/bin
        #[arg(long)]
        from_workspace: bool,
    },

    /// Erstellt und signiert verifizierbare S&B-Releases
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },

    /// Führt einen 360-Grad Integritäts- und Sicherheits-Check der S&B Suite durch
    Doctor {
        /// Behebt erkannte Probleme und Berechtigungsfehler automatisch
        #[arg(long)]
        fix: bool,

        /// Gibt das Diagnose-Ergebnis als maschinenlesbares JSON aus
        #[arg(long)]
        json: bool,
    },

    /// Delegiert an S&B NetGate (sb-ssh)
    Ssh {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Domänen-Verwaltung (sb domain status | list | join | revoke) -> delegiert an sb-node
    Domain {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Signierte Cross-Platform GPOs (sb policy apply | list | status) -> delegiert an sb-node
    Policy {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Domänen-Agent-Dienst (sb agent install | start | stop | restart | status | update | uninstall) -> delegiert an sb-node service
    Agent {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Domänen-Benutzer & SSH-Zertifikate (sb user add | list | ssh-cert | offboard) -> delegiert an sb-node
    User {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Öffnet einen sicheren TCP-Port-Tunnel über das HTTPS-443 Relay zu einer Remote-Maschine
    Tunnel {
        /// Ziel-Maschinen-ID (z.B. mach_d61a1fc747530eb2)
        machine: String,
        /// Remote-TCP-Port auf der Zielmaschine (z.B. 3389, 5432, 8080)
        remote_port: u16,
        /// Lokaler Listen-Port auf 127.0.0.1 (Standard: identisch mit remote_port)
        #[arg(long)]
        local_port: Option<u16>,
        /// Optionale Domain-Controller-URL (überschreibt session.json)
        #[arg(long)]
        dc: Option<String>,
    },

    /// Server-Management & Flotten-Bootstrap (sb server dc-init, sb server init <target>)
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },

    /// Tritt einer Domäne (z. B. corp.example.sb) oder einem Mesh (sbm-pair://...) bei
    Join {
        /// Domänenname (z. B. corp.example.sb) oder Pairing-Token (sbm-pair://...)
        target: String,

        /// Optionaler Name des Entwicklers (nur für sbm-pair:// Mesh-Pairing)
        #[arg(short, long)]
        name: Option<String>,

        /// Adresse des Domain Controllers (z. B. https://console.skulls-and-bones.org)
        #[arg(long)]
        dc: Option<String>,

        /// Join-/Access-Token für den Domänenbeitritt
        #[arg(long)]
        token: Option<String>,

        /// Domänen-Benutzername (wie bei Windows-Domänenbeitritt)
        #[arg(short, long)]
        username: Option<String>,

        /// Domänen-Passwort (ohne Angabe erfolgt verdeckte Eingabe)
        #[arg(short, long)]
        password: Option<String>,

        /// Hintergrunddienst (sb-node service install) nicht automatisch einrichten
        #[arg(long)]
        no_service: bool,

        /// Trockenlauf ohne Systemänderungen
        #[arg(long)]
        dry_run: bool,
    },

    /// Verwaltet Isolations- und Projekt-Kontexte (sb context list|use|create|remove)
    #[command(alias = "ctx")]
    Context {
        #[command(subcommand)]
        action: Option<ContextAction>,
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

    /// Richtet einen Sovereign Domain Controller auf einem VPS ein (ersetzt install-dc.sh)
    #[command(alias = "dc")]
    DcInit {
        /// Optionaler Zielserver via SSH (z. B. 'root@145.223.83.235' oder Alias aus servers.toml; ohne Angabe lokal auf dem VPS)
        #[arg(long)]
        target: Option<String>,

        /// Domänenname (z. B. skulls-and-bones.sb)
        #[arg(long, default_value = "skulls-and-bones.sb")]
        domain: String,

        /// Öffentlicher Hostname der Web-Konsole (Standard: console.<domain>)
        #[arg(long)]
        console_host: Option<String>,

        /// Öffentlicher Hostname für Enrollment (Standard: enroll.<domain>)
        #[arg(long)]
        enroll_host: Option<String>,

        /// Initialer Admin-Benutzername (Standard: sb.admin)
        #[arg(long, default_value = "sb.admin")]
        admin: String,

        /// Initiales Admin-Passwort (ohne Angabe wird ein sicheres Zufallspasswort generiert)
        #[arg(long)]
        password: Option<String>,

        /// TLS Reverse-Proxy Engine ('caddy' oder 'sb-proxy')
        #[arg(long, default_value = "caddy")]
        proxy: String,

        /// Optionale URL zu einem Linux Release-Tarball (.tar.gz)
        #[arg(long)]
        tarball_url: Option<String>,

        /// Trockenlauf: Gibt das Setup-Skript aus, ohne Änderungen vorzunehmen
        #[arg(long)]
        dry_run: bool,
    },

    /// Sichert DC-Zustand (domain, ca, auth) lokal oder von einem Remote-Server in ein .tar.gz Archiv
    Backup {
        /// Optionaler Zielserver via SSH (z. B. 'srv490042'; ohne Angabe lokal)
        #[arg(long)]
        target: Option<String>,

        /// Ausgabedatei (Standard: sb-dc-backup-<timestamp>.tar.gz)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Stellt einen DC-Zustand aus einem Backup-Archiv lokal oder auf einem Server wieder her
    Restore {
        /// Pfad zum Backup-Archiv (.tar.gz)
        #[arg(short, long)]
        input: PathBuf,

        /// Optionaler Zielserver via SSH (z. B. 'srv490042'; ohne Angabe lokal)
        #[arg(long)]
        target: Option<String>,
    },
}
