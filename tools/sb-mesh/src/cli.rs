use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "sb-mesh",
    about = "S&B Sovereign Mesh — User-Space P2P Overlay Network & Terminal TUI",
    version = "0.1.0"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch the interactive Ratatui terminal dashboard (Default)
    Tui,

    /// Run headless mesh node daemon
    Daemon {
        #[arg(short, long)]
        port: Option<u16>,
        /// Run in Anchor / Sovereign Hub mode (SBM-TEP ticket issuer & rendezvous broker)
        #[arg(long)]
        anchor: bool,
        /// Mesh network name to bind to (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },

    /// 1-Click Interactive Bootstrap Wizard for Company / Team Mesh Networks
    Bootstrap {
        /// Mesh network name (e.g. acme-mesh, dev-corp)
        #[arg(short, long)]
        name: Option<String>,

        /// Public anchor endpoint IP:Port (e.g. 145.223.83.235:58888 or vps.corp.net:58888)
        #[arg(short, long)]
        anchor: Option<String>,

        /// Overlay Subnet CIDR (default: 10.240.0.0/16)
        #[arg(short, long)]
        cidr: Option<String>,

        /// Administrator callsign / name (default: admin)
        #[arg(long)]
        admin: Option<String>,

        /// Headless / non-interactive mode (use defaults for any omitted fields)
        #[arg(long)]
        headless: bool,
    },

    /// Manage sb-mesh as native OS background service (Systemd on Linux, Windows Service on Windows — Zero Docker!)
    Service {
        #[command(subcommand)]
        sub: ServiceCommands,
    },

    /// Display current node status, public keys, and peer count
    Status,

    /// Inspect process and OS-level identity isolation for a mesh network
    Isolation {
        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
        /// Output isolation report as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage mesh peers
    Peer {
        #[command(subcommand)]
        sub: PeerCommands,
    },

    /// Generate or consume direct device pairing tokens (sbm-pair://)
    Pair {
        #[command(subcommand)]
        sub: PairCommands,
    },

    /// Send an authenticated cryptographic ping to a peer
    Ping {
        /// Callsign, Node ID or Public Key of the peer
        target: String,
    },

    /// Toggle or inspect Air-Gap killswitch status
    Airgap {
        /// Action: 'on', 'off', or 'toggle'
        #[arg(default_value = "toggle")]
        action: String,
    },

    /// Run user-space SOCKS5 proxy (127.0.0.1:1080)
    Proxy {
        /// Local port for SOCKS5 proxy listener
        #[arg(short, long, default_value_t = 1080)]
        port: u16,

        /// Mesh network name (default: active mesh network, e.g. dev-mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },

    /// Establish a P2P port-forwarding tunnel to a peer
    Tunnel {
        /// Local listening port (e.g. 8080)
        #[arg(short, long)]
        local: u16,
        /// Remote destination address (e.g. 10.240.0.2:80 or target_ip:port)
        #[arg(short, long)]
        remote: String,
    },

    /// Establish an encrypted Mesh Stealth Ingress tunnel to a remote service (e.g. SSH over Port 58888)
    Stealth {
        /// Remote node endpoint (default: from ~/.sb/config.toml or 145.223.83.235:58888)
        #[arg(short, long)]
        server: Option<String>,

        /// Remote target service port on server's loopback (e.g. 22 for SSH)
        #[arg(short, long, default_value_t = 22)]
        target_port: u16,

        /// Local listening port on client's loopback (default: from ~/.sb/config.toml or 58822)
        #[arg(short, long)]
        local_port: Option<u16>,

        /// Mesh network name (default: active mesh network, e.g. dev-mesh)
        #[arg(short, long)]
        mesh: Option<String>,

        /// Swarm topic for Multi-Mesh routing (default: auto-resolved from ticket/mesh)
        #[arg(long)]
        swarm: Option<String>,

        /// Remote node public key (optional base64, auto-resolved via SBM-TEP if omitted)
        #[arg(long)]
        pubkey: Option<String>,

        /// Inactivity timeout in seconds before closing tunnel (0 = disabled, default: 120s)
        #[arg(long, default_value_t = 120)]
        idle_timeout: u64,

        /// Oneshot mode: terminate process immediately after the first SSH connection terminates
        #[arg(short, long)]
        oneshot: bool,
    },

    /// Display multi-hop routing table, subnet routes, and exit node status
    Routes,

    /// Manage Subnet Routes and VPC Gateway Bridges (AWS, Hetzner, On-Premise LANs)
    Route {
        #[command(subcommand)]
        sub: Option<RouteCommands>,

        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },

    /// Manage OS-level Magic Split-DNS (.sbm) routing (Windows NRPT, Linux systemd-resolved)
    Dns {
        #[command(subcommand)]
        sub: Option<DnsCommands>,
    },

    /// Revoke a compromised public key via P2P Gossip CRL
    Revoke {
        /// WireGuard Base64 public key to revoke
        pubkey: String,
        /// Reason for revocation
        #[arg(short, long, default_value = "Device compromised or decommissioned")]
        reason: String,
    },

    /// Forward a local development port over loopback (not exposed to mesh peers)
    Share {
        /// Local port to share (e.g. 3000, 8080)
        port: u16,
        /// Optional service label or custom subdomain name
        #[arg(short, long)]
        label: Option<String>,
        /// Local service bind host (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Local loopback listener port (default: same as local port)
        #[arg(short, long)]
        ingress_port: Option<u16>,
    },

    /// Request to join a Sovereign Mesh using an Invite URI (requires administrator approval)
    Join {
        /// Invite URI or token (e.g. sbm-invite://eyJuYW1lIjoiYWxpY2Ui...)
        invite: String,
    },

    /// Create or manage sovereign invite tokens for user onboarding
    Invite {
        #[command(subcommand)]
        sub: InviteCommands,
    },

    /// Manage Active Directory-style Security Groups and permission inheritance
    Group {
        #[command(subcommand)]
        sub: GroupCommands,
    },

    /// Manage isolated Multi-Mesh Overlay Networks (VRF)
    Network {
        #[command(subcommand)]
        sub: NetworkCommands,
    },

    /// Manage Sovereign Mesh Pre-Auth Tickets (SBM-TEP)
    Ticket {
        #[command(subcommand)]
        sub: TicketCommands,
    },

    /// Manage Tenant-Scoped Role-Based Access Control (Mesh-RBAC)
    Rbac {
        #[command(subcommand)]
        sub: Option<RbacCommands>,

        /// Launch the interactive Cyberpunk Terminal TUI
        #[arg(long)]
        ui: bool,

        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum RbacCommands {
    /// Launch the interactive Cyberpunk Terminal TUI
    Ui {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// List all members, roles and capabilities for a mesh
    List {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// List mesh join requests awaiting local administrator approval
    Pending {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Approve a pending join request and activate its mesh membership
    Approve {
        /// Join request ID
        request_id: String,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Deny a pending join request
    Deny {
        /// Join request ID
        request_id: String,
        /// Denial reason
        #[arg(short, long, default_value = "Denied by administrator")]
        reason: String,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Add or update a member in a mesh
    Add {
        /// Name / identifier of the user
        #[arg(short, long)]
        name: String,
        /// Public key (Base64 X25519)
        #[arg(short, long)]
        pubkey: String,
        /// Role (Admin, Developer, Operator, Consumer, Auditor)
        #[arg(short, long, default_value = "Developer")]
        role: String,
        /// Optional custom capabilities (comma-separated, e.g. tunnel:ssh,tunnel:port:8080)
        #[arg(short, long)]
        caps: Option<String>,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Revoke a member from a mesh (instant KRL eviction)
    Revoke {
        /// Name or public key of the member
        #[arg(short, long)]
        name: String,
        /// Reason for revocation
        #[arg(short, long, default_value = "Administrative eviction")]
        reason: String,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Remove a member completely from a mesh
    Remove {
        /// Name or public key of the member
        #[arg(short, long)]
        name: String,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Show immutable security audit log (Security Audit Event Logging)
    Audit {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
        /// Number of recent entries to show
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
pub enum InviteCommands {
    /// Create a new signed invite token for single-command user onboarding
    Create {
        /// Name of the user to invite
        name: String,
        /// Role (Admin, Developer, Operator, Consumer, Auditor)
        #[arg(short, long, default_value = "Developer")]
        role: String,
        /// Optional groups to assign (comma-separated, e.g. developers,operators)
        #[arg(short, long)]
        groups: Option<String>,
        /// Time-to-live in hours (default: 24h)
        #[arg(short, long, default_value_t = 24)]
        ttl: u64,
        /// Maximum number of redemptions allowed (0 = unlimited, default: 1)
        #[arg(short, long, default_value_t = 1)]
        uses: u32,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
        /// Invite-URI auf stdout ausgeben (Standard: nur in 0600-Datei schreiben)
        #[arg(long)]
        print: bool,
    },
    /// List all generated invite tokens and their status
    List {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Revoke an existing invite token immediately
    Revoke {
        /// Invite token ID (e.g. inv-...)
        token: String,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum GroupCommands {
    /// List all security groups and their capabilities
    List {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Create or update a security group
    Add {
        /// Group identifier (e.g. frontend, database-admins)
        name: String,
        /// Human-readable description
        #[arg(short, long, default_value = "Security Group")]
        desc: String,
        /// Comma-separated capabilities (e.g. tunnel:ssh,tunnel:port:5432)
        #[arg(short, long)]
        caps: String,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Delete a security group
    Remove {
        /// Group identifier
        name: String,
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TicketCommands {
    /// Request or renew an authenticated ticket lease from server
    Request {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,

        /// Server address (default: from ~/.sb/config.toml)
        #[arg(short, long)]
        server: Option<String>,
    },

    /// Show current cached ticket status and lease expiry
    Status {
        /// Mesh network name (default: active mesh network)
        #[arg(short, long)]
        mesh: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum NetworkCommands {
    /// Create a new isolated overlay network
    Create {
        /// Network identifier (e.g. acme-dev, bank-prod)
        name: String,
        /// Isolated IPv4 CIDR subnet (e.g. 10.42.0.0/16)
        #[arg(short, long)]
        subnet: String,
        /// Description of the overlay network
        #[arg(short, long, default_value = "Isolated Overlay Network")]
        desc: String,
        /// Optional custom swarm topic namespace
        #[arg(long)]
        swarm: Option<String>,
        /// Optional legacy PSK metadata (not currently used by the transport)
        #[arg(long)]
        psk: Option<String>,
    },
    /// List all configured overlay networks
    List {
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Display details of the currently active overlay network
    Current,
    /// Switch active overlay network
    Switch {
        /// Name of the network to activate
        name: String,
    },
    /// Delete an isolated overlay network
    Delete {
        /// Name of the network to delete
        name: String,
    },
    /// Migrate legacy catalog PSKs into private per-mesh files
    MigratePsks,
}

#[derive(Subcommand, Debug)]
pub enum PeerCommands {
    /// Add a new peer manually
    Add {
        /// Callsign / Friendly name for the peer
        callsign: String,
        /// WireGuard-compatible Base64 public key (32 bytes)
        public_key: String,
        /// Peer socket endpoint IP:Port (e.g. 192.168.1.50:58888)
        #[arg(short, long)]
        endpoint: Option<String>,
        /// Optional internal overlay IP (e.g. 10.240.0.2)
        #[arg(short, long)]
        overlay_ip: Option<String>,
    },
    /// List all configured peers
    List,
    /// Remove a peer by public key or callsign
    Remove { target: String },
}

#[derive(Subcommand, Debug)]
pub enum PairCommands {
    /// Generate a pairing token to invite another device
    Generate {
        /// Your public or LAN IP:Port endpoint (e.g. 192.168.1.100:58888)
        endpoint: String,
        /// Display high-density terminal QR code for scanning
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// Time-to-Live (TTL) in seconds (default: 300s = 5 min, 0 = unlimited)
        #[arg(long, default_value_t = 300)]
        ttl: u64,
    },
    /// Connect to a device using a pairing token (sbm-pair://...)
    Connect {
        /// Friendly callsign for this new device
        callsign: String,
        /// The pairing token
        token: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServiceCommands {
    /// Install sb-mesh as native system service (Systemd on Linux, Background Service on Windows)
    Install {
        /// Run as Anchor node (SBM-TEP ticket issuer & rendezvous broker)
        #[arg(long)]
        anchor: bool,
        /// Port to listen on (default: 58888)
        #[arg(short, long)]
        port: Option<u16>,
        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Start the background service
    Start,
    /// Stop the background service
    Stop,
    /// Check service status and active process metrics
    Status,
    /// Uninstall the background service and clean up OS registrations
    Uninstall,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RouteCommands {
    /// List all advertised subnet routes and VPC gateways across the mesh
    List {
        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Advertise a local subnet (e.g. 10.0.0.0/16 or 192.168.1.0/24) into the mesh
    Advertise {
        /// Subnet CIDR prefix (e.g. 10.0.0.0/16)
        cidr: String,
        /// Reached endpoint of this gateway node (default: auto-detected or 127.0.0.1:58888)
        #[arg(short, long)]
        endpoint: Option<String>,
        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Withdraw a previously advertised subnet from the mesh
    Withdraw {
        /// Subnet CIDR prefix (e.g. 10.0.0.0/16)
        cidr: String,
        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Transparently forward a local port directly to a private VPC IP:Port via Subnet Router
    Forward {
        /// Local listening port on 127.0.0.1 (e.g. 5432)
        #[arg(short, long)]
        local_port: u16,
        /// Remote private VPC target address (e.g. 10.0.5.12:5432)
        #[arg(short, long)]
        target: String,
        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },
    /// Run the headless VPC Subnet Router & Egress Bridge worker
    Bridge {
        /// Subnet CIDR to advertise and bridge (optional)
        #[arg(short, long)]
        cidr: Option<String>,
        /// Mesh network name (default: active mesh)
        #[arg(short, long)]
        mesh: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DnsCommands {
    /// Install OS-level Magic Split-DNS (.sbm) routing (Windows NRPT / Linux systemd-resolved)
    Setup {
        /// DNS resolver IP to route .sbm queries to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        ip: String,
    },
    /// Remove OS-level Magic Split-DNS routing
    Teardown,
    /// Inspect OS-level Split-DNS registration status
    Status,
}
