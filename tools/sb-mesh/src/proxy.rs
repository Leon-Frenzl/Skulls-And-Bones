use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dns::SovereignResolver;

pub const DEFAULT_SOCKS5_PORT: u16 = 1080;

fn has_mesh_port_grant(capabilities: Option<&Vec<String>>, port: u16) -> bool {
    capabilities
        .map(|caps| crate::rbac::is_port_permitted(caps, port))
        .unwrap_or(false)
}

/// Subnet Route Definition for Sovereign Subnet Routing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetRoute {
    pub cidr: String,
    pub target_node_id: String,
    pub router_endpoint: SocketAddr,
}

/// Matches an IPv4 address against a CIDR prefix (e.g., 192.168.1.0/24)
pub fn ip_matches_cidr(ip: std::net::Ipv4Addr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let base_ip: std::net::Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix_len: u32 = match parts[1].parse() {
        Ok(len) if len <= 32 => len,
        _ => return false,
    };

    if prefix_len == 0 {
        return true;
    }

    let mask = !((1u32 << (32 - prefix_len)) - 1);
    let ip_u32 = u32::from(ip);
    let base_u32 = u32::from(base_ip);

    (ip_u32 & mask) == (base_u32 & mask)
}

/// User-Space Subnet Router & Exit Node Dispatcher
#[derive(Debug, Clone, Default)]
pub struct SubnetRouter {
    pub routes: Vec<SubnetRoute>,
    pub exit_node: Option<SocketAddr>,
}

impl SubnetRouter {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            exit_node: None,
        }
    }

    pub fn add_subnet_route(
        &mut self,
        cidr: &str,
        target_node_id: &str,
        router_endpoint: SocketAddr,
    ) {
        self.routes.push(SubnetRoute {
            cidr: cidr.to_string(),
            target_node_id: target_node_id.to_string(),
            router_endpoint,
        });
    }

    pub fn set_exit_node(&mut self, exit_endpoint: SocketAddr) {
        self.exit_node = Some(exit_endpoint);
    }

    pub fn resolve_target(&self, ip: std::net::Ipv4Addr) -> Option<SocketAddr> {
        for route in &self.routes {
            if ip_matches_cidr(ip, &route.cidr) {
                return Some(route.router_endpoint);
            }
        }
        self.exit_node
    }
}

/// User-Space SOCKS5 Proxy Server (RFC 1928)
///
/// Runs completely in user-space without requiring Wintun kernel drivers or administrator privileges.
/// Any browser, curl, git, or SSH client can route traffic through sb-mesh via SOCKS5 proxy 127.0.0.1:1080.
/// Automatically resolves sovereign `.sbm` domains across Layer 0 (Canonical), Layer 1 (Swarm Zone),
/// and Layer 2 (Petnames) with zero DNS-leaks.
/// Also routes configured LAN subnets and general traffic across Sovereign Subnet Routers and Exit Nodes.
pub struct Socks5Server {
    pub bind_port: u16,
    pub mesh_name: Option<String>,
    pub mesh_capabilities: Option<Arc<Vec<String>>>,
    pub resolver: Option<Arc<SovereignResolver>>,
    pub acl: Option<Arc<tokio::sync::RwLock<crate::acl::AclEngine>>>,
    pub subnet_router: Option<Arc<tokio::sync::RwLock<SubnetRouter>>>,
    pub subnet_store: Option<Arc<tokio::sync::RwLock<crate::subnet_route::SubnetRouteStore>>>,
}

impl Socks5Server {
    pub fn new(bind_port: u16) -> Self {
        Self {
            bind_port,
            mesh_name: None,
            mesh_capabilities: None,
            resolver: None,
            acl: None,
            subnet_router: None,
            subnet_store: None,
        }
    }

    pub fn with_resolver(mut self, resolver: Arc<SovereignResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_mesh_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.mesh_capabilities = Some(Arc::new(capabilities));
        self
    }

    pub fn with_mesh_ticket(
        mut self,
        ticket: &crate::ticket::CachedTicket,
        expected_mesh: &str,
        local_node_id: &str,
    ) -> Result<Self, String> {
        if !ticket.is_valid()
            || !ticket.mesh_name.eq_ignore_ascii_case(expected_mesh)
            || !ticket
                .grant
                .granted_mesh
                .eq_ignore_ascii_case(expected_mesh)
            || ticket.grant.subject_node_id != local_node_id
        {
            return Err("A valid mesh-bound ticket for the local node is required".to_string());
        }
        self.mesh_name = Some(expected_mesh.to_string());
        self.mesh_capabilities = Some(Arc::new(ticket.grant.capabilities.clone()));
        Ok(self)
    }

    pub fn with_acl(mut self, acl: Arc<tokio::sync::RwLock<crate::acl::AclEngine>>) -> Self {
        self.acl = Some(acl);
        self
    }

    pub fn with_subnet_router(mut self, router: Arc<tokio::sync::RwLock<SubnetRouter>>) -> Self {
        self.subnet_router = Some(router);
        self
    }

    pub fn with_subnet_store(
        mut self,
        store: Arc<tokio::sync::RwLock<crate::subnet_route::SubnetRouteStore>>,
    ) -> Self {
        self.subnet_store = Some(store);
        self
    }

    pub fn with_mesh_name(mut self, mesh: &str) -> Result<Self, String> {
        self.mesh_name = Some(mesh.to_string());
        if self.subnet_store.is_none() {
            let store = crate::subnet_route::SubnetRouteStore::load_or_create(mesh)?;
            self.subnet_store = Some(Arc::new(tokio::sync::RwLock::new(store)));
        }
        Ok(self)
    }

    /// Starts the SOCKS5 server listening on 127.0.0.1:bind_port
    pub async fn run(&self) -> Result<(), String> {
        let addr = format!("127.0.0.1:{}", self.bind_port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Failed to bind SOCKS5 listener on {}: {}", addr, e))?;

        println!("SOCKS5 User-Space Proxy active on {}", addr);
        if self.resolver.is_some() {
            println!("  Sovereign Name System: ACTIVE (.sbm domains routed natively)");
        }
        if self.acl.is_some() {
            println!("  Capability-Based ACLs: ENFORCED (Port-level default-deny)");
        }
        if self.subnet_router.is_some() {
            println!("  Subnet & Exit Routing: ACTIVE (Zero-tun user-space forwarding)");
        }
        if self.subnet_store.is_some() {
            println!("  VPC Subnet Routing:   ACTIVE (Zero-tun bridge to advertised subnets)");
        }

        loop {
            if let Ok((socket, peer_addr)) = listener.accept().await {
                let resolver = self.resolver.clone();
                let acl = self.acl.clone();
                let mesh_capabilities = self.mesh_capabilities.clone();
                let subnet_router = self.subnet_router.clone();
                let subnet_store = self.subnet_store.clone();
                tokio::spawn(async move {
                    let _ = handle_socks5_client(
                        socket,
                        peer_addr,
                        resolver,
                        acl,
                        mesh_capabilities,
                        subnet_router,
                        subnet_store,
                    )
                    .await;
                });
            }
        }
    }
}

async fn handle_socks5_client(
    mut client: TcpStream,
    _peer_addr: SocketAddr,
    resolver: Option<Arc<SovereignResolver>>,
    acl: Option<Arc<tokio::sync::RwLock<crate::acl::AclEngine>>>,
    mesh_capabilities: Option<Arc<Vec<String>>>,
    subnet_router: Option<Arc<tokio::sync::RwLock<SubnetRouter>>>,
    subnet_store: Option<Arc<tokio::sync::RwLock<crate::subnet_route::SubnetRouteStore>>>,
) -> Result<(), String> {
    // 1. SOCKS5 Method Negotiation
    let mut header = [0u8; 2];
    client
        .read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;

    if header[0] != 0x05 {
        return Err("Unsupported SOCKS version".to_string());
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|e| e.to_string())?;

    // We accept Method 0x00 (NO AUTHENTICATION)
    client
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|e| e.to_string())?;

    // 2. SOCKS5 Request Details
    let mut req_header = [0u8; 4];
    client
        .read_exact(&mut req_header)
        .await
        .map_err(|e| e.to_string())?;

    let cmd = req_header[1];
    let atyp = req_header[3];

    // Only CMD 0x01 (CONNECT) is supported
    if cmd != 0x01 {
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(|e| e.to_string())?;
        return Err("Only CONNECT command supported".to_string());
    }

    let target_dest = match atyp {
        0x01 => {
            // IPv4 (4 bytes) + Port (2 bytes)
            let mut buf = [0u8; 6];
            client
                .read_exact(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);

            // Intercept VPC Subnet routes
            if let Some(ref store_arc) = subnet_store {
                let store = store_arc.read().await;
                if let Some(sub) = store.resolve_target_ip(ip) {
                    if !has_mesh_port_grant(mesh_capabilities.as_deref(), port) {
                        client
                            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await
                            .map_err(|e| e.to_string())?;
                        return Err(format!(
                            "Access to mesh subnet port {port} denied by ticket capabilities"
                        ));
                    }
                    let ep = sub.gateway_endpoint.clone();
                    let pk = sub.gateway_pubkey.clone();
                    let m = sub.mesh_name.clone();
                    drop(store);
                    return crate::subnet_route::tunnel_tcp_to_vpc(
                        client,
                        &ip.to_string(),
                        port,
                        &ep,
                        &pk,
                        &m,
                        true,
                    )
                    .await;
                }
            }

            if let Some(ref sr) = subnet_router {
                let router_endpoint = sr.read().await.resolve_target(ip);
                if let Some(router_endpoint) = router_endpoint {
                    if !has_mesh_port_grant(mesh_capabilities.as_deref(), port) {
                        client
                            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await
                            .map_err(|e| e.to_string())?;
                        return Err(format!(
                            "Access to mesh route port {port} denied by ticket capabilities"
                        ));
                    }
                    router_endpoint.to_string()
                } else {
                    format!("{}:{}", ip, port)
                }
            } else {
                format!("{}:{}", ip, port)
            }
        }
        0x03 => {
            // Domain name (1 byte length + domain) + Port (2 bytes)
            let mut len_buf = [0u8; 1];
            client
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| e.to_string())?;
            let domain_len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; domain_len];
            client
                .read_exact(&mut domain_buf)
                .await
                .map_err(|e| e.to_string())?;
            let mut port_buf = [0u8; 2];
            client
                .read_exact(&mut port_buf)
                .await
                .map_err(|e| e.to_string())?;
            let port = u16::from_be_bytes(port_buf);
            let domain = String::from_utf8_lossy(&domain_buf).to_string();

            // Intercept domain as IPv4 for VPC Subnet routes
            if let Ok(ip) = domain.parse::<std::net::Ipv4Addr>() {
                if let Some(ref store_arc) = subnet_store {
                    let store = store_arc.read().await;
                    if let Some(sub) = store.resolve_target_ip(ip) {
                        if !has_mesh_port_grant(mesh_capabilities.as_deref(), port) {
                            client
                                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                .await
                                .map_err(|e| e.to_string())?;
                            return Err(format!(
                                "Access to mesh subnet port {port} denied by ticket capabilities"
                            ));
                        }
                        let ep = sub.gateway_endpoint.clone();
                        let pk = sub.gateway_pubkey.clone();
                        let m = sub.mesh_name.clone();
                        drop(store);
                        return crate::subnet_route::tunnel_tcp_to_vpc(
                            client,
                            &ip.to_string(),
                            port,
                            &ep,
                            &pk,
                            &m,
                            true,
                        )
                        .await;
                    }
                }
            }

            // Intercept and resolve sovereign .sbm domains across Layers 0, 1, and 2
            if domain.ends_with(".sbm") {
                if let Some(ref res) = resolver {
                    match res.resolve(&format!("{}:{}", domain, port)).await {
                        Ok(resolved) => {
                            let now = chrono::Utc::now().timestamp() as u64;
                            let ticket_allowed =
                                has_mesh_port_grant(mesh_capabilities.as_deref(), resolved.port);
                            let acl_allowed = match &acl {
                                Some(acl_engine) => acl_engine.read().await.is_port_allowed(
                                    &resolved.node_id,
                                    resolved.port,
                                    now,
                                ),
                                None => true,
                            };
                            let allowed = ticket_allowed && acl_allowed;
                            if !allowed {
                                client
                                    .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                    .await
                                    .map_err(|e| e.to_string())?;
                                return Err(format!(
                                    "Access to port {} blocked by Capability ACL for node {}",
                                    resolved.port, resolved.node_id
                                ));
                            }
                            if let Some(ref ep) = resolved.endpoint {
                                ep.to_string()
                            } else if let Some(ref oip) = resolved.overlay_ip {
                                format!("{}:{}", oip, resolved.port)
                            } else {
                                client
                                    .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                    .await
                                    .map_err(|e| e.to_string())?;
                                return Err(format!(
                                    "Host unreachable: node {} has no known endpoint/IP",
                                    resolved.node_id
                                ));
                            }
                        }
                        Err(e) => {
                            client
                                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                .await
                                .map_err(|e| e.to_string())?;
                            return Err(format!(
                                "Sovereign name resolution failed for {}: {}",
                                domain, e
                            ));
                        }
                    }
                } else {
                    client
                        .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await
                        .map_err(|e| e.to_string())?;
                    return Err(format!(
                        "Sovereign resolver inactive for .sbm domain: {}",
                        domain
                    ));
                }
            } else if let Some(ref sr) = subnet_router {
                let exit_ep = sr.read().await.exit_node;
                if let Some(exit_ep) = exit_ep {
                    if !has_mesh_port_grant(mesh_capabilities.as_deref(), port) {
                        client
                            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await
                            .map_err(|e| e.to_string())?;
                        return Err(format!(
                            "Access to mesh exit route port {port} denied by ticket capabilities"
                        ));
                    }
                    exit_ep.to_string()
                } else {
                    format!("{}:{}", domain, port)
                }
            } else {
                format!("{}:{}", domain, port)
            }
        }
        _ => {
            client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| e.to_string())?;
            return Err("Address type not supported".to_string());
        }
    };

    // Connect to target destination
    match TcpStream::connect(&target_dest).await {
        Ok(mut target_stream) => {
            // Reply: 0x05 (ver), 0x00 (success), 0x00 (rsv), 0x01 (IPv4), 0,0,0,0 (bnd), 0,0 (port)
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| e.to_string())?;

            // Bidirectional pipe
            let (mut cr, mut cw) = client.split();
            let (mut tr, mut tw) = target_stream.split();

            let client_to_target = tokio::io::copy(&mut cr, &mut tw);
            let target_to_client = tokio::io::copy(&mut tr, &mut cw);

            let _ = tokio::select! {
                res1 = client_to_target => res1,
                res2 = target_to_client => res2,
            };

            Ok(())
        }
        Err(e) => {
            client
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| e.to_string())?;
            Err(format!(
                "Failed to connect to target {}: {}",
                target_dest, e
            ))
        }
    }
}

/// P2P Port Forwarding Tunnel
///
/// Listens on a local port and securely tunnels all TCP connections directly to a remote peer's endpoint.
pub struct PortForwardTunnel {
    pub local_port: u16,
    pub remote_target: String,
}

impl PortForwardTunnel {
    pub fn new(local_port: u16, remote_target: String) -> Self {
        Self {
            local_port,
            remote_target,
        }
    }

    pub async fn start(self: Arc<Self>) -> Result<(), String> {
        let addr = format!("127.0.0.1:{}", self.local_port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Failed to bind local tunnel port {}: {}", addr, e))?;

        println!(
            "P2P Port-Forward Tunnel active: 127.0.0.1:{} -> {}",
            self.local_port, self.remote_target
        );

        while let Ok((mut local_stream, _)) = listener.accept().await {
            let target = self.remote_target.clone();
            tokio::spawn(async move {
                if let Ok(mut remote_stream) = TcpStream::connect(&target).await {
                    let (mut lr, mut lw) = local_stream.split();
                    let (mut rr, mut rw) = remote_stream.split();

                    let _ = tokio::select! {
                        _ = tokio::io::copy(&mut lr, &mut rw) => (),
                        _ = tokio::io::copy(&mut rr, &mut lw) => (),
                    };
                }
            });
        }

        Ok(())
    }
}

/// Loopback-only local development port forwarder.
///
/// This listener is not an authenticated mesh ingress and must not be exposed
/// to remote peers or public interfaces.
pub struct MeshPortShareServer {
    pub local_host: String,
    pub local_port: u16,
    pub ingress_port: u16,
    pub label: String,
}

impl MeshPortShareServer {
    pub fn new(local_host: String, local_port: u16, ingress_port: u16, label: String) -> Self {
        Self {
            local_host,
            local_port,
            ingress_port,
            label,
        }
    }

    /// Checks if the local service is responding on TCP
    pub async fn check_local_service(&self) -> bool {
        let addr = format!("{}:{}", self.local_host, self.local_port);
        tokio::net::TcpStream::connect(&addr).await.is_ok()
    }

    pub async fn start(self: Arc<Self>) -> Result<(), String> {
        let bind_addr = port_share_bind_addr(self.ingress_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| format!("Fehler beim Binden des Ingress-Ports {}: {}", bind_addr, e))?;

        println!(
            "  ● Lokaler Port-Forward aktiv: 127.0.0.1:{} ➔ Ziel {}:{}",
            self.ingress_port, self.local_host, self.local_port
        );

        let target_addr = format!("{}:{}", self.local_host, self.local_port);
        let active_connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        loop {
            let (mut client_stream, client_addr) = listener
                .accept()
                .await
                .map_err(|e| format!("Fehler beim Annehmen einer lokalen Verbindung: {e}"))?;
            let target = target_addr.clone();
            let conns = active_connections.clone();
            let label = self.label.clone();

            tokio::spawn(async move {
                conns.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let current = conns.load(std::sync::atomic::Ordering::SeqCst);
                println!(
                    "  ► [Mesh-Share: {}] Eingehende Verbindung von {} (Aktive Clients: {})",
                    label, client_addr, current
                );

                if let Ok(mut target_stream) = TcpStream::connect(&target).await {
                    let (mut cr, mut cw) = client_stream.split();
                    let (mut tr, mut tw) = target_stream.split();

                    let _ = tokio::select! {
                        _ = tokio::io::copy(&mut cr, &mut tw) => (),
                        _ = tokio::io::copy(&mut tr, &mut cw) => (),
                    };
                } else {
                    eprintln!(
                        "  ✗ Konnte lokalen Dienst unter {} nicht erreichen!",
                        target
                    );
                }

                conns.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
    }
}

fn port_share_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_share_listener_is_loopback_only() {
        assert_eq!(
            port_share_bind_addr(58888),
            "127.0.0.1:58888".parse().unwrap()
        );
    }

    #[test]
    fn test_ip_matches_cidr() {
        let ip_in: std::net::Ipv4Addr = "192.168.1.42".parse().unwrap();
        let ip_out: std::net::Ipv4Addr = "192.168.2.42".parse().unwrap();

        assert!(ip_matches_cidr(ip_in, "192.168.1.0/24"));
        assert!(!ip_matches_cidr(ip_out, "192.168.1.0/24"));
        assert!(ip_matches_cidr(ip_in, "192.168.0.0/16"));
        assert!(ip_matches_cidr(ip_out, "192.168.0.0/16"));
        assert!(ip_matches_cidr(ip_in, "0.0.0.0/0"));
    }

    #[test]
    fn test_subnet_router_resolution() {
        let mut router = SubnetRouter::new();
        let home_lan_endpoint: SocketAddr = "10.240.0.5:58888".parse().unwrap();
        let exit_node_endpoint: SocketAddr = "10.240.0.99:58888".parse().unwrap();

        router.add_subnet_route("192.168.1.0/24", "sbm-0xhomelan", home_lan_endpoint);
        router.set_exit_node(exit_node_endpoint);

        // Target in 192.168.1.0/24 should route to home_lan_endpoint
        let target_lan: std::net::Ipv4Addr = "192.168.1.100".parse().unwrap();
        assert_eq!(router.resolve_target(target_lan), Some(home_lan_endpoint));

        // Target outside 192.168.1.0/24 should fallback to exit_node
        let target_internet: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        assert_eq!(
            router.resolve_target(target_internet),
            Some(exit_node_endpoint)
        );
    }

    #[test]
    fn mesh_port_access_is_ticket_bound_and_default_deny() {
        let ssh_only = vec![crate::rbac::CAP_TUNNEL_SSH.to_string()];
        let explicit_web = vec!["tunnel:port:443".to_string()];

        assert!(!has_mesh_port_grant(None, 22));
        assert!(has_mesh_port_grant(Some(&ssh_only), 22));
        assert!(!has_mesh_port_grant(Some(&ssh_only), 443));
        assert!(has_mesh_port_grant(Some(&explicit_web), 443));
        assert!(!has_mesh_port_grant(Some(&explicit_web), 80));
    }

    #[test]
    fn proxy_rejects_cached_ticket_for_another_mesh_identity() {
        let local = crate::identity::NodeIdentity::generate();
        let anchor = crate::identity::NodeIdentity::generate();
        let grant = crate::ticket::TicketGrantPayload {
            server_node_id: anchor.node_id.clone(),
            server_pubkey: anchor.wireguard_pubkey.clone(),
            subject_node_id: local.node_id.clone(),
            granted_mesh: "test-mesh".to_string(),
            overlay_subnet: String::new(),
            swarm_topic: "test-topic".to_string(),
            swarm_tag: [0; 8],
            valid_until: chrono::Utc::now().timestamp() as u64 + 3600,
            session_ticket: "session".to_string(),
            assigned_ip: None,
            relay_port: 58888,
            request_nonce: 1,
            role: "Consumer".to_string(),
            capabilities: vec!["tunnel:port:443".to_string()],
        };
        let ticket = crate::ticket::CachedTicket {
            mesh_name: "test-mesh".to_string(),
            server_addr: "127.0.0.1:58888".to_string(),
            grant,
            acquired_at: chrono::Utc::now(),
        };
        assert!(ticket.is_valid());
        assert!(Socks5Server::new(0)
            .with_mesh_ticket(&ticket, "test-mesh", &local.node_id)
            .is_ok());
        assert!(Socks5Server::new(0)
            .with_mesh_ticket(&ticket, "other-mesh", &local.node_id)
            .is_err());
        assert!(Socks5Server::new(0)
            .with_mesh_ticket(&ticket, "test-mesh", &anchor.node_id)
            .is_err());
    }

    #[tokio::test]
    async fn test_mesh_port_share_server_forwarding() {
        // 1. Starte einen Dummy Echo-Server auf freiem Port
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 128];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // 2. Erstelle MeshPortShareServer mit Ingress auf freiem Port
        let ingress_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_port = ingress_listener.local_addr().unwrap().port();
        drop(ingress_listener); // Port freigeben für Server

        let server = Arc::new(MeshPortShareServer::new(
            "127.0.0.1".to_string(),
            echo_port,
            ingress_port,
            "test-service".to_string(),
        ));

        // Prüfe lokalen Check
        assert!(server.check_local_service().await);

        let server_clone = server.clone();
        tokio::spawn(async move {
            let _ = server_clone.start().await;
        });

        // Kurze Wartezeit für Bind
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 3. Verbinde zu Ingress-Port und sende Daten
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", ingress_port))
            .await
            .unwrap();
        client.write_all(b"PING_MESH_PORT").await.unwrap();

        let mut reply = [0u8; 128];
        let n = client.read(&mut reply).await.unwrap();
        assert_eq!(&reply[..n], b"PING_MESH_PORT");
    }
}
