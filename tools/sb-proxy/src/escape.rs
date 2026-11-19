use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// Status of an Escape Space (Public Egress Gateway).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscapeStatus {
    Active,
    Paused,
    DnsPending,
    Maintenance,
    Error(String),
}

impl std::fmt::Display for EscapeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscapeStatus::Active => write!(f, "Active"),
            EscapeStatus::Paused => write!(f, "Paused"),
            EscapeStatus::DnsPending => write!(f, "DNS Pending"),
            EscapeStatus::Maintenance => write!(f, "Maintenance"),
            EscapeStatus::Error(e) => write!(f, "Error: {}", e),
        }
    }
}

/// A sandboxed Public Egress Gateway (Escape Space) on a Node Server.
/// Routes public traffic from a purchased domain directly to a local target port
/// without exposing private mesh overlay traffic or creating 0.0.0.0 leaks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeSpace {
    pub id: String,
    pub domain: String,
    pub node_callsign: String,
    pub target_port: u16,
    pub public_port: u16,
    pub tls_enabled: bool,
    pub status: EscapeStatus,
    pub mesh_isolated: bool,
    pub rate_limit_rpm: u32,
    pub created_at: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub maintenance_msg: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub custom_cert_path: Option<String>,
    #[serde(default)]
    pub custom_key_path: Option<String>,
    #[serde(default)]
    pub cert_expires_at: Option<String>,
    #[serde(default)]
    pub is_tunnel: bool,
    #[serde(default)]
    pub tunnel_peer: Option<String>,
    #[serde(default)]
    pub static_root: Option<String>,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub required_role: Option<String>,
    #[serde(default)]
    pub required_capability: Option<String>,
}

pub const DEFAULT_TUNNEL_PORT: u16 = 58910;

/// Protected ports that must NEVER be exposed via an Escape Space.
/// Protects against accidental 0.0.0.0 leaks of internal Mesh, SSH, and Swarm controllers.
const PROTECTED_PORTS: &[u16] = &[
    22,    // SSH
    53,    // DNS
    58888, // Sovereign Mesh Overlay & Anchor Port
    4001,  // P2P Gossip
    8008,  // S&B Matrix Sync
    9090,  // Prometheus / Internal Metrics
];

/// Validates whether a requested target port is safe to expose.
pub fn validate_target_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("Port 0 ist ungültig".to_string());
    }
    if PROTECTED_PORTS.contains(&port) {
        return Err(format!(
            "Sicherheits-Verletzung: Port {} ist ein interner S&B Mesh-/System-Port und darf niemals exponiert werden!",
            port
        ));
    }
    Ok(())
}

/// Validates a domain name format.
pub fn validate_domain(domain: &str) -> Result<String, String> {
    let clean = domain.trim().to_lowercase();
    if clean.is_empty() {
        return Err("Domain-Name darf nicht leer sein".to_string());
    }
    if clean.contains('/') || clean.contains('\\') || clean.contains(':') || clean.contains('@') {
        return Err(
            "Ungültiger Domain-Name: Darf keine Pfade oder Sonderzeichen enthalten".to_string(),
        );
    }
    if !clean.contains('.') {
        return Err(
            "Ungültige Domain: Muss mindestens einen Punkt enthalten (z. B. app.example.com)"
                .to_string(),
        );
    }
    Ok(clean)
}

/// Checks whether a domain resolves via DNS to the expected node IP.
pub fn verify_domain_dns(domain: &str, expected_ip: &str) -> bool {
    let lookup_target = format!("{}:80", domain);
    if let Ok(mut addrs) = lookup_target.to_socket_addrs() {
        return addrs.any(|addr| addr.ip().to_string() == expected_ip);
    }
    false
}

/// Persistent store for Escape Spaces (~/.sb/escape_spaces.json).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscapeSpaceStore {
    pub spaces: Vec<EscapeSpace>,
}

impl Default for EscapeSpaceStore {
    fn default() -> Self {
        Self {
            spaces: vec![EscapeSpace {
                id: "esc-web-demo".to_string(),
                domain: "preview.sbm.network".to_string(),
                node_callsign: "hostinger-node".to_string(),
                target_port: 3000,
                public_port: 443,
                tls_enabled: true,
                status: EscapeStatus::Active,
                mesh_isolated: true,
                rate_limit_rpm: 600,
                created_at: Utc::now().to_rfc3339(),
                aliases: Vec::new(),
                maintenance_msg: None,
                expires_at: None,
                custom_cert_path: None,
                custom_key_path: None,
                cert_expires_at: None,
                is_tunnel: false,
                tunnel_peer: None,
                static_root: None,
                auth_required: false,
                required_role: None,
                required_capability: None,
            }],
        }
    }
}

impl EscapeSpaceStore {
    fn store_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".sb").join("escape_spaces.json"))
    }

    pub fn load() -> Self {
        if let Some(path) = Self::store_path() {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(store) = serde_json::from_str::<EscapeSpaceStore>(&content) {
                        return store;
                    }
                }
            }
        }
        let def = Self::default();
        let _ = def.save();
        def
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(path) = Self::store_path() {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
            fs::write(path, json).map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Home-Verzeichnis nicht gefunden".to_string())
        }
    }

    pub fn add(
        &mut self,
        domain: &str,
        target_port: u16,
        node_callsign: &str,
    ) -> Result<EscapeSpace, String> {
        let clean_domain = validate_domain(domain)?;
        validate_target_port(target_port)?;

        if self.spaces.iter().any(|s| s.domain == clean_domain) {
            return Err(format!(
                "Domain '{}' ist bereits als Escape Space registriert",
                clean_domain
            ));
        }

        let id = format!("esc-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let space = EscapeSpace {
            id,
            domain: clean_domain,
            node_callsign: if node_callsign.trim().is_empty() {
                "hostinger-node".to_string()
            } else {
                node_callsign.trim().to_string()
            },
            target_port,
            public_port: 443,
            tls_enabled: true,
            status: EscapeStatus::Active,
            mesh_isolated: true,
            rate_limit_rpm: 600,
            created_at: Utc::now().to_rfc3339(),
            aliases: Vec::new(),
            maintenance_msg: None,
            expires_at: None,
            custom_cert_path: None,
            custom_key_path: None,
            cert_expires_at: None,
            is_tunnel: false,
            tunnel_peer: None,
            static_root: None,
            auth_required: false,
            required_role: None,
            required_capability: None,
        };

        self.spaces.push(space.clone());
        self.save()?;
        Ok(space)
    }

    /// Adds a Mesh-Tunnel Escape Space (is_tunnel=true).
    /// Traffic is forwarded by the developer's machine via `sb proxy link` over the
    /// encrypted sb-mesh Stealth tunnel.  No local port is needed on the VPS.
    pub fn add_mesh_tunnel(
        &mut self,
        domain: &str,
        node_callsign: &str,
    ) -> Result<EscapeSpace, String> {
        let clean_domain = validate_domain(domain)?;

        if self.spaces.iter().any(|s| s.domain == clean_domain) {
            return Err(format!(
                "Domain '{}' ist bereits als Escape Space registriert",
                clean_domain
            ));
        }

        let id = format!("esc-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let space = EscapeSpace {
            id,
            domain: clean_domain,
            node_callsign: if node_callsign.trim().is_empty() {
                "hostinger-node".to_string()
            } else {
                node_callsign.trim().to_string()
            },
            // target_port=0 signals "no direct loopback service" — traffic comes via Tunnel Hub
            target_port: 0,
            public_port: 443,
            tls_enabled: true,
            status: EscapeStatus::Active,
            mesh_isolated: true,
            rate_limit_rpm: 600,
            created_at: Utc::now().to_rfc3339(),
            aliases: Vec::new(),
            maintenance_msg: None,
            expires_at: None,
            custom_cert_path: None,
            custom_key_path: None,
            cert_expires_at: None,
            is_tunnel: true,
            tunnel_peer: Some(node_callsign.trim().to_string()),
            static_root: None,
            auth_required: false,
            required_role: None,
            required_capability: None,
        };

        self.spaces.push(space.clone());
        self.save()?;
        Ok(space)
    }

    pub fn add_static_site(
        &mut self,
        domain: &str,
        node_callsign: &str,
        root: &str,
    ) -> Result<EscapeSpace, String> {
        let clean_domain = validate_domain(domain)?;
        if self.spaces.iter().any(|space| space.domain == clean_domain) {
            return Err(format!(
                "Domain '{}' ist bereits als Escape Space registriert",
                clean_domain
            ));
        }

        let id = format!("esc-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let space = EscapeSpace {
            id,
            domain: clean_domain,
            node_callsign: if node_callsign.trim().is_empty() {
                "hostinger-node".to_string()
            } else {
                node_callsign.trim().to_string()
            },
            target_port: 0,
            public_port: 443,
            tls_enabled: true,
            status: EscapeStatus::Active,
            mesh_isolated: true,
            rate_limit_rpm: 600,
            created_at: Utc::now().to_rfc3339(),
            aliases: Vec::new(),
            maintenance_msg: None,
            expires_at: None,
            custom_cert_path: None,
            custom_key_path: None,
            cert_expires_at: None,
            is_tunnel: false,
            tunnel_peer: None,
            static_root: Some(root.to_string()),
            auth_required: false,
            required_role: None,
            required_capability: None,
        };

        self.spaces.push(space.clone());
        self.save()?;
        Ok(space)
    }

    pub fn remove(&mut self, id: &str) -> Result<bool, String> {
        let initial_len = self.spaces.len();
        self.spaces.retain(|s| s.id != id);
        if self.spaces.len() < initial_len {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn toggle_status(&mut self, id: &str) -> Result<EscapeStatus, String> {
        if let Some(space) = self.spaces.iter_mut().find(|s| s.id == id) {
            space.status = match space.status {
                EscapeStatus::Active => EscapeStatus::Paused,
                _ => EscapeStatus::Active,
            };
            let status = space.status.clone();
            self.save()?;
            Ok(status)
        } else {
            Err(format!("Escape Space '{}' nicht gefunden", id))
        }
    }

    pub fn set_maintenance(
        &mut self,
        query: &str,
        msg: Option<String>,
        enable: bool,
    ) -> Result<EscapeStatus, String> {
        let q = query.trim().to_lowercase();
        let found = self
            .spaces
            .iter_mut()
            .find(|s| s.id == q || s.domain.to_lowercase() == q);
        if let Some(space) = found {
            if enable {
                space.status = EscapeStatus::Maintenance;
                space.maintenance_msg = msg;
            } else {
                space.status = EscapeStatus::Active;
                space.maintenance_msg = None;
            }
            let status = space.status.clone();
            self.save()?;
            Ok(status)
        } else {
            Err(format!("Escape Space '{}' nicht gefunden", query))
        }
    }

    pub fn add_preview(
        &mut self,
        domain: &str,
        target_port: u16,
        node_callsign: &str,
        ttl_hours: u64,
    ) -> Result<EscapeSpace, String> {
        let mut space = self.add(domain, target_port, node_callsign)?;
        let expires_at = Utc::now() + chrono::Duration::hours(ttl_hours as i64);
        space.expires_at = Some(expires_at.to_rfc3339());

        if let Some(s) = self.spaces.iter_mut().find(|s| s.id == space.id) {
            s.expires_at = space.expires_at.clone();
        }
        self.save()?;
        Ok(space)
    }

    pub fn add_alias(&mut self, query: &str, alias: &str) -> Result<String, String> {
        let clean_alias = validate_domain(alias)?;
        let q = query.trim().to_lowercase();
        let found = self
            .spaces
            .iter_mut()
            .find(|s| s.id == q || s.domain.to_lowercase() == q);
        if let Some(space) = found {
            if !space.aliases.contains(&clean_alias) {
                space.aliases.push(clean_alias.clone());
                self.save()?;
            }
            Ok(clean_alias)
        } else {
            Err(format!("Escape Space '{}' nicht gefunden", query))
        }
    }

    pub fn set_custom_cert(
        &mut self,
        query: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), String> {
        let q = query.trim().to_lowercase();
        let found = self
            .spaces
            .iter_mut()
            .find(|s| s.id == q || s.domain.to_lowercase() == q);
        if let Some(space) = found {
            space.custom_cert_path = Some(cert_path.to_string());
            space.custom_key_path = Some(key_path.to_string());
            space.tls_enabled = true;
            self.save()?;
            Ok(())
        } else {
            Err(format!("Escape Space '{}' nicht gefunden", query))
        }
    }

    pub fn update_cert_expiry(&mut self, query: &str, expires_at: &str) -> Result<(), String> {
        let q = query.trim().to_lowercase();
        let found = self
            .spaces
            .iter_mut()
            .find(|s| s.id == q || s.domain.to_lowercase() == q);
        if let Some(space) = found {
            space.cert_expires_at = Some(expires_at.to_string());
            self.save()?;
            Ok(())
        } else {
            Err(format!("Escape Space '{}' nicht gefunden", query))
        }
    }

    pub fn set_tunnel_mode(
        &mut self,
        query: &str,
        enabled: bool,
        peer: Option<String>,
    ) -> Result<EscapeSpace, String> {
        let q = query.trim().to_lowercase();
        let found = self
            .spaces
            .iter_mut()
            .find(|s| s.id == q || s.domain.to_lowercase() == q);
        if let Some(space) = found {
            space.is_tunnel = enabled;
            space.tunnel_peer = peer;
            let cloned = space.clone();
            self.save()?;
            Ok(cloned)
        } else {
            Err(format!("Escape Space '{}' nicht gefunden", query))
        }
    }
}

/// Real-time metrics for an active Sovereign Tunnel session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelSessionStats {
    pub domain: String,
    pub local_port: u16,
    pub gateway: String,
    pub streams_served: u64,
    pub bytes_transferred: u64,
    pub is_connected: bool,
}

/// Sovereign Tunnel Client (Cloudflare Tunnel & ngrok Killer).
/// Runs on developer's machine behind any NAT/firewall and connects outbound to the Gateway Hub.
pub struct SovereignTunnelClient {
    pub domain: String,
    pub local_port: u16,
    pub gateway_addr: String,
    pub callsign: String,
    pub running: Arc<AtomicBool>,
}

impl SovereignTunnelClient {
    pub fn new(
        domain: &str,
        local_port: u16,
        gateway_addr: &str,
        callsign: &str,
    ) -> Result<Self, String> {
        validate_target_port(local_port)?;
        let clean_domain = validate_domain(domain)?;
        Ok(Self {
            domain: clean_domain,
            local_port,
            gateway_addr: gateway_addr.to_string(),
            callsign: callsign.to_string(),
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub async fn run(&self) -> Result<(), String> {
        let mut control_stream = tokio::net::TcpStream::connect(&self.gateway_addr)
            .await
            .map_err(|e| {
                format!(
                    "Konnte keine Verbindung zum Gateway-Hub '{}' herstellen: {}",
                    self.gateway_addr, e
                )
            })?;

        // 1. Send Handshake
        let register_cmd = format!("REGISTER\t{}\t{}\n", self.domain, self.callsign);
        control_stream
            .write_all(register_cmd.as_bytes())
            .await
            .map_err(|e| format!("Handshake-Fehler: {}", e))?;

        let (reader, mut writer) = control_stream.into_split();
        let mut lines = tokio::io::BufReader::new(reader).lines();

        let resp = lines
            .next_line()
            .await
            .map_err(|e| format!("Gateway-Antwortfehler: {}", e))?
            .ok_or_else(|| "Gateway hat Verbindung vorzeitig geschlossen".to_string())?;

        if !resp.starts_with("OK") {
            return Err(format!("Gateway Registrierungsfehler: {}", resp));
        }

        println!(
            "⚡ Sovereign Tunnel aktiv: {} <==> 127.0.0.1:{}",
            self.domain, self.local_port
        );

        let gateway_addr = self.gateway_addr.clone();
        let local_port = self.local_port;
        let running = self.running.clone();

        while running.load(Ordering::SeqCst) {
            tokio::select! {
                line_res = lines.next_line() => {
                    match line_res {
                        Ok(Some(line)) => {
                            let parts: Vec<&str> = line.trim().split('\t').collect();
                            if parts[0] == "OPEN_STREAM" && parts.len() > 1 {
                                let stream_id = parts[1].to_string();
                                let gw = gateway_addr.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_stream(&gw, local_port, &stream_id).await {
                                        eprintln!("Tunnel Stream Fehler (ID: {}): {}", stream_id, e);
                                    }
                                });
                            } else if parts[0] == "PING" {
                                let _ = writer.write_all(b"PONG\n").await;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Tunnel Control Error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_stream(
        gateway_addr: &str,
        local_port: u16,
        stream_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut data_stream = tokio::net::TcpStream::connect(gateway_addr).await?;
        let attach_cmd = format!("ATTACH_STREAM\t{}\n", stream_id);
        data_stream.write_all(attach_cmd.as_bytes()).await?;

        let mut local_stream =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", local_port)).await?;
        tokio::io::copy_bidirectional(&mut data_stream, &mut local_stream).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_validation_blocks_mesh_leaks() {
        // Internal mesh overlay port must be blocked
        assert!(validate_target_port(58888).is_err());
        // SSH port must be blocked
        assert!(validate_target_port(22).is_err());
        // Standard dev ports must be allowed
        assert!(validate_target_port(3000).is_ok());
        assert!(validate_target_port(5173).is_ok());
        assert!(validate_target_port(8080).is_ok());
    }

    #[test]
    fn test_domain_validation() {
        assert!(validate_domain("app.example.com").is_ok());
        assert!(validate_domain("  SHOP.MYBRAND.DE ").is_ok());
        assert_eq!(
            validate_domain("  SHOP.MYBRAND.DE ").unwrap(),
            "shop.mybrand.de"
        );
        assert!(validate_domain("invalid domain").is_err());
        assert!(validate_domain("nodot").is_err());
        assert!(validate_domain("http://withscheme.com").is_err());
    }

    #[test]
    fn old_escape_space_records_default_to_non_static_routes() {
        let mut value = serde_json::to_value(EscapeSpaceStore::default()).unwrap();
        value["spaces"][0]
            .as_object_mut()
            .unwrap()
            .remove("static_root");

        let store: EscapeSpaceStore = serde_json::from_value(value).unwrap();
        assert_eq!(store.spaces[0].static_root, None);
    }

    #[test]
    fn test_sovereign_tunnel_client_validation() {
        // Protected ports must be blocked
        assert!(SovereignTunnelClient::new("app.local", 22, "127.0.0.1:58910", "alice").is_err());
        assert!(
            SovereignTunnelClient::new("app.local", 58888, "127.0.0.1:58910", "alice").is_err()
        );

        // Valid setup
        let client = SovereignTunnelClient::new("app.local", 3000, "127.0.0.1:58910", "alice");
        assert!(client.is_ok());
        let c = client.unwrap();
        assert_eq!(c.domain, "app.local");
        assert_eq!(c.local_port, 3000);
    }
}
