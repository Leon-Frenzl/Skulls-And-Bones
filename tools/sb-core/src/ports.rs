//! S&B Suite — Unified Ports & Network Topology Constants

/// Standard UDP port for the Sovereign Mesh Single-Port Dispatcher (WireGuard-style multiplexer)
pub const DEFAULT_MESH_UDP_PORT: u16 = 58888;

/// Standard TCP port for local Loopback IPC Telemetry & Control of S&B Edge Proxy (127.0.0.1:58900)
pub const DEFAULT_PROXY_IPC_PORT: u16 = 58900;

/// Standard TCP port for the Sovereign Tunnel Hub (Cloudflare Tunnel / ngrok alternative)
pub const DEFAULT_TUNNEL_HUB_PORT: u16 = 58910;

/// Standard TCP port for local Mesh Control IPC
pub const DEFAULT_MESH_IPC_PORT: u16 = 58890;

/// Standard HTTP port for ACME HTTP-01 Challenges and HTTPS redirects
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Standard HTTPS port for S&B Edge Gateway traffic
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// Standard local port for stealth SSH ingress tunnels (127.0.0.1:58822)
pub const DEFAULT_STEALTH_SSH_PORT: u16 = 58822;

/// Standard default development target port (e.g. 3000)
pub const DEFAULT_DEV_TARGET_PORT: u16 = 3000;

/// Standard local port for the Sovereign Headless Daemon Loopback API (127.0.0.1:58905)
pub const DEFAULT_DAEMON_API_PORT: u16 = 58905;
