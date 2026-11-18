use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct DiscoveredService {
    pub port: u16,
    pub hint: &'static str,
}

const COMMON_DEV_PORTS: &[(u16, &str)] = &[
    (3000, "Next.js / Node / React"),
    (5173, "Vite Dev Server"),
    (4173, "Vite Preview"),
    (8080, "API Gateway / Go / Java"),
    (8000, "Python FastAPI / Django"),
    (3001, "Secondary Web App"),
    (8081, "Secondary API"),
    (8888, "Internal Service"),
];

/// Scans 127.0.0.1 for active listening web services.
pub fn discover_active_services() -> Vec<DiscoveredService> {
    let mut active = Vec::new();

    for &(port, hint) in COMMON_DEV_PORTS {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpStream::connect_timeout(&addr, Duration::from_millis(30)).is_ok() {
            active.push(DiscoveredService { port, hint });
        }
    }

    active
}
