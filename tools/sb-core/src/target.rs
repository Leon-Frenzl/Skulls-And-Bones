use crate::config::SuiteConfig;
use crate::paths::{sb_home, servers_config_path};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default = "default_ssh_user")]
    pub user: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_ssh_user() -> String {
    "root".to_string()
}

impl ServerConfig {
    pub fn new(name: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port: 22,
            user: "root".to_string(),
            tags: Vec::new(),
            description: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn mesh_domain(&self) -> String {
        if self.name.ends_with(".sbm") {
            self.name.clone()
        } else {
            format!("{}.sbm", self.name)
        }
    }

    pub fn ssh_destination(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct ServersFile {
    #[serde(default)]
    servers: Vec<ServerConfig>,
}

pub struct TargetResolver;

impl TargetResolver {
    /// Lädt alle konfigurierten Server aus ~/.sb/servers.toml
    pub fn load_servers() -> Vec<ServerConfig> {
        let path = servers_config_path();
        if !path.exists() {
            return Vec::new();
        }

        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(file) = toml::from_str::<ServersFile>(&content) {
                if !file.servers.is_empty() {
                    return file.servers;
                }
            }
            // Resilienter Fallback-Parser für handgeschriebene servers.toml
            Self::parse_servers_fallback(&content)
        } else {
            Vec::new()
        }
    }

    /// Resilienter Fallback-Parser für handgeschriebene servers.toml
    fn parse_servers_fallback(content: &str) -> Vec<ServerConfig> {
        let mut servers = Vec::new();
        let mut current: Option<ServerConfig> = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == "[[servers]]" {
                if let Some(s) = current.take() {
                    if !s.name.is_empty() || !s.host.is_empty() {
                        servers.push(s);
                    }
                }
                current = Some(ServerConfig {
                    name: String::new(),
                    host: String::new(),
                    port: 22,
                    user: "root".to_string(),
                    tags: Vec::new(),
                    description: None,
                });
            } else if let Some(ref mut s) = current {
                if let Some(val) = trimmed.strip_prefix("name = ") {
                    s.name = val.trim_matches([' ', '"', '\'']).to_string();
                } else if let Some(val) = trimmed.strip_prefix("host = ") {
                    s.host = val.trim_matches([' ', '"', '\'']).to_string();
                } else if let Some(val) = trimmed.strip_prefix("port = ") {
                    if let Ok(p) = val.trim().parse() {
                        s.port = p;
                    }
                } else if let Some(val) = trimmed.strip_prefix("user = ") {
                    s.user = val.trim_matches([' ', '"', '\'']).to_string();
                } else if let Some(val) = trimmed.strip_prefix("description = ") {
                    s.description = Some(val.trim_matches([' ', '"', '\'']).to_string());
                }
            }
        }

        if let Some(s) = current {
            if !s.name.is_empty() || !s.host.is_empty() {
                servers.push(s);
            }
        }

        servers
    }

    /// Liest den Standard-Zielserver aus dem aktiven Context (~/.sb/contexts/current)
    pub fn get_context_default_server() -> Option<String> {
        let home = sb_home();
        let current_ptr = home.join("contexts").join("current");
        if current_ptr.exists() {
            if let Ok(active_name) = fs::read_to_string(&current_ptr) {
                let ctx_file = home
                    .join("contexts")
                    .join(format!("{}.json", active_name.trim().to_lowercase()));
                if ctx_file.exists() {
                    if let Ok(content) = fs::read_to_string(&ctx_file) {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(srv) = json.get("target_server").and_then(|v| v.as_str()) {
                                if !srv.trim().is_empty() {
                                    return Some(srv.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Löst einen Servernamen, Alias, IP oder Mesh-Domain auf.
    /// Falls `target_str` None oder leer ist, wird der Context-Default,
    /// gefolgt von SuiteConfig::default_server herangezogen.
    pub fn resolve_node_or_default(target_str: Option<&str>) -> Option<ServerConfig> {
        let clean = target_str
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && *s != "default");
        if let Some(t) = clean {
            Self::resolve(t)
        } else {
            // 1. Try context default
            if let Some(ctx_srv) = Self::get_context_default_server() {
                if let Some(resolved) = Self::resolve(&ctx_srv) {
                    return Some(resolved);
                }
            }

            // 2. Try suite config default_server
            let suite_cfg = SuiteConfig::load();
            if let Some(ref def_srv) = suite_cfg.network.default_server {
                if let Some(resolved) = Self::resolve(def_srv) {
                    return Some(resolved);
                }
            }

            // 3. Try first server in servers.toml
            let all = Self::load_servers();
            if let Some(first) = all.into_iter().next() {
                return Some(first);
            }

            // 4. Fallback to expected_node_ip if configured
            if let Some(ref ip) = suite_cfg.network.expected_node_ip {
                return Some(ServerConfig {
                    name: "default-node".to_string(),
                    host: ip.clone(),
                    port: 22,
                    user: "root".to_string(),
                    tags: vec!["default".to_string()],
                    description: Some("Default Node IP".to_string()),
                });
            }

            None
        }
    }

    /// Löst ein Ziel (Name, Alias, IP, Domain, user@host) explizit auf.
    pub fn resolve(target: &str) -> Option<ServerConfig> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Handle user@host syntax
        let (extracted_user, raw_host) = if let Some((u, h)) = trimmed.split_once('@') {
            (Some(u.to_string()), h)
        } else {
            (None, trimmed)
        };

        let clean_name = raw_host.to_lowercase();
        let stripped_sbm = clean_name.strip_suffix(".sbm").unwrap_or(&clean_name);

        // Check configured servers in servers.toml
        let servers = Self::load_servers();
        for mut s in servers {
            let s_name_clean = s.name.to_lowercase();
            let s_name_stripped = s_name_clean.strip_suffix(".sbm").unwrap_or(&s_name_clean);
            if s_name_clean == clean_name
                || s_name_stripped == stripped_sbm
                || s.host.eq_ignore_ascii_case(raw_host)
                || s.tags.iter().any(|t| t.eq_ignore_ascii_case(stripped_sbm))
            {
                if let Some(u) = extracted_user {
                    s.user = u;
                }
                return Some(s);
            }
        }

        // Check known aliases in SuiteConfig
        let suite_cfg = SuiteConfig::load();
        let expected_ip = suite_cfg
            .network
            .expected_node_ip
            .as_deref()
            .unwrap_or("145.223.83.235");

        let is_node_alias = matches!(
            stripped_sbm,
            "srv490042" | "hostinger-node" | "hostinger-prod" | "hostinger-stealth" | "stealth"
        ) || raw_host == expected_ip;

        if is_node_alias {
            return Some(ServerConfig {
                name: stripped_sbm.to_string(),
                host: expected_ip.to_string(),
                port: 22,
                user: extracted_user.unwrap_or_else(|| "root".to_string()),
                tags: vec!["fleet".to_string(), "stealth".to_string()],
                description: Some("Sovereign Hostinger Node".to_string()),
            });
        }

        // Direct IP address or domain
        let host_string = if raw_host.contains('.') || raw_host == "localhost" {
            raw_host.to_string()
        } else {
            format!("{}.sbm", raw_host)
        };

        Some(ServerConfig {
            name: stripped_sbm.to_string(),
            host: host_string,
            port: 22,
            user: extracted_user.unwrap_or_else(|| "root".to_string()),
            tags: Vec::new(),
            description: None,
        })
    }

    /// Registriert einen Server in servers.toml
    pub fn register_server(server: &ServerConfig) -> Result<(), std::io::Error> {
        let path = servers_config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut servers = Self::load_servers();
        // Remove existing with same name or host
        servers.retain(|s| s.name != server.name && s.host != server.host);
        servers.push(server.clone());

        let file = ServersFile { servers };
        let toml_str = toml::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(path, toml_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_explicit_ip_and_user() {
        let res = TargetResolver::resolve("admin@192.168.1.100").expect("should resolve");
        assert_eq!(res.user, "admin");
        assert_eq!(res.host, "192.168.1.100");
        assert_eq!(res.port, 22);
    }

    #[test]
    fn test_resolve_mesh_domain() {
        let res = TargetResolver::resolve("node-alpha.sbm").expect("should resolve");
        assert_eq!(res.name, "node-alpha");
        assert_eq!(res.host, "node-alpha.sbm");
    }

    #[test]
    fn test_resolve_known_stealth_alias() {
        let res = TargetResolver::resolve("hostinger-stealth").expect("should resolve");
        assert_eq!(res.name, "hostinger-stealth");
        assert!(res.tags.contains(&"stealth".to_string()));
    }

    #[test]
    fn test_server_config_builder() {
        let cfg = ServerConfig::new("alpha", "10.0.0.1")
            .with_port(2222)
            .with_user("deploy")
            .with_description("Alpha Test Server");
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.user, "deploy");
        assert_eq!(cfg.ssh_destination(), "deploy@10.0.0.1");
        assert_eq!(cfg.mesh_domain(), "alpha.sbm");
    }
}
