use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub listen_port: u16,
    pub air_gap_killswitch: bool,
    pub lan_discovery: bool,
    pub keepalive_secs: u64,
    pub overlay_subnet: String,
    #[serde(default = "default_true")]
    pub traffic_obfuscation: bool,
    #[serde(default = "default_true")]
    pub relay_enabled: bool,
    #[serde(default)]
    pub advertised_subnets: Vec<String>,
    #[serde(default)]
    pub is_exit_node: bool,
    #[serde(default)]
    pub exit_node: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            listen_port: 58888,
            air_gap_killswitch: false,
            lan_discovery: true,
            keepalive_secs: 25,
            overlay_subnet: "10.240.0.0/16".to_string(),
            traffic_obfuscation: true,
            relay_enabled: true,
            advertised_subnets: Vec::new(),
            is_exit_node: false,
            exit_node: None,
        }
    }
}

impl MeshConfig {
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        Self::load_or_default(path)
    }

    pub fn load_or_default(path: &Path) -> Result<Self, String> {
        if path.exists() {
            let content = fs::read_to_string(path)
                .map_err(|error| format!("Failed to read mesh config: {error}"))?;
            toml::from_str::<MeshConfig>(&content)
                .map_err(|error| format!("Invalid mesh config: {error}"))
        } else {
            let config = Self::default();
            config.save(path)?;
            Ok(config)
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        fs::write(path, content).map_err(|e| format!("Failed to write config: {}", e))?;
        Ok(())
    }
}
