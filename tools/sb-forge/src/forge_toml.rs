//! Forge.toml Parser — Konfigurationsstruktur für S&B Forge
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ForgeConfig {
    pub forge: ForgeSection,

    #[serde(default)]
    pub secret: HashMap<String, SecretDef>,

    #[serde(default)]
    pub config: HashMap<String, HashMap<String, String>>,

    #[serde(default)]
    pub recipe: HashMap<String, RecipeDef>,

    #[serde(default)]
    pub pipeline: HashMap<String, PipelineDef>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ForgeSection {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    "1.0".to_string()
}

/// Secret-Definition in Forge.toml — enthält KEINE Werte
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretDef {
    pub description: Option<String>,
    pub environments: Vec<String>,
    pub inject_as: String,
    pub rotate_every: Option<String>, // z.B. "30d", "90d"
}

/// Recipe — atomare Aufgabe
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecipeDef {
    pub description: Option<String>,
    pub env: Option<String>,

    /// Lokale Shell-Befehle
    pub run: Option<Vec<String>>,

    /// Direkter Prozess-Start mit Secrets (forge exec intern)
    pub exec: Option<String>,

    /// Remote-Ausführung via sb-ssh
    pub server: Option<String>,

    /// SFTP push/pull
    pub action: Option<String>, // "push" | "pull"
    pub local: Option<String>,
    pub remote: Option<String>,

    /// Was bei Fehler tun
    pub on_fail: Option<String>, // "stop" | "continue" | "rollback"

    /// Parallele Sub-Recipes
    pub parallel: Option<Vec<ParallelEntry>>,

    /// Abhängigkeiten
    pub depends_on: Option<Vec<String>>,

    /// File-Watching für dev-Modus
    pub watch: Option<Vec<String>>,

    /// Automatischer Post-Deploy Health-Check (z.B. "systemctl is-active <service>")
    pub health_check: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParallelEntry {
    pub recipe: String,
}

/// Pipeline — geordnete Stage-Abfolge
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PipelineDef {
    pub description: Option<String>,
    pub stages: Vec<StageDef>,
    pub on_failure: Option<FailureAction>,
    pub notify: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StageDef {
    pub name: String,
    pub recipes: Vec<String>,
    #[serde(default)]
    pub parallel: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FailureAction {
    pub recipe: Option<String>,
}

/// Lädt Forge.toml aus aktuellem oder übergeordnetem Verzeichnis
pub fn load_forge_toml() -> Result<ForgeConfig, String> {
    let path = find_forge_toml()?;
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Konnte Forge.toml nicht lesen: {}", e))?;
    toml::from_str(&content).map_err(|e| format!("Forge.toml Syntax-Fehler: {}", e))
}

fn find_forge_toml() -> Result<std::path::PathBuf, String> {
    let mut dir = std::env::current_dir()
        .map_err(|e| format!("Aktuelles Verzeichnis nicht lesbar: {}", e))?;

    loop {
        let candidate = dir.join("Forge.toml");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !dir.pop() {
            return Err(
                "Kein Forge.toml gefunden (weder hier noch in übergeordneten Verzeichnissen)"
                    .to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_forge_toml_with_dag_and_parallel() {
        let toml_str = r#"
        [forge]
        name = "test-project"
        version = "1.0.0"

        [recipe.lint]
        description = "Linting"
        run = ["cargo clippy"]

        [recipe.test]
        description = "Tests"
        depends_on = ["lint"]
        watch = ["src/**/*.rs", "tests/**/*.rs"]
        run = ["cargo test"]

        [pipeline.ci]
        description = "CI Pipeline"
        stages = [
            { name = "Gate", recipes = ["lint", "test"], parallel = true }
        ]
        "#;

        let config: ForgeConfig = toml::from_str(toml_str).expect("Valid toml");
        assert_eq!(config.forge.name, "test-project");
        assert_eq!(
            config.recipe["test"].depends_on.as_ref().unwrap(),
            &vec!["lint".to_string()]
        );
        assert_eq!(config.recipe["test"].watch.as_ref().unwrap().len(), 2);
        assert!(config.pipeline["ci"].stages[0].parallel);
        assert_eq!(config.pipeline["ci"].stages[0].recipes.len(), 2);
    }

    #[test]
    fn test_parse_remote_and_sftp_recipe() {
        let toml_str = r#"
        [forge]
        name = "remote-deploy"
        version = "1.0.0"

        [recipe.upload]
        description = "Upload bundle via SFTP"
        server = "hostinger-prod"
        action = "push"
        local = "./dist/app.tar.gz"
        remote = "/var/www/app/app.tar.gz"

        [recipe.restart]
        description = "Restart systemd service"
        server = "hostinger-prod"
        run = ["systemctl restart app"]
        health_check = "systemctl is-active app"
        "#;

        let config: ForgeConfig = toml::from_str(toml_str).expect("Valid toml");
        let upload = &config.recipe["upload"];
        assert_eq!(upload.server.as_deref(), Some("hostinger-prod"));
        assert_eq!(upload.action.as_deref(), Some("push"));
        assert_eq!(upload.local.as_deref(), Some("./dist/app.tar.gz"));
        assert_eq!(upload.remote.as_deref(), Some("/var/www/app/app.tar.gz"));

        let restart = &config.recipe["restart"];
        assert_eq!(restart.server.as_deref(), Some("hostinger-prod"));
        assert_eq!(
            restart.health_check.as_deref(),
            Some("systemctl is-active app")
        );
    }
}
