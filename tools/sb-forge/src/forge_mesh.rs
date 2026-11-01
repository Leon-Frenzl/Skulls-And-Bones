//! FORGE_MESH.toml Parser & Validator
//! Spezifikation für dezentrale Swarm- & Code-Streams im Skulls & Bones Sovereign Mesh.

use crate::forge_toml::ForgeConfig;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const MESH_CONFIG_FILENAME: &str = "FORGE_MESH.toml";

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ForgeMeshConfig {
    pub mesh: MeshMeta,

    #[serde(default)]
    pub swarm: SwarmSpec,

    #[serde(default)]
    pub lifecycle: LifecycleHooks,

    #[serde(default)]
    pub ignore: MeshIgnoreRules,

    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MeshMeta {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    pub topic: String,
    #[serde(default = "default_channel")]
    pub channel: String,
    pub description: Option<String>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

fn default_channel() -> String {
    "main".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SwarmSpec {
    #[serde(default = "default_replication")]
    pub replication_factor: usize,

    #[serde(default)]
    pub preferred_anchors: Vec<String>,

    #[serde(default)]
    pub tags: Vec<String>,
}

impl Default for SwarmSpec {
    fn default() -> Self {
        Self {
            replication_factor: default_replication(),
            preferred_anchors: Vec::new(),
            tags: Vec::new(),
        }
    }
}

fn default_replication() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LifecycleHooks {
    pub pre_publish: Option<String>,
    pub post_subscribe: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MeshIgnoreRules {
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Sucht nach FORGE_MESH.toml im Verzeichnis oder Parent-Verzeichnissen
pub fn find_mesh_file(start_dir: &Path) -> Option<PathBuf> {
    let mut curr = Some(start_dir.to_path_buf());
    while let Some(dir) = curr {
        let candidate = dir.join(MESH_CONFIG_FILENAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        let lowercase = dir.join("forge_mesh.toml");
        if lowercase.is_file() {
            return Some(lowercase);
        }
        curr = dir.parent().map(|p| p.to_path_buf());
    }
    None
}

/// Lädt FORGE_MESH.toml aus einem Verzeichnis
pub fn load_from_dir(dir: &Path) -> Result<(ForgeMeshConfig, PathBuf), String> {
    let path = find_mesh_file(dir).ok_or_else(|| {
        format!(
            "Keine {} im Pfad '{}' oder übergeordneten Ordnern gefunden",
            MESH_CONFIG_FILENAME,
            dir.display()
        )
    })?;

    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Fehler beim Lesen von {}: {}", path.display(), e))?;

    let config: ForgeMeshConfig = toml::from_str(&content)
        .map_err(|e| format!("Fehler beim Parsen von {}: {}", path.display(), e))?;

    Ok((config, path))
}

/// Erstellt eine FORGE_MESH.toml Vorlage für ein Projekt
pub fn init_template(dir: &Path, custom_name: Option<&str>) -> Result<PathBuf, String> {
    let target_path = dir.join(MESH_CONFIG_FILENAME);
    if target_path.exists() {
        return Err(format!(
            "{} existiert bereits in {}",
            MESH_CONFIG_FILENAME,
            dir.display()
        ));
    }

    let project_name = if let Some(n) = custom_name {
        n.to_string()
    } else {
        dir.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed-tool".to_string())
    };

    let topic = format!("sbm:code:{}", project_name);

    let template = format!(
        r#"[mesh]
name = "{name}"
version = "0.1.0"
topic = "{topic}"
channel = "main"
description = "Sovereign Mesh Component for {name}"

[swarm]
# Mindestanzahl an Seeding Anchors zur Persistenz-Garantie
replication_factor = 1
preferred_anchors = ["hostinger-node"]

[lifecycle]
# Wird vor 'sb publish' ausgeführt — bricht bei Fehlern ab
pre_publish = "forge run check"
# Wird nach 'sb subscribe' ausgeführt
post_subscribe = ""

[ignore]
# Zusätzliche Streaming-Ausschlüsse neben .sbignore
exclude = [
  "target/",
  "dist/",
  "node_modules/",
  "*.tar.gz"
]
"#,
        name = project_name,
        topic = topic
    );

    fs::write(&target_path, template)
        .map_err(|e| format!("Fehler beim Schreiben von {}: {}", target_path.display(), e))?;

    Ok(target_path)
}

/// Validiert die Mesh-Konfiguration gegen eine optionale Forge.toml
pub fn validate_mesh_config(
    mesh: &ForgeMeshConfig,
    forge_opt: Option<&ForgeConfig>,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if mesh.mesh.name.trim().is_empty() {
        warnings.push("mesh.name darf nicht leer sein.".to_string());
    }

    if mesh.mesh.topic.trim().is_empty() {
        warnings.push("mesh.topic darf nicht leer sein.".to_string());
    } else if !mesh.mesh.topic.starts_with("sbm:") {
        warnings.push(format!(
            "mesh.topic '{}' sollte dem Standard 'sbm:code:<name>' folgen.",
            mesh.mesh.topic
        ));
    }

    if mesh.swarm.replication_factor == 0 {
        warnings.push(
            "swarm.replication_factor ist 0 (keine automatische Verankerung im Schwarm)."
                .to_string(),
        );
    }

    // Prüfe, ob pre_publish Befehle auf existierende Rezepte in Forge.toml verweisen
    if let (Some(ref pre), Some(forge)) = (&mesh.lifecycle.pre_publish, forge_opt) {
        if pre.starts_with("forge run ") || pre.starts_with("sb-forge run ") {
            let recipe_name = pre
                .strip_prefix("forge run ")
                .or_else(|| pre.strip_prefix("sb-forge run "))
                .unwrap_or("")
                .trim();
            if !recipe_name.is_empty() && !forge.recipe.contains_key(recipe_name) {
                warnings.push(format!(
                    "lifecycle.pre_publish referenziert Rezept '{}', aber dieses existiert nicht in Forge.toml!",
                    recipe_name
                ));
            }
        }
    }

    warnings
}

/// Gibt einen formatierten Statusbericht über die Mesh-Spezifikation aus
pub fn print_mesh_info(mesh: &ForgeMeshConfig, path: &Path, forge_opt: Option<&ForgeConfig>) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_red().bold(),
        "//".bright_black(),
        "MESH SWARM SPECIFICATION".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} Datei:      {}",
        "►".bright_cyan(),
        path.display().to_string().cyan()
    );
    println!(
        "  {} Tool-Name:  {}",
        "►".bright_cyan(),
        mesh.mesh.name.bold().green()
    );
    println!(
        "  {} Version:    {}",
        "►".bright_cyan(),
        mesh.mesh.version.bold().white()
    );
    println!(
        "  {} Swarm Topic:{}",
        "►".bright_cyan(),
        mesh.mesh.topic.bold().yellow()
    );
    println!(
        "  {} Channel:    {}",
        "►".bright_cyan(),
        mesh.mesh.channel.bold().magenta()
    );

    if let Some(ref desc) = mesh.mesh.description {
        println!("  {} Info:       {}", "►".bright_cyan(), desc.dimmed());
    }

    println!();
    println!("  {}", "Swarm & Replikation:".bold());
    println!(
        "    • Mindest-Replikation:  {} Anchors",
        mesh.swarm.replication_factor.to_string().cyan()
    );
    if mesh.swarm.preferred_anchors.is_empty() {
        println!("    • Bevorzugte Anchors:  keine (Nutzt beliebige verfügbare Mesh-Anchors)");
    } else {
        println!(
            "    • Bevorzugte Anchors:  {}",
            mesh.swarm.preferred_anchors.join(", ").yellow()
        );
    }

    println!();
    println!("  {}", "Lifecycle Swarm Hooks:".bold());
    println!(
        "    • pre_publish:    {}",
        mesh.lifecycle
            .pre_publish
            .as_deref()
            .unwrap_or("<keiner>")
            .bright_white()
    );
    println!(
        "    • post_subscribe: {}",
        mesh.lifecycle
            .post_subscribe
            .as_deref()
            .unwrap_or("<keiner>")
            .bright_white()
    );

    println!();
    println!("  {}", "Streaming Excludes:".bold());
    if mesh.ignore.exclude.is_empty() {
        println!("    • Keine zusätzlichen Excludes (Nutzt .sbignore und Kernel-Regeln)");
    } else {
        for excl in &mesh.ignore.exclude {
            println!("    • {}", excl.dimmed());
        }
    }

    let validation = validate_mesh_config(mesh, forge_opt);
    println!();
    if validation.is_empty() {
        println!(
            "  {} Spezifikation ist syntaktisch und mit Forge.toml kompatibel!",
            "✔".bright_green().bold()
        );
    } else {
        println!(
            "  {} Gefundene Hinweise / Warnungen:",
            "⚠".bright_yellow().bold()
        );
        for w in validation {
            println!("    • {}", w.yellow());
        }
    }
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}
