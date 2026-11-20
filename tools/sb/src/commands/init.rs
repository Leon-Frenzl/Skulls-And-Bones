use colored::*;
use std::fs;
use std::path::PathBuf;

use crate::commands::lease::is_lease_active;
use crate::meta::print_banner;

pub fn handle_sb_init(force: bool, template: Option<&str>) {
    print_banner();
    println!(
        "  {} {}\n",
        "► PROJEKT-BOOTSTRAP & SECRET-GUARD".bold(),
        "[INIT]".bright_cyan()
    );

    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let project_name = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-project");

    let forge_file = current_dir.join("Forge.toml");
    if forge_file.exists() && !force {
        println!(
            "  {} Forge.toml existiert bereits (Verwende --force zum Überschreiben).",
            "○".bright_black()
        );
    } else {
        let stack = if let Some(t) = template {
            t.to_lowercase()
        } else if current_dir.join("Cargo.toml").exists() {
            "rust".to_string()
        } else if current_dir.join("package.json").exists() {
            "node".to_string()
        } else if current_dir.join("pyproject.toml").exists()
            || current_dir.join("requirements.txt").exists()
        {
            "python".to_string()
        } else if current_dir.join("go.mod").exists() {
            "go".to_string()
        } else {
            "generic".to_string()
        };

        let (stack_title, check_cmd, build_cmd) = match stack.as_str() {
            "rust" => (
                "Rust",
                "cargo clippy --all-targets --all-features && cargo test",
                "cargo build --release",
            ),
            "node" | "ts" | "typescript" => ("Node.js / TypeScript", "npm test", "npm run build"),
            "python" | "py" => ("Python", "pytest", "python -m build"),
            "go" | "golang" => ("Go", "go vet ./... && go test ./...", "go build -o bin/app"),
            _ => (
                "Generisch",
                "echo 'Running tests...'",
                "echo 'Building project...'",
            ),
        };

        println!(
            "  {} Erkannter Tech-Stack: {}",
            "►".bright_cyan(),
            stack_title.bold().bright_white()
        );

        let forge_content = format!(
            r#"[forge]
name = "{}"
version = "0.1.0"

# ── SECRETS (Werte werden via `sb env set` verwaltet — KEINE .env DATEIEN) ────
# [secret.database_url]
# description  = "Datenbankverbindung"
# environments = ["dev", "staging", "prod"]
# inject_as    = "DATABASE_URL"

# ── KONFIGURATION (nicht-sensible Umgebungsvariablen) ─────────────────────────
[config.dev]
NODE_ENV = "development"
LOG_LEVEL = "debug"

[config.prod]
NODE_ENV = "production"
LOG_LEVEL = "warn"

# ── RECIPES (atomare Tasks) ───────────────────────────────────────────────────
[recipe.check]
description = "Tests & statische Code-Analyse"
run = ["{}"]

[recipe.build]
description = "Projekt kompilieren"
run = ["{}"]

# ── PIPELINES (geordnete Stages) ──────────────────────────────────────────────
[pipeline.deploy]
description = "Vollständige Pipeline"
stages = [
  {{ name = "Quality Gate", recipes = ["check"] }},
  {{ name = "Build",        recipes = ["build"] }}
]
"#,
            project_name, check_cmd, build_cmd
        );

        if let Err(e) = fs::write(&forge_file, forge_content) {
            sb_core::logfmt::error(
                "ERR_SB_INIT_FORGE",
                "sb.init",
                "Failed to write Forge.toml",
                &[("error", &e.to_string())],
            );
        } else {
            println!(
                "  {} Forge.toml für {} erfolgreich erstellt.",
                "✓".bright_green(),
                stack_title.bold()
            );
        }
    }

    // 2. Lease & Identity Telemetry
    if is_lease_active() {
        println!(
            "  {} Ephemeral RAM Lease ist aktiv. Du bist sofort startklar!",
            "✓".bright_green().bold()
        );
    } else {
        println!(
            "  {} Hinweis: Schalte dein RAM Lease frei mit: {}",
            "i".bright_yellow(),
            "sb lease".bright_cyan().bold()
        );
    }

    println!("\n  {} Schnelleinstieg:", "►".bold());
    println!(
        "    • Variable / Secret setzen:    {}",
        "sb env set DATABASE_URL --value \"postgres://...\"".bright_white()
    );
    println!(
        "    • App ohne .env starten:        {}",
        "sb env run -- npm run dev".bright_white()
    );
    println!(
        "    • Bestehende .env importieren:   {}",
        "sb env import .env --delete-source".bright_white()
    );
}
