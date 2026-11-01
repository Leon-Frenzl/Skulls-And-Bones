mod audit;
mod cli;
mod config;
mod exec;
pub mod forge_mesh;
mod forge_toml;
mod pipeline;
pub mod remote;
mod runner;
mod scan;
mod seal;
mod secret;
pub mod sharding;
mod tui;
mod vault;

use clap::Parser;
use cli::{Cli, Commands};
use colored::*;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Some(Commands::Completions { shell }) = cli.command {
        handle_completions(shell);
        return;
    }

    if std::env::var("SB_FORGE_NESTED").is_err() {
        print_banner();
    }

    match cli.command {
        Some(Commands::Secret(cmd)) => secret::handle_secret(cmd),
        Some(Commands::Env(cmd)) => seal::handle_env(cmd).await,
        Some(Commands::Run(cmd)) => runner::handle_run(cmd).await,
        Some(Commands::Exec(cmd)) => exec::handle_exec(cmd).await,
        Some(Commands::Scan(cmd)) => scan::handle_scan(cmd),
        Some(Commands::Audit(cmd)) => audit::handle_audit(cmd),
        Some(Commands::Init) => handle_init(),
        Some(Commands::Watch) => tui::run_tui().await,
        Some(Commands::SystemdUnit(cmd)) => handle_systemd_unit(cmd),
        Some(Commands::Check(cmd)) => audit::handle_check(cmd),
        Some(Commands::Fix(cmd)) => handle_fix(cmd),
        Some(Commands::Mesh(cmd)) => handle_mesh(cmd),
        Some(Commands::Remote(cmd)) => {
            if let Err(e) = remote::run_remote_pipeline(
                &cmd.server,
                &cmd.target,
                &cmd.env,
                cmd.sync,
                cmd.dry_run,
                cmd.verbose,
                cmd.force_lock,
            )
            .await
            {
                eprintln!("  {} {}", "✗".bright_red().bold(), e);
                std::process::exit(1);
            }
        }
        Some(Commands::Completions { .. }) => unreachable!(),
        None => tui::run_tui().await,
    }
}

fn handle_mesh(cmd: cli::MeshArgs) {
    let curr = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let action = cmd.action.unwrap_or(cli::MeshAction::Info);
    let forge_opt = forge_toml::load_forge_toml().ok();

    match action {
        cli::MeshAction::Info => match forge_mesh::load_from_dir(&curr) {
            Ok((mesh, path)) => {
                forge_mesh::print_mesh_info(&mesh, &path, forge_opt.as_ref());
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".bright_red().bold(), e);
                println!(
                    "  {} Tipp: Erstelle eine mit: {}",
                    "►".bright_cyan(),
                    "forge mesh init".bright_yellow()
                );
            }
        },
        cli::MeshAction::Check => match forge_mesh::load_from_dir(&curr) {
            Ok((mesh, path)) => {
                let warnings = forge_mesh::validate_mesh_config(&mesh, forge_opt.as_ref());
                println!(
                    "  {} Validiere {}...",
                    "►".bright_cyan(),
                    path.display().to_string().cyan()
                );
                if warnings.is_empty() {
                    println!(
                        "  {} FORGE_MESH.toml ist gültig und konform zu Forge.toml!",
                        "✔".bright_green().bold()
                    );
                } else {
                    println!("  {} Warnungen gefunden:", "⚠".bright_yellow().bold());
                    for w in warnings {
                        println!("    • {}", w.yellow());
                    }
                }
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".bright_red().bold(), e);
            }
        },
        cli::MeshAction::Init { name } => match forge_mesh::init_template(&curr, name.as_deref()) {
            Ok(path) => {
                println!(
                    "  {} FORGE_MESH.toml erfolgreich erstellt: {}",
                    "✔".bright_green().bold(),
                    path.display().to_string().cyan()
                );
                println!(
                    "  {} Passe Swarm-Topic und Anchors nach Bedarf an.",
                    "►".bright_cyan()
                );
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".bright_red().bold(), e);
            }
        },
    }
}

fn print_banner() {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "PIPELINE & SECRET ENGINE".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}

fn handle_init() {
    println!(
        "  {} Initialisiere S&B Forge im aktuellen Verzeichnis...",
        "►".bright_cyan()
    );

    let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let project_name = current_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-project");

    // 1. Forge.toml mit intelligenter Stack-Erkennung
    let forge_path = current_dir.join("Forge.toml");
    if forge_path.exists() {
        println!("  {} Forge.toml existiert bereits", "○".bright_black());
    } else {
        let (stack_name, check_cmd, build_cmd) = if current_dir.join("Cargo.toml").exists() {
            (
                "Rust",
                "cargo clippy --all-targets --all-features && cargo test",
                "cargo build --release",
            )
        } else if current_dir.join("package.json").exists() {
            ("Node.js / TypeScript", "npm test", "npm run build")
        } else if current_dir.join("pyproject.toml").exists()
            || current_dir.join("requirements.txt").exists()
        {
            ("Python", "pytest", "python -m build")
        } else if current_dir.join("go.mod").exists() {
            ("Go", "go vet ./... && go test ./...", "go build -o bin/app")
        } else {
            (
                "Generisch",
                "echo 'Running checks...'",
                "echo 'Building project...'",
            )
        };

        println!(
            "  {} Erkannter Tech-Stack: {}",
            "►".bright_cyan(),
            stack_name.bold().bright_white()
        );

        let template = format!(
            r#"[forge]
name = "{}"
version = "0.1.0"

# ── SECRETS (Werte werden via `sb env set` oder `sb-forge secret set` verwaltet) ──
# [secret.database_url]
# description  = "PostgreSQL Connection String"
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
description = "Linter, Formatierung und Tests prüfen"
run = ["{}"]

[recipe.build]
description = "Projekt kompilieren / bauen"
run = ["{}"]

# ── PIPELINES (geordnete Stages) ──────────────────────────────────────────────
[pipeline.deploy]
description = "Vollständige Deploy-Pipeline"
stages = [
  {{ name = "Quality Gate", recipes = ["check"] }},
  {{ name = "Build",        recipes = ["build"] }}
]
"#,
            project_name, check_cmd, build_cmd
        );

        if let Err(e) = std::fs::write(&forge_path, template) {
            eprintln!(
                "  {} Konnte Forge.toml nicht erstellen: {}",
                "✗".bright_red(),
                e
            );
        } else {
            println!(
                "  {} Forge.toml Template für {} erstellt",
                "✓".bright_green(),
                stack_name
            );
        }
    }

    // 2. Gemeinsame Workspace- und Secret-Ausschlüsse pflegen
    let ignore_path = current_dir.join(".sbignore");
    let mut ignore_content = std::fs::read_to_string(&ignore_path).unwrap_or_default();

    let forge_ignores = [
        ".sb-forge/",
        "forge-secrets.local.toml",
        "target/",
        "dist/",
        "node_modules/",
    ];

    let mut added_ignores = false;
    for pattern in &forge_ignores {
        if !ignore_content.lines().any(|l| l.trim() == *pattern) {
            if !added_ignores {
                if !ignore_content.is_empty() && !ignore_content.ends_with('\n') {
                    ignore_content.push('\n');
                }
                ignore_content.push_str("\n# S&B Forge workspace exclusions\n");
                added_ignores = true;
            }
            ignore_content.push_str(pattern);
            ignore_content.push('\n');
        }
    }

    if added_ignores {
        if let Err(e) = std::fs::write(&ignore_path, ignore_content) {
            eprintln!(
                "  {} Konnte .sbignore nicht aktualisieren: {}",
                "✗".bright_red(),
                e
            );
        } else {
            println!(
                "  {} .sbignore um Workspace-Ausschlüsse erweitert",
                "✓".bright_green()
            );
        }
    } else {
        println!(
            "  {} .sbignore enthält bereits die Workspace-Ausschlüsse",
            "✓".bright_green()
        );
    }

    println!();
    println!(
        "  {} S&B Forge erfolgreich eingerichtet!",
        "✓".bright_green().bold()
    );
    println!(
        "    • Secret anlegen:      {}",
        "sb-forge secret set <name> --env dev".bright_white()
    );
    println!(
        "    • Recipe ausführen:    {}",
        "sb-forge run check".bright_white()
    );
    println!(
        "    • Pipeline starten:    {}",
        "sb-forge run --pipeline deploy".bright_white()
    );
}

fn handle_systemd_unit(args: cli::SystemdUnitArgs) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "SYSTEMD SERVICE GENERATOR".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let (project_name, exec_cmd, description) = if let Ok(config) = forge_toml::load_forge_toml() {
        let p_name = config.forge.name;
        if let Some(recipe) = config.recipe.get(&args.recipe) {
            let cmd = recipe
                .exec
                .clone()
                .or_else(|| recipe.run.as_ref().and_then(|r| r.first().cloned()))
                .unwrap_or_else(|| format!("./{}", args.recipe));
            let desc = recipe
                .description
                .clone()
                .unwrap_or_else(|| format!("{} - {}", p_name, args.recipe));
            (p_name, cmd, desc)
        } else {
            (
                p_name,
                format!("./{}", args.recipe),
                format!("Service {}", args.recipe),
            )
        }
    } else {
        (
            "my-service".to_string(),
            format!("./{}", args.recipe),
            format!("Service {}", args.recipe),
        )
    };

    let workdir = args
        .workdir
        .unwrap_or_else(|| format!("/opt/{}", project_name));
    let service_name = format!("{}-{}.service", project_name, args.recipe);

    let unit = format!(
        r#"[Unit]
Description={description}
After=network.target remote-fs.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={workdir}

# S&B Forge transparent secret injection (zero plaintext on disk)
ExecStart=/usr/local/bin/sb-forge exec --env {env} -- {exec_cmd}

Restart=always
RestartSec=2s

# Hardening Directives (BSI IT-Grundschutz compliant)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/{project_name}

[Install]
WantedBy=multi-user.target
"#,
        description = description,
        user = args.user,
        workdir = workdir,
        env = args.env,
        exec_cmd = exec_cmd,
        project_name = project_name,
    );

    println!(
        "  {} Generierte Service-Unit: {}",
        "►".bright_cyan(),
        service_name.bright_green().bold()
    );
    println!();
    println!("{}", unit.bright_white());
    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────".bright_black()
    );
    println!("  Installation auf dem Produktionsserver:");
    println!(
        "    1. Speichern als:      sudo tee /etc/systemd/system/{}",
        service_name
    );
    println!("    2. Daemon neu laden:   sudo systemctl daemon-reload");
    println!(
        "    3. Service aktivieren: sudo systemctl enable --now {}",
        service_name
    );
    println!(
        "    4. Status prüfen:      sudo systemctl status {}",
        service_name
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}

fn handle_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    let mut cmd = cli::Cli::command();
    clap_complete::generate(shell, &mut cmd, "sb-forge", &mut std::io::stdout());
}

fn handle_fix(args: cli::FixArgs) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "AUTOMATIC WORKSPACE FIXER & FORMATTER".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let mut actions_taken = Vec::new();
    let is_dry = args.dry_run;

    // 1. Rust Detection & Formatting
    if std::path::Path::new("Cargo.toml").exists() {
        if !args.lint {
            println!(
                "  {} Führe Rust-Formatierung aus (cargo fmt)...",
                "►".bright_cyan()
            );
            if is_dry {
                println!("    [DRY-RUN] cargo fmt --all --check");
            } else {
                let status = std::process::Command::new("cargo")
                    .args(&["fmt", "--all"])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        actions_taken.push("cargo fmt --all (Formatiert)".to_string())
                    }
                    _ => eprintln!(
                        "    {} cargo fmt fehlgeschlagen oder nicht im PATH",
                        "✗".bright_red()
                    ),
                }
            }
        }

        if !args.fmt {
            println!(
                "  {} Wende automatische Clippy-Fixes an...",
                "►".bright_cyan()
            );
            if is_dry {
                println!("    [DRY-RUN] cargo clippy --fix --allow-dirty --allow-staged");
            } else {
                let status = std::process::Command::new("cargo")
                    .args(&["clippy", "--fix", "--allow-dirty", "--allow-staged"])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        actions_taken.push("cargo clippy --fix (Lints korrigiert)".to_string())
                    }
                    _ => eprintln!(
                        "    {} cargo clippy --fix fehlgeschlagen oder keine Fixes",
                        "i".bright_yellow()
                    ),
                }
            }
        }
    }

    // 2. Web / Node Detection & Formatting (oxlint / prettier)
    if std::path::Path::new("package.json").exists() {
        println!(
            "  {} Prüfe Web/TypeScript Workspace (package.json gefunden)...",
            "►".bright_cyan()
        );
        if !args.fmt {
            if is_dry {
                println!("    [DRY-RUN] npx oxlint --fix");
            } else {
                let npx_cmd = if cfg!(windows) { "npx.cmd" } else { "npx" };
                if let Ok(s) = std::process::Command::new(npx_cmd)
                    .args(&["oxlint", "--fix"])
                    .status()
                {
                    if s.success() {
                        actions_taken.push("oxlint --fix (Lints korrigiert)".to_string());
                    }
                }
            }
        }

        if !args.lint {
            if is_dry {
                println!("    [DRY-RUN] npx prettier --write .");
            } else {
                let npx_cmd = if cfg!(windows) { "npx.cmd" } else { "npx" };
                if let Ok(s) = std::process::Command::new(npx_cmd)
                    .args(&["prettier", "--write", "."])
                    .status()
                {
                    if s.success() {
                        actions_taken.push("prettier --write (Web-Code formatiert)".to_string());
                    }
                }
            }
        }
    }

    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────".bright_black()
    );
    if is_dry {
        println!(
            "  {} [DRY-RUN] Es wurden keine Änderungen auf der Festplatte vorgenommen.",
            "i".bright_yellow()
        );
    } else if actions_taken.is_empty() {
        println!(
            "  {} Keine Formatierungs- oder Linter-Werkzeuge im aktuellen Verzeichnis nötig.",
            "i".bright_yellow()
        );
    } else {
        println!(
            "  {} Folgende automatische Korrekturen wurden durchgeführt:",
            "✓".bright_green().bold()
        );
        for act in &actions_taken {
            println!("    • {}", act.bright_green());
        }
    }
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}
