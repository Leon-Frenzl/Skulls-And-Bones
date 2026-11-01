//! Pipeline & Recipe Runner (Parallele Ausführung, DAG-Resolver & Watch-Mode)
use crate::forge_toml::load_forge_toml;
use colored::*;
use std::collections::HashSet;

/// Extrahiert die relevantesten Fehlerzeilen aus einem Command-Output (Rust Panic, TypeScript, Syntax, etc.)
fn extract_smart_error(output: &str) -> Option<String> {
    let lines: Vec<&str> = output.lines().collect();
    if lines.is_empty() {
        return None;
    }

    let mut important_lines = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let l_lower = line.to_lowercase();
        if l_lower.contains("error:")
            || l_lower.contains("error[e")
            || l_lower.contains("panic:")
            || l_lower.contains("fatal:")
            || l_lower.contains("failed to compile")
            || l_lower.contains("unhandled rejection")
            || l_lower.contains("traceback (most recent call last)")
        {
            let start = idx.saturating_sub(1);
            let end = (idx + 8).min(lines.len());
            for item in &lines[start..end] {
                if !important_lines.contains(item) {
                    important_lines.push(*item);
                }
            }
        }
    }

    if !important_lines.is_empty() {
        Some(important_lines.join("\n"))
    } else if lines.len() > 10 {
        // Fallback: Die letzten 10 Zeilen ausgeben
        Some(lines[lines.len() - 10..].join("\n"))
    } else {
        Some(lines.join("\n"))
    }
}

pub async fn handle_run(args: crate::cli::RunArgs) {
    if args.watch {
        run_watch_mode(args).await;
    } else {
        run_once(&args).await;
    }
}

async fn run_once(args: &crate::cli::RunArgs) {
    if let Some(remote_server) = &args.remote {
        let target_name = args
            .pipeline
            .as_deref()
            .or(args.recipe.as_deref())
            .unwrap_or("deploy");
        let env = args.env.as_deref().unwrap_or("prod");
        if let Err(e) = crate::remote::run_remote_pipeline(
            remote_server,
            target_name,
            env,
            args.sync,
            args.dry_run,
            args.verbose,
            args.force_lock,
        )
        .await
        {
            eprintln!("  {} {}", "✗".bright_red(), e);
            std::process::exit(1);
        }
        return;
    }

    let config = match load_forge_toml() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  {} {}", "✗".bright_red(), e);
            std::process::exit(1);
        }
    };

    if let Some(pipeline_name) = &args.pipeline {
        run_pipeline(&config, pipeline_name, args).await;
    } else if let Some(target_name) = &args.recipe {
        if config.recipe.contains_key(target_name) {
            run_recipe(&config, target_name, args).await;
        } else if config.pipeline.contains_key(target_name) {
            run_pipeline(&config, target_name, args).await;
        } else {
            eprintln!(
                "  {} Weder Recipe noch Pipeline '{}' in Forge.toml gefunden.",
                "✗".bright_red(),
                target_name
            );
            std::process::exit(1);
        }
    } else {
        eprintln!(
            "  {} Kein Recipe oder Pipeline angegeben.",
            "✗".bright_red()
        );
        eprintln!(
            "  Verwendung: sb-forge run <recipe|pipeline> oder sb-forge run --pipeline <name>"
        );
        std::process::exit(1);
    }
}

async fn run_watch_mode(args: crate::cli::RunArgs) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "WATCH MODE (AUTO-RELOAD)".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} Überwache Dateien auf Änderungen... (Abbruch mit Ctrl+C)",
        "►".bright_cyan()
    );
    println!();

    let mut args_no_watch = args.clone();
    args_no_watch.watch = false;

    // Erster Durchlauf
    run_once(&args_no_watch).await;

    let mut last_modified = get_latest_project_mod_time();
    let mut last_run = std::time::Instant::now();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        let current_mod = get_latest_project_mod_time();
        if current_mod > last_modified && last_run.elapsed().as_millis() > 800 {
            last_modified = current_mod;
            last_run = std::time::Instant::now();
            println!();
            println!(
                "  {} Änderung erkannt — führe Tasks erneut aus...",
                "►".bright_yellow().bold()
            );
            run_once(&args_no_watch).await;
        }
    }
}

fn get_latest_project_mod_time() -> std::time::SystemTime {
    let mut latest = std::time::SystemTime::UNIX_EPOCH;
    for entry in walkdir::WalkDir::new(".")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path().to_string_lossy();
        if path.contains(".git")
            || path.contains("target")
            || path.contains(".sb-forge")
            || path.contains("node_modules")
        {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                if mtime > latest {
                    latest = mtime;
                }
            }
        }
    }
    latest
}

async fn run_pipeline(
    config: &crate::forge_toml::ForgeConfig,
    name: &str,
    args: &crate::cli::RunArgs,
) {
    let pipeline = match config.pipeline.get(name) {
        Some(p) => p,
        None => {
            eprintln!(
                "  {} Pipeline '{}' nicht in Forge.toml gefunden",
                "✗".bright_red(),
                name
            );
            std::process::exit(1);
        }
    };

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}: {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "PIPELINE".bold(),
        name.bright_yellow()
    );
    if let Some(desc) = &pipeline.description {
        println!("  {} {}", "i".bright_black(), desc.bright_black());
    }
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!();

    let start = std::time::Instant::now();
    let mut failed = false;

    for (i, stage) in pipeline.stages.iter().enumerate() {
        let parallel_info = if stage.parallel && stage.recipes.len() > 1 {
            format!("(PARALLEL, {} Tasks)", stage.recipes.len())
        } else {
            String::new()
        };

        println!(
            "  {} STAGE {}/{}: {} {}",
            "►".bright_cyan(),
            i + 1,
            pipeline.stages.len(),
            stage.name.bright_white().bold(),
            parallel_info.bright_yellow()
        );

        let stage_start = std::time::Instant::now();

        if stage.parallel && stage.recipes.len() > 1 {
            // PARALLELE AUSFÜHRUNG MIT TOKIO JOINSET
            let mut join_set = tokio::task::JoinSet::new();

            for recipe_name in &stage.recipes {
                let cfg = config.clone();
                let r_name = recipe_name.clone();
                let a = args.clone();
                join_set.spawn(async move {
                    let res = execute_recipe_with_deps(&cfg, &r_name, &a).await;
                    (r_name, res)
                });
            }

            while let Some(res) = join_set.join_next().await {
                match res {
                    Ok((r_name, Ok(duration))) => {
                        println!(
                            "    {} {}  {}",
                            "✓".bright_green(),
                            r_name.bright_white(),
                            format!("{:.1}s", duration.as_secs_f32()).bright_black()
                        );
                    }
                    Ok((r_name, Err(e))) => {
                        println!(
                            "    {} {}  {}",
                            "✗".bright_red(),
                            r_name.bright_white(),
                            e.bright_red()
                        );
                        failed = true;
                    }
                    Err(e) => {
                        println!("    {} Task paniced: {}", "✗".bright_red(), e);
                        failed = true;
                    }
                }
            }
        } else {
            // SEQUENTIELLE AUSFÜHRUNG
            for recipe_name in &stage.recipes {
                if args.dry_run {
                    println!(
                        "    {} [DRY-RUN] {}",
                        "○".bright_black(),
                        recipe_name.bright_yellow()
                    );
                    continue;
                }

                let recipe_result = execute_recipe_with_deps(config, recipe_name, args).await;

                match recipe_result {
                    Ok(duration) => {
                        println!(
                            "    {} {}  {}",
                            "✓".bright_green(),
                            recipe_name.bright_white(),
                            format!("{:.1}s", duration.as_secs_f32()).bright_black()
                        );
                    }
                    Err(e) => {
                        println!(
                            "    {} {}  {}",
                            "✗".bright_red(),
                            recipe_name.bright_white(),
                            e.bright_red()
                        );
                        failed = true;
                        break;
                    }
                }
            }
        }

        let stage_duration = stage_start.elapsed();

        if failed {
            println!(
                "  {} Stage '{}' fehlgeschlagen ({:.1}s)",
                "✗".bright_red(),
                stage.name,
                stage_duration.as_secs_f32()
            );
            break;
        }

        println!(
            "  {} Stage '{}' abgeschlossen ({:.1}s)",
            "✓".bright_green(),
            stage.name,
            stage_duration.as_secs_f32()
        );
        println!();
    }

    let total = start.elapsed();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let run_id = format!("run-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let status_str = if failed { "FAILED" } else { "SUCCESS" };

    crate::audit::log_pipeline_run(&crate::audit::PipelineRunRecord {
        run_id,
        pipeline_or_recipe: name.to_string(),
        is_pipeline: true,
        env: args
            .env
            .clone()
            .unwrap_or_else(crate::config::get_active_env),
        user: crate::config::get_current_identity(),
        started_at: chrono::Utc::now() - chrono::Duration::from_std(total).unwrap_or_default(),
        ended_at: chrono::Utc::now(),
        duration_ms: total.as_millis() as u64,
        status: status_str.to_string(),
        stages_total: pipeline.stages.len(),
        stages_passed: if failed { 0 } else { pipeline.stages.len() },
        failed_step: if failed {
            Some("stage_failure".to_string())
        } else {
            None
        },
    });

    if failed {
        println!(
            "  {} PIPELINE FEHLGESCHLAGEN  {:.1}s total",
            "✗".bright_red().bold(),
            total.as_secs_f32()
        );

        if let Some(failure_action) = &pipeline.on_failure {
            if let Some(rollback_recipe) = &failure_action.recipe {
                println!(
                    "  {} Führe Rollback aus: {}",
                    "►".bright_yellow(),
                    rollback_recipe
                );
                let _ = execute_recipe_with_deps(config, rollback_recipe, args).await;
            }
        }
        std::process::exit(1);
    } else {
        println!(
            "  {} PIPELINE ERFOLGREICH  {:.1}s total",
            "✓".bright_green().bold(),
            total.as_secs_f32()
        );
    }
}

async fn run_recipe(
    config: &crate::forge_toml::ForgeConfig,
    name: &str,
    args: &crate::cli::RunArgs,
) {
    println!("  {} Recipe: {}", "►".bright_cyan(), name.bright_yellow());

    if args.dry_run {
        println!(
            "  {} [DRY-RUN] würde ausführen: {}",
            "○".bright_black(),
            name
        );
        return;
    }

    match execute_recipe_with_deps(config, name, args).await {
        Ok(d) => {
            let run_id = format!("run-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            crate::audit::log_pipeline_run(&crate::audit::PipelineRunRecord {
                run_id,
                pipeline_or_recipe: name.to_string(),
                is_pipeline: false,
                env: args
                    .env
                    .clone()
                    .unwrap_or_else(crate::config::get_active_env),
                user: crate::config::get_current_identity(),
                started_at: chrono::Utc::now() - chrono::Duration::from_std(d).unwrap_or_default(),
                ended_at: chrono::Utc::now(),
                duration_ms: d.as_millis() as u64,
                status: "SUCCESS".to_string(),
                stages_total: 1,
                stages_passed: 1,
                failed_step: None,
            });
            println!(
                "  {} {} ({:.1}s)",
                "✓".bright_green(),
                name,
                d.as_secs_f32()
            );
        }
        Err(e) => {
            let run_id = format!("run-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            crate::audit::log_pipeline_run(&crate::audit::PipelineRunRecord {
                run_id,
                pipeline_or_recipe: name.to_string(),
                is_pipeline: false,
                env: args
                    .env
                    .clone()
                    .unwrap_or_else(crate::config::get_active_env),
                user: crate::config::get_current_identity(),
                started_at: chrono::Utc::now(),
                ended_at: chrono::Utc::now(),
                duration_ms: 0,
                status: "FAILED".to_string(),
                stages_total: 1,
                stages_passed: 0,
                failed_step: Some(e.clone()),
            });
            eprintln!("  {} {}", "✗".bright_red(), e);
            std::process::exit(1);
        }
    }
}

async fn execute_recipe_with_deps(
    config: &crate::forge_toml::ForgeConfig,
    name: &str,
    args: &crate::cli::RunArgs,
) -> Result<std::time::Duration, String> {
    let mut visited = HashSet::new();
    let mut stack = Vec::new();
    execute_recipe_dag(config, name, args, &mut visited, &mut stack).await
}

fn execute_recipe_dag<'a>(
    config: &'a crate::forge_toml::ForgeConfig,
    name: &'a str,
    args: &'a crate::cli::RunArgs,
    visited: &'a mut HashSet<String>,
    stack: &'a mut Vec<String>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<std::time::Duration, String>> + Send + 'a>,
> {
    Box::pin(async move {
        if stack.contains(&name.to_string()) {
            return Err(format!(
                "Zirkuläre Abhängigkeit in Recipes erkannt: {} -> {}",
                stack.join(" -> "),
                name
            ));
        }
        if visited.contains(name) {
            return Ok(std::time::Duration::from_millis(0));
        }

        let recipe = config
            .recipe
            .get(name)
            .ok_or_else(|| format!("Recipe '{}' nicht in Forge.toml gefunden", name))?;

        stack.push(name.to_string());

        if let Some(ref deps) = recipe.depends_on {
            for dep in deps {
                if args.verbose {
                    println!(
                        "    {} Abhängigkeit: {} -> {}",
                        "►".bright_black(),
                        name,
                        dep.bright_yellow()
                    );
                }
                execute_recipe_dag(config, dep, args, visited, stack).await?;
            }
        }

        stack.pop();
        visited.insert(name.to_string());

        execute_single_recipe(config, name, recipe, args).await
    })
}

async fn execute_single_recipe(
    config: &crate::forge_toml::ForgeConfig,
    name: &str,
    recipe: &crate::forge_toml::RecipeDef,
    args: &crate::cli::RunArgs,
) -> Result<std::time::Duration, String> {
    let start = std::time::Instant::now();

    // Secrets & Konfiguration für das Recipe laden
    let env_name = args
        .env
        .as_deref()
        .or(recipe.env.as_deref())
        .unwrap_or("dev");

    let project_name = &config.forge.name;
    let mut secrets =
        crate::secret::get_secrets_for_project(env_name, project_name).unwrap_or_default();
    let config_values = config.config.get(env_name).cloned().unwrap_or_default();
    secrets.extend(config_values.clone());

    // 1. SFTP Actions (Push / Pull)
    if let Some(action) = &recipe.action {
        let server = recipe.server.as_deref().ok_or_else(|| {
            format!(
                "SFTP Action '{}' in Recipe '{}' erfordert 'server = ...'",
                action, name
            )
        })?;

        match action.to_lowercase().as_str() {
            "push" => {
                let local = recipe.local.as_deref().ok_or_else(|| {
                    format!("SFTP Push in Recipe '{}' erfordert 'local = ...'", name)
                })?;
                if args.verbose {
                    println!(
                        "    {} SFTP Push: {} -> {}:{:?}",
                        "►".bright_cyan(),
                        local,
                        server,
                        recipe.remote
                    );
                }
                crate::remote::sftp_push(server, local, recipe.remote.as_deref(), args.verbose)
                    .await?;
                println!(
                    "    {} SFTP Push erfolgreich übertragen",
                    "✓".bright_green()
                );
            }
            "pull" => {
                let remote = recipe.remote.as_deref().ok_or_else(|| {
                    format!("SFTP Pull in Recipe '{}' erfordert 'remote = ...'", name)
                })?;
                if args.verbose {
                    println!(
                        "    {} SFTP Pull: {}:{} -> {:?}",
                        "►".bright_cyan(),
                        server,
                        remote,
                        recipe.local
                    );
                }
                crate::remote::sftp_pull(server, remote, recipe.local.as_deref(), args.verbose)
                    .await?;
                println!(
                    "    {} SFTP Pull erfolgreich heruntergeladen",
                    "✓".bright_green()
                );
            }
            other => {
                return Err(format!(
                    "Unbekannte SFTP Action '{}' in Recipe '{}' (erwartet: 'push' oder 'pull')",
                    other, name
                ))
            }
        }
    }

    // 2. Befehlsausführung (Remote vs. Lokal)
    if let Some(server) = &recipe.server {
        // Remote-Befehle via sb-ssh
        if let Some(commands) = &recipe.run {
            for cmd in commands {
                if args.verbose {
                    println!(
                        "    {} [{}] {}",
                        "►".bright_cyan(),
                        server.bright_yellow(),
                        cmd
                    );
                }
                crate::remote::remote_exec(server, cmd, &secrets, args.verbose).await?;
            }
        }

        if let Some(exec_cmd) = &recipe.exec {
            if args.verbose {
                println!(
                    "    {} [{}] exec {}",
                    "►".bright_cyan(),
                    server.bright_yellow(),
                    exec_cmd
                );
            }
            crate::remote::remote_exec(server, exec_cmd, &secrets, args.verbose).await?;
        }
    } else {
        // Lokale Shell-Befehle
        if let Some(commands) = &recipe.run {
            for cmd in commands {
                if args.verbose {
                    println!("    {} {}", "$".bright_black(), cmd.bright_black());
                }

                let output =
                    tokio::process::Command::new(if cfg!(windows) { "powershell" } else { "sh" })
                        .args(if cfg!(windows) {
                            vec!["-Command", cmd]
                        } else {
                            vec!["-c", cmd]
                        })
                        .env("SB_FORGE_NESTED", "1")
                        .env("CLICOLOR_FORCE", "1")
                        .envs(&secrets)
                        .envs(&config_values)
                        .output()
                        .await
                        .map_err(|e| format!("Befehl konnte nicht gestartet werden: {}", e))?;

                if !output.status.success() {
                    let err_text = String::from_utf8_lossy(&output.stderr);
                    let out_text = String::from_utf8_lossy(&output.stdout);
                    let combined = format!("{}\n{}", out_text, err_text);

                    // Print captured stdout if not verbose (since it wasn't streamed)
                    if !args.verbose && !out_text.trim().is_empty() {
                        println!("{}", out_text.trim_end());
                    }
                    if !err_text.trim().is_empty() {
                        eprintln!("{}", err_text.trim_end());
                    }

                    if let Some(smart_err) = extract_smart_error(&combined) {
                        println!();
                        println!("    {}", "┌── [SMART ERROR INSPECTOR] ──────────────────────────────────────────".bright_red().bold());
                        for line in smart_err.lines() {
                            println!("    {} {}", "│".bright_red(), line.bright_yellow());
                        }
                        println!(
                            "    {}",
                            "└────────────────────────────────────────────────────────────────────"
                                .bright_red()
                                .bold()
                        );
                        println!();
                    }

                    return Err(format!(
                        "Befehl in Recipe '{}' fehlgeschlagen (Exit-Code: {:?}): {}",
                        name,
                        output.status.code(),
                        cmd
                    ));
                } else if !args.verbose {
                    let stdout_str = String::from_utf8_lossy(&output.stdout);
                    if !stdout_str.trim().is_empty() {
                        println!("{}", stdout_str.trim_end());
                    }
                }
            }
        }

        // Direkte lokale exec
        if let Some(exec_cmd) = &recipe.exec {
            let parts: Vec<&str> = exec_cmd.split_whitespace().collect();
            if !parts.is_empty() {
                let status = tokio::process::Command::new(parts[0])
                    .args(&parts[1..])
                    .env("SB_FORGE_NESTED", "1")
                    .env("CLICOLOR_FORCE", "1")
                    .envs(&secrets)
                    .envs(&config_values)
                    .status()
                    .await
                    .map_err(|e| format!("exec fehlgeschlagen: {}", e))?;

                if !status.success() {
                    return Err(format!("exec fehlgeschlagen: {}", exec_cmd));
                }
            }
        }
    }

    // 3. Automatisierter Health-Check
    if let Some(hc) = &recipe.health_check {
        crate::remote::run_health_check(recipe.server.as_deref(), hc, 3, 2, args.verbose).await?;
    }

    Ok(start.elapsed())
}
