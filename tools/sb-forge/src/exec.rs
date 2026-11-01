//! forge exec — Prozess mit lokalen Vault-Secrets starten; Legacy-Dateien werden abgelehnt.
use colored::*;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::get_active_env;
use crate::forge_toml::load_forge_toml;
use crate::seal::decrypt_sealed_file;
use crate::secret::get_all_secrets;

pub async fn handle_exec(args: crate::cli::ExecArgs) {
    if args.sealed.is_some() {
        eprintln!(
            "  {} Die Nutzung von --sealed ist deaktiviert, da das Legacy-Format keine vertrauliche servergebundene Speicherung bietet.",
            "✗".bright_red()
        );
        std::process::exit(1);
    }

    if args.command.is_empty() {
        eprintln!(
            "  {} Kein Befehl angegeben. Verwendung: sb-forge exec -- node server.js",
            "✗".bright_red()
        );
        std::process::exit(1);
    }

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "EXEC (SECRET INJECTION)".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let mut secrets: HashMap<String, String> = HashMap::new();
    let mut source_description = String::new();

    // 1. Legacy-Dateien erkennen und durch den deaktivierten Decoder ablehnen.
    let sealed_candidate = if let Some(ref path_str) = args.sealed {
        Some(PathBuf::from(path_str))
    } else {
        // Automatische Erkennung typischer Sealed-Pfade (z.B. auf Produktionsserver)
        let candidates = [
            PathBuf::from("/etc/forge/env.sealed"),
            PathBuf::from("env.sealed"),
            crate::config::get_forge_dir().join("env.sealed"),
        ];
        candidates.into_iter().find(|p| p.exists())
    };

    if let Some(ref sealed_path) = sealed_candidate {
        if sealed_path.exists() {
            match decrypt_sealed_file(sealed_path) {
                Ok(decrypted) => {
                    source_description = format!("Sealed Envelope ({:?})", sealed_path);
                    secrets = decrypted;
                }
                Err(e) => {
                    eprintln!(
                        "  {} Fehler beim Entschlüsseln der Sealed-Datei: {}",
                        "✗".bright_red(),
                        e
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    // 2. Falls kein Sealed-File genutzt wurde: aus lokalem Vault laden
    let env_name = if secrets.is_empty() {
        let selected_env = args.env.unwrap_or_else(get_active_env);
        source_description = format!("Lokaler Vault (Environment '{}')", selected_env);

        match get_all_secrets(&selected_env) {
            Ok(s) => secrets = s,
            Err(e) => {
                if !e.contains("nicht im Vault") {
                    eprintln!("  {} Vault-Fehler: {}", "✗".bright_red(), e);
                    std::process::exit(1);
                }
            }
        }

        // Nicht-sensible Config aus Forge.toml dazumischen
        if let Ok(config) = load_forge_toml() {
            if let Some(env_cfg) = config.config.get(&selected_env) {
                for (k, v) in env_cfg {
                    secrets.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
        selected_env
    } else {
        args.env.unwrap_or_else(|| "sealed".to_string())
    };

    println!(
        "  {} Quelle:      {}",
        "►".bright_cyan(),
        source_description.bright_yellow()
    );
    println!(
        "  {} Environment: {}",
        "►".bright_cyan(),
        env_name.bright_yellow()
    );
    println!(
        "  {} Variablen:   {} injiziert",
        "►".bright_cyan(),
        secrets.len()
    );
    println!(
        "  {} Befehl:      {}",
        "►".bright_cyan(),
        args.command.join(" ").bright_white()
    );
    println!();

    let binary = &args.command[0];
    let cmd_args = &args.command[1..];

    crate::audit::log_secret_action(&crate::audit::SecretAuditRecord {
        timestamp: chrono::Utc::now(),
        action: "INJECT".to_string(),
        secret_name: format!("{} secrets injected into {}", secrets.len(), binary),
        env: env_name.clone(),
        user: crate::config::get_current_identity(),
        target_server: None,
        status: "OK".to_string(),
        version: 1,
    });

    let mut child = tokio::process::Command::new(binary)
        .args(cmd_args)
        .envs(&secrets) // Secrets transparent als Env-Vars injizieren
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("  {} Konnte Prozess nicht starten: {}", "✗".bright_red(), e);
            std::process::exit(1);
        });

    let status = child.wait().await.unwrap_or_else(|e| {
        eprintln!("  {} Prozess-Fehler: {}", "✗".bright_red(), e);
        std::process::exit(1);
    });

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
