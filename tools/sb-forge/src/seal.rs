//! Environment activation and revocation; legacy sealing is disabled.
use chrono::Utc;
use colored::*;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::config::{
    get_active_env, get_current_identity, load_forge_session, save_forge_session, ForgeSession,
};
use crate::forge_toml::load_forge_toml;

const LEGACY_SEAL_DISABLED: &str = "Das unsichere SB_FORGE_SEALED_V1-Format ist deaktiviert. Bestehende env.sealed-Dateien werden nicht verwendet. Lokale Vault-Abläufe bleiben verfügbar; serverseitige Secret-Verteilung wird derzeit nicht unterstützt.";

pub async fn handle_env(args: crate::cli::EnvArgs) {
    use crate::cli::EnvAction;
    match args.action {
        EnvAction::Activate { env } => {
            activate_environment(&env);
        }
        EnvAction::List => {
            list_environments();
        }
        EnvAction::Revoke { env } => {
            revoke_environment(&env);
        }
        EnvAction::Seal { .. } => {
            eprintln!("  {} {}", "✗".bright_red(), LEGACY_SEAL_DISABLED);
            std::process::exit(1);
        }
    }
}

// ── ENVIRONMENT AKTIVIERUNG ─────────────────────────────────────────────────

fn activate_environment(env: &str) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "ENVIRONMENT AKTIVIEREN".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let identity = get_current_identity();
    let session = ForgeSession {
        active_env: env.to_string(),
        activated_at: Utc::now(),
        activated_by: identity.clone(),
    };

    if let Err(e) = save_forge_session(&session) {
        eprintln!(
            "  {} Konnte Session nicht speichern: {}",
            "✗".bright_red(),
            e
        );
        std::process::exit(1);
    }

    println!(
        "  {} Environment '{}' ist jetzt aktiv",
        "✓".bright_green().bold(),
        env.bright_yellow()
    );
    println!(
        "  {} Operator:   {}",
        "i".bright_cyan(),
        identity.bright_white()
    );
    println!(
        "  {} Gespeichert: ~/.sb-forge/session.toml",
        "i".bright_black()
    );
    println!();
    println!("  Standard für alle nachfolgenden Befehle ohne `--env`:");
    println!(
        "    • {}",
        format!("sb-forge run <recipe>       (nutzt {})", env).bright_white()
    );
    println!(
        "    • {}",
        format!("sb-forge exec -- <cmd>      (nutzt {})", env).bright_white()
    );
    println!(
        "    • {}",
        format!("sb-forge secret list        (zeigt {})", env).bright_white()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}

// ── ENVIRONMENT LISTE ───────────────────────────────────────────────────────

fn list_environments() {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "ENVIRONMENTS".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let active_env = get_active_env();
    let session = load_forge_session();

    let mut all_envs: HashSet<String> = ["dev", "staging", "prod"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Environments aus Forge.toml einlesen
    if let Ok(config) = load_forge_toml() {
        for def in config.secret.values() {
            for e in &def.environments {
                all_envs.insert(e.clone());
            }
        }
        for e in config.config.keys() {
            all_envs.insert(e.clone());
        }
    }

    // Environments aus bestehenden Vaults einlesen
    let vault_dir = match sb_core::vault::VaultStore::active() {
        Ok(store) => store.root().to_path_buf(),
        Err(error) => {
            eprintln!(
                "  {} Vault-Profile konnten nicht geladen werden: {}",
                "✗".bright_red(),
                error
            );
            std::process::exit(1);
        }
    };
    if let Ok(entries) = std::fs::read_dir(&vault_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("vault") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    all_envs.insert(stem.to_string());
                }
            }
        }
    }

    let mut sorted_envs: Vec<String> = all_envs.into_iter().collect();
    sorted_envs.sort();

    for env_name in &sorted_envs {
        let is_active = env_name == &active_env;
        let vault = crate::secret::load_vault_or_exit(env_name);
        let secret_count = vault.secrets.len();

        let badge = if is_active {
            "[AKTIV]".bright_green().bold()
        } else {
            "       ".normal()
        };

        let status_dot = if is_active {
            "●".bright_green()
        } else if secret_count > 0 {
            "●".bright_cyan()
        } else {
            "○".bright_black()
        };

        println!(
            "  {} {:10} {:7} — {:2} Secrets im Vault",
            status_dot,
            env_name.bright_yellow(),
            badge,
            secret_count
        );
    }

    println!();
    if let Some(sess) = session {
        println!(
            "  {} Aktives Environment: {} (aktiviert von {} am {})",
            "i".bright_cyan(),
            sess.active_env.bright_yellow(),
            sess.activated_by.bright_white(),
            sess.activated_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    } else {
        println!(
            "  {} Kein Environment manuell aktiviert (Default: dev)",
            "i".bright_black()
        );
    }
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}

// ── ENVIRONMENT REVOKE ──────────────────────────────────────────────────────

fn revoke_environment(env: &str) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "ENVIRONMENT REVOKE".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let current = get_active_env();
    if current == env {
        let reset_session = ForgeSession {
            active_env: "dev".to_string(),
            activated_at: Utc::now(),
            activated_by: get_current_identity(),
        };
        let _ = save_forge_session(&reset_session);
        println!(
            "  {} Aktives Environment '{}' zurückgesetzt auf 'dev'",
            "✓".bright_green(),
            env
        );
    }

    // Lokales env.sealed entfernen falls vorhanden
    let local_sealed = PathBuf::from(format!("env.{}.sealed", env));
    if local_sealed.exists() {
        let _ = std::fs::remove_file(&local_sealed);
        println!(
            "  {} Lokales {:?} entfernt",
            "✓".bright_green(),
            local_sealed
        );
    }

    println!(
        "  {} Environment '{}' erfolgreich widerrufen",
        "✓".bright_green().bold(),
        env
    );
}

// ── DISABLED LEGACY SEAL FORMAT ─────────────────────────────────────────────

pub fn decrypt_sealed_file(
    _path: &std::path::Path,
) -> Result<std::collections::HashMap<String, String>, String> {
    Err(LEGACY_SEAL_DISABLED.to_string())
}
