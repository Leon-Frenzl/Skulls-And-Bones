//! Secret Vault — verschlüsselter lokaler Secret-Speicher
//! Verschlüsselung und Dateizugriff werden zentral über sb-core bereitgestellt.
use chrono::Utc;
use colored::*;
use std::collections::HashMap;

pub use sb_core::vault::{VaultFile as Vault, VaultSecretEntry as SecretEntry};

fn store() -> Result<sb_core::vault::VaultStore, String> {
    sb_core::vault::VaultStore::active()
}

pub fn load_vault(env: &str) -> Result<Vault, String> {
    store()?.load(env)
}

pub fn load_vault_or_exit(env: &str) -> Vault {
    load_vault(env).unwrap_or_else(|error| {
        eprintln!("  {} Vault-Fehler: {}", "✗".bright_red(), error);
        std::process::exit(1);
    })
}

fn save_vault(env: &str, vault: &Vault) -> Result<(), String> {
    store()?.save(env, vault)
}

fn prompt_vault_session() -> Result<sb_core::vault::VaultSession, String> {
    let passphrase = rpassword::prompt_password("Vault-Passwort: ")
        .map_err(|e| format!("Vault-Passwort konnte nicht sicher abgefragt werden: {e}"))?;
    Ok(sb_core::vault::VaultSession::from_owned_passphrase(
        passphrase,
    ))
}

/// Secret verschlüsseln und im Vault speichern
pub fn set_secret(
    env: &str,
    name: &str,
    value: &str,
    identity: &str,
    project: &str,
) -> Result<(), String> {
    if let Some(client) = sb_core::daemon_client::DaemonClient::try_connect_default()? {
        ensure_daemon_vault_session(&client, env, true)?;
        client.call(
            "vault.set",
            serde_json::json!({
                "environment": env,
                "name": name,
                "value": value,
                "project": project,
                "updated_by": identity
            }),
        )?;
        return Ok(());
    }

    let session = prompt_vault_session()?;
    let mut vault = load_vault(env)?;
    if vault.verifier.is_none() {
        if !vault.secrets.is_empty() {
            return Err("Dieser Vault ist nicht initialisiert; bestehende Daten werden nicht automatisch übernommen".to_string());
        }
        session.initialize(&mut vault)?;
    } else {
        session.verify_vault(&vault)?;
    }
    let (ciphertext, nonce, salt) = session.encrypt(value)?;
    let version = vault.secrets.get(name).map(|e| e.version + 1).unwrap_or(1);
    vault.secrets.insert(
        name.to_string(),
        SecretEntry {
            ciphertext,
            nonce,
            salt,
            updated_at: Utc::now().to_rfc3339(),
            updated_by: identity.to_string(),
            version,
            project: project.to_string(),
        },
    );
    save_vault(env, &vault)
}

/// Aktuelles Projekt aus lokaler Forge.toml ableiten (oder "global" als Fallback)
pub fn detect_current_project() -> String {
    if let Ok(config) = crate::forge_toml::load_forge_toml() {
        if !config.forge.name.is_empty() {
            return config.forge.name;
        }
    }
    "global".to_string()
}

/// Secret entschlüsseln
pub fn get_secret(env: &str, name: &str) -> Result<String, String> {
    if let Some(client) = sb_core::daemon_client::DaemonClient::try_connect_default()? {
        ensure_daemon_vault_session(&client, env, false)?;
        let mut result = client.call(
            "vault.get",
            serde_json::json!({"environment": env, "name": name}),
        )?;
        return match result
            .as_object_mut()
            .and_then(|fields| fields.remove("value"))
        {
            Some(serde_json::Value::String(value)) => Ok(value),
            _ => Err("Daemon returned no secret value".to_string()),
        };
    }

    let vault = load_vault(env)?;
    let entry = vault
        .secrets
        .get(name)
        .ok_or_else(|| format!("Secret '{}' nicht im Vault für Environment '{}'", name, env))?;
    let session = prompt_vault_session()?;
    session.verify_vault(&vault)?;
    session.decrypt(entry)
}

/// Alle Secrets eines bestimmten Projekts + globale Secrets entschlüsseln
pub fn get_secrets_for_project(
    env: &str,
    project: &str,
) -> Result<HashMap<String, String>, String> {
    if let Some(client) = sb_core::daemon_client::DaemonClient::try_connect_default()? {
        ensure_daemon_vault_session(&client, env, false)?;
        let values = client.call(
            "vault.get_all",
            serde_json::json!({"environment": env, "project": project}),
        )?;
        return serde_json::from_value(values)
            .map_err(|error| format!("Daemon returned invalid project secrets: {error}"));
    }

    let vault = load_vault(env)?;
    let session = prompt_vault_session()?;
    session.verify_vault(&vault)?;
    let mut result = HashMap::new();

    for (name, entry) in &vault.secrets {
        if entry.project == project || entry.project == "global" {
            let value = session.decrypt(entry)?;
            result.insert(name.clone(), value);
        }
    }

    Ok(result)
}

/// Alle Secrets eines Environments entschlüsseln (für forge exec)
pub fn get_all_secrets(env: &str) -> Result<HashMap<String, String>, String> {
    if let Some(client) = sb_core::daemon_client::DaemonClient::try_connect_default()? {
        ensure_daemon_vault_session(&client, env, false)?;
        let values = client.call("vault.get_all", serde_json::json!({"environment": env}))?;
        return serde_json::from_value(values)
            .map_err(|error| format!("Daemon returned invalid secrets: {error}"));
    }

    let vault = load_vault(env)?;
    let session = prompt_vault_session()?;
    session.verify_vault(&vault)?;
    let mut result = HashMap::new();

    for (name, entry) in &vault.secrets {
        let value = session.decrypt(entry)?;
        result.insert(name.clone(), value);
    }

    Ok(result)
}

fn ensure_daemon_vault_session(
    client: &sb_core::daemon_client::DaemonClient,
    environment: &str,
    initialize_if_needed: bool,
) -> Result<(), String> {
    let status = client.call(
        "vault.status",
        serde_json::json!({"environment": environment}),
    )?;
    let initialized = status
        .get("initialized")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "Daemon returned invalid vault status".to_string())?;
    let unlocked = status
        .get("unlocked")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "Daemon returned invalid vault status".to_string())?;
    if unlocked && initialized {
        return Ok(());
    }
    if !initialized && !initialize_if_needed {
        return Err("Vault ist noch nicht initialisiert; zuerst ein Secret setzen".to_string());
    }

    let password = rpassword::prompt_password("Vault-Passwort: ")
        .map_err(|error| format!("Vault-Passwort konnte nicht abgefragt werden: {error}"))?;
    if password.is_empty() {
        return Err("Vault-Passwort darf nicht leer sein".to_string());
    }
    let mut params = serde_json::json!({"environment": environment});
    params
        .as_object_mut()
        .ok_or_else(|| "Invalid RPC parameter object".to_string())?
        .insert("password".to_string(), serde_json::Value::String(password));
    let method = if initialized {
        "vault.unlock"
    } else {
        "vault.initialize"
    };
    client.call(method, params)?;
    Ok(())
}

/// Secret-Handler für CLI
pub fn handle_secret(args: crate::cli::SecretArgs) {
    use crate::cli::SecretAction;

    match args.action {
        SecretAction::Set {
            name,
            env,
            value,
            project,
        } => {
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!(
                "  {} {} {}",
                "S&B FORGE".bright_blue().bold(),
                "//".bright_black(),
                "SECRET SETZEN".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            let proj = project.unwrap_or_else(detect_current_project);
            println!(
                "  {} Secret:      {}",
                "►".bright_cyan(),
                name.bright_yellow()
            );
            println!(
                "  {} Projekt:     {}",
                "►".bright_cyan(),
                proj.bright_magenta()
            );
            println!(
                "  {} Environment: {}",
                "►".bright_cyan(),
                env.bright_yellow()
            );
            println!();

            let val = match value {
                Some(v) => v,
                None => read_secret_input(),
            };

            if val.is_empty() {
                eprintln!("  {} Leerer Wert — abgebrochen", "✗".bright_red());
                std::process::exit(1);
            }

            let identity = crate::config::get_current_identity();
            match set_secret(&env, &name, &val, &identity, &proj) {
                Ok(()) => {
                    let vault = load_vault_or_exit(&env);
                    let ver = vault.secrets.get(&name).map(|s| s.version).unwrap_or(1);
                    crate::audit::log_secret_action(&crate::audit::SecretAuditRecord {
                        timestamp: chrono::Utc::now(),
                        action: "SET".to_string(),
                        secret_name: name.clone(),
                        env: env.clone(),
                        user: identity,
                        target_server: None,
                        status: "OK".to_string(),
                        version: ver,
                    });
                    println!(
                        "  {} Secret '{}' (Projekt: '{}') für '{}' gespeichert (v{})",
                        "✓".bright_green(),
                        name.bright_yellow(),
                        proj.bright_magenta(),
                        env.bright_yellow(),
                        ver
                    );
                }
                Err(e) => {
                    eprintln!("  {} Fehler: {}", "✗".bright_red(), e);
                    std::process::exit(1);
                }
            }
        }

        SecretAction::List { env, project } => {
            let envs = env.map(|e| vec![e]).unwrap_or_else(|| {
                vec!["dev".to_string(), "staging".to_string(), "prod".to_string()]
            });

            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!(
                "  {} {} {}",
                "S&B FORGE".bright_blue().bold(),
                "//".bright_black(),
                "SECRET ÜBERSICHT".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );

            for env_name in &envs {
                let vault = load_vault_or_exit(env_name);
                if vault.secrets.is_empty() {
                    println!(
                        "  {} [{}]  — keine Secrets",
                        "○".bright_black(),
                        env_name.bright_yellow()
                    );
                    continue;
                }
                println!("  {} [{}]", "●".bright_cyan(), env_name.bright_yellow());

                // Gruppieren nach Projekt
                let mut by_project: std::collections::BTreeMap<
                    String,
                    Vec<(&String, &SecretEntry)>,
                > = std::collections::BTreeMap::new();
                for (name, entry) in &vault.secrets {
                    if let Some(ref filter_proj) = project {
                        if &entry.project != filter_proj && entry.project != "global" {
                            continue;
                        }
                    }
                    by_project
                        .entry(entry.project.clone())
                        .or_default()
                        .push((name, entry));
                }

                if by_project.is_empty() {
                    println!(
                        "    {} Keine Treffer für Filter '{:?}'",
                        "○".bright_black(),
                        project
                    );
                    continue;
                }

                for (proj_name, list) in by_project {
                    println!(
                        "    {} Projekt: {}",
                        "◆".bright_magenta(),
                        proj_name.bright_white().bold()
                    );
                    for (name, entry) in list {
                        let date_str = if entry.updated_at.len() >= 10 {
                            &entry.updated_at[..10]
                        } else {
                            &entry.updated_at
                        };
                        println!(
                            "      {} {:30}  v{}  aktualisiert: {}",
                            "►".bright_black(),
                            name.bright_white(),
                            entry.version,
                            date_str
                        );
                    }
                }
            }
        }

        SecretAction::Get {
            name,
            env,
            project: _,
        } => match get_secret(&env, &name) {
            Ok(value) => {
                crate::audit::log_secret_action(&crate::audit::SecretAuditRecord {
                    timestamp: chrono::Utc::now(),
                    action: "GET".to_string(),
                    secret_name: name.clone(),
                    env: env.clone(),
                    user: crate::config::get_current_identity(),
                    target_server: None,
                    status: "OK".to_string(),
                    version: 1,
                });
                println!("{}", value);
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".bright_red(), e);
                std::process::exit(1);
            }
        },

        SecretAction::Rotate {
            name,
            env,
            value,
            grace,
            project,
        } => {
            let proj = project.unwrap_or_else(detect_current_project);
            println!(
                "  {} Rotiere '{}' in '{}' (Projekt: '{}', Grace: {})...",
                "►".bright_cyan(),
                name,
                env,
                proj,
                grace
            );

            let val = match value {
                Some(v) => v,
                None => read_secret_input(),
            };

            if !val.is_empty() {
                let identity = crate::config::get_current_identity();
                if let Err(e) = set_secret(&env, &name, &val, &identity, &proj) {
                    eprintln!("  {} Fehler bei Rotation: {}", "✗".bright_red(), e);
                    std::process::exit(1);
                }
                let vault = load_vault_or_exit(&env);
                let ver = vault.secrets.get(&name).map(|s| s.version).unwrap_or(2);
                crate::audit::log_secret_action(&crate::audit::SecretAuditRecord {
                    timestamp: chrono::Utc::now(),
                    action: "ROTATE".to_string(),
                    secret_name: name.clone(),
                    env: env.clone(),
                    user: identity,
                    target_server: None,
                    status: "OK".to_string(),
                    version: ver,
                });
                println!(
                    "  {} Secret '{}' (Projekt: '{}') in '{}' rotiert (v{})",
                    "✓".bright_green(),
                    name,
                    proj,
                    env,
                    ver
                );
            } else {
                println!(
                    "  {} Leerer Wert übergeben — Rotation abgebrochen",
                    "✗".bright_red()
                );
            }
        }

        SecretAction::Delete {
            name,
            env,
            project: _,
        } => {
            let mut vault = load_vault_or_exit(&env);
            if vault.secrets.remove(&name).is_some() {
                if let Err(error) = save_vault(&env, &vault) {
                    eprintln!(
                        "  {} Vault konnte nicht gespeichert werden: {}",
                        "✗".bright_red(),
                        error
                    );
                    std::process::exit(1);
                }
                crate::audit::log_secret_action(&crate::audit::SecretAuditRecord {
                    timestamp: chrono::Utc::now(),
                    action: "DELETE".to_string(),
                    secret_name: name.clone(),
                    env: env.clone(),
                    user: crate::config::get_current_identity(),
                    target_server: None,
                    status: "OK".to_string(),
                    version: 0,
                });
                println!(
                    "  {} Secret '{}' aus '{}' gelöscht",
                    "✓".bright_green(),
                    name,
                    env
                );
            } else {
                eprintln!("  {} Secret '{}' nicht gefunden", "✗".bright_red(), name);
            }
        }

        SecretAction::Audit { env, limit } => {
            crate::audit::handle_audit(crate::cli::AuditArgs {
                target: "secrets".to_string(),
                limit,
                pipeline: None,
                env,
                json: false,
            });
        }

        SecretAction::Shard {
            name,
            env,
            threshold,
            total,
            out_dir,
            value,
        } => {
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!(
                "  {} {} {}",
                "S&B FORGE".bright_blue().bold(),
                "//".bright_black(),
                "AONT SECRET SHARDING (k-aus-n)".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );

            let secret_val = if let Some(v) = value {
                v
            } else {
                let vault = load_vault_or_exit(&env);
                if let Some(entry) = vault.secrets.get(&name) {
                    let session = match prompt_vault_session() {
                        Ok(session) => session,
                        Err(error) => {
                            eprintln!("  {} {}", "✗".bright_red(), error);
                            std::process::exit(1);
                        }
                    };
                    if let Err(error) = session.verify_vault(&vault) {
                        eprintln!("  {} {}", "✗".bright_red(), error);
                        std::process::exit(1);
                    }
                    match session.decrypt(entry) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "  {} Konnte Secret '{}' nicht aus dem Vault entschlüsseln: {}",
                                "✗".bright_red(),
                                name,
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                } else {
                    println!(
                        "  {} Secret '{}' nicht im Vault ('{}') gefunden. Bitte Wert eingeben:",
                        "i".bright_yellow(),
                        name,
                        env
                    );
                    let val = read_secret_input();
                    if val.is_empty() {
                        eprintln!("  {} Leerer Wert — abgebrochen", "✗".bright_red());
                        std::process::exit(1);
                    }
                    val
                }
            };

            println!(
                "  {} Secret:         {}",
                "►".bright_cyan(),
                name.bright_yellow()
            );
            println!(
                "  {} Quorum-Modus:   {}-aus-{} Threshold",
                "►".bright_cyan(),
                threshold.to_string().bright_green().bold(),
                total.to_string().bright_white().bold()
            );
            println!(
                "  {} Ausgabepfad:    {}",
                "►".bright_cyan(),
                out_dir.bright_yellow()
            );

            match crate::sharding::generate_aont_shards(
                &name,
                secret_val.as_bytes(),
                threshold,
                total,
            ) {
                Ok(shards) => {
                    let out_path = std::path::Path::new(&out_dir);
                    match crate::sharding::save_shards_to_dir(&shards, out_path) {
                        Ok(saved_paths) => {
                            println!(
                                "\n  {} {} Shards erfolgreich generiert & kryptographisch verwebt:",
                                "✓".bright_green(),
                                saved_paths.len()
                            );
                            for p in saved_paths {
                                println!(
                                    "    {} {}",
                                    "•".bright_cyan(),
                                    p.display().to_string().bright_white()
                                );
                            }
                            println!("\n  {} Mathematische AONT-Garantie:", "i".bright_black());
                            println!("    Jeder einzelne Shard besitzt 0 Bits Information über das Secret.");
                            println!("    Zur Rekonstruktion sind mindestens {} beliebige Shards erforderlich.", threshold.to_string().bright_green().bold());
                            println!("    Befehl zur Rekonstruktion: sb-forge secret assemble -s <shard1>,<shard2>,...");
                        }
                        Err(e) => eprintln!(
                            "  {} Fehler beim Speichern der Shards: {}",
                            "✗".bright_red(),
                            e
                        ),
                    }
                }
                Err(e) => eprintln!("  {} Sharding-Fehler: {}", "✗".bright_red(), e),
            }
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
        }

        SecretAction::Assemble {
            shards,
            save_as,
            env,
        } => {
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!(
                "  {} {} {}",
                "S&B FORGE".bright_blue().bold(),
                "//".bright_black(),
                "AONT SECRET REKONSTRUKTION".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );

            if shards.is_empty() {
                eprintln!(
                    "  {} Keine Shards übergeben (--shards s1,s2,...)",
                    "✗".bright_red()
                );
                std::process::exit(1);
            }

            let paths: Vec<std::path::PathBuf> =
                shards.iter().map(std::path::PathBuf::from).collect();
            match crate::sharding::load_shards_from_files(&paths) {
                Ok(loaded) => match crate::sharding::reconstruct_aont_secret(&loaded) {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes).to_string();
                        let first = &loaded[0];
                        println!(
                            "  {} Secret:         {}",
                            "✓".bright_green(),
                            first.secret_name.bright_green().bold()
                        );
                        println!(
                            "  {} Epoche:         {}",
                            "►".bright_cyan(),
                            first.epoch.to_string().bright_yellow()
                        );
                        println!(
                            "  {} Genutzte Shards:{} / (Schwelle: {})",
                            "►".bright_cyan(),
                            loaded.len().to_string().bright_green().bold(),
                            first.threshold
                        );
                        println!(
                            "  {} AONT-Tag:       {}",
                            "►".bright_cyan(),
                            first.aont_tag.bright_black()
                        );
                        println!(
                            "  {} Status:         {}",
                            "✓".bright_green(),
                            "VERIFIZIERT & AUTHENTIFIZIERT".bright_green().bold()
                        );

                        if let Some(target_name) = save_as {
                            let identity = crate::config::get_current_identity();
                            match set_secret(&env, &target_name, &text, &identity, "global") {
                                    Ok(_) => println!("\n  {} Secret als '{}' in Environment '{}' im Vault gespeichert.", "✓".bright_green(), target_name.bold(), env.bold()),
                                    Err(e) => eprintln!("  {} Fehler beim Speichern im Vault: {}", "✗".bright_red(), e),
                                }
                        } else {
                            println!("\n  {} Rekonstruierter Wert:", "►".bright_cyan());
                            println!("    {}", text.bright_white().bold());
                        }
                    }
                    Err(e) => eprintln!(
                        "  {} Rekonstruktion fehlgeschlagen: {}",
                        "✗".bright_red(),
                        e
                    ),
                },
                Err(e) => eprintln!(
                    "  {} Fehler beim Laden der Shard-Dateien: {}",
                    "✗".bright_red(),
                    e
                ),
            }
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
        }

        SecretAction::Reshare {
            shards,
            revoke,
            out_dir,
        } => {
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!(
                "  {} {} {}",
                "S&B FORGE".bright_blue().bold(),
                "//".bright_black(),
                "PROACTIVE SECRET SHARING (REVOCATION)".bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );

            if shards.is_empty() {
                eprintln!(
                    "  {} Keine Shards übergeben (--shards s1,s2,...)",
                    "✗".bright_red()
                );
                std::process::exit(1);
            }

            let paths: Vec<std::path::PathBuf> =
                shards.iter().map(std::path::PathBuf::from).collect();
            match crate::sharding::load_shards_from_files(&paths) {
                Ok(loaded) => match crate::sharding::proactive_reshare(&loaded, revoke) {
                    Ok(new_shards) => {
                        let out_path = std::path::Path::new(&out_dir);
                        match crate::sharding::save_shards_to_dir(&new_shards, out_path) {
                            Ok(saved_paths) => {
                                let new_epoch = new_shards[0].epoch;
                                println!("  {} Mitglied Shard #{} erfolgreich aus dem Swarm ausgeschlossen!", "✓".bright_green(), revoke.to_string().bright_red().bold());
                                println!(
                                    "  {} Neue Epoche:     {}",
                                    "►".bright_cyan(),
                                    new_epoch.to_string().bright_green().bold()
                                );
                                println!(
                                    "  {} Aktive Shards:   {}",
                                    "►".bright_cyan(),
                                    new_shards.len()
                                );
                                println!(
                                    "  {} Null-Polynom:    g(0) = 0 in GF(256) angewendet",
                                    "►".bright_cyan()
                                );
                                println!("  {} Zero-Knowledge:  Das Secret wurde im Speicher NIEMALS entschlüsselt!", "i".bright_black());
                                println!(
                                    "\n  {} Erneuerte Epochen-Shards gespeichert in {}:",
                                    "✓".bright_green(),
                                    out_dir.bright_yellow()
                                );
                                for p in saved_paths {
                                    println!(
                                        "    {} {}",
                                        "•".bright_cyan(),
                                        p.display().to_string().bright_white()
                                    );
                                }
                                println!(
                                    "\n  Der alte Shard #{} ist ab sofort mathematisch wertlos!",
                                    revoke.to_string().bright_red().bold()
                                );
                            }
                            Err(e) => eprintln!(
                                "  {} Fehler beim Speichern der neuen Shards: {}",
                                "✗".bright_red(),
                                e
                            ),
                        }
                    }
                    Err(e) => eprintln!("  {} Resharing fehlgeschlagen: {}", "✗".bright_red(), e),
                },
                Err(e) => eprintln!(
                    "  {} Fehler beim Laden der Shard-Dateien: {}",
                    "✗".bright_red(),
                    e
                ),
            }
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
        }
    }
}

fn read_secret_input() -> String {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password("  Wert eingeben (versteckt): ").unwrap_or_else(|_| {
            eprint!("  Wert: ");
            let mut s = String::new();
            std::io::stdin().read_line(&mut s).ok();
            s.trim().to_string()
        })
    } else {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).ok();
        s.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_cycle() {
        let password = "test-master-passphrase-12345";
        let plaintext = "postgresql://sb_user:SuperSecretPassword123@db.internal:5432/app";

        let (ciphertext, nonce, salt) =
            sb_core::vault::vault_encrypt(plaintext, password).expect("encryption succeeds");
        let entry = SecretEntry {
            ciphertext,
            nonce,
            salt,
            updated_at: Utc::now().to_rfc3339(),
            updated_by: "test-user".to_string(),
            version: 1,
            project: "test-project".to_string(),
        };

        let decrypted =
            sb_core::vault::vault_decrypt(&entry, password).expect("decryption succeeds");
        assert_eq!(decrypted, plaintext);

        let wrong_res = sb_core::vault::vault_decrypt(&entry, "wrong-password");
        assert!(wrong_res.is_err());
    }
}
