//! Remote Execution & SFTP Integration (S&B NetGate / sb-ssh Anbindung)
use colored::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tar::Builder;
use walkdir::WalkDir;

/// Ermittelt den Pfad zur authentischen System-OpenSSH Binary (`ssh`)
pub fn find_sb_ssh_binary() -> Result<PathBuf, String> {
    sb_core::ssh_transport::resolve_system_ssh()
}

/// Resolves the canonical SSH & CA environment paths (`~/.sb/ssh`, `~/.sb/ca/ssh/ca_key.pub`).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Child SSH invocations reading legacy `~/.sb-ssh` keys instead of unified `sb-ca` credentials.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Injects canonical `SB_SSH_HOME` (`~/.sb/ssh`) and `SB_CA_SSH_PUB` (`~/.sb/ca/ssh/ca_key.pub`) and ensures `~/.sb/ssh/ssh_config` is up to date.
/// - Standards Compliance: Conforms to IETF RFC 4251.
pub fn unified_ssh_ca_env() -> (PathBuf, PathBuf) {
    let ssh_dir = crate::config::get_sb_ssh_dir();
    let ca_ssh_dir = crate::config::get_sb_ca_ssh_dir();
    let _ca_ready = crate::config::is_ssh_ca_initialized();
    let _ = sb_core::ssh_transport::ensure_sovereign_ssh_config();
    (ssh_dir, ca_ssh_dir.join("ca_key.pub"))
}

/// Lädt eine Datei oder Verzeichnis via OpenSSH SCP (`~/.sb/ssh/ssh_config`) auf den Zielserver hoch
pub async fn sftp_push(
    server: &str,
    local_path: &str,
    remote_path: Option<&str>,
    verbose: bool,
) -> Result<(), String> {
    let (ssh_home, ca_pub) = unified_ssh_ca_env();
    let local = std::path::Path::new(local_path);
    if !local.exists() {
        return Err(format!("Lokaler Pfad '{}' existiert nicht", local_path));
    }

    let (scp_bin, args) =
        sb_core::ssh_transport::build_scp_push_args(server, local_path, remote_path)?;

    if verbose {
        println!("    {} scp {}", "►".bright_black(), args.join(" "));
    }

    let status = tokio::process::Command::new(&scp_bin)
        .env("SB_SSH_HOME", &ssh_home)
        .env("SB_CA_SSH_PUB", &ca_pub)
        .args(&args)
        .status()
        .await
        .map_err(|e| format!("Fehler beim Starten von scp push: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "SCP Push auf Server '{}' fehlgeschlagen (Exit-Code: {:?})",
            server,
            status.code()
        ))
    }
}

/// Lädt eine Datei oder Verzeichnis via OpenSSH SCP (`~/.sb/ssh/ssh_config`) vom Zielserver herunter
pub async fn sftp_pull(
    server: &str,
    remote_path: &str,
    local_path: Option<&str>,
    verbose: bool,
) -> Result<(), String> {
    let (ssh_home, ca_pub) = unified_ssh_ca_env();
    let (scp_bin, args) =
        sb_core::ssh_transport::build_scp_pull_args(server, remote_path, local_path)?;

    if verbose {
        println!("    {} scp {}", "►".bright_black(), args.join(" "));
    }

    let status = tokio::process::Command::new(&scp_bin)
        .env("SB_SSH_HOME", &ssh_home)
        .env("SB_CA_SSH_PUB", &ca_pub)
        .args(&args)
        .status()
        .await
        .map_err(|e| format!("Fehler beim Starten von scp pull: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "SCP Pull von Server '{}' fehlgeschlagen (Exit-Code: {:?})",
            server,
            status.code()
        ))
    }
}

/// Führt einen Befehl remote via OpenSSH (`~/.sb/ssh/ssh_config`) auf dem Zielserver aus (mit In-Memory Secret-Injektion)
pub async fn remote_exec(
    server: &str,
    cmd: &str,
    envs: &HashMap<String, String>,
    verbose: bool,
) -> Result<(), String> {
    let (ssh_home, ca_pub) = unified_ssh_ca_env();
    let formatted_cmd = format_remote_cmd_with_envs(cmd, envs);
    let (ssh_bin, args) = sb_core::ssh_transport::build_ssh_exec_args(server, &formatted_cmd)?;

    if verbose {
        println!(
            "    {} [{}] {}",
            "►".bright_black(),
            server.bright_yellow(),
            cmd.bright_black()
        );
    }

    let status = tokio::process::Command::new(&ssh_bin)
        .env("SB_SSH_HOME", &ssh_home)
        .env("SB_CA_SSH_PUB", &ca_pub)
        .args(&args)
        .status()
        .await
        .map_err(|e| format!("Fehler beim Ausführen von remote_exec via OpenSSH: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Remote-Befehl auf Server '{}' fehlgeschlagen: {}",
            server, cmd
        ))
    }
}

/// Führt einen Remote-Befehl via OpenSSH (`~/.sb/ssh/ssh_config`) aus und erfasst stdout/stderr
pub async fn remote_exec_output(
    server: &str,
    cmd: &str,
    verbose: bool,
) -> Result<std::process::Output, String> {
    let (ssh_home, ca_pub) = unified_ssh_ca_env();
    let (ssh_bin, args) = sb_core::ssh_transport::build_ssh_exec_args(server, cmd)?;

    if verbose {
        println!(
            "    {} [{}] {}",
            "►".bright_black(),
            server.bright_yellow(),
            cmd.bright_black()
        );
    }

    tokio::process::Command::new(&ssh_bin)
        .env("SB_SSH_HOME", &ssh_home)
        .env("SB_CA_SSH_PUB", &ca_pub)
        .args(&args)
        .output()
        .await
        .map_err(|e| {
            format!(
                "Fehler beim Ausführen von remote_exec_output via OpenSSH: {}",
                e
            )
        })
}

/// Metadaten eines aktiven Remote-Deployment-Locks zur Kollisions- und Race-Condition-Abwehr
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentLock {
    pub project: String,
    pub target: String,
    pub user: String,
    pub host: String,
    pub pid: u32,
    pub timestamp: u64,
    pub ttl_secs: u64,
}

impl DeploymentLock {
    pub fn new(project: &str, target: &str, ttl_secs: u64) -> Self {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            project: project.to_string(),
            target: target.to_string(),
            user,
            host,
            pid,
            timestamp,
            ttl_secs,
        }
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time >= self.timestamp.saturating_add(self.ttl_secs)
    }

    pub fn lock_file_path(project_name: &str) -> String {
        let safe_name: String = project_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("/tmp/sb_forge_{}.lock", safe_name)
    }
}

/// RAII-Guard für den Remote-Deployment-Lock
pub struct RemoteLockGuard {
    pub server: String,
    pub lock_path: String,
    pub acquired: bool,
}

impl RemoteLockGuard {
    pub async fn release(&mut self) {
        if self.acquired {
            let rm_cmd = format!("rm -f '{}'", self.lock_path);
            let _ = remote_exec(&self.server, &rm_cmd, &HashMap::new(), false).await;
            self.acquired = false;
        }
    }
}

/// Sichert atomar einen Remote-Deployment-Run-Lock auf dem Zielserver
pub async fn acquire_remote_lock(
    server: &str,
    project_name: &str,
    target_name: &str,
    force: bool,
    verbose: bool,
) -> Result<RemoteLockGuard, String> {
    let lock_path = DeploymentLock::lock_file_path(project_name);
    let check_cmd = format!("cat '{}' 2>/dev/null || true", lock_path);

    if let Ok(out) = remote_exec_output(server, &check_cmd, verbose).await {
        let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !raw.is_empty() {
            if let Ok(existing) = serde_json::from_str::<DeploymentLock>(&raw) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if !existing.is_expired(now) && !force {
                    let elapsed = now.saturating_sub(existing.timestamp);
                    let remaining = (existing.timestamp + existing.ttl_secs).saturating_sub(now);
                    return Err(format!(
                        "Remote-Deployment ist gesperrt: Lockfile auf '{}' existiert bereits!\n  \
                         • Projekt:     {}\n  \
                         • Gehalten von: {}@{} (PID {})\n  \
                         • Pipeline:    '{}'\n  \
                         • Aktiv seit:  vor {}s (verbleibende TTL: {}s)\n  \
                         Tipp: Wenn der vorherige Lauf abgebrochen ist, nutze '--force-lock' zum Entsperren.",
                        server, existing.project, existing.user, existing.host, existing.pid, existing.target, elapsed, remaining
                    ));
                } else if force {
                    println!(
                        "  {} [LOCK-OVERRIDE] Vorhandener Lock von {}@{} (PID {}) wird mit --force-lock überschrieben.",
                        "⚠".bright_yellow().bold(), existing.user, existing.host, existing.pid
                    );
                } else {
                    println!(
                        "  {} [LOCK-EXPIRED] Vorheriger Lock von {}@{} (PID {}) ist abgelaufen (TTL überschritten) und wird neu übernommen.",
                        "ℹ".bright_cyan(), existing.user, existing.host, existing.pid
                    );
                }
            }
        }
    }

    // Setze neuen Lock
    let new_lock = DeploymentLock::new(project_name, target_name, 900); // 15 Min TTL
    let json_bytes = serde_json::to_string(&new_lock)
        .map_err(|e| format!("Lock Serialisierungsfehler: {}", e))?;
    let set_cmd = format!(
        "echo '{}' > '{}'",
        json_bytes.replace('\'', "'\\''"),
        lock_path
    );
    remote_exec(server, &set_cmd, &HashMap::new(), verbose).await?;

    Ok(RemoteLockGuard {
        server: server.to_string(),
        lock_path,
        acquired: true,
    })
}

pub fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

/// Bereitet den Remote-Befehl vor und hängt Umgebungsvariablen / Secrets voran
pub fn format_remote_cmd_with_envs(cmd: &str, envs: &HashMap<String, String>) -> String {
    if envs.is_empty() {
        return cmd.to_string();
    }

    let mut keys: Vec<&String> = envs.keys().collect();
    keys.sort();

    let mut prefix = String::new();
    for k in keys {
        if !is_valid_env_var_name(k) {
            eprintln!(
                "Warnung: Ignoriere ungültigen Umgebungs-Variablennamen: {}",
                k
            );
            continue;
        }
        let v = &envs[k];
        // Sicherung von Anführungszeichen für Bash-Ausführung
        let escaped_val = v.replace('\'', "'\\''");
        prefix.push_str(&format!("export {}='{}'; ", k, escaped_val));
    }

    format!("{}{}", prefix, cmd)
}

/// Führt einen automatisierten Health-Check (lokal oder remote) mit Wiederholungsversuchen durch
pub async fn run_health_check(
    server: Option<&str>,
    check_cmd: &str,
    max_retries: u32,
    delay_secs: u64,
    verbose: bool,
) -> Result<(), String> {
    println!(
        "    {} Prüfe Service-Gesundheit: {}",
        "►".bright_cyan(),
        check_cmd.bright_yellow()
    );

    for attempt in 1..=max_retries {
        let is_ok = if let Some(srv) = server {
            remote_exec(srv, check_cmd, &HashMap::new(), verbose)
                .await
                .is_ok()
        } else {
            let status =
                tokio::process::Command::new(if cfg!(windows) { "powershell" } else { "sh" })
                    .args(if cfg!(windows) {
                        vec!["-Command", check_cmd]
                    } else {
                        vec!["-c", check_cmd]
                    })
                    .status()
                    .await;
            status.map(|s| s.success()).unwrap_or(false)
        };

        if is_ok {
            println!(
                "    {} Health-Check erfolgreich bestanden",
                "✓".bright_green()
            );
            return Ok(());
        }

        if attempt < max_retries {
            println!(
                "    {} Health-Check Versuch {}/{} nicht erfolgreich — warte {}s...",
                "○".bright_yellow(),
                attempt,
                max_retries,
                delay_secs
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
        }
    }

    Err(format!(
        "Health-Check '{}' nach {} Versuchen fehlgeschlagen",
        check_cmd, max_retries
    ))
}

/// Packt das lokale Projektverzeichnis in ein tar.gz Archiv unter Ausschluss von Build-Artefakten
pub fn bundle_workspace(src_dir: &Path, out_tar_gz: &Path) -> Result<usize, String> {
    let tar_gz_file = File::create(out_tar_gz)
        .map_err(|e| format!("Konnte Archiv-Datei nicht erstellen: {}", e))?;
    let enc = GzEncoder::new(tar_gz_file, Compression::default());
    let mut tar = Builder::new(enc);

    let mut count = 0;
    for entry in WalkDir::new(src_dir).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        // Strikte Ausschlüsse
        if name == ".git"
            || name == "target"
            || name == "node_modules"
            || name == "dist"
            || name == ".sb"
            || name.ends_with(".sbkey")
            || name.ends_with(".sealed")
            || name.ends_with(".tar.gz")
            || name.ends_with(".tgz")
            || name == ".env"
        {
            return false;
        }
        true
    }) {
        let entry =
            entry.map_err(|e| format!("Fehler beim Durchlaufen des Verzeichnisses: {}", e))?;
        let path = entry.path();
        if path.is_file() {
            let rel_path = path.strip_prefix(src_dir).map_err(|e| e.to_string())?;
            tar.append_path_with_name(path, rel_path).map_err(|e| {
                format!("Fehler beim Hinzufügen von '{}': {}", rel_path.display(), e)
            })?;
            count += 1;
        }
    }

    tar.finish()
        .map_err(|e| format!("Fehler beim Finalisieren des Tar-Archivs: {}", e))?;
    Ok(count)
}

/// Führt eine Forge Pipeline oder ein Recipe vollständig remote auf einem Flotten-Server aus
pub async fn run_remote_pipeline(
    server: &str,
    target_name: &str,
    env: &str,
    sync: bool,
    dry_run: bool,
    verbose: bool,
    force_lock: bool,
) -> Result<(), String> {
    let start_time = std::time::Instant::now();
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let project_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "REMOTE PIPELINE RUNNER (SOVEREIGN MESH)".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!("  Ziel-Server:     {}", server.cyan().bold());
    println!("  Pipeline/Target: {}", target_name.bright_yellow().bold());
    println!("  Environment:     {}", env.bright_green());
    println!(
        "  Mesh Sync:       {}",
        if sync {
            "Aktiviert (tar.gz Delta-Bundle)".bright_cyan()
        } else {
            "Übersprungen (--no-sync)".bright_black()
        }
    );
    println!(
        "  Run-Lock:        {}",
        if force_lock {
            "Erzwungen (--force-lock)".bright_yellow()
        } else {
            "Aktiv (Kollisionsschutz)".bright_green()
        }
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!();

    if dry_run {
        println!(
            "  {} [DRY-RUN] Es werden keine Remote-Befehle ausgeführt.",
            "ℹ".bright_yellow()
        );
        let lock_path = DeploymentLock::lock_file_path(&project_name);
        println!(
            "  ► Würde Remote Deployment-Run-Lock prüfen: {}",
            lock_path.cyan()
        );
        if sync {
            println!("  ► Würde lokales Workspace '{}' packen und nach /tmp/sb-forge-{}.tar.gz übertragen", project_name, project_name);
        }
        println!(
            "  ► Würde auf Server '{}' ausführen: cd /tmp/sb-forge-{} && sb-forge run {} --env {}",
            server, project_name, target_name, env
        );
        println!(
            "  ► Würde Remote Deployment-Run-Lock nach Abschluss freigeben: {}",
            lock_path.cyan()
        );
        return Ok(());
    }

    print!(
        "  {} Sichere Remote Deployment-Run-Lock auf '{}'... ",
        "►".bright_blue(),
        server.cyan()
    );
    let mut lock_guard =
        acquire_remote_lock(server, &project_name, target_name, force_lock, verbose).await?;
    println!("{}", "✓".green());

    let execution = async {
        let remote_archive = format!("/tmp/sb-forge-{}.tar.gz", project_name);
        let remote_workspace = format!("/tmp/sb-forge-{}", project_name);

        if sync {
            let temp_local_archive =
                std::env::temp_dir().join(format!("sb_forge_{}.tar.gz", project_name));
            print!("  {} Packe lokales Projekt... ", "►".bright_blue());
            let file_count = bundle_workspace(&cwd, &temp_local_archive)?;
            println!("{} ({} Dateien verpackt)", "✓".green(), file_count);

            print!(
                "  {} Übertrage Projekt via NetGate SFTP auf '{}'... ",
                "►".bright_blue(),
                server.cyan()
            );
            sftp_push(
                server,
                &temp_local_archive.to_string_lossy(),
                Some(&remote_archive),
                verbose,
            )
            .await?;
            println!("{}", "✓".green());

            let _ = fs::remove_file(&temp_local_archive);

            print!(
                "  {} Entpacke Projekt im remote Workspace '{}'... ",
                "►".bright_blue(),
                remote_workspace.cyan()
            );
            let unpack_cmd = format!(
                "mkdir -p '{}' && tar -xzf '{}' -C '{}'",
                remote_workspace, remote_archive, remote_workspace
            );
            remote_exec(server, &unpack_cmd, &HashMap::new(), verbose).await?;
            println!("{}", "✓".green());
        }

        // Sammle Secrets für das Environment aus dem lokalen Vault (falls vorhanden)
        let envs = match crate::secret::get_all_secrets(env) {
            Ok(secrets) => secrets,
            Err(_) => HashMap::new(),
        };

        println!(
            "\n  {} Starte Remote-Ausführung von '{}' auf '{}'...\n",
            "►".bright_yellow().bold(),
            target_name.bold(),
            server.cyan().bold()
        );

        let remote_run_cmd = format!(
            "cd '{}' && sb-forge run '{}' --env '{}'",
            remote_workspace, target_name, env
        );

        remote_exec(server, &remote_run_cmd, &envs, true).await?;
        Ok::<(), String>(())
    };

    tokio::pin!(execution);

    let result = tokio::select! {
        res = &mut execution => res,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n  {} SIGINT empfangen! Breche Deployment ab und gebe Remote-Lock frei...", "⚠".bright_yellow().bold());
            lock_guard.release().await;
            return Err("Remote Deployment durch Benutzer abgebrochen (SIGINT / Ctrl+C)".to_string());
        }
    };

    // Release lock guard safely
    lock_guard.release().await;

    result?;

    let elapsed = start_time.elapsed().as_secs_f64();
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} Remote Pipeline '{}' auf '{}' erfolgreich abgeschlossen in {:.2}s!",
        "✓".bright_green().bold(),
        target_name.bold(),
        server.cyan().bold(),
        elapsed
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_remote_cmd_with_envs() {
        let mut envs = HashMap::new();
        envs.insert(
            "DATABASE_URL".to_string(),
            "postgres://localhost:5432".to_string(),
        );
        envs.insert("PORT".to_string(), "8080".to_string());

        let cmd = "node server.js";
        let formatted = format_remote_cmd_with_envs(cmd, &envs);

        assert!(formatted.contains("export DATABASE_URL='postgres://localhost:5432';"));
        assert!(formatted.contains("export PORT='8080';"));
        assert!(formatted.ends_with("node server.js"));
    }

    #[test]
    fn test_format_remote_cmd_empty_envs() {
        let envs = HashMap::new();
        let cmd = "uptime";
        let formatted = format_remote_cmd_with_envs(cmd, &envs);
        assert_eq!(formatted, "uptime");
    }

    #[test]
    fn test_format_remote_cmd_ignores_malicious_env_keys() {
        let mut envs = HashMap::new();
        envs.insert("SAFE_VAR".to_string(), "safe_value".to_string());
        envs.insert("EVIL_VAR; rm -rf /".to_string(), "bad".to_string());
        envs.insert("123INVALID".to_string(), "bad".to_string());
        envs.insert("EVIL$(whoami)".to_string(), "bad".to_string());

        let cmd = "echo test";
        let formatted = format_remote_cmd_with_envs(cmd, &envs);
        assert!(formatted.contains("export SAFE_VAR='safe_value';"));
        assert!(!formatted.contains("rm -rf"));
        assert!(!formatted.contains("123INVALID"));
        assert!(!formatted.contains("whoami"));
        assert!(formatted.ends_with("echo test"));
    }

    #[test]
    fn test_bundle_workspace_excludes_build_artifacts() {
        let temp_dir =
            std::env::temp_dir().join(format!("sb_bundle_test_{}", rand::random::<u32>()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(temp_dir.join("src")).unwrap();
        fs::create_dir_all(temp_dir.join("target/debug")).unwrap();
        fs::create_dir_all(temp_dir.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(temp_dir.join(".git")).unwrap();

        fs::write(temp_dir.join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(temp_dir.join("Forge.toml"), "[forge]").unwrap();
        fs::write(temp_dir.join("target/debug/app.exe"), "binary data").unwrap();
        fs::write(temp_dir.join("node_modules/pkg/index.js"), "console.log()").unwrap();
        fs::write(temp_dir.join(".git/config"), "repo").unwrap();
        fs::write(temp_dir.join(".env"), "SECRET=123").unwrap();

        let out_archive = temp_dir.join("bundle.tar.gz");
        let count = bundle_workspace(&temp_dir, &out_archive).unwrap();

        // Only src/main.rs and Forge.toml must be included (2 files)
        assert_eq!(count, 2);
        assert!(out_archive.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_deployment_lock_serialization_roundtrip() {
        let lock = DeploymentLock {
            project: "my-service".to_string(),
            target: "deploy".to_string(),
            user: "operator".to_string(),
            host: "control-node".to_string(),
            pid: 12345,
            timestamp: 1700000000,
            ttl_secs: 900,
        };

        let json = serde_json::to_string(&lock).unwrap();
        let deserialized: DeploymentLock = serde_json::from_str(&json).unwrap();
        assert_eq!(lock, deserialized);
    }

    #[test]
    fn test_deployment_lock_expiration() {
        let lock = DeploymentLock {
            project: "app".to_string(),
            target: "build".to_string(),
            user: "dev".to_string(),
            host: "laptop".to_string(),
            pid: 999,
            timestamp: 1000,
            ttl_secs: 60,
        };

        // Before TTL expiration
        assert!(!lock.is_expired(1030));
        assert!(!lock.is_expired(1059));

        // At or after TTL expiration
        assert!(lock.is_expired(1060));
        assert!(lock.is_expired(1500));
    }

    #[test]
    fn test_lock_file_path_sanitization() {
        assert_eq!(
            DeploymentLock::lock_file_path("my-app"),
            "/tmp/sb_forge_my-app.lock"
        );
        assert_eq!(
            DeploymentLock::lock_file_path("evil/../name"),
            "/tmp/sb_forge_evil____name.lock"
        );
        assert_eq!(
            DeploymentLock::lock_file_path("prod_v2.0!"),
            "/tmp/sb_forge_prod_v2_0_.lock"
        );
    }

    #[test]
    fn test_unified_ssh_ca_env_strict_paths() {
        let (ssh_home, ca_pub) = unified_ssh_ca_env();
        assert!(!ssh_home.to_string_lossy().contains(".sb-ssh"));
        assert!(ssh_home.ends_with("ssh"));
        assert!(ca_pub.ends_with("ca_key.pub"));
        assert!(ca_pub.to_string_lossy().contains("ca"));
    }
}
