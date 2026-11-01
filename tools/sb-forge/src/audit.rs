//! Audit-Log & Secret-Lifecycle Management (BSI IT-Grundschutz OPS.1.1.4 konform)
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::config::{get_active_env, get_forge_dir};
use crate::forge_toml::load_forge_toml;
use crate::secret::load_vault_or_exit;

// ── AUDIT DATENSTRUKTUREN ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRunRecord {
    pub run_id: String,
    pub pipeline_or_recipe: String,
    pub is_pipeline: bool,
    pub env: String,
    pub user: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub status: String, // "SUCCESS", "FAILED", "ROLLED_BACK"
    pub stages_total: usize,
    pub stages_passed: usize,
    pub failed_step: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAuditRecord {
    pub timestamp: DateTime<Utc>,
    pub action: String, // "SET", "GET", "ROTATE", "DELETE", "SEAL", "INJECT"
    pub secret_name: String,
    pub env: String,
    pub user: String,
    pub target_server: Option<String>,
    pub status: String, // "OK", "DENIED", "ERROR"
    pub version: u32,
}

// ── PFADE & LOGGING ─────────────────────────────────────────────────────────

pub fn get_audit_dir() -> PathBuf {
    let dir = get_forge_dir().join("audit");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn runs_log_path() -> PathBuf {
    get_audit_dir().join("runs.jsonl")
}

fn secrets_log_path() -> PathBuf {
    get_audit_dir().join("secrets.jsonl")
}

pub fn log_pipeline_run(record: &PipelineRunRecord) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(runs_log_path())
    {
        if let Ok(line) = serde_json::to_string(record) {
            let _ = writeln!(file, "{}", line);
        }
    }
}

pub fn log_secret_action(record: &SecretAuditRecord) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(secrets_log_path())
    {
        if let Ok(line) = serde_json::to_string(record) {
            let _ = writeln!(file, "{}", line);
        }
    }
}

// ── CLI HANDLER: AUDIT ──────────────────────────────────────────────────────

pub fn handle_audit(args: crate::cli::AuditArgs) {
    if args.json {
        handle_audit_json(&args);
        return;
    }

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "REVISIONSSICHERES AUDIT-LOG".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    match args.target.as_str() {
        "secrets" | "secret" => {
            println!(
                "  {} Ziel: Secret-Lifecycle (SET, GET, ROTATE, SEAL, INJECT)",
                "i".bright_cyan()
            );
            println!();
            display_secret_audit(&args);
        }
        _ => {
            println!(
                "  {} Ziel: Pipeline- & Recipe-Ausführungen",
                "i".bright_cyan()
            );
            println!();
            display_runs_audit(&args);
        }
    }

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}

fn display_runs_audit(args: &crate::cli::AuditArgs) {
    let records = read_run_records(args.limit, args.pipeline.as_deref(), args.env.as_deref());

    if records.is_empty() {
        println!(
            "  {} Keine Pipeline-Aufzeichnungen gefunden in ~/.sb-forge/audit/runs.jsonl",
            "○".bright_black()
        );
        return;
    }

    println!(
        "  {:<16}  {:<8}  {:<18}  {:<8}  {:<16}  {:<8}  {}",
        "RUN ID".bright_black(),
        "STATUS".bright_black(),
        "TASK / PIPELINE".bright_black(),
        "ENV".bright_black(),
        "OPERATOR".bright_black(),
        "DAUER".bright_black(),
        "ZEITPUNKT".bright_black()
    );
    println!("  {}", "─".repeat(95).bright_black());

    for r in &records {
        let status_badge = match r.status.as_str() {
            "SUCCESS" => "✓ OK   ".bright_green().bold(),
            "FAILED" => "✗ FAIL ".bright_red().bold(),
            "ROLLED_BACK" => "↺ ROLL ".bright_yellow().bold(),
            _ => "● RUN  ".bright_blue(),
        };

        let duration_str = format!("{:.2}s", (r.duration_ms as f64) / 1000.0);
        let time_str = r.started_at.format("%Y-%m-%d %H:%M").to_string();

        println!(
            "  {:<16}  {}  {:<18}  {:<8}  {:<16}  {:<8}  {}",
            r.run_id.bright_white(),
            status_badge,
            r.pipeline_or_recipe.bright_yellow(),
            r.env.bright_cyan(),
            r.user,
            duration_str,
            time_str.bright_black()
        );
    }
}

fn display_secret_audit(args: &crate::cli::AuditArgs) {
    let records = read_secret_records(args.limit, args.env.as_deref());

    if records.is_empty() {
        println!(
            "  {} Keine Secret-Aufzeichnungen gefunden in ~/.sb-forge/audit/secrets.jsonl",
            "○".bright_black()
        );
        return;
    }

    println!(
        "  {:<16}  {:<8}  {:<20}  {:<8}  {:<16}  {:<6}  {}",
        "ZEITPUNKT".bright_black(),
        "AKTION".bright_black(),
        "SECRET".bright_black(),
        "ENV".bright_black(),
        "OPERATOR".bright_black(),
        "VERS.".bright_black(),
        "ZIEL-SERVER".bright_black()
    );
    println!("  {}", "─".repeat(95).bright_black());

    for r in &records {
        let action_badge = match r.action.as_str() {
            "SET" => "SET   ".bright_green(),
            "ROTATE" => "ROTATE".bright_yellow().bold(),
            "DELETE" => "DELETE".bright_red().bold(),
            "SEAL" => "SEAL  ".bright_blue().bold(),
            "GET" => "GET   ".normal(),
            _ => "INJECT".bright_cyan(),
        };

        let time_str = r.timestamp.format("%Y-%m-%d %H:%M").to_string();
        let server_str = r.target_server.as_deref().unwrap_or("-");

        println!(
            "  {:<16}  {}  {:<20}  {:<8}  {:<16}  v{:<5}  {}",
            time_str.bright_black(),
            action_badge,
            r.secret_name.bright_white(),
            r.env.bright_yellow(),
            r.user,
            r.version,
            server_str.bright_cyan()
        );
    }
}

fn handle_audit_json(args: &crate::cli::AuditArgs) {
    if args.target == "secrets" || args.target == "secret" {
        let records = read_secret_records(args.limit, args.env.as_deref());
        for r in records {
            if let Ok(line) = serde_json::to_string(&r) {
                println!("{}", line);
            }
        }
    } else {
        let records = read_run_records(args.limit, args.pipeline.as_deref(), args.env.as_deref());
        for r in records {
            if let Ok(line) = serde_json::to_string(&r) {
                println!("{}", line);
            }
        }
    }
}

fn read_run_records(
    limit: usize,
    pipeline_filter: Option<&str>,
    env_filter: Option<&str>,
) -> Vec<PipelineRunRecord> {
    let path = runs_log_path();
    if !path.exists() {
        return vec![];
    }

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let reader = BufReader::new(file);
    let mut records: Vec<PipelineRunRecord> = reader
        .lines()
        .flatten()
        .filter_map(|l| serde_json::from_str::<PipelineRunRecord>(&l).ok())
        .filter(|r| {
            if let Some(p) = pipeline_filter {
                if r.pipeline_or_recipe != p {
                    return false;
                }
            }
            if let Some(e) = env_filter {
                if r.env != e {
                    return false;
                }
            }
            true
        })
        .collect();

    // Neueste zuerst
    records.reverse();
    records.truncate(limit);
    records
}

fn read_secret_records(limit: usize, env_filter: Option<&str>) -> Vec<SecretAuditRecord> {
    let path = secrets_log_path();
    if !path.exists() {
        return vec![];
    }

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let reader = BufReader::new(file);
    let mut records: Vec<SecretAuditRecord> = reader
        .lines()
        .flatten()
        .filter_map(|l| serde_json::from_str::<SecretAuditRecord>(&l).ok())
        .filter(|r| {
            if let Some(e) = env_filter {
                if r.env != e {
                    return false;
                }
            }
            true
        })
        .collect();

    records.reverse();
    records.truncate(limit);
    records
}

// ── CLI HANDLER: CHECK (SECRET LIFECYCLE & ROTATION REMINDER) ───────────────

pub fn handle_check(args: crate::cli::CheckArgs) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "SECRET LIFECYCLE & DRIFT CHECK".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    let target_env = args.env.unwrap_or_else(get_active_env);
    println!(
        "  {} Prüfe Environment: {}",
        "►".bright_cyan(),
        target_env.bright_yellow()
    );
    println!();

    let forge_toml = load_forge_toml().ok();
    let vault = load_vault_or_exit(&target_env);

    let now = Utc::now();
    let mut warnings_count = 0;

    println!("  {}", "1. SECRET ROTATION-STATUS:".bold());
    println!("  {}", "─".repeat(60).bright_black());

    if vault.secrets.is_empty() {
        println!(
            "  {} Keine Secrets im Vault für '{}'",
            "○".bright_black(),
            target_env
        );
    } else {
        for (secret_name, entry) in &vault.secrets {
            let updated_time = DateTime::parse_from_rfc3339(&entry.updated_at)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or(now);

            let age_days = (now - updated_time).num_days();

            // Erwartetes Rotationsintervall aus Forge.toml lesen
            let rotate_policy = forge_toml
                .as_ref()
                .and_then(|cfg| cfg.secret.get(secret_name))
                .and_then(|def| def.rotate_every.as_deref())
                .unwrap_or("90d");

            let max_days = parse_rotation_days(rotate_policy);

            if age_days > max_days {
                println!(
                    "  {} {:24}  {:>3} Tage alt (Soll: max. {:>2} Tage)  {}",
                    "✗".bright_red(),
                    secret_name.bright_white(),
                    age_days,
                    max_days,
                    "[ÜBERFÄLLIG ZUR ROTATION]".bright_red().bold()
                );
                warnings_count += 1;
            } else {
                println!(
                    "  {} {:24}  {:>3} Tage alt (Soll: max. {:>2} Tage)  {}",
                    "✓".bright_green(),
                    secret_name.bright_white(),
                    age_days,
                    max_days,
                    "[GÜLTIG]".bright_green()
                );
            }
        }
    }

    println!();

    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    if warnings_count == 0 {
        println!(
            "  {} Alle Lifecycle-Prüfungen bestanden",
            "✓".bright_green().bold()
        );
    } else {
        println!(
            "  {} {} Warnungen festgestellt — bitte Secrets rotieren!",
            "✗".bright_red().bold(),
            warnings_count
        );
        println!(
            "  i Befehl: sb-forge secret rotate <name> --env {}",
            target_env
        );
    }
}

fn parse_rotation_days(policy: &str) -> i64 {
    let lower = policy.to_lowercase();
    if let Some(stripped) = lower.strip_suffix('d') {
        stripped.parse::<i64>().unwrap_or(90)
    } else if let Some(stripped) = lower.strip_suffix('m') {
        stripped.parse::<i64>().unwrap_or(3) * 30
    } else if let Some(stripped) = lower.strip_suffix('y') {
        stripped.parse::<i64>().unwrap_or(1) * 365
    } else {
        90
    }
}
