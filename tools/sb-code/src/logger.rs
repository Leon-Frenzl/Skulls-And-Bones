#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    pub timestamp: DateTime<Utc>,
    pub tool: String,
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Returns the central logs directory ~/.sb/logs
pub fn get_logs_dir() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sb")
        .join("logs");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn get_errors_jsonl_path() -> PathBuf {
    get_logs_dir().join("errors.jsonl")
}

pub fn get_tool_log_path(tool: &str) -> PathBuf {
    let clean = tool.replace(['/', '\\', ':', '.'], "-");
    get_logs_dir().join(format!("{}.log", clean))
}

/// Appends a structured error record to ~/.sb/logs/errors.jsonl and the tool log
pub fn log_error(tool: &str, message: &str, details: Option<&str>, exit_code: Option<i32>) {
    let now = Utc::now();
    let record = ErrorRecord {
        timestamp: now,
        tool: tool.to_string(),
        level: "ERROR".to_string(),
        message: message.to_string(),
        details: details.map(|s| s.to_string()),
        exit_code,
    };

    // 1. Write to errors.jsonl
    let jsonl_path = get_errors_jsonl_path();
    if let Ok(json_line) = serde_json::to_string(&record) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(jsonl_path)
        {
            let _ = writeln!(file, "{}", json_line);
        }
    }

    // 2. Write to tool-specific text log
    let text_path = get_tool_log_path(tool);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(text_path) {
        let details_str = match details {
            Some(d) if !d.is_empty() => format!(" | Details: {}", d),
            _ => String::new(),
        };
        let code_str = match exit_code {
            Some(c) => format!(" [Exit Code: {}]", c),
            None => String::new(),
        };
        let _ = writeln!(
            file,
            "[{}] [ERROR] {}{}{}",
            now.format("%Y-%m-%d %H:%M:%S UTC"),
            message,
            code_str,
            details_str
        );
    }
}

/// Appends a warning message to the tool-specific log
pub fn log_warn(tool: &str, message: &str) {
    let now = Utc::now();
    let text_path = get_tool_log_path(tool);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(text_path) {
        let _ = writeln!(
            file,
            "[{}] [WARN] {}",
            now.format("%Y-%m-%d %H:%M:%S UTC"),
            message
        );
    }
}

/// Appends an informational message to the tool-specific log
pub fn log_info(tool: &str, message: &str) {
    let now = Utc::now();
    let text_path = get_tool_log_path(tool);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(text_path) {
        let _ = writeln!(
            file,
            "[{}] [INFO] {}",
            now.format("%Y-%m-%d %H:%M:%S UTC"),
            message
        );
    }
}

/// Reads recent error records from ~/.sb/logs/errors.jsonl
pub fn read_recent_errors(limit: usize) -> Vec<ErrorRecord> {
    let path = get_errors_jsonl_path();
    if !path.exists() {
        return Vec::new();
    }

    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<ErrorRecord>(&line) {
            records.push(record);
        }
    }

    records.reverse();
    records.truncate(limit);
    records
}

/// Clears all log files in ~/.sb/logs/
pub fn clear_all_logs() -> std::io::Result<()> {
    let logs_dir = get_logs_dir();
    if let Ok(entries) = fs::read_dir(&logs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = fs::remove_file(path);
            }
        }
    }
    Ok(())
}
