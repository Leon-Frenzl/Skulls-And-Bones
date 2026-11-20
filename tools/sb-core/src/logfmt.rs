//! Canonical ordered `logfmt` structured logger with CWE-117 log-injection escaping.
//!
//! Format: `ts=<RFC3339_UTC> lvl=<LEVEL> code=<CODE> trace=<TRACE_ID> src=<SOURCE> msg="<TEXT>" [key=value ...]`

use chrono::{SecondsFormat, Utc};
use std::fmt::Write as _;

/// Standard log severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }
}

/// Escapes `"`, `\`, `\n`, `\r`, `\t`, and all ASCII control characters (`< 0x20` or `0x7F`)
/// to prevent CWE-117 log injection.
pub fn escape_logfmt_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Formats a single `key=value` attribute, quoting values that contain spaces, `=`, `"`, `\`, or control chars.
pub fn format_logfmt_attr(key: &str, value: &str) -> String {
    let safe_key = escape_logfmt_value(key);
    let needs_quotes = value.is_empty()
        || value.chars().any(|c| {
            c.is_whitespace()
                || c == '='
                || c == '"'
                || c == '\\'
                || (c as u32) < 0x20
                || c as u32 == 0x7F
        });
    if needs_quotes {
        format!("{safe_key}=\"{}\"", escape_logfmt_value(value))
    } else {
        format!("{safe_key}={value}")
    }
}

/// Formats a complete canonical ordered `logfmt` line.
pub fn format_logfmt_line(
    level: LogLevel,
    code: &str,
    trace: &str,
    src: &str,
    msg: &str,
    attrs: &[(&str, &str)],
) -> String {
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_val = if trace.trim().is_empty() {
        "none"
    } else {
        trace.trim()
    };
    let mut line = format!(
        "ts={} lvl={} code={} trace={} src={} msg=\"{}\"",
        ts,
        level.as_str(),
        escape_logfmt_value(code),
        escape_logfmt_value(trace_val),
        escape_logfmt_value(src),
        escape_logfmt_value(msg),
    );
    for (k, v) in attrs {
        line.push(' ');
        line.push_str(&format_logfmt_attr(k, v));
    }
    line
}

/// Emits a structured `logfmt` line to `stdout` (`Trace`/`Debug`/`Info`) or `stderr` (`Warn`/`Error`/`Fatal`).
pub fn log_event(
    level: LogLevel,
    code: &str,
    trace: &str,
    src: &str,
    msg: &str,
    attrs: &[(&str, &str)],
) {
    let line = format_logfmt_line(level, code, trace, src, msg, attrs);
    match level {
        LogLevel::Warn | LogLevel::Error | LogLevel::Fatal => eprintln!("{line}"),
        LogLevel::Trace | LogLevel::Debug | LogLevel::Info => println!("{line}"),
    }
}

/// Logs an `INFO` event with `trace=none`.
pub fn info(code: &str, src: &str, msg: &str, attrs: &[(&str, &str)]) {
    log_event(LogLevel::Info, code, "none", src, msg, attrs);
}

/// Logs a `WARN` event with `trace=none`.
pub fn warn(code: &str, src: &str, msg: &str, attrs: &[(&str, &str)]) {
    log_event(LogLevel::Warn, code, "none", src, msg, attrs);
}

/// Logs an `ERROR` event with `trace=none`.
pub fn error(code: &str, src: &str, msg: &str, attrs: &[(&str, &str)]) {
    log_event(LogLevel::Error, code, "none", src, msg, attrs);
}

/// Logs a `DEBUG` event with `trace=none`.
pub fn debug(code: &str, src: &str, msg: &str, attrs: &[(&str, &str)]) {
    log_event(LogLevel::Debug, code, "none", src, msg, attrs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logfmt_orders_fields_and_escapes_cwe_117() {
        let line = format_logfmt_line(
            LogLevel::Warn,
            "USER_OFFBOARD_FAIL",
            "req-42",
            "node.offboard",
            "Failed to purge user",
            &[("user", "alice\nlvl=INFO fake=true"), ("port", "443")],
        );
        assert!(line.starts_with("ts="));
        assert!(line.contains(" lvl=WARN code=USER_OFFBOARD_FAIL trace=req-42 src=node.offboard msg=\"Failed to purge user\""));
        assert!(line.contains("user=\"alice\\nlvl=INFO fake=true\""));
        assert!(line.contains(" port=443"));
        assert!(!line.contains('\n'));
    }
}
