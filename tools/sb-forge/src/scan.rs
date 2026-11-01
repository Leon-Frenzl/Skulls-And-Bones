//! Secret-Scanner — erkennt potenzielle Secrets in Dateien
use colored::*;
use regex::Regex;

struct SecretPattern {
    name: &'static str,
    pattern: &'static str,
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        name: "PostgreSQL Connection String",
        pattern: r"postgres://[^:]+:[^@]+@",
    },
    SecretPattern {
        name: "Stripe Secret Key",
        pattern: r"sk_(live|test)_[a-zA-Z0-9]{20,}",
    },
    SecretPattern {
        name: "GitHub Personal Access Token",
        pattern: r"(ghp_|github_pat_)[a-zA-Z0-9]{20,}",
    },
    SecretPattern {
        name: "AWS Access Key",
        pattern: r"AKIA[A-Z0-9]{16}",
    },
    SecretPattern {
        name: "AWS Secret",
        pattern: r"aws_secret_access_key\s*=\s*[a-zA-Z0-9+/]{40}",
    },
    SecretPattern {
        name: "Private Key",
        pattern: r"-----BEGIN\s+\w+\s+PRIVATE KEY-----",
    },
    SecretPattern {
        name: "Generic Password",
        pattern: r#"(?i)(password|passwd|secret|token)\s*[=:]\s*["']?[a-zA-Z0-9!@#$%^&*]{8,}["']?"#,
    },
    SecretPattern {
        name: "OpenAI API Key",
        pattern: r"sk-[a-zA-Z0-9]{48}",
    },
    SecretPattern {
        name: "JWT Token",
        pattern: r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    },
];

struct ScanResult {
    file: String,
    line: usize,
    pattern_name: String,
    snippet: String,
}

pub fn handle_scan(args: crate::cli::ScanArgs) {
    if std::env::var("SB_FORGE_NESTED").is_err() {
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════".bright_black()
        );
        println!(
            "  {} {} {}",
            "S&B FORGE".bright_blue().bold(),
            "//".bright_black(),
            "SECRET SCANNER".bold()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════".bright_black()
        );
    } else {
        println!(
            "  {} {}",
            "S&B FORGE // SECRET SCANNER".bright_blue().bold(),
            "active".bright_black()
        );
    }

    let files_to_scan = if let Some(path) = &args.path {
        vec![path.clone()]
    } else {
        get_all_project_files()
    };

    if files_to_scan.is_empty() {
        println!("  {} Keine Dateien zu scannen", "i".bright_black());
        return;
    }

    println!(
        "  {} Analysiere {} Dateien...",
        "►".bright_cyan(),
        files_to_scan.len()
    );
    println!();

    let mut findings: Vec<ScanResult> = Vec::new();

    let compiled_patterns: Vec<(&SecretPattern, Regex)> = SECRET_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.pattern).ok().map(|r| (p, r)))
        .collect();

    for file_path in &files_to_scan {
        // Forge.toml selbst ist OK (keine Werte)
        if file_path.ends_with("Forge.toml") {
            continue;
        }
        // Scanner-eigene Pattern & Tests ignorieren
        if file_path.ends_with("scan.rs") {
            continue;
        }
        // Vault-Files nie scannen (verschlüsselt, irrelevant)
        if file_path.contains(".sb-forge") {
            continue;
        }

        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (line_num, line) in content.lines().enumerate() {
            if line.contains("forge:ignore") {
                continue;
            }
            for (pattern, regex) in &compiled_patterns {
                if regex.is_match(line) {
                    let snippet = if line.len() > 80 {
                        format!("{}...", &line[..80])
                    } else {
                        line.to_string()
                    };
                    findings.push(ScanResult {
                        file: file_path.clone(),
                        line: line_num + 1,
                        pattern_name: pattern.name.to_string(),
                        snippet: snippet.trim().to_string(),
                    });
                }
            }
        }
    }

    if findings.is_empty() {
        println!(
            "  {} Alle Dateien sauber — keine Secrets gefunden",
            "✓".bright_green()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════".bright_black()
        );
        return;
    }

    for finding in &findings {
        println!("  {} {}", "✗".bright_red(), finding.file.bright_red());
        println!(
            "    {} Zeile {}: {} erkannt",
            "→".bright_red(),
            finding.line,
            finding.pattern_name.bright_yellow()
        );
        println!(
            "    {} {}",
            "│".bright_black(),
            finding.snippet.bright_black()
        );
        println!();
    }

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} SCAN FEHLGESCHLAGEN — {} potenzielle Secrets gefunden",
        "✗".bright_red().bold(),
        findings.len()
    );
    println!(
        "  {} Verwende: sb-forge secret set <name> --env <env>",
        "i".bright_yellow()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );

    std::process::exit(1);
}

fn get_all_project_files() -> Vec<String> {
    let mut files = vec![];
    let extensions = [
        "env", "toml", "json", "yaml", "yml", "js", "ts", "py", "sh", "conf", "ini", "cfg",
    ];

    if let Ok(entries) = walkdir::WalkDir::new(".")
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_string_lossy().to_string())
        .filter(|p| {
            let normalized = p.replace('\\', "/");
            let ignored_dirs = [
                "/node_modules/",
                "/.git/",
                "/target/",
                "/.next/",
                "/out/",
                "/dist/",
                "/build/",
                "/.sb-forge/",
                "/.gemini/",
            ];
            !ignored_dirs.iter().any(|d| normalized.contains(d))
        })
        .map(|p| {
            let ext = std::path::Path::new(&p)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if extensions.contains(&ext) {
                Some(p)
            } else {
                None
            }
        })
        .filter_map(|p| p)
        .collect::<Vec<_>>()
        .into_iter()
        .map(Ok::<_, std::io::Error>)
        .collect::<Result<Vec<_>, _>>()
    {
        files = entries;
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_patterns_matching() {
        let stripe_mock = format!("sk_{}_{}", "test", "1234567890abcdefghijklmn");
        let ghp_mock = format!("ghp_{}", "mocktoken1234567890abcdefghijklmnopqrstuvwxyz");
        let aws_mock = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let test_cases = [
            (aws_mock.as_str(), "AWS Access Key"),
            (stripe_mock.as_str(), "Stripe Secret Key"),
            (ghp_mock.as_str(), "GitHub Personal Access Token"),
            ("-----BEGIN RSA PRIVATE KEY-----", "Private Key"),
            (
                "postgres://user:password123@localhost:5432/db",
                "PostgreSQL Connection String",
            ),
        ];

        for (input, expected_pattern_name) in test_cases {
            let mut matched = false;
            for pattern in SECRET_PATTERNS {
                let re = Regex::new(pattern.pattern).unwrap();
                if re.is_match(input) {
                    assert_eq!(pattern.name, expected_pattern_name);
                    matched = true;
                    break;
                }
            }
            assert!(
                matched,
                "Expected pattern {} to match input: {}",
                expected_pattern_name, input
            );
        }
    }
}
