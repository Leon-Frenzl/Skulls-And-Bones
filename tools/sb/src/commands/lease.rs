use colored::*;
use std::io::Write;
use std::process::Command;

pub fn is_lease_active() -> bool {
    sb_key::get_lease_status().is_some()
}

pub fn ensure_lease_active() -> bool {
    if is_lease_active() {
        return true;
    }

    let root_key = sb_key::default_identity_path();
    if root_key.exists() {
        eprintln!(
            "{}",
            "══════════════════════════════════════════════════════════════════".bright_black()
        );
        eprintln!(
            "  {} {} {}",
            "S&B SUITE".bright_blue().bold(),
            "//".bright_black(),
            "EPHEMERAL LEASE REQUIRED".bright_yellow().bold()
        );
        eprintln!(
            "{}",
            "══════════════════════════════════════════════════════════════════".bright_black()
        );
        eprintln!(
            "  {} Kein aktives Ephemeral RAM Lease vorhanden.",
            "i".bright_yellow()
        );
        eprint!("  ► Möchtest du deine Sitzung jetzt für 8h entsperren? [Y/n]: ");
        let _ = std::io::stderr().flush();

        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_ok() {
            let trimmed = answer.trim().to_lowercase();
            if trimmed.is_empty() || trimmed == "y" || trimmed == "ja" || trimmed == "yes" {
                println!("  ► Präge neues 8h Ephemeral Lease aus ~/.sb/identity.sbkey...");
                let status = Command::new("sb-key").arg("lease").status();
                if let Ok(s) = status {
                    if s.success() {
                        println!();
                        return true;
                    }
                }
            }
        }
    }

    eprintln!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    eprintln!(
        "  {} {} {}",
        "S&B SUITE".bright_blue().bold(),
        "//".bright_black(),
        "ACCESS DENIED: LEASE REQUIRED".bright_red().bold()
    );
    eprintln!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    eprintln!(
        "  {} Kein aktives Ephemeral RAM Lease gefunden!",
        "✗".bright_red().bold()
    );
    eprintln!("  i Deine Umgebungsvariablen und Secrets sind im Vault kryptographisch geschützt.");
    eprintln!(
        "  ► Schalte deine Sitzung frei mit: {}\n",
        "sb lease".bright_yellow().bold()
    );
    false
}
