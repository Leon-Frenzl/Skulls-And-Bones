//! Native OS Background Service Manager for S&B Sovereign Mesh
//!
//! Provides zero-container, zero-daemon-bloat native service integration:
//! - Systemd on Linux (/etc/systemd/system/sb-mesh.service)
//! - Native Background Service / Scheduled Task on Windows
//!
//! Strict rule: NO DOCKER IMAGES. 100% native Rust execution.

use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::ServiceCommands;

pub const SERVICE_NAME: &str = "sb-mesh";

/// Dedicated unprivileged system account the daemon runs as.
pub const SERVICE_USER: &str = "sb-mesh";

// CVE-Threat: Privilege escalation / host takeover via a compromised daemon (parser RCE, gadget).
// Analysis: An unsandboxed root daemon turns any memory/logic bug into full host compromise.
// Hardening: Dedicated user, no new privileges, read-only OS, private /tmp, empty capability set,
//            syscall-arch lock and a state dir under /var/lib as the only writable path.
const SYSTEMD_HARDENING: &str = "User=sb-mesh
Group=sb-mesh
Environment=HOME=/var/lib/sb-mesh
StateDirectory=sb-mesh
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
";

/// Generates systemd unit file content
pub fn generate_systemd_unit(
    binary_path: &Path,
    anchor: bool,
    port: Option<u16>,
    mesh: Option<&str>,
) -> String {
    let mut args = vec!["daemon".to_string()];
    if anchor {
        args.push("--anchor".to_string());
    }
    if let Some(p) = port {
        args.push(format!("--port {}", p));
    }
    if let Some(m) = mesh {
        args.push(format!("--mesh {}", m));
    }

    let exec_cmd = format!("{} {}", binary_path.display(), args.join(" "));

    format!(
        r#"[Unit]
Description=Skulls & Bones Sovereign Mesh Daemon (sb-mesh)
Documentation=https://skulls-and-bones.org
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={}
Restart=always
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
{}
[Install]
WantedBy=multi-user.target
"#,
        exec_cmd, SYSTEMD_HARDENING
    )
}

/// Generates Windows PowerShell service installer script
pub fn generate_windows_ps1_script(
    binary_path: &Path,
    anchor: bool,
    port: Option<u16>,
    mesh: Option<&str>,
) -> String {
    let mut args = vec!["daemon".to_string()];
    if anchor {
        args.push("--anchor".to_string());
    }
    if let Some(p) = port {
        args.push(format!("--port {}", p));
    }
    if let Some(m) = mesh {
        args.push(format!("--mesh {}", m));
    }

    let exec_args = args.join(" ");

    format!(
        r#"# Skulls & Bones Sovereign Mesh — Windows Service Installer
# Zero-Docker Native Background Service
$BinaryPath = "{}"
$Arguments = "{}"
$TaskName = "{}"

Write-Host "Registering $TaskName Native Background Service..." -ForegroundColor Cyan

# Register as auto-starting Scheduled Task
schtasks.exe /Create /TN $TaskName /TR "`"$BinaryPath`" $Arguments" /SC ONLOGON /RL HIGHEST /F

if ($LASTEXITCODE -eq 0) {{
    Write-Host "[OK] Service '$TaskName' registered successfully!" -ForegroundColor Green
    Write-Host "Start service with: schtasks.exe /Run /TN $TaskName" -ForegroundColor Yellow
}} else {{
    Write-Host "[ERROR] Registration failed. Please run PowerShell as Administrator." -ForegroundColor Red
}}
"#,
        binary_path.display(),
        exec_args,
        SERVICE_NAME
    )
}

/// Generates Linux 1-Click Anchor Setup bash script
pub fn generate_linux_deploy_script(mesh_name: &str, port: u16) -> String {
    format!(
        r#"#!/usr/bin/env bash
# Skulls & Bones Sovereign Mesh — 1-Click Native Anchor Deploy Script
# ZERO DOCKER — Pure native Rust Systemd service
set -euo pipefail

echo "=========================================================="
echo "  SKULLS & BONES // SOVEREIGN MESH ANCHOR INSTALLER       "
echo "  Target Mesh: {}"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
    echo "Bitte als root ausführen (sudo ./deploy-anchor.sh)"
    exit 1
fi

# 1. Install binary if not in /usr/local/bin
if [ ! -f /usr/local/bin/sb-mesh ]; then
    if [ -f ./sb-mesh ]; then
        cp ./sb-mesh /usr/local/bin/sb-mesh
        chmod +x /usr/local/bin/sb-mesh
        echo "[OK] sb-mesh nach /usr/local/bin/sb-mesh installiert"
    else
        echo "[WARN] sb-mesh nicht im aktuellen Verzeichnis gefunden. Verwende bestehende Installation falls vorhanden."
    fi
fi

# 2. Unprivileged service account (no login shell, no home beyond state dir)
if ! id -u sb-mesh >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/sb-mesh --shell /usr/sbin/nologin sb-mesh
fi

# 3. Write hardened Systemd Service Unit
cat << 'EOF' > /etc/systemd/system/sb-mesh.service
[Unit]
Description=Skulls & Bones Sovereign Mesh Anchor ({})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sb-mesh daemon --anchor --port {} --mesh {}
Restart=always
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
@@HARDENING@@
[Install]
WantedBy=multi-user.target
EOF

echo "[OK] Systemd Unit /etc/systemd/system/sb-mesh.service erstellt."

# 3. Reload & Enable Systemd
systemctl daemon-reload
systemctl enable --now sb-mesh

echo "=========================================================="
echo "  [SUCCESS] Sovereign Mesh Anchor läuft als nativer Dienst!"
echo "  Status prüfen: systemctl status sb-mesh"
echo "  Live-Logs:     journalctl -u sb-mesh -f"
echo "=========================================================="
"#,
        mesh_name, mesh_name, port, mesh_name
    )
    .replace("@@HARDENING@@", SYSTEMD_HARDENING)
}

/// Dispatches service subcommands
pub fn handle_service(sub: ServiceCommands) -> Result<(), String> {
    match sub {
        ServiceCommands::Install { anchor, port, mesh } => {
            install_service(anchor, port, mesh.as_deref())
        }
        ServiceCommands::Start => start_service(),
        ServiceCommands::Stop => stop_service(),
        ServiceCommands::Status => status_service(),
        ServiceCommands::Uninstall => uninstall_service(),
    }
}

fn install_service(anchor: bool, port: Option<u16>, mesh: Option<&str>) -> Result<(), String> {
    let current_exe = std::env::current_exe().map_err(|e| {
        format!(
            "Konnte aktuellen Pfad zur ausführbaren Datei nicht ermitteln: {}",
            e
        )
    })?;

    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {} // {}",
        "S&B SOVEREIGN MESH".cyan().bold(),
        "NATIVE OS SERVICE INSTALLER".bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {:<20} {}",
        "Executable:".bold(),
        current_exe.display().to_string().yellow()
    );
    println!(
        "  {:<20} {}",
        "Anchor Hub Mode:".bold(),
        if anchor {
            "ENABLED (SBM-TEP & Rendezvous)".green().bold()
        } else {
            "Standard Node".white()
        }
    );
    println!(
        "  {:<20} {}",
        "Listen Port:".bold(),
        port.unwrap_or(58888).to_string().magenta()
    );
    if let Some(m) = mesh {
        println!("  {:<20} {}", "Mesh-Netzwerk:".bold(), m.cyan().bold());
    }
    println!(
        "  {:<20} {}",
        "Architektur:".bold(),
        "0% Container / 100% Nativer OS-Dienst".green().bold()
    );
    println!(
        "{}",
        "───────────────────────────────────────────────────────────".dimmed()
    );

    if cfg!(windows) {
        let mut tr_args = format!("\"{}\" daemon", current_exe.display());
        if anchor {
            tr_args.push_str(" --anchor");
        }
        if let Some(p) = port {
            tr_args.push_str(&format!(" --port {}", p));
        }
        if let Some(m) = mesh {
            tr_args.push_str(&format!(" --mesh {}", m));
        }

        // 1. Register Scheduled Task for auto-start on logon with highest elevation
        let sch_out = Command::new("schtasks.exe")
            .args([
                "/Create",
                "/TN",
                SERVICE_NAME,
                "/TR",
                &tr_args,
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
                "/F",
            ])
            .output();

        let sch_success = matches!(sch_out, Ok(ref o) if o.status.success());

        // Also save PowerShell installer script in data dir for manual execution
        let data_dir = dirs::home_dir()
            .map(|h| h.join(".sb-mesh"))
            .unwrap_or_else(|| PathBuf::from("."));
        let _ = fs::create_dir_all(&data_dir);
        let ps_path = data_dir.join("install-service.ps1");
        let ps_content = generate_windows_ps1_script(&current_exe, anchor, port, mesh);
        let _ = fs::write(&ps_path, ps_content);

        if sch_success {
            println!(
                "  {} Native Windows-Hintergrunddienst '{}' erfolgreich registriert!",
                "✓".bright_green().bold(),
                SERVICE_NAME
            );
            println!(
                "  {} Starte den Dienst mit: {}",
                "►".yellow(),
                "sb mesh service start".bold().yellow()
            );
        } else {
            println!(
                "  {} Automatische Registrierung benötigte Administrator-Rechte.",
                "i".yellow()
            );
            println!(
                "  {} Führe PowerShell als Admin aus oder nutze das Skript:",
                "►".yellow()
            );
            println!(
                "    powershell -ExecutionPolicy Bypass -File \"{}\"",
                ps_path.display()
            );
        }
    } else {
        // Unix / Linux Systemd
        let unit_content = generate_systemd_unit(&current_exe, anchor, port, mesh);
        let system_unit_path = Path::new("/etc/systemd/system/sb-mesh.service");

        if fs::write(system_unit_path, &unit_content).is_ok() {
            let _ = Command::new("systemctl").arg("daemon-reload").status();
            let _ = Command::new("systemctl")
                .args(["enable", "sb-mesh"])
                .status();
            println!(
                "  {} Systemd Service '/etc/systemd/system/sb-mesh.service' erfolgreich erstellt!",
                "✓".bright_green().bold()
            );
            println!(
                "  {} Starte den Dienst mit: {}",
                "►".yellow(),
                "sb mesh service start".bold().yellow()
            );
        } else {
            // Fallback to user-level systemd
            let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            let user_unit_dir = home.join(".config").join("systemd").join("user");
            let _ = fs::create_dir_all(&user_unit_dir);
            let user_unit_path = user_unit_dir.join("sb-mesh.service");

            if fs::write(&user_unit_path, &unit_content).is_ok() {
                let _ = Command::new("systemctl")
                    .args(["--user", "daemon-reload"])
                    .status();
                let _ = Command::new("systemctl")
                    .args(["--user", "enable", "sb-mesh"])
                    .status();
                println!(
                    "  {} User-Systemd Service '{}' erstellt!",
                    "✓".bright_green().bold(),
                    user_unit_path.display()
                );
                println!(
                    "  {} Starte den Dienst mit: {}",
                    "►".yellow(),
                    "systemctl --user start sb-mesh".bold().yellow()
                );
            } else {
                return Err("Konnte Systemd-Unit nicht schreiben (Root-Rechte oder ~/.config/systemd/user nötig).".to_string());
            }
        }
    }

    Ok(())
}

fn start_service() -> Result<(), String> {
    println!(
        "  Starte Sovereign Mesh Hintergrunddienst '{}'...",
        SERVICE_NAME
    );
    if cfg!(windows) {
        // Run via schtasks
        let status = Command::new("schtasks.exe")
            .args(["/Run", "/TN", SERVICE_NAME])
            .output();

        match status {
            Ok(o) if o.status.success() => {
                println!(
                    "  {} Hintergrunddienst '{}' gestartet!",
                    "✓".bright_green().bold(),
                    SERVICE_NAME
                );
            }
            _ => {
                // If scheduled task failed, spawn directly in background
                let current_exe = std::env::current_exe()
                    .map_err(|e| format!("Fehler beim Ermitteln der Binärdatei: {}", e))?;
                match Command::new(&current_exe).arg("daemon").spawn() {
                    Ok(child) => {
                        println!(
                            "  {} sb-mesh Prozess im Hintergrund gestartet (PID: {})",
                            "✓".bright_green().bold(),
                            child.id()
                        );
                    }
                    Err(e) => {
                        return Err(format!("Konnte Hintergrundprozess nicht starten: {}", e));
                    }
                }
            }
        }
    } else {
        let status = Command::new("systemctl")
            .args(["start", SERVICE_NAME])
            .status()
            .or_else(|_| {
                Command::new("systemctl")
                    .args(["--user", "start", SERVICE_NAME])
                    .status()
            });

        match status {
            Ok(s) if s.success() => {
                println!(
                    "  {} Systemd Dienst '{}' gestartet!",
                    "✓".bright_green().bold(),
                    SERVICE_NAME
                );
            }
            Ok(_) => {
                sb_core::logfmt::warn("ERR_MESH_SYSTEMCTL", "mesh.service", "Systemctl reported an error", &[]);
            }
            Err(e) => return Err(format!("Fehler beim Ausführen von systemctl: {}", e)),
        }
    }
    Ok(())
}

fn stop_service() -> Result<(), String> {
    println!(
        "  Stoppe Sovereign Mesh Hintergrunddienst '{}'...",
        SERVICE_NAME
    );
    if cfg!(windows) {
        let _ = Command::new("schtasks.exe")
            .args(["/End", "/TN", SERVICE_NAME])
            .output();

        let kill_out = Command::new("taskkill.exe")
            .args(["/F", "/IM", "sb-mesh.exe"])
            .output();

        match kill_out {
            Ok(o) if o.status.success() => {
                println!(
                    "  {} Dienst '{}' gestoppt.",
                    "✓".bright_green(),
                    SERVICE_NAME
                );
            }
            _ => {
                println!(
                    "  {} Kein laufender Prozess für '{}' gefunden oder bereits beendet.",
                    "i".yellow(),
                    SERVICE_NAME
                );
            }
        }
    } else {
        let _ = Command::new("systemctl")
            .args(["stop", SERVICE_NAME])
            .status();
        let _ = Command::new("systemctl")
            .args(["--user", "stop", SERVICE_NAME])
            .status();
        println!(
            "  {} Dienst '{}' gestoppt.",
            "✓".bright_green(),
            SERVICE_NAME
        );
    }
    Ok(())
}

fn status_service() -> Result<(), String> {
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {} // {}",
        "S&B SOVEREIGN MESH".cyan().bold(),
        "NATIVE SERVICE STATUS".bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );

    if cfg!(windows) {
        let q_task = Command::new("schtasks.exe")
            .args(["/Query", "/TN", SERVICE_NAME, "/FO", "LIST"])
            .output();

        let task_registered = matches!(q_task, Ok(ref o) if o.status.success());

        // Query active process
        let p_out = Command::new("tasklist.exe")
            .args(["/FI", "IMAGENAME eq sb-mesh.exe", "/FO", "CSV", "/NH"])
            .output();

        let mut running_pids = Vec::new();
        if let Ok(po) = p_out {
            let stdout = String::from_utf8_lossy(&po.stdout);
            for line in stdout.lines() {
                if line.contains("sb-mesh.exe") {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        let pid = parts[1].trim_matches('"');
                        let mem = if parts.len() >= 5 {
                            parts[4].trim_matches('"')
                        } else {
                            "N/A"
                        };
                        running_pids.push((pid.to_string(), mem.to_string()));
                    }
                }
            }
        }

        println!("  {:<22} {}", "Service Name:", SERVICE_NAME.cyan().bold());
        println!(
            "  {:<22} {}",
            "OS Registrierung:",
            if task_registered {
                "INSTALLIERT (Scheduled Task)".green().bold()
            } else {
                "NICHT REGISTRIERT".yellow()
            }
        );

        if !running_pids.is_empty() {
            println!(
                "  {:<22} {}",
                "Ausführungs-Status:",
                "● AKTIV / RUNNING".bright_green().bold()
            );
            for (pid, mem) in running_pids {
                println!(
                    "  {:<22} PID: {} | RAM: {}",
                    "  Prozess:".dimmed(),
                    pid.bright_white().bold(),
                    mem.cyan()
                );
            }
        } else {
            println!(
                "  {:<22} {}",
                "Ausführungs-Status:",
                "○ INAKTIV / GESTOPPT".dimmed()
            );
        }
    } else {
        let output = Command::new("systemctl")
            .args(["status", SERVICE_NAME, "--no-pager"])
            .output()
            .or_else(|_| {
                Command::new("systemctl")
                    .args(["--user", "status", SERVICE_NAME, "--no-pager"])
                    .output()
            });

        match output {
            Ok(o) => {
                let status_str = String::from_utf8_lossy(&o.stdout);
                println!("{}", status_str);
            }
            Err(e) => {
                return Err(format!("Konnte systemctl status nicht aufrufen: {}", e));
            }
        }
    }
    println!(
        "{}",
        "───────────────────────────────────────────────────────────".dimmed()
    );
    Ok(())
}

fn uninstall_service() -> Result<(), String> {
    println!(
        "  Deinstalliere Sovereign Mesh Dienst '{}'...",
        SERVICE_NAME
    );
    if cfg!(windows) {
        let _ = Command::new("schtasks.exe")
            .args(["/End", "/TN", SERVICE_NAME])
            .output();
        let _ = Command::new("taskkill.exe")
            .args(["/F", "/IM", "sb-mesh.exe"])
            .output();
        let del_out = Command::new("schtasks.exe")
            .args(["/Delete", "/TN", SERVICE_NAME, "/F"])
            .output();

        match del_out {
            Ok(o) if o.status.success() => {
                println!(
                    "  {} Dienst '{}' erfolgreich deinstalliert.",
                    "✓".bright_green().bold(),
                    SERVICE_NAME
                );
            }
            _ => {
                println!(
                    "  {} Dienst war nicht registriert oder Deinstallation fehlgeschlagen.",
                    "i".yellow()
                );
            }
        }
    } else {
        let _ = Command::new("systemctl")
            .args(["stop", SERVICE_NAME])
            .status();
        let _ = Command::new("systemctl")
            .args(["disable", SERVICE_NAME])
            .status();
        let _ = fs::remove_file("/etc/systemd/system/sb-mesh.service");
        let _ = Command::new("systemctl").arg("daemon-reload").status();

        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let user_unit = home
            .join(".config")
            .join("systemd")
            .join("user")
            .join("sb-mesh.service");
        if user_unit.exists() {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", SERVICE_NAME])
                .status();
            let _ = Command::new("systemctl")
                .args(["--user", "disable", SERVICE_NAME])
                .status();
            let _ = fs::remove_file(user_unit);
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
        }
        println!(
            "  {} Systemd Dienst '{}' erfolgreich entfernt.",
            "✓".bright_green().bold(),
            SERVICE_NAME
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_systemd_unit() {
        let bin = PathBuf::from("/usr/local/bin/sb-mesh");
        let unit = generate_systemd_unit(&bin, true, Some(58888), Some("corp-mesh"));
        assert!(unit.contains("Description=Skulls & Bones Sovereign Mesh Daemon (sb-mesh)"));
        assert!(unit.contains(
            "ExecStart=/usr/local/bin/sb-mesh daemon --anchor --port 58888 --mesh corp-mesh"
        ));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("User=sb-mesh"));
    }

    #[test]
    fn test_generate_windows_ps1_script() {
        let bin = PathBuf::from("sb-mesh.exe");
        let ps1 = generate_windows_ps1_script(&bin, true, Some(58888), Some("corp-mesh"));
        assert!(ps1.contains("schtasks.exe /Create /TN $TaskName"));
        assert!(ps1.contains("daemon --anchor --port 58888 --mesh corp-mesh"));
        assert!(ps1.contains("Zero-Docker Native Background Service"));
    }

    #[test]
    fn test_generate_linux_deploy_script() {
        let script = generate_linux_deploy_script("acme-net", 58888);
        assert!(script.contains("Target Mesh: acme-net"));
        assert!(script.contains("systemctl daemon-reload"));
        assert!(script.contains("systemctl enable --now sb-mesh"));
        assert!(script.contains("ZERO DOCKER"));
        assert!(script.contains("NoNewPrivileges=yes"));
        assert!(!script.contains("@@HARDENING@@"));
    }
}
