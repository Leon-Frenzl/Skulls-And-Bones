use colored::Colorize;
use serde_json::Value;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl PackageManager {
    fn from_manifest_and_lockfile(project_dir: &Path, manifest: &Value) -> Self {
        if let Some(manager) = manifest
            .get("packageManager")
            .and_then(Value::as_str)
            .and_then(|value| value.split('@').next())
        {
            match manager {
                "pnpm" => return Self::Pnpm,
                "yarn" => return Self::Yarn,
                "bun" => return Self::Bun,
                _ => {}
            }
        }

        if project_dir.join("pnpm-lock.yaml").exists() {
            Self::Pnpm
        } else if project_dir.join("yarn.lock").exists() {
            Self::Yarn
        } else if project_dir.join("bun.lock").exists() || project_dir.join("bun.lockb").exists() {
            Self::Bun
        } else {
            Self::Npm
        }
    }

    fn executable(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }

    fn script_args(self, script: &str, extra_args: &[String]) -> Vec<String> {
        let mut args = match self {
            Self::Npm | Self::Pnpm => vec!["run".into(), script.into()],
            Self::Yarn => vec!["run".into(), script.into()],
            Self::Bun => vec!["run".into(), script.into()],
        };
        if !extra_args.is_empty() {
            if matches!(self, Self::Npm | Self::Pnpm) {
                args.push("--".into());
            }
            args.extend(extra_args.iter().cloned());
        }
        args
    }
}

fn package_scripts(manifest: &Value) -> Result<&serde_json::Map<String, Value>, String> {
    manifest
        .get("scripts")
        .and_then(Value::as_object)
        .ok_or_else(|| "package.json enthält keine scripts-Sektion.".to_string())
}

fn command_args(manager: PackageManager, args: &[String]) -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        let command = format!("{} {}", manager.executable(), args.join(" "));
        (
            "cmd".into(),
            vec!["/d".into(), "/s".into(), "/c".into(), command],
        )
    }
    #[cfg(not(windows))]
    {
        (manager.executable().to_string(), args.to_vec())
    }
}

async fn run_script(
    project_dir: &Path,
    manager: PackageManager,
    script: &str,
    extra_args: &[String],
) -> Result<(), String> {
    let args = manager.script_args(script, extra_args);
    let (program, args) = command_args(manager, &args);
    println!("  {} {} run {}", "▶".cyan(), manager.executable(), script);
    let status = Command::new(program)
        .args(args)
        .current_dir(project_dir)
        .status()
        .await
        .map_err(|error| {
            format!("Build-Skript '{script}' konnte nicht gestartet werden: {error}")
        })?;
    if !status.success() {
        return Err(format!(
            "Build-Skript '{script}' wurde mit Status {status} beendet."
        ));
    }
    Ok(())
}

async fn start_web_server(
    project_dir: &Path,
    manager: PackageManager,
    script: &str,
    port: u16,
    is_preview: bool,
) -> Result<Child, String> {
    let extra_args = if is_preview {
        vec![
            "--host".into(),
            "127.0.0.1".into(),
            "--port".into(),
            port.to_string(),
            "--strictPort".into(),
        ]
    } else {
        Vec::new()
    };
    let args = manager.script_args(script, &extra_args);
    let (program, args) = command_args(manager, &args);

    println!(
        "  {} Starte Produktionsserver auf 127.0.0.1:{port} ({script})",
        "▶".cyan()
    );
    Command::new(program)
        .args(args)
        .current_dir(project_dir)
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1")
        .env("HOSTNAME", "127.0.0.1")
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("Produktionsserver konnte nicht gestartet werden: {error}"))
}

async fn wait_for_http(child: &mut Child, port: u16) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let address = format!("127.0.0.1:{port}");
    loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            format!("Produktionsserver-Status konnte nicht gelesen werden: {error}")
        })? {
            return Err(format!(
                "Produktionsserver wurde vor dem HTTP-Healthcheck beendet (Status {status})."
            ));
        }

        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(&address)).await
        {
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .await
                .map_err(|error| {
                    format!("HTTP-Healthcheck konnte Anfrage nicht senden: {error}")
                })?;
            let mut response = [0u8; 128];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response))
                .await
                .map_err(|_| "HTTP-Healthcheck hat nicht rechtzeitig geantwortet.".to_string())?
                .map_err(|error| format!("HTTP-Healthcheck konnte Antwort nicht lesen: {error}"))?;
            let status_line = String::from_utf8_lossy(&response[..read]);
            if status_line.starts_with("HTTP/1.1 2")
                || status_line.starts_with("HTTP/1.1 3")
                || status_line.starts_with("HTTP/1.0 2")
                || status_line.starts_with("HTTP/1.0 3")
            {
                return Ok(());
            }
            return Err(format!(
                "Produktionsserver antwortet mit unerwartetem Status: {}",
                status_line
                    .lines()
                    .next()
                    .unwrap_or("keine HTTP-Statuszeile")
            ));
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "Produktionsserver wurde innerhalb von 45 Sekunden nicht unter http://{address} erreichbar."
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn inspect_gateway_response(
    status: u16,
    body: &str,
    domain: &str,
    gateway_node: &str,
) -> Result<(), String> {
    if status == 404 && body.contains("404 - Kein Escape Space konfiguriert") {
        return Err(format!(
            "Auf dem erreichbaren S&B-Gateway fehlt die Tunnel-Route. Lege sie dort zuerst an: `sb proxy tunnel-route add {domain} --node {gateway_node}`."
        ));
    }
    Ok(())
}

fn check_gateway_https(domain: &str, gateway_node: &str) -> Result<u16, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    let response = match agent.get(&format!("https://{domain}/")).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => {
            return Err(format!(
                "Gateway-Vorprüfung für https://{domain} fehlgeschlagen: {error}. Prüfe öffentlichen DNS-Eintrag, Erreichbarkeit auf Port 443 und ein gültiges TLS-Zertifikat."
            ));
        }
    };

    let status = response.status();
    let mut body = Vec::new();
    response
        .into_reader()
        .take(16 * 1024)
        .read_to_end(&mut body)
        .map_err(|error| format!("Gateway-Antwort konnte nicht gelesen werden: {error}"))?;
    let body = String::from_utf8_lossy(&body);
    inspect_gateway_response(status, &body, domain, gateway_node)?;
    Ok(status)
}

async fn preflight_gateway(domain: &str, gateway_node: &str) -> Result<(), String> {
    let domain = domain.to_string();
    let gateway_node = gateway_node.to_string();
    let status = tokio::task::spawn_blocking(move || check_gateway_https(&domain, &gateway_node))
        .await
        .map_err(|error| format!("Gateway-Vorprüfung konnte nicht ausgeführt werden: {error}"))??;
    println!(
        "  {} Öffentlicher HTTPS-Endpunkt erreichbar (HTTP {status}); eine bestehende Route wird vorausgesetzt.",
        "✓".green().bold()
    );
    Ok(())
}

pub async fn publish(
    domain: &str,
    project_dir: &Path,
    port: u16,
    gateway_node: &str,
) -> Result<(), String> {
    sb_proxy::escape::validate_domain(domain)?;
    if !(1024..=65535).contains(&port) {
        return Err("Der Produktionsport muss zwischen 1024 und 65535 liegen.".into());
    }

    let project_dir = project_dir
        .canonicalize()
        .map_err(|error| format!("Projektverzeichnis konnte nicht geöffnet werden: {error}"))?;
    let package_path = project_dir.join("package.json");
    let manifest_text = std::fs::read_to_string(&package_path).map_err(|error| {
        format!(
            "{} fehlt oder kann nicht gelesen werden. `sb web publish` unterstützt derzeit JavaScript-Webprojekte mit package.json: {error}",
            package_path.display()
        )
    })?;
    let manifest: Value = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("package.json ist ungültig: {error}"))?;
    let scripts = package_scripts(&manifest)?;
    if scripts.get("build").and_then(Value::as_str).is_none() {
        return Err("package.json benötigt ein 'build'-Skript.".into());
    }

    let start_script = if scripts.get("start").and_then(Value::as_str).is_some() {
        ("start", false)
    } else if scripts.get("preview").and_then(Value::as_str).is_some() {
        ("preview", true)
    } else {
        return Err(
            "package.json benötigt ein 'start'- oder 'preview'-Skript für den Produktionsserver."
                .into(),
        );
    };
    let manager = PackageManager::from_manifest_and_lockfile(&project_dir, &manifest);

    println!(
        "\n{} Veröffentliche {} aus {}\n",
        "S&B WEB".bold().cyan(),
        domain.bold(),
        project_dir.display()
    );
    println!(
        "  {} Auf dem öffentlichen Gateway muss die Domain einmalig als Tunnel-Route angelegt sein:",
        "Voraussetzung:".yellow().bold()
    );
    println!(
        "     sb proxy tunnel-route add {} --node {}",
        domain, gateway_node
    );
    println!(
        "  {} DNS muss auf den öffentlichen sb-proxy zeigen.\n",
        "Voraussetzung:".yellow().bold()
    );

    preflight_gateway(domain, gateway_node).await?;
    run_script(&project_dir, manager, "build", &[]).await?;

    let mut web_server =
        start_web_server(&project_dir, manager, start_script.0, port, start_script.1).await?;
    if let Err(error) = wait_for_http(&mut web_server, port).await {
        let _ = web_server.kill().await;
        return Err(error);
    }

    println!(
        "  {} Produktionsserver antwortet. Verbinde Mesh-Tunnel zu {} ...",
        "✓".green().bold(),
        domain
    );
    let callsign = sb_proxy::default_callsign();
    let tunnel_result = sb_proxy::run_escape_link(domain, port, &callsign, gateway_node)
        .await
        .map_err(|error| error.to_string());

    if let Err(error) = web_server.kill().await {
        sb_core::logfmt::warn(
            "ERR_SB_WEB_KILL",
            "sb.web",
            "Failed to stop production server after tunnel exit",
            &[("error", &error.to_string())],
        );
    }
    let _ = web_server.wait().await;
    tunnel_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_preflight_detects_missing_s_and_b_tunnel_route() {
        let error = inspect_gateway_response(
            404,
            "<h1>404 - Kein Escape Space konfiguriert</h1>",
            "app.example.com",
            "gateway",
        )
        .unwrap_err();
        assert!(error.contains("sb proxy tunnel-route add app.example.com --node gateway"));
    }

    #[test]
    fn gateway_preflight_allows_a_reachable_route_response() {
        assert!(inspect_gateway_response(
            503,
            "Tunnel derzeit nicht verbunden",
            "app.example.com",
            "gateway"
        )
        .is_ok());
        assert!(inspect_gateway_response(
            200,
            "Published application",
            "app.example.com",
            "gateway"
        )
        .is_ok());
    }

    #[test]
    fn package_manager_prefers_declared_manager_and_lockfile() {
        let root = std::env::temp_dir().join(format!("sb-web-manager-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("pnpm-lock.yaml"), "").unwrap();

        assert_eq!(
            PackageManager::from_manifest_and_lockfile(&root, &serde_json::json!({})),
            PackageManager::Pnpm
        );
        assert_eq!(
            PackageManager::from_manifest_and_lockfile(
                &root,
                &serde_json::json!({"packageManager": "yarn@4.0.0"})
            ),
            PackageManager::Yarn
        );

        std::fs::remove_file(root.join("pnpm-lock.yaml")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn preview_script_receives_host_and_port_arguments() {
        let args = PackageManager::Npm.script_args(
            "preview",
            &[
                "--host".into(),
                "127.0.0.1".into(),
                "--port".into(),
                "4173".into(),
            ],
        );
        assert_eq!(
            args,
            [
                "run",
                "preview",
                "--",
                "--host",
                "127.0.0.1",
                "--port",
                "4173"
            ]
        );
    }
}
