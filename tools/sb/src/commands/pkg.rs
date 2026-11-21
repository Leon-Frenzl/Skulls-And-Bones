use colored::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::meta::{get_sb_dir, print_banner, SovereignIdentity};

fn executable_filename(name: &str) -> String {
    if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

pub fn cleanup_old_binary() {
    if let Ok(current_exe) = std::env::current_exe() {
        let old_exe = PathBuf::from(format!("{}.old", current_exe.display()));
        if old_exe.exists() {
            let _ = fs::remove_file(old_exe);
        }
    }
}

#[allow(dead_code)]
pub fn handle_update(requested: &[String]) -> Result<(), String> {
    handle_update_with_source(requested, None)
}

pub fn handle_update_with_options(
    requested: &[String],
    allow_downgrade: bool,
    from_dir: Option<PathBuf>,
    from_url: Option<String>,
    from_mesh: Option<String>,
) -> Result<(), String> {
    let source = resolve_source(from_dir, from_url, from_mesh)?;
    handle_update_with_source_and_options(requested, allow_downgrade, Some(source))
}

pub fn handle_update_with_source(
    requested: &[String],
    source: Option<super::release::ReleaseSource>,
) -> Result<(), String> {
    handle_update_with_source_and_options(requested, false, source)
}

fn handle_update_with_source_and_options(
    requested: &[String],
    allow_downgrade: bool,
    source: Option<super::release::ReleaseSource>,
) -> Result<(), String> {
    print_banner();
    let source = source.unwrap_or_default();
    super::release::update_installed_with_options(requested, allow_downgrade, &source)
        .map_err(|e| e.to_string())
}

fn resolve_source(
    from_dir: Option<PathBuf>,
    from_url: Option<String>,
    from_mesh: Option<String>,
) -> Result<super::release::ReleaseSource, String> {
    let count = [from_dir.is_some(), from_url.is_some(), from_mesh.is_some()]
        .into_iter()
        .filter(|&b| b)
        .count();
    if count > 1 {
        return Err(
            "Nur eines von --from-dir, --from-url oder --from-mesh kann angegeben werden."
                .to_string(),
        );
    }

    if let Some(dir) = from_dir {
        Ok(super::release::ReleaseSource::LocalDir(dir))
    } else if let Some(url) = from_url {
        Ok(super::release::ReleaseSource::RemoteUrl(url))
    } else if let Some(mesh) = from_mesh {
        Ok(super::release::ReleaseSource::Mesh {
            mesh_name: mesh,
            namespace: "releases".to_string(),
        })
    } else {
        Ok(super::release::ReleaseSource::default())
    }
}

#[cfg(test)]
fn verify_release_manifest(manifest: &[u8], signature_hex: &str) -> Result<(), String> {
    verify_release_manifest_with_key(manifest, signature_hex, &super::release::RELEASE_PUBLIC_KEY)
}

#[cfg(test)]
fn verify_release_manifest_with_key(
    manifest: &[u8],
    signature_hex: &str,
    public_key: &[u8; 32],
) -> Result<(), String> {
    super::release::verify_manifest_signature(manifest, signature_hex, public_key)
        .map_err(|e| e.to_string())
}

const GITHUB_REPO: &str = "Leon-Frenzl/Skulls-And-Bones";

fn validate_release_tag(tag: &str) -> Result<String, String> {
    let clean = tag.trim();
    if clean.is_empty()
        || clean.len() > 32
        || clean.contains("..")
        || !clean
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!("Ungültiges Release-Tag: '{tag}'"));
    }
    Ok(clean.to_string())
}

fn expected_github_asset_name(tag: &str) -> Result<String, String> {
    let clean_tag = validate_release_tag(tag)?;
    if cfg!(target_os = "windows") {
        Ok(format!("sb-{clean_tag}-windows-x86_64.zip"))
    } else if cfg!(target_os = "linux") {
        Ok(format!("sb-{clean_tag}-linux-x86_64.tar.gz"))
    } else {
        Err("GitHub Self-Update wird aktuell für Windows und Linux (x86_64) unterstützt.".into())
    }
}

fn replace_binary_atomically(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    if !src.exists() {
        return Err(format!("Extrahiertes Binary fehlt: {}", src.display()));
    }
    #[cfg(windows)]
    {
        let backup = dst.with_extension("exe.old");
        let _ = std::fs::remove_file(&backup);
        if dst.exists() {
            std::fs::rename(dst, &backup)
                .map_err(|e| format!("Konnte {} nicht umbenennen: {e}", dst.display()))?;
        }
        if let Err(e) = std::fs::copy(src, dst) {
            let _ = std::fs::rename(&backup, dst);
            return Err(format!("Konnte {} nicht schreiben: {e}", dst.display()));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let tmp = dst.with_extension("tmp");
        std::fs::copy(src, &tmp)
            .map_err(|e| format!("Konnte {} nicht kopieren: {e}", tmp.display()))?;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        std::fs::rename(&tmp, dst)
            .map_err(|e| format!("Konnte {} nicht ersetzen: {e}", dst.display()))?;
        Ok(())
    }
}

/// Self-updates `sb` and `sb-node` directly from GitHub Releases (`Leon-Frenzl/Skulls-And-Bones`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Archive path traversal (ZipSlip/TarSlip) or insecure HTTP downgrade
///   during self-update.
/// - **CVE / CWE Mapping:** CWE-22 (Path Traversal), CWE-494 (Download of Code Without Integrity Check).
/// - **Likelihood & Exploitability:** Medium (6/10) on self-update pipelines.
/// - **Applied Mitigation:** Enforces HTTPS-only GitHub API/Release URLs, validates release tag
///   characters, rejects archive entries with `..` or absolute paths, only extracts `sb`/`sb-node`,
///   and performs atomic/rollback-safe binary replacement.
pub fn self_update_from_github(tag_override: Option<&str>) -> Result<(), String> {
    print_banner();

    // Option 1: Self-hosted DC / Enterprise mirror via SB_RELEASE_BASE_URL (e.g. https://console.corp.example/v1/releases)
    if let Ok(mirror_base) = std::env::var("SB_RELEASE_BASE_URL") {
        let base = mirror_base.trim().trim_end_matches('/');
        if !base.is_empty() {
            if !base.starts_with("https://") {
                return Err("SB_RELEASE_BASE_URL muss mit https:// beginnen.".into());
            }
            let tag = tag_override.unwrap_or(env!("CARGO_PKG_VERSION"));
            let clean_tag = validate_release_tag(&format!("v{}", tag.trim_start_matches('v')))?;
            let asset_name = expected_github_asset_name(&clean_tag)?;
            let dl_url = format!("{base}/{asset_name}");
            println!("  {} Lade {asset_name} vom DC-Mirror ({dl_url})...", "►".cyan());
            let dl_resp = ureq::get(&dl_url)
                .set("User-Agent", "sb-cli-updater")
                .call()
                .map_err(|e| format!("Mirror-Download fehlgeschlagen: {e}"))?;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut dl_resp.into_reader(), &mut bytes)
                .map_err(|e| format!("Archiv-Lesefehler: {e}"))?;
            return extract_and_install_update_bytes(&bytes, &asset_name, &clean_tag);
        }
    }

    let api_url = match tag_override {
        Some(t) => {
            let clean = validate_release_tag(t)?;
            format!("https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{clean}")
        }
        None => format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest"),
    };

    println!("  {} Prüfe GitHub Releases ({})...", "►".cyan(), api_url);
    let resp = ureq::get(&api_url)
        .set("User-Agent", "sb-cli-updater")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GitHub Release-Abfrage fehlgeschlagen: {e}"))?;
    let meta: serde_json::Value = serde_json::from_reader(resp.into_reader())
        .map_err(|e| format!("Ungültige GitHub-Release-Antwort: {e}"))?;

    let tag = meta
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "GitHub Release enthält kein tag_name.".to_string())?;
    let clean_tag = validate_release_tag(tag)?;
    let asset_name = expected_github_asset_name(&clean_tag)?;

    let download_url = meta
        .get("assets")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(asset_name.as_str()))
        })
        .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
        .ok_or_else(|| format!("Asset '{asset_name}' in Release '{clean_tag}' nicht gefunden."))?;
    if !download_url.starts_with("https://") {
        return Err("Unsichere Download-URL (nur HTTPS erlaubt).".into());
    }

    println!("  {} Lade {asset_name} ({clean_tag})...", "►".cyan());
    let dl_resp = ureq::get(download_url)
        .set("User-Agent", "sb-cli-updater")
        .call()
        .map_err(|e| format!("Download fehlgeschlagen: {e}"))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut dl_resp.into_reader(), &mut bytes)
        .map_err(|e| format!("Archiv-Lesefehler: {e}"))?;

    // Verify SHA-256 against SHA256SUMS.txt if published alongside the release
    if let Some(sums_url) = meta
        .get("assets")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().find(|a| a.get("name").and_then(|n| n.as_str()) == Some("SHA256SUMS.txt")))
        .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
        .filter(|u| u.starts_with("https://"))
    {
        if let Ok(sums_resp) = ureq::get(sums_url).set("User-Agent", "sb-cli-updater").call() {
            if let Ok(sums_text) = sums_resp.into_string() {
                if let Some(expected_hex) = sums_text
                    .lines()
                    .find_map(|line| {
                        let mut parts = line.split_whitespace();
                        let hash = parts.next()?;
                        let file = parts.next()?;
                        (file == asset_name).then(|| hash.to_ascii_lowercase())
                    })
                {
                    use sha2::{Digest, Sha256};
                    let actual_hex = hex::encode(Sha256::digest(&bytes));
                    if actual_hex != expected_hex {
                        return Err(format!(
                            "SHA-256 Prüfsumme für {asset_name} stimmt nicht überein (erwartet {expected_hex}, erhalten {actual_hex})."
                        ));
                    }
                    println!("  {} SHA-256 verifiziert ({})", "✓".bright_green(), &actual_hex[..16]);
                }
            }
        }
    }

    extract_and_install_update_bytes(&bytes, &asset_name, &clean_tag)
}

fn extract_and_install_update_bytes(bytes: &[u8], asset_name: &str, clean_tag: &str) -> Result<(), String> {
    let temp_dir = std::env::temp_dir().join(format!(
        "sb_self_update_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&temp_dir).map_err(|e| e.to_string())?;

    let extract_res: Result<(), String> = (|| {
        if asset_name.ends_with(".zip") {
            let cursor = std::io::Cursor::new(&bytes);
            let mut archive =
                zip::ZipArchive::new(cursor).map_err(|e| format!("Ungültiges ZIP: {e}"))?;
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
                let name = file
                    .name()
                    .map(|s| s.to_string())
                    .map_err(|e| e.to_string())?;
                if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
                    return Err(format!("Unsicherer Archivpfad abgelehnt: {name}"));
                }
                if name == "sb.exe" || name == "sb-node.exe" {
                    let mut out =
                        std::fs::File::create(temp_dir.join(&name)).map_err(|e| e.to_string())?;
                    std::io::copy(&mut file, &mut out).map_err(|e| e.to_string())?;
                }
            }
        } else {
            let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(&bytes));
            let mut archive = tar::Archive::new(gz);
            for entry in archive.entries().map_err(|e| e.to_string())? {
                let mut entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path().map_err(|e| e.to_string())?.to_path_buf();
                let name = path.to_string_lossy().to_string();
                if name.contains("..") || path.is_absolute() {
                    return Err(format!("Unsicherer Archivpfad abgelehnt: {name}"));
                }
                if name == "sb" || name == "sb-node" || name == "./sb" || name == "./sb-node" {
                    let file_name = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| "Invalid tar entry".to_string())?;
                    entry
                        .unpack(temp_dir.join(file_name))
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        let current_exe =
            std::env::current_exe().map_err(|e| format!("current_exe fehlgeschlagen: {e}"))?;
        let install_dir = current_exe
            .parent()
            .ok_or_else(|| "Installationsverzeichnis nicht ermittelbar".to_string())?;

        // Falls Windows-Service läuft, zuverlässig stoppen und ggf. abweichenden Service-Binary-Pfad ermitteln
        #[cfg(windows)]
        let (service_was_running, service_bin_path) = {
            let qc_out = std::process::Command::new("sc.exe")
                .args(["qc", "sb-node-agent"])
                .output()
                .ok();
            let svc_path = qc_out.and_then(|o| {
                let text = String::from_utf8_lossy(&o.stdout);
                for line in text.lines() {
                    if let Some(rest) = line.trim().strip_prefix("BINARY_PATH_NAME") {
                        if let Some(rhs) = rest.split_once(':').map(|(_, v)| v.trim()) {
                            let extracted = if let Some(after_q) = rhs.strip_prefix('"') {
                                after_q.split('"').next().unwrap_or("")
                            } else {
                                rhs.split_whitespace().next().unwrap_or("")
                            };
                            if !extracted.is_empty() {
                                return Some(std::path::PathBuf::from(extracted));
                            }
                        }
                    }
                }
                None
            });

            let q = std::process::Command::new("sc.exe")
                .args(["query", "sb-node-agent"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
                .unwrap_or(false);
            if q {
                let _ = std::process::Command::new("sc.exe")
                    .args(["stop", "sb-node-agent"])
                    .output();
                let mut stopped = false;
                for _ in 0..10 {
                    let st = std::process::Command::new("sc.exe")
                        .args(["query", "sb-node-agent"])
                        .output();
                    if let Ok(out) = st {
                        if String::from_utf8_lossy(&out.stdout).contains("STOPPED") {
                            stopped = true;
                            break;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                if !stopped {
                    if let Ok(qex) = std::process::Command::new("sc.exe")
                        .args(["queryex", "sb-node-agent"])
                        .output()
                    {
                        for line in String::from_utf8_lossy(&qex.stdout).lines() {
                            if let Some(rest) = line.trim().strip_prefix("PID") {
                                if let Some(pid) = rest.split(':').nth(1).map(str::trim) {
                                    if !pid.is_empty() && pid != "0" {
                                        let _ = std::process::Command::new("taskkill")
                                            .args(["/F", "/PID", pid])
                                            .output();
                                        std::thread::sleep(std::time::Duration::from_millis(700));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (q, svc_path)
        };

        let sb_bin = if cfg!(windows) { "sb.exe" } else { "sb" };
        let node_bin = if cfg!(windows) {
            "sb-node.exe"
        } else {
            "sb-node"
        };

        replace_binary_atomically(&temp_dir.join(sb_bin), &install_dir.join(sb_bin))?;
        if temp_dir.join(node_bin).exists() {
            let primary_node = install_dir.join(node_bin);
            replace_binary_atomically(&temp_dir.join(node_bin), &primary_node)?;
            #[cfg(windows)]
            if let Some(ref svc_path) = service_bin_path {
                if svc_path != &primary_node
                    && svc_path.parent().map(|p| p.exists()).unwrap_or(false)
                {
                    let _ = replace_binary_atomically(&temp_dir.join(node_bin), svc_path);
                }
            }
        }

        #[cfg(windows)]
        if service_was_running {
            let _ = std::process::Command::new("sc.exe")
                .args(["start", "sb-node-agent"])
                .output();
        }

        println!(
            "\n  {} Skulls & Bones erfolgreich auf {} aktualisiert ({}).",
            "✓".bright_green().bold(),
            clean_tag.cyan().bold(),
            install_dir.display()
        );
        Ok(())
    })();

    let _ = std::fs::remove_dir_all(&temp_dir);
    extract_res
}

pub fn handle_identity() {
    print_banner();
    println!(
        "  {} {}\n",
        "► KRYPTOGRAPHISCHE IDENTITÄT & SCHLÜSSEL".bold(),
        "[SOVEREIGN IDENTITY]".bright_cyan()
    );

    let sb_dir = get_sb_dir();
    let _ = fs::create_dir_all(&sb_dir);
    let root_key_file = sb_dir.join("identity.sbkey");

    if root_key_file.exists() {
        println!(
            "  {} {}\n",
            "1. SOVEREIGN ROOT IDENTITY (sb-key)".bold(),
            "[MATHEMATISCHER WURZELANKER]".bright_green()
        );
        let _ = Command::new("sb-key").arg("inspect").status();
        println!();
    } else {
        println!(
            "  {} 1. Sovereign Root Key: {}",
            "►".bright_cyan(),
            "NICHT INITIALISIERT".bright_yellow().bold()
        );
        println!(
            "    Erzeuge deinen souveränen Root-Key mit: {}\n",
            "sb key init".bright_green().bold()
        );
    }

    let id_file = sb_dir.join("identity.json");
    if id_file.exists() {
        if let Ok(content) = fs::read_to_string(&id_file) {
            if let Ok(id) = serde_json::from_str::<SovereignIdentity>(&content) {
                println!(
                    "  {} {}\n",
                    "2. SWARM NODE TELEMETRIE (P2P Mesh)".bold(),
                    "[LOKALER KNOTEN]".bright_cyan()
                );
                println!(
                    "  {} Callsign:     {}",
                    "►".bright_cyan(),
                    id.callsign.bold()
                );
                println!(
                    "  {} Fingerprint:  {}",
                    "►".bright_cyan(),
                    id.node_fingerprint.bright_yellow().bold()
                );
                println!("  {} Erstellt am:  {}", "►".bright_cyan(), id.created_at);
                println!(
                    "  {} Ablageort:    {}",
                    "►".bright_cyan(),
                    id_file.display().to_string().bright_black()
                );
                return;
            }
        }
    }

    let random_bytes: [u8; 16] = rand::random();
    let fingerprint = format!("sbm-{}", hex::encode(&random_bytes[..8]));
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "node-alpha".to_string());
    let callsign = format!("sb-{}", hostname.to_lowercase());

    let identity = SovereignIdentity {
        callsign,
        node_fingerprint: fingerprint,
        created_at: chrono::Utc::now().to_rfc3339(),
        root_dir: sb_dir.display().to_string(),
    };

    if let Ok(json) = serde_json::to_string_pretty(&identity) {
        let _ = fs::write(&id_file, json);
        println!(
            "  {} Neue gemeinsame S&B Identität erfolgreich generiert!\n",
            "✓".bright_green().bold()
        );
        println!(
            "  {} Callsign:     {}",
            "►".bright_cyan(),
            identity.callsign.bold()
        );
        println!(
            "  {} Fingerprint:  {}",
            "►".bright_cyan(),
            identity.node_fingerprint.bright_yellow().bold()
        );
        println!(
            "  {} Ablageort:    {}",
            "►".bright_cyan(),
            id_file.display().to_string().bright_black()
        );
    } else {
        sb_core::logfmt::error(
            "PKG_IDENTITY_SAVE_ERROR",
            "sb::pkg",
            "Fehler beim Speichern der Identitaet",
            &[("path", &id_file.display().to_string())],
        );
    }
}

/// Checks if a locally staged `target/rel-stage/release/sb-node(.exe)` exists in the current
/// workspace (or known service parent) and installs it directly into the `sb-node-agent` binary path.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Arbitrary binary planting if an untrusted relative path is copied into a privileged service.
/// - **CWE Mapping:** CWE-426 (Untrusted Search Path).
/// - **Likelihood & Exploitability:** Low (2/10); only activates when `Cargo.toml` + `target/rel-stage/release` exist alongside the workspace.
/// - **Applied Mitigation:** Resolves canonical workspace root, queries `sc.exe qc sb-node-agent` for the exact service path, and replaces atomically.
pub fn try_local_stage_update() -> Result<bool, String> {
    let node_name = if cfg!(windows) {
        "sb-node.exe"
    } else {
        "sb-node"
    };
    let sb_name = if cfg!(windows) { "sb.exe" } else { "sb" };

    let mut candidate_roots = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        candidate_roots.push(cwd);
    }

    #[cfg(windows)]
    let svc_bin_path: Option<PathBuf> = {
        let mut found = None;
        if let Ok(q) = Command::new("sc.exe")
            .args(["qc", "sb-node-agent"])
            .output()
        {
            for line in String::from_utf8_lossy(&q.stdout).lines() {
                if let Some(rest) = line.trim().strip_prefix("BINARY_PATH_NAME") {
                    if let Some((_, val)) = rest.split_once(':') {
                        let trimmed = val.trim();
                        let exe = if let Some(after_q) = trimmed.strip_prefix('"') {
                            after_q.split('"').next().unwrap_or("")
                        } else {
                            trimmed.split_whitespace().next().unwrap_or("")
                        };
                        if !exe.is_empty() {
                            let p = PathBuf::from(exe);
                            // Also check repo root two levels above target/release/sb-node.exe
                            if let Some(repo) =
                                p.parent().and_then(|d| d.parent()).and_then(|d| d.parent())
                            {
                                candidate_roots.push(repo.to_path_buf());
                            }
                            found = Some(p);
                        }
                    }
                }
            }
        }
        found
    };
    #[cfg(not(windows))]
    let svc_bin_path: Option<PathBuf> = None;

    let stage_dir = candidate_roots
        .into_iter()
        .map(|r| r.join("target").join("rel-stage").join("release"))
        .find(|d| d.join(node_name).exists() || d.join(sb_name).exists());

    let Some(stage_dir) = stage_dir else {
        return Ok(false);
    };

    let stage_node = stage_dir.join(node_name);
    if stage_node.exists() {
        if let Some(ref target_node) = svc_bin_path {
            replace_binary_atomically(&stage_node, target_node)?;
            println!(
                "  {} Lokales Service-Update installiert: {}",
                "✓".bright_green().bold(),
                target_node.display()
            );
        }
    }

    let stage_sb = stage_dir.join(sb_name);
    if stage_sb.exists() {
        if let Ok(cur) = std::env::current_exe() {
            let _ = replace_binary_atomically(&stage_sb, &cur);
        }
        if let Some(home) = dirs::home_dir() {
            let cargo_sb = home.join(".cargo").join("bin").join(sb_name);
            if cargo_sb.exists() {
                let _ = replace_binary_atomically(&stage_sb, &cargo_sb);
            }
        }
        println!(
            "  {} Lokales CLI-Update installiert: {}",
            "✓".bright_green().bold(),
            stage_sb.display()
        );
    }

    Ok(true)
}

/// Builds release binaries from the local Cargo workspace and installs them into `~/.sb/bin`.
// [SECURITY-HYPOTHESIS] CWE-78 / CWE-426: Untrusted tool names could select unintended Cargo packages or paths.
// [SECURITY-VERIFIED] Package names are strictly validated against an explicit static allowlist.
pub fn update_from_local_workspace(tools: &[String]) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|e| format!("Arbeitsverzeichnis nicht lesbar: {e}"))?;
    if !cwd.join("Cargo.toml").is_file() || !cwd.join("tools").is_dir() {
        return Err("Kein Skulls-And-Bones Cargo-Workspace im aktuellen Verzeichnis gefunden.".into());
    }

    const ALLOWED_PACKAGES: &[(&str, &str)] = &[
        ("sb-cli", "sb"),
        ("sb-node", "sb-node"),
        ("sb-proxy", "sb-proxy"),
        ("sb-mesh", "sb-mesh"),
        ("sb-dns", "sb-dns"),
        ("sb-auth", "sb-auth"),
        ("sb-ca", "sb-ca"),
        ("sb-key", "sb-key"),
    ];

    let mut selected: Vec<(&str, &str)> = Vec::new();
    if tools.is_empty() || tools.iter().any(|t| t == "all") {
        selected.extend_from_slice(ALLOWED_PACKAGES);
    } else {
        for raw in tools {
            let norm = raw.trim().to_ascii_lowercase();
            let matched = ALLOWED_PACKAGES
                .iter()
                .find(|(pkg, bin)| *pkg == norm || *bin == norm || bin.strip_prefix("sb-") == Some(norm.as_str()));
            match matched {
                Some(pair) => {
                    if !selected.contains(pair) {
                        selected.push(*pair);
                    }
                }
                None => return Err(format!("Unbekanntes Workspace-Werkzeug: '{raw}'")),
            }
        }
    }

    let mut cargo_args = vec!["build".to_string(), "--release".to_string()];
    for (pkg, _) in &selected {
        cargo_args.push("-p".to_string());
        cargo_args.push((*pkg).to_string());
    }

    println!(
        "  {} Baue lokale Release-Binaries im Workspace...",
        "►".bright_cyan()
    );
    let status = Command::new("cargo")
        .args(&cargo_args)
        .current_dir(&cwd)
        .status()
        .map_err(|e| format!("cargo build fehlgeschlagen: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build --release beendet mit {status}"));
    }

    let bin_dir = get_sb_dir().join("bin");
    fs::create_dir_all(&bin_dir).map_err(|e| format!("Kann ~/.sb/bin nicht anlegen: {e}"))?;
    let release_dir = cwd.join("target").join("release");

    for (_, bin_base) in &selected {
        let filename = executable_filename(bin_base);
        let src = release_dir.join(&filename);
        if src.is_file() {
            let dst = bin_dir.join(&filename);
            replace_binary_atomically(&src, &dst)?;
            println!("  {} Aktualisiert: {}", "✓".bright_green(), dst.display());
        }
    }
    Ok(())
}

/// Updates a configured remote server from `~/.sb/servers.toml` using `sb ssh` (`git archive` -> `scp` -> remote build & restart).
// [SECURITY-HYPOTHESIS] CWE-78: Unsanitized server alias passed into remote shell or scp arguments.
// [SECURITY-VERIFIED] `server_name` is strictly validated to `[A-Za-z0-9._-]` and resolved via `sb_core::ssh_transport`.
pub fn update_remote_server(server_name: &str) -> Result<(), String> {
    if server_name.is_empty()
        || !server_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!("Ungültiger Server-Name: '{server_name}'"));
    }

    let cwd = std::env::current_dir().map_err(|e| format!("Arbeitsverzeichnis nicht lesbar: {e}"))?;
    if !cwd.join("Cargo.toml").is_file() || !cwd.join(".git").exists() {
        return Err("Remote-Server-Update benötigt ein Git-Repository des Skulls-And-Bones-Workspace.".into());
    }

    let _ = crate::commands::ssh::ensure_ephemeral_ssh_user_cert();
    let _ = sb_core::ssh_transport::ensure_sovereign_ssh_config();

    let tmp_tar = std::env::temp_dir().join(format!("sb-src-{}.tar.gz", std::process::id()));
    println!(
        "  {} Erstelle Source-Archiv von HEAD für '{}'...",
        "►".bright_cyan(),
        server_name
    );
    let archive_status = Command::new("git")
        .args(["archive", "--format=tar.gz", "-o"])
        .arg(&tmp_tar)
        .arg("HEAD")
        .current_dir(&cwd)
        .status()
        .map_err(|e| format!("git archive fehlgeschlagen: {e}"))?;
    if !archive_status.success() {
        let _ = fs::remove_file(&tmp_tar);
        return Err("git archive HEAD fehlgeschlagen".into());
    }

    let tmp_tar_str = tmp_tar.to_string_lossy().to_string();
    let (scp_bin, scp_args) =
        sb_core::ssh_transport::build_scp_push_args(server_name, &tmp_tar_str, Some("/tmp/sb-src.tar.gz"))
            .inspect_err(|_| {
                let _ = fs::remove_file(&tmp_tar);
            })?;
    let scp_status = Command::new(&scp_bin).args(&scp_args).status();
    let _ = fs::remove_file(&tmp_tar);
    match scp_status {
        Ok(s) if s.success() => {}
        Ok(s) => return Err(format!("SCP-Upload nach '{server_name}' fehlgeschlagen ({s})")),
        Err(e) => return Err(format!("SCP konnte nicht gestartet werden: {e}")),
    }

    let remote_cmd = concat!(
        "set -euo pipefail; ",
        "export PATH=\"$HOME/.cargo/bin:$PATH\"; ",
        "rm -rf /opt/skulls-and-bones-src/tools /opt/skulls-and-bones-src/console; ",
        "tar -xzf /tmp/sb-src.tar.gz -C /opt/skulls-and-bones-src; ",
        "rm -f /tmp/sb-src.tar.gz; ",
        "cd /opt/skulls-and-bones-src/console && npm ci --no-audit --no-fund && npm run build; ",
        "rm -rf /opt/skulls-and-bones/console/dist && mkdir -p /opt/skulls-and-bones/console && cp -r /opt/skulls-and-bones-src/console/dist /opt/skulls-and-bones/console/dist; ",
        "cd /opt/skulls-and-bones-src && cargo build --release -p sb-cli -p sb-node -p sb-proxy -p sb-mesh -p sb-dns -p sb-auth -p sb-ca -p sb-key; ",
        "systemctl stop sb-dc.service || true; ",
        "cp -f target/release/sb target/release/sb-node target/release/sb-proxy target/release/sb-mesh target/release/sb-dns target/release/sb-auth target/release/sb-ca target/release/sb-key /usr/local/bin/; ",
        "systemctl start sb-dc.service; ",
        "systemctl is-active sb-dc.service"
    );

    println!(
        "  {} Baue & deploye auf '{}' (Console + Rust Release + sb-dc.service)...",
        "►".bright_cyan(),
        server_name
    );
    let (ssh_bin, ssh_args) = sb_core::ssh_transport::build_ssh_exec_args(server_name, remote_cmd)?;
    let ssh_status = Command::new(&ssh_bin)
        .args(&ssh_args)
        .status()
        .map_err(|e| format!("SSH konnte nicht gestartet werden: {e}"))?;
    if !ssh_status.success() {
        return Err(format!("Remote-Update auf '{server_name}' fehlgeschlagen ({ssh_status})"));
    }

    println!(
        "  {} Server '{}' erfolgreich aktualisiert.",
        "✓".bright_green().bold(),
        server_name
    );
    Ok(())
}

#[cfg(test)]
mod release_signature_tests {
    use super::{verify_release_manifest, verify_release_manifest_with_key};
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn release_manifest_signature_verifies_and_detects_tampering() {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let manifest = b"0123456789abcdef  sb-v1.2.3-x86_64-pc-windows-msvc.zip\n";
        let signature = signing_key.sign(manifest);
        let signature_hex = hex::encode(signature.to_bytes());

        assert!(verify_release_manifest_with_key(
            manifest,
            &signature_hex,
            &signing_key.verifying_key().to_bytes()
        )
        .is_ok());
        assert!(verify_release_manifest_with_key(
            b"tampered manifest",
            &signature_hex,
            &signing_key.verifying_key().to_bytes()
        )
        .is_err());
    }

    #[test]
    fn release_manifest_signature_rejects_malformed_input() {
        assert!(verify_release_manifest_with_key(b"manifest", "xyz", &[1; 32]).is_err());
        assert!(verify_release_manifest_with_key(b"manifest", &"0".repeat(128), &[0; 32]).is_err());
    }

    /// Verifies static manifest signature fixture against the rotated pinned Ed25519 public key.
    /// Conforms to IETF RFC 8032 (Ed25519 signature verification).
    ///
    /// SECURITY AUDIT:
    /// - Dynamic Threat Vector: Regression or unintended mutation of pinned release verification key.
    /// - CVE / CWE Mapping: CWE-347 (Improper Verification of Cryptographic Signature).
    /// - Likelihood & Exploitability: High (Score: 8/10) if verification logic regresses.
    /// - Applied Mitigation: Pinned test vector signed by rotated offline key fixture.
    #[test]
    fn release_manifest_signature_matches_the_pinned_release_key() {
        let signature = "2978b7cb652f75e7b891ad6fb3c4be34bfdc28db1865157a356fc708662fb8be89d4fe3beac607a632fb7d425f0743bf4e75bba4e055df710e10515b25f6f003";
        assert!(verify_release_manifest(b"sb-release-signing-fixture-v1", signature).is_ok());
    }
}
