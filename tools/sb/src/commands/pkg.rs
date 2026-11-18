use colored::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::meta::{available_tools, get_sb_dir, print_banner, resolve_tools, SovereignIdentity};

pub fn handle_install(requested: &[String], force: bool) -> Result<(), String> {
    handle_install_with_source(requested, force, None)
}

pub fn handle_install_with_options(
    requested: &[String],
    force: bool,
    allow_downgrade: bool,
    from_dir: Option<PathBuf>,
    from_url: Option<String>,
    from_mesh: Option<String>,
) -> Result<(), String> {
    let source = resolve_source(from_dir, from_url, from_mesh)?;
    handle_install_with_source_and_options(requested, force, allow_downgrade, Some(source))
}

pub fn handle_install_with_source(
    requested: &[String],
    force: bool,
    source: Option<super::release::ReleaseSource>,
) -> Result<(), String> {
    handle_install_with_source_and_options(requested, force, false, source)
}

fn handle_install_with_source_and_options(
    requested: &[String],
    force: bool,
    allow_downgrade: bool,
    source: Option<super::release::ReleaseSource>,
) -> Result<(), String> {
    print_banner();
    let source = source.unwrap_or_default();
    super::release::install_requested_with_options(requested, force, allow_downgrade, &source)
        .map_err(|e| e.to_string())
}

pub fn handle_uninstall(requested: &[String]) {
    print_banner();
    let bin_dir = get_sb_dir().join("bin");
    if requested.is_empty() {
        println!(
            "  {} {}\n",
            "► MODULARE DEINSTALLATION".bold(),
            "[ÜBERSICHT]".bright_yellow()
        );
        for tool in available_tools() {
            let filename = executable_filename(tool.binary_name.as_deref().unwrap_or_default());
            if bin_dir.join(&filename).is_file() {
                println!("    ► {:<8} {}", tool.id.bold().bright_cyan(), filename);
            }
        }
        println!("    Installationspfad: {}", bin_dir.display());
        return;
    }

    let (targets, include_cli) = match resolve_tools(requested) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  {} {}", "✗".bright_red(), e);
            return;
        }
    };

    println!(
        "  {} {}\n",
        "► DEINSTALLIERE S&B-BINARIES".bold(),
        "[~/.sb/bin]".bright_yellow()
    );
    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok());
    let mut filenames: Vec<String> = targets
        .iter()
        .filter_map(|tool| tool.binary_name.as_deref())
        .map(executable_filename)
        .collect();
    if include_cli {
        filenames.push(executable_filename("sb"));
    }
    for filename in filenames {
        let path = bin_dir.join(&filename);
        if current_exe.as_ref() == path.canonicalize().ok().as_ref() {
            eprintln!(
                "  {} Überspringe die aktuell laufende sb-Binary.",
                "i".bright_yellow()
            );
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => println!("  {} Entfernt: {}", "✓".bright_green(), path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!(
                    "  {} {} war nicht in ~/.sb/bin installiert.",
                    "i".bright_black(),
                    filename
                );
            }
            Err(error) => eprintln!(
                "  {} {} kann nicht entfernt werden: {error}",
                "✗".bright_red(),
                path.display()
            ),
        }
    }
}

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
        eprintln!(
            "  {} Fehler beim Speichern der Identität.",
            "✗".bright_red()
        );
    }
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
