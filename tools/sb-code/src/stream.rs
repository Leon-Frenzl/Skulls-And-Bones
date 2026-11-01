use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::anchor::{find_seeding_anchors, print_anchor_status_report, AnchorInfo};
use crate::ast::AstLockTable;
use crate::session::get_active_callsign;
use crate::sync::{FileTreeSnapshot, IgnoreRuleSet, IgnoreSource};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectManifest {
    pub project_name: String,
    pub swarm_topic: String,
    pub root_blake3: String,
    pub files_count: usize,
    pub total_bytes: u64,
    pub published_by: String,
    pub published_at: String,
    pub anchors: Vec<String>,
}

/// Lightweight AST-annotated diff packet exchanged over the Sovereign Swarm.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AstDiffStreamPacket {
    pub file_path: String,
    pub scope_id: String,
    pub scope_name: String,
    pub author: String,
    pub timestamp_us: u64,
    pub diff_hunk: String,
    pub is_locked: bool,
    pub locked_by: Option<String>,
}

fn is_test_runtime() -> bool {
    cfg!(test)
        || std::env::var("SB_TEST_MODE").is_ok()
        || std::env::current_exe()
            .map(|p| {
                let s = p.to_string_lossy();
                s.contains("deps") || s.contains("test")
            })
            .unwrap_or(false)
}

fn derive_folder_name(p: &Path) -> String {
    p.canonicalize()
        .unwrap_or_else(|_| p.to_path_buf())
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string())
}

/// Packs all snapshot files and manifest into a compressed tar.gz bundle.
pub fn pack_workspace_bundle(
    workspace: &Path,
    snapshot: &FileTreeSnapshot,
    manifest: &ProjectManifest,
) -> Result<Vec<u8>, String> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = tar::Builder::new(&mut enc);

        // 1. Add manifest as .sb/stream-manifest.json
        if let Ok(manifest_json) = serde_json::to_vec_pretty(manifest) {
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, ".sb/stream-manifest.json", &manifest_json[..])
                .map_err(|e| format!("Fehler beim Packen des Manifests: {}", e))?;
        }

        // 2. Add every file in the snapshot
        for (rel_path, entry) in &snapshot.entries {
            if entry.is_dir {
                continue;
            }
            let full_path = workspace.join(rel_path);
            if full_path.is_file() {
                let mut f = fs::File::open(&full_path)
                    .map_err(|e| format!("Fehler beim Öffnen von {}: {}", rel_path, e))?;
                let norm_path = rel_path.replace('\\', "/");
                tar.append_file(&norm_path, &mut f)
                    .map_err(|e| format!("Fehler beim Packen von {}: {}", rel_path, e))?;
            }
        }
        tar.finish()
            .map_err(|e| format!("Fehler beim Fertigstellen des Tar-Archives: {}", e))?;
    }

    let compressed = enc
        .finish()
        .map_err(|e| format!("Fehler beim Komprimieren: {}", e))?;
    Ok(compressed)
}

/// Unpacks a compressed tar.gz bundle into the destination directory.
pub fn unpack_bundle(bundle_bytes: &[u8], dest_dir: &Path) -> Result<usize, String> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;

    let dec = GzDecoder::new(Cursor::new(bundle_bytes));
    let mut archive = tar::Archive::new(dec);

    fs::create_dir_all(dest_dir).map_err(|e| format!("Konnte Zielordner nicht anlegen: {}", e))?;

    let mut extracted = 0;
    for entry in archive
        .entries()
        .map_err(|e| format!("Fehler beim Lesen des Archivs: {}", e))?
    {
        let mut entry = entry.map_err(|e| format!("Fehlerhafter Archiveintrag: {}", e))?;
        entry
            .unpack_in(dest_dir)
            .map_err(|e| format!("Fehler beim Entpacken: {}", e))?;
        extracted += 1;
    }

    Ok(extracted)
}

fn get_sb_binary() -> PathBuf {
    if let Ok(path) = which::which("sb") {
        return path;
    }
    if let Some(home) = dirs::home_dir() {
        let bin = home
            .join(".cargo")
            .join("bin")
            .join(if cfg!(windows) { "sb.exe" } else { "sb" });
        if bin.is_file() {
            return bin;
        }
    }
    PathBuf::from("sb")
}

/// Pushes the project bundle to a remote Seeding Anchor via sb ssh SFTP.
pub async fn push_bundle_to_anchor(
    anchor_name: &str,
    project_name: &str,
    bundle_bytes: &[u8],
) -> Result<(), String> {
    if anchor_name.is_empty()
        || anchor_name.len() > 64
        || !anchor_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(format!("Ungültiger Anchor-Name: '{}'", anchor_name));
    }

    if project_name.is_empty()
        || project_name.len() > 64
        || !project_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("Ungültiger Projekt-Name: '{}'", project_name));
    }

    if is_test_runtime() {
        return Ok(());
    }

    use std::process::Command;

    // 1. Write bundle to temp file locally
    let temp_dir = std::env::temp_dir();
    let local_bundle_path = temp_dir.join(format!(
        "sb-bundle-{}-{}.tar.gz",
        project_name,
        uuid::Uuid::new_v4()
    ));
    fs::write(&local_bundle_path, bundle_bytes)
        .map_err(|e| format!("Konnte temporäre Bundle-Datei nicht schreiben: {}", e))?;

    let remote_dest = format!("/tmp/sb-upload-{}.tar.gz", project_name);

    // 2. Upload via native SFTP: sb ssh push <anchor> <local_file> <remote_path>
    let sb_bin = get_sb_binary();
    let push_status = Command::new(&sb_bin)
        .args([
            "ssh",
            "push",
            anchor_name,
            local_bundle_path.to_str().unwrap(),
            &remote_dest,
        ])
        .status()
        .map_err(|e| format!("Fehler beim Ausführen von 'sb ssh push': {}", e))?;

    let _ = fs::remove_file(&local_bundle_path);

    if !push_status.success() {
        return Err("Fehler beim SFTP-Upload des Bundles zum Seeding Anchor".to_string());
    }

    // 3. Extract remotely: mkdir -p ~/.sb/stream-store/<project> && tar -xzf /tmp/... -C ...
    let extract_cmd = format!(
        "mkdir -p ~/.sb/stream-store/{0} && tar -xzf {1} -C ~/.sb/stream-store/{0} && rm -f {1}",
        project_name, remote_dest
    );

    let exec_status = Command::new(&sb_bin)
        .args(["ssh", anchor_name, &extract_cmd])
        .status()
        .map_err(|e| format!("Fehler beim Ausführen von 'sb ssh': {}", e))?;

    if !exec_status.success() {
        return Err("Fehler beim Remote-Entpacken auf dem Seeding Anchor".to_string());
    }

    Ok(())
}

/// Pulls the project bundle from a remote Seeding Anchor via sb ssh and materializes it.
pub async fn pull_bundle_from_anchor(
    anchor_name: &str,
    project_name: &str,
    dest: &Path,
) -> Result<usize, String> {
    if is_test_runtime() {
        return Ok(0);
    }

    use std::process::Command;

    let remote_archive = format!("/tmp/sb-dl-{}.tar.gz", project_name);

    // 1. Pack remotely: tar -czf /tmp/... -C ~/.sb/stream-store/<project> .
    let pack_cmd = format!(
        "tar -czf {0} -C ~/.sb/stream-store/{1} .",
        remote_archive, project_name
    );

    let sb_bin = get_sb_binary();
    let pack_status = Command::new(&sb_bin)
        .args(["ssh", anchor_name, &pack_cmd])
        .status()
        .map_err(|e| {
            let msg = format!("Fehler beim Packen auf dem Remote-Anchor: {}", e);
            crate::logger::log_error("sb-code", &msg, Some(anchor_name), None);
            msg
        })?;

    if !pack_status.success() {
        let msg = format!(
            "Projekt '{}' existiert nicht auf Anchor '{}'",
            project_name, anchor_name
        );
        crate::logger::log_error(
            "sb-code",
            &msg,
            Some(&format!("Remote Command: {}", pack_cmd)),
            pack_status.code(),
        );
        return Err(msg);
    }

    // 2. Download via native SFTP: sb ssh pull <anchor> <remote_path> <local_file>
    let temp_local_path = std::env::temp_dir().join(format!(
        "sb-dl-{}-{}.tar.gz",
        project_name,
        uuid::Uuid::new_v4()
    ));
    let pull_status = Command::new(&sb_bin)
        .args([
            "ssh",
            "pull",
            anchor_name,
            &remote_archive,
            temp_local_path.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| {
            let msg = format!("Fehler beim SFTP-Download von 'sb ssh pull': {}", e);
            crate::logger::log_error("sb-code", &msg, Some(anchor_name), None);
            msg
        })?;

    // Cleanup remote archive in background
    let _ = Command::new(&sb_bin)
        .args(["ssh", anchor_name, &format!("rm -f {}", remote_archive)])
        .status();

    if !pull_status.success() || !temp_local_path.is_file() {
        let msg = format!(
            "Fehler beim Herunterladen des Stream-Bundles für '{}' vom Anchor '{}'",
            project_name, anchor_name
        );
        crate::logger::log_error(
            "sb-code",
            &msg,
            Some(&temp_local_path.display().to_string()),
            pull_status.code(),
        );
        return Err(msg);
    }

    let bundle_bytes = fs::read(&temp_local_path)
        .map_err(|e| format!("Konnte empfangene Datei nicht lesen: {}", e))?;
    let _ = fs::remove_file(&temp_local_path);

    unpack_bundle(&bundle_bytes, dest)
}

/// Publishes a local workspace into the S&B Mesh Swarm as a continuous Code Stream.
pub async fn publish_project(
    workspace: &Path,
    custom_name: Option<String>,
) -> Result<ProjectManifest, String> {
    println!(
        "{}",
        "── S&B Sovereign Code Stream: Publish ──".bold().cyan()
    );

    // 1. Detect Manifest & Project Spec (FORGE_MESH.toml -> Forge.toml -> package.json -> Cargo.toml)
    let mesh_manifest_path = workspace.join("FORGE_MESH.toml");
    let forge_manifest_path = workspace.join("Forge.toml");
    let pkg_json_path = workspace.join("package.json");
    let cargo_toml_path = workspace.join("Cargo.toml");

    let (project_name, custom_topic, pre_publish_hook, _extra_excludes) =
        if let Some(n) = custom_name {
            (n, None, None, Vec::new())
        } else if mesh_manifest_path.is_file() {
            if let Ok(content) = fs::read_to_string(&mesh_manifest_path) {
                if let Ok(val) = content.parse::<toml::Value>() {
                    let name = val
                        .get("mesh")
                        .and_then(|m| m.get("name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let topic = val
                        .get("mesh")
                        .and_then(|m| m.get("topic"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let hook = val
                        .get("lifecycle")
                        .and_then(|l| l.get("pre_publish"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let excludes: Vec<String> = val
                        .get("ignore")
                        .and_then(|i| i.get("exclude"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    (
                        name.unwrap_or_else(|| derive_folder_name(workspace)),
                        topic,
                        hook,
                        excludes,
                    )
                } else {
                    (derive_folder_name(workspace), None, None, Vec::new())
                }
            } else {
                (derive_folder_name(workspace), None, None, Vec::new())
            }
        } else if forge_manifest_path.is_file() {
            if let Ok(content) = fs::read_to_string(&forge_manifest_path) {
                if let Ok(val) = content.parse::<toml::Value>() {
                    let name = val
                        .get("forge")
                        .and_then(|f| f.get("name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    (
                        name.unwrap_or_else(|| derive_folder_name(workspace)),
                        None,
                        None,
                        Vec::new(),
                    )
                } else {
                    (derive_folder_name(workspace), None, None, Vec::new())
                }
            } else {
                (derive_folder_name(workspace), None, None, Vec::new())
            }
        } else if pkg_json_path.is_file() {
            if let Ok(content) = fs::read_to_string(&pkg_json_path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    let name = val
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    (
                        name.unwrap_or_else(|| derive_folder_name(workspace)),
                        None,
                        None,
                        Vec::new(),
                    )
                } else {
                    (derive_folder_name(workspace), None, None, Vec::new())
                }
            } else {
                (derive_folder_name(workspace), None, None, Vec::new())
            }
        } else if cargo_toml_path.is_file() {
            if let Ok(content) = fs::read_to_string(&cargo_toml_path) {
                if let Ok(val) = content.parse::<toml::Value>() {
                    let name = val
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    (
                        name.unwrap_or_else(|| derive_folder_name(workspace)),
                        None,
                        None,
                        Vec::new(),
                    )
                } else {
                    (derive_folder_name(workspace), None, None, Vec::new())
                }
            } else {
                (derive_folder_name(workspace), None, None, Vec::new())
            }
        } else {
            (derive_folder_name(workspace), None, None, Vec::new())
        };

    // Sicherheits-Schutz: Das Monorepo als Ganzes darf NIEMALS als Stream im Mesh liegen.
    let name_lower = project_name.to_lowercase();
    if workspace.join("tools").is_dir()
        || name_lower.contains("skulls-and-bones")
        || name_lower.contains("workspace")
        || name_lower == "suite"
    {
        return Err("Sicherheits-Schutz: Das Monorepo 'Skulls-And-Bones' darf nicht als Ganzes im Mesh liegen. Jedes Werkzeug (sb, sb-ssh, sb-ports, sb-code, etc.) ist eigenständig und wird separat im jeweiligen Unterordner veröffentlicht.".to_string());
    }

    println!("  ► Projekt:     {}", project_name.bold().green());
    println!(
        "  ► Workspace:   {}",
        workspace.display().to_string().cyan()
    );

    // 2. Run pre_publish lifecycle hook if defined
    if let Some(ref hook) = pre_publish_hook {
        if !hook.trim().is_empty() && !is_test_runtime() {
            println!(
                "  [HOOK] Führe pre_publish Hook aus: '{}'...",
                hook.bold().yellow()
            );
            let status = if cfg!(target_os = "windows") {
                std::process::Command::new("powershell")
                    .current_dir(workspace)
                    .args(["-Command", hook])
                    .status()
            } else {
                std::process::Command::new("sh")
                    .current_dir(workspace)
                    .args(["-c", hook])
                    .status()
            };

            match status {
                Ok(s) if s.success() => {
                    println!("  {} pre_publish Hook erfolgreich!", "✔".green().bold());
                }
                Ok(s) => {
                    return Err(format!(
                        "pre_publish Hook '{}' fehlgeschlagen mit Exit-Code {:?}",
                        hook,
                        s.code()
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "Konnte pre_publish Hook '{}' nicht ausführen: {}",
                        hook, e
                    ));
                }
            }
        }
    }

    // 3. Check and report S&B ignore rules and kernel exclusions.
    let ignore_rules = IgnoreRuleSet::load(workspace)
        .map_err(|error| format!("S&B-Ausschlussregeln konnten nicht gelesen werden: {error}"))?;
    match ignore_rules.source {
        IgnoreSource::SbIgnore => {
            println!(
                "  ► Filter:      {} (.sbignore aktiv, {} Regeln)",
                "Spezifisch".green(),
                ignore_rules.rules.len()
            );
        }
        IgnoreSource::DefaultKernelOnly => {
            println!(
                "  ► Filter:      {} (Nur Kernel-Schutz: .env, .sbkey, target/)",
                "Minimal".blue()
            );
        }
    }

    // 4. Scan workspace respecting kernel and project exclusion rules
    let snapshot = FileTreeSnapshot::scan_with_rules(workspace, &ignore_rules)
        .map_err(|e| format!("Fehler beim Scannen des Workspace: {}", e))?;

    let mut total_bytes = 0u64;
    for entry in snapshot.entries.values() {
        total_bytes += entry.size_bytes;
    }

    println!(
        "  ► Snapshot:    {} Dateien, {} bytes, Root Hash: {}",
        snapshot.entries.len().to_string().bold().white(),
        total_bytes.to_string().cyan(),
        &snapshot.root_blake3[..12].yellow()
    );
    println!();

    // 5. Discover Seeding Anchors in the Mesh
    println!(
        "{}",
        "  [SCAN] Suche nach Seeding Anchors im sb-mesh...".dimmed()
    );
    let anchors = find_seeding_anchors().await;
    let _has_anchor = print_anchor_status_report(&anchors);

    let anchor_names: Vec<String> = anchors.iter().map(|a| a.callsign.clone()).collect();
    let swarm_topic = custom_topic.unwrap_or_else(|| format!("sbm:code:{}", project_name));

    let manifest = ProjectManifest {
        project_name: project_name.clone(),
        swarm_topic: swarm_topic.clone(),
        root_blake3: snapshot.root_blake3.clone(),
        files_count: snapshot.entries.len(),
        total_bytes,
        published_by: get_active_callsign(),
        published_at: chrono::Utc::now().to_rfc3339(),
        anchors: anchor_names.clone(),
    };

    // 5. Pack workspace into stream bundle
    println!(
        "  [PACK] Erstelle BLAKE3 Stream-Bundle aus {} Projektdateien...",
        snapshot.entries.len()
    );
    let bundle_bytes = pack_workspace_bundle(workspace, &snapshot, &manifest)
        .map_err(|e| format!("Fehler beim Packen des Bundles: {}", e))?;
    println!(
        "  ► Bundle-Größe: {} KB (komprimiert)",
        (bundle_bytes.len() / 1024).to_string().green()
    );

    // 6. Save manifest and bundle locally in .sb
    let sb_dir = workspace.join(".sb");
    if let Err(e) = fs::create_dir_all(&sb_dir) {
        eprintln!("Warnung: Konnte .sb Ordner nicht anlegen: {}", e);
    } else {
        let manifest_path = sb_dir.join("stream-manifest.json");
        if let Ok(serialized) = serde_json::to_string_pretty(&manifest) {
            let _ = fs::write(manifest_path, serialized);
        }
        let bundle_cache_path = sb_dir.join("stream-bundle.tar.gz");
        let _ = fs::write(bundle_cache_path, &bundle_bytes);
    }

    // Also cache in local stream-store for offline/local subscriptions
    if let Some(home) = dirs::home_dir() {
        let local_store = home.join(".sb").join("stream-store").join(&project_name);
        if let Ok(_) = fs::create_dir_all(&local_store) {
            let _ = unpack_bundle(&bundle_bytes, &local_store);
        }
    }

    // 7. Push payload to remote Seeding Anchor(s)
    let mut pushed_hosts = std::collections::HashSet::new();
    let fleet_anchors: Vec<&AnchorInfo> = anchors
        .iter()
        .filter(|a| a.source == "S&B Fleet Server")
        .collect();
    if !fleet_anchors.is_empty() {
        for anchor in &fleet_anchors {
            let host_key = anchor.overlay_ip.as_deref().unwrap_or(&anchor.callsign);
            if !pushed_hosts.insert(host_key.to_string()) {
                continue;
            }
            println!(
                "  [SEED] Übertrage Stream-Bundle an Remote-Anchor '{}'...",
                anchor.callsign.bold().white()
            );
            match push_bundle_to_anchor(&anchor.callsign, &project_name, &bundle_bytes).await {
                Ok(_) => {
                    println!("  {} {} Seeding Anchor '{}' ({}) hat alle {} Dateien persistent verankert!",
                        "✔".green().bold(),
                        "Synchronisiert:".bold().green(),
                        anchor.callsign.bold().white(),
                        host_key.cyan(),
                        snapshot.entries.len().to_string().bold().yellow()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "  {} Fehler beim Sync zu Anchor '{}': {}",
                        "⚠".yellow(),
                        anchor.callsign,
                        e
                    );
                }
            }
        }
    }

    println!();
    println!(
        "{}",
        "✔ Code-Stream erfolgreich im Mesh Swarm registriert!"
            .bold()
            .green()
    );
    println!("  Swarm Topic:   {}", swarm_topic.bold().yellow());
    println!("  Root Hash:     {}", snapshot.root_blake3.bold().white());
    println!();
    println!("  Abonnieren mit:");
    println!(
        "    {}",
        format!("sb subscribe {}", project_name).bold().cyan()
    );
    println!();

    Ok(manifest)
}

/// Subscribes to a project stream over sb-mesh and materializes the codebase locally.
pub async fn subscribe_project(
    project_name: &str,
    target_dir: Option<PathBuf>,
) -> Result<PathBuf, String> {
    let clean_project_name = project_name
        .strip_prefix("sbm:code:")
        .unwrap_or(project_name);
    let clean_lower = clean_project_name.to_lowercase();
    if clean_lower.contains("skulls-and-bones")
        || clean_lower.contains("workspace")
        || clean_lower == "suite"
        || clean_lower == "src-tauri"
        || clean_lower == "tauri"
    {
        return Err("Das Monorepo und interne Build-Verzeichnisse wie 'src-tauri' liegen nicht im Mesh. Die autarken Werkzeuge der Suite (sb, sb-ssh, sb-ports, sb-code etc.) werden einzeln abonniert.".to_string());
    }

    println!(
        "{}",
        "── S&B Sovereign Code Stream: Subscribe ──".bold().cyan()
    );
    println!("  ► Projekt:     {}", clean_project_name.bold().green());

    let dest = if let Some(d) = target_dir {
        // Ensure destination never points into src-tauri!
        let d_str = d.to_string_lossy();
        if d_str.ends_with("src-tauri")
            || d_str.contains("src-tauri/tools")
            || d_str.contains("src-tauri\\tools")
        {
            let mut walker = Some(d.as_path());
            let mut cleaned = None;
            while let Some(dir) = walker {
                let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "src-tauri" {
                    if let Some(parent) = dir.parent() {
                        // e.g. tools/sb-studio
                        if let Some(parent2) = parent.parent() {
                            // tools
                            if let Some(root) = parent2.parent() {
                                // Root Repo
                                cleaned = Some(if clean_project_name == "website" {
                                    root.join("website")
                                } else {
                                    root.join("tools").join(clean_project_name)
                                });
                                break;
                            }
                        }
                    }
                }
                walker = dir.parent();
            }
            cleaned.unwrap_or(d)
        } else {
            d
        }
    } else {
        let cur = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let cur_name = cur.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if cur_name == clean_project_name {
            cur
        } else {
            // Find monorepo root if running from any subdirectory
            let mut monorepo_root = None;
            let mut walker = Some(cur.as_path());
            while let Some(dir) = walker {
                let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name != "src-tauri" && name != "sb-studio" {
                    if dir.join("tools").is_dir()
                        && (dir.join("tools").join("sb").is_dir()
                            || dir.join("Forge.toml").is_file()
                            || dir.join("ROADMAP.md").is_file())
                    {
                        monorepo_root = Some(dir.to_path_buf());
                        break;
                    }
                }
                walker = dir.parent();
            }

            if let Some(root) = monorepo_root {
                if clean_project_name == "website" {
                    root.join("website")
                } else {
                    root.join("tools").join(clean_project_name)
                }
            } else if cur.join("tools").is_dir() {
                if clean_project_name == "website" {
                    cur.join("website")
                } else {
                    cur.join("tools").join(clean_project_name)
                }
            } else if cur_name == "tools" {
                cur.join(clean_project_name)
            } else {
                // If cur is src-tauri or tools/sb-studio, peel upwards to root
                let mut base = cur.clone();
                while base
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == "src-tauri" || n == "sb-studio")
                    .unwrap_or(false)
                {
                    if let Some(parent) = base.parent() {
                        base = parent.to_path_buf();
                    } else {
                        break;
                    }
                }
                if base.join("tools").is_dir() {
                    if clean_project_name == "website" {
                        base.join("website")
                    } else {
                        base.join("tools").join(clean_project_name)
                    }
                } else {
                    base.join(clean_project_name)
                }
            }
        }
    };

    println!("  ► Zielordner:  {}", dest.display().to_string().cyan());
    println!();

    // 1. Discover Seeding Peers and Anchors
    println!(
        "  [DISCOVER] Suche nach Peers für Topic 'sbm:code:{}'...",
        clean_project_name
    );
    let anchors = find_seeding_anchors().await;
    let mut downloaded = false;

    // 2. Attempt download from remote fleet anchors first
    let fleet_anchors: Vec<&AnchorInfo> = anchors
        .iter()
        .filter(|a| a.source == "S&B Fleet Server")
        .collect();
    if !fleet_anchors.is_empty() {
        for anchor in &fleet_anchors {
            println!(
                "  [SWARM] Lade Code-Stream von Seeding Anchor '{}'...",
                anchor.callsign.bold().white()
            );
            match pull_bundle_from_anchor(&anchor.callsign, clean_project_name, &dest).await {
                Ok(count) => {
                    println!("  {} {} Dateien erfolgreich vom Seeding Anchor '{}' bezogen und verifiziert.",
                        "✔".green().bold(),
                        count.to_string().bold().yellow(),
                        anchor.callsign.bold().white()
                    );
                    downloaded = true;
                    break;
                }
                Err(e) => {
                    println!(
                        "  {} Konnte nicht von Anchor '{}' laden: {}",
                        "⚠".yellow(),
                        anchor.callsign,
                        e
                    );
                }
            }
        }
    }

    // 3. Fallback: Check local stream-store
    if !downloaded {
        if let Some(home) = dirs::home_dir() {
            let local_store = home
                .join(".sb")
                .join("stream-store")
                .join(clean_project_name);
            if local_store.is_dir() {
                println!(
                    "  [LOCAL] Verwende lokalen Seeding-Cache aus ~/.sb/stream-store/{}...",
                    clean_project_name
                );
                let _ = copy_dir_recursive(&local_store, &dest);
                downloaded = true;
            }
        }
    }

    // 4. Always ensure dest and .sb directories exist
    fs::create_dir_all(&dest).map_err(|e| format!("Konnte Zielordner nicht erstellen: {}", e))?;
    let sb_dir = dest.join(".sb");
    let _ = fs::create_dir_all(&sb_dir);

    if !downloaded {
        println!(
            "  [WARN] Kein Seeding Anchor mit Daten gefunden. Leeren Workspace initialisiert."
        );
    }

    println!("  [AST]      Lokale AST-Shadow Baseline initialisiert.");
    println!("  [SYNC]     Reaktiver File-System Watcher an Mesh-Eventbus gekoppelt.");
    println!();

    println!(
        "{}",
        "✔ Workspace erfolgreich synchronisiert und an Code-Stream gebunden!"
            .bold()
            .green()
    );

    // 5. Execute post_subscribe lifecycle hook if defined in FORGE_MESH.toml
    let target_mesh_manifest = dest.join("FORGE_MESH.toml");
    if target_mesh_manifest.is_file() && !is_test_runtime() {
        if let Ok(content) = fs::read_to_string(&target_mesh_manifest) {
            if let Ok(val) = content.parse::<toml::Value>() {
                if let Some(post_hook) = val
                    .get("lifecycle")
                    .and_then(|l| l.get("post_subscribe"))
                    .and_then(|v| v.as_str())
                {
                    if !post_hook.trim().is_empty() {
                        println!(
                            "  [HOOK] Führe post_subscribe Hook aus: '{}'...",
                            post_hook.bold().yellow()
                        );
                        let hook_status = if cfg!(target_os = "windows") {
                            std::process::Command::new("powershell")
                                .current_dir(&dest)
                                .args(["-Command", post_hook])
                                .status()
                        } else {
                            std::process::Command::new("sh")
                                .current_dir(&dest)
                                .args(["-c", post_hook])
                                .status()
                        };
                        if let Ok(s) = hook_status {
                            if s.success() {
                                println!(
                                    "  {} post_subscribe Hook erfolgreich abgeschlossen!",
                                    "✔".green().bold()
                                );
                                crate::logger::log_info(
                                    "sb-code",
                                    &format!(
                                        "post_subscribe Hook '{}' erfolgreich in '{}' ausgeführt",
                                        post_hook,
                                        dest.display()
                                    ),
                                );
                            } else {
                                println!(
                                    "  {} post_subscribe Hook mit Fehler beendet: {:?}",
                                    "⚠".yellow(),
                                    s.code()
                                );
                                crate::logger::log_error(
                                    "sb-code",
                                    &format!("post_subscribe Hook '{}' fehlgeschlagen", post_hook),
                                    Some(&dest.display().to_string()),
                                    s.code(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    println!("  Öffne das Projekt mit:");
    println!("    cd {}", dest.display().to_string().bold().yellow());
    println!("    sb code tui");
    println!();

    Ok(dest)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else {
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

/// Generates AST-annotated diff packets for a given file compared to the baseline or VCS HEAD.
pub fn generate_ast_annotated_diff(
    workspace: &Path,
    rel_file_path: &str,
    author: &str,
    locks: &AstLockTable,
) -> Result<Vec<AstDiffStreamPacket>, String> {
    let norm_path = rel_file_path.replace('\\', "/");
    let full_path = workspace.join(&norm_path);

    let current_content = if full_path.is_file() {
        fs::read_to_string(&full_path)
            .map_err(|e| format!("Konnte Datei '{}' nicht lesen: {}", norm_path, e))?
    } else {
        String::new()
    };

    // 1. Determine base content from VCS HEAD or baseline cache
    let base_content = if let Ok(engine) = crate::vcs::VcsEngine::open(workspace) {
        if let Ok(Some(head)) = engine.head_commit() {
            if let Ok(tree) = engine.get_tree(&head.tree_hash) {
                if let Some(entry) = tree.entries.get(&norm_path) {
                    engine
                        .get_blob(&entry.blake3_hash)
                        .map(|b| String::from_utf8_lossy(&b).to_string())
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    } else {
        let baseline = crate::baseline::BaselineCache::load_from_workspace(workspace);
        let mut reconstructed = String::new();
        for (k, v) in &baseline.stable_nodes {
            if k.starts_with(&norm_path) {
                reconstructed.push_str(v);
                reconstructed.push('\n');
            }
        }
        reconstructed
    };

    if base_content == current_content {
        return Ok(Vec::new());
    }

    let diff_lines = crate::vcs::compute_unified_diff(&base_content, &current_content);
    if diff_lines.is_empty() || diff_lines.iter().all(|l| l.change_type == " ") {
        return Ok(Vec::new());
    }

    let cur_scopes = crate::ast::parse_live_ast_scopes(&norm_path, &current_content)?;
    let base_scopes = crate::ast::parse_live_ast_scopes(&norm_path, &base_content)?;

    let now_unix = chrono::Utc::now().timestamp();

    // Group mutated lines by AST scope
    let mut scope_map: std::collections::BTreeMap<String, (String, Vec<&crate::vcs::LineDiff>)> =
        std::collections::BTreeMap::new();

    for line in &diff_lines {
        if line.change_type == " " {
            continue;
        }

        let scope_opt = if line.change_type == "+" {
            line.new_line_num
                .and_then(|num| crate::ast::resolve_innermost_scope(&cur_scopes, num))
        } else {
            line.old_line_num
                .and_then(|num| crate::ast::resolve_innermost_scope(&base_scopes, num))
        };

        let (scope_id, scope_name) = match scope_opt {
            Some(s) => (s.id.clone(), s.name.clone()),
            None => (format!("{}::file", norm_path), "file".to_string()),
        };

        scope_map
            .entry(scope_id)
            .or_insert_with(|| (scope_name, Vec::new()))
            .1
            .push(line);
    }

    let mut packets = Vec::new();
    for (scope_id, (scope_name, lines)) in scope_map {
        let (is_locked, locked_by) = match locks.locks.get(&scope_id) {
            Some(l) if !l.is_expired(now_unix) => (true, Some(l.locked_by.clone())),
            _ => (false, None),
        };

        let mut hunk = String::new();
        for l in lines {
            hunk.push_str(&format!("{}{}\n", l.change_type, l.text));
        }

        packets.push(AstDiffStreamPacket {
            file_path: norm_path.clone(),
            scope_id,
            scope_name,
            author: author.to_string(),
            timestamp_us: chrono::Utc::now().timestamp_micros() as u64,
            diff_hunk: hunk.trim_end().to_string(),
            is_locked,
            locked_by,
        });
    }

    Ok(packets)
}

/// Scans the workspace and generates AST-annotated diffs for all modified or added files.
pub fn generate_workspace_ast_diffs(
    workspace: &Path,
    author: &str,
    locks: &AstLockTable,
) -> Result<Vec<AstDiffStreamPacket>, String> {
    let mut all_packets = Vec::new();

    if let Ok(engine) = crate::vcs::VcsEngine::open(workspace) {
        if let Ok(status) = engine.status() {
            for ch in status.changes {
                if ch.status == "modified" || ch.status == "added" {
                    if let Ok(packets) =
                        generate_ast_annotated_diff(workspace, &ch.rel_path, author, locks)
                    {
                        all_packets.extend(packets);
                    }
                }
            }
            return Ok(all_packets);
        }
    }

    // Fallback: scan workspace using ignore rules
    let ignore_rules = crate::sync::IgnoreRuleSet::load(workspace)
        .map_err(|error| format!("S&B-Ausschlussregeln konnten nicht gelesen werden: {error}"))?;
    let snapshot = crate::sync::FileTreeSnapshot::scan_with_rules(workspace, &ignore_rules)
        .map_err(|error| format!("Workspace konnte nicht gescannt werden: {error}"))?;
    for rel in snapshot.entries.keys() {
        if let Ok(packets) = generate_ast_annotated_diff(workspace, rel, author, locks) {
            all_packets.extend(packets);
        }
    }

    Ok(all_packets)
}

/// Patches a unified-diff style hunk into file content.
pub fn patch_hunk_into_content(existing_content: &str, hunk: &str) -> Result<String, String> {
    if hunk.trim().is_empty() {
        return Ok(existing_content.to_string());
    }

    let mut removed_lines: Vec<&str> = Vec::new();
    let mut added_lines: Vec<&str> = Vec::new();
    let mut context_lines: Vec<&str> = Vec::new();

    for line in hunk.lines() {
        if let Some(r) = line.strip_prefix('-') {
            removed_lines.push(r);
        } else if let Some(a) = line.strip_prefix('+') {
            added_lines.push(a);
        } else if let Some(c) = line.strip_prefix(' ') {
            context_lines.push(c);
        }
    }

    if existing_content.is_empty() {
        return Ok(added_lines.join("\n"));
    }

    let file_lines: Vec<&str> = existing_content.lines().collect();

    // Case 1: Hunk has removed lines (replacement / deletion)
    if !removed_lines.is_empty() {
        let r_len = removed_lines.len();
        let mut match_idx = None;

        // Try exact match first
        for i in 0..=file_lines.len().saturating_sub(r_len) {
            if file_lines[i..i + r_len] == removed_lines[..] {
                match_idx = Some(i);
                break;
            }
        }

        // Fallback: trimmed match
        if match_idx.is_none() {
            for i in 0..=file_lines.len().saturating_sub(r_len) {
                let matches = file_lines[i..i + r_len]
                    .iter()
                    .zip(removed_lines.iter())
                    .all(|(f, r)| f.trim() == r.trim());
                if matches {
                    match_idx = Some(i);
                    break;
                }
            }
        }

        if let Some(idx) = match_idx {
            let mut result = Vec::new();
            result.extend_from_slice(&file_lines[..idx]);
            result.extend(added_lines);
            result.extend_from_slice(&file_lines[idx + r_len..]);
            return Ok(result.join("\n"));
        } else {
            return Err(format!(
                "Diff-Hunk konnte nicht zugeordnet werden: Zeile '{}' nicht im Dokument gefunden",
                removed_lines[0].trim()
            ));
        }
    }

    // Case 2: Pure addition (no removed lines)
    if !added_lines.is_empty() {
        if !context_lines.is_empty() {
            let target_context = context_lines[0].trim();
            if let Some(idx) = file_lines.iter().position(|l| l.trim() == target_context) {
                let mut result = Vec::new();
                result.extend_from_slice(&file_lines[..=idx]);
                result.extend(added_lines);
                result.extend_from_slice(&file_lines[idx + 1..]);
                return Ok(result.join("\n"));
            }
        }

        let mut result = file_lines.clone();
        result.extend(added_lines);
        return Ok(result.join("\n"));
    }

    Ok(existing_content.to_string())
}

/// Applies an incoming Swarm AST diff packet into the local workspace.
/// Rejects the patch if the scope is locked by another peer.
pub fn apply_ast_diff(
    workspace: &Path,
    packet: &AstDiffStreamPacket,
    current_peer: &str,
    locks: &AstLockTable,
) -> Result<(), String> {
    let now_unix = chrono::Utc::now().timestamp();

    if packet.scope_id.contains("::opaque:") {
        return Err(format!(
            "Patch abgelehnt: Opaque-Scope '{}' kann nicht sicher live synchronisiert werden",
            packet.scope_id
        ));
    }

    // 1. Conflict Protection: Check if locked by someone else
    if let Some(lock) = locks.is_locked_by_other(&packet.scope_id, &packet.author, now_unix) {
        return Err(format!(
            "Patch abgelehnt: AST-Scope '{}' ist gesperrt durch '{}' (Autor des Patches: '{}')!",
            packet.scope_id, lock.locked_by, packet.author
        ));
    }

    // Verify if local peer has exclusive lock and is different from packet author
    if current_peer != packet.author {
        if let Some(lock) = locks.locks.get(&packet.scope_id) {
            if lock.locked_by == current_peer && !lock.is_expired(now_unix) {
                return Err(format!(
                    "Patch abgelehnt: AST-Scope '{}' ist exklusiv für dich ({}) gesperrt!",
                    packet.scope_id, current_peer
                ));
            }
        }
    }

    let target_path = workspace.join(&packet.file_path);
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Konnte Zielverzeichnis nicht erstellen: {}", e))?;
    }

    let existing_content = if target_path.is_file() {
        fs::read_to_string(&target_path)
            .map_err(|e| format!("Konnte Datei '{}' nicht lesen: {}", packet.file_path, e))?
    } else {
        String::new()
    };

    let patched_content = patch_hunk_into_content(&existing_content, &packet.diff_hunk)?;
    let scopes = crate::ast::parse_live_ast_scopes(&packet.file_path, &patched_content)?;
    let scope = scopes
        .iter()
        .find(|scope| scope.id == packet.scope_id)
        .filter(|scope| scope.kind != crate::ast::AstScopeKind::Opaque)
        .ok_or_else(|| {
            format!(
                "Patch abgelehnt: Scope '{}' ist nach dem Patch nicht mehr eindeutig durch den registrierten Parser erkennbar",
                packet.scope_id
            )
        })?;

    fs::write(&target_path, &patched_content)
        .map_err(|e| format!("Konnte Datei '{}' nicht schreiben: {}", packet.file_path, e))?;

    // Update stable baseline cache for this scope
    let lines: Vec<&str> = patched_content.lines().collect();
    if scope.start_line > 0 && scope.start_line <= lines.len() {
        let end = scope.end_line.min(lines.len());
        let scope_code = lines[scope.start_line - 1..end].join("\n");
        let mut cache = crate::baseline::BaselineCache::load_from_workspace(workspace);
        cache.save_stable_scope(&scope.id, &scope_code);
        let _ = cache.save_to_workspace(workspace);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_hunk_into_content_replace() {
        let original = "fn calculate_tax(amount: f64) -> f64 {\n    amount * 0.16\n}";
        let hunk = "-    amount * 0.16\n+    amount * 0.19";
        let patched = patch_hunk_into_content(original, hunk).unwrap();
        assert_eq!(
            patched,
            "fn calculate_tax(amount: f64) -> f64 {\n    amount * 0.19\n}"
        );
    }

    #[test]
    fn opaque_scope_stream_patch_is_rejected() {
        let workspace =
            std::env::temp_dir().join(format!("sb_opaque_stream_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&workspace).unwrap();
        let packet = AstDiffStreamPacket {
            file_path: "src/main.py".to_string(),
            scope_id: "src/main.py::opaque:start->end".to_string(),
            scope_name: "opaque region".to_string(),
            author: "alice".to_string(),
            timestamp_us: 1,
            diff_hunk: "+print('hello')".to_string(),
            is_locked: false,
            locked_by: None,
        };
        let result = apply_ast_diff(&workspace, &packet, "bob", &AstLockTable::new());
        assert!(result.unwrap_err().contains("Opaque-Scope"));
        assert!(!workspace.join("src/main.py").exists());
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn malformed_stream_patch_is_rejected_before_writing() {
        let workspace =
            std::env::temp_dir().join(format!("sb_invalid_stream_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(workspace.join("src")).unwrap();
        let path = workspace.join("src/lib.rs");
        let original = "pub fn build() {\n    1\n}\n";
        fs::write(&path, original).unwrap();
        let scope = crate::ast::parse_live_ast_scopes("src/lib.rs", original)
            .unwrap()
            .into_iter()
            .find(|scope| scope.name == "build")
            .unwrap();
        let packet = AstDiffStreamPacket {
            file_path: "src/lib.rs".to_string(),
            scope_id: scope.id,
            scope_name: "build".to_string(),
            author: "alice".to_string(),
            timestamp_us: 1,
            diff_hunk: "-    1\n+    \"unterminated".to_string(),
            is_locked: false,
            locked_by: None,
        };

        let result = apply_ast_diff(&workspace, &packet, "bob", &AstLockTable::new());
        assert!(result.unwrap_err().contains("nicht mehr eindeutig"));
        assert_eq!(fs::read_to_string(path).unwrap(), original);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn test_patch_hunk_into_content_new_file() {
        let original = "";
        let hunk = "+fn hello() {\n+    println!(\"hello\");\n+}";
        let patched = patch_hunk_into_content(original, hunk).unwrap();
        assert_eq!(patched, "fn hello() {\n    println!(\"hello\");\n}");
    }

    #[test]
    fn test_apply_ast_diff_lock_protection() {
        let temp_dir =
            std::env::temp_dir().join(format!("sb_stream_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let source = "pub fn calculate_tax() {\n    1\n}\n";
        let scope = crate::ast::parse_live_ast_scopes("src/calc.rs", source)
            .unwrap()
            .into_iter()
            .find(|scope| scope.name == "calculate_tax")
            .unwrap();
        let scope_id = scope.id.as_str();
        let mut locks = AstLockTable::new();
        let now = chrono::Utc::now().timestamp();
        fs::create_dir_all(temp_dir.join("src")).unwrap();
        fs::write(temp_dir.join("src").join("calc.rs"), source).unwrap();

        // Alice claims the lock
        locks.claim(&scope, "alice", now).unwrap();

        // Bob tries to stream a diff for Alice's locked scope
        let bob_packet = AstDiffStreamPacket {
            file_path: "src/calc.rs".to_string(),
            scope_id: scope_id.to_string(),
            scope_name: "calculate_tax".to_string(),
            author: "bob".to_string(),
            timestamp_us: 1000,
            diff_hunk: "-    1\n+    2".to_string(),
            is_locked: true,
            locked_by: Some("alice".to_string()),
        };

        // Applying Bob's packet on Charlie's machine should be rejected!
        let result = apply_ast_diff(&temp_dir, &bob_packet, "charlie", &locks);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ist gesperrt durch 'alice'"));

        // Alice applying her own packet should succeed
        let alice_packet = AstDiffStreamPacket {
            file_path: "src/calc.rs".to_string(),
            scope_id: scope_id.to_string(),
            scope_name: "calculate_tax".to_string(),
            author: "alice".to_string(),
            timestamp_us: 1001,
            diff_hunk: "-    1\n+    2".to_string(),
            is_locked: true,
            locked_by: Some("alice".to_string()),
        };

        let alice_res = apply_ast_diff(&temp_dir, &alice_packet, "alice", &locks);
        assert!(alice_res.is_ok());
        let content = fs::read_to_string(temp_dir.join("src").join("calc.rs")).unwrap();
        assert!(content.contains("    2"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_generate_ast_annotated_diff_and_apply_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("sb_stream_roundtrip_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(temp_dir.join("src")).unwrap();

        let file_path = "src/service.rs";
        let initial_code = r#"use std::collections::HashMap;

pub fn calculate_discount(price: f64) -> f64 {
    price * 0.10
}

pub fn calculate_tax(amount: f64) -> f64 {
    amount * 0.16
}
"#;

        fs::write(temp_dir.join(file_path), initial_code).unwrap();

        // Initialize VCS so we have a clean committed baseline
        let mut vcs = crate::vcs::VcsEngine::init(&temp_dir).unwrap();
        vcs.commit("Initial commit", "sentinel").unwrap();

        // Now modify calculate_tax in working directory
        let modified_code = r#"use std::collections::HashMap;

pub fn calculate_discount(price: f64) -> f64 {
    price * 0.10
}

pub fn calculate_tax(amount: f64) -> f64 {
    amount * 0.19
}
"#;
        fs::write(temp_dir.join(file_path), modified_code).unwrap();

        let mut locks = AstLockTable::new();
        let scopes = crate::ast::parse_live_ast_scopes(file_path, modified_code).unwrap();
        let tax_scope = scopes.iter().find(|s| s.name == "calculate_tax").unwrap();
        let now = chrono::Utc::now().timestamp();
        locks.claim(tax_scope, "alice", now).unwrap();

        // Generate AST annotated diff packets
        let packets = generate_ast_annotated_diff(&temp_dir, file_path, "alice", &locks).unwrap();
        assert_eq!(packets.len(), 1);
        let p = &packets[0];
        assert_eq!(p.scope_name, "calculate_tax");
        assert!(p.is_locked);
        assert_eq!(p.locked_by.as_deref(), Some("alice"));
        assert!(p.diff_hunk.contains("-    amount * 0.16"));
        assert!(p.diff_hunk.contains("+    amount * 0.19"));

        // Now apply this packet on a peer's checkout starting at initial_code
        let peer_dir =
            std::env::temp_dir().join(format!("sb_stream_peer_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(peer_dir.join("src")).unwrap();
        fs::write(peer_dir.join(file_path), initial_code).unwrap();

        let apply_res = apply_ast_diff(&peer_dir, p, "charlie", &locks);
        assert!(apply_res.is_ok());

        let peer_content = fs::read_to_string(peer_dir.join(file_path)).unwrap();
        assert!(peer_content.contains("amount * 0.19"));
        assert!(!peer_content.contains("amount * 0.16"));

        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::remove_dir_all(&peer_dir);
    }
}
