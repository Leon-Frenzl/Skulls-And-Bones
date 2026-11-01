use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sb_core::dto::{PeerDirectoryResult, PeerFileContentResult, PeerFileItem};
use std::path::{Path, PathBuf};

pub fn determine_file_type(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.ends_with(".docx") || lower.ends_with(".doc") {
        "word"
    } else if lower.ends_with(".xlsx") || lower.ends_with(".xls") || lower.ends_with(".csv") {
        "excel"
    } else if lower.ends_with(".rs")
        || lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".js")
        || lower.ends_with(".json")
        || lower.ends_with(".toml")
        || lower.ends_with(".py")
        || lower.ends_with(".sh")
        || lower.ends_with(".html")
        || lower.ends_with(".css")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".conf")
    {
        "code"
    } else if lower.ends_with(".pdf") {
        "pdf"
    } else if lower.ends_with(".zip")
        || lower.ends_with(".tar")
        || lower.ends_with(".gz")
        || lower.ends_with(".bz2")
        || lower.ends_with(".xz")
        || lower.ends_with(".7z")
    {
        "archive"
    } else if lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".webp")
        || lower.ends_with(".ico")
    {
        "image"
    } else {
        "text"
    }
}

pub fn map_effective_server(peer: &str) -> String {
    let clean = peer.trim_start_matches('@');
    if clean.contains("hostinger") || clean.contains("stealth") || clean.contains("anchor") {
        "hostinger-stealth".to_string()
    } else {
        clean.to_string()
    }
}

pub fn is_local_peer(peer: &str) -> bool {
    let clean = peer.trim_start_matches('@').to_lowercase();
    if clean == "local"
        || clean == "local-node"
        || clean == "localhost"
        || clean == "127.0.0.1"
        || clean == "self"
        || clean.starts_with("local")
    {
        return true;
    }
    if let Ok(user) = std::env::var("USERNAME") {
        if clean == user.to_lowercase() {
            return true;
        }
    }
    if let Ok(user) = std::env::var("USER") {
        if clean == user.to_lowercase() {
            return true;
        }
    }
    false
}

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerFsError {
    InvalidPath(String),
    NotFound(String),
    SshNotFound,
    HomeDirNotFound,
    RemoteCommandFailed { peer: String, message: String },
    ExecutionFailed(String),
    Base64Error(String),
    Io(String),
}

impl fmt::Display for PeerFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(msg) => write!(f, "Ungültiger Dateipfad: {msg}"),
            Self::NotFound(p) => write!(f, "Pfad existiert nicht: {p}"),
            Self::SshNotFound => write!(f, "Weder sb-ssh noch System-ssh gefunden"),
            Self::HomeDirNotFound => write!(f, "Home-Verzeichnis nicht gefunden"),
            Self::RemoteCommandFailed { peer, message } => {
                write!(f, "Remote-Fehler auf '{peer}': {message}")
            }
            Self::ExecutionFailed(msg) => write!(f, "Fehler beim Ausführen: {msg}"),
            Self::Base64Error(msg) => write!(f, "Base64-Fehler: {msg}"),
            Self::Io(msg) => write!(f, "E/A-Fehler: {msg}"),
        }
    }
}

impl std::error::Error for PeerFsError {}

impl From<std::io::Error> for PeerFsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<PeerFsError> for String {
    fn from(err: PeerFsError) -> Self {
        err.to_string()
    }
}

pub fn resolve_sb_ssh() -> Result<PathBuf, PeerFsError> {
    sb_core::BinaryResolver::resolve_ssh().ok_or(PeerFsError::SshNotFound)
}

/// Resolves the canonical unified SSH and OpenSSH CA paths (`~/.sb/ssh`, `~/.sb/ca/ssh/ca_key.pub`) without legacy `~/.sb-ssh` fallback.
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Peer filesystem transport falling back to stale `~/.sb-ssh` credentials or untrusted search paths.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path), CWE-295 (Improper Certificate Validation).
/// - Likelihood & Exploitability: Low (2/10).
/// - Applied Mitigation: Strictly binds `SB_SSH_HOME` to `sb_core::paths::sb_ssh_dir()` and `SB_CA_SSH_PUB` to `sb_core::paths::sb_ca_ssh_pub_path()`.
/// - Standards Compliance: Conforms to IETF RFC 4251 and IEEE 1003.1 (POSIX.1-2017).
pub fn resolve_ssh_ca_env() -> (PathBuf, PathBuf) {
    (
        sb_core::paths::sb_ssh_dir(),
        sb_core::paths::sb_ca_ssh_pub_path(),
    )
}

/// Validiert einen Pfad auf gefährliche Steuerzeichen oder Null-Bytes
pub fn validate_path(path: &str) -> Result<&str, PeerFsError> {
    if path.contains('\0') || path.contains('\r') || path.contains('\n') {
        return Err(PeerFsError::InvalidPath(
            "enthält unzulässige Steuerzeichen oder Null-Bytes".to_string(),
        ));
    }
    Ok(path)
}

/// Kapselt ein Argument in strikte POSIX-Shell Single-Quotes ('...').
/// In POSIX-Shells (sh, bash, zsh, dash) schützt das Single-Quote vor jeglicher
/// Variablenexpansion ($), Befehlssubstitution (` oder $()), Wildcards (*, ?)
/// oder Escape-Breakouts. Enthaltene Single-Quotes werden sicher als '\'' quotiert.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub struct PeerFilesystem;

impl PeerFilesystem {
    /// Listet ein lokales oder entferntes Verzeichnis auf
    pub async fn list_directory(
        peer: String,
        path: Option<String>,
    ) -> Result<PeerDirectoryResult, PeerFsError> {
        let is_local = is_local_peer(&peer);

        if is_local {
            let os_type = if cfg!(windows) {
                "windows"
            } else if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            };

            let target_path_buf = match path {
                Some(ref p) if !p.trim().is_empty() => PathBuf::from(p),
                _ => {
                    if let Some(h) = dirs::home_dir() {
                        h
                    } else {
                        PathBuf::from("/")
                    }
                }
            };

            if !target_path_buf.exists() {
                return Err(PeerFsError::NotFound(target_path_buf.display().to_string()));
            }

            let canonical_str = target_path_buf.to_string_lossy().replace('\\', "/");
            let parent_path = target_path_buf
                .parent()
                .map(|p| p.to_string_lossy().replace('\\', "/"));

            let mut items = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&target_path_buf) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let fname = entry.file_name().to_string_lossy().to_string();
                    let is_symlink = p.is_symlink();
                    let meta = entry.metadata().ok();
                    let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                    let size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                    let modified = meta
                        .and_then(|m| m.modified().ok())
                        .map(|sys_time| {
                            let dt: chrono::DateTime<chrono::Local> = sys_time.into();
                            dt.format("%Y-%m-%d %H:%M").to_string()
                        })
                        .unwrap_or_else(|| "–".into());

                    let file_type = if is_dir {
                        "folder".to_string()
                    } else {
                        determine_file_type(&fname).to_string()
                    };

                    items.push(PeerFileItem {
                        name: fname,
                        path: p.to_string_lossy().replace('\\', "/"),
                        is_dir,
                        is_symlink,
                        size_bytes: if is_dir { 4096 } else { size_bytes },
                        permissions: if is_dir {
                            "drwxr-xr-x".into()
                        } else {
                            "-rw-r--r--".into()
                        },
                        modified,
                        file_type,
                    });
                }
            }

            items.sort_by(|a, b| {
                if a.is_dir == b.is_dir {
                    a.name.to_lowercase().cmp(&b.name.to_lowercase())
                } else if a.is_dir {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            });

            let total_count = items.len();
            return Ok(PeerDirectoryResult {
                peer,
                os_type: os_type.to_string(),
                current_path: canonical_str,
                parent_path,
                items,
                total_count,
            });
        }

        // --- REMOTE NODE FILESYSTEM ---
        let (ssh_home, ca_pub) = resolve_ssh_ca_env();
        let effective_server = map_effective_server(&peer);

        let remote_target = path.unwrap_or_else(|| "/home/leonf".to_string());
        let clean_target = if remote_target.trim().is_empty() {
            "/home/leonf".to_string()
        } else {
            remote_target
        };
        validate_path(&clean_target)?;

        let cmd = format!(
            "ls -la --time-style=long-iso {}",
            shell_quote(&clean_target)
        );

        let (ssh_bin, ssh_args) =
            sb_core::ssh_transport::build_ssh_exec_args(&effective_server, &cmd)
                .map_err(PeerFsError::ExecutionFailed)?;

        let output = tokio::process::Command::new(&ssh_bin)
            .env("SB_SSH_HOME", &ssh_home)
            .env("SB_CA_SSH_PUB", &ca_pub)
            .args(&ssh_args)
            .output()
            .await
            .map_err(|e| {
                PeerFsError::ExecutionFailed(format!("OpenSSH Aufruf fehlgeschlagen: {e}"))
            })?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(PeerFsError::RemoteCommandFailed { peer, message: err });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let items = Self::parse_ls_output(&stdout, &clean_target, &peer);

        let parent_path = if clean_target == "/" {
            None
        } else {
            let trimmed = clean_target.trim_end_matches('/');
            if let Some(idx) = trimmed.rfind('/') {
                if idx == 0 {
                    Some("/".to_string())
                } else {
                    Some(trimmed[..idx].to_string())
                }
            } else {
                Some("/".to_string())
            }
        };

        let total_count = items.len();
        Ok(PeerDirectoryResult {
            peer,
            os_type: "linux".to_string(),
            current_path: clean_target,
            parent_path,
            items,
            total_count,
        })
    }

    /// Hilfsfunktion: Parst das Output von `ls -la --time-style=long-iso`
    pub fn parse_ls_output(stdout: &str, parent_path: &str, _peer: &str) -> Vec<PeerFileItem> {
        let mut items = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 || parts[0].starts_with("total") {
                continue;
            }

            let perms = parts[0];
            let is_dir = perms.starts_with('d');
            let is_symlink = perms.starts_with('l');
            let size_bytes: u64 = parts[4].parse().unwrap_or(0);
            let modified = format!("{} {}", parts[5], parts[6]);
            let name = parts[7..].join(" ");

            if name == "." || name == ".." {
                continue;
            }

            let file_type = if is_dir {
                "folder".to_string()
            } else {
                determine_file_type(&name).to_string()
            };

            let clean_parent = parent_path.trim_end_matches('/');
            let full_path = if clean_parent.is_empty() {
                format!("/{}", name)
            } else {
                format!("{}/{}", clean_parent, name)
            };

            items.push(PeerFileItem {
                name,
                path: full_path,
                is_dir,
                is_symlink,
                size_bytes,
                permissions: perms.to_string(),
                modified,
                file_type,
            });
        }

        items.sort_by(|a, b| {
            if a.is_dir == b.is_dir {
                a.name.to_lowercase().cmp(&b.name.to_lowercase())
            } else if a.is_dir {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });

        items
    }

    /// Liest den Inhalt einer Datei (Text oder Base64)
    pub async fn read_file(
        peer: String,
        path: String,
    ) -> Result<PeerFileContentResult, PeerFsError> {
        validate_path(&path)?;
        let is_local = is_local_peer(&peer);
        let fname = Path::new(&path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "unbekannt".into());

        if is_local {
            let p = PathBuf::from(&path);
            if !p.exists() {
                return Err(PeerFsError::NotFound(path));
            }

            let bytes = std::fs::read(&p).map_err(|e| PeerFsError::Io(e.to_string()))?;
            let size_bytes = bytes.len() as u64;

            let meta = p.metadata().ok();
            let modified = meta
                .and_then(|m| m.modified().ok())
                .map(|sys_time| {
                    let dt: chrono::DateTime<chrono::Local> = sys_time.into();
                    dt.format("%Y-%m-%d %H:%M").to_string()
                })
                .unwrap_or_else(|| "–".into());

            let is_binary = bytes.contains(&0u8);
            let content = if is_binary {
                BASE64.encode(&bytes)
            } else {
                String::from_utf8_lossy(&bytes).to_string()
            };

            return Ok(PeerFileContentResult {
                peer,
                path,
                name: fname,
                size_bytes,
                is_binary,
                content,
                modified,
            });
        }

        // Remote Read via OpenSSH (~/.sb/ssh/ssh_config)
        let (ssh_home, ca_pub) = resolve_ssh_ca_env();
        let effective_server = map_effective_server(&peer);

        let remote_cmd = format!("base64 -w 0 {}", shell_quote(&path));
        let (ssh_bin, ssh_args) =
            sb_core::ssh_transport::build_ssh_exec_args(&effective_server, &remote_cmd)
                .map_err(PeerFsError::ExecutionFailed)?;

        let output = tokio::process::Command::new(&ssh_bin)
            .env("SB_SSH_HOME", &ssh_home)
            .env("SB_CA_SSH_PUB", &ca_pub)
            .args(&ssh_args)
            .output()
            .await
            .map_err(|e| {
                PeerFsError::ExecutionFailed(format!("OpenSSH Aufruf fehlgeschlagen: {e}"))
            })?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(PeerFsError::RemoteCommandFailed { peer, message: err });
        }

        let b64_clean = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let bytes = BASE64
            .decode(b64_clean.as_bytes())
            .map_err(|e| PeerFsError::Base64Error(e.to_string()))?;

        let size_bytes = bytes.len() as u64;
        let is_binary = bytes.contains(&0u8);
        let content = if is_binary {
            b64_clean
        } else {
            String::from_utf8_lossy(&bytes).to_string()
        };

        Ok(PeerFileContentResult {
            peer,
            path,
            name: fname,
            size_bytes,
            is_binary,
            content,
            modified: "Remote (synchronisiert)".into(),
        })
    }

    /// Schreibt Text- oder Binärinhalt in eine Datei
    pub async fn write_file(
        peer: String,
        path: String,
        content: String,
        is_binary: Option<bool>,
    ) -> Result<bool, PeerFsError> {
        validate_path(&path)?;
        let is_local = is_local_peer(&peer);

        let bytes = if is_binary.unwrap_or(false) {
            BASE64
                .decode(content.trim().as_bytes())
                .map_err(|e| PeerFsError::Base64Error(e.to_string()))?
        } else {
            content.into_bytes()
        };

        if is_local {
            let p = PathBuf::from(&path);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| PeerFsError::Io(e.to_string()))?;
            }
            std::fs::write(&p, &bytes).map_err(|e| PeerFsError::Io(e.to_string()))?;
            return Ok(true);
        }

        // Remote Write via OpenSSH (~/.sb/ssh/ssh_config): Pipe through stdin into base64 -d > '<path>'
        let (ssh_home, ca_pub) = resolve_ssh_ca_env();
        let effective_server = map_effective_server(&peer);

        let remote_cmd = format!("base64 -d > {}", shell_quote(&path));
        let (ssh_bin, ssh_args) =
            sb_core::ssh_transport::build_ssh_exec_args(&effective_server, &remote_cmd)
                .map_err(PeerFsError::ExecutionFailed)?;

        let mut child = tokio::process::Command::new(&ssh_bin)
            .env("SB_SSH_HOME", &ssh_home)
            .env("SB_CA_SSH_PUB", &ca_pub)
            .args(&ssh_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                PeerFsError::ExecutionFailed(format!("Fehler beim Starten von OpenSSH: {e}"))
            })?;

        let b64_content = BASE64.encode(&bytes);
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(b64_content.as_bytes()).await.map_err(|e| {
                PeerFsError::ExecutionFailed(format!("Fehler beim Senden der Daten: {e}"))
            })?;
        }

        let output = child.wait_with_output().await.map_err(|e| {
            PeerFsError::ExecutionFailed(format!("Fehler beim Schreiben über sb-ssh: {e}"))
        })?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(PeerFsError::RemoteCommandFailed { peer, message: err });
        }

        Ok(true)
    }

    /// Spiegelt eine Datei in den lokalen Ghost-Cache
    pub async fn download_to_cache(peer: String, path: String) -> Result<String, PeerFsError> {
        let home = dirs::home_dir().ok_or(PeerFsError::HomeDirNotFound)?;
        let clean_peer = peer.trim_start_matches('@').replace([':', '/', '\\'], "_");
        let cache_dir = home.join(".sb-drive").join("ghost_cache").join(&clean_peer);
        std::fs::create_dir_all(&cache_dir).map_err(|e| PeerFsError::Io(e.to_string()))?;

        let fname = Path::new(&path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "ghost_file.tmp".into());

        let target_file = cache_dir.join(&fname);

        if is_local_peer(&peer) {
            let src = PathBuf::from(&path);
            if src.canonicalize().ok() == target_file.canonicalize().ok() {
                return Ok(target_file.to_string_lossy().to_string());
            }
            std::fs::copy(&src, &target_file)
                .map_err(|e| PeerFsError::Io(format!("Kopierfehler: {e}")))?;
            return Ok(target_file.to_string_lossy().to_string());
        }

        let content_res = Self::read_file(peer.clone(), path.clone()).await?;
        let bytes = if content_res.is_binary {
            BASE64
                .decode(content_res.content.trim().as_bytes())
                .map_err(|e| PeerFsError::Base64Error(e.to_string()))?
        } else {
            content_res.content.into_bytes()
        };

        std::fs::write(&target_file, bytes)
            .map_err(|e| PeerFsError::Io(format!("Cache-Schreibfehler: {e}")))?;
        Ok(target_file.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_file_type_detection() {
        assert_eq!(determine_file_type("main.rs"), "code");
        assert_eq!(determine_file_type("report.docx"), "word");
        assert_eq!(determine_file_type("data.xlsx"), "excel");
        assert_eq!(determine_file_type("archive.tar.gz"), "archive");
        assert_eq!(determine_file_type("photo.png"), "image");
        assert_eq!(determine_file_type("note.txt"), "text");
    }

    #[test]
    fn test_map_effective_server() {
        assert_eq!(
            map_effective_server("@hostinger-anchor"),
            "hostinger-stealth"
        );
        assert_eq!(
            map_effective_server("@hostinger-stealth"),
            "hostinger-stealth"
        );
        assert_eq!(map_effective_server("dev-node"), "dev-node");
    }

    #[test]
    fn test_is_local_peer() {
        assert!(is_local_peer("@local"));
        assert!(is_local_peer("localhost"));
        assert!(is_local_peer("127.0.0.1"));
        assert!(!is_local_peer("@hostinger-anchor"));
    }

    #[test]
    fn test_parse_ls_output() {
        let sample = "total 24\n\
drwxr-xr-x 2 leonf leonf 4096 2026-10-02 21:50 .config\n\
-rw-r--r-- 1 leonf leonf 3771 2026-09-30 21:11 .bashrc\n\
lrwxrwxrwx 1 leonf leonf   12 2026-10-02 20:00 link.sh -> target.sh";

        let parsed = PeerFilesystem::parse_ls_output(sample, "/home/leonf", "@hostinger-anchor");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].name, ".config");
        assert!(parsed[0].is_dir);
        assert_eq!(parsed[1].name, ".bashrc");
        assert!(!parsed[1].is_dir);
        assert_eq!(parsed[2].name, "link.sh -> target.sh");
        assert!(parsed[2].is_symlink);
    }

    #[test]
    fn test_shell_quote_and_path_validation() {
        assert_eq!(shell_quote("/var/log/app.log"), "'/var/log/app.log'");
        assert_eq!(
            shell_quote("path with spaces/file.txt"),
            "'path with spaces/file.txt'"
        );
        assert_eq!(shell_quote("file;rm -rf /;"), "'file;rm -rf /;'");
        assert_eq!(shell_quote("it's cool.txt"), "'it'\\''s cool.txt'");

        assert!(validate_path("/normal/path/file.txt").is_ok());
        assert!(validate_path("/evil/path\0null").is_err());
        assert!(validate_path("/evil/path\ninjection").is_err());
        assert!(validate_path("/evil/path\rinjection").is_err());
    }

    #[test]
    fn test_resolve_ssh_ca_env_strict_unified_paths() {
        let (ssh_home, ca_pub) = resolve_ssh_ca_env();
        assert!(!ssh_home.to_string_lossy().contains(".sb-ssh"));
        assert!(ssh_home.ends_with("ssh"));
        assert!(ca_pub.ends_with("ca_key.pub"));
        assert!(ca_pub.to_string_lossy().contains("ca"));
    }
}
