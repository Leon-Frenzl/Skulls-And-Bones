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
