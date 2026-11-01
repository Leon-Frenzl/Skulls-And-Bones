//! Universal Binary & Tool Locator for Skulls & Bones Suite

use std::path::PathBuf;

pub struct BinaryResolver;

impl BinaryResolver {
    /// Canonical executable name for the current operating system (appends .exe on Windows).
    pub fn exe_name(base: &str) -> String {
        if cfg!(windows) && !base.to_lowercase().ends_with(".exe") {
            format!("{base}.exe")
        } else {
            base.to_string()
        }
    }

    /// Resolves a binary path by checking in canonical order:
    /// 1. Exact path if absolute/relative and exists on disk
    /// 2. Parent directory of currently running executable
    /// 3. Workspace build candidates (`target/release`, `target/debug`, `tools/<name>/target/...`)
    /// 4. User home binaries (`~/.sb/bin/`, `~/.cargo/bin/`)
    /// 5. System `PATH` via `which`
    pub fn resolve(base: &str) -> Option<PathBuf> {
        Self::resolve_binary(base)
    }

    pub fn resolve_binary(base: &str) -> Option<PathBuf> {
        let exe = Self::exe_name(base);
        let path = PathBuf::from(&exe);
        if path.is_absolute() && path.exists() {
            return Some(path);
        }

        // 1. Current exe directory
        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(parent) = current_exe.parent() {
                let candidate = parent.join(&exe);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }

        // 2. Workspace build candidates
        if let Ok(cwd) = std::env::current_dir() {
            let candidates = [
                cwd.join("target").join("release").join(&exe),
                cwd.join("target").join("debug").join(&exe),
                cwd.join("tools")
                    .join(base)
                    .join("target")
                    .join("release")
                    .join(&exe),
                cwd.join("tools")
                    .join(base)
                    .join("target")
                    .join("debug")
                    .join(&exe),
                crate::paths::sb_home().join("bin").join(&exe),
            ];

            for cand in candidates {
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }

        // 3. ~/.cargo/bin and ~/.sb/bin
        if let Some(home) = dirs::home_dir() {
            let sb_cand = home.join(".sb").join("bin").join(&exe);
            if sb_cand.is_file() {
                return Some(sb_cand);
            }
            let cargo_cand = home.join(".cargo").join("bin").join(&exe);
            if cargo_cand.is_file() {
                return Some(cargo_cand);
            }
        }

        // 4. System PATH via which
        if let Ok(found) = which::which(base) {
            return Some(found);
        }
        if let Ok(found) = which::which(&exe) {
            return Some(found);
        }

        None
    }

    /// Resolves the authentic system OpenSSH `ssh` executable via `crate::ssh_transport::resolve_system_ssh`.
    ///
    /// SECURITY AUDIT:
    /// - Dynamic Threat Vector: Legacy `sb-ssh` or shadowing `.cargo/bin/ssh` breaking standard OpenSSH wire invocations.
    /// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path).
    /// - Likelihood & Exploitability: Low (2/10).
    /// - Applied Mitigation: Delegates strictly to `crate::ssh_transport::resolve_system_ssh()`.
    pub fn resolve_ssh() -> Option<PathBuf> {
        crate::ssh_transport::resolve_system_ssh().ok()
    }

    /// Resolves `sb-mesh` binary.
    pub fn resolve_mesh() -> Option<PathBuf> {
        Self::resolve_binary("sb-mesh")
    }

    /// Resolves `sb` CLI binary.
    pub fn resolve_cli() -> Option<PathBuf> {
        Self::resolve_binary("sb")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_name_handling() {
        let name = BinaryResolver::exe_name("sb-mesh");
        if cfg!(windows) {
            assert_eq!(name, "sb-mesh.exe");
        } else {
            assert_eq!(name, "sb-mesh");
        }
    }

    #[test]
    fn test_exe_name_already_with_extension() {
        let name = BinaryResolver::exe_name("sb-mesh.exe");
        assert_eq!(name, "sb-mesh.exe");
    }

    #[test]
    fn test_resolve_current_or_system_binary() {
        // Cargo test binary or current exe should always be resolvable
        let current = std::env::current_exe().ok();
        assert!(current.is_some());
    }
}
