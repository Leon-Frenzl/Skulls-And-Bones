use rand::RngCore;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const TOKEN_BYTES: usize = 32;

pub struct DaemonAuthToken {
    value: Zeroizing<String>,
    path: PathBuf,
}

impl DaemonAuthToken {
    pub fn create_default() -> Result<Self, String> {
        let path = crate::paths::sb_run_dir().join("daemon.token");
        Self::create_at(path)
    }

    pub fn create_at(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let parent = path
            .parent()
            .ok_or_else(|| "Daemon-Token-Pfad besitzt kein Verzeichnis".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Daemon-Runtime-Verzeichnis konnte nicht erstellt werden: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| format!("Daemon-Runtime-Verzeichnis konnte nicht geschützt werden: {e}"),
            )?;
        }

        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Altes Daemon-Token konnte nicht entfernt werden: {error}"
                ));
            }
        }

        let mut random = [0u8; TOKEN_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let token = Zeroizing::new(encode_hex(&random));
        random.zeroize();

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|e| format!("Daemon-Token konnte nicht sicher angelegt werden: {e}"))?;
        file.write_all(token.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("Daemon-Token konnte nicht geschrieben werden: {e}"))?;

        Ok(Self { value: token, path })
    }

    pub fn verify(&self, candidate: &str) -> bool {
        constant_time_eq(self.value.as_bytes(), candidate.as_bytes())
    }

    pub fn token_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DaemonAuthToken {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("Daemon-Token konnte beim Beenden nicht entfernt werden: {error}");
            }
        }
    }
}

pub fn read_default_token() -> Result<Zeroizing<String>, String> {
    let path = crate::paths::sb_run_dir().join("daemon.token");
    let mut file = std::fs::File::open(&path)
        .map_err(|e| format!("Daemon-Token konnte nicht geöffnet werden: {e}"))?;
    let mut token = String::new();
    file.read_to_string(&mut token)
        .map_err(|e| format!("Daemon-Token konnte nicht gelesen werden: {e}"))?;
    let token = token.trim().to_string();
    if token.len() != TOKEN_BYTES * 2 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Daemon-Token-Datei enthält kein gültiges Token".to_string());
    }
    Ok(Zeroizing::new(token))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn constant_time_eq(expected: &[u8], candidate: &[u8]) -> bool {
    let mut difference = expected.len() ^ candidate.len();
    for index in 0..expected.len().max(candidate.len()) {
        let left = expected.get(index).copied().unwrap_or_default();
        let right = candidate.get(index).copied().unwrap_or_default();
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_token_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "sb-daemon-auth-{}-{}-token",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn generated_token_is_random_and_verified() {
        let path = temporary_token_path();
        let token = DaemonAuthToken::create_at(&path).unwrap();
        let from_disk = std::fs::read_to_string(&path).unwrap();

        assert_eq!(from_disk.len(), TOKEN_BYTES * 2);
        assert!(token.verify(&from_disk));
        assert!(!token.verify("incorrect-token"));

        drop(token);
        assert!(!path.exists());
    }

    #[test]
    fn token_verification_rejects_length_and_case_changes() {
        let path = temporary_token_path();
        let token = DaemonAuthToken::create_at(&path).unwrap();
        let value = std::fs::read_to_string(&path).unwrap();

        assert!(!token.verify(&value[..value.len() - 1]));
        assert!(!token.verify(&value.to_uppercase()));
    }
}
