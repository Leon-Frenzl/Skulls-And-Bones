use std::path::Path;
use std::process::Command;

pub struct HostLauncher;

impl HostLauncher {
    /// Öffnet eine Datei mit der im Betriebssystem registrierten Standardanwendung
    /// (z. B. Word für .docx, Excel für .xlsx, VS Code für .rs/.json, Preview für .pdf)
    pub fn open_with_default_app<P: AsRef<Path>>(path: P) -> Result<(), String> {
        let p = path.as_ref();
        if !p.exists() {
            return Err(format!("Datei existiert nicht: {}", p.display()));
        }

        let p_str = p.to_string_lossy().to_string();

        #[cfg(target_os = "windows")]
        {
            // Windows: ShellExecute via cmd.exe /c start "" "path"
            let status = Command::new("cmd")
                .args(["/c", "start", "", &p_str])
                .status()
                .map_err(|e| format!("Fehler beim Starten der Host-App auf Windows: {}", e))?;

            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "Windows start Befehl beendet mit Exit-Code: {:?}",
                    status.code()
                ))
            }
        }

        #[cfg(target_os = "macos")]
        {
            let status = Command::new("open")
                .arg(&p_str)
                .status()
                .map_err(|e| format!("Fehler beim Starten von 'open' auf macOS: {}", e))?;

            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "macOS open Befehl beendet mit Exit-Code: {:?}",
                    status.code()
                ))
            }
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let status = Command::new("xdg-open")
                .arg(&p_str)
                .status()
                .map_err(|e| format!("Fehler beim Starten von 'xdg-open' auf Linux: {}", e))?;

            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "Linux xdg-open Befehl beendet mit Exit-Code: {:?}",
                    status.code()
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_non_existent_file_fails() {
        let res =
            HostLauncher::open_with_default_app(PathBuf::from("non_existent_document_123.docx"));
        assert!(res.is_err());
    }
}
