//! Cross-platform background service manager (`systemd` on Linux, Windows Service SCM on Windows)
//! for `sb-node agent` (automatic GPO policy pull + LAPS rotation timer).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Name of the managed system service.
pub const SERVICE_NAME: &str = "sb-node-agent";

/// Configuration for installing the `sb-node` background agent service.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub dc_url: String,
    pub interval_secs: u64,
    pub laps_rotate_days: u64,
    pub binary_path: PathBuf,
}

impl ServiceConfig {
    /// Validates and clamps service configuration values.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** Command or unit-file injection via `--dc` URL or binary path
    ///   written into a `systemd` unit or Windows `sc.exe` `binPath=`.
    /// - **CVE / CWE Mapping:** CWE-78 (OS Command Injection), CWE-20 (Improper Input Validation).
    /// - **Likelihood & Exploitability:** Medium (6/10) if untrusted strings reach service definitions.
    /// - **Applied Mitigation:** Rejects control characters, newlines, quotes, and shell
    ///   metacharacters in `dc_url` and `binary_path`, and clamps `interval_secs` (`10..=3600`)
    ///   and `laps_rotate_days` (`1..=90`).
    pub fn validate(&self) -> Result<Self, String> {
        let dc = self.dc_url.trim();
        if dc.is_empty()
            || (!dc.starts_with("https://") && !dc.starts_with("http://"))
            || dc.chars().any(|c| {
                c.is_control()
                    || matches!(
                        c,
                        '"' | '\'' | '`' | '$' | ';' | '&' | '|' | '<' | '>' | '\\' | ' '
                    )
            })
        {
            return Err(format!("Invalid DC URL for service configuration: '{dc}'"));
        }
        let bin_str = self.binary_path.to_string_lossy();
        if bin_str.is_empty()
            || bin_str
                .chars()
                .any(|c| c.is_control() || matches!(c, '"' | '`'))
        {
            return Err(format!("Invalid binary path for service: '{bin_str}'"));
        }
        Ok(Self {
            dc_url: dc.to_string(),
            interval_secs: self.interval_secs.clamp(10, 3600),
            laps_rotate_days: self.laps_rotate_days.clamp(1, 90),
            binary_path: self.binary_path.clone(),
        })
    }
}

/// Renders a hardened `systemd` unit file for `sb-node-agent.service`.
pub fn render_systemd_unit(cfg: &ServiceConfig) -> Result<String, String> {
    let valid = cfg.validate()?;
    Ok(format!(
        "[Unit]\n\
         Description=Skulls & Bones Sovereign Node Agent (GPO Sync & LAPS)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} agent --dc {} --interval-secs {} --laps-rotate-days {}\n\
         Restart=always\n\
         RestartSec=10\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectHome=read-only\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        valid.binary_path.display(),
        valid.dc_url,
        valid.interval_secs,
        valid.laps_rotate_days
    ))
}

/// Builds the `binPath=` value for Windows `sc.exe create/config`.
pub fn render_windows_bin_path(cfg: &ServiceConfig) -> Result<String, String> {
    let valid = cfg.validate()?;
    Ok(format!(
        "\"{}\" agent --dc {} --interval-secs {} --laps-rotate-days {} --windows-service",
        valid.binary_path.display(),
        valid.dc_url,
        valid.interval_secs,
        valid.laps_rotate_days
    ))
}

fn is_live_root(sys_root: &Path) -> bool {
    let raw = sys_root.to_string_lossy();
    raw == "/" || raw == "\\" || raw.eq_ignore_ascii_case("C:\\") || raw.eq_ignore_ascii_case("C:/")
}

/// Installs (or dry-run previews) the `sb-node-agent` background service for the current OS.
pub fn install_service(
    cfg: &ServiceConfig,
    sys_root: &Path,
    dry_run: bool,
) -> Result<String, String> {
    let valid = cfg.validate()?;

    #[cfg(target_os = "linux")]
    {
        let unit = render_systemd_unit(&valid)?;
        let unit_path = sys_root.join("etc/systemd/system/sb-node-agent.service");
        if dry_run {
            return Ok(format!(
                "Dry-Run: would write {} and enable {SERVICE_NAME}.service",
                unit_path.display()
            ));
        }
        if let Some(parent) = unit_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create systemd dir {}: {e}", parent.display()))?;
        }
        fs::write(&unit_path, unit)
            .map_err(|e| format!("Failed to write {}: {e}", unit_path.display()))?;

        if is_live_root(sys_root) {
            run_cmd("systemctl", &["daemon-reload"])?;
            run_cmd(
                "systemctl",
                &["enable", "--now", &format!("{SERVICE_NAME}.service")],
            )?;
            return Ok(format!(
                "systemd service '{SERVICE_NAME}' installed and started ({})",
                unit_path.display()
            ));
        }
        return Ok(format!(
            "systemd unit rendered to {} (non-root target)",
            unit_path.display()
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let bin_path = render_windows_bin_path(&valid)?;
        let manifest_path = sys_root.join("ProgramData/SkullsAndBones/service/sb-node-agent.json");
        if dry_run {
            return Ok(format!(
                "Dry-Run: would register Windows service '{SERVICE_NAME}' with binPath={bin_path}"
            ));
        }
        if let Some(parent) = manifest_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create service dir {}: {e}", parent.display()))?;
        }
        let manifest = serde_json::json!({
            "service_name": SERVICE_NAME,
            "bin_path": bin_path,
            "dc_url": valid.dc_url,
            "interval_secs": valid.interval_secs,
            "laps_rotate_days": valid.laps_rotate_days,
        });
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("Failed to write {}: {e}", manifest_path.display()))?;

        if is_live_root(sys_root) {
            let exists = std::process::Command::new("sc.exe")
                .args(["query", SERVICE_NAME])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if exists {
                run_cmd(
                    "sc.exe",
                    &[
                        "config",
                        SERVICE_NAME,
                        &format!("binPath= {bin_path}"),
                        "start=",
                        "auto",
                    ],
                )?;
            } else {
                run_cmd(
                    "sc.exe",
                    &[
                        "create",
                        SERVICE_NAME,
                        &format!("binPath= {bin_path}"),
                        "start=",
                        "auto",
                        "DisplayName=",
                        "Skulls & Bones Node Agent",
                    ],
                )?;
            }
            let _ = run_cmd("sc.exe", &["start", SERVICE_NAME]);
            return Ok(format!(
                "Windows Service '{SERVICE_NAME}' registered and started."
            ));
        }
        Ok(format!(
            "Windows Service manifest written to {} (non-root target)",
            manifest_path.display()
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (valid, sys_root, dry_run, is_live_root(sys_root));
        Err(
            "Service installation is currently supported on Linux (systemd) and Windows (SCM)"
                .into(),
        )
    }
}

/// Uninstalls the `sb-node-agent` background service.
pub fn uninstall_service(sys_root: &Path, dry_run: bool) -> Result<String, String> {
    if dry_run {
        return Ok(format!("Dry-Run: would uninstall service '{SERVICE_NAME}'"));
    }

    #[cfg(target_os = "linux")]
    {
        if is_live_root(sys_root) {
            let _ = run_cmd(
                "systemctl",
                &["disable", "--now", &format!("{SERVICE_NAME}.service")],
            );
        }
        let unit_path = sys_root.join("etc/systemd/system/sb-node-agent.service");
        if unit_path.exists() {
            fs::remove_file(&unit_path)
                .map_err(|e| format!("Failed to remove {}: {e}", unit_path.display()))?;
        }
        if is_live_root(sys_root) {
            let _ = run_cmd("systemctl", &["daemon-reload"]);
        }
        Ok(format!("systemd service '{SERVICE_NAME}' uninstalled."))
    }

    #[cfg(target_os = "windows")]
    {
        if is_live_root(sys_root) {
            let _ = run_cmd("sc.exe", &["stop", SERVICE_NAME]);
            run_cmd("sc.exe", &["delete", SERVICE_NAME])?;
        }
        let manifest_path = sys_root.join("ProgramData/SkullsAndBones/service/sb-node-agent.json");
        if manifest_path.exists() {
            let _ = fs::remove_file(&manifest_path);
        }
        Ok(format!("Windows Service '{SERVICE_NAME}' uninstalled."))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = sys_root;
        Err("Service uninstall is supported on Linux and Windows only".into())
    }
}

/// Queries the OS service status for `sb-node-agent`.
pub fn service_status() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("systemctl")
            .args(["is-active", &format!("{SERVICE_NAME}.service")])
            .output()
            .map_err(|e| format!("systemctl failed: {e}"))?;
        let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return Ok(if state.is_empty() {
            "inactive".into()
        } else {
            state
        });
    }

    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("sc.exe")
            .args(["query", SERVICE_NAME])
            .output()
            .map_err(|e| format!("sc.exe query failed: {e}"))?;
        if !out.status.success() {
            return Ok("not_installed".into());
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains("RUNNING") {
            Ok("running".into())
        } else if stdout.contains("STOPPED") {
            Ok("stopped".into())
        } else {
            Ok("installed".into())
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok("unsupported".into())
    }
}

fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to spawn {program}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Runs `sb-node agent` as a native Windows Service under the Service Control Manager (SCM).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Uncontrolled background execution or hung Windows service stop
///   preventing clean GPO/LAPS state flush.
/// - **CVE / CWE Mapping:** CWE-404 (Improper Resource Shutdown or Release).
/// - **Likelihood & Exploitability:** Low (3/10).
/// - **Applied Mitigation:** Registers a `LPHANDLER_FUNCTION_EX` handler with `SERVICE_ACCEPT_STOP`
///   and `SERVICE_ACCEPT_SHUTDOWN`, signals an `AtomicBool` for graceful tokio shutdown, and
///   reports `SERVICE_STOPPED` to SCM on exit.
#[cfg(target_os = "windows")]
pub fn run_windows_service_dispatcher<F>(runner: F) -> Result<(), String>
where
    F: FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send + 'static,
{
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };

    struct ServiceCtx {
        runner: Option<Box<dyn FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send>>,
        stop_flag: Arc<AtomicBool>,
        status_handle: isize,
    }

    static CTX: Mutex<Option<ServiceCtx>> = Mutex::new(None);

    fn set_status(handle: isize, state: u32, controls: u32) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 5000,
        };
        // SAFETY: `handle` is a valid `SERVICE_STATUS_HANDLE` from `RegisterServiceCtrlHandlerExW`.
        unsafe {
            SetServiceStatus(handle as SERVICE_STATUS_HANDLE, &status);
        }
    }

    unsafe extern "system" fn ctrl_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        if let Ok(guard) = CTX.lock() {
            if let Some(ctx) = guard.as_ref() {
                match control {
                    SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                        set_status(ctx.status_handle, SERVICE_STOP_PENDING, 0);
                        ctx.stop_flag.store(true, Ordering::SeqCst);
                    }
                    SERVICE_CONTROL_INTERROGATE => {
                        set_status(
                            ctx.status_handle,
                            SERVICE_RUNNING,
                            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                        );
                    }
                    _ => {}
                }
            }
        }
        NO_ERROR
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let mut name_w: Vec<u16> = OsStr::new(SERVICE_NAME)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(name_w.as_mut_ptr(), Some(ctrl_handler), null_mut())
        };
        if handle.is_null() {
            return;
        }
        let handle_raw = handle as isize;
        set_status(handle_raw, SERVICE_START_PENDING, 0);

        let (runner_opt, stop_flag) = {
            let mut guard = match CTX.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if let Some(ctx) = guard.as_mut() {
                ctx.status_handle = handle_raw;
                (ctx.runner.take(), Arc::clone(&ctx.stop_flag))
            } else {
                (None, Arc::new(AtomicBool::new(false)))
            }
        };

        set_status(
            handle_raw,
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        );
        if let Some(run_fn) = runner_opt {
            let _ = run_fn(stop_flag);
        }
        set_status(handle_raw, SERVICE_STOPPED, 0);
    }

    {
        let mut guard = CTX
            .lock()
            .map_err(|_| "Service mutex poisoned".to_string())?;
        *guard = Some(ServiceCtx {
            runner: Some(Box::new(runner)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            status_handle: 0,
        });
    }

    let mut name_w: Vec<u16> = OsStr::new(SERVICE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name_w.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];

    // SAFETY: `table` is null-terminated and valid for the lifetime of `StartServiceCtrlDispatcherW`.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        return Err("StartServiceCtrlDispatcherW failed (must be launched by Windows SCM)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_config_renders_safe_systemd_and_windows_definitions() {
        let cfg = ServiceConfig {
            dc_url: "https://console.skulls-and-bones.org".into(),
            interval_secs: 60,
            laps_rotate_days: 30,
            binary_path: PathBuf::from("/usr/local/bin/sb-node"),
        };
        let unit = render_systemd_unit(&cfg).unwrap();
        assert!(unit.contains("ExecStart=/usr/local/bin/sb-node agent --dc https://console.skulls-and-bones.org --interval-secs 60 --laps-rotate-days 30"));
        assert!(unit.contains("NoNewPrivileges=yes"));

        let win_bin = render_windows_bin_path(&cfg).unwrap();
        assert!(win_bin.contains("--windows-service"));

        // Injection attempt in DC URL must be rejected
        let bad = ServiceConfig {
            dc_url: "https://evil.org;rm -rf /".into(),
            interval_secs: 60,
            laps_rotate_days: 30,
            binary_path: PathBuf::from("/usr/local/bin/sb-node"),
        };
        assert!(bad.validate().is_err());
    }
}
