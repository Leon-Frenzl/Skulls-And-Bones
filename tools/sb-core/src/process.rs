//! Unified Process Ledger & Service Supervisor Engine (~/.sb/run/ Namespace)

use crate::binary_resolver::BinaryResolver;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TrackedProcess {
    pub name: String,
    pub pid: u32,
    pub port: Option<u16>,
    pub command: String,
    pub started_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct ProcessLedger {
    pub processes: Vec<TrackedProcess>,
}

static LEDGER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn ledger_path() -> PathBuf {
    crate::paths::sb_run_dir().join("processes.json")
}

pub fn load_ledger() -> ProcessLedger {
    let _guard = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = ledger_path();
    if !path.exists() {
        return ProcessLedger::default();
    }
    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => ProcessLedger::default(),
    }
}

pub fn save_ledger(ledger: &ProcessLedger) -> Result<(), std::io::Error> {
    let _guard = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = ledger_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let data = serde_json::to_string_pretty(ledger).map_err(std::io::Error::other)?;
    fs::write(path, data)
}

pub fn modify_ledger<F, R>(f: F) -> R
where
    F: FnOnce(&mut ProcessLedger) -> R,
{
    let _guard = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = ledger_path();
    let mut ledger: ProcessLedger = if path.exists() {
        fs::read_to_string(&path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    } else {
        ProcessLedger::default()
    };

    let result = f(&mut ledger);

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(data) = serde_json::to_string_pretty(&ledger) {
        let _ = fs::write(path, data);
    }

    result
}

#[cfg(windows)]
pub fn is_pid_alive(pid: u32) -> bool {
    use std::ffi::c_void;
    extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *mut c_void;
        fn GetExitCodeProcess(process: *mut c_void, exit_code: *mut u32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let res = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        res != 0 && exit_code == STILL_ACTIVE
    }
}

/// Contextual Threat Analysis:
///   - Dynamic Threat Vector: In Unix systems, process IDs can be recycled quickly or enter zombie ('Z') state
///     after receiving SIGTERM. A naive `kill -0` check reports zombies as alive, leading to supervisor
///     hangs or misinterpreting terminated services as active. Furthermore, passing PID 0 or out-of-range PIDs
///     could signal the entire process group or trigger unexpected signal delivery.
///   - CVE / CWE Mapping: CWE-20 (Improper Input Validation), CWE-372 (Incomplete Internal State Distinction),
///     CWE-703 (Improper Check or Handling of Exceptional Conditions).
///   - Likelihood & Exploitability: High likelihood under process lifecycle management (score 8/10);
///     triggered whenever child processes terminate without immediate synchronous reaping.
///   - Applied Mitigation: Enforce non-zero & positive bounds validation. On Unix, attempt non-blocking
///     `waitpid` with `WNOHANG` for child processes to avoid zombie buildup, and inspect `/proc/<pid>/status`
///     on Linux to explicitly classify 'Z' (Zombie) and 'X'/'x' (Dead) states as not alive.
///
/// Conforms to POSIX.1-2017 (IEEE Std 1003.1-2017) §kill, §waitpid, and Linux procfs semantics.
#[cfg(not(windows))]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }

    // POSIX.1-2017 §waitpid: If the process is a child of the current process, non-blocking
    // waitpid with WNOHANG reaps it if terminated and returns its PID immediately.
    #[cfg(unix)]
    unsafe {
        extern "C" {
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        }
        const WNOHANG: i32 = 1;
        let mut status: i32 = 0;
        let res = waitpid(pid as i32, &mut status, WNOHANG);
        if res == pid as i32 {
            // Child process has terminated and has been reaped; it is no longer alive.
            return false;
        }
    }

    // Linux procfs inspection: /proc/<pid>/status provides authoritative process state.
    // States 'Z' (Zombie) and 'X'/'x' (Dead) mean the process execution has ceased.
    #[cfg(target_os = "linux")]
    {
        let status_path = format!("/proc/{}/status", pid);
        match std::fs::read_to_string(&status_path) {
            Ok(content) => {
                for line in content.lines() {
                    if let Some(state_part) = line.strip_prefix("State:") {
                        let trimmed = state_part.trim_start();
                        if trimmed.starts_with('Z')
                            || trimmed.starts_with('X')
                            || trimmed.starts_with('x')
                        {
                            return false;
                        }
                        return true;
                    }
                }
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => {
                // If /proc read fails due to permissions or non-standard environment, fallback to kill -0
                kill_zero_check(pid)
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        kill_zero_check(pid)
    }
}

#[cfg(not(windows))]
fn kill_zero_check(pid: u32) -> bool {
    let status = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn terminate_pid(pid: u32) -> bool {
    use std::ffi::c_void;
    extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *mut c_void;
        fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    const PROCESS_TERMINATE: u32 = 0x0001;
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return false;
        }
        let res = TerminateProcess(handle, 1);
        CloseHandle(handle);
        res != 0
    }
}

/// Contextual Threat Analysis:
///   - Dynamic Threat Vector: Passing PID 0 to `kill -15 0` in Unix signals the calling process's entire
///     process group, inadvertently killing the supervisor or test runner itself.
///   - CVE / CWE Mapping: CWE-20 (Improper Input Validation), CWE-703 (Improper Check or Handling of Exceptional Conditions).
///   - Likelihood & Exploitability: High (score 8/10) if uninitialized or zeroed PID is passed.
///   - Applied Mitigation: Reject PID 0 and values exceeding i32::MAX before executing kill.
///
/// Conforms to POSIX.1-2017 (IEEE Std 1003.1-2017) §kill signal 15 (SIGTERM).
#[cfg(not(windows))]
pub fn terminate_pid(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    let status = std::process::Command::new("kill")
        .args(["-15", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

pub fn is_port_listening(port: u16) -> bool {
    if let Ok(addr) = format!("127.0.0.1:{}", port).parse() {
        TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
    } else {
        false
    }
}

pub fn register_process(name: &str, pid: u32, port: Option<u16>, command: &str) {
    modify_ledger(|ledger| {
        prune_dead(ledger);
        // Prune existing with same name or same port
        ledger
            .processes
            .retain(|p| p.name != name && (port.is_none() || p.port != port) && p.pid != pid);

        ledger.processes.push(TrackedProcess {
            name: name.to_string(),
            pid,
            port,
            command: command.to_string(),
            started_at: chrono::Utc::now().timestamp(),
        });
    });
}

pub fn unregister_process_by_pid(pid: u32) {
    modify_ledger(|ledger| {
        ledger.processes.retain(|p| p.pid != pid);
    });
}

pub fn prune_dead(ledger: &mut ProcessLedger) -> usize {
    let initial_count = ledger.processes.len();
    ledger.processes.retain(|p| is_pid_alive(p.pid));
    initial_count - ledger.processes.len()
}

#[derive(Debug, Clone)]
pub struct ServiceSupervisor {
    pub name: String,
    pub binary: String,
    pub args: Vec<String>,
    pub port: Option<u16>,
    pub ready_port: Option<u16>,
    pub log_file: Option<PathBuf>,
    pub working_dir: Option<PathBuf>,
    pub detached: bool,
    pub envs: Vec<(String, String)>,
}

impl ServiceSupervisor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            binary: String::new(),
            args: Vec::new(),
            port: None,
            ready_port: None,
            log_file: None,
            working_dir: None,
            detached: true,
            envs: Vec::new(),
        }
    }

    pub fn with_bin(mut self, bin: impl Into<String>) -> Self {
        self.binary = bin.into();
        self
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_ready_port(mut self, port: u16) -> Self {
        self.ready_port = Some(port);
        self
    }

    pub fn with_log_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_file = Some(path.into());
        self
    }

    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    pub fn with_env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.envs.push((key.into(), val.into()));
        self
    }

    pub fn detached(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    pub fn resolve_binary(&self) -> PathBuf {
        let base = if self.binary.is_empty() {
            &self.name
        } else {
            &self.binary
        };

        BinaryResolver::resolve_binary(base)
            .unwrap_or_else(|| PathBuf::from(BinaryResolver::exe_name(base)))
    }

    pub fn resolve_log_path(&self) -> PathBuf {
        let run_dir = crate::paths::sb_run_dir();
        if let Some(log_file) = &self.log_file {
            if log_file.is_absolute() {
                log_file.clone()
            } else {
                run_dir.join(log_file)
            }
        } else {
            run_dir.join(format!("{}.log", self.name))
        }
    }

    pub fn is_running(&self) -> bool {
        let ledger = load_ledger();
        if let Some(p) = ledger.processes.iter().find(|p| p.name == self.name) {
            if is_pid_alive(p.pid) {
                return true;
            }
        }
        if let Some(port) = self.ready_port.or(self.port) {
            if is_port_listening(port) {
                return true;
            }
        }
        false
    }

    pub fn stop_by_name(name: &str) -> bool {
        modify_ledger(|ledger| {
            let pos = ledger.processes.iter().position(|p| p.name == name);
            if let Some(idx) = pos {
                let proc = ledger.processes.remove(idx);
                terminate_pid(proc.pid) || !is_pid_alive(proc.pid)
            } else {
                false
            }
        })
    }

    pub fn spawn_and_track(&self) -> Result<TrackedProcess, std::io::Error> {
        let binary_path = self.resolve_binary();
        let log_path = self.resolve_log_path();

        if let Some(parent) = log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut cmd = std::process::Command::new(&binary_path);
        cmd.args(&self.args);

        if let Some(dir) = &self.working_dir {
            cmd.current_dir(dir);
        }

        for (k, v) in &self.envs {
            cmd.env(k, v);
        }

        if self.detached {
            let stdout_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)?;

            let stderr_file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)?;

            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
                const DETACHED_PROCESS: u32 = 0x00000008;
                cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
            }

            cmd.stdin(std::process::Stdio::null());
            cmd.stdout(stdout_file);
            cmd.stderr(stderr_file);
        }

        let child = cmd.spawn()?;
        let pid = child.id();

        let full_command = if self.args.is_empty() {
            binary_path.display().to_string()
        } else {
            format!("{} {}", binary_path.display(), self.args.join(" "))
        };

        register_process(&self.name, pid, self.port, &full_command);

        Ok(TrackedProcess {
            name: self.name.clone(),
            pid,
            port: self.port,
            command: full_command,
            started_at: chrono::Utc::now().timestamp(),
        })
    }

    /// Spawns the service and awaits its readiness on `ready_port` (or `port`) up to `timeout`.
    pub fn spawn_and_await_ready(
        &self,
        timeout: Duration,
    ) -> Result<TrackedProcess, std::io::Error> {
        let tracked = self.spawn_and_track()?;
        let target_port = self.ready_port.or(self.port);

        if let Some(port) = target_port {
            let start = std::time::Instant::now();
            while start.elapsed() < timeout {
                if !is_pid_alive(tracked.pid) {
                    return Err(std::io::Error::other(format!(
                        "Prozess '{}' (PID {}) wurde vorzeitig beendet.",
                        self.name, tracked.pid
                    )));
                }
                if is_port_listening(port) {
                    return Ok(tracked);
                }
                std::thread::sleep(Duration::from_millis(150));
            }

            // If timeout occurred, check one last time
            if is_port_listening(port) {
                return Ok(tracked);
            }

            Err(std::io::Error::other(format!(
                "Dienst '{}' wurde gestartet (PID {}), Port {} war nach {:.1}s jedoch nicht erreichbar.",
                self.name, tracked.pid, port, timeout.as_secs_f32()
            )))
        } else {
            Ok(tracked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pid_alive() {
        let current_pid = std::process::id();
        assert!(is_pid_alive(current_pid));
        assert!(!is_pid_alive(999_999_999));
        assert!(!is_pid_alive(0));
    }

    #[test]
    fn test_terminated_child_is_not_alive() {
        let mut child = if cfg!(windows) {
            std::process::Command::new("powershell")
                .args(["-Command", "Start-Sleep -Seconds 5"])
                .spawn()
                .expect("failed to spawn child")
        } else {
            std::process::Command::new("sleep")
                .args(["5"])
                .spawn()
                .expect("failed to spawn child")
        };
        let pid = child.id();
        assert!(is_pid_alive(pid));
        assert!(terminate_pid(pid));
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!is_pid_alive(pid));
        let _ = child.wait();
    }

    #[test]
    fn test_supervisor_builder_lifecycle() {
        let supervisor = ServiceSupervisor::new("test-service")
            .with_bin("sb-test")
            .with_arg("daemon")
            .with_port(59999)
            .detached(true);

        assert_eq!(supervisor.name, "test-service");
        assert_eq!(supervisor.binary, "sb-test");
        assert_eq!(supervisor.port, Some(59999));
        assert!(supervisor.detached);
    }
}
