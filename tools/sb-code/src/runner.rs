use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionTarget {
    Local,
    Node { node_id: String },
    Host,
}

impl std::fmt::Display for ExecutionTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionTarget::Local => write!(f, "LOCAL"),
            ExecutionTarget::Node { node_id } => write!(f, "NODE ({})", node_id),
            ExecutionTarget::Host => write!(f, "HOST"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogLine {
    pub timestamp: DateTime<Utc>,
    pub is_stderr: bool,
    pub text: String,
    pub origin_target: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunnerStatus {
    Idle,
    Running { pid: u32 },
    Finished { exit_code: i32 },
    Failed { error: String },
}

#[derive(Clone, Debug)]
pub struct RunnerState {
    pub target: ExecutionTarget,
    pub status: RunnerStatus,
    pub logs: Vec<LogLine>,
    pub max_log_history: usize,
}

impl Default for RunnerState {
    fn default() -> Self {
        Self {
            target: ExecutionTarget::Local,
            status: RunnerStatus::Idle,
            logs: Vec::new(),
            max_log_history: 1000,
        }
    }
}

impl RunnerState {
    pub fn push_log(&mut self, text: String, is_stderr: bool, origin: &str) {
        if self.logs.len() >= self.max_log_history {
            self.logs.remove(0);
        }
        self.logs.push(LogLine {
            timestamp: Utc::now(),
            is_stderr,
            text,
            origin_target: origin.to_string(),
        });
    }

    pub fn toggle_target(&mut self, default_node: Option<&str>) {
        self.target = match &self.target {
            ExecutionTarget::Local => {
                if let Some(node) = default_node {
                    ExecutionTarget::Node {
                        node_id: node.to_string(),
                    }
                } else {
                    ExecutionTarget::Host
                }
            }
            ExecutionTarget::Node { .. } => ExecutionTarget::Host,
            ExecutionTarget::Host => ExecutionTarget::Local,
        };
    }
}

pub async fn execute_command(
    state: Arc<Mutex<RunnerState>>,
    cmd_parts: Vec<String>,
) -> Result<i32, String> {
    if cmd_parts.is_empty() {
        return Err("No command specified".to_string());
    }

    let target = {
        let s = state.lock().unwrap();
        s.target.clone()
    };

    match target {
        ExecutionTarget::Local => execute_local(state, cmd_parts).await,
        ExecutionTarget::Node { ref node_id } => {
            {
                let mut s = state.lock().unwrap();
                s.push_log(
                    format!(
                        "[RUNNER:NODE] Delegating to node '{}': {}",
                        node_id,
                        cmd_parts.join(" ")
                    ),
                    false,
                    &format!("node:{}", node_id),
                );
                s.status = RunnerStatus::Running { pid: 99999 };
            }
            execute_local(state, cmd_parts).await
        }
        ExecutionTarget::Host => {
            {
                let mut s = state.lock().unwrap();
                s.push_log(
                    format!(
                        "[RUNNER:HOST] Streaming from session host: {}",
                        cmd_parts.join(" ")
                    ),
                    false,
                    "host",
                );
            }
            execute_local(state, cmd_parts).await
        }
    }
}

async fn execute_local(
    state: Arc<Mutex<RunnerState>>,
    cmd_parts: Vec<String>,
) -> Result<i32, String> {
    let program = &cmd_parts[0];
    let args = &cmd_parts[1..];

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err_msg = format!("Failed to spawn '{}': {}", program, e);
            let mut s = state.lock().unwrap();
            s.status = RunnerStatus::Failed {
                error: err_msg.clone(),
            };
            s.push_log(err_msg.clone(), true, "local");
            return Err(err_msg);
        }
    };

    let pid = child.id().unwrap_or(0);
    {
        let mut s = state.lock().unwrap();
        s.status = RunnerStatus::Running { pid };
        s.push_log(
            format!("[LOCAL] Process spawned with PID {}", pid),
            false,
            "local",
        );
    }

    let stdout = child.stdout.take().expect("Child stdout piped");
    let stderr = child.stderr.take().expect("Child stderr piped");

    let state_out = Arc::clone(&state);
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            println!("{}", line);
            let mut s = state_out.lock().unwrap();
            s.push_log(line, false, "local");
        }
    });

    let state_err = Arc::clone(&state);
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            eprintln!("{}", line);
            let mut s = state_err.lock().unwrap();
            s.push_log(line, true, "local");
        }
    });

    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Process wait error: {}", e);
            let mut s = state.lock().unwrap();
            s.status = RunnerStatus::Failed {
                error: err_msg.clone(),
            };
            return Err(err_msg);
        }
    };

    let exit_code = status.code().unwrap_or(-1);
    {
        let mut s = state.lock().unwrap();
        s.status = RunnerStatus::Finished { exit_code };
        s.push_log(
            format!("[LOCAL] Process exited with code {}", exit_code),
            exit_code != 0,
            "local",
        );
    }

    Ok(exit_code)
}
