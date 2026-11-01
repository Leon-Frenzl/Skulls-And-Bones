use crate::ast::{parse_live_ast_scopes, resolve_innermost_scope, AstLockTable, AstScope};
use crate::runner::{execute_command, RunnerState};
use crate::session::CodeSession;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub const DEFAULT_CODE_IPC_PORT: u16 = 44990;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", content = "payload")]
pub enum CodeIpcRequest {
    Ping,
    GetSession,
    ClaimScope { file: String, line: usize },
    ReleaseScope { scope_id: String },
    Run { command: Vec<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum CodeIpcResponse {
    Ok,
    Pong,
    ScopeClaimed { scope: AstScope },
    ScopeRejected { reason: String },
    Session(CodeSession),
    Error(String),
}

pub async fn start_ipc_server(
    session: Arc<Mutex<CodeSession>>,
    runner_state: Arc<Mutex<RunnerState>>,
    lock_table: Arc<Mutex<AstLockTable>>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    if let Some(home) = dirs::home_dir() {
        let port_file = home.join(".sb").join("code-ipc.port");
        let _ = fs::write(port_file, port.to_string());
    }

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let session_clone = Arc::clone(&session);
            let runner_clone = Arc::clone(&runner_state);
            let locks_clone = Arc::clone(&lock_table);

            tokio::spawn(async move {
                let (reader, mut writer) = socket.split();
                let mut lines = BufReader::new(reader).lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    let req: Result<CodeIpcRequest, _> = serde_json::from_str(&line);
                    let resp = match req {
                        Ok(CodeIpcRequest::Ping) => CodeIpcResponse::Pong,
                        Ok(CodeIpcRequest::GetSession) => {
                            let s = session_clone.lock().unwrap().clone();
                            CodeIpcResponse::Session(s)
                        }
                        Ok(CodeIpcRequest::ClaimScope { file, line }) => {
                            // Read file content if exists and parse AST
                            let parsed = fs::read_to_string(&file)
                                .map_err(|error| format!("Could not read '{}': {error}", file))
                                .and_then(|content| parse_live_ast_scopes(&file, &content));

                            match parsed {
                                Ok(scopes) => {
                                    if let Some(scope) = resolve_innermost_scope(&scopes, line) {
                                        let (peer, now) = {
                                            let s = session_clone.lock().unwrap();
                                            (
                                                s.self_callsign.clone(),
                                                chrono::Utc::now().timestamp(),
                                            )
                                        };

                                        let mut table = locks_clone.lock().unwrap();
                                        match table.claim(scope, &peer, now) {
                                            Ok(()) => {
                                                let mut s = session_clone.lock().unwrap();
                                                s.update_scope(&peer, &scope.id);
                                                CodeIpcResponse::ScopeClaimed {
                                                    scope: scope.clone(),
                                                }
                                            }
                                            Err(reason) => {
                                                CodeIpcResponse::ScopeRejected { reason }
                                            }
                                        }
                                    } else {
                                        CodeIpcResponse::ScopeRejected {
                                            reason: "Kein spezifischer AST-Knoten in dieser Zeile"
                                                .to_string(),
                                        }
                                    }
                                }
                                Err(reason) => CodeIpcResponse::ScopeRejected { reason },
                            }
                        }
                        Ok(CodeIpcRequest::ReleaseScope { scope_id }) => {
                            let peer = {
                                let s = session_clone.lock().unwrap();
                                s.self_callsign.clone()
                            };
                            let mut table = locks_clone.lock().unwrap();
                            table.release(&scope_id, &peer);
                            CodeIpcResponse::Ok
                        }
                        Ok(CodeIpcRequest::Run { command }) => {
                            let r_clone = Arc::clone(&runner_clone);
                            tokio::spawn(async move {
                                let _ = execute_command(r_clone, command).await;
                            });
                            CodeIpcResponse::Ok
                        }
                        Err(e) => CodeIpcResponse::Error(format!("Invalid IPC payload: {}", e)),
                    };

                    let resp_str = serde_json::to_string(&resp).unwrap_or_default() + "\n";
                    if writer.write_all(resp_str.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    Ok(())
}
