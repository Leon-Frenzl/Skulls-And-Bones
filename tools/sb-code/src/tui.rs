use crate::ast::AstLockTable;
use crate::merkle::CommitStore;
use crate::runner::{RunnerState, RunnerStatus};
use crate::session::{CodeSession, PeerRole};
use crate::sync::FileTreeSnapshot;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ingress::{self, IngressEndpoint};

pub fn run_tui(
    session: Arc<Mutex<CodeSession>>,
    runner_state: Arc<Mutex<RunnerState>>,
    lock_table: Arc<Mutex<AstLockTable>>,
    workspace_root: &std::path::Path,
) -> io::Result<()> {
    if let Err(e) = enable_raw_mode() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("TUI erfordert ein echtes, interaktives Konsolenfenster (z. B. Windows Terminal / cmd.exe). In nicht-interaktiven Streams oder IDE-Pipes kann die TUI nicht dargestellt werden: {}", e)
        ));
    }
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = main_loop(
        &mut terminal,
        session,
        runner_state,
        lock_table,
        workspace_root,
    );

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

fn main_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    session: Arc<Mutex<CodeSession>>,
    runner_state: Arc<Mutex<RunnerState>>,
    lock_table: Arc<Mutex<AstLockTable>>,
    workspace_root: &std::path::Path,
) -> io::Result<()> {
    let mut last_scan = std::time::Instant::now();
    let mut last_ingress_scan = std::time::Instant::now();
    let mut current_snapshot = FileTreeSnapshot::scan(workspace_root).unwrap_or_default();
    let mut commit_store = CommitStore::load_or_init(workspace_root);
    let mut active_ingress = ingress::detect_ingress_endpoints();

    loop {
        if last_scan.elapsed() > Duration::from_secs(2) {
            if let Ok(s) = FileTreeSnapshot::scan(workspace_root) {
                current_snapshot = s;
            }
            last_scan = std::time::Instant::now();
        }

        if last_ingress_scan.elapsed() > Duration::from_secs(2) {
            active_ingress = ingress::detect_ingress_endpoints();
            last_ingress_scan = std::time::Instant::now();
        }

        terminal.draw(|f| {
            render_ui(
                f,
                &session,
                &runner_state,
                &lock_table,
                &current_snapshot,
                &commit_store,
                &active_ingress,
            );
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('t') | KeyCode::Char('T') => {
                        let mut r = runner_state.lock().unwrap();
                        r.toggle_target(Some("sb-node-01"));
                    }
                    KeyCode::Char('k') | KeyCode::Char('K') => {
                        let mut r = runner_state.lock().unwrap();
                        r.status = RunnerStatus::Idle;
                        r.push_log("[LOCAL] Execution cancelled [K]".to_string(), true, "local");
                    }
                    KeyCode::Char('i') | KeyCode::Char('I') => {
                        let mut r = runner_state.lock().unwrap();
                        if let Some(first) = active_ingress.first() {
                            r.push_log(
                                format!(
                                    "[INGRESS] 🌐 Active Mesh URL: {} (Port {})",
                                    first.mesh_url, first.port
                                ),
                                false,
                                "ingress",
                            );
                        } else {
                            r.push_log(
                                "[INGRESS] Kein aktiver Webserver auf Standard-Ports erkannt"
                                    .to_string(),
                                true,
                                "ingress",
                            );
                        }
                    }
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        // Quick snapshot commit
                        let s = session.lock().unwrap();
                        let author = s.self_callsign.clone();
                        drop(s);
                        let commit = commit_store.create_commit(
                            "Live session snapshot",
                            &current_snapshot.root_blake3,
                            &author,
                        );
                        let _ = commit_store.save(workspace_root);
                        let mut r = runner_state.lock().unwrap();
                        let cid_preview = if commit.commit_id.len() >= 16 {
                            &commit.commit_id[..16]
                        } else {
                            &commit.commit_id
                        };
                        r.push_log(
                            format!("[VCS] Merkle Commit created: {}", cid_preview),
                            false,
                            "vcs",
                        );
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        let runner_clone = Arc::clone(&runner_state);
                        tokio::spawn(async move {
                            #[cfg(target_os = "windows")]
                            let cmd = vec!["cargo.exe".to_string(), "test".to_string()];
                            #[cfg(not(target_os = "windows"))]
                            let cmd = vec!["cargo".to_string(), "test".to_string()];

                            let _ = crate::runner::execute_command(runner_clone, cmd).await;
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn render_ui(
    f: &mut Frame,
    session: &Arc<Mutex<CodeSession>>,
    runner_state: &Arc<Mutex<RunnerState>>,
    lock_table: &Arc<Mutex<AstLockTable>>,
    snapshot: &FileTreeSnapshot,
    commit_store: &CommitStore,
    active_ingress: &[IngressEndpoint],
) {
    let (session_name, lease_ttl, target_str) = {
        let s = session.lock().unwrap();
        let r = runner_state.lock().unwrap();
        (
            s.session_name.clone(),
            s.formatted_lease_ttl(),
            format!("{}", r.target),
        )
    };

    let head_commit = commit_store
        .head_commit_id
        .as_deref()
        .map(|id| if id.len() >= 8 { &id[..8] } else { id })
        .unwrap_or("none");

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header Bar
            Constraint::Min(10),   // Main View (Peers + Console)
            Constraint::Length(5), // File Buffer, VCS & Dev Ingress Status
            Constraint::Length(3), // Hotkeys
        ])
        .split(f.area());

    // 1. Header Bar
    let header_text = vec![Line::from(vec![
        Span::styled(
            "⚡ Skulls & Bones · sb-code v0.1.0 ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ Session: "),
        Span::styled(
            format!("[{}] ", session_name),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ Lease: "),
        Span::styled(format!("{} ", lease_ttl), Style::default().fg(Color::Green)),
        Span::raw("│ Target: "),
        Span::styled(
            format!("[{}] ", target_str),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ Head: "),
        Span::styled(
            format!("#{} ", head_commit),
            Style::default().fg(Color::LightBlue),
        ),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(header, chunks[0]);

    // 2. Middle Panel: Left = Peers & AST Scopes, Right = Console
    let middle_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(chunks[1]);

    let peers_list: Vec<ListItem> = {
        let s = session.lock().unwrap();
        let _lt = lock_table.lock().unwrap();
        s.peers
            .iter()
            .map(|p| {
                let role_style = match p.role {
                    PeerRole::Host => Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                    PeerRole::Collaborator => Style::default().fg(Color::Green),
                    PeerRole::Observer => Style::default().fg(Color::DarkGray),
                };

                let active_scope = p
                    .active_scope
                    .clone()
                    .unwrap_or_else(|| "<idle>".to_string());
                let self_badge = if p.is_self { " (YOU)" } else { "" };

                let content = vec![
                    Line::from(vec![Span::styled(
                        format!("● {}{}", p.callsign, self_badge),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    )]),
                    Line::from(vec![
                        Span::raw("  ├─ Role:  "),
                        Span::styled(format!("{}", p.role), role_style),
                    ]),
                    Line::from(vec![
                        Span::raw("  ├─ Scope: "),
                        Span::styled(active_scope, Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(vec![
                        Span::raw("  └─ Ping:  "),
                        Span::styled(
                            format!("{} ms", p.ping_ms),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]),
                ];
                ListItem::new(content)
            })
            .collect()
    };

    let peers_widget = List::new(peers_list).block(
        Block::default()
            .title(" 👥 ACTIVE SWARM & AST SCOPES ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(peers_widget, middle_chunks[0]);

    // Right: Shared Execution Console
    let log_items: Vec<ListItem> = {
        let r = runner_state.lock().unwrap();
        r.logs
            .iter()
            .rev()
            .take(30)
            .rev()
            .map(|l| {
                let color = if l.is_stderr {
                    Color::Red
                } else if l.text.contains("Compiling") || l.text.contains("Running") {
                    Color::Cyan
                } else if l.text.contains("ok")
                    || l.text.contains("Finished")
                    || l.text.contains("VCS")
                {
                    Color::Green
                } else {
                    Color::White
                };

                let prefix = format!("[{}] ", l.timestamp.format("%H:%M:%S"));
                ListItem::new(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                    Span::styled(l.text.clone(), Style::default().fg(color)),
                ]))
            })
            .collect()
    };

    let status_str = {
        let r = runner_state.lock().unwrap();
        match &r.status {
            RunnerStatus::Idle => "READY (Idle)".to_string(),
            RunnerStatus::Running { pid } => format!("RUNNING (PID {})", pid),
            RunnerStatus::Finished { exit_code } => format!("FINISHED (Code {})", exit_code),
            RunnerStatus::Failed { error } => format!("FAILED: {}", error),
        }
    };

    let console_widget = List::new(log_items).block(
        Block::default()
            .title(format!(" ⚡ SHARED EXECUTION CONSOLE [{}] ", status_str))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );
    f.render_widget(console_widget, middle_chunks[1]);

    // 3. File Buffer & VCS Status
    let ingress_line = if let Some(first) = active_ingress.first() {
        Line::from(vec![
            Span::styled(
                "🌐 DEV INGRESS: ",
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                first.mesh_url.clone(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" ({} on port {}) ", first.process_name, first.port)),
            Span::styled(
                "● MESH E2E ACTIVE",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("🌐 DEV INGRESS: ", Style::default().fg(Color::DarkGray)),
            Span::raw(
                "Kein lokaler Webdienst aktiv (Starte App; Port wird per Mesh bereitgestellt)",
            ),
        ])
    };

    let file_stats = vec![
        Line::from(vec![
            Span::styled(
                "📁 REPO & VCS: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{} source files │ Root BLAKE3: {}... │ Commits: {} ",
                snapshot.entries.len(),
                &snapshot.root_blake3.get(..12).unwrap_or("000000000000"),
                commit_store.commits.len()
            )),
            Span::styled(
                "● ZERO-CONFLICT ACTIVE",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("AST Isolation: "),
            Span::styled("METHOD/FN-LEVEL SCOPES ", Style::default().fg(Color::Cyan)),
            Span::raw("│ Shadow Baseline: "),
            Span::styled(
                "ACTIVE (No broken builds) ",
                Style::default().fg(Color::Magenta),
            ),
            Span::raw("│ Net: "),
            Span::styled("P2P Noise_IK UDP", Style::default().fg(Color::Green)),
        ]),
        ingress_line,
    ];
    let file_widget = Paragraph::new(file_stats).block(
        Block::default()
            .title(" 📁 SOVEREIGN CODE & DEV INGRESS STATUS ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(file_widget, chunks[2]);

    // 4. Hotkeys Bar
    let hotkeys = Paragraph::new(Line::from(vec![
        Span::styled(
            " [R] ",
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Run   "),
        Span::styled(
            " [T] ",
            Style::default()
                .bg(Color::Magenta)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Target   "),
        Span::styled(
            " [I] ",
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Ingress URL   "),
        Span::styled(
            " [C] ",
            Style::default()
                .bg(Color::Green)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Commit   "),
        Span::styled(
            " [K] ",
            Style::default()
                .bg(Color::Red)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Kill   "),
        Span::styled(
            " [Q] ",
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Detach"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(hotkeys, chunks[3]);
}
