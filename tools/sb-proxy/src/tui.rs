use crate::escape::{verify_domain_dns, EscapeSpaceStore, EscapeStatus};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::io;
use std::time::Duration;

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_tui_loop(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("TUI-Fehler: {:?}", err);
    }
    Ok(())
}

fn run_tui_loop<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let mut selected_idx = 0;
    let mut status_msg = String::from("Willkommen im S&B Proxy Cockpit. Drücke [?] für Hilfe.");

    loop {
        let store = EscapeSpaceStore::load();
        let spaces = store.spaces;
        let spaces_len = spaces.len();

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header
                    Constraint::Min(6),    // Routes Table
                    Constraint::Length(3), // Status & Shortcuts
                ])
                .split(f.area());

            // 1. Header Banner
            let header = Paragraph::new(
                " 🛡️  S&B Sovereign Proxy & Edge Gateway — Pure-Rust Airgap Routing [Node: hostinger-node]",
            )
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(header, chunks[0]);

            // 2. Routes Table
            let rows: Vec<Row> = spaces
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let is_selected = i == selected_idx;
                    let (status_icon, status_color) = match &s.status {
                        EscapeStatus::Active => ("🟢 LIVE (200 OK)", Color::Green),
                        EscapeStatus::Paused => ("⏸️ PAUSED (503)", Color::DarkGray),
                        EscapeStatus::Maintenance => ("🛠️ WARTUNG (503)", Color::Magenta),
                        EscapeStatus::DnsPending => ("⏳ DNS PENDING", Color::Yellow),
                        EscapeStatus::Error(_) => ("❌ FEHLER", Color::Red),
                    };

                    let cells = vec![
                        Cell::from(s.domain.clone()).style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                        Cell::from(format!("127.0.0.1:{}", s.target_port)).style(Style::default().fg(Color::Cyan)),
                        Cell::from(status_icon).style(Style::default().fg(status_color)),
                        Cell::from(s.node_callsign.clone()).style(Style::default().fg(Color::Gray)),
                        Cell::from(if s.tls_enabled { "Auto-ACME (TLS 1.3)" } else { "HTTP" }).style(Style::default().fg(Color::Magenta)),
                    ];

                    let row_style = if is_selected {
                        Style::default().bg(Color::Rgb(30, 30, 45)).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };

                    Row::new(cells).style(row_style).height(1)
                })
                .collect();

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(35),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                    Constraint::Percentage(15),
                    Constraint::Percentage(10),
                ],
            )
            .header(
                Row::new(vec![
                    Cell::from("DOMAIN").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Cell::from("AIRGAP ZIEL").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Cell::from("STATUS").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Cell::from("NODE").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Cell::from("SSL/TLS").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                ])
                .style(Style::default().bg(Color::Rgb(15, 15, 22)))
                .bottom_margin(1),
            )
            .block(
                Block::default()
                    .title(" Aktive Egress-Routen & Escape Spaces ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );

            f.render_widget(table, chunks[1]);

            // 3. Footer Bar with Shortcuts & Status
            let footer_text = format!(
                " [{}]  |  [Leertaste] Pause/Play  [D] DNS prüfen  [Q] Beenden  [↑/↓] Auswählen",
                status_msg
            );
            let footer = Paragraph::new(footer_text)
                .style(Style::default().fg(Color::Gray))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                );
            f.render_widget(footer, chunks[2]);
        })?;

        // Handle Keyboard Events
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                        return Ok(());
                    }
                    KeyCode::Up => {
                        if selected_idx > 0 {
                            selected_idx -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if spaces_len > 0 && selected_idx + 1 < spaces_len {
                            selected_idx += 1;
                        }
                    }
                    KeyCode::Char(' ') => {
                        // Toggle Status (Pause / Resume)
                        if selected_idx < spaces_len {
                            let space_id = spaces[selected_idx].id.clone();
                            let mut store_mut = EscapeSpaceStore::load();
                            if let Ok(new_status) = store_mut.toggle_status(&space_id) {
                                status_msg = format!("Status geändert: {}", new_status);
                            }
                        }
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        // Trigger DNS Check
                        if selected_idx < spaces_len {
                            let domain = spaces[selected_idx].domain.clone();
                            let suite_cfg = sb_core::config::SuiteConfig::load();
                            let node_ip = suite_cfg
                                .network
                                .expected_node_ip
                                .unwrap_or_else(|| "127.0.0.1".into());
                            let is_match = verify_domain_dns(&domain, &node_ip);
                            status_msg = if is_match {
                                format!("✅ DNS für '{}' zeigt korrekt auf {}", domain, node_ip)
                            } else {
                                format!(
                                    "⚠️ DNS für '{}' noch nicht auf {} propagiert",
                                    domain, node_ip
                                )
                            };
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
