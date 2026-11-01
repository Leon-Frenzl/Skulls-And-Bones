use crate::db::Database;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io;

pub fn run_tui(db: Database) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut selected_idx = 0;
    let mut filter = String::new();
    let mut filter_mode = false;

    loop {
        let stats = db.stats().unwrap_or_else(|_| crate::db::DbStats {
            path: std::path::PathBuf::from("."),
            key_count: 0,
            index_count: 0,
            file_size_bytes: 0,
            last_tx_id: 0,
        });

        let mut items = db.scan("");
        if !filter.is_empty() {
            items.retain(|(k, _)| k.to_lowercase().contains(&filter.to_lowercase()));
        }

        if selected_idx >= items.len() && !items.is_empty() {
            selected_idx = items.len() - 1;
        }

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header HUD
                    Constraint::Min(10),   // Main View (Keys + JSON)
                    Constraint::Length(3), // Status Bar / Filter
                ])
                .split(f.area());

            // 1. Header HUD
            let header_text = vec![Line::from(vec![
                Span::styled(
                    "💀 SKULLS & BONES // SOVEREIGN DB INSPECTOR",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" • "),
                Span::styled(
                    format!("Keys: {}", stats.key_count),
                    Style::default().fg(Color::Green),
                ),
                Span::raw(" • "),
                Span::styled(
                    format!("Size: {:.2} KB", stats.file_size_bytes as f64 / 1024.0),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(" • "),
                Span::styled(
                    format!("Indexes: {}", stats.index_count),
                    Style::default().fg(Color::Magenta),
                ),
            ])];
            let header = Paragraph::new(header_text)
                .block(Block::default().borders(Borders::ALL).title(" HUD "));
            f.render_widget(header, chunks[0]);

            // 2. Main split (Left: Key List, Right: JSON Preview)
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
                .split(chunks[1]);

            let list_items: Vec<ListItem> = items
                .iter()
                .enumerate()
                .map(|(i, (k, _))| {
                    let style = if i == selected_idx {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    ListItem::new(k.clone()).style(style)
                })
                .collect();

            let list = List::new(list_items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Keys (↑/↓ to select) "),
            );
            f.render_widget(list, main_chunks[0]);

            let right_text = if !items.is_empty() && selected_idx < items.len() {
                let (key, val) = &items[selected_idx];
                let formatted =
                    serde_json::to_string_pretty(val).unwrap_or_else(|_| "Invalid JSON".into());
                format!("Key: {}\n\n{}", key, formatted)
            } else {
                "No keys found in database.".to_string()
            };

            let preview = Paragraph::new(right_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Document Inspector "),
            );
            f.render_widget(preview, main_chunks[1]);

            // 3. Status Bar / Search Input
            let footer_content = if filter_mode {
                format!(
                    "Search Filter: {}█ (Press Enter to finish, Esc to clear)",
                    filter
                )
            } else {
                format!(
                    "Filter: '{}' | [q] Quit  [/] Search  [d] Delete  [c] Compact  [r] Refresh",
                    if filter.is_empty() { "none" } else { &filter }
                )
            };
            let footer = Paragraph::new(footer_content)
                .style(Style::default().fg(if filter_mode {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(footer, chunks[2]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if filter_mode {
                    match key.code {
                        KeyCode::Enter => filter_mode = false,
                        KeyCode::Esc => {
                            filter.clear();
                            filter_mode = false;
                        }
                        KeyCode::Backspace => {
                            filter.pop();
                        }
                        KeyCode::Char(c) => {
                            filter.push(c);
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => {
                            if selected_idx > 0 {
                                selected_idx -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !items.is_empty() && selected_idx < items.len() - 1 {
                                selected_idx += 1;
                            }
                        }
                        KeyCode::Char('/') => {
                            filter_mode = true;
                        }
                        KeyCode::Char('c') => {
                            let _ = db.compact();
                        }
                        KeyCode::Char('d') => {
                            if !items.is_empty() && selected_idx < items.len() {
                                let (k, _) = &items[selected_idx];
                                let _ = db.delete(k);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
