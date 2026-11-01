//! Ratatui TUI Dashboard — Live Pipeline Monitor & Operations Center
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
use std::io::{stdout, IsTerminal};
use std::time::{Duration, Instant};

use crate::audit::PipelineRunRecord;
use crate::config::{get_active_env, get_current_identity};
use crate::forge_toml::load_forge_toml;
use crate::secret::load_vault;

pub async fn run_tui() {
    if !stdout().is_terminal() {
        print_fallback_summary();
        return;
    }

    if let Err(e) = run_interactive_dashboard().await {
        eprintln!("Fehler im TUI-Dashboard: {}", e);
    }
}

fn print_fallback_summary() {
    use colored::*;
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "S&B FORGE".bright_blue().bold(),
        "//".bright_black(),
        "TUI DASHBOARD".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  Aktives Environment: {}",
        get_active_env().bright_yellow()
    );
    println!(
        "  Operator:           {}",
        get_current_identity().bright_white()
    );
    println!();
    println!("  Verfügbare Befehle:");
    println!("    sb-forge run <recipe>                      Recipe ausführen");
    println!("    sb-forge run --pipeline <name>             Pipeline starten");
    println!("    sb-forge exec --env <env> -- <cmd>         Prozess mit Secrets");
    println!("    sb-forge audit                             Audit-Log einsehen");
    println!("    sb-forge check                             Lifecycle-Check");
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
}

async fn run_interactive_dashboard() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut selected_index: usize = 0;
    let mut last_fetch = Instant::now() - Duration::from_secs(10);
    let mut cached_runs: Vec<PipelineRunRecord> = vec![];

    loop {
        // Cache alle 2 Sekunden oder bei Bedarf neu einlesen
        if last_fetch.elapsed() > Duration::from_secs(2) {
            let path = crate::config::get_forge_dir()
                .join("audit")
                .join("runs.jsonl");
            if path.exists() {
                if let Ok(file) = std::fs::File::open(&path) {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(file);
                    let mut runs: Vec<PipelineRunRecord> = reader
                        .lines()
                        .flatten()
                        .filter_map(|l| serde_json::from_str::<PipelineRunRecord>(&l).ok())
                        .collect();
                    runs.reverse();
                    runs.truncate(20);
                    cached_runs = runs;
                }
            }
            last_fetch = Instant::now();
        }

        let active_env = get_active_env();
        let operator = get_current_identity();
        let vault = load_vault(&active_env)
            .map_err(|error| format!("Gemeinsamer Vault konnte nicht geladen werden: {error}"))?;
        let secret_count = vault.secrets.len();
        let config_count = load_forge_toml()
            .ok()
            .and_then(|c| c.config.get(&active_env).map(|m| m.len()))
            .unwrap_or(0);

        if !cached_runs.is_empty() && selected_index >= cached_runs.len() {
            selected_index = cached_runs.len() - 1;
        }

        terminal.draw(|f| {
            let size = f.area();

            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header
                    Constraint::Min(8),    // Body
                    Constraint::Length(3), // Footer
                ])
                .split(size);

            // 1. Header
            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let header_text = vec![Line::from(vec![
                Span::styled(
                    " S&B FORGE ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    "LIVE OPERATIONS CENTER",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" │ Env: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("[{}]", active_env),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" │ Operator: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&operator, Style::default().fg(Color::Green)),
                Span::styled(format!(" │ {}", now), Style::default().fg(Color::DarkGray)),
            ])];

            let header_widget = Paragraph::new(header_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(header_widget, main_chunks[0]);

            // 2. Body Split (Links: Runs List, Rechts: Details & Status)
            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(main_chunks[1]);

            // Links: Recent Runs
            let items: Vec<ListItem> = if cached_runs.is_empty() {
                vec![ListItem::new("  Keine Pipeline-Runs aufgezeichnet")]
            } else {
                cached_runs
                    .iter()
                    .enumerate()
                    .map(|(idx, run)| {
                        let is_selected = idx == selected_index;
                        let status_badge = match run.status.as_str() {
                            "SUCCESS" => Span::styled(
                                "✓ OK  ",
                                Style::default()
                                    .fg(Color::Green)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            "FAILED" => Span::styled(
                                "✗ FAIL",
                                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                            ),
                            _ => Span::styled("● RUN ", Style::default().fg(Color::Yellow)),
                        };

                        let duration = format!("{:.2}s", run.duration_ms as f64 / 1000.0);
                        let name_span = Span::styled(
                            format!("{:<14}", run.pipeline_or_recipe),
                            Style::default().fg(Color::White),
                        );
                        let dur_span = Span::styled(
                            format!(" {:>6}", duration),
                            Style::default().fg(Color::Cyan),
                        );
                        let env_span = Span::styled(
                            format!(" [{}]", run.env),
                            Style::default().fg(Color::Yellow),
                        );

                        let mut line_spans =
                            vec![status_badge, Span::raw(" "), name_span, dur_span, env_span];
                        if is_selected {
                            line_spans.insert(
                                0,
                                Span::styled(
                                    "► ",
                                    Style::default()
                                        .fg(Color::Cyan)
                                        .add_modifier(Modifier::BOLD),
                                ),
                            );
                        } else {
                            line_spans.insert(0, Span::raw("  "));
                        }

                        let item = ListItem::new(Line::from(line_spans));
                        if is_selected {
                            item.style(Style::default().bg(Color::Rgb(20, 30, 45)))
                        } else {
                            item
                        }
                    })
                    .collect()
            };

            let list_widget = List::new(items).block(
                Block::default()
                    .title(" Pipeline- & Recipe-Historie ")
                    .title_style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(list_widget, body_chunks[0]);

            // Rechts Split (Oben: Run Details, Unten: Project / Vault Info)
            let right_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(body_chunks[1]);

            // Details des ausgewählten Runs
            let detail_text = if let Some(selected_run) = cached_runs.get(selected_index) {
                vec![
                    Line::from(vec![
                        Span::styled("Run ID:        ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            &selected_run.run_id,
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Task/Pipeline: ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            &selected_run.pipeline_or_recipe,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(if selected_run.is_pipeline {
                            " (Pipeline)"
                        } else {
                            " (Recipe)"
                        }),
                    ]),
                    Line::from(vec![
                        Span::styled("Status:        ", Style::default().fg(Color::DarkGray)),
                        match selected_run.status.as_str() {
                            "SUCCESS" => Span::styled(
                                "ERFOLGREICH",
                                Style::default()
                                    .fg(Color::Green)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            "FAILED" => Span::styled(
                                "FEHLGESCHLAGEN",
                                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                            ),
                            _ => Span::styled(
                                &selected_run.status,
                                Style::default().fg(Color::Yellow),
                            ),
                        },
                    ]),
                    Line::from(vec![
                        Span::styled("Environment:   ", Style::default().fg(Color::DarkGray)),
                        Span::styled(&selected_run.env, Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(vec![
                        Span::styled("Operator:      ", Style::default().fg(Color::DarkGray)),
                        Span::styled(&selected_run.user, Style::default().fg(Color::White)),
                    ]),
                    Line::from(vec![
                        Span::styled("Dauer:         ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            format!("{:.3} Sekunden", selected_run.duration_ms as f64 / 1000.0),
                            Style::default().fg(Color::Cyan),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Stages:        ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            format!(
                                "{}/{} abgeschlossen",
                                selected_run.stages_passed, selected_run.stages_total
                            ),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Ausgeführt am: ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            selected_run
                                .started_at
                                .format("%Y-%m-%d %H:%M:%S UTC")
                                .to_string(),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]),
                ]
            } else {
                vec![Line::from("Kein Run ausgewählt")]
            };

            let detail_widget = Paragraph::new(detail_text).block(
                Block::default()
                    .title(" Run Details ")
                    .title_style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(detail_widget, right_chunks[0]);

            // Projekt & Vault Status
            let vault_text = vec![
                Line::from(vec![
                    Span::styled("Vault-Status:      ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{} Secrets verschlüsselt in [{}]", secret_count, active_env),
                        Style::default().fg(Color::Green),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Config-Variablen:  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{} Variablen in Forge.toml", config_count),
                        Style::default().fg(Color::Cyan),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Secret-Schutz:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        "Projekt-Scan bei Bedarf: sb-forge scan",
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Krypto-Engine:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        "AES-256-GCM + argon2 (Zero Plaintext on Disk)",
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
            ];

            let vault_widget = Paragraph::new(vault_text).block(
                Block::default()
                    .title(" Environment & Security Status ")
                    .title_style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(vault_widget, right_chunks[1]);

            // 3. Footer
            let footer_text = vec![Line::from(vec![
                Span::styled(
                    " [↑/↓] ",
                    Style::default().fg(Color::Black).bg(Color::DarkGray),
                ),
                Span::raw(" Navigieren  "),
                Span::styled(
                    " [R] ",
                    Style::default().fg(Color::Black).bg(Color::DarkGray),
                ),
                Span::raw(" Aktualisieren  "),
                Span::styled(
                    " [Q / Esc] ",
                    Style::default().fg(Color::Black).bg(Color::DarkGray),
                ),
                Span::raw(" Beenden  "),
                Span::styled(
                    " │ S&B Forge v0.1.0 (Autark & MIT)",
                    Style::default().fg(Color::DarkGray),
                ),
            ])];

            let footer_widget = Paragraph::new(footer_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(footer_widget, main_chunks[2]);
        })?;

        // Event Handling
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected_index = selected_index.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !cached_runs.is_empty() && selected_index + 1 < cached_runs.len() {
                            selected_index += 1;
                        }
                    }
                    KeyCode::Char('r') => {
                        last_fetch = Instant::now() - Duration::from_secs(10);
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
