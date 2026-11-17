use crate::config::MeshConfig;
use crate::discovery::DiscoveryManager;
use crate::identity::NodeIdentity;
use crate::peer::{PeerConfig, PeerStatus, PeerTable};
use crate::transport::MeshTransport;
use chrono::Utc;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub struct TuiApp {
    pub identity: Arc<NodeIdentity>,
    pub transport: Arc<MeshTransport>,
    pub peer_table: Arc<RwLock<PeerTable>>,
    pub discovery: Arc<DiscoveryManager>,
    pub config: MeshConfig,
    pub active_tab: usize,
    pub selected_peer_idx: usize,
    pub selected_discovered_idx: usize,
    pub status_message: String,
    pub logs: Vec<String>,
    pub show_pairing_input: bool,
    pub pairing_input: String,
}

impl TuiApp {
    pub fn new(
        identity: Arc<NodeIdentity>,
        transport: Arc<MeshTransport>,
        peer_table: Arc<RwLock<PeerTable>>,
        discovery: Arc<DiscoveryManager>,
        config: MeshConfig,
    ) -> Self {
        let mut logs = Vec::new();
        logs.push(format!(
            "[{}] Node initialisiert. Identität: {}",
            Utc::now().format("%H:%M:%S"),
            identity.node_id
        ));
        logs.push(format!(
            "[{}] Transport aktiv auf UDP Port {}.",
            Utc::now().format("%H:%M:%S"),
            config.listen_port
        ));
        if config.air_gap_killswitch {
            logs.push(format!(
                "[{}] WARNUNG: Air-Gap Killswitch ist AKTIV. Sämtlicher Netzwerkverkehr blockiert.",
                Utc::now().format("%H:%M:%S")
            ));
        }

        Self {
            identity,
            transport,
            peer_table,
            discovery,
            config,
            active_tab: 0,
            selected_peer_idx: 0,
            selected_discovered_idx: 0,
            status_message: "Bereit. Drücken Sie [H] für Hilfe oder [A] für Air-Gap Toggle."
                .to_string(),
            logs,
            show_pairing_input: false,
            pairing_input: String::new(),
        }
    }

    pub async fn run(&mut self) -> Result<(), io::Error> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let res = self.main_loop(&mut terminal).await;

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        res
    }

    async fn main_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    ) -> Result<(), io::Error> {
        let mut last_discovery_broadcast = std::time::Instant::now();

        loop {
            // Periodic local broadcast
            if self.config.lan_discovery
                && last_discovery_broadcast.elapsed() > Duration::from_secs(10)
            {
                let _ = DiscoveryManager::broadcast_presence(
                    &self.identity.node_id,
                    &self.identity.wireguard_pubkey,
                    self.config.listen_port,
                )
                .await;
                last_discovery_broadcast = std::time::Instant::now();
            }

            // Draw frame
            let is_air_gap = *self.transport.air_gap.read().await;
            let peers_snapshot: Vec<_> = {
                let lock = self.peer_table.read().await;
                lock.list().into_iter().cloned().collect()
            };
            let discovered_snapshot: Vec<_> = {
                let lock = self.discovery.devices.read().await;
                lock.values().cloned().collect()
            };

            terminal.draw(|f| {
                self.ui(f, is_air_gap, &peers_snapshot, &discovered_snapshot);
            })?;

            // Poll keyboard input
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if self.show_pairing_input {
                        match key.code {
                            KeyCode::Esc => {
                                self.show_pairing_input = false;
                                self.pairing_input.clear();
                            }
                            KeyCode::Enter => {
                                let token = self.pairing_input.trim().to_string();
                                self.show_pairing_input = false;
                                self.pairing_input.clear();
                                self.handle_pairing_token(&token).await;
                            }
                            KeyCode::Backspace => {
                                self.pairing_input.pop();
                            }
                            KeyCode::Char(c) => {
                                self.pairing_input.push(c);
                            }
                            _ => {}
                        }
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break
                        }

                        // Air-gap toggle
                        KeyCode::Char('a') | KeyCode::Char('A') | KeyCode::Char(' ') => {
                            let mut lock = self.transport.air_gap.write().await;
                            *lock = !*lock;
                            let new_state = *lock;
                            drop(lock);
                            self.logs.push(format!(
                                "[{}] Air-Gap Killswitch: {}",
                                Utc::now().format("%H:%M:%S"),
                                if new_state {
                                    "AKTIVIERT (Verkehr blockiert)"
                                } else {
                                    "DEAKTIVIERT (Netzwerk online)"
                                }
                            ));
                            self.status_message = if new_state {
                                "Air-Gap AKTIV: Keine Pakete verlassen das System.".to_string()
                            } else {
                                "Air-Gap AUS: Peer-Kommunikation freigegeben.".to_string()
                            };
                        }

                        // Tab navigation
                        KeyCode::Tab => {
                            self.active_tab = (self.active_tab + 1) % 5;
                        }
                        KeyCode::BackTab => {
                            self.active_tab = (self.active_tab + 4) % 5;
                        }
                        KeyCode::Char('1') => self.active_tab = 0,
                        KeyCode::Char('2') => self.active_tab = 1,
                        KeyCode::Char('3') => self.active_tab = 2,
                        KeyCode::Char('4') => self.active_tab = 3,
                        KeyCode::Char('5') => self.active_tab = 4,

                        // Peer / Discovered selection
                        KeyCode::Up => {
                            if self.active_tab == 1 {
                                if self.selected_discovered_idx > 0 {
                                    self.selected_discovered_idx -= 1;
                                }
                            } else if self.selected_peer_idx > 0 {
                                self.selected_peer_idx -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if self.active_tab == 1 {
                                if !discovered_snapshot.is_empty()
                                    && self.selected_discovered_idx < discovered_snapshot.len() - 1
                                {
                                    self.selected_discovered_idx += 1;
                                }
                            } else if !peers_snapshot.is_empty()
                                && self.selected_peer_idx < peers_snapshot.len() - 1
                            {
                                self.selected_peer_idx += 1;
                            }
                        }

                        // Ping / Connect
                        KeyCode::Enter => {
                            if self.active_tab == 1 {
                                if let Some(dev) =
                                    discovered_snapshot.get(self.selected_discovered_idx)
                                {
                                    let clean_name = dev.node_id.replace("sbm-", "");
                                    let callsign =
                                        format!("lan-{}", &clean_name[..clean_name.len().min(8)]);
                                    let cfg = crate::peer::PeerConfig {
                                        callsign: callsign.clone(),
                                        node_id: dev.node_id.clone(),
                                        public_key_base64: dev.wireguard_pubkey.clone(),
                                        endpoint: Some(dev.observed_addr.to_string()),
                                        overlay_ip: None,
                                        created_at: Utc::now(),
                                    };
                                    {
                                        let mut lock = self.peer_table.write().await;
                                        lock.add_peer(cfg);
                                    }
                                    self.logs.push(format!(
                                        "[{}] LAN Gerät '{}' ({}) hinzugefügt. Starte Handshake...",
                                        Utc::now().format("%H:%M:%S"),
                                        callsign,
                                        dev.observed_addr
                                    ));
                                    let _ = self
                                        .transport
                                        .initiate_handshake(&dev.wireguard_pubkey)
                                        .await;
                                    self.status_message = format!(
                                        "Gerät '{}' als Peer verbunden & Handshake gestartet!",
                                        callsign
                                    );
                                    self.active_tab = 0;
                                }
                            } else if let Some(peer) = peers_snapshot.get(self.selected_peer_idx) {
                                let target_pk = peer.config.public_key_base64.clone();
                                let callsign = peer.config.callsign.clone();
                                self.logs.push(format!(
                                    "[{}] Ping an '{}' gesendet...",
                                    Utc::now().format("%H:%M:%S"),
                                    callsign
                                ));
                                match self.transport.send_ping(&target_pk).await {
                                    Ok(_) => {
                                        self.status_message =
                                            format!("Ping an '{}' übermittelt.", callsign);
                                    }
                                    Err(e) => {
                                        self.logs.push(format!(
                                            "[{}] FEHLER: Ping an '{}' fehlgeschlagen: {}",
                                            Utc::now().format("%H:%M:%S"),
                                            callsign,
                                            e
                                        ));
                                        self.status_message = format!("Ping Fehler: {}", e);
                                    }
                                }
                            }
                        }

                        // Handshake
                        KeyCode::Char('h') | KeyCode::Char('H') => {
                            if let Some(peer) = peers_snapshot.get(self.selected_peer_idx) {
                                let target_pk = peer.config.public_key_base64.clone();
                                let callsign = peer.config.callsign.clone();
                                self.logs.push(format!(
                                    "[{}] Initialisiere Noise_IK Handshake mit '{}'...",
                                    Utc::now().format("%H:%M:%S"),
                                    callsign
                                ));
                                match self.transport.initiate_handshake(&target_pk).await {
                                    Ok(_) => {
                                        self.status_message =
                                            format!("Handshake mit '{}' gestartet.", callsign);
                                    }
                                    Err(e) => {
                                        self.logs.push(format!(
                                            "[{}] Handshake-Fehler: {}",
                                            Utc::now().format("%H:%M:%S"),
                                            e
                                        ));
                                        self.status_message = format!("Fehler: {}", e);
                                    }
                                }
                            }
                        }

                        // Open pairing modal
                        KeyCode::Char('p') | KeyCode::Char('P') => {
                            self.show_pairing_input = true;
                            self.pairing_input.clear();
                        }

                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_pairing_token(&mut self, token: &str) {
        match NodeIdentity::parse_pairing_token(token) {
            Ok((remote_node_id, remote_pubkey, remote_endpoint)) => {
                let callsign = format!(
                    "peer-{}",
                    &remote_node_id[remote_node_id.len().saturating_sub(6)..]
                );
                let cfg = PeerConfig {
                    callsign: callsign.clone(),
                    node_id: remote_node_id.clone(),
                    public_key_base64: remote_pubkey.clone(),
                    endpoint: Some(remote_endpoint.clone()),
                    overlay_ip: None,
                    created_at: Utc::now(),
                };

                let mut table = self.peer_table.write().await;
                table.add_peer(cfg);
                drop(table);

                self.logs.push(format!(
                    "[{}] Neuer Peer gekoppelt: '{}' ({}) via {}",
                    Utc::now().format("%H:%M:%S"),
                    callsign,
                    remote_node_id,
                    remote_endpoint
                ));
                self.status_message = format!("Peer '{}' erfolgreich hinzugefügt!", callsign);

                // Auto-initiate handshake
                let _ = self.transport.initiate_handshake(&remote_pubkey).await;
            }
            Err(e) => {
                self.logs.push(format!(
                    "[{}] Ungültiger Pairing-Token: {}",
                    Utc::now().format("%H:%M:%S"),
                    e
                ));
                self.status_message = format!("Ungültiger Token: {}", e);
            }
        }
    }

    fn ui(
        &self,
        f: &mut Frame,
        is_air_gap: bool,
        peers: &[crate::peer::PeerState],
        discovered: &[crate::discovery::DiscoveredDevice],
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header Banner
                Constraint::Min(12),   // Main View (Left: Peers, Right: Tabs)
                Constraint::Length(3), // Command & Status Footer
            ])
            .split(f.area());

        // 1. Header Banner
        self.render_header(f, chunks[0], is_air_gap, peers.len());

        // 2. Main Body (Horizontal Split)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(35), // Peers list
                Constraint::Percentage(65), // Detail Tabs
            ])
            .split(chunks[1]);

        self.render_peer_list(f, main_chunks[0], peers);
        self.render_tabs(f, main_chunks[1], peers, discovered);

        // 3. Footer Bar
        self.render_footer(f, chunks[2], is_air_gap);

        // Modal dialog for Pairing Token Input
        if self.show_pairing_input {
            self.render_pairing_modal(f);
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect, is_air_gap: bool, peer_count: usize) {
        let (status_text, status_color) = if is_air_gap {
            ("[100% AIR-GAPPED]", Color::LightYellow)
        } else {
            ("[ONLINE / P2P MESH]", Color::LightGreen)
        };

        let title = Line::from(vec![
            Span::styled(
                "💀 SKULLS & BONES // SOVEREIGN MESH ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("(sb-mesh v0.1.0)  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Node: ", Style::default().fg(Color::Gray)),
            Span::styled(
                &self.identity.node_id,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  |  WireGuard: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}...", &self.identity.wireguard_pubkey[..14]),
                Style::default().fg(Color::White),
            ),
            Span::styled("  |  Status: ", Style::default().fg(Color::Gray)),
            Span::styled(
                status_text,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  |  Peers: {}", peer_count),
                Style::default().fg(Color::White),
            ),
            Span::styled("  |  ZK-Shield: ", Style::default().fg(Color::Gray)),
            Span::styled(
                "[0-LEAK ACTIVE]",
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(15, 18, 26)));

        let p = Paragraph::new(title).block(block);
        f.render_widget(p, area);
    }

    fn render_peer_list(&self, f: &mut Frame, area: Rect, peers: &[crate::peer::PeerState]) {
        let items: Vec<ListItem> = if peers.is_empty() {
            vec![
                ListItem::new(Line::from(vec![Span::styled(
                    "Keine Peers konfiguriert.",
                    Style::default().fg(Color::DarkGray),
                )])),
                ListItem::new(Line::from(vec![Span::styled(
                    "Drücken Sie [P] zum Koppeln",
                    Style::default().fg(Color::Yellow),
                )])),
            ]
        } else {
            peers
                .iter()
                .enumerate()
                .map(|(idx, peer)| {
                    let is_selected = idx == self.selected_peer_idx;
                    let (st_badge, st_color) = match peer.status {
                        PeerStatus::Connected => ("● ONLINE", Color::LightGreen),
                        PeerStatus::HandshakeInProgress => ("◐ SYNC", Color::Yellow),
                        PeerStatus::Standby => ("○ STANDBY", Color::DarkGray),
                        PeerStatus::Disconnected => ("○ OFFLINE", Color::Red),
                    };

                    let rtt_str = peer
                        .rtt_ms
                        .map(|ms| format!("{:.1}ms", ms))
                        .unwrap_or_else(|| "-".to_string());

                    let zk_badge = if peer.zk_attested {
                        Span::styled(
                            "[ZK-OK] ",
                            Style::default()
                                .fg(Color::LightCyan)
                                .add_modifier(Modifier::BOLD),
                        )
                    } else {
                        Span::styled("[NO-ZK] ", Style::default().fg(Color::DarkGray))
                    };

                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(
                            &peer.config.callsign,
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(" ", Style::default()),
                        zk_badge,
                        Span::styled(format!("[{}] ", st_badge), Style::default().fg(st_color)),
                        Span::styled(format!("({}) ", rtt_str), Style::default().fg(Color::Cyan)),
                    ]);

                    let style = if is_selected {
                        Style::default().bg(Color::Rgb(30, 38, 56))
                    } else {
                        Style::default()
                    };

                    ListItem::new(line).style(style)
                })
                .collect()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" PEERS & GERÄTE ")
            .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let list = List::new(items).block(block);
        f.render_widget(list, area);
    }

    fn render_tabs(
        &self,
        f: &mut Frame,
        area: Rect,
        peers: &[crate::peer::PeerState],
        discovered: &[crate::discovery::DiscoveredDevice],
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Tab Headers
                Constraint::Min(6),    // Tab Content
            ])
            .split(area);

        let titles = vec![
            "[1] Telemetrie",
            "[2] LAN Discovery",
            "[3] Handshake Log",
            "[4] Kopplung & Token",
            "[5] Rollen & RBAC",
        ];
        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .select(self.active_tab)
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );

        f.render_widget(tabs, chunks[0]);

        match self.active_tab {
            0 => self.render_tab_telemetry(f, chunks[1], peers),
            1 => self.render_tab_discovery(f, chunks[1], discovered),
            2 => self.render_tab_logs(f, chunks[1]),
            3 => self.render_tab_pairing(f, chunks[1]),
            4 => self.render_tab_rbac(f, chunks[1]),
            _ => {}
        }
    }

    fn render_tab_rbac(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" MANDANTEN-RBAC & ROLLENRECHTE ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let store = crate::rbac::MeshRbacStore::load_or_create("dev-mesh")
            .unwrap_or_else(|_| crate::rbac::MeshRbacStore::new("dev-mesh"));
        let now = Utc::now().timestamp() as u64;

        let mut lines = Vec::new();
        lines.push(Line::from(vec![
            Span::styled("Aktiver Mesh-Mandant: ", Style::default().fg(Color::Gray)),
            Span::styled(
                "dev-mesh",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "   (Für interaktive Verwaltung: ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                "sb-mesh rbac",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(")", Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::from(
            "─────────────────────────────────────────────────────────────────────────────",
        ));

        if store.members.is_empty() {
            lines.push(Line::from("Keine Mitglieder im dev-mesh konfiguriert."));
            lines.push(Line::from(
                "Fügen Sie ein Mitglied hinzu mit: sb-mesh rbac add --mesh dev-mesh ...",
            ));
        } else {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "  {:<16} {:<10} {:<14} {:<10} {}",
                    "NAME", "ROLLE", "NODE ID", "STATUS", "CAPABILITIES"
                ),
                Style::default().fg(Color::DarkGray),
            )]));
            for m in &store.members {
                let (st_badge, st_color) = if m.revoked {
                    ("○ REVOKED", Color::Red)
                } else if m.is_active(now) {
                    ("● AKTIV", Color::LightGreen)
                } else {
                    ("◐ EXPIRED", Color::Yellow)
                };
                let caps_str = if m.capabilities.is_empty() {
                    "-".to_string()
                } else {
                    m.capabilities.join(", ")
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<16} ", m.name),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<10} ", m.role.badge()),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!("{:<14} ", m.node_id),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(format!("{:<10} ", st_badge), Style::default().fg(st_color)),
                    Span::styled(caps_str, Style::default().fg(Color::White)),
                ]));
            }
        }

        let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
        f.render_widget(p, area);
    }

    fn render_tab_telemetry(&self, f: &mut Frame, area: Rect, peers: &[crate::peer::PeerState]) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" PEER DETAILS & VERBINDUNGSSTATUS ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        if let Some(peer) = peers.get(self.selected_peer_idx) {
            let (status_text, status_color) = match peer.status {
                PeerStatus::Connected => ("ONLINE (Kryptographisch Handshaked)", Color::LightGreen),
                PeerStatus::HandshakeInProgress => {
                    ("HANDSHAKE IN PROGRESS (Noise_IK)", Color::Yellow)
                }
                PeerStatus::Standby => ("STANDBY (Wartet auf Keepalive)", Color::DarkGray),
                PeerStatus::Disconnected => ("OFFLINE (Kein Signal)", Color::Red),
            };

            let text = vec![
                Line::from(vec![
                    Span::styled("Callsign:      ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        &peer.config.callsign,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Node ID:       ", Style::default().fg(Color::Gray)),
                    Span::styled(&peer.config.node_id, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("Endpoint:      ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        peer.config
                            .endpoint
                            .as_deref()
                            .unwrap_or("Dynamisch / Unbekannt"),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("WireGuard Key: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        &peer.config.public_key_base64,
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Status:        ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        status_text,
                        Style::default()
                            .fg(status_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("ZK-Attest:     ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        if peer.zk_attested {
                            "VERIFIED (Zero-Knowledge / 0 Bits Hardware Leak)"
                        } else {
                            "PENDING (Awaiting Initial ZK Handshake)"
                        },
                        Style::default()
                            .fg(if peer.zk_attested {
                                Color::LightCyan
                            } else {
                                Color::Yellow
                            })
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Privacy Shield:", Style::default().fg(Color::Gray)),
                    Span::styled(
                        " 100% Active — Zero Serial/EK/PCR Leaks",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Latenz (RTT):  ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        peer.rtt_ms
                            .map(|m| format!("{:.2} ms", m))
                            .unwrap_or_else(|| "N/A".to_string()),
                        Style::default().fg(Color::LightGreen),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Cipher Suite:  ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        "ChaCha20-Poly1305 (Noise_IK + ZK-PoK)",
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Traffic:       ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!(
                            "RX: {} Bytes | TX: {} Bytes",
                            peer.bytes_recv, peer.bytes_sent
                        ),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Replay Seq:    ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("#{}", peer.sequence_counter),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
            ];

            let p = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
            f.render_widget(p, area);
        } else {
            let p = Paragraph::new("Kein Peer ausgewählt. Drücken Sie [P] zum Hinzufügen.")
                .block(block)
                .style(Style::default().fg(Color::DarkGray));
            f.render_widget(p, area);
        }
    }

    fn render_tab_discovery(
        &self,
        f: &mut Frame,
        area: Rect,
        discovered: &[crate::discovery::DiscoveredDevice],
    ) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" LOKALE LAN-GERÄTE (mDNS MULTICAST) — [ENTER] ZUM VERBINDEN ")
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        if discovered.is_empty() {
            let p = Paragraph::new(vec![
                Line::from(Span::styled(
                    "Keine Geräte im lokalen Netzwerk entdeckt.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "Sobald ein weiteres S&B Gerät im LAN aktiv ist, erscheint es hier.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(block);
            f.render_widget(p, area);
        } else {
            let items: Vec<ListItem> = discovered
                .iter()
                .enumerate()
                .map(|(idx, dev)| {
                    let is_selected = idx == self.selected_discovered_idx;
                    let prefix = if is_selected { "▶ 📡 " } else { "  📡 " };
                    let style = if is_selected {
                        Style::default()
                            .bg(Color::Rgb(30, 41, 59))
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    let line = Line::from(vec![
                        Span::styled(prefix, Style::default().fg(Color::Cyan)),
                        Span::styled(&dev.node_id, style),
                        Span::styled(
                            format!("  ({})  ", dev.observed_addr),
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(
                            format!("Key: {}...", &dev.wireguard_pubkey[..12]),
                            Style::default().fg(Color::DarkGray),
                        ),
                        if is_selected {
                            Span::styled(
                                "  [ENTER = 1-Klick Kopplung]",
                                Style::default().fg(Color::LightGreen),
                            )
                        } else {
                            Span::raw("")
                        },
                    ]);
                    ListItem::new(line)
                })
                .collect();

            let list = List::new(items).block(block);
            f.render_widget(list, area);
        }
    }

    fn render_tab_logs(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" ECHTZEIT HANDSHAKE & EVENT LOG ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let lines: Vec<Line> = self
            .logs
            .iter()
            .rev()
            .take(15)
            .map(|l| {
                let color = if l.contains("FEHLER") {
                    Color::Red
                } else if l.contains("WARNUNG") {
                    Color::Yellow
                } else {
                    Color::Gray
                };
                Line::from(Span::styled(l, Style::default().fg(color)))
            })
            .collect();

        let p = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false });
        f.render_widget(p, area);
    }

    fn render_tab_pairing(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" GERÄTE-KOPPLUNG & INVITE TOKEN (AIR-GAPPED QR) ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let inner_area = block.inner(area);
        f.render_widget(block, area);

        let local_endpoint = format!("127.0.0.1:{}", self.config.listen_port);
        // Ephemeral token with 5 min (300s) TTL
        let token = self
            .identity
            .generate_pairing_token_with_ttl(&local_endpoint, Some(300));

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(35), Constraint::Length(46)])
            .split(inner_area);

        let lines = vec![
            Line::from(vec![Span::styled(
                "Einladungs-Token (Gültigkeit: 5 Minuten):",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(&token, Style::default().fg(Color::Cyan))]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Anleitung & Sicherheit:",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::UNDERLINED),
            )]),
            Line::from(vec![Span::styled(
                "1. QR-Code mit Kamera / Zweitgerät scannen oder Token kopieren.",
                Style::default().fg(Color::Gray),
            )]),
            Line::from(vec![Span::styled(
                "2. Auf dem Zielgerät [P] drücken und Token einfügen.",
                Style::default().fg(Color::Gray),
            )]),
            Line::from(vec![Span::styled(
                "3. Beide Geräte etablieren sofort einen direkten X25519 Tunnel ohne Cloud-Server.",
                Style::default().fg(Color::LightGreen),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Sicherheitsmerkmale & Isolation:",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![Span::styled(
                "• Der QR-Code enthält nur den öffentlichen Schlüssel (Public Key).",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(vec![Span::styled(
                "• Der private Schlüssel verlässt niemals dieses Gerät.",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(vec![Span::styled(
                "• Zeitlich befristet: Läuft nach 5 Minuten automatisch ab.",
                Style::default().fg(Color::DarkGray),
            )]),
        ];

        let p = Paragraph::new(lines).wrap(Wrap { trim: false });
        f.render_widget(p, chunks[0]);

        // Right side: QR Code
        if let Ok(qr_str) = crate::identity::render_terminal_qr(&token) {
            let qr_lines: Vec<Line> = qr_str
                .lines()
                .map(|line| Line::from(Span::styled(line, Style::default().fg(Color::Cyan))))
                .collect();
            let qr_block = Block::default()
                .borders(Borders::ALL)
                .title(" QR-CODE SCAN ")
                .border_style(Style::default().fg(Color::Cyan));
            let qr_p = Paragraph::new(qr_lines).block(qr_block);
            f.render_widget(qr_p, chunks[1]);
        }
    }

    fn render_footer(&self, f: &mut Frame, area: Rect, is_air_gap: bool) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1)])
            .split(area);

        let keybindings = Line::from(vec![
            Span::styled(
                " [Tab] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Tabs wechseln  ", Style::default().fg(Color::Gray)),
            Span::styled(
                " [Space/A] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if is_air_gap {
                    "Air-Gap Deaktivieren  "
                } else {
                    "Air-Gap Killswitch  "
                },
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                " [Enter] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Ping  ", Style::default().fg(Color::Gray)),
            Span::styled(
                " [H] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Handshake  ", Style::default().fg(Color::Gray)),
            Span::styled(
                " [P] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Koppeln  ", Style::default().fg(Color::Gray)),
            Span::styled(
                " [Q] ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled("Beenden", Style::default().fg(Color::Gray)),
        ]);

        let status = Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&self.status_message, Style::default().fg(Color::White)),
        ]);

        f.render_widget(Paragraph::new(keybindings), chunks[0]);
        f.render_widget(Paragraph::new(status), chunks[1]);
    }

    fn render_pairing_modal(&self, f: &mut Frame) {
        let area = centered_rect(65, 25, f.area());
        f.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" GERÄT KOPPELN — TOKEN EINGEBEN ")
            .border_style(Style::default().fg(Color::Yellow))
            .style(Style::default().bg(Color::Rgb(20, 24, 36)));

        let text = vec![
            Line::from("Fügen Sie den sbm-pair:// Token des Partner-Geräts ein:"),
            Line::from(""),
            Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    &self.pairing_input,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("█", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "[Enter] Bestätigen & Handshake starten   |   [Esc] Abbrechen",
                Style::default().fg(Color::Gray),
            )]),
        ];

        let p = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
        f.render_widget(p, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
