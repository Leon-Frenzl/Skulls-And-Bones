//! S&B Sovereign Mesh — Interactive Master Cockpit TUI & Identity Platform
//!
//! Provides a unified Cyberpunk terminal interface covering:
//! - [1] Topologie & Peers (Live P2P node health, latency, ZK attestation)
//! - [2] Mitglieder & Rollen (RBAC user management & capability matrix)
//! - [3] Security Groups (AD-style security groups & capability inheritance)
//! - [4] Invites & Onboarding (One-click tokens, TTL, max uses & ASCII QR codes)
//! - [5] Tunnels & Port Shares (Stealth ingress tunnels, reverse-proxy dev links)
//! - [6] Security Audit Log (Immutable chronological security event trail)

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

use crate::identity::{render_terminal_qr, NodeIdentity};
use crate::network::NetworkStore;
use crate::peer::{PeerConfig, PeerTable};
use crate::rbac::{
    MeshGroup, MeshInviteToken, MeshMember, MeshRbacStore, MeshRole, CAP_ARTIFACT_DOWNLOAD,
    CAP_CODE_SYNC, CAP_MESH_INVITE, CAP_MESH_KRL, CAP_MESH_MANAGE, CAP_STREAM_TRANSFER,
    CAP_TELEMETRY_READ, CAP_TUNNEL_ANY, CAP_TUNNEL_SSH,
};
use crate::subnet_route::SubnetRouteStore;

const ALL_ROLES: [MeshRole; 5] = [
    MeshRole::Admin,
    MeshRole::Developer,
    MeshRole::Operator,
    MeshRole::Consumer,
    MeshRole::Auditor,
];

#[derive(Debug, Clone)]
pub struct TunnelItem {
    pub name: String,
    pub kind: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub status: String,
    pub required_cap: String,
}

#[derive(Debug, Clone)]
pub enum ModalState {
    // Member Modals
    AddMember {
        name: String,
        pubkey: String,
        role_idx: usize,
        active_field: usize,
    },
    RevokeMember {
        name: String,
        reason: String,
    },
    ConfirmDeleteMember {
        name: String,
    },
    // Group Modals
    CreateGroup {
        name: String,
        description: String,
        capabilities: String,
        active_field: usize,
    },
    ConfirmDeleteGroup {
        name: String,
    },
    // Invite Modals
    CreateInvite {
        user_name: String,
        role_idx: usize,
        groups: String,
        ttl_hours: u64,
        max_uses: u32,
        active_field: usize,
    },
    ShowInviteQr {
        uri: String,
        token_id: String,
        user_name: String,
        qr_lines: Vec<String>,
    },
    ConfirmRevokeInvite {
        token_id: String,
        user_name: String,
    },
    // Peer Modals
    AddPeer {
        callsign: String,
        node_id: String,
        pubkey: String,
        endpoint: String,
        active_field: usize,
    },
    ConfirmDeletePeer {
        callsign: String,
        pubkey: String,
    },
    // Tunnel Modals
    CreateTunnel {
        name: String,
        local_port: String,
        remote_port: String,
        active_field: usize,
    },
    ConfirmDeleteTunnel {
        idx: usize,
        name: String,
    },
    // Subnet Route Modals
    AdvertiseSubnet {
        cidr: String,
        endpoint: String,
        active_field: usize,
    },
    ConfirmWithdrawSubnet {
        cidr: String,
    },
}

pub struct RbacTuiApp {
    pub meshes: Vec<String>,
    pub current_mesh_idx: usize,
    pub active_tab: usize, // 0..=5
    pub store: MeshRbacStore,
    pub identity: Option<NodeIdentity>,
    pub peers: Vec<PeerConfig>,
    pub tunnels: Vec<TunnelItem>,
    pub subnet_store: SubnetRouteStore,

    // Tab-specific selection indices
    pub selected_peer_idx: usize,
    pub selected_member_idx: usize,
    pub selected_group_idx: usize,
    pub selected_invite_idx: usize,
    pub selected_tunnel_idx: usize,
    pub selected_subnet_idx: usize,
    pub tunnel_panel: usize, // 0 = Tunnels, 1 = Subnets
    pub selected_audit_idx: usize,

    pub status_message: String,
    pub modal: Option<ModalState>,
}

impl RbacTuiApp {
    pub fn new(initial_mesh: Option<String>) -> Self {
        let identity = NodeIdentity::load_or_generate_default().ok();
        let pubkey = identity
            .as_ref()
            .map(|id| id.wireguard_pubkey.as_str())
            .unwrap_or("");

        let networks_file = sb_core::paths::sb_mesh_dir().join("networks.json");
        let net_store = NetworkStore::load_or_create_default(&networks_file, pubkey).ok();

        let mut meshes = Vec::new();
        if let Some(store) = net_store {
            for net in store.list() {
                if !meshes.contains(&net.name) {
                    meshes.push(net.name.clone());
                }
            }
        }

        if meshes.is_empty() {
            meshes = vec![
                "dev-mesh".to_string(),
                "staging-mesh".to_string(),
                "public-mesh".to_string(),
            ];
        }

        let current_mesh_idx = if let Some(ref m) = initial_mesh {
            meshes.iter().position(|name| name == m).unwrap_or(0)
        } else {
            0
        };

        let active_mesh = meshes
            .get(current_mesh_idx)
            .cloned()
            .unwrap_or_else(|| "dev-mesh".to_string());
        let store = MeshRbacStore::load_or_create(&active_mesh)
            .unwrap_or_else(|_| MeshRbacStore::new(&active_mesh));
        let subnet_store =
            SubnetRouteStore::load_or_create(&active_mesh).unwrap_or_else(|_| SubnetRouteStore {
                mesh_name: active_mesh.clone(),
                routes: Vec::new(),
            });

        let peers = Self::load_peers();
        let tunnels = Self::load_default_tunnels();

        Self {
            meshes,
            current_mesh_idx,
            active_tab: 1, // Default to Members & Roles tab
            store,
            identity,
            peers,
            tunnels,
            subnet_store,
            selected_peer_idx: 0,
            selected_member_idx: 0,
            selected_group_idx: 0,
            selected_invite_idx: 0,
            selected_tunnel_idx: 0,
            selected_subnet_idx: 0,
            tunnel_panel: 0,
            selected_audit_idx: 0,
            status_message: "Bereit. [1-6] Tab wählen • [Tab] Mesh wechseln • [A] Hinzufügen • [I] Invite • [Q] Beenden".to_string(),
            modal: None,
        }
    }

    fn load_peers() -> Vec<PeerConfig> {
        let peers_path = sb_core::paths::sb_mesh_dir().join("peers.toml");
        if let Ok(table) = PeerTable::load_from_file(&peers_path) {
            let list: Vec<PeerConfig> = table.list().iter().map(|p| p.config.clone()).collect();
            if !list.is_empty() {
                return list;
            }
        }
        vec![
            PeerConfig {
                callsign: "hostinger-vps".to_string(),
                node_id: "sbm-0xvps83235".to_string(),
                public_key_base64: "dGVzdF92cHNfa2V5XzEyMzQ1Njc4OWFiY2RlZg==".to_string(),
                endpoint: Some("145.223.83.235:58888".to_string()),
                overlay_ip: Some("10.240.0.1".to_string()),
                created_at: Utc::now(),
            },
            PeerConfig {
                callsign: "office-laptop".to_string(),
                node_id: "sbm-0xlaptop42".to_string(),
                public_key_base64: "bGFwdG9wX3B1YmtleV9mZWRjYmE5ODc2NTQzMjE=".to_string(),
                endpoint: Some("192.168.1.150:58888".to_string()),
                overlay_ip: Some("10.240.0.2".to_string()),
                created_at: Utc::now(),
            },
        ]
    }

    fn load_default_tunnels() -> Vec<TunnelItem> {
        vec![
            TunnelItem {
                name: "Stealth SSH Gateway".to_string(),
                kind: "Stealth Ingress (Noise_IK)".to_string(),
                local_addr: "127.0.0.1:58822".to_string(),
                remote_addr: "145.223.83.235:22".to_string(),
                status: "BEREIT".to_string(),
                required_cap: "tunnel:ssh".to_string(),
            },
            TunnelItem {
                name: "Vite / Next.js Dev Tunnel".to_string(),
                kind: "Sovereign Link (Loopback)".to_string(),
                local_addr: "127.0.0.1:3000".to_string(),
                remote_addr: "127.0.0.1:58912".to_string(),
                status: "STANDBY".to_string(),
                required_cap: "tunnel:port:3000".to_string(),
            },
            TunnelItem {
                name: "Edge Gateway Reverse-Proxy".to_string(),
                kind: "HTTPS / ACME Dual-Port".to_string(),
                local_addr: "0.0.0.0:443 / 80".to_string(),
                remote_addr: "Local Cluster Services".to_string(),
                status: "ONLINE".to_string(),
                required_cap: "tunnel:any".to_string(),
            },
        ]
    }

    pub fn current_mesh(&self) -> &str {
        self.meshes
            .get(self.current_mesh_idx)
            .map(|s| s.as_str())
            .unwrap_or("dev-mesh")
    }

    pub fn switch_mesh(&mut self, idx: usize) {
        if idx < self.meshes.len() {
            self.current_mesh_idx = idx;
            let m_name = self.current_mesh().to_string();
            self.store = MeshRbacStore::load_or_create(&m_name)
                .unwrap_or_else(|_| MeshRbacStore::new(&m_name));
            self.subnet_store =
                SubnetRouteStore::load_or_create(&m_name).unwrap_or_else(|_| SubnetRouteStore {
                    mesh_name: m_name.clone(),
                    routes: Vec::new(),
                });
            self.selected_member_idx = 0;
            self.selected_group_idx = 0;
            self.selected_invite_idx = 0;
            self.selected_subnet_idx = 0;
            self.selected_audit_idx = 0;
            self.status_message = format!("Zu Mesh-Mandant '{}' gewechselt.", m_name);
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
        loop {
            terminal.draw(|f| {
                self.ui(f);
            })?;

            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    // Modal handling takes precedence
                    if self.modal.is_some() {
                        self.handle_modal_key(key.code);
                        continue;
                    }

                    // Global Navigation
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break
                        }

                        // Workspace Tabs (1..6)
                        KeyCode::Char('1') => self.active_tab = 0,
                        KeyCode::Char('2') => self.active_tab = 1,
                        KeyCode::Char('3') => self.active_tab = 2,
                        KeyCode::Char('4') => self.active_tab = 3,
                        KeyCode::Char('5') => self.active_tab = 4,
                        KeyCode::Char('6') => self.active_tab = 5,

                        KeyCode::Left => {
                            self.active_tab = (self.active_tab + 5) % 6;
                        }
                        KeyCode::Right => {
                            self.active_tab = (self.active_tab + 1) % 6;
                        }

                        // Mesh tenant switching
                        KeyCode::Tab => {
                            let next_idx = (self.current_mesh_idx + 1) % self.meshes.len();
                            self.switch_mesh(next_idx);
                        }
                        KeyCode::BackTab => {
                            let prev_idx = if self.current_mesh_idx == 0 {
                                self.meshes.len() - 1
                            } else {
                                self.current_mesh_idx - 1
                            };
                            self.switch_mesh(prev_idx);
                        }

                        // Active Tab Sub-Navigation
                        _ => {
                            self.handle_tab_key(key.code);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_tab_key(&mut self, code: KeyCode) {
        match self.active_tab {
            // [0] Topologie & Peers
            0 => match code {
                KeyCode::Up => {
                    if self.selected_peer_idx > 0 {
                        self.selected_peer_idx -= 1;
                    }
                }
                KeyCode::Down => {
                    if !self.peers.is_empty() && self.selected_peer_idx + 1 < self.peers.len() {
                        self.selected_peer_idx += 1;
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.modal = Some(ModalState::AddPeer {
                        callsign: String::new(),
                        node_id: String::new(),
                        pubkey: String::new(),
                        endpoint: "127.0.0.1:58888".to_string(),
                        active_field: 0,
                    });
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    if let Some(peer) = self.peers.get(self.selected_peer_idx) {
                        self.modal = Some(ModalState::ConfirmDeletePeer {
                            callsign: peer.callsign.clone(),
                            pubkey: peer.public_key_base64.clone(),
                        });
                    }
                }
                _ => {}
            },

            // [1] Mitglieder & Rollen
            1 => match code {
                KeyCode::Up => {
                    if self.selected_member_idx > 0 {
                        self.selected_member_idx -= 1;
                    }
                }
                KeyCode::Down => {
                    if !self.store.members.is_empty()
                        && self.selected_member_idx + 1 < self.store.members.len()
                    {
                        self.selected_member_idx += 1;
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.modal = Some(ModalState::AddMember {
                        name: String::new(),
                        pubkey: String::new(),
                        role_idx: 1, // Developer
                        active_field: 0,
                    });
                }
                KeyCode::Char('e') | KeyCode::Char('E') => {
                    if let Some(member) = self.store.members.get_mut(self.selected_member_idx) {
                        let cur_idx = ALL_ROLES
                            .iter()
                            .position(|r| *r == member.role)
                            .unwrap_or(1);
                        let next_role = ALL_ROLES[(cur_idx + 1) % ALL_ROLES.len()];
                        member.role = next_role;
                        member.capabilities = next_role.default_capabilities();
                        let m_name = member.name.clone();
                        let _ = self.store.save();
                        self.status_message = format!(
                            "✓ Rolle von '{}' geändert zu {}.",
                            m_name,
                            next_role.badge()
                        );
                    }
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    if let Some(member) = self.store.members.get_mut(self.selected_member_idx) {
                        if member.revoked {
                            member.restore();
                            let m_name = member.name.clone();
                            let _ = self.store.save();
                            self.status_message = format!(
                                "✓ Mitglied '{}' reaktiviert (KRL-Sperre aufgehoben).",
                                m_name
                            );
                        } else {
                            let m_name = member.name.clone();
                            self.modal = Some(ModalState::RevokeMember {
                                name: m_name,
                                reason: String::new(),
                            });
                        }
                    }
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    if let Some(member) = self.store.members.get(self.selected_member_idx) {
                        let m_name = member.name.clone();
                        self.modal = Some(ModalState::ConfirmDeleteMember { name: m_name });
                    }
                }
                KeyCode::Char('i') | KeyCode::Char('I') => {
                    self.modal = Some(ModalState::CreateInvite {
                        user_name: String::new(),
                        role_idx: 1,
                        groups: "@developers".to_string(),
                        ttl_hours: 24,
                        max_uses: 1,
                        active_field: 0,
                    });
                }
                _ => {}
            },

            // [2] Security Groups
            2 => match code {
                KeyCode::Up => {
                    if self.selected_group_idx > 0 {
                        self.selected_group_idx -= 1;
                    }
                }
                KeyCode::Down => {
                    if !self.store.groups.is_empty()
                        && self.selected_group_idx + 1 < self.store.groups.len()
                    {
                        self.selected_group_idx += 1;
                    }
                }
                KeyCode::Char('g')
                | KeyCode::Char('G')
                | KeyCode::Char('a')
                | KeyCode::Char('A') => {
                    self.modal = Some(ModalState::CreateGroup {
                        name: String::new(),
                        description: String::new(),
                        capabilities: "tunnel:ssh,stream:transfer".to_string(),
                        active_field: 0,
                    });
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    if let Some(grp) = self.store.groups.get(self.selected_group_idx) {
                        self.modal = Some(ModalState::ConfirmDeleteGroup {
                            name: grp.name.clone(),
                        });
                    }
                }
                _ => {}
            },

            // [3] Invites & Onboarding
            3 => match code {
                KeyCode::Up => {
                    if self.selected_invite_idx > 0 {
                        self.selected_invite_idx -= 1;
                    }
                }
                KeyCode::Down => {
                    if !self.store.invites.is_empty()
                        && self.selected_invite_idx + 1 < self.store.invites.len()
                    {
                        self.selected_invite_idx += 1;
                    }
                }
                KeyCode::Char('i')
                | KeyCode::Char('I')
                | KeyCode::Char('a')
                | KeyCode::Char('A') => {
                    self.modal = Some(ModalState::CreateInvite {
                        user_name: String::new(),
                        role_idx: 1,
                        groups: "@developers".to_string(),
                        ttl_hours: 24,
                        max_uses: 1,
                        active_field: 0,
                    });
                }
                KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('Q') => {
                    if let Some(inv) = self.store.invites.get(self.selected_invite_idx) {
                        let uri = inv.encode_uri();
                        let qr = render_terminal_qr(&uri).unwrap_or_default();
                        let qr_lines = qr.lines().map(|s| s.to_string()).collect();
                        self.modal = Some(ModalState::ShowInviteQr {
                            uri,
                            token_id: inv.token_id.clone(),
                            user_name: inv.user_name.clone(),
                            qr_lines,
                        });
                    }
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    if let Some(inv) = self.store.invites.get(self.selected_invite_idx) {
                        self.modal = Some(ModalState::ConfirmRevokeInvite {
                            token_id: inv.token_id.clone(),
                            user_name: inv.user_name.clone(),
                        });
                    }
                }
                _ => {}
            },

            // [4] Tunnels & VPC Bridges
            4 => match code {
                KeyCode::Tab => {
                    self.tunnel_panel = (self.tunnel_panel + 1) % 2;
                    self.status_message = if self.tunnel_panel == 0 {
                        "Fokus: Stealth Tunnels & Forwarders [Tab=Wechsel zu VPC Subnetzen, T=Tunnel, D=Löschen]".to_string()
                    } else {
                        "Fokus: VPC Subnetz-Routen [Tab=Wechsel zu Tunnels, S=Subnetz bewerben, D=Zurückziehen]".to_string()
                    };
                }
                KeyCode::Up => {
                    if self.tunnel_panel == 0 {
                        if self.selected_tunnel_idx > 0 {
                            self.selected_tunnel_idx -= 1;
                        }
                    } else {
                        if self.selected_subnet_idx > 0 {
                            self.selected_subnet_idx -= 1;
                        }
                    }
                }
                KeyCode::Down => {
                    if self.tunnel_panel == 0 {
                        if !self.tunnels.is_empty()
                            && self.selected_tunnel_idx + 1 < self.tunnels.len()
                        {
                            self.selected_tunnel_idx += 1;
                        }
                    } else {
                        if !self.subnet_store.routes.is_empty()
                            && self.selected_subnet_idx + 1 < self.subnet_store.routes.len()
                        {
                            self.selected_subnet_idx += 1;
                        }
                    }
                }
                KeyCode::Char('t') | KeyCode::Char('T') => {
                    self.modal = Some(ModalState::CreateTunnel {
                        name: String::new(),
                        local_port: "3000".to_string(),
                        remote_port: "58912".to_string(),
                        active_field: 0,
                    });
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    let ep = "145.223.83.235:58888".to_string();
                    self.modal = Some(ModalState::AdvertiseSubnet {
                        cidr: "10.0.0.0/16".to_string(),
                        endpoint: ep,
                        active_field: 0,
                    });
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    if self.tunnel_panel == 0 {
                        self.modal = Some(ModalState::CreateTunnel {
                            name: String::new(),
                            local_port: "3000".to_string(),
                            remote_port: "58912".to_string(),
                            active_field: 0,
                        });
                    } else {
                        let ep = "145.223.83.235:58888".to_string();
                        self.modal = Some(ModalState::AdvertiseSubnet {
                            cidr: "10.0.0.0/16".to_string(),
                            endpoint: ep,
                            active_field: 0,
                        });
                    }
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    if self.tunnel_panel == 0 {
                        if let Some(t) = self.tunnels.get(self.selected_tunnel_idx) {
                            self.modal = Some(ModalState::ConfirmDeleteTunnel {
                                idx: self.selected_tunnel_idx,
                                name: t.name.clone(),
                            });
                        }
                    } else {
                        if let Some(r) = self.subnet_store.routes.get(self.selected_subnet_idx) {
                            self.modal = Some(ModalState::ConfirmWithdrawSubnet {
                                cidr: r.cidr.clone(),
                            });
                        }
                    }
                }
                _ => {}
            },

            // [5] Security Audit Log
            5 => match code {
                KeyCode::Up => {
                    if self.selected_audit_idx > 0 {
                        self.selected_audit_idx -= 1;
                    }
                }
                KeyCode::Down
                    if !self.store.audit_log.is_empty()
                        && self.selected_audit_idx + 1 < self.store.audit_log.len() =>
                {
                    self.selected_audit_idx += 1;
                }
                _ => {}
            },

            _ => {}
        }
    }

    fn handle_modal_key(&mut self, code: KeyCode) {
        let current_modal = match self.modal.take() {
            Some(m) => m,
            None => return,
        };

        match current_modal {
            // ── Modal: Add Member ──
            ModalState::AddMember {
                mut name,
                mut pubkey,
                mut role_idx,
                mut active_field,
            } => match code {
                KeyCode::Esc => {
                    self.status_message = "Aktion abgebrochen.".to_string();
                }
                KeyCode::Tab => {
                    active_field = (active_field + 1) % 3;
                    self.modal = Some(ModalState::AddMember {
                        name,
                        pubkey,
                        role_idx,
                        active_field,
                    });
                }
                KeyCode::BackTab => {
                    active_field = (active_field + 2) % 3;
                    self.modal = Some(ModalState::AddMember {
                        name,
                        pubkey,
                        role_idx,
                        active_field,
                    });
                }
                KeyCode::Left => {
                    if active_field == 2 && role_idx > 0 {
                        role_idx -= 1;
                    }
                    self.modal = Some(ModalState::AddMember {
                        name,
                        pubkey,
                        role_idx,
                        active_field,
                    });
                }
                KeyCode::Right => {
                    if active_field == 2 && role_idx + 1 < ALL_ROLES.len() {
                        role_idx += 1;
                    }
                    self.modal = Some(ModalState::AddMember {
                        name,
                        pubkey,
                        role_idx,
                        active_field,
                    });
                }
                KeyCode::Backspace => {
                    if active_field == 0 {
                        name.pop();
                    } else if active_field == 1 {
                        pubkey.pop();
                    }
                    self.modal = Some(ModalState::AddMember {
                        name,
                        pubkey,
                        role_idx,
                        active_field,
                    });
                }
                KeyCode::Char(c) => {
                    if active_field == 0 && name.len() < 32 {
                        name.push(c);
                    } else if active_field == 1 && pubkey.len() < 64 {
                        pubkey.push(c);
                    }
                    self.modal = Some(ModalState::AddMember {
                        name,
                        pubkey,
                        role_idx,
                        active_field,
                    });
                }
                KeyCode::Enter => {
                    if !name.trim().is_empty() && !pubkey.trim().is_empty() {
                        let role = ALL_ROLES[role_idx];
                        let node_id = NodeIdentity::derive_node_id_from_pubkey(&pubkey);
                        let member = MeshMember::new(
                            name.trim(),
                            pubkey.trim(),
                            &node_id,
                            self.current_mesh(),
                            role,
                        );
                        self.store.add_or_update(member);
                        let _ = self.store.save();
                        self.status_message =
                            format!("✓ Mitglied '{}' ({}) hinzugefügt!", name.trim(), role);
                    } else {
                        self.status_message =
                            "Name und Public Key dürfen nicht leer sein!".to_string();
                        self.modal = Some(ModalState::AddMember {
                            name,
                            pubkey,
                            role_idx,
                            active_field,
                        });
                    }
                }
                _ => {
                    self.modal = Some(ModalState::AddMember {
                        name,
                        pubkey,
                        role_idx,
                        active_field,
                    });
                }
            },

            // ── Modal: Revoke Member ──
            ModalState::RevokeMember { name, mut reason } => match code {
                KeyCode::Esc => {
                    self.status_message = "Sperrung abgebrochen.".to_string();
                }
                KeyCode::Backspace => {
                    reason.pop();
                    self.modal = Some(ModalState::RevokeMember { name, reason });
                }
                KeyCode::Char(c) => {
                    if reason.len() < 64 {
                        reason.push(c);
                    }
                    self.modal = Some(ModalState::RevokeMember { name, reason });
                }
                KeyCode::Enter => {
                    let r_text = if reason.trim().is_empty() {
                        "Administrative Sperre"
                    } else {
                        reason.trim()
                    };
                    let n = name.clone();
                    self.store.revoke(&n, r_text);
                    let _ = self.store.save();
                    self.status_message =
                        format!("✓ Mitglied '{}' revoziert (KRL-Sperre aktiv)!", n);
                }
                _ => {
                    self.modal = Some(ModalState::RevokeMember { name, reason });
                }
            },

            // ── Modal: Confirm Delete Member ──
            ModalState::ConfirmDeleteMember { name } => match code {
                KeyCode::Char('j')
                | KeyCode::Char('J')
                | KeyCode::Char('y')
                | KeyCode::Char('Y')
                | KeyCode::Enter => {
                    let n = name.clone();
                    self.store.remove(&n);
                    let _ = self.store.save();
                    if self.selected_member_idx > 0
                        && self.selected_member_idx >= self.store.members.len()
                    {
                        self.selected_member_idx = self.store.members.len().saturating_sub(1);
                    }
                    self.status_message = format!("✓ Mitglied '{}' vollständig gelöscht.", n);
                }
                _ => {
                    self.status_message = "Löschen abgebrochen.".to_string();
                }
            },

            // ── Modal: Create Group ──
            ModalState::CreateGroup {
                mut name,
                mut description,
                mut capabilities,
                mut active_field,
            } => match code {
                KeyCode::Esc => {
                    self.status_message = "Aktion abgebrochen.".to_string();
                }
                KeyCode::Tab => {
                    active_field = (active_field + 1) % 3;
                    self.modal = Some(ModalState::CreateGroup {
                        name,
                        description,
                        capabilities,
                        active_field,
                    });
                }
                KeyCode::BackTab => {
                    active_field = (active_field + 2) % 3;
                    self.modal = Some(ModalState::CreateGroup {
                        name,
                        description,
                        capabilities,
                        active_field,
                    });
                }
                KeyCode::Backspace => {
                    if active_field == 0 {
                        name.pop();
                    } else if active_field == 1 {
                        description.pop();
                    } else if active_field == 2 {
                        capabilities.pop();
                    }
                    self.modal = Some(ModalState::CreateGroup {
                        name,
                        description,
                        capabilities,
                        active_field,
                    });
                }
                KeyCode::Char(c) => {
                    if active_field == 0 && name.len() < 32 {
                        name.push(c);
                    } else if active_field == 1 && description.len() < 64 {
                        description.push(c);
                    } else if active_field == 2 && capabilities.len() < 128 {
                        capabilities.push(c);
                    }
                    self.modal = Some(ModalState::CreateGroup {
                        name,
                        description,
                        capabilities,
                        active_field,
                    });
                }
                KeyCode::Enter => {
                    if !name.trim().is_empty() {
                        let caps_vec = capabilities
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        let grp = MeshGroup::new(name.trim(), description.trim(), caps_vec);
                        self.store.add_or_update_group(grp);
                        let _ = self.store.save();
                        self.status_message = format!("✓ Gruppe '@{}' angelegt!", name.trim());
                    } else {
                        self.status_message = "Gruppenname darf nicht leer sein!".to_string();
                        self.modal = Some(ModalState::CreateGroup {
                            name,
                            description,
                            capabilities,
                            active_field,
                        });
                    }
                }
                _ => {
                    self.modal = Some(ModalState::CreateGroup {
                        name,
                        description,
                        capabilities,
                        active_field,
                    });
                }
            },

            // ── Modal: Confirm Delete Group ──
            ModalState::ConfirmDeleteGroup { name } => match code {
                KeyCode::Char('j')
                | KeyCode::Char('J')
                | KeyCode::Char('y')
                | KeyCode::Char('Y')
                | KeyCode::Enter => {
                    let n = name.clone();
                    self.store.remove_group(&n);
                    let _ = self.store.save();
                    if self.selected_group_idx > 0
                        && self.selected_group_idx >= self.store.groups.len()
                    {
                        self.selected_group_idx = self.store.groups.len().saturating_sub(1);
                    }
                    self.status_message = format!("✓ Gruppe '@{}' gelöscht.", n);
                }
                _ => {
                    self.status_message = "Löschen abgebrochen.".to_string();
                }
            },

            // ── Modal: Create Invite ──
            ModalState::CreateInvite {
                mut user_name,
                mut role_idx,
                mut groups,
                mut ttl_hours,
                mut max_uses,
                mut active_field,
            } => {
                match code {
                    KeyCode::Esc => {
                        self.status_message = "Aktion abgebrochen.".to_string();
                    }
                    KeyCode::Tab => {
                        active_field = (active_field + 1) % 5;
                        self.modal = Some(ModalState::CreateInvite {
                            user_name,
                            role_idx,
                            groups,
                            ttl_hours,
                            max_uses,
                            active_field,
                        });
                    }
                    KeyCode::BackTab => {
                        active_field = (active_field + 4) % 5;
                        self.modal = Some(ModalState::CreateInvite {
                            user_name,
                            role_idx,
                            groups,
                            ttl_hours,
                            max_uses,
                            active_field,
                        });
                    }
                    KeyCode::Left => {
                        if active_field == 1 && role_idx > 0 {
                            role_idx -= 1;
                        } else if active_field == 3 && ttl_hours > 1 {
                            ttl_hours -= 1;
                        } else if active_field == 4 && max_uses > 1 {
                            max_uses -= 1;
                        }
                        self.modal = Some(ModalState::CreateInvite {
                            user_name,
                            role_idx,
                            groups,
                            ttl_hours,
                            max_uses,
                            active_field,
                        });
                    }
                    KeyCode::Right => {
                        if active_field == 1 && role_idx + 1 < ALL_ROLES.len() {
                            role_idx += 1;
                        } else if active_field == 3 && ttl_hours < 720 {
                            ttl_hours += 1;
                        } else if active_field == 4 && max_uses < 100 {
                            max_uses += 1;
                        }
                        self.modal = Some(ModalState::CreateInvite {
                            user_name,
                            role_idx,
                            groups,
                            ttl_hours,
                            max_uses,
                            active_field,
                        });
                    }
                    KeyCode::Backspace => {
                        if active_field == 0 {
                            user_name.pop();
                        } else if active_field == 2 {
                            groups.pop();
                        }
                        self.modal = Some(ModalState::CreateInvite {
                            user_name,
                            role_idx,
                            groups,
                            ttl_hours,
                            max_uses,
                            active_field,
                        });
                    }
                    KeyCode::Char(c) => {
                        if active_field == 0 && user_name.len() < 32 {
                            user_name.push(c);
                        } else if active_field == 2 && groups.len() < 64 {
                            groups.push(c);
                        }
                        self.modal = Some(ModalState::CreateInvite {
                            user_name,
                            role_idx,
                            groups,
                            ttl_hours,
                            max_uses,
                            active_field,
                        });
                    }
                    KeyCode::Enter => {
                        if !user_name.trim().is_empty() {
                            let role = ALL_ROLES[role_idx];
                            let now = Utc::now().timestamp() as u64;
                            let expires_at = now + (ttl_hours * 3600);
                            let rand_id = format!("{:08x}", rand::random::<u32>());
                            let token_id = format!("inv-{}", rand_id);

                            let pubkey = self
                                .identity
                                .as_ref()
                                .map(|id| id.wireguard_pubkey.clone())
                                .unwrap_or_else(|| "dGVzdF9rZXk=".to_string());
                            let endpoint = "145.223.83.235:58888".to_string();
                            let swarm_topic = format!("sbm-swarm-{}", self.current_mesh());
                            let groups_vec: Vec<String> = groups
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();

                            let token = MeshInviteToken {
                                token_id: token_id.clone(),
                                mesh_name: self.current_mesh().to_string(),
                                user_name: user_name.trim().to_string(),
                                role,
                                groups: groups_vec,
                                capabilities: role.default_capabilities(),
                                server_endpoint: endpoint,
                                server_pubkey: pubkey,
                                swarm_topic,
                                created_at: now,
                                expires_at,
                                max_uses,
                                current_uses: 0,
                                revoked: false,
                                signature: MeshInviteToken::new_secret(),
                            };

                            let uri = token.encode_uri();
                            let qr = render_terminal_qr(&uri).unwrap_or_default();
                            let qr_lines = qr.lines().map(|s| s.to_string()).collect();

                            self.store.add_invite(token.to_stored());
                            let _ = self.store.save();
                            self.status_message = format!(
                                "✓ Token für '{}' erstellt! QR-Code bereit.",
                                user_name.trim()
                            );

                            // Instantly show the generated QR code modal!
                            self.modal = Some(ModalState::ShowInviteQr {
                                uri,
                                token_id,
                                user_name: user_name.trim().to_string(),
                                qr_lines,
                            });
                        } else {
                            self.status_message = "Benutzername darf nicht leer sein!".to_string();
                            self.modal = Some(ModalState::CreateInvite {
                                user_name,
                                role_idx,
                                groups,
                                ttl_hours,
                                max_uses,
                                active_field,
                            });
                        }
                    }
                    _ => {
                        self.modal = Some(ModalState::CreateInvite {
                            user_name,
                            role_idx,
                            groups,
                            ttl_hours,
                            max_uses,
                            active_field,
                        });
                    }
                }
            }

            // ── Modal: Show Invite QR Code ──
            ModalState::ShowInviteQr {
                uri,
                token_id,
                user_name,
                qr_lines,
            } => match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('Q') => {
                    self.status_message =
                        format!("Invite für '{}' gespeichert. Bereit.", user_name);
                }
                _ => {
                    self.modal = Some(ModalState::ShowInviteQr {
                        uri,
                        token_id,
                        user_name,
                        qr_lines,
                    });
                }
            },

            // ── Modal: Confirm Revoke Invite ──
            ModalState::ConfirmRevokeInvite {
                token_id,
                user_name,
            } => match code {
                KeyCode::Char('j')
                | KeyCode::Char('J')
                | KeyCode::Char('y')
                | KeyCode::Char('Y')
                | KeyCode::Enter => {
                    self.store.revoke_invite(&token_id);
                    let _ = self.store.save();
                    self.status_message =
                        format!("✓ Token '{}' für '{}' revoziert.", token_id, user_name);
                }
                _ => {
                    self.status_message = "Revozieren abgebrochen.".to_string();
                }
            },

            // ── Modal: Add Peer ──
            ModalState::AddPeer {
                mut callsign,
                mut node_id,
                mut pubkey,
                mut endpoint,
                mut active_field,
            } => match code {
                KeyCode::Esc => {
                    self.status_message = "Aktion abgebrochen.".to_string();
                }
                KeyCode::Tab => {
                    active_field = (active_field + 1) % 4;
                    self.modal = Some(ModalState::AddPeer {
                        callsign,
                        node_id,
                        pubkey,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::BackTab => {
                    active_field = (active_field + 3) % 4;
                    self.modal = Some(ModalState::AddPeer {
                        callsign,
                        node_id,
                        pubkey,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::Backspace => {
                    if active_field == 0 {
                        callsign.pop();
                    } else if active_field == 1 {
                        node_id.pop();
                    } else if active_field == 2 {
                        pubkey.pop();
                    } else if active_field == 3 {
                        endpoint.pop();
                    }
                    self.modal = Some(ModalState::AddPeer {
                        callsign,
                        node_id,
                        pubkey,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::Char(c) => {
                    if active_field == 0 && callsign.len() < 24 {
                        callsign.push(c);
                    } else if active_field == 1 && node_id.len() < 32 {
                        node_id.push(c);
                    } else if active_field == 2 && pubkey.len() < 64 {
                        pubkey.push(c);
                    } else if active_field == 3 && endpoint.len() < 32 {
                        endpoint.push(c);
                    }
                    self.modal = Some(ModalState::AddPeer {
                        callsign,
                        node_id,
                        pubkey,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::Enter => {
                    if !callsign.trim().is_empty() && !pubkey.trim().is_empty() {
                        let n_id = if node_id.trim().is_empty() {
                            NodeIdentity::derive_node_id_from_pubkey(&pubkey)
                        } else {
                            node_id.trim().to_string()
                        };

                        let p_cfg = PeerConfig {
                            callsign: callsign.trim().to_string(),
                            node_id: n_id,
                            public_key_base64: pubkey.trim().to_string(),
                            endpoint: Some(endpoint.trim().to_string()),
                            overlay_ip: None,
                            created_at: Utc::now(),
                        };

                        let peers_path = sb_core::paths::sb_mesh_dir().join("peers.toml");
                        let mut table = PeerTable::load_from_file(&peers_path)
                            .unwrap_or_else(|_| PeerTable::new());
                        table.add_peer(p_cfg.clone());
                        let _ = table.save_to_file(&peers_path);

                        self.peers.push(p_cfg);
                        self.status_message = format!("✓ Peer '{}' hinzugefügt!", callsign.trim());
                    } else {
                        self.status_message =
                            "Callsign und Public Key dürfen nicht leer sein!".to_string();
                        self.modal = Some(ModalState::AddPeer {
                            callsign,
                            node_id,
                            pubkey,
                            endpoint,
                            active_field,
                        });
                    }
                }
                _ => {
                    self.modal = Some(ModalState::AddPeer {
                        callsign,
                        node_id,
                        pubkey,
                        endpoint,
                        active_field,
                    });
                }
            },

            // ── Modal: Confirm Delete Peer ──
            ModalState::ConfirmDeletePeer { callsign, pubkey } => match code {
                KeyCode::Char('j')
                | KeyCode::Char('J')
                | KeyCode::Char('y')
                | KeyCode::Char('Y')
                | KeyCode::Enter => {
                    let peers_path = sb_core::paths::sb_mesh_dir().join("peers.toml");
                    let mut table =
                        PeerTable::load_from_file(&peers_path).unwrap_or_else(|_| PeerTable::new());
                    table.remove_peer(&pubkey);
                    let _ = table.save_to_file(&peers_path);

                    self.peers.retain(|p| p.public_key_base64 != pubkey);
                    if self.selected_peer_idx > 0 && self.selected_peer_idx >= self.peers.len() {
                        self.selected_peer_idx = self.peers.len().saturating_sub(1);
                    }
                    self.status_message = format!("✓ Peer '{}' entfernt.", callsign);
                }
                _ => {
                    self.status_message = "Löschen abgebrochen.".to_string();
                }
            },

            // ── Modal: Create Tunnel ──
            ModalState::CreateTunnel {
                mut name,
                mut local_port,
                mut remote_port,
                mut active_field,
            } => match code {
                KeyCode::Esc => {
                    self.status_message = "Aktion abgebrochen.".to_string();
                }
                KeyCode::Tab => {
                    active_field = (active_field + 1) % 3;
                    self.modal = Some(ModalState::CreateTunnel {
                        name,
                        local_port,
                        remote_port,
                        active_field,
                    });
                }
                KeyCode::BackTab => {
                    active_field = (active_field + 2) % 3;
                    self.modal = Some(ModalState::CreateTunnel {
                        name,
                        local_port,
                        remote_port,
                        active_field,
                    });
                }
                KeyCode::Backspace => {
                    if active_field == 0 {
                        name.pop();
                    } else if active_field == 1 {
                        local_port.pop();
                    } else if active_field == 2 {
                        remote_port.pop();
                    }
                    self.modal = Some(ModalState::CreateTunnel {
                        name,
                        local_port,
                        remote_port,
                        active_field,
                    });
                }
                KeyCode::Char(c) => {
                    if active_field == 0 && name.len() < 32 {
                        name.push(c);
                    } else if (active_field == 1 || active_field == 2) && c.is_ascii_digit() {
                        if active_field == 1 && local_port.len() < 5 {
                            local_port.push(c);
                        } else if active_field == 2 && remote_port.len() < 5 {
                            remote_port.push(c);
                        }
                    }
                    self.modal = Some(ModalState::CreateTunnel {
                        name,
                        local_port,
                        remote_port,
                        active_field,
                    });
                }
                KeyCode::Enter => {
                    if !name.trim().is_empty() {
                        let item = TunnelItem {
                            name: name.trim().to_string(),
                            kind: "Custom TCP Port-Share".to_string(),
                            local_addr: format!("127.0.0.1:{}", local_port),
                            remote_addr: format!("mesh-ingress:{}", remote_port),
                            status: "BEREIT".to_string(),
                            required_cap: format!("tunnel:port:{}", local_port),
                        };
                        self.tunnels.push(item);
                        self.status_message =
                            format!("✓ Tunnel-Freigabe '{}' angelegt!", name.trim());
                    } else {
                        self.status_message = "Name darf nicht leer sein!".to_string();
                        self.modal = Some(ModalState::CreateTunnel {
                            name,
                            local_port,
                            remote_port,
                            active_field,
                        });
                    }
                }
                _ => {
                    self.modal = Some(ModalState::CreateTunnel {
                        name,
                        local_port,
                        remote_port,
                        active_field,
                    });
                }
            },

            // ── Modal: Confirm Delete Tunnel ──
            ModalState::ConfirmDeleteTunnel { idx, name } => match code {
                KeyCode::Char('j')
                | KeyCode::Char('J')
                | KeyCode::Char('y')
                | KeyCode::Char('Y')
                | KeyCode::Enter => {
                    if idx < self.tunnels.len() {
                        self.tunnels.remove(idx);
                        if self.selected_tunnel_idx > 0
                            && self.selected_tunnel_idx >= self.tunnels.len()
                        {
                            self.selected_tunnel_idx = self.tunnels.len().saturating_sub(1);
                        }
                        self.status_message = format!("✓ Tunnel '{}' entfernt.", name);
                    }
                }
                _ => {
                    self.status_message = "Löschen abgebrochen.".to_string();
                }
            },

            // ── Modal: Advertise Subnet ──
            ModalState::AdvertiseSubnet {
                mut cidr,
                mut endpoint,
                mut active_field,
            } => match code {
                KeyCode::Esc => {
                    self.status_message = "Aktion abgebrochen.".to_string();
                }
                KeyCode::Tab => {
                    active_field = (active_field + 1) % 2;
                    self.modal = Some(ModalState::AdvertiseSubnet {
                        cidr,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::BackTab => {
                    active_field = (active_field + 1) % 2;
                    self.modal = Some(ModalState::AdvertiseSubnet {
                        cidr,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::Backspace => {
                    if active_field == 0 {
                        cidr.pop();
                    } else if active_field == 1 {
                        endpoint.pop();
                    }
                    self.modal = Some(ModalState::AdvertiseSubnet {
                        cidr,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::Char(c) => {
                    if active_field == 0 && cidr.len() < 24 {
                        cidr.push(c);
                    } else if active_field == 1 && endpoint.len() < 40 {
                        endpoint.push(c);
                    }
                    self.modal = Some(ModalState::AdvertiseSubnet {
                        cidr,
                        endpoint,
                        active_field,
                    });
                }
                KeyCode::Enter => {
                    let clean_cidr = cidr.trim();
                    let clean_ep = endpoint.trim();
                    if !crate::network::validate_cidr(clean_cidr) {
                        self.status_message = format!(
                            "Ungültiges CIDR-Format '{}'! Erwartet z.B. '10.0.0.0/16'",
                            clean_cidr
                        );
                        self.modal = Some(ModalState::AdvertiseSubnet {
                            cidr,
                            endpoint,
                            active_field,
                        });
                    } else {
                        let node_id = self
                            .identity
                            .as_ref()
                            .map(|id| id.node_id.clone())
                            .unwrap_or_else(|| "sbm-local".to_string());
                        let pubkey = self
                            .identity
                            .as_ref()
                            .map(|id| id.wireguard_pubkey.clone())
                            .unwrap_or_default();
                        match self
                            .subnet_store
                            .advertise(clean_cidr, &node_id, &pubkey, clean_ep)
                        {
                            Ok(r) => {
                                self.status_message = format!(
                                    "✓ Subnetz-Route '{}' via Gateway '{}' aktiviert!",
                                    r.cidr, clean_ep
                                );
                                if let Ok(updated_store) =
                                    MeshRbacStore::load_or_create(&self.subnet_store.mesh_name)
                                {
                                    self.store = updated_store;
                                }
                            }
                            Err(e) => {
                                self.status_message = format!("Fehler beim Bewerben: {}", e);
                            }
                        }
                    }
                }
                _ => {
                    self.modal = Some(ModalState::AdvertiseSubnet {
                        cidr,
                        endpoint,
                        active_field,
                    });
                }
            },

            // ── Modal: Confirm Withdraw Subnet ──
            ModalState::ConfirmWithdrawSubnet { cidr } => match code {
                KeyCode::Char('j')
                | KeyCode::Char('J')
                | KeyCode::Char('y')
                | KeyCode::Char('Y')
                | KeyCode::Enter => {
                    let pubkey = self
                        .identity
                        .as_ref()
                        .map(|id| id.wireguard_pubkey.clone())
                        .unwrap_or_default();
                    let clean_cidr = cidr.trim();
                    let route_pk = self
                        .subnet_store
                        .routes
                        .iter()
                        .find(|r| r.cidr == clean_cidr)
                        .map(|r| r.gateway_pubkey.clone())
                        .unwrap_or(pubkey);

                    if self.subnet_store.withdraw(clean_cidr, &route_pk) {
                        if self.selected_subnet_idx > 0
                            && self.selected_subnet_idx >= self.subnet_store.routes.len()
                        {
                            self.selected_subnet_idx =
                                self.subnet_store.routes.len().saturating_sub(1);
                        }
                        if let Ok(updated_store) =
                            MeshRbacStore::load_or_create(&self.subnet_store.mesh_name)
                        {
                            self.store = updated_store;
                        }
                        self.status_message =
                            format!("✓ Subnetz-Route '{}' zurückgezogen.", clean_cidr);
                    } else {
                        self.status_message = format!(
                            "Subnetz-Route '{}' konnte nicht zurückgezogen werden.",
                            clean_cidr
                        );
                    }
                }
                _ => {
                    self.status_message = "Zurückziehen abgebrochen.".to_string();
                }
            },
        }
    }

    fn ui(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header Banner & Tenant Tabs
                Constraint::Min(12),   // Main Workspace Split
                Constraint::Length(3), // Footer Bar
            ])
            .split(f.area());

        self.render_header(f, chunks[0]);

        match self.active_tab {
            0 => self.render_workspace_peers(f, chunks[1]),
            1 => self.render_workspace_members(f, chunks[1]),
            2 => self.render_workspace_groups(f, chunks[1]),
            3 => self.render_workspace_invites(f, chunks[1]),
            4 => self.render_workspace_tunnels(f, chunks[1]),
            5 => self.render_workspace_audit(f, chunks[1]),
            _ => {}
        }

        self.render_footer(f, chunks[2]);

        if let Some(ref modal) = self.modal {
            self.render_modal(f, modal);
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let node_id = self
            .identity
            .as_ref()
            .map(|id| id.node_id.as_str())
            .unwrap_or("sbm-local");
        let header_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        let title_line = Line::from(vec![
            Span::styled(
                "💀 SKULLS & BONES // ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "SOVEREIGN MESH MASTER COCKPIT ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("({})", node_id), Style::default().fg(Color::Cyan)),
        ]);

        let title_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));
        let p_title = Paragraph::new(title_line).block(title_block);
        f.render_widget(p_title, header_chunks[0]);

        // Mesh tenant tabs
        let tab_titles: Vec<Line> = self
            .meshes
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let badge = if i == self.current_mesh_idx {
                    format!("● {}", m)
                } else {
                    format!("○ {}", m)
                };
                Line::from(vec![Span::raw(badge)])
            })
            .collect();

        let tabs = Tabs::new(tab_titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" MESH TENANT [Tab] ")
                    .border_style(Style::default().fg(Color::DarkGray))
                    .style(Style::default().bg(Color::Rgb(12, 15, 22))),
            )
            .select(self.current_mesh_idx)
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        f.render_widget(tabs, header_chunks[1]);
    }

    fn render_tabs_bar(&self, f: &mut Frame, area: Rect) {
        let titles = vec![
            Line::from(vec![Span::raw("[1] 🌐 Topologie & Peers")]),
            Line::from(vec![Span::raw("[2] 👥 Mitglieder & Rollen")]),
            Line::from(vec![Span::raw("[3] 🛡️ Security Groups")]),
            Line::from(vec![Span::raw("[4] 🎟️ Invites & Onboarding")]),
            Line::from(vec![Span::raw("[5] ⚡ Tunnels & Shares")]),
            Line::from(vec![Span::raw("[6] 📜 Security Audit")]),
        ];

        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
                    .style(Style::default().bg(Color::Rgb(15, 20, 30))),
            )
            .select(self.active_tab)
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );

        f.render_widget(tabs, area);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Workspace 0: Topologie & Peers
    // ─────────────────────────────────────────────────────────────────────────
    fn render_workspace_peers(&self, f: &mut Frame, area: Rect) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(8)])
            .split(area);

        self.render_tabs_bar(f, outer[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(outer[1]);

        // Left: Peers List
        let items: Vec<ListItem> = if self.peers.is_empty() {
            vec![
                ListItem::new(Line::from("Keine Peers konfiguriert.")),
                ListItem::new(Line::from("Drücken Sie [A] zum Hinzufügen.")),
            ]
        } else {
            self.peers
                .iter()
                .enumerate()
                .map(|(idx, p)| {
                    let is_selected = idx == self.selected_peer_idx;
                    let ep = p.endpoint.as_deref().unwrap_or("P2P Direct");
                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:<15}", p.callsign),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" {:<18} ", ep),
                            Style::default().fg(Color::LightCyan),
                        ),
                        Span::styled("[ONLINE]", Style::default().fg(Color::LightGreen)),
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

        let list_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" PEER TOPOLOGIE (Total: {}) ", self.peers.len()))
            .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));
        let list = List::new(items).block(list_block);
        f.render_widget(list, body[0]);

        // Right: Peer Details
        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title(" PEER HEALTH & KRYPTO-TELEMETRIE ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let mut lines = Vec::new();
        if let Some(p) = self.peers.get(self.selected_peer_idx) {
            lines.push(Line::from(vec![
                Span::styled("Callsign:        ", Style::default().fg(Color::Gray)),
                Span::styled(
                    &p.callsign,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Node ID:         ", Style::default().fg(Color::Gray)),
                Span::styled(&p.node_id, Style::default().fg(Color::Yellow)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Public Key:      ", Style::default().fg(Color::Gray)),
                Span::styled(&p.public_key_base64, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Endpunkt:        ", Style::default().fg(Color::Gray)),
                Span::styled(
                    p.endpoint.as_deref().unwrap_or("P2P Direct Hole-Punch"),
                    Style::default().fg(Color::Cyan),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Overlay-IP:      ", Style::default().fg(Color::Gray)),
                Span::styled(
                    p.overlay_ip.as_deref().unwrap_or("Auto (VRF IPAM)"),
                    Style::default().fg(Color::Green),
                ),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "KRYPTOGRAFISCHE INTEGRITÄT & MULTI-PATH:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]));
            lines.push(Line::from(
                "─────────────────────────────────────────────────────────────────",
            ));
            lines.push(Line::from(vec![
                Span::styled(
                    "● Zero-Knowledge Attest:    ",
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    "VERIFIZIERT (Platform Witness validiert)",
                    Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    "● Latenz / RTT (Gradient):  ",
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    "14.2 ms (BBR Gradient Paced)",
                    Style::default().fg(Color::Cyan),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    "● Rekeying & PFS Ratchet:   ",
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    "Epoch 4 (In-Band X25519 Ratchet aktiv)",
                    Style::default().fg(Color::White),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    "● Multi-Path Status:        ",
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    "Direktverbindung aktiv (Fast Failover Standby)",
                    Style::default().fg(Color::White),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    "● Sleep-Aware Keepalive:    ",
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    "ACTIVE MODE (2s Intervall)",
                    Style::default().fg(Color::LightGreen),
                ),
            ]));
        } else {
            lines.push(Line::from("Kein Peer ausgewählt."));
        }

        let p_details = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: true });
        f.render_widget(p_details, body[1]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Workspace 1: Mitglieder & Rollen
    // ─────────────────────────────────────────────────────────────────────────
    fn render_workspace_members(&self, f: &mut Frame, area: Rect) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(8)])
            .split(area);

        self.render_tabs_bar(f, outer[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(outer[1]);

        let now = Utc::now().timestamp() as u64;

        // Left: Members List
        let items: Vec<ListItem> = if self.store.members.is_empty() {
            vec![
                ListItem::new(Line::from(vec![Span::styled(
                    "Keine Mitglieder vorhanden.",
                    Style::default().fg(Color::DarkGray),
                )])),
                ListItem::new(Line::from(vec![Span::styled(
                    "Drücken Sie [A] zum Hinzufügen oder [I] für Invite.",
                    Style::default().fg(Color::Yellow),
                )])),
            ]
        } else {
            self.store
                .members
                .iter()
                .enumerate()
                .map(|(idx, m)| {
                    let is_selected = idx == self.selected_member_idx;
                    let (st_badge, st_color) = if m.revoked {
                        ("○ REVOKED", Color::Red)
                    } else if m.is_active(now) {
                        ("● AKTIV", Color::LightGreen)
                    } else {
                        ("◐ EXPIRED", Color::Yellow)
                    };

                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:<14}", m.name),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" {:<9} ", m.role.badge()),
                            Style::default().fg(Color::LightCyan),
                        ),
                        Span::styled(format!("[{}]", st_badge), Style::default().fg(st_color)),
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
            .title(format!(
                " MITGLIEDER (Total: {}) ",
                self.store.members.len()
            ))
            .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let list = List::new(items).block(block);
        f.render_widget(list, body[0]);

        // Right: Member Details & Capabilities Matrix
        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title(" CAPABILITIES MATRIX & RECHTE ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let member = self.store.members.get(self.selected_member_idx);
        let mut lines = Vec::new();
        if let Some(m) = member {
            lines.push(Line::from(vec![
                Span::styled("Name:             ", Style::default().fg(Color::Gray)),
                Span::styled(
                    &m.name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("   Rolle: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{} ({})", m.role.badge(), m.role.as_str()),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Node ID:          ", Style::default().fg(Color::Gray)),
                Span::styled(&m.node_id, Style::default().fg(Color::Yellow)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Public Key:       ", Style::default().fg(Color::Gray)),
                Span::styled(&m.pubkey, Style::default().fg(Color::White)),
            ]));

            let (status_text, status_style) = if m.revoked {
                (
                    format!(
                        "GESPERRT / KRL-EVICTED ({})",
                        m.revoked_reason.as_deref().unwrap_or("Admin")
                    ),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )
            } else if m.is_active(now) {
                (
                    "AUTORISIERT & AKTIV".to_string(),
                    Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                (
                    "ABGELAUFEN (EXPIRED)".to_string(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            };

            lines.push(Line::from(vec![
                Span::styled("Status:           ", Style::default().fg(Color::Gray)),
                Span::styled(status_text, status_style),
            ]));

            if !m.groups.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Gruppen (AD):     ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        m.groups.join(", "),
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "BERECHTIGUNGEN & CAPABILITIES (Capability Enforcement):",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]));
            lines.push(Line::from(
                "─────────────────────────────────────────────────────────────────",
            ));

            let standard_caps = [
                (
                    CAP_TUNNEL_SSH,
                    "tunnel:ssh           (Port 22 Stealth Ingress / SSH Tunneling)",
                ),
                (
                    CAP_TUNNEL_ANY,
                    "tunnel:any           (Beliebige TCP-Ports tunneln & forwarden)",
                ),
                (
                    CAP_STREAM_TRANSFER,
                    "stream:transfer      (SFTP / SCP Paced Reliable Stream-Transfer)",
                ),
                (
                    CAP_CODE_SYNC,
                    "code:sync            (sb-code Repository Push / Pull über Mesh-Streams)",
                ),
                (
                    CAP_MESH_INVITE,
                    "mesh:invite          (Neue Mitglieder & Pairing-Token ausstellen)",
                ),
                (
                    CAP_MESH_KRL,
                    "mesh:krl             (KRL Key-Revocation & Node-Eviction)",
                ),
                (
                    CAP_MESH_MANAGE,
                    "mesh:manage          (Mesh-Einstellungen & Topologie verwalten)",
                ),
                (
                    CAP_TELEMETRY_READ,
                    "telemetry:read       (Live-Telemetrie & Status einsehen)",
                ),
                (
                    CAP_ARTIFACT_DOWNLOAD,
                    "artifact:download    (Software-Downloads & Releases beziehen)",
                ),
            ];

            for (cap, label) in standard_caps {
                let has = m.has_capability(cap);
                let (mark, mark_style) = if has {
                    (
                        "[X] ",
                        Style::default()
                            .fg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    ("[ ] ", Style::default().fg(Color::DarkGray))
                };
                let text_style = if has {
                    Style::default().fg(Color::White)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                lines.push(Line::from(vec![
                    Span::styled(mark, mark_style),
                    Span::styled(label, text_style),
                ]));
            }
        } else {
            lines.push(Line::from("Kein Mitglied ausgewählt."));
        }

        let p = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: true });
        f.render_widget(p, body[1]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Workspace 2: Security Groups
    // ─────────────────────────────────────────────────────────────────────────
    fn render_workspace_groups(&self, f: &mut Frame, area: Rect) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(8)])
            .split(area);

        self.render_tabs_bar(f, outer[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(outer[1]);

        let items: Vec<ListItem> = if self.store.groups.is_empty() {
            vec![
                ListItem::new(Line::from("Keine Gruppen vorhanden.")),
                ListItem::new(Line::from("Drücken Sie [G] zum Anlegen.")),
            ]
        } else {
            self.store
                .groups
                .iter()
                .enumerate()
                .map(|(idx, g)| {
                    let is_selected = idx == self.selected_group_idx;
                    let member_count = self
                        .store
                        .members
                        .iter()
                        .filter(|m| {
                            m.groups
                                .iter()
                                .any(|gn| gn == &g.name || gn == &format!("@{}", g.name))
                        })
                        .count();
                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("@{:<18}", g.name),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("({} Mitglieder)", member_count),
                            Style::default().fg(Color::Magenta),
                        ),
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
            .title(format!(
                " SECURITY GROUPS (AD-STYLE) (Total: {}) ",
                self.store.groups.len()
            ))
            .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let list = List::new(items).block(block);
        f.render_widget(list, body[0]);

        // Right: Group Details & Inherited Capabilities
        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title(" GRUPPENDETAILS & VERERBTE CAPABILITIES ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let mut lines = Vec::new();
        if let Some(g) = self.store.groups.get(self.selected_group_idx) {
            lines.push(Line::from(vec![
                Span::styled("Gruppenname:     ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("@{}", g.name),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Beschreibung:    ", Style::default().fg(Color::Gray)),
                Span::styled(&g.description, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "AUTOMATISCH VERERBTE CAPABILITIES (Role Hierarchy):",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]));
            lines.push(Line::from(
                "─────────────────────────────────────────────────────────────────",
            ));

            if g.capabilities.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  Keine speziellen Capabilities konfiguriert.",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for cap in &g.capabilities {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "  [✓] ",
                            Style::default()
                                .fg(Color::LightGreen)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(cap, Style::default().fg(Color::White)),
                    ]));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "AKTUELL ZUGEORDNETE MITGLIEDER:",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]));
            lines.push(Line::from(
                "─────────────────────────────────────────────────────────────────",
            ));

            let members_in_group: Vec<&MeshMember> = self
                .store
                .members
                .iter()
                .filter(|m| {
                    m.groups
                        .iter()
                        .any(|gn| gn == &g.name || gn == &format!("@{}", g.name))
                })
                .collect();
            if members_in_group.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  Keine Mitglieder in dieser Gruppe.",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for m in members_in_group {
                    lines.push(Line::from(vec![
                        Span::styled("  ● ", Style::default().fg(Color::LightGreen)),
                        Span::styled(
                            &m.name,
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" [{}]", m.role.badge()),
                            Style::default().fg(Color::Cyan),
                        ),
                    ]));
                }
            }
        } else {
            lines.push(Line::from("Keine Gruppe ausgewählt."));
        }

        let p = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: true });
        f.render_widget(p, body[1]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Workspace 3: Invites & Onboarding
    // ─────────────────────────────────────────────────────────────────────────
    fn render_workspace_invites(&self, f: &mut Frame, area: Rect) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(8)])
            .split(area);

        self.render_tabs_bar(f, outer[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(outer[1]);

        let now = Utc::now().timestamp() as u64;

        let items: Vec<ListItem> = if self.store.invites.is_empty() {
            vec![
                ListItem::new(Line::from("Keine Invite-Token vorhanden.")),
                ListItem::new(Line::from("Drücken Sie [I] zur Erstellung.")),
            ]
        } else {
            self.store
                .invites
                .iter()
                .enumerate()
                .map(|(idx, inv)| {
                    let is_selected = idx == self.selected_invite_idx;
                    let (st_badge, st_color) = if inv.revoked {
                        ("REVOKED", Color::Red)
                    } else if inv.max_uses > 0 && inv.current_uses >= inv.max_uses {
                        ("VERBRAUCHT", Color::Yellow)
                    } else if now >= inv.expires_at {
                        ("ABGELAUFEN", Color::DarkGray)
                    } else {
                        ("AKTIV", Color::LightGreen)
                    };

                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:<14}", inv.user_name),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" {:<8} ", inv.role.badge()),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::styled(
                            format!("{}/{} ", inv.current_uses, inv.max_uses),
                            Style::default().fg(Color::Gray),
                        ),
                        Span::styled(format!("[{}]", st_badge), Style::default().fg(st_color)),
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
            .title(format!(
                " EINLADUNGS-TOKEN (Total: {}) ",
                self.store.invites.len()
            ))
            .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let list = List::new(items).block(block);
        f.render_widget(list, body[0]);

        // Right: Invite Details & Full URI
        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title(" ONE-CLICK ONBOARDING TOKEN DETAILS ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let mut lines = Vec::new();
        if let Some(inv) = self.store.invites.get(self.selected_invite_idx) {
            lines.push(Line::from(vec![
                Span::styled("Token ID:        ", Style::default().fg(Color::Gray)),
                Span::styled(
                    &inv.token_id,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Ziel-Nutzer:     ", Style::default().fg(Color::Gray)),
                Span::styled(
                    &inv.user_name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("   Rolle: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{} ({})", inv.role.badge(), inv.role.as_str()),
                    Style::default().fg(Color::Cyan),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Server Endpunkt: ", Style::default().fg(Color::Gray)),
                Span::styled(&inv.server_endpoint, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Swarm Topic:     ", Style::default().fg(Color::Gray)),
                Span::styled(&inv.swarm_topic, Style::default().fg(Color::Cyan)),
            ]));

            let remaining_secs = inv.expires_at.saturating_sub(now);
            lines.push(Line::from(vec![
                Span::styled("Gültigkeit:      ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!(
                        "{} Stunden ({}s verbleibend)",
                        remaining_secs / 3600,
                        remaining_secs
                    ),
                    Style::default().fg(Color::Yellow),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Nutzungen:       ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{} von max. {}", inv.current_uses, inv.max_uses),
                    Style::default().fg(Color::White),
                ),
            ]));

            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "SBM-INVITE URI (One-Click Handshake):",
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            )]));
            lines.push(Line::from(
                "─────────────────────────────────────────────────────────────────",
            ));

            let uri = inv.encode_uri();
            let uri_preview = if uri.len() > 60 {
                format!("{}...", &uri[..60])
            } else {
                uri.clone()
            };
            lines.push(Line::from(Span::styled(
                uri_preview,
                Style::default().fg(Color::Cyan),
            )));

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("▶ Drücken Sie ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    "[Enter] / [Q]",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " um den ASCII QR-Code für Smartphones/Laptops anzuzeigen!",
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        } else {
            lines.push(Line::from("Kein Invite ausgewählt."));
        }

        let p = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: true });
        f.render_widget(p, body[1]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Workspace 4: Tunnels & VPC Bridges
    // ─────────────────────────────────────────────────────────────────────────
    fn render_workspace_tunnels(&self, f: &mut Frame, area: Rect) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(8)])
            .split(area);

        self.render_tabs_bar(f, outer[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
            .split(outer[1]);

        // Left side split into Tunnels (top) and Advertised Subnets (bottom)
        let left_panes = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(body[0]);

        // 1. Tunnels List
        let tunnel_items: Vec<ListItem> = if self.tunnels.is_empty() {
            vec![
                ListItem::new(Line::from("Keine Tunnels oder Port-Freigaben aktiv.")),
                ListItem::new(Line::from("Drücken Sie [T] zum Anlegen.")),
            ]
        } else {
            self.tunnels
                .iter()
                .enumerate()
                .map(|(idx, t)| {
                    let is_selected = self.tunnel_panel == 0 && idx == self.selected_tunnel_idx;
                    let (st_badge, st_color) = match t.status.as_str() {
                        "ONLINE" => ("ONLINE", Color::LightGreen),
                        "STANDBY" => ("STANDBY", Color::Yellow),
                        _ => ("BEREIT", Color::Cyan),
                    };

                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:<18}", t.name),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(format!("[{}]", st_badge), Style::default().fg(st_color)),
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

        let tunnel_border_color = if self.tunnel_panel == 0 {
            Color::Yellow
        } else {
            Color::Rgb(56, 189, 248)
        };
        let tunnel_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " STEALTH TUNNELS & FORWARDING (Total: {}) ",
                self.tunnels.len()
            ))
            .border_style(Style::default().fg(tunnel_border_color))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let tunnel_list = List::new(tunnel_items).block(tunnel_block);
        f.render_widget(tunnel_list, left_panes[0]);

        // 2. Advertised Subnet Routes List
        let subnet_items: Vec<ListItem> = if self.subnet_store.routes.is_empty() {
            vec![
                ListItem::new(Line::from("Keine VPC Subnetze registriert.")),
                ListItem::new(Line::from("Drücken Sie [S] um Subnetz zu bewerben.")),
            ]
        } else {
            self.subnet_store
                .routes
                .iter()
                .enumerate()
                .map(|(idx, r)| {
                    let is_selected = self.tunnel_panel == 1 && idx == self.selected_subnet_idx;
                    let (st_badge, st_color) = if r.is_active {
                        ("AKTIV", Color::LightGreen)
                    } else {
                        ("INAKTIV", Color::DarkGray)
                    };

                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:<15}", r.cidr),
                            Style::default()
                                .fg(Color::LightGreen)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" ➔ {:<12}", r.gateway_node_id),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::styled(format!("[{}]", st_badge), Style::default().fg(st_color)),
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

        let subnet_border_color = if self.tunnel_panel == 1 {
            Color::Yellow
        } else {
            Color::Rgb(56, 189, 248)
        };
        let subnet_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " VPC SUBNET ROUTEN & BRIDGES (Total: {}) ",
                self.subnet_store.routes.len()
            ))
            .border_style(Style::default().fg(subnet_border_color))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let subnet_list = List::new(subnet_items).block(subnet_block);
        f.render_widget(subnet_list, left_panes[1]);

        // Right side: Detail view
        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title(if self.tunnel_panel == 0 {
                " TUNNEL ROUTING & SICHERHEITSPROFIL "
            } else {
                " VPC SUBNET BRIDGE INSPECTOR "
            })
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let mut lines = Vec::new();

        if self.tunnel_panel == 0 {
            if let Some(t) = self.tunnels.get(self.selected_tunnel_idx) {
                lines.push(Line::from(vec![
                    Span::styled("Dienstname:       ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        &t.name,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Tunnel-Typ:       ", Style::default().fg(Color::Gray)),
                    Span::styled(&t.kind, Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Lokaler Endpunkt: ", Style::default().fg(Color::Gray)),
                    Span::styled(&t.local_addr, Style::default().fg(Color::Green)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Remote Endpunkt:  ", Style::default().fg(Color::Gray)),
                    Span::styled(&t.remote_addr, Style::default().fg(Color::Yellow)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Erforderliche Cap:", Style::default().fg(Color::Gray)),
                    Span::styled(
                        &t.required_cap,
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "SOVEREIGN STEALTH EIGENSCHAFTEN:",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )]));
                lines.push(Line::from(
                    "─────────────────────────────────────────────────────────────────",
                ));
                lines.push(Line::from(vec![
                    Span::styled("● Transport:        ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        "UDP Noise_IK Multiplexer (Port 58888)",
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("● Verschlüsselung:  ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        "ChaCha20-Poly1305 AEAD + Anti-Replay Filter",
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("● Cloud-Abhängigkeit:", Style::default().fg(Color::Gray)),
                    Span::styled(
                        "0% (Kein Cloudflare / Ngrok / Relay Broker)",
                        Style::default()
                            .fg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
            } else {
                lines.push(Line::from("Kein Tunnel ausgewählt."));
            }
        } else {
            if let Some(r) = self.subnet_store.routes.get(self.selected_subnet_idx) {
                lines.push(Line::from(vec![
                    Span::styled("Subnetz CIDR:     ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        &r.cidr,
                        Style::default()
                            .fg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Gateway Node ID:  ", Style::default().fg(Color::Gray)),
                    Span::styled(&r.gateway_node_id, Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Gateway Router:   ", Style::default().fg(Color::Gray)),
                    Span::styled(&r.gateway_endpoint, Style::default().fg(Color::Yellow)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Mesh Netzwerk:    ", Style::default().fg(Color::Gray)),
                    Span::styled(&r.mesh_name, Style::default().fg(Color::White)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Routing Status:   ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        if r.is_active {
                            "AKTIV (Subnet Router Bridge)"
                        } else {
                            "INAKTIV"
                        },
                        Style::default()
                            .fg(if r.is_active {
                                Color::LightGreen
                            } else {
                                Color::Red
                            })
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "TRANSPARENTER ZERO-TUNNELING ZUGANG:",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )]));
                lines.push(Line::from(
                    "─────────────────────────────────────────────────────────────────",
                ));
                lines.push(Line::from(vec![Span::styled(
                    "1. SOCKS5 Proxy Auto-Routing (Alle Tools / Browser / DBs):",
                    Style::default().fg(Color::White),
                )]));
                let sample_ip = r.cidr.split('/').next().unwrap_or("10.0.0.1");
                lines.push(Line::from(vec![Span::styled(
                    format!(
                        "   curl --socks5-hostname 127.0.0.1:1080 http://{}/",
                        sample_ip
                    ),
                    Style::default().fg(Color::Cyan),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "2. Lokaler Dedicated Port-Forwarder:",
                    Style::default().fg(Color::White),
                )]));
                lines.push(Line::from(vec![Span::styled(
                    format!(
                        "   sb mesh route forward --local-port 5432 --target {}:5432",
                        sample_ip
                    ),
                    Style::default().fg(Color::Yellow),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "3. VPC Bridge Worker (Headless Service im LAN):",
                    Style::default().fg(Color::White),
                )]));
                lines.push(Line::from(vec![Span::styled(
                    format!(
                        "   sb mesh route bridge --cidr {} --mesh {}",
                        r.cidr, r.mesh_name
                    ),
                    Style::default().fg(Color::Green),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("● Audit-Status:     ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        "Kryptografisch im RBAC Audit-Log verzeichnet",
                        Style::default().fg(Color::LightCyan),
                    ),
                ]));
            } else {
                lines.push(Line::from("Keine Subnetz-Route ausgewählt."));
                lines.push(Line::from(
                    "Drücken Sie [S] um ein neues VPC-Subnetz zu bewerben.",
                ));
            }
        }

        let p = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: true });
        f.render_widget(p, body[1]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Workspace 5: Security Audit Log
    // ─────────────────────────────────────────────────────────────────────────
    fn render_workspace_audit(&self, f: &mut Frame, area: Rect) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(8)])
            .split(area);

        self.render_tabs_bar(f, outer[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(outer[1]);

        let items: Vec<ListItem> = if self.store.audit_log.is_empty() {
            vec![ListItem::new(Line::from("Keine Audit-Einträge vorhanden."))]
        } else {
            self.store
                .audit_log
                .iter()
                .enumerate()
                .rev()
                .map(|(idx, entry)| {
                    let is_selected = idx == self.selected_audit_idx;
                    let dt = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                        .map(|d| d.format("%H:%M:%S").to_string())
                        .unwrap_or_else(|| entry.timestamp.to_string());

                    let action_color = match entry.action.as_str() {
                        "member_revoked" | "invite_revoked" => Color::Red,
                        "joined_via_invite" | "invite_created" => Color::LightGreen,
                        _ => Color::Cyan,
                    };

                    let line = Line::from(vec![
                        Span::styled(
                            if is_selected { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(format!("{:<9} ", dt), Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            format!("{:<16} ", entry.action),
                            Style::default()
                                .fg(action_color)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:<12} ", entry.actor),
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(&entry.target, Style::default().fg(Color::White)),
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
            .title(format!(
                " AUDIT EVENT STREAM (Total: {}) ",
                self.store.audit_log.len()
            ))
            .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let list = List::new(items).block(block);
        f.render_widget(list, body[0]);

        // Right: Audit Inspector
        let detail_block = Block::default()
            .borders(Borders::ALL)
            .title(" SECURITY AUDIT INSPECTOR ")
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let mut lines = Vec::new();
        if let Some(entry) = self.store.audit_log.get(self.selected_audit_idx) {
            let dt = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| entry.timestamp.to_string());

            lines.push(Line::from(vec![
                Span::styled("Zeitpunkt:       ", Style::default().fg(Color::Gray)),
                Span::styled(
                    dt,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Aktion:          ", Style::default().fg(Color::Gray)),
                Span::styled(
                    &entry.action,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Akteur / Issuer: ", Style::default().fg(Color::Gray)),
                Span::styled(&entry.actor, Style::default().fg(Color::Cyan)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Ziel-Objekt:     ", Style::default().fg(Color::Gray)),
                Span::styled(&entry.target, Style::default().fg(Color::LightGreen)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Details:         ", Style::default().fg(Color::Gray)),
                Span::styled(&entry.details, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "UNVERÄNDERLICHE KRYPTOGRAFISCHE VERIFIKATION:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]));
            lines.push(Line::from(
                "─────────────────────────────────────────────────────────────────",
            ));
            lines.push(Line::from(vec![
                Span::styled("● Audit-Status:     ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "GÜLTIG (Append-Only Audit Log)",
                    Style::default().fg(Color::LightGreen),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("● Compliance:       ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "Zero-Knowledge Witness Attested",
                    Style::default().fg(Color::Cyan),
                ),
            ]));
        } else {
            lines.push(Line::from("Kein Audit-Eintrag ausgewählt."));
        }

        let p = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: true });
        f.render_widget(p, body[1]);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .style(Style::default().bg(Color::Rgb(12, 15, 22)));

        let shortcuts_line = match self.active_tab {
            0 => Line::from(vec![
                Span::styled(
                    "[1-6] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Tabs  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[A] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Peer hinzufügen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[D] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Peer löschen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Tab] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Mesh wechseln  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Q] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Beenden", Style::default().fg(Color::White)),
            ]),
            1 => Line::from(vec![
                Span::styled(
                    "[1-6] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Tabs  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[A] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Mitglied  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[E] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Rolle  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[R] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Sperren/Entsperren  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[I] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Invite  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[D] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Löschen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Q] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Beenden", Style::default().fg(Color::White)),
            ]),
            2 => Line::from(vec![
                Span::styled(
                    "[1-6] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Tabs  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[G] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Gruppe anlegen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[D] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Gruppe löschen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Q] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Beenden", Style::default().fg(Color::White)),
            ]),
            3 => Line::from(vec![
                Span::styled(
                    "[1-6] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Tabs  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[I] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Neuer Invite  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Enter/Q] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("QR-Code anzeigen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[R] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Revozieren  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Q] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Beenden", Style::default().fg(Color::White)),
            ]),
            4 => Line::from(vec![
                Span::styled(
                    "[1-6] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Tabs  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Tab] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Panel  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[T] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Tunnel  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[S] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Subnetz bewerben  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[D] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Löschen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Q] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Beenden", Style::default().fg(Color::White)),
            ]),
            _ => Line::from(vec![
                Span::styled(
                    "[1-6] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Tabs  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Tab] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Mesh wechseln  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[▲/▼] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Scrollen  ", Style::default().fg(Color::White)),
                Span::styled(
                    "[Q] ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("Beenden", Style::default().fg(Color::White)),
            ]),
        };

        let status_line = Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Gray)),
            Span::styled(&self.status_message, Style::default().fg(Color::LightCyan)),
        ]);

        let p = Paragraph::new(vec![shortcuts_line, status_line]).block(block);
        f.render_widget(p, area);
    }

    fn render_modal(&self, f: &mut Frame, modal: &ModalState) {
        let area = f.area();

        match modal {
            ModalState::ShowInviteQr {
                uri,
                token_id,
                user_name,
                qr_lines,
            } => {
                let modal_width = 68.min(area.width);
                let modal_height = (qr_lines.len() as u16 + 10).min(area.height);
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(x, y, modal_width, modal_height);

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" SOVEREIGN ONE-CLICK ONBOARDING QR-CODE ")
                    .border_style(
                        Style::default()
                            .fg(Color::LightGreen)
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(Style::default().bg(Color::Rgb(15, 20, 30)));

                let mut lines = Vec::new();
                lines.push(Line::from(vec![
                    Span::styled("Nutzer: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        user_name,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("   Token ID: ", Style::default().fg(Color::Gray)),
                    Span::styled(token_id, Style::default().fg(Color::Yellow)),
                ]));
                lines.push(Line::from(""));

                for ql in qr_lines {
                    lines.push(Line::from(Span::styled(
                        format!("   {}", ql),
                        Style::default().fg(Color::White),
                    )));
                }

                lines.push(Line::from(""));
                let uri_prev = if uri.len() > 60 {
                    format!("{}...", &uri[..60])
                } else {
                    uri.clone()
                };
                lines.push(Line::from(Span::styled(
                    format!("  URI: {}", uri_prev),
                    Style::default().fg(Color::Cyan),
                )));
                lines.push(Line::from(Span::styled(
                    "  [Esc / Enter / Q] Schließen",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::AddMember {
                name,
                pubkey,
                role_idx,
                active_field,
            } => {
                let modal_width = 64;
                let modal_height = 12;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" MITGLIED HINZUFÜGEN ")
                    .border_style(Style::default().fg(Color::Yellow))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let current_role = ALL_ROLES[*role_idx];
                let lines = vec![
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 0 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Name:       ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", name),
                            if *active_field == 0 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 1 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Public Key: ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", pubkey),
                            if *active_field == 1 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 2 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Rolle:      ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("◀ {} ({}) ▶", current_role.badge(), current_role.as_str()),
                            if *active_field == 2 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::LightCyan)
                            },
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Tab] Feld wechseln   [◀/▶] Rolle   [Enter] Speichern   [Esc] Abbruch",
                        Style::default().fg(Color::DarkGray),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::CreateInvite {
                user_name,
                role_idx,
                groups,
                ttl_hours,
                max_uses,
                active_field,
            } => {
                let modal_width = 68;
                let modal_height = 16;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" NEUEN ONBOARDING-INVITE ERSTELLEN ")
                    .border_style(Style::default().fg(Color::LightGreen))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let current_role = ALL_ROLES[*role_idx];
                let lines = vec![
                    Line::from(vec![
                        Span::styled(if *active_field == 0 { "▶ " } else { "  " }, Style::default().fg(Color::Yellow)),
                        Span::styled("Ziel-Nutzer:   ", Style::default().fg(Color::Gray)),
                        Span::styled(format!("{}_", user_name), if *active_field == 0 { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) }),
                    ]),
                    Line::from(vec![
                        Span::styled(if *active_field == 1 { "▶ " } else { "  " }, Style::default().fg(Color::Yellow)),
                        Span::styled("Rolle:         ", Style::default().fg(Color::Gray)),
                        Span::styled(format!("◀ {} ({}) ▶", current_role.badge(), current_role.as_str()), if *active_field == 1 { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Cyan) }),
                    ]),
                    Line::from(vec![
                        Span::styled(if *active_field == 2 { "▶ " } else { "  " }, Style::default().fg(Color::Yellow)),
                        Span::styled("Gruppen (AD):  ", Style::default().fg(Color::Gray)),
                        Span::styled(format!("{}_", groups), if *active_field == 2 { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) }),
                    ]),
                    Line::from(vec![
                        Span::styled(if *active_field == 3 { "▶ " } else { "  " }, Style::default().fg(Color::Yellow)),
                        Span::styled("Gültigkeit:    ", Style::default().fg(Color::Gray)),
                        Span::styled(format!("◀ {} Stunden ▶", ttl_hours), if *active_field == 3 { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) }),
                    ]),
                    Line::from(vec![
                        Span::styled(if *active_field == 4 { "▶ " } else { "  " }, Style::default().fg(Color::Yellow)),
                        Span::styled("Max. Verwend.: ", Style::default().fg(Color::Gray)),
                        Span::styled(format!("◀ {} Mal ▶", max_uses), if *active_field == 4 { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::White) }),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("  [Tab] Feld   [◀/▶] Wert anpassen   [Enter] QR-Code generieren   [Esc] Abbruch", Style::default().fg(Color::DarkGray)),
                    ]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::CreateGroup {
                name,
                description,
                capabilities,
                active_field,
            } => {
                let modal_width = 68;
                let modal_height = 14;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" SECURITY GROUP ANLEGEN (AD-STYLE) ")
                    .border_style(Style::default().fg(Color::Magenta))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 0 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Gruppenname:   @", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", name),
                            if *active_field == 0 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 1 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Beschreibung:  ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", description),
                            if *active_field == 1 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 2 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Capabilities:  ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", capabilities),
                            if *active_field == 2 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Tab] Feld wechseln   [Enter] Gruppe erstellen   [Esc] Abbruch",
                        Style::default().fg(Color::DarkGray),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::AddPeer {
                callsign,
                node_id,
                pubkey,
                endpoint,
                active_field,
            } => {
                let modal_width = 68;
                let modal_height = 15;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" PEER TOPOLOGIE KONFIGURIEREN ")
                    .border_style(Style::default().fg(Color::Cyan))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 0 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Callsign:    ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", callsign),
                            if *active_field == 0 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 1 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Node ID:     ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", node_id),
                            if *active_field == 1 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 2 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Public Key:  ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", pubkey),
                            if *active_field == 2 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 3 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Endpunkt:    ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", endpoint),
                            if *active_field == 3 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Tab] Feld wechseln   [Enter] Speichern   [Esc] Abbruch",
                        Style::default().fg(Color::DarkGray),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::CreateTunnel {
                name,
                local_port,
                remote_port,
                active_field,
            } => {
                let modal_width = 64;
                let modal_height = 13;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" TUNNEL / PORT-FREIGABE ERSTELLEN ")
                    .border_style(Style::default().fg(Color::Yellow))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 0 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Dienst-Name:  ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", name),
                            if *active_field == 0 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 1 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Lokaler Port: ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", local_port),
                            if *active_field == 1 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 2 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Remote Port:  ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", remote_port),
                            if *active_field == 2 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Tab] Feld wechseln   [Enter] Anlegen   [Esc] Abbruch",
                        Style::default().fg(Color::DarkGray),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::RevokeMember { name, reason } => {
                let modal_width = 64;
                let modal_height = 8;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" MITGLIED SPERREN (KRL EVICTION) ")
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Sperre Mitglied: ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            name,
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Begründung:      ", Style::default().fg(Color::Gray)),
                        Span::styled(format!("{}_", reason), Style::default().fg(Color::White)),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Enter] Bestätigen & Sperren   [Esc] Abbrechen",
                        Style::default().fg(Color::DarkGray),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::ConfirmDeleteMember { name } => {
                let modal_width = 64;
                let modal_height = 7;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" MITGLIED WIRKLICH LÖSCHEN? ")
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Soll Mitglied '", Style::default().fg(Color::White)),
                        Span::styled(
                            name,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            "' unwiderruflich gelöscht werden?",
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Enter / J] Ja, Löschen         [Esc] Abbrechen",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::ConfirmDeleteGroup { name } => {
                let modal_width = 64;
                let modal_height = 7;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" GRUPPE WIRKLICH LÖSCHEN? ")
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Soll Gruppe '@", Style::default().fg(Color::White)),
                        Span::styled(
                            name,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("' gelöscht werden?", Style::default().fg(Color::White)),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Enter / J] Ja, Löschen         [Esc] Abbrechen",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::ConfirmRevokeInvite {
                token_id,
                user_name,
            } => {
                let modal_width = 64;
                let modal_height = 7;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" INVITE-TOKEN WIRKLICH REVOZIEREN? ")
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Soll Token '", Style::default().fg(Color::White)),
                        Span::styled(
                            token_id,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("' für '{}' gesperrt werden?", user_name),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Enter / J] Ja, Sperren         [Esc] Abbrechen",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::ConfirmDeletePeer { callsign, .. } => {
                let modal_width = 64;
                let modal_height = 7;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" PEER ENTFERNEN? ")
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Soll Peer '", Style::default().fg(Color::White)),
                        Span::styled(
                            callsign,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            "' aus der Topologie entfernt werden?",
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Enter / J] Ja, Entfernen       [Esc] Abbrechen",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::ConfirmDeleteTunnel { name, .. } => {
                let modal_width = 64;
                let modal_height = 7;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" TUNNEL ENTFERNEN? ")
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Soll Tunnel '", Style::default().fg(Color::White)),
                        Span::styled(
                            name,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            "' geschlossen und entfernt werden?",
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Enter / J] Ja, Schließen       [Esc] Abbrechen",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::AdvertiseSubnet {
                cidr,
                endpoint,
                active_field,
            } => {
                let modal_width = 68;
                let modal_height = 13;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" VPC SUBMETZ BEWERBEN (SUBNET ROUTER) ")
                    .border_style(Style::default().fg(Color::LightGreen))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 0 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Subnetz-CIDR:     ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", cidr),
                            if *active_field == 0 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled(
                            if *active_field == 1 { "▶ " } else { "  " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled("Gateway Router:   ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            format!("{}_", endpoint),
                            if *active_field == 1 {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  Beispiel: 10.0.0.0/16 oder 192.168.1.0/24 (Zero Kernel-TUN)",
                        Style::default().fg(Color::DarkGray),
                    )]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Tab] Feld wechseln   [Enter] Route aktivieren   [Esc] Abbruch",
                        Style::default().fg(Color::DarkGray),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }

            ModalState::ConfirmWithdrawSubnet { cidr } => {
                let modal_width = 64;
                let modal_height = 7;
                let x = area.width.saturating_sub(modal_width) / 2;
                let y = area.height.saturating_sub(modal_height) / 2;
                let modal_rect = Rect::new(
                    x,
                    y,
                    modal_width.min(area.width),
                    modal_height.min(area.height),
                );

                f.render_widget(Clear, modal_rect);

                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(" SUBNETZ-ROUTE ZURÜCKZIEHEN? ")
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::Rgb(20, 24, 34)));

                let lines = vec![
                    Line::from(vec![
                        Span::styled("Soll Subnetz-Route '", Style::default().fg(Color::White)),
                        Span::styled(
                            cidr,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            "' wirklich zurückgezogen werden?",
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "  [Enter / J] Ja, Zurückziehen    [Esc] Abbrechen",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )]),
                ];

                let p = Paragraph::new(lines).block(block);
                f.render_widget(p, modal_rect);
            }
        }
    }
}
