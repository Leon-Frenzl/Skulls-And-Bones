//! 1-Click Sovereign Company & Team Mesh Bootstrap Wizard
//!
//! Enables teams and organizations to bootstrap and self-host their own
//! sovereign P2P mesh network with local-first peer routing.
//!
//! Sets up:
//! - Hermetic VRF Overlay Network Subnet (e.g. 10.240.0.0/16)
//! - Active Directory-style RBAC Groups (@admins, @devops, @developers, @database-admins, @auditors)
//! - Root Identity & Admin User with cryptographic credentials
//! - Initial 1-Click Developer Onboarding Invite Link & Terminal ASCII QR Code
//! - Production-ready Native OS Service units (Systemd on Linux, Background Service on Windows)

use colored::Colorize;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::identity::NodeIdentity;
use crate::network::NetworkStore;
use crate::rbac::{
    MeshGroup, MeshInviteToken, MeshMember, MeshRbacStore, MeshRole, CAP_STREAM_TRANSFER,
    CAP_TELEMETRY_READ, CAP_TUNNEL_ANY, CAP_TUNNEL_SSH,
};
use crate::service::{
    generate_linux_deploy_script, generate_systemd_unit, generate_windows_ps1_script,
};

pub struct BootstrapOptions {
    pub name: Option<String>,
    pub anchor_endpoint: Option<String>,
    pub cidr: Option<String>,
    pub admin_name: Option<String>,
    pub headless: bool,
}

fn prompt(prompt_text: &str, default_val: &str) -> String {
    print!(
        "  {} [{}] > ",
        prompt_text.bold().cyan(),
        default_val.yellow()
    );
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let trimmed = input.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    default_val.to_string()
}

pub fn run_bootstrap(opts: BootstrapOptions) -> Result<(), String> {
    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {} // {}",
        "S&B SOVEREIGN MESH".cyan().bold(),
        "COMPANY & TEAM BOOTSTRAP WIZARD".bold()
    );
    println!(
        "  {}",
        "Sovereign Team & Enterprise Mesh Bootstrap (Bring-Your-Own-Mesh)".bright_white()
    );
    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );

    let (mesh_name, anchor_ep, subnet_cidr, admin_user) = if opts.headless {
        let name = opts.name.unwrap_or_else(|| "corp-mesh".to_string());
        let anchor = opts
            .anchor_endpoint
            .unwrap_or_else(|| "127.0.0.1:58888".to_string());
        let cidr = opts.cidr.unwrap_or_else(|| "auto".to_string());
        let admin = opts.admin_name.unwrap_or_else(|| "admin".to_string());
        (name, anchor, cidr, admin)
    } else {
        println!("  Beantworte kurz die Parameter für dein souveränes Firmen-Netzwerk:");
        println!("  (Drücke ENTER um den Standardwert zu übernehmen)\n");

        let name = opts
            .name
            .unwrap_or_else(|| prompt("1. Name des Mesh-Netzwerks (Tenant)", "corp-mesh"));
        let default_anchor = opts
            .anchor_endpoint
            .unwrap_or_else(|| "127.0.0.1:58888".to_string());
        let anchor = prompt("2. Öffentliche Anchor IP:Port (Server)", &default_anchor);
        let default_cidr = opts.cidr.unwrap_or_else(|| "auto".to_string());
        let cidr = prompt(
            "3. Overlay IP-Subnetz CIDR ('auto' = nächster freier Bereich)",
            &default_cidr,
        );
        let default_admin = opts.admin_name.unwrap_or_else(|| "admin".to_string());
        let admin = prompt("4. Administrator Rufname / Callsign", &default_admin);
        (name, anchor, cidr, admin)
    };

    let clean_name = mesh_name.trim().to_lowercase();
    let data_dir = crate::identity::default_data_dir()?;
    let state_paths = crate::state::MeshStatePaths::for_mesh_at(&data_dir, &clean_name)?;
    state_paths.ensure()?;
    let legacy_paths = crate::state::MeshStatePaths::legacy_paths(&data_dir, &clean_name)?;
    if legacy_paths.iter().any(|path| path.exists()) {
        eprintln!(
            "Legacy-Dateien für '{}' gefunden; sie werden nicht importiert oder gelöscht.",
            clean_name
        );
    }

    println!(
        "\n  {} Initialisiere kryptographische Identität & Keys...",
        "►".bright_cyan()
    );
    let identity = NodeIdentity::load_or_generate(&state_paths.identity)?;

    // 1. Initialize Network in NetworkStore
    fs::create_dir_all(&data_dir)
        .map_err(|error| format!("Mesh-Netzwerkkatalog konnte nicht erstellt werden: {error}"))?;
    let networks_file = data_dir.join("networks.json");

    let mut net_store =
        NetworkStore::load_or_create_default(&networks_file, &identity.wireguard_pubkey)?;
    let swarm_topic = format!("sbm-swarm-{}", clean_name);

    let anchor_port = anchor_ep
        .split(':')
        .last()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(58888);

    if !net_store.networks.contains_key(&clean_name) {
        let subnet_cidr = if subnet_cidr.trim().eq_ignore_ascii_case("auto") {
            net_store.next_free_cidr().ok_or_else(|| {
                "Kein freier Overlay-Bereich in 10.240.0.0/12 verfügbar.".to_string()
            })?
        } else {
            subnet_cidr.clone()
        };
        net_store.create_network(
            &clean_name,
            &format!("Sovereign Team Mesh ({})", clean_name),
            &subnet_cidr,
            &identity.wireguard_pubkey,
            Some(&swarm_topic),
            None,
            Some(anchor_port),
        )?;
    }
    if let Some(network) = net_store.networks.get_mut(&clean_name) {
        network.wireguard_pubkey = identity.wireguard_pubkey.clone();
        network.listen_port = anchor_port;
    }
    net_store.switch_network(&clean_name)?;
    net_store.save()?;
    if state_paths.config.exists() {
        let content = fs::read_to_string(&state_paths.config)
            .map_err(|error| format!("Mesh-Konfiguration konnte nicht gelesen werden: {error}"))?;
        toml::from_str::<crate::config::MeshConfig>(&content)
            .map_err(|error| format!("Mesh-Konfiguration ist ungültig: {error}"))?;
    } else {
        crate::config::MeshConfig::default().save(&state_paths.config)?;
    }
    if !state_paths.peers.exists() {
        crate::peer::PeerTable::new().save_to_file(&state_paths.peers)?;
    }
    println!(
        "  {} Multi-Mesh VRF Subnetz '{}' angelegt und aktiviert.",
        "✓".bright_green().bold(),
        clean_name
    );

    // 2. Initialize RBAC Store with Standard Security Groups & Admin
    let mut rbac_store = MeshRbacStore::load_or_create(&clean_name)?;

    // Define standard corporate security groups
    let corp_groups = vec![
        MeshGroup::new(
            "admins",
            "Enterprise Mesh Administrators with unrestricted management access",
            vec![
                "admin:*".to_string(),
                CAP_TUNNEL_ANY.to_string(),
                "routes:*".to_string(),
            ],
        ),
        MeshGroup::new(
            "devops",
            "Infrastructure & Deployment Engineers (Tunnels, Shares, Relays)",
            vec![
                CAP_TUNNEL_ANY.to_string(),
                "share:*".to_string(),
                "relay:allow".to_string(),
                "routes:*".to_string(),
                CAP_TELEMETRY_READ.to_string(),
            ],
        ),
        MeshGroup::new(
            "developers",
            "Software Developers & Microservices (SSH, Dev-Ports, Shared APIs)",
            vec![
                CAP_TUNNEL_SSH.to_string(),
                "tunnel:port:3000".to_string(),
                "tunnel:port:8000".to_string(),
                "tunnel:port:8080".to_string(),
                "share:*".to_string(),
                CAP_STREAM_TRANSFER.to_string(),
                "network:read".to_string(),
            ],
        ),
        MeshGroup::new(
            "database-admins",
            "Database Engineers & Data Stores (PostgreSQL, MySQL, MongoDB, Redis)",
            vec![
                "tunnel:port:5432".to_string(),
                "tunnel:port:3306".to_string(),
                "tunnel:port:27017".to_string(),
                "tunnel:port:6379".to_string(),
                "network:read".to_string(),
            ],
        ),
        MeshGroup::new(
            "auditors",
            "Compliance & Security Auditors (Read-Only Audit & Telemetry)",
            vec![
                "audit:read".to_string(),
                "rbac:read".to_string(),
                CAP_TELEMETRY_READ.to_string(),
                "network:read".to_string(),
            ],
        ),
    ];

    for g in corp_groups {
        rbac_store.add_or_update_group(g);
    }

    // Register root admin member
    let mut admin_member = MeshMember::new(
        &admin_user,
        &identity.wireguard_pubkey,
        &identity.node_id,
        &clean_name,
        MeshRole::Admin,
    );
    admin_member.groups = vec!["admins".to_string()];
    admin_member.capabilities = vec!["admin:*".to_string()];
    rbac_store.add_or_update(admin_member);
    rbac_store.log_event(
        "mesh_bootstrapped",
        &admin_user,
        &identity.wireguard_pubkey,
        &format!(
            "Mesh '{}' mit Subnetz {} initialisiert",
            clean_name, subnet_cidr
        ),
    );

    // 3. Generate initial Developer Onboarding Invite Token
    let now = chrono::Utc::now().timestamp() as u64;
    let expires_at = now + (72 * 3600); // 72 h valid, single use
    let token_id = format!("inv-{:08x}", rand::random::<u32>());

    let dev_invite = MeshInviteToken {
        token_id: token_id.clone(),
        mesh_name: clean_name.clone(),
        user_name: "developer".to_string(),
        role: MeshRole::Developer,
        groups: vec!["developers".to_string()],
        capabilities: MeshRole::Developer.default_capabilities(),
        server_endpoint: anchor_ep.clone(),
        server_pubkey: identity.wireguard_pubkey.clone(),
        swarm_topic: swarm_topic.clone(),
        created_at: now,
        expires_at,
        max_uses: 1,
        current_uses: 0,
        revoked: false,
        signature: MeshInviteToken::new_secret(),
    };

    let invite_uri = dev_invite.encode_uri();
    let invite_file = dev_invite.write_uri_file(&invite_uri)?;
    rbac_store.add_invite(dev_invite.to_stored());
    rbac_store.save()?;
    println!(
        "  {} Enterprise RBAC Store mit 5 Gruppen & Admin '{}' konfiguriert.",
        "✓".bright_green().bold(),
        admin_user
    );

    // 4. Generate Deployment & Service Files (Native OS)
    let deploy_dir = data_dir.join("tenants").join(&clean_name).join("deploy");
    let _ = fs::create_dir_all(&deploy_dir);

    let dummy_exe = PathBuf::from("/usr/local/bin/sb-mesh");
    let systemd_content =
        generate_systemd_unit(&dummy_exe, true, Some(anchor_port), Some(&clean_name));
    let bash_content = generate_linux_deploy_script(&clean_name, anchor_port);
    let ps1_content = generate_windows_ps1_script(
        &PathBuf::from("sb-mesh.exe"),
        true,
        Some(anchor_port),
        Some(&clean_name),
    );

    let readme_content = format!(
        r#"# Sovereign Mesh: {}
Self-Hosted Overlay Network for Teams & Enterprises.
Native Rust — Local-First — Unabhängig von zentralen Cloud-Brokern.

## 1. Network Overview
- **Mesh Name:** `{}`
- **Subnet CIDR:** `{}`
- **Swarm Topic:** `{}`
- **Anchor Endpoint:** `{}`
- **Admin Identity:** `{}`

## 2. Anchor Deployment (Native OS Service)

### Option A: Linux VPS / Server (Systemd)
Run as root on your cloud VPS or dedicated server:
```bash
sudo ./deploy-anchor.sh
```
Or manually install the unit:
```bash
sudo cp sb-mesh.service /etc/systemd/system/sb-mesh.service
sudo systemctl daemon-reload
sudo systemctl enable --now sb-mesh
```

### Option B: Windows Server / Workstation
Run in PowerShell as Administrator:
```powershell
.\install-service.ps1
```
Or directly using CLI:
```cmd
sb mesh service install --anchor --mesh {}
sb mesh service start
```

## 3. Team Onboarding
An invite (72 h, single use) was written to an owner-only file (`~/.sb-mesh/invites/`).
Hand it to the invitee over a trusted channel; it is a bearer credential.
Developers join with a single command:
```bash
sb mesh join <invite-uri>
```
"#,
        clean_name,
        clean_name,
        subnet_cidr,
        swarm_topic,
        anchor_ep,
        identity.wireguard_pubkey,
        clean_name
    );

    // Save deploy files to ~/.sb-mesh/tenants/<name>/deploy only (never into the CWD)
    let _ = fs::write(deploy_dir.join("sb-mesh.service"), &systemd_content);
    let _ = fs::write(deploy_dir.join("deploy-anchor.sh"), &bash_content);
    let _ = fs::write(deploy_dir.join("install-service.ps1"), &ps1_content);
    let _ = fs::write(deploy_dir.join("README.md"), &readme_content);
    let local_deploy_dir = deploy_dir.clone();
    println!(
        "  {} Native Service- & Deployment-Skripte exportiert nach: {}",
        "✓".bright_green().bold(),
        local_deploy_dir.display()
    );

    println!(
        "\n{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );
    println!(
        "  {} // {}",
        "DEVELOPER ONBOARDING".bold().bright_green(),
        "INVITE (72 h, einmalig)".bold()
    );
    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════"
            .bold()
            .cyan()
    );

    // CVE-Threat: Bearer-credential leakage via stdout/QR in logs. Hardening: file (0600) only.
    println!(
        "\n  {} Invite-URI gespeichert (nur Besitzer lesbar): {}",
        "►".bright_yellow().bold(),
        invite_file.display().to_string().bright_white().bold()
    );
    println!(
        "  {} Entwickler treten mit diesem Befehl bei:",
        "►".bright_cyan().bold()
    );
    println!("    {}", "sb mesh join <invite-uri>".bright_yellow().bold());
    println!(
        "\n  {} Native Anchor-Hintergrunddienst starten:",
        "►".bright_magenta().bold()
    );
    println!(
        "    Auf diesem Rechner:  {}",
        format!("sb mesh service install --anchor --mesh {}", clean_name).white()
    );
    println!(
        "    Dienst starten:      {}",
        "sb mesh service start".bold().green()
    );
    println!(
        "    Auf Linux VPS:       {}",
        format!(
            "cd {} && sudo ./deploy-anchor.sh",
            local_deploy_dir.display()
        )
        .yellow()
    );

    println!(
        "\n  {} Live-Monitoring & RBAC Cockpit starten:",
        "►".bright_green().bold()
    );
    println!("    Terminal UI:         {}", "sb mesh ui".bold().cyan());
    println!("    Audit-Log:           {}", "sb mesh rbac audit".white());
    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════════════\n"
            .bold()
            .cyan()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_bootstrap_headless() {
        let opts = BootstrapOptions {
            name: Some("test-bootstrap-net".to_string()),
            anchor_endpoint: Some("192.168.1.100:58888".to_string()),
            cidr: Some("10.250.0.0/16".to_string()),
            admin_name: Some("alice-admin".to_string()),
            headless: true,
        };

        let res = run_bootstrap(opts);
        assert!(res.is_ok(), "Bootstrap should succeed: {:?}", res.err());

        // Verify rbac store created
        let rbac = MeshRbacStore::load_or_create("test-bootstrap-net").unwrap();
        assert_eq!(rbac.mesh_name, "test-bootstrap-net");
        assert!(rbac.groups.iter().any(|g| g.name == "admins"));
        assert!(rbac.groups.iter().any(|g| g.name == "developers"));
        assert!(rbac
            .members
            .iter()
            .any(|m| m.name == "alice-admin" && m.role == MeshRole::Admin));
        assert!(rbac
            .invites
            .iter()
            .any(|inv| inv.role == MeshRole::Developer));
        assert!(!rbac.audit_log.is_empty());

        // Clean up test deploy folder
        let _ = fs::remove_dir_all("deploy-test-bootstrap-net");
    }
}
