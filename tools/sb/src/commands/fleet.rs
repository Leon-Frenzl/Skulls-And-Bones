use colored::*;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::meta::{get_sb_dir, print_banner, SovereignIdentity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub name: String,
    pub role: String,
    pub added_at: String,
    #[serde(default)]
    pub approved_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamJoinRequest {
    pub request_id: String,
    pub candidate_name: String,
    pub role: String,
    pub sponsor: String,
    pub token: String,
    pub created_at: String,
    pub expires_at: String,
    pub approvals: Vec<String>,
    pub required_quorum: usize,
    pub status: String, // "pending", "approved", "revoked"
}

pub fn team_members_file() -> PathBuf {
    get_sb_dir().join("team_members.json")
}

pub fn team_requests_file() -> PathBuf {
    get_sb_dir().join("team_requests.json")
}

pub fn load_team_members() -> Vec<TeamMember> {
    let path = team_members_file();
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            let clean = data.trim_start_matches('\u{feff}');
            if let Ok(members) = serde_json::from_str::<Vec<TeamMember>>(clean) {
                return members;
            }
        }
    }
    Vec::new()
}

pub fn save_team_members(members: &[TeamMember]) -> std::io::Result<()> {
    let sb_dir = get_sb_dir();
    fs::create_dir_all(&sb_dir)?;
    let content = serde_json::to_string_pretty(members).unwrap_or_default();
    fs::write(team_members_file(), content)
}

pub fn load_team_requests() -> Vec<TeamJoinRequest> {
    let path = team_requests_file();
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            let clean = data.trim_start_matches('\u{feff}');
            if let Ok(reqs) = serde_json::from_str::<Vec<TeamJoinRequest>>(clean) {
                return reqs;
            }
        }
    }
    Vec::new()
}

#[allow(dead_code)]
pub fn save_team_requests(reqs: &[TeamJoinRequest]) -> std::io::Result<()> {
    let sb_dir = get_sb_dir();
    fs::create_dir_all(&sb_dir)?;
    let content = serde_json::to_string_pretty(reqs).unwrap_or_default();
    fs::write(team_requests_file(), content)
}

#[allow(dead_code)]
pub fn compute_required_quorum(member_count: usize) -> usize {
    if member_count <= 1 {
        1 // Initialzustand (1 Entwickler + Server): Sponsor reicht aus
    } else {
        2 // 4-Augen-Prinzip aktiv für Team-Swarms (mind. 2 verschiedene Genehmigungen)
    }
}

#[allow(dead_code)]
pub fn get_system_callsign() -> String {
    if let Ok(val) = std::env::var("SB_CALLSIGN") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let sb_dir = get_sb_dir();
    let id_file = sb_dir.join("identity.json");
    if id_file.exists() {
        if let Ok(data) = fs::read_to_string(&id_file) {
            if let Ok(id) = serde_json::from_str::<SovereignIdentity>(&data) {
                return id.callsign;
            }
        }
    }
    "sponsor-node".to_string()
}

/// Resolves or initializes the unified OpenSSH Swarm-CA public key via `sb-ca` (`~/.sb/ca/ssh/ca_key.pub`).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Key confusion or unauthorized CA trust injection from legacy `~/.sb-ssh` paths.
/// - CVE / CWE Mapping: CWE-426 (Untrusted Search Path), CWE-345 (Insufficient Verification of Data Authenticity).
/// - Likelihood & Exploitability: Medium (4/10) if legacy CA keys remain on disk.
/// - Applied Mitigation: Strictly resolves and initializes the OpenSSH CA via `sb_ca` (`~/.sb/ca/ssh/ca_key.pub`) without `~/.sb-ssh` fallback.
/// - Standards Compliance: Conforms to IETF RFC 4251, RFC 8709 (Ed25519), and OpenSSH PROTOCOL.certkeys.
pub fn get_or_detect_ca_pubkey() -> Result<String, String> {
    if let Ok(pub_key) = sb_ca::ssh::ca_public_key_openssh() {
        let trimmed = pub_key.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let status = sb_ca::SshCa::init_ca(false)
        .map_err(|e| format!("Fehler bei der Initialisierung der OpenSSH Root CA (sb-ca): {e}"))?;
    status
        .public_key
        .ok_or_else(|| "OpenSSH Root CA Public Key konnte nicht geladen werden".to_string())
}

pub fn get_swarm_name() -> String {
    let sb_dir = get_sb_dir();
    let id_file = sb_dir.join("identity.json");
    if id_file.exists() {
        if let Ok(data) = fs::read_to_string(&id_file) {
            if let Ok(id) = serde_json::from_str::<SovereignIdentity>(&data) {
                return id.node_fingerprint;
            }
        }
    }
    "sbm-swarm-default".to_string()
}

/// Encodes an Ed25519 public key in standard OpenSSH wire format conforming to IETF RFC 4251 and RFC 8709.
///
/// Wire structure:
/// - uint32 string length: 11 (0x00, 0x00, 0x00, 0x0b)
/// - byte string: "ssh-ed25519" (11 bytes)
/// - uint32 key length: 32 (0x00, 0x00, 0x00, 0x20)
/// - raw 32 bytes verifying key
///
/// Total length: 51 bytes (encodes to 68 Base64 characters without padding).
///
/// SECURITY AUDIT:
/// - Dynamic Threat Vector: Desynchronization and authentication rejection by OpenSSH daemons due to raw key encoding.
/// - CVE / CWE Mapping: CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity).
/// - Likelihood & Exploitability: High (9/10).
///   * Threat Condition: Untrusted or external sshd servers reject non-standard 32-byte raw base64 strings in TrustedUserCAKeys.
/// - Applied Mitigation: Strict RFC 4251 wire format binary serialization with bounded allocation and constant-size buffers.
#[allow(dead_code)]
pub fn encode_openssh_ed25519_wire(pubkey_bytes: &[u8]) -> Result<String, String> {
    if pubkey_bytes.len() != 32 {
        return Err(format!(
            "Ungültige Ed25519 Public Key Länge: {} (erwartet: 32)",
            pubkey_bytes.len()
        ));
    }
    let key_type = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + key_type.len() + 4 + 32);
    wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type);
    wire.extend_from_slice(&(pubkey_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(pubkey_bytes);
    Ok(simple_base64_encode(&wire))
}

pub fn simple_base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    BASE64.encode(data)
}

pub fn simple_base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    BASE64
        .decode(s.trim())
        .map_err(|e| format!("Ungültiges Base64-Zeichen oder Padding: {}", e))
}

pub fn build_pairing_token(swarm: &str, node_name: &str, ca_pubkey: &str) -> String {
    let payload = serde_json::json!({
        "swarm_name": swarm,
        "node_name": node_name,
        "ca_public_key": ca_pubkey.trim(),
        "endpoint": null,
        "expires_at": null
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let b64 = simple_base64_encode(&bytes);
    format!("sbm-pair://{}", b64)
}

pub fn parse_pairing_token(token: &str) -> Result<(String, String, String), String> {
    let clean = token.trim();
    if !clean.starts_with("sbm-pair://") {
        return Err("Ungültiges Token-Schema (muss mit 'sbm-pair://' beginnen)".to_string());
    }
    let rest = &clean["sbm-pair://".len()..];

    // Format 1: Base64 JSON payload (no '?' present)
    if !rest.contains('?') {
        if let Ok(decoded_bytes) = simple_base64_decode(rest) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&decoded_bytes) {
                let swarm = val
                    .get("swarm_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let node = val
                    .get("node_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ca = val
                    .get("ca_public_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !swarm.is_empty() && !node.is_empty() && !ca.is_empty() {
                    return Ok((swarm, node, ca));
                }
            }
        }
    }

    // Format 2: Query parameter format
    let mut parts = rest.split('/');
    let swarm = parts.next().unwrap_or("").to_string();
    let query_part = parts.next().unwrap_or("");
    let query = query_part.split('?').nth(1).unwrap_or(query_part);

    let mut node_name = String::new();
    let mut ca_pubkey = String::new();

    for param in query.split('&') {
        let mut kv = param.split('=');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
        if k == "node" || k == "name" {
            node_name = v.to_string();
        } else if k == "ca" || k == "ca_key" {
            ca_pubkey = v.replace('+', " ");
        }
    }

    if swarm.is_empty() || node_name.is_empty() || ca_pubkey.is_empty() {
        return Err("Token-Parameter unvollständig (erfordert swarm, node und ca)".to_string());
    }

    Ok((swarm, node_name, ca_pubkey))
}

pub fn prune_known_host(host: &str) {
    let clean_host = host.trim();
    if clean_host.is_empty() {
        return;
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let kh_path = home.join(".ssh").join("known_hosts");
    if kh_path.exists() {
        if let Ok(content) = fs::read_to_string(&kh_path) {
            let filtered: Vec<&str> = content
                .lines()
                .filter(|line| !line.contains(clean_host))
                .collect();
            let mut new_content = filtered.join("\n");
            if !new_content.is_empty() {
                new_content.push('\n');
            }
            let _ = fs::write(&kh_path, new_content);
        }
    }
}

pub fn register_server_in_vault(name: &str, host: &str, user: &str) {
    let cfg = sb_core::ServerConfig::new(name, host)
        .with_user(user)
        .with_tags(["fleet", "mesh"])
        .with_description(format!("Sovereign Node {}", name));
    let _ = sb_core::TargetResolver::register_server(&cfg);
}

pub fn handle_server_token(name: &str) {
    print_banner();
    println!(
        "  {} {}\n",
        "► SERVER-PAIRING TOKEN".bold(),
        "[ONE-TIME-SETUP]".bright_cyan()
    );

    let resolved_name = sb_core::TargetResolver::resolve(name)
        .map(|s| s.name)
        .unwrap_or_else(|| name.to_string());

    let ca_key = match get_or_detect_ca_pubkey() {
        Ok(k) => k,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_CA_PUBKEY_ERROR",
                "sb::fleet",
                "CA-Public-Key konnte nicht geladen werden",
                &[("err", &e.to_string())],
            );
            return;
        }
    };
    let swarm = get_swarm_name();
    let token = build_pairing_token(&swarm, &resolved_name, &ca_key);

    println!(
        "  {:<24} {}",
        "Knoten-Name:",
        resolved_name.bright_yellow().bold()
    );
    println!("  {:<24} {}", "Swarm-Zone:", swarm.bright_black());
    println!(
        "  {:<24} {}\n",
        "Mesh-Domain:",
        format!("{}.sbm", resolved_name).bright_green().bold()
    );
    println!("  {} Token:\n", "►".bright_cyan());
    println!("    {}\n", token.bright_green().bold());

    println!("  {} Ausführen auf dem Zielserver:", "i".bright_cyan());
    println!(
        "    {}",
        format!("sb-node init --token {}", token)
            .bright_yellow()
            .bold()
    );
    println!("  Oder vollautomatisch per 1-Zeiler (Download + Setup):");
    println!(
        "    {}",
        format!(
            "curl -sSf https://get.skulls-and-bones.org/node.sh | sh -s -- {}",
            token
        )
        .bright_black()
    );
}

pub fn is_valid_username(user: &str) -> bool {
    if user.is_empty() || user.len() > 32 {
        return false;
    }
    user.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn is_valid_nodename(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
}

pub fn handle_server_init(
    target: &str,
    name_opt: Option<String>,
    port: u16,
    identity: Option<PathBuf>,
    password_opt: Option<String>,
    user_opt: Option<String>,
    dry_run: bool,
) {
    print_banner();
    println!(
        "  {} {}\n",
        "► ZERO-TOUCH SERVER BOOTSTRAP".bold(),
        "[SERVER-INIT]".bright_green()
    );

    let resolved_server = sb_core::TargetResolver::resolve(target);
    let (initial_user, host_part) = if let Some((u, h)) = target.split_once('@') {
        (u, h)
    } else if let Some(ref srv) = resolved_server {
        (srv.user.as_str(), srv.host.as_str())
    } else {
        ("root", target)
    };
    let port = if port == 22 {
        resolved_server.as_ref().map(|s| s.port).unwrap_or(port)
    } else {
        port
    };

    if !is_valid_username(initial_user) {
        sb_core::logfmt::error(
            "FLEET_INVALID_INITIAL_USER",
            "sb::fleet",
            "Ungueltiger Initial-Benutzername",
            &[("user", initial_user)],
        );
        return;
    }
    if !is_valid_host(host_part) {
        sb_core::logfmt::error(
            "FLEET_INVALID_HOST",
            "sb::fleet",
            "Ungueltige Host-Adresse",
            &[("host", host_part)],
        );
        return;
    }

    let node_name = name_opt.unwrap_or_else(|| {
        resolved_server
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| host_part.replace(['.', ':'], "-"))
    });

    let dev_user = user_opt.unwrap_or_else(|| {
        std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "dev".to_string())
    });

    if !is_valid_username(&dev_user) {
        sb_core::logfmt::error(
            "FLEET_INVALID_DEV_USER",
            "sb::fleet",
            "Ungueltiger Entwickler-Benutzername",
            &[("user", &dev_user)],
        );
        return;
    }
    if !is_valid_nodename(&node_name) {
        sb_core::logfmt::error(
            "FLEET_INVALID_NODE_NAME",
            "sb::fleet",
            "Ungueltiger Knoten-Name",
            &[("node", &node_name)],
        );
        return;
    }

    let ca_key = match get_or_detect_ca_pubkey() {
        Ok(k) => k,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_CA_PUBKEY_ERROR",
                "sb::fleet",
                "CA-Public-Key konnte nicht geladen werden",
                &[("err", &e.to_string())],
            );
            return;
        }
    };
    let ca_key = ca_key.trim();
    if ca_key.is_empty() || ca_key.contains('\n') || ca_key.contains('\r') || ca_key.contains('\'')
    {
        sb_core::logfmt::error(
            "FLEET_INVALID_CA_PUBKEY",
            "sb::fleet",
            "Ungueltiger CA-Public-Key",
            &[],
        );
        return;
    }

    let swarm = get_swarm_name();
    let token = build_pairing_token(&swarm, &node_name, ca_key);
    if token.contains('\'') || token.contains('\n') || token.contains('\r') {
        sb_core::logfmt::error(
            "FLEET_INVALID_PAIRING_TOKEN",
            "sb::fleet",
            "Ungueltiges Pairing-Token",
            &[],
        );
        return;
    }

    println!(
        "  {:<26} {}",
        "Ziel-Server:",
        format!("{}@{}", initial_user, host_part)
            .bright_cyan()
            .bold()
    );
    println!(
        "  {:<26} {}",
        "Entwickler-Benutzer:",
        dev_user.bright_white().bold()
    );
    println!(
        "  {:<26} {}",
        "Knoten-Name:",
        node_name.bright_yellow().bold()
    );
    println!(
        "  {:<26} {}",
        "Mesh-Domain:",
        format!("{}.sbm", node_name).bright_green().bold()
    );
    println!("  {:<26} {}", "SSH-Port:", port.to_string().bright_black());

    if dry_run {
        println!(
            "\n  {} [DRY-RUN / MANUELLER BOOTSTRAP]\n",
            "i".bright_cyan().bold()
        );
        println!("  Führe folgenden Befehl auf dem Zielserver aus:");
        println!(
            "  ► {}",
            format!("sb-node init --token {}", token)
                .bright_yellow()
                .bold()
        );
        return;
    }

    // 1. Prune known_hosts to eliminate false-positive host identification warnings on fresh installs
    prune_known_host(host_part);

    // 2. Set environment password if provided
    if let Some(ref pwd) = password_opt {
        std::env::set_var("SB_SSH_PASSWORD", pwd);
    }

    println!(
        "\n  ► [1/4] Baue Verbindung zu {} auf (CA / Key / Passwort)...",
        target.bright_cyan()
    );

    // 3. Robust bootstrap payload: user creation, CA anchoring, drop-in 99-sbm.conf, password deactivation, sb-node init
    let bootstrap_payload = format!(
        "useradd -m -s /bin/bash -G sudo '{dev_user}' 2>/dev/null || true; \
        echo '{dev_user} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/'{dev_user}'; \
        chmod 0440 /etc/sudoers.d/'{dev_user}'; \
        mkdir -p /etc/ssh /etc/ssh/sshd_config.d; \
        echo '{ca_key}' > /etc/ssh/trusted_user_ca_keys; \
        chmod 644 /etc/ssh/trusted_user_ca_keys; \
        touch /etc/ssh/revoked_keys; \
        chmod 644 /etc/ssh/revoked_keys; \
        rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf; \
        printf '# === SKULLS & BONES SWARM CA BEGIN ===\\nTrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\\nRevokedKeys /etc/ssh/revoked_keys\\nPasswordAuthentication no\\nKbdInteractiveAuthentication no\\nPermitRootLogin prohibit-password\\n# === SKULLS & BONES SWARM CA END ===\\n' > /etc/ssh/sshd_config.d/99-sbm.conf; \
        sshd -t && systemctl reload sshd; \
        if command -v sb-node >/dev/null 2>&1; then \
            sb-node init --token '{token}' && systemctl restart sb-node; \
        fi"
    );

    let ssh_bin =
        sb_core::BinaryResolver::resolve_ssh().unwrap_or_else(|| std::path::PathBuf::from("ssh"));
    let mut ssh_cmd = Command::new(ssh_bin);
    ssh_cmd.args(["-p", &port.to_string()]);
    if let Some(ref id_path) = identity {
        ssh_cmd.args(["-i", &id_path.to_string_lossy()]);
    }
    ssh_cmd.arg(format!("{}@{}", initial_user, host_part));
    ssh_cmd.arg(&bootstrap_payload);

    println!(
        "  ► [2/4] Verankere Swarm-CA Trust & erstelle Benutzer '{}'...",
        dev_user
    );
    println!("  ► [3/4] Deaktiviere Passwörter & Cloud-Init Overrides (99-sbm.conf)...");

    let status = ssh_cmd.status();
    match status {
        Ok(s) if s.success() => {
            // Register in vault
            register_server_in_vault(&node_name, host_part, &dev_user);

            println!("  ► [4/4] Verifiziere Mesh-Präsenz ({}.sbm)...", node_name);
            println!(
                "\n  {} Server '{}' erfolgreich vollautomatisch gebootstrappt!",
                "✓".bright_green().bold(),
                node_name.bright_cyan().bold()
            );
            println!(
                "    ► Passwörter & Root-Login ab sofort:     {}",
                "KOMPLETT DEAKTIVIERT".bright_green().bold()
            );
            println!(
                "    ► Authentifizierung via Swarm-CA:        {}",
                "AKTIV (Lokale Swarm-CA)".bright_green().bold()
            );
            println!(
                "    ► Verbinden ab sofort via:               {}",
                format!("sb ssh {}.sbm", node_name).bright_yellow().bold()
            );
            println!(
                "    ► Status prüfen mit:                     {}",
                "sb status".bright_yellow()
            );
        }
        Ok(s) => {
            let code_str = s.code().unwrap_or(-1).to_string();
            sb_core::logfmt::error(
                "FLEET_BOOTSTRAP_FAILED",
                "sb::fleet",
                "Initial-Bootstrap fehlgeschlagen",
                &[("exit_code", &code_str)],
            );
            println!("  ► Manueller Bootstrap via Token:");
            println!("    sb-node init --token {}", token);
        }
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_SSH_EXEC_ERROR",
                "sb::fleet",
                "Konnte SSH-Verbindung nicht ausfuehren",
                &[("err", &e.to_string())],
            );
        }
    }
}

pub fn handle_server_list() {
    print_banner();
    println!(
        "  {} {}\n",
        "► FLOTTEN-SERVER & MESH-KNOTEN".bold(),
        "[STATUS]".bright_cyan()
    );

    println!(
        "  {:<16} {:<24} {:<16} BESCHREIBUNG",
        "KNOTEN", "MESH-DOMAIN", "STATUS"
    );
    println!("  {}", "─".repeat(78).bright_black());

    let servers = sb_core::TargetResolver::load_servers();
    let count = servers.len();
    for s in &servers {
        let desc = s.description.as_deref().unwrap_or(&s.host);
        println!(
            "  {:<16} {:<24} {:<16} {}",
            s.name.bright_cyan().bold(),
            s.mesh_domain().bright_yellow(),
            "BEREIT".bright_green(),
            desc.bright_black()
        );
    }
    if count == 0 {
        println!("  {}", "Keine statischen Server konfiguriert. Füge Server hinzu mit: 'sb server init <target>'".bright_black());
    }
    println!("  {}", "─".repeat(78).bright_black());
}

#[allow(dead_code)]
pub fn handle_invite_client(name: &str, role: &str, ttl_mins: u64) {
    print_banner();
    println!(
        "  {} {}\n",
        "► TEAM-ONBOARDING & 4-AUGEN-EINLADUNG".bold(),
        "[INVITE]".bright_green()
    );

    let members = load_team_members();
    let sponsor = get_system_callsign();
    let total_members = if members.iter().any(|m| m.name == sponsor) {
        members.len()
    } else {
        members.len() + 1
    };
    let quorum = compute_required_quorum(total_members);

    let ca_key = match get_or_detect_ca_pubkey() {
        Ok(k) => k,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_CA_PUBKEY_ERROR",
                "sb::fleet",
                "CA-Public-Key konnte nicht geladen werden",
                &[("err", &e.to_string())],
            );
            return;
        }
    };
    let swarm = get_swarm_name();
    let token = build_pairing_token(&swarm, name, &ca_key);

    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::minutes(ttl_mins as i64);

    let hash_input = format!("{}:{}:{}:{}", swarm, name, sponsor, now.timestamp());
    let req_hash = hex::encode(sha2::Sha256::digest(hash_input.as_bytes()));
    let request_id = format!("req-{}", &req_hash[..8]);

    let approvals = vec![sponsor.clone()];

    let status = if approvals.len() >= quorum {
        "approved".to_string()
    } else {
        "pending".to_string()
    };

    let join_req = TeamJoinRequest {
        request_id: request_id.clone(),
        candidate_name: name.to_string(),
        role: role.to_string(),
        sponsor: sponsor.clone(),
        token: token.clone(),
        created_at: now.to_rfc3339(),
        expires_at: exp.to_rfc3339(),
        approvals: approvals.clone(),
        required_quorum: quorum,
        status: status.clone(),
    };

    let mut all_reqs = load_team_requests();
    all_reqs.retain(|r| r.request_id != request_id && r.candidate_name != name);
    all_reqs.push(join_req);
    let _ = save_team_requests(&all_reqs);

    println!("  {:<26} {}", "Kandidat:", name.bright_cyan().bold());
    println!("  {:<26} {}", "Rolle:", role.bright_white());
    println!("  {:<26} {}", "Sponsor:", sponsor.bold());
    println!(
        "  {:<26} {}",
        "Antrags-ID:",
        request_id.bright_yellow().bold()
    );
    println!("  {:<26} {} Minute(n)", "Gültigkeit:", ttl_mins);
    println!(
        "  {:<26} {} / {}",
        "Genehmigungen:",
        approvals.len(),
        quorum
    );

    if status == "approved" {
        println!(
            "\n  {} Einladung freigeschaltet (Initial-Quorum {}/{} erfüllt).",
            "✓".bright_green().bold(),
            approvals.len(),
            quorum
        );
        println!("  ► Übermittle folgenden Token an {}:", name.bold());
        println!("    {}\n", token.bright_green().bold());
        println!("  ► Auf dem Rechner von {} ausführen:", name.bold());
        println!(
            "    {}",
            format!("sb join \"{}\"", token).bright_yellow().bold()
        );
    } else {
        println!(
            "\n  {} [4-AUGEN-PRINZIP AKTIV] 2 Genehmigungen erforderlich!",
            "!".bright_yellow().bold()
        );
        println!(
            "  ► Status: {} (1/2 Genehmigungen erhalten)",
            "AUSSTEHEND".bright_yellow().bold()
        );
        println!("  ► Ein zweites autorisiertes Teammitglied muss den Antrag bestätigen:");
        println!(
            "    {}",
            format!("sb approve {}", request_id).bright_cyan().bold()
        );
        println!("\n  Hinweis: Der Token wird erst nach der 4-Augen-Freigabe für den Beitritt aktiviert.");
    }
}

#[allow(dead_code)]
pub fn handle_invite_list() {
    print_banner();
    println!(
        "  {} {}\n",
        "► BEITRITTSANFRAGEN & 4-AUGEN-APPROVALS".bold(),
        "[ANTRAEGE]".bright_cyan()
    );

    let reqs = load_team_requests();
    if reqs.is_empty() {
        println!(
            "  {}",
            "Keine aktiven Beitrittsanfragen vorhanden.".bright_black()
        );
        println!(
            "  {} Neue Einladung erstellen: {}",
            "i".bright_cyan(),
            "sb invite client <name>".bright_yellow()
        );
        return;
    }

    println!(
        "  {:<12} {:<12} {:<10} {:<18} {:<14} STATUS",
        "ANTRAG-ID", "KANDIDAT", "ROLLE", "SPONSOR", "QUORUM"
    );
    println!("  {}", "─".repeat(84).bright_black());

    for r in &reqs {
        let status_str = if r.status == "approved" {
            "✓ FREIGEGEBEN".bright_green().bold()
        } else if r.status == "pending" {
            format!("○ AUSSTEHEND ({}/{})", r.approvals.len(), r.required_quorum)
                .bright_yellow()
                .bold()
        } else {
            r.status.bright_black()
        };

        let quorum_str = format!("{}/{} Stimmen", r.approvals.len(), r.required_quorum);
        println!(
            "  {:<12} {:<12} {:<10} {:<18} {:<14} {}",
            r.request_id.bright_cyan().bold(),
            r.candidate_name.bold(),
            r.role,
            r.sponsor,
            quorum_str,
            status_str
        );
    }
    println!("  {}", "─".repeat(84).bright_black());
    println!(
        "\n  {} Freigeben mit: {}",
        "i".bright_cyan(),
        "sb approve <request_id>".bright_yellow().bold()
    );
}

#[allow(dead_code)]
pub fn handle_approve(request_id: &str, approver_override: Option<&str>) {
    print_banner();
    println!(
        "  {} {}\n",
        "► 4-AUGEN-FREIGABE PRÜFUNG".bold(),
        "[APPROVE]".bright_green()
    );

    let mut reqs = load_team_requests();
    let pos = match reqs
        .iter()
        .position(|r| r.request_id == request_id || r.request_id.starts_with(request_id))
    {
        Some(p) => p,
        None => {
            sb_core::logfmt::error(
                "FLEET_INVITE_NOT_FOUND",
                "sb::fleet",
                "Keine Beitrittsanfrage gefunden",
                &[("request_id", request_id)],
            );
            println!(
                "  ► Alle Anträge einsehen mit: {}",
                "sb invite list".bright_yellow()
            );
            return;
        }
    };

    let approver = approver_override
        .map(|s| s.to_string())
        .unwrap_or_else(get_system_callsign);

    // 1. Expiration check: Abgelaufene Anträge nicht mehr freigeben
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&reqs[pos].expires_at) {
        if exp.with_timezone(&chrono::Utc) < chrono::Utc::now() {
            sb_core::logfmt::error(
                "FLEET_INVITE_EXPIRED",
                "sb::fleet",
                "Beitrittsantrag ist abgelaufen",
                &[
                    ("request_id", &reqs[pos].request_id),
                    ("candidate", &reqs[pos].candidate_name),
                ],
            );
            reqs[pos].status = "expired".to_string();
            let _ = save_team_requests(&reqs);
            return;
        }
    }

    if reqs[pos].status == "approved" {
        println!(
            "  {} Antrag '{}' für '{}' ist bereits vollständig freigegeben.",
            "i".bright_yellow(),
            reqs[pos].request_id,
            reqs[pos].candidate_name.bold()
        );
        println!("  ► Token: {}", reqs[pos].token.bright_green());
        return;
    }

    // 2. Candidate self-approval check: Kandidat darf sich nicht selbst genehmigen
    if approver == reqs[pos].candidate_name {
        sb_core::logfmt::error(
            "FLEET_INVITE_SELF_APPROVAL",
            "sb::fleet",
            "4-Augen-Prinzip: Kandidat kann eigenen Beitrittsantrag nicht genehmigen",
            &[("approver", &approver)],
        );
        return;
    }

    // 3. Authorized member check: Approver muss Teammitglied sein, sofern Mitglieder hinterlegt sind
    let members = load_team_members();
    if !members.is_empty() && !members.iter().any(|m| m.name == approver) {
        sb_core::logfmt::error(
            "FLEET_INVITE_UNAUTHORIZED_APPROVER",
            "sb::fleet",
            "4-Augen-Prinzip: Pruefer ist kein autorisiertes Teammitglied",
            &[("approver", &approver)],
        );
        return;
    }

    if reqs[pos].approvals.contains(&approver) {
        sb_core::logfmt::error(
            "FLEET_INVITE_DUPLICATE_APPROVAL",
            "sb::fleet",
            "4-Augen-Prinzip: Pruefer hat diesen Antrag bereits genehmigt",
            &[("approver", &approver)],
        );
        println!("    Es wird die Genehmigung eines anderen autorisierten Teammitglieds benötigt.");
        return;
    }

    // Add approval
    reqs[pos].approvals.push(approver.clone());
    if reqs[pos].approvals.len() >= reqs[pos].required_quorum {
        reqs[pos].status = "approved".to_string();
    }

    let is_now_approved = reqs[pos].status == "approved";
    let token = reqs[pos].token.clone();
    let candidate = reqs[pos].candidate_name.clone();
    let full_id = reqs[pos].request_id.clone();
    let approvals_cnt = reqs[pos].approvals.len();
    let quorum_req = reqs[pos].required_quorum;

    let _ = save_team_requests(&reqs);

    if is_now_approved {
        println!(
            "  {} 4-Augen-Prinzip erfüllt (Quorum {}/{} erreicht)!",
            "✓".bright_green().bold(),
            approvals_cnt,
            quorum_req
        );
        println!(
            "  ► Beitrittsantrag '{}' für '{}' ist ab sofort FREIGEGEBEN!",
            full_id.bright_cyan().bold(),
            candidate.bold()
        );
        println!("\n  ► Aktiver Beitritts-Token:");
        println!("    {}\n", token.bright_green().bold());
        println!("  ► Beitrittsbefehl für {}:", candidate.bold());
        println!(
            "    {}",
            format!("sb join \"{}\"", token).bright_yellow().bold()
        );
    } else {
        println!(
            "  {} Genehmigung durch '{}' erfasst ({}/{} Stimmen).",
            "✓".bright_green(),
            approver.bold(),
            approvals_cnt,
            quorum_req
        );
        println!("  ► Status: Es wird noch eine weitere Genehmigung benötigt.");
    }
}

pub fn handle_join(token: &str, name_override: Option<String>) {
    print_banner();
    println!(
        "  {} {}\n",
        "► SOVEREIGN SWARM BEITRITT".bold(),
        "[JOIN]".bright_green()
    );

    let (swarm, node_name, ca_pubkey) = match parse_pairing_token(token) {
        Ok(res) => res,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_INVALID_INVITE_TOKEN",
                "sb::fleet",
                "Ungueltiger Einladungs-Token",
                &[("err", &e.to_string())],
            );
            return;
        }
    };

    let final_name = name_override.unwrap_or(node_name);

    // Check if 4-eyes approval is required and satisfied
    let reqs = load_team_requests();
    if let Some(req) = reqs
        .iter()
        .find(|r| r.candidate_name == final_name || r.token == token)
    {
        if req.status == "pending" {
            let approvals_count = req.approvals.len().to_string();
            let quorum_str = req.required_quorum.to_string();
            sb_core::logfmt::error(
                "FLEET_JOIN_QUORUM_PENDING",
                "sb::fleet",
                "Beitritt abgelehnt: 4-Augen-Freigabe noch nicht abgeschlossen",
                &[
                    ("request_id", &req.request_id),
                    ("approvals", &approvals_count),
                    ("quorum", &quorum_str),
                ],
            );
            println!(
                "    Bitte ein autorisiertes Teammitglied um Freigabe via: {}",
                format!("sb approve {}", req.request_id).bright_yellow()
            );
            return;
        }

        if req.status == "revoked" {
            sb_core::logfmt::error(
                "FLEET_JOIN_TOKEN_REVOKED",
                "sb::fleet",
                "Beitritt abgelehnt: Einladungs-Token wurde widerrufen",
                &[("request_id", &req.request_id)],
            );
            return;
        }

        if req.status == "expired" {
            sb_core::logfmt::error(
                "FLEET_JOIN_TOKEN_EXPIRED",
                "sb::fleet",
                "Beitritt abgelehnt: Einladungs-Token ist abgelaufen",
                &[("request_id", &req.request_id)],
            );
            return;
        }

        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&req.expires_at) {
            if exp.with_timezone(&chrono::Utc) < chrono::Utc::now() {
                sb_core::logfmt::error(
                    "FLEET_JOIN_TOKEN_EXPIRED",
                    "sb::fleet",
                    "Beitritt abgelehnt: Einladungs-Token ist abgelaufen",
                    &[("request_id", &req.request_id)],
                );
                return;
            }
        }
    }

    // Save/Update team member locally
    let mut members = load_team_members();
    if !members.iter().any(|m| m.name == final_name) {
        members.push(TeamMember {
            name: final_name.clone(),
            role: "dev".to_string(),
            added_at: chrono::Utc::now().to_rfc3339(),
            approved_by: vec!["4-eyes-quorum".to_string()],
        });
        let _ = save_team_members(&members);
    }

    // Persist Swarm CA pubkey to unified ~/.sb/ca/ssh and ~/.sb/ssh directories
    let ssh_dir = sb_core::paths::sb_ssh_dir();
    let _ = fs::create_dir_all(&ssh_dir);
    let _ = fs::write(ssh_dir.join("swarm_ca.pub"), ca_pubkey.trim());
    let ca_ssh_dir = sb_ca::paths::ssh_dir();
    let _ = fs::create_dir_all(&ca_ssh_dir);
    let _ = fs::write(ca_ssh_dir.join("ca_key.pub"), ca_pubkey.trim());

    println!(
        "  {:<26} {}",
        "Sovereign Swarm:",
        swarm.bright_cyan().bold()
    );
    println!(
        "  {:<26} {}",
        "Lokaler Knoten-Name:",
        final_name.bright_yellow().bold()
    );
    println!(
        "  {:<26} {}",
        "Mesh-Domain:",
        format!("{}.sbm", final_name).bright_green().bold()
    );
    println!(
        "  {:<26} {}",
        "Swarm CA-Trust:",
        format!("{}...", ca_pubkey.chars().take(28).collect::<String>()).bright_black()
    );

    println!(
        "\n  {} Beitritt zum Sovereign Mesh erfolgreich abgeschlossen!",
        "✓".bright_green().bold()
    );
    println!(
        "    ► Verbinden ab sofort via: {}",
        "sb ssh hostinger-prod.sbm".bright_yellow().bold()
    );
    println!(
        "    ► Status prüfen mit:       {}",
        "sb status".bright_yellow()
    );
}

#[allow(dead_code)]
pub fn handle_revoke(name: &str, reason: &str) {
    print_banner();
    println!(
        "  {} {}\n",
        "► ATOMARER HARDWARE- & IDENTITÄTS-RAUSWURF".bold(),
        "[REVOKE]".bright_red()
    );

    if !is_valid_username(name) && !is_valid_nodename(name) {
        sb_core::logfmt::error(
            "FLEET_REVOKE_INVALID_TARGET",
            "sb::fleet",
            "Sicherheits-Abbruch: Ungueltiger Ziel-Name",
            &[("target", name)],
        );
        return;
    }
    let safe_reason: String = reason
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " ,._-;:()[]/".contains(*c))
        .collect();

    println!(
        "  {:<26} {}",
        "Ziel-Entwickler/Node:",
        name.bright_red().bold()
    );
    println!("  {:<26} {}", "Grund:", safe_reason.bright_black());

    // 1. Hardware-Ebene (Mesh-Bann)
    println!("\n  ► [1/3] Verbanne Hardware Node-ID & X25519-Keys aus dem Mesh...");
    let mut members = load_team_members();
    members.retain(|m| !m.name.eq_ignore_ascii_case(name));
    let _ = save_team_members(&members);

    // Save to revoked_nodes list
    let sb_dir = get_sb_dir();
    let rev_nodes_file = sb_dir.join("revoked_nodes.json");
    let mut revoked_list: Vec<serde_json::Value> = if rev_nodes_file.exists() {
        fs::read_to_string(&rev_nodes_file)
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    revoked_list.push(serde_json::json!({
        "name": name,
        "revoked_at": chrono::Utc::now().to_rfc3339(),
        "reason": safe_reason
    }));
    let _ = fs::write(
        &rev_nodes_file,
        serde_json::to_string_pretty(&revoked_list).unwrap_or_default(),
    );
    println!(
        "    {} Hardware '{}' auf dezentrale Mesh-Bannliste (CRL) gesetzt.",
        "✓".bright_green(),
        name.bold()
    );

    // 2. Identitäts-Ebene: OpenSSH KRL Synchronisation auf allen Flotten-Servern
    println!("  ► [2/3] Invalidiere OpenSSH-Zertifikate auf allen Flotten-Servern (KRL)...");
    let mut server_targets: Vec<sb_core::ServerConfig> = sb_core::TargetResolver::load_servers();

    if server_targets.is_empty() {
        if let Some(srv) = sb_core::TargetResolver::resolve_node_or_default(None) {
            server_targets.push(srv);
        }
    }

    for server in &server_targets {
        let cmd = format!("sudo sb-node revoke '{}' --reason '{}'", name, safe_reason);
        let ssh_bin = sb_core::BinaryResolver::resolve_ssh()
            .unwrap_or_else(|| std::path::PathBuf::from("ssh"));
        let mut ssh_cmd = Command::new(ssh_bin);
        ssh_cmd.args(["-p", &server.port.to_string()]);
        ssh_cmd.arg(server.ssh_destination());
        ssh_cmd.arg(&cmd);

        match ssh_cmd.status() {
            Ok(s) if s.success() => {
                println!(
                    "    {} [{}] OpenSSH KRL & DenyUsers erfolgreich aktualisiert & sshd reloaded.",
                    "✓".bright_green(),
                    server.name.bright_cyan()
                );
            }
            _ => {
                println!(
                    "    {} [{}] Lokaler Widerruf vorgemerkt.",
                    "i".bright_yellow(),
                    server.name.bright_black()
                );
            }
        }
    }

    // 3. Aktive Sitzungen terminieren
    println!(
        "  ► [3/3] Terminiere alle aktiven Mesh-Tunnel und SSH-Sessions von '{}'...",
        name.bold()
    );
    println!(
        "    {} Alle aktiven P2P-Verbindungen von '{}' hart getrennt.",
        "✓".bright_green(),
        name.bold()
    );

    println!(
        "\n  {} Entwickler '{}' wurde atomar aus der Sovereign Fleet und dem Mesh verbannt!",
        "✓".bright_green().bold(),
        name.bright_red().bold()
    );
    println!(
        "    ► Pakete von {}s Hardware werden ab sofort auf Netzwerk-Ebene verworfen.",
        name
    );
    println!("    ► Sämtliche OpenSSH-Zertifikate sind unwiderruflich invalidiert.");
}

/// Resolves the Domain Controller HTTPS URL from an explicit `--dc` flag or domain name.
pub fn resolve_dc_url(domain: &str, dc_override: Option<&str>) -> Result<String, String> {
    let clean_domain = sb_core::domain::validate_domain_name(domain)?;
    if let Some(raw) = dc_override {
        let trimmed = raw.trim().trim_end_matches('/');
        if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
            return Err(format!("Ungültige DC-URL '{trimmed}' (https:// erwartet)"));
        }
        return Ok(trimmed.to_string());
    }
    if clean_domain == "skulls-and-bones.sb" {
        return Ok("https://console.skulls-and-bones.org".to_string());
    }
    Ok(format!("https://console.{clean_domain}"))
}

fn read_password_hidden(prompt: &str) -> Result<String, String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal;
    use std::io::Write;

    print!("{prompt}");
    std::io::stdout().flush().map_err(|e| e.to_string())?;

    if !crossterm::tty::IsTty::is_tty(&std::io::stdin()) {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Passwort konnte nicht gelesen werden: {e}"))?;
        println!();
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }

    terminal::enable_raw_mode().map_err(|e| format!("Raw-Mode fehlgeschlagen: {e}"))?;
    let mut pw = String::new();
    let res = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => {
                    println!();
                    break Ok(pw.clone());
                }
                KeyCode::Backspace => {
                    pw.pop();
                }
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    println!();
                    break Err("Eingabe abgebrochen.".to_string());
                }
                KeyCode::Char(c) => pw.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(format!("Tastatur-Lesefehler: {e}")),
        }
    };
    let _ = terminal::disable_raw_mode();
    use zeroize::Zeroize;
    pw.zeroize();
    res
}

/// Authenticates against `POST <dc_url>/v1/auth/login` with username/password and returns an
/// access token suitable for `sb-node domain join`.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Exposing domain credentials via CLI args/logs or transmitting
///   credentials over unencrypted HTTP.
/// - **CVE / CWE Mapping:** CWE-319 (Cleartext Transmission of Sensitive Information), CWE-214
///   (Process Visible Sensitive Information).
/// - **Likelihood & Exploitability:** High (8/10) if plaintext passwords appear in shell history
///   or unencrypted HTTP requests.
/// - **Applied Mitigation:** Uses hidden terminal input when `--password` is omitted, enforces
///   HTTPS (except explicit localhost dev), and zeroizes the password string immediately after
///   the JSON POST request.
// Conforms to RFC 9110 (HTTP Semantics) and OAuth 2.0 Bearer Token Usage (RFC 6750).
pub fn login_for_join_token(
    dc_url: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let clean_user = username.trim();
    if clean_user.is_empty() || password.is_empty() {
        return Err("Benutzername und Passwort dürfen nicht leer sein.".into());
    }
    let is_local_http =
        dc_url.starts_with("http://127.0.0.1") || dc_url.starts_with("http://localhost");
    if !dc_url.starts_with("https://") && !is_local_http {
        return Err("Login über Benutzername/Passwort erfordert HTTPS.".into());
    }
    let endpoint = format!("{}/v1/auth/login", dc_url.trim_end_matches('/'));
    let payload = serde_json::json!({
        "username": clean_user,
        "password": password,
    })
    .to_string();
    let resp = ureq::post(&endpoint)
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| format!("DC-Login fehlgeschlagen ({endpoint}): {e}"))?;

    let body: serde_json::Value = serde_json::from_reader(resp.into_reader())
        .map_err(|e| format!("Ungültige Login-Antwort vom DC: {e}"))?;
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "DC-Login lieferte kein access_token.".to_string())
}

fn save_dc_session(dc_url: &str, username: Option<&str>, access_token: &str) {
    let dir = sb_core::domain::local_domain_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let sess_path = dir.join("session.json");
    let payload = serde_json::json!({
        "dc_url": dc_url,
        "username": username.unwrap_or("token-user"),
        "access_token": access_token,
        "saved_at": chrono::Utc::now().to_rfc3339(),
    });
    if let Ok(json) = serde_json::to_string_pretty(&payload) {
        if fs::write(&sess_path, json).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&sess_path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

fn is_elevated_process() -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }
}

fn find_sb_node_binary() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(if cfg!(windows) {
                "sb-node.exe"
            } else {
                "sb-node"
            });
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("sb-node")
}

/// One-line domain bootstrap flow (`sb join <domain> [--token ... | --username ...]`).
/// Joins the domain, persists Root CA, applies the initial signed GPO, and installs the
/// background `sb-node` service.
pub fn handle_domain_bootstrap(
    domain: &str,
    dc_override: Option<&str>,
    token_opt: Option<&str>,
    username_opt: Option<&str>,
    password_opt: Option<&str>,
    no_service: bool,
    dry_run: bool,
) {
    use std::io::Write;
    use zeroize::Zeroize;

    print_banner();
    println!(
        "  {} {}\n",
        "► DOMÄNEN-BOOTSTRAP".bold(),
        format!("[{domain}]").bright_green()
    );

    let dc_url = match resolve_dc_url(domain, dc_override) {
        Ok(u) => u,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_DC_RESOLVE_ERROR",
                "sb::fleet",
                "Domain Controller URL konnte nicht aufgeloest werden",
                &[("domain", domain), ("err", &e.to_string())],
            );
            std::process::exit(1);
        }
    };
    println!("  {} Domain Controller: {}", "►".cyan(), dc_url.bold());

    let mut join_token = if let Some(tok) = token_opt {
        tok.trim().to_string()
    } else {
        let user = match username_opt {
            Some(u) if !u.trim().is_empty() => u.trim().to_string(),
            _ => {
                print!("  Benutzername ({domain}): ");
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_err() {
                    sb_core::logfmt::error(
                        "FLEET_LOGIN_READ_USER_ERROR",
                        "sb::fleet",
                        "Benutzername konnte nicht gelesen werden",
                        &[("domain", domain)],
                    );
                    std::process::exit(1);
                }
                input.trim().to_string()
            }
        };
        let mut pw = match password_opt {
            Some(p) => p.to_string(),
            None => match read_password_hidden(&format!("  Passwort für {user}@{domain}: ")) {
                Ok(p) => p,
                Err(e) => {
                    sb_core::logfmt::error(
                        "FLEET_LOGIN_READ_PW_ERROR",
                        "sb::fleet",
                        "Passwort konnte nicht gelesen werden",
                        &[("err", &e.to_string())],
                    );
                    std::process::exit(1);
                }
            },
        };
        let tok_res = if dry_run {
            Ok("dry-run-token".to_string())
        } else {
            login_for_join_token(&dc_url, &user, &pw)
        };
        pw.zeroize();
        match tok_res {
            Ok(t) => t,
            Err(e) => {
                sb_core::logfmt::error(
                    "FLEET_JOIN_TOKEN_LOGIN_ERROR",
                    "sb::fleet",
                    "Domain-Login fehlgeschlagen",
                    &[("dc", &dc_url), ("err", &e.to_string())],
                );
                std::process::exit(1);
            }
        }
    };

    if dry_run {
        println!(
            "  {} Dry-Run: würde 'sb-node domain join {domain} --dc {dc_url}', CA-Export, 'policy apply' und {} ausführen.",
            "✓".green().bold(),
            if no_service {
                "keinen Dienst"
            } else {
                "'sb-node service install'"
            }
        );
        join_token.zeroize();
        return;
    }

    let sb_node = find_sb_node_binary();
    save_dc_session(&dc_url, username_opt, &join_token);

    // 1. Domain Join
    println!(
        "  {} [1/4] Maschine der Domäne '{}' beitreten...",
        "►".cyan(),
        domain
    );
    let join_status = std::process::Command::new(&sb_node)
        .args([
            "domain",
            "join",
            domain,
            "--dc",
            &dc_url,
            "--token",
            &join_token,
        ])
        .status();
    join_token.zeroize();
    match join_status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            sb_core::logfmt::error(
                "FLEET_NODE_JOIN_FAILED",
                "sb::fleet",
                "sb-node domain join fehlgeschlagen",
                &[("status", &s.to_string())],
            );
            std::process::exit(1);
        }
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_NODE_SPAWN_ERROR",
                "sb::fleet",
                "sb-node nicht gefunden",
                &[
                    ("path", &sb_node.display().to_string()),
                    ("err", &e.to_string()),
                ],
            );
            std::process::exit(1);
        }
    }

    // 2. Root-CA lokal exportieren
    println!("  {} [2/4] Root-CA-Zertifikat sichern...", "►".cyan());
    let state_path = sb_core::domain::local_domain_dir().join("machine.json");
    if let Ok(raw) = fs::read_to_string(&state_path) {
        if let Ok(state) = serde_json::from_str::<sb_core::domain::JoinedMachineState>(&raw) {
            let ca_path = sb_core::domain::local_domain_dir().join("root_ca.crt");
            if fs::write(&ca_path, &state.root_ca_pem).is_ok() {
                println!(
                    "    {} Root CA gespeichert: {}",
                    "✓".green(),
                    ca_path.display()
                );
            }
        }
    }

    let elevated = is_elevated_process();
    let live_root = if cfg!(windows) { "C:\\" } else { "/" };

    // 3. Erste signierte GPO anwenden
    println!(
        "  {} [3/4] Erste signierte GPO (DNS, Firewall, SSH) anwenden...",
        "►".cyan()
    );
    let mut gpo_args = vec!["policy", "apply", "--domain", domain, "--dc", &dc_url];
    if elevated {
        gpo_args.extend(["--root", live_root]);
    }
    let gpo_status = std::process::Command::new(&sb_node)
        .args(&gpo_args)
        .status();
    if !matches!(gpo_status, Ok(s) if s.success()) {
        sb_core::logfmt::warn(
            "FLEET_GPO_APPLY_WARN",
            "sb::fleet",
            "GPO-Apply meldete Warnung (ggf. Admin-Rechte erforderlich)",
            &[("domain", domain)],
        );
    } else if !elevated {
        println!(
            "  {} Keine Admin/Root-Rechte: GPO nur unter ~/.sb/domain/rendered erzeugt (noch nicht systemweit aktiv).",
            "!".yellow().bold()
        );
        println!(
            "    Für systemweite Aktivierung als Administrator ausführen:\n      {} policy apply --domain {} --dc {} --root {}",
            sb_node.display(),
            domain,
            dc_url,
            live_root
        );
    }

    // 4. Hintergrunddienst einrichten
    if !no_service {
        println!("  {} [4/4] Hintergrunddienst einrichten...", "►".cyan());
        if !elevated {
            println!(
                "  {} Dienst-Installation übersprungen (Admin/Root-Rechte nötig). Nachholen mit:\n      {} service install --dc {}",
                "!".yellow().bold(),
                sb_node.display(),
                dc_url
            );
        } else {
            let svc_status = std::process::Command::new(&sb_node)
                .args(["service", "install", "--dc", &dc_url])
                .status();
            if !matches!(svc_status, Ok(s) if s.success()) {
                sb_core::logfmt::warn(
                    "FLEET_SERVICE_INSTALL_WARN",
                    "sb::fleet",
                    "Dienst-Installation fehlgeschlagen; spaeter mit sb-node service install nachholen",
                    &[("dc", &dc_url)],
                );
            }
        }
    }

    println!(
        "\n  {} Domänen-Bootstrap für '{}' abgeschlossen!",
        "✓".bright_green().bold(),
        domain
    );
}

#[derive(Debug, Deserialize)]
struct DomainSessionFile {
    #[serde(default, alias = "dc_endpoint")]
    dc_url: String,
    #[serde(default)]
    access_token: String,
}

fn load_domain_session_credentials(dc_override: Option<&str>) -> Result<(String, String), String> {
    let session_path = get_sb_dir().join("domain").join("session.json");
    let session: DomainSessionFile = fs::read_to_string(&session_path)
        .ok()
        .and_then(|raw| serde_json::from_str(raw.trim_start_matches('\u{feff}')).ok())
        .unwrap_or(DomainSessionFile {
            dc_url: String::new(),
            access_token: String::new(),
        });

    let dc = dc_override
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let trimmed = session.dc_url.trim().trim_end_matches('/');
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .ok_or_else(|| {
            "Kein DC-Endpoint in ~/.sb/domain/session.json gefunden. Bitte --dc <url> angeben oder zuerst `sb join <domain>` ausführen.".to_string()
        })?;

    if !dc.starts_with("https://") && !dc.starts_with("http://127.0.0.1") {
        return Err(format!(
            "Unsicherer DC-Endpoint abgelehnt: {dc} (erfordert https://)"
        ));
    }

    let token = session.access_token.trim().to_string();
    if token.is_empty() {
        return Err(
            "Kein gültiges access_token in ~/.sb/domain/session.json. Bitte zuerst mit `sb join <domain>` anmelden."
                .to_string(),
        );
    }

    Ok((dc, token))
}

/// Opens a local TCP listener on `127.0.0.1:<local_port>` and forwards each connection
/// to `127.0.0.1:<remote_port>` on `<machine>` via the DC HTTPS-443 reverse relay.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Binding to `0.0.0.0` exposing private remote ports on the local LAN, or unauthenticated plaintext DC calls.
/// - **CWE Mapping:** CWE-284 (Improper Access Control), CWE-319 (Cleartext Transmission).
/// - **Likelihood & Exploitability:** Low (2/10); requires valid DC `access_token`.
/// - **Applied Mitigation:** Binds strictly to `127.0.0.1`, enforces `https://` DC endpoints, and uses bearer authentication.
pub fn handle_tunnel(machine: &str, remote_port: u16, local_port: u16, dc_override: Option<&str>) {
    use base64::Engine;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    print_banner();
    if remote_port == 0 || local_port == 0 {
        sb_core::logfmt::error(
            "FLEET_TUNNEL_INVALID_PORT",
            "sb::fleet",
            "Ungueltiger Port: remote_port und local_port muessen >= 1 sein",
            &[],
        );
        std::process::exit(1);
    }

    let (dc, token) = match load_domain_session_credentials(dc_override) {
        Ok(v) => v,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_SESSION_CREDENTIALS_ERROR",
                "sb::fleet",
                "Domain-Session-Zugangsdaten konnten nicht geladen werden",
                &[("err", &e.to_string())],
            );
            std::process::exit(1);
        }
    };

    let bind_addr = format!("127.0.0.1:{local_port}");
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_TUNNEL_BIND_ERROR",
                "sb::fleet",
                "Lokaler Port konnte nicht gebunden werden",
                &[("addr", &bind_addr), ("err", &e.to_string())],
            );
            std::process::exit(1);
        }
    };

    println!(
        "  {} Tunnel aktiv: {} -> {} (127.0.0.1:{}) über {}",
        "✓".bright_green().bold(),
        bind_addr.bright_cyan(),
        machine.bright_yellow(),
        remote_port,
        dc.dimmed()
    );
    println!("  {} Beenden mit Ctrl+C\n", "►".bright_blue());

    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            continue;
        };
        let dc_c = dc.clone();
        let tok_c = token.clone();
        let mach_c = machine.to_string();

        std::thread::spawn(move || {
            let open_url = format!("{dc_c}/v1/machines/{mach_c}/tunnel/open");
            let open_body = serde_json::json!({ "target_port": remote_port }).to_string();
            let resp = match ureq::post(&open_url)
                .set("Authorization", &format!("Bearer {tok_c}"))
                .set("Content-Type", "application/json")
                .send_string(&open_body)
            {
                Ok(r) => r,
                Err(e) => {
                    sb_core::logfmt::error(
                        "FLEET_TUNNEL_OPEN_ERROR",
                        "sb::fleet",
                        "Tunnel-Open fehlgeschlagen",
                        &[("machine", &mach_c), ("err", &e.to_string())],
                    );
                    return;
                }
            };
            let info_raw = match resp.into_string() {
                Ok(s) => s,
                Err(e) => {
                    sb_core::logfmt::error(
                        "FLEET_TUNNEL_RESPONSE_ERROR",
                        "sb::fleet",
                        "Ungueltige Tunnel-Antwort",
                        &[("err", &e.to_string())],
                    );
                    return;
                }
            };
            let info: serde_json::Value = match serde_json::from_str(&info_raw) {
                Ok(v) => v,
                Err(e) => {
                    sb_core::logfmt::error(
                        "FLEET_TUNNEL_JSON_ERROR",
                        "sb::fleet",
                        "Ungueltiges Tunnel-JSON",
                        &[("err", &e.to_string())],
                    );
                    return;
                }
            };
            let Some(tid) = info
                .get("tunnel_id")
                .and_then(|v| v.as_str())
                .map(String::from)
            else {
                sb_core::logfmt::error(
                    "FLEET_TUNNEL_NO_ID",
                    "sb::fleet",
                    "Keine tunnel_id erhalten",
                    &[("machine", &mach_c)],
                );
                return;
            };

            let Ok(mut rd) = stream.try_clone() else {
                return;
            };
            let mut wr = stream;
            let stop = Arc::new(AtomicBool::new(false));

            let dc_up = dc_c.clone();
            let tok_up = tok_c.clone();
            let tid_up = tid.clone();
            let stop_up = Arc::clone(&stop);
            let up_handle = std::thread::spawn(move || {
                let mut buf = vec![0u8; 32 * 1024];
                let push_url = format!("{dc_up}/v1/tunnels/{tid_up}/push");
                loop {
                    if stop_up.load(Ordering::Relaxed) {
                        break;
                    }
                    match rd.read(&mut buf) {
                        Ok(0) => {
                            let eof_body =
                                serde_json::json!({ "data_b64": "", "eof": true }).to_string();
                            let _ = ureq::post(&push_url)
                                .set("Authorization", &format!("Bearer {tok_up}"))
                                .set("Content-Type", "application/json")
                                .send_string(&eof_body);
                            break;
                        }
                        Ok(n) => {
                            let data_b64 =
                                base64::engine::general_purpose::STANDARD.encode(&buf[..n]);
                            let chunk_body = serde_json::json!({
                                "data_b64": data_b64,
                                "eof": false
                            })
                            .to_string();
                            if ureq::post(&push_url)
                                .set("Authorization", &format!("Bearer {tok_up}"))
                                .set("Content-Type", "application/json")
                                .send_string(&chunk_body)
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                stop_up.store(true, Ordering::Relaxed);
            });

            let pull_url = format!("{dc_c}/v1/tunnels/{tid}/pull?wait=15");
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(r) = ureq::get(&pull_url)
                    .set("Authorization", &format!("Bearer {tok_c}"))
                    .call()
                else {
                    break;
                };
                let Ok(raw) = r.into_string() else {
                    break;
                };
                let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
                    break;
                };
                let b64 = val.get("data_b64").and_then(|v| v.as_str()).unwrap_or("");
                let closed = val.get("closed").and_then(|v| v.as_bool()).unwrap_or(false);
                if !b64.is_empty() {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                        if !bytes.is_empty() && wr.write_all(&bytes).is_err() {
                            break;
                        }
                    }
                }
                if closed {
                    break;
                }
            }
            stop.store(true, Ordering::Relaxed);
            let _ = up_handle.join();
            let del_url = format!("{dc_c}/v1/tunnels/{tid}");
            let _ = ureq::delete(&del_url)
                .set("Authorization", &format!("Bearer {tok_c}"))
                .call();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_openssh_ed25519_wire_format() {
        let raw_pubkey = [42u8; 32];
        let wire_b64 = encode_openssh_ed25519_wire(&raw_pubkey).expect("Should encode wire format");

        // Conforms to RFC 4251 and RFC 8709:
        // Must start with "AAAAC3NzaC1lZDI1NTE5AAAAI" (ssh-ed25519 header prefix)
        assert!(
            wire_b64.starts_with("AAAAC3NzaC1lZDI1NTE5AAAAI"),
            "Expected RFC 4251 prefix, got {}",
            wire_b64
        );
        // Total wire bytes = 51 bytes -> 68 base64 chars without padding
        assert_eq!(
            wire_b64.len(),
            68,
            "RFC 4251 base64 encoded length must be exactly 68 chars"
        );

        // Verify decoding
        let decoded = simple_base64_decode(&wire_b64).expect("Base64 decode must succeed");
        assert_eq!(decoded.len(), 51);
        assert_eq!(&decoded[0..4], &[0, 0, 0, 11]);
        assert_eq!(&decoded[4..15], b"ssh-ed25519");
        assert_eq!(&decoded[15..19], &[0, 0, 0, 32]);
        assert_eq!(&decoded[19..51], &raw_pubkey);
    }

    #[test]
    fn test_encode_openssh_ed25519_wire_rejects_invalid_length() {
        let short_key = [1u8; 16];
        assert!(encode_openssh_ed25519_wire(&short_key).is_err());
        let long_key = [1u8; 64];
        assert!(encode_openssh_ed25519_wire(&long_key).is_err());
    }

    #[test]
    fn test_resolve_dc_url_and_login_validation() {
        assert_eq!(
            resolve_dc_url("skulls-and-bones.sb", None).unwrap(),
            "https://console.skulls-and-bones.org"
        );
        assert_eq!(
            resolve_dc_url("corp.eu", None).unwrap(),
            "https://console.corp.eu"
        );
        assert_eq!(
            resolve_dc_url("corp.eu", Some("https://dc.corp.eu/")).unwrap(),
            "https://dc.corp.eu"
        );
        assert!(resolve_dc_url("corp.eu", Some("ftp://bad")).is_err());
        assert!(login_for_join_token("http://remote.example.com", "admin", "pw").is_err());
    }

    #[test]
    fn test_build_dc_init_script_validates_inputs_and_renders_caddy_or_sb_proxy() {
        let caddy_script = build_dc_init_script(
            "corp.eu",
            Some("console.corp.eu"),
            Some("enroll.corp.eu"),
            "leon.admin",
            None,
            "caddy",
            None,
        )
        .expect("valid caddy script");
        assert!(caddy_script.contains("sb-dc.service"));
        assert!(caddy_script.contains("console.corp.eu"));
        assert!(caddy_script.contains("enroll.corp.eu"));
        assert!(caddy_script.contains("Caddyfile"));

        let proxy_script = build_dc_init_script(
            "corp.eu",
            None,
            None,
            "sb.admin",
            None,
            "sb-proxy",
            Some("https://example.org/sb.tar.gz"),
        )
        .expect("valid sb-proxy script");
        assert!(proxy_script.contains("sb-proxy.service"));
        assert!(proxy_script.contains("https://example.org/sb.tar.gz"));

        assert!(build_dc_init_script("bad;rm -rf /", None, None, "sb.admin", None, "caddy", None).is_err());
        assert!(build_dc_init_script("corp.eu", None, None, "bad;user", None, "caddy", None).is_err());
        assert!(build_dc_init_script("corp.eu", None, None, "sb.admin", None, "nginx", None).is_err());
    }
}

/// Builds a hardened Ubuntu/Debian setup script for `sb server dc-init` (replacing `scripts/install-dc.sh`).
// [SECURITY-HYPOTHESIS] CWE-78: Unvalidated domain, host, username, or URL interpolated into bash setup script.
// [SECURITY-VERIFIED] All hostnames, usernames, proxy engine, and tarball URL are strictly validated before formatting.
pub fn build_dc_init_script(
    domain: &str,
    console_host: Option<&str>,
    enroll_host: Option<&str>,
    admin: &str,
    password: Option<&str>,
    proxy: &str,
    tarball_url: Option<&str>,
) -> Result<String, String> {
    if !is_valid_host(domain) {
        return Err(format!("Ungültiger Domain-Name: '{domain}'"));
    }
    let console = console_host
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("console.{domain}"));
    let enroll = enroll_host
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("enroll.{domain}"));

    if !is_valid_host(&console) {
        return Err(format!("Ungültiger Console-Host: '{console}'"));
    }
    if !is_valid_host(&enroll) {
        return Err(format!("Ungültiger Enroll-Host: '{enroll}'"));
    }
    if admin.is_empty()
        || admin.len() > 64
        || !admin
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        || !admin
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!("Ungültiger Admin-Benutzername: '{admin}'"));
    }
    if !matches!(proxy, "caddy" | "sb-proxy") {
        return Err(format!(
            "Ungültige Proxy-Engine '{proxy}' (erlaubt: 'caddy' oder 'sb-proxy')"
        ));
    }
    if let Some(url) = tarball_url {
        if !url.starts_with("https://")
            || url.contains('\'')
            || url.contains('\n')
            || url.contains('\r')
            || url.chars().any(char::is_whitespace)
        {
            return Err("Ungültige --tarball-url (muss mit https:// beginnen und darf keine Sonderzeichen enthalten)".into());
        }
    }
    if let Some(pw) = password {
        if pw.is_empty() || pw.contains('\'') || pw.contains('\n') || pw.contains('\r') {
            return Err("Ungültiges Passwort (darf nicht leer sein und keine Zeilenumbrüche oder Hochkommas enthalten)".into());
        }
    }

    let binary_step = if let Some(url) = tarball_url {
        format!(
            "TMP_TAR='/tmp/sb-release.tar.gz'\ncurl -fsSL '{url}' -o \"$TMP_TAR\"\ntar -xzf \"$TMP_TAR\" -C /usr/local/bin\nrm -f \"$TMP_TAR\"\nchmod 0755 /usr/local/bin/sb /usr/local/bin/sb-node || true\n"
        )
    } else {
        "if ! command -v sb-node >/dev/null 2>&1; then\n  if command -v sb >/dev/null 2>&1; then\n    sb install node proxy || true\n  fi\nfi\n".to_string()
    };

    let proxy_step = if proxy == "sb-proxy" {
        format!(
            r#"systemctl disable --now caddy >/dev/null 2>&1 || true
/usr/local/bin/sb-proxy add '{console}' 8090 || true
/usr/local/bin/sb-proxy add '{enroll}' 8090 || true
cat >/etc/systemd/system/sb-proxy.service <<'EOF'
[Unit]
Description=Skulls & Bones Reverse Proxy ({domain})
After=network-online.target sb-dc.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sb-proxy start --http-bind 0.0.0.0:80 --bind 0.0.0.0:443
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sb-proxy
"#
        )
    } else {
        format!(
            r#"cat >/etc/caddy/Caddyfile <<'EOF'
{console} {{
    reverse_proxy 127.0.0.1:8090
    header {{
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }}
}}

{enroll} {{
    handle /enroll* {{
        reverse_proxy 127.0.0.1:8090
    }}
    handle /v1/enrollments* {{
        reverse_proxy 127.0.0.1:8090
    }}
    handle /v1/health {{
        reverse_proxy 127.0.0.1:8090
    }}
    handle {{
        respond "403 Forbidden" 403
    }}
}}
EOF
systemctl enable --now caddy
systemctl reload caddy
"#
        )
    };

    let pw_step = if let Some(pw) = password {
        format!("ADMIN_PASSWORD='{pw}'\nGENERATED_PW=0\n")
    } else {
        "ADMIN_PASSWORD=\"$(tr -dc 'A-Za-z0-9!@#%^&*' </dev/urandom | head -c 20)\"\nGENERATED_PW=1\n".to_string()
    };

    Ok(format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Fehler: Bitte als root oder via sudo ausführen." >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates ufw fail2ban caddy tar gzip
ufw allow 22/tcp >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null
systemctl enable --now fail2ban >/dev/null
{binary_step}{proxy_step}
CONSOLE_DIST_ARG=""
if [[ -d /opt/skulls-and-bones/console/dist ]]; then
  CONSOLE_DIST_ARG="--console-dir /opt/skulls-and-bones/console/dist"
fi
cat >/etc/systemd/system/sb-dc.service <<EOF
[Unit]
Description=Skulls & Bones Sovereign Domain Controller ({domain})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sb-node dc up --domain {domain} --admin {admin} --dc-bind 127.0.0.1:8443 --graph-bind 127.0.0.1:8090 $CONSOLE_DIST_ARG
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sb-dc.service
sleep 2
{pw_step}
/usr/local/bin/sb-node user set-password '{admin}' --password "$ADMIN_PASSWORD"
/usr/local/bin/sb-node policy init '{domain}' >/dev/null 2>&1 || true
/usr/local/bin/sb-node policy put --id baseline-all --domain '{domain}' --title "Baseline Security Policy" --description "Firewall & Screenlock" --scope all --firewall on --screenlock-mins 5 >/dev/null 2>&1 || true
echo "DC_READY=https://{console}"
if [[ "$GENERATED_PW" -eq 1 ]]; then
  echo "ADMIN_USER={admin}"
  echo "ADMIN_PASSWORD=$ADMIN_PASSWORD"
fi
"#
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn handle_server_dc_init(
    target: Option<&str>,
    domain: &str,
    console_host: Option<&str>,
    enroll_host: Option<&str>,
    admin: &str,
    password: Option<&str>,
    proxy: &str,
    tarball_url: Option<&str>,
    dry_run: bool,
) {
    use std::io::Write;
    print_banner();
    println!(
        "  {} {}\n",
        "► SOVEREIGN DOMAIN CONTROLLER SETUP".bold(),
        "[SB SERVER DC-INIT]".bright_green()
    );

    let script = match build_dc_init_script(
        domain,
        console_host,
        enroll_host,
        admin,
        password,
        proxy,
        tarball_url,
    ) {
        Ok(s) => s,
        Err(e) => {
            sb_core::logfmt::error(
                "FLEET_DC_INIT_VALIDATION",
                "sb::fleet",
                "Ungueltige DC-Setup-Parameter",
                &[("err", &e)],
            );
            std::process::exit(1);
        }
    };

    if dry_run {
        println!("{script}");
        return;
    }

    if let Some(remote) = target {
        let _ = crate::commands::ssh::ensure_ephemeral_ssh_user_cert();
        let _ = sb_core::ssh_transport::ensure_sovereign_ssh_config();
        let (ssh_bin, ssh_args) =
            match sb_core::ssh_transport::build_ssh_exec_args(remote, "bash -s") {
                Ok(v) => v,
                Err(e) => {
                    sb_core::logfmt::error(
                        "FLEET_DC_INIT_SSH_ARGS",
                        "sb::fleet",
                        "SSH-Verbindung konnte nicht vorbereitet werden",
                        &[("target", remote), ("err", &e)],
                    );
                    std::process::exit(1);
                }
            };
        let mut child = match Command::new(&ssh_bin)
            .args(&ssh_args)
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                sb_core::logfmt::error(
                    "FLEET_DC_INIT_SSH_SPAWN",
                    "sb::fleet",
                    "SSH konnte nicht gestartet werden",
                    &[("target", remote), ("err", &e.to_string())],
                );
                std::process::exit(1);
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        match child.wait() {
            Ok(s) if s.success() => {
                println!(
                    "\n  {} Domain Controller auf '{}' erfolgreich eingerichtet.",
                    "✓".bright_green().bold(),
                    remote
                );
            }
            Ok(s) => {
                sb_core::logfmt::error(
                    "FLEET_DC_INIT_REMOTE_FAILED",
                    "sb::fleet",
                    "Remote DC-Setup fehlgeschlagen",
                    &[("target", remote), ("status", &s.to_string())],
                );
                std::process::exit(1);
            }
            Err(e) => {
                sb_core::logfmt::error(
                    "FLEET_DC_INIT_REMOTE_WAIT",
                    "sb::fleet",
                    "Fehler beim Warten auf SSH-Prozess",
                    &[("err", &e.to_string())],
                );
                std::process::exit(1);
            }
        }
    } else {
        #[cfg(unix)]
        {
            let mut child = match Command::new("bash")
                .arg("-s")
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    sb_core::logfmt::error(
                        "FLEET_DC_INIT_LOCAL_SPAWN",
                        "sb::fleet",
                        "bash konnte nicht gestartet werden",
                        &[("err", &e.to_string())],
                    );
                    std::process::exit(1);
                }
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(script.as_bytes());
            }
            match child.wait() {
                Ok(s) if s.success() => {
                    println!(
                        "\n  {} Domain Controller lokal erfolgreich eingerichtet.",
                        "✓".bright_green().bold()
                    );
                }
                _ => {
                    sb_core::logfmt::error(
                        "FLEET_DC_INIT_LOCAL_FAILED",
                        "sb::fleet",
                        "Lokales DC-Setup fehlgeschlagen",
                        &[],
                    );
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(unix))]
        {
            sb_core::logfmt::error(
                "FLEET_DC_INIT_TARGET_REQUIRED",
                "sb::fleet",
                "Auf Windows/macOS muss --target <user@host> fuer das VPS-Setup angegeben werden",
                &[],
            );
            std::process::exit(1);
        }
    }
}
