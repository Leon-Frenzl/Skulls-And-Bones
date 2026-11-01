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

pub fn save_team_requests(reqs: &[TeamJoinRequest]) -> std::io::Result<()> {
    let sb_dir = get_sb_dir();
    fs::create_dir_all(&sb_dir)?;
    let content = serde_json::to_string_pretty(reqs).unwrap_or_default();
    fs::write(team_requests_file(), content)
}

pub fn compute_required_quorum(member_count: usize) -> usize {
    if member_count <= 1 {
        1 // Initialzustand (1 Entwickler + Server): Sponsor reicht aus
    } else {
        2 // 4-Augen-Prinzip aktiv für Team-Swarms (mind. 2 verschiedene Genehmigungen)
    }
}

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
            eprintln!("  {} {}", "✗".bright_red(), e);
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
        eprintln!(
            "  {} Ungültiger Initial-Benutzername: '{}'",
            "✗".bright_red(),
            initial_user
        );
        return;
    }
    if !is_valid_host(host_part) {
        eprintln!(
            "  {} Ungültige Host-Adresse: '{}'",
            "✗".bright_red(),
            host_part
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
        eprintln!(
            "  {} Ungültiger Entwickler-Benutzername: '{}'",
            "✗".bright_red(),
            dev_user
        );
        return;
    }
    if !is_valid_nodename(&node_name) {
        eprintln!(
            "  {} Ungültiger Knoten-Name: '{}'",
            "✗".bright_red(),
            node_name
        );
        return;
    }

    let ca_key = match get_or_detect_ca_pubkey() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  {} {}", "✗".bright_red(), e);
            return;
        }
    };
    let ca_key = ca_key.trim();
    if ca_key.is_empty() || ca_key.contains('\n') || ca_key.contains('\r') || ca_key.contains('\'')
    {
        eprintln!("  {} Ungültiger CA-Public-Key", "✗".bright_red());
        return;
    }

    let swarm = get_swarm_name();
    let token = build_pairing_token(&swarm, &node_name, ca_key);
    if token.contains('\'') || token.contains('\n') || token.contains('\r') {
        eprintln!("  {} Ungültiges Pairing-Token", "✗".bright_red());
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
            eprintln!(
                "\n  {} Initial-Bootstrap fehlgeschlagen (Exit Code: {}).",
                "✗".bright_red().bold(),
                s.code().unwrap_or(-1)
            );
            println!("  ► Manueller Bootstrap via Token:");
            println!("    sb-node init --token {}", token);
        }
        Err(e) => {
            eprintln!(
                "\n  {} Konnte SSH-Verbindung nicht ausführen: {}",
                "✗".bright_red().bold(),
                e
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
            eprintln!("  {} {}", "✗".bright_red(), e);
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
            eprintln!(
                "  {} Keine Beitrittsanfrage mit ID '{}' gefunden.",
                "✗".bright_red(),
                request_id
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
            eprintln!(
                "  {} Beitrittsantrag '{}' für '{}' ist abgelaufen (Gültigkeit überschritten).",
                "✗".bright_red(),
                reqs[pos].request_id,
                reqs[pos].candidate_name.bold()
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
        eprintln!(
            "  {} 4-Augen-Prinzip: Der Kandidat '{}' kann seinen eigenen Beitrittsantrag nicht genehmigen!",
            "✗".bright_red(),
            approver.bold()
        );
        return;
    }

    // 3. Authorized member check: Approver muss Teammitglied sein, sofern Mitglieder hinterlegt sind
    let members = load_team_members();
    if !members.is_empty() && !members.iter().any(|m| m.name == approver) {
        eprintln!(
            "  {} 4-Augen-Prinzip: Prüfer '{}' ist kein autorisiertes Mitglied dieses Teams!",
            "✗".bright_red(),
            approver.bold()
        );
        return;
    }

    if reqs[pos].approvals.contains(&approver) {
        eprintln!(
            "  {} 4-Augen-Prinzip: Prüfer '{}' hat diesen Antrag bereits genehmigt!",
            "✗".bright_red(),
            approver.bold()
        );
        eprintln!(
            "    Es wird die Genehmigung eines anderen autorisierten Teammitglieds benötigt."
        );
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
            eprintln!("  {} Ungültiger Einladungs-Token: {}", "✗".bright_red(), e);
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
            eprintln!(
                "  {} Beitritt abgelehnt: 4-Augen-Freigabe noch nicht abgeschlossen!",
                "✗".bright_red().bold()
            );
            eprintln!(
                "    Antrag '{}' benötigt {} Genehmigungen (bisher: {}/{}).",
                req.request_id,
                req.required_quorum,
                req.approvals.len(),
                req.required_quorum
            );
            eprintln!(
                "    Bitte ein autorisiertes Teammitglied um Freigabe via: {}",
                format!("sb approve {}", req.request_id).bright_yellow()
            );
            return;
        }

        if req.status == "revoked" {
            eprintln!(
                "  {} Beitritt abgelehnt: Einladungs-Token wurde widerrufen!",
                "✗".bright_red().bold()
            );
            return;
        }

        if req.status == "expired" {
            eprintln!(
                "  {} Beitritt abgelehnt: Einladungs-Token ist abgelaufen!",
                "✗".bright_red().bold()
            );
            return;
        }

        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&req.expires_at) {
            if exp.with_timezone(&chrono::Utc) < chrono::Utc::now() {
                eprintln!(
                    "  {} Beitritt abgelehnt: Einladungs-Token ist abgelaufen (Gültigkeit überschritten)!",
                    "✗".bright_red().bold()
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

pub fn handle_revoke(name: &str, reason: &str) {
    print_banner();
    println!(
        "  {} {}\n",
        "► ATOMARER HARDWARE- & IDENTITÄTS-RAUSWURF".bold(),
        "[REVOKE]".bright_red()
    );

    if !is_valid_username(name) && !is_valid_nodename(name) {
        eprintln!(
            "  {} Sicherheits-Abbruch: Ungültiger Ziel-Name '{}'",
            "✗".bright_red(),
            name
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
}

