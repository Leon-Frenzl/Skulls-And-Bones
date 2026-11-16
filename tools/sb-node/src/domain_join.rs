use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sb_auth::crypto::parse_public_key;
use sb_auth::AuthVerifier;
use sb_ca::{SshCa, X509Ca};
use sb_core::domain::{
    local_domain_dir, validate_domain_name, validate_hostname, DomainJoinRequest,
    DomainJoinResponse, JoinedMachineState, MachineRecord, OsKind,
};
use sb_dns::config::ConfigManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const MAX_JOIN_REQUEST_BYTES: usize = 64 * 1024;

/// Persistent registry of domain-joined machines for a single domain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainRegistry {
    pub domain: String,
    pub machines: Vec<MachineRecord>,
}

impl DomainRegistry {
    /// Returns the registry path under `~/.sb-node/domain/<domain>/machines.json`.
    pub fn path_for(domain: &str) -> Result<PathBuf, String> {
        let clean = validate_domain_name(domain)?;
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Ok(home
            .join(".sb-node")
            .join("domain")
            .join(clean)
            .join("machines.json"))
    }

    /// Loads an existing registry or creates an empty one for `domain`.
    pub fn load_or_create(domain: &str) -> Result<Self, String> {
        let clean = validate_domain_name(domain)?;
        let path = Self::path_for(&clean)?;
        Self::load_from_path(&path, &clean)
    }

    pub fn load_from_path(path: &Path, domain: &str) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self {
                domain: domain.to_string(),
                machines: Vec::new(),
            });
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read domain registry {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Failed to parse domain registry {}: {e}", path.display()))
    }

    /// Saves the registry atomically to disk.
    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize domain registry: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)
            .map_err(|e| format!("Failed to write temp registry {}: {e}", tmp.display()))?;
        fs::rename(&tmp, path)
            .map_err(|e| format!("Failed to replace registry {}: {e}", path.display()))
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::path_for(&self.domain)?;
        self.save_to_path(&path)
    }

    /// Allocates the next available `10.42.0.10..=10.42.254.254` IPv4 address.
    pub fn allocate_next_ip(&self) -> Result<Ipv4Addr, String> {
        let mut used: std::collections::HashSet<Ipv4Addr> = self
            .machines
            .iter()
            .filter(|m| !m.revoked)
            .filter_map(|m| m.mesh_ip.parse::<Ipv4Addr>().ok())
            .collect();
        // Reserve 10.42.0.1 for the primary Domain Controller / gateway
        used.insert(Ipv4Addr::new(10, 42, 0, 1));

        for third in 0u8..=254 {
            let start_fourth = if third == 0 { 10 } else { 1 };
            for fourth in start_fourth..=254 {
                let candidate = Ipv4Addr::new(10, 42, third, fourth);
                if !used.contains(&candidate) {
                    return Ok(candidate);
                }
            }
        }
        Err("Domain IPv4 pool (10.42.0.0/16) is exhausted".to_string())
    }
}

/// Derives a deterministic `mach_<16-hex>` identifier from an Ed25519 machine public key.
pub fn derive_machine_id(pubkey_bytes: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sb-machine-id-v1:");
    hasher.update(pubkey_bytes);
    let digest = hasher.finalize();
    format!("mach_{}", hex::encode(&digest[..8]))
}

/// Processes a `DomainJoinRequest` on the Domain Controller.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unauthorized machine enrollment, hostname hijacking, or rogue CA
///   certificate issuance by an unauthenticated or low-privilege caller.
/// - **CVE / CWE Mapping:** CWE-287 (Improper Authentication) / CWE-863 (Incorrect Authorization).
/// - **Likelihood & Exploitability:** High (9/10) on Domain Controller join endpoints.
/// - **Applied Mitigation:** Verifies `join_token` via `AuthVerifier` (Ed25519 signature, time
///   bounds, multi-tier revocation), enforces `domain:join` capability or `admin` role fail-closed,
///   validates RFC 1123 hostname/domain, and rejects conflicting active hostnames.
// Conforms to RFC 1123 §2.1 (hostnames), RFC 5280 (X.509), and OpenSSH PROTOCOL.certkeys.
pub fn process_join_request(
    req: &DomainJoinRequest,
    verifier: &AuthVerifier,
    registry_path: Option<&Path>,
    register_dns: bool,
) -> Result<DomainJoinResponse, String> {
    let hostname = validate_hostname(&req.hostname)?;
    let domain = validate_domain_name(&req.domain)?;
    let fqdn = format!("{hostname}.{domain}");

    // 1. Verify user token and authorization (fail-closed)
    let claims = verifier
        .verify_token(&req.join_token)
        .map_err(|e| format!("Domain join authentication failed: {e}"))?;
    if !claims.has_capability("domain:join") && !claims.has_role("admin") {
        return Err(format!(
            "User '{}' lacks 'domain:join' capability or 'admin' role",
            claims.subject
        ));
    }

    // 2. Validate machine Ed25519 public key (private key never leaves joining machine)
    let machine_vk = parse_public_key(&req.machine_public_key_b64)
        .map_err(|e| format!("Invalid machine Ed25519 public key: {e}"))?;
    let machine_id = derive_machine_id(&machine_vk.to_bytes());

    // 3. Load domain registry and prevent hostname hijacking
    let default_path = DomainRegistry::path_for(&domain)?;
    let reg_path = registry_path.unwrap_or(&default_path);
    let mut registry = DomainRegistry::load_from_path(reg_path, &domain)?;

    if let Some(existing) = registry
        .machines
        .iter()
        .find(|m| !m.revoked && m.fqdn == fqdn && m.machine_id != machine_id)
    {
        return Err(format!(
            "Hostname '{}' is already joined by active machine '{}' (joined by '{}')",
            fqdn, existing.machine_id, existing.joined_by
        ));
    }

    // 4. Assign or validate Mesh IPv4 address
    let assigned_ip: Ipv4Addr = match &req.mesh_ip {
        Some(raw) => raw
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("Invalid requested mesh IP '{}': {e}", raw))?,
        None => {
            if let Some(existing) = registry
                .machines
                .iter()
                .find(|m| !m.revoked && m.machine_id == machine_id)
            {
                existing
                    .mesh_ip
                    .parse::<Ipv4Addr>()
                    .unwrap_or(registry.allocate_next_ip()?)
            } else {
                registry.allocate_next_ip()?
            }
        }
    };

    // 5. Issue X.509 device certificate + read Root CA from sb-ca
    let leaf = X509Ca::issue_leaf_certificate(&[fqdn.clone(), hostname.clone()], 365)
        .map_err(|e| format!("X.509 device certificate issuance failed: {e}"))?;
    let root_ca_pem = fs::read_to_string(sb_ca::paths::x509_root_crt_path())
        .map_err(|e| format!("Failed to read X.509 Root CA certificate: {e}"))?;

    // 6. Optionally issue OpenSSH Host Certificate + read OpenSSH User CA public key
    let ssh_host_cert = match &req.ssh_host_public_key {
        Some(host_pub) if !host_pub.trim().is_empty() => {
            let cert = SshCa::issue_host_certificate(host_pub.trim(), &fqdn, 365 * 24 * 3600, None)
                .map_err(|e| format!("OpenSSH host certificate issuance failed: {e}"))?;
            Some(cert)
        }
        _ => None,
    };
    let ssh_user_ca_pubkey = SshCa::ca_public_key_openssh()
        .map_err(|e| format!("Failed to read OpenSSH CA public key: {e}"))?;

    let joined_at = Utc::now().to_rfc3339();
    let record = MachineRecord {
        machine_id: machine_id.clone(),
        hostname,
        domain: domain.clone(),
        fqdn: fqdn.clone(),
        os: req.os,
        machine_public_key_b64: req.machine_public_key_b64.clone(),
        mesh_ip: assigned_ip.to_string(),
        joined_by: claims.subject.clone(),
        joined_at: joined_at.clone(),
        revoked: false,
        revoked_reason: None,
    };

    registry
        .machines
        .retain(|m| m.machine_id != machine_id || m.revoked);
    registry.machines.push(record);
    registry.save_to_path(reg_path)?;

    // 7. Register FQDN in sb-dns if enabled
    if register_dns {
        ConfigManager::add_a_record(&fqdn, assigned_ip)?;
    }

    Ok(DomainJoinResponse {
        machine_id,
        fqdn,
        domain,
        joined_by: claims.subject,
        mesh_ip: assigned_ip.to_string(),
        dns_server: "10.42.0.1".to_string(),
        device_cert_pem: leaf.cert_pem.clone(),
        root_ca_pem,
        ssh_host_cert,
        ssh_user_ca_pubkey,
        joined_at,
    })
}

/// Generates a fresh local Ed25519 machine keypair (`machine.key`), executes join, and persists
/// `machine.json` locally under `~/.sb/domain/`.
pub fn generate_local_machine_keypair() -> (SigningKey, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let pub_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    (signing_key, pub_b64)
}

/// Persists the joined machine's private key (`0o600` on Unix) and state under `base_dir`
/// (defaults to `~/.sb/domain`).
pub fn persist_local_machine_state(
    response: &DomainJoinResponse,
    signing_key: &SigningKey,
    os: sb_core::domain::OsKind,
    base_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let dir = base_dir.map(PathBuf::from).unwrap_or_else(local_domain_dir);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create domain state dir {}: {e}", dir.display()))?;

    let key_path = dir.join("machine.key");
    let key_b64 = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    fs::write(&key_path, key_b64)
        .map_err(|e| format!("Failed to write machine key {}: {e}", key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }

    let state = JoinedMachineState {
        machine_id: response.machine_id.clone(),
        fqdn: response.fqdn.clone(),
        domain: response.domain.clone(),
        os,
        joined_by: response.joined_by.clone(),
        mesh_ip: response.mesh_ip.clone(),
        dns_server: response.dns_server.clone(),
        device_cert_pem: response.device_cert_pem.clone(),
        root_ca_pem: response.root_ca_pem.clone(),
        ssh_user_ca_pubkey: response.ssh_user_ca_pubkey.clone(),
        joined_at: response.joined_at.clone(),
    };
    let state_path = dir.join("machine.json");
    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("Failed to serialize machine state: {e}"))?;
    fs::write(&state_path, json).map_err(|e| {
        format!(
            "Failed to write machine state {}: {e}",
            state_path.display()
        )
    })?;

    Ok(state_path)
}

/// Revokes a joined machine by `machine_id` or `fqdn` and removes its DNS A-record.
pub fn revoke_machine(
    domain: &str,
    target: &str,
    reason: &str,
    registry_path: Option<&Path>,
    remove_dns: bool,
) -> Result<MachineRecord, String> {
    let domain = validate_domain_name(domain)?;
    let default_path = DomainRegistry::path_for(&domain)?;
    let reg_path = registry_path.unwrap_or(&default_path);
    let mut registry = DomainRegistry::load_from_path(reg_path, &domain)?;

    let q = target.trim().to_ascii_lowercase();
    let Some(machine) = registry
        .machines
        .iter_mut()
        .find(|m| !m.revoked && (m.machine_id == q || m.fqdn == q || m.hostname == q))
    else {
        return Err(format!(
            "Active machine '{}' not found in domain '{}'",
            target, domain
        ));
    };

    machine.revoked = true;
    machine.revoked_reason = Some(reason.to_string());
    let updated = machine.clone();
    registry.save_to_path(reg_path)?;

    if remove_dns {
        let _ = ConfigManager::remove_record(&updated.fqdn);
    }
    Ok(updated)
}

/// Runs the Domain Controller HTTP/1.1 JSON join server (`POST /v1/domain/join`, `GET /v1/domain/health`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unbounded HTTP body allocation (OOM DoS) or unauthenticated
///   machine enrollment over the network.
/// - **CVE / CWE Mapping:** CWE-770 (Allocation of Resources Without Limits) / CWE-306.
/// - **Likelihood & Exploitability:** High (8/10) on network-exposed DC join port.
/// - **Applied Mitigation:** Bounds total HTTP request read to `MAX_JOIN_REQUEST_BYTES` (64 KiB)
///   with a 10s read timeout, requires `POST /v1/domain/join`, and delegates all authorization to
///   `process_join_request` (fail-closed `AuthVerifier`).
// Conforms to RFC 9110 / RFC 9112 (HTTP/1.1 framing and status codes).
pub async fn serve_domain_join(
    bind: SocketAddr,
    verifier: Arc<AuthVerifier>,
    registry_path: Option<PathBuf>,
    register_dns: bool,
) -> Result<(), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("Failed to bind Domain Join server on {bind}: {e}"))?;
    serve_domain_join_on_listener(listener, verifier, registry_path, register_dns).await
}

pub async fn serve_domain_join_on_listener(
    listener: TcpListener,
    verifier: Arc<AuthVerifier>,
    registry_path: Option<PathBuf>,
    register_dns: bool,
) -> Result<(), String> {
    loop {
        let (mut stream, _peer) = listener
            .accept()
            .await
            .map_err(|e| format!("Domain Join accept failed: {e}"))?;
        let verifier = verifier.clone();
        let reg_path = registry_path.clone();
        tokio::spawn(async move {
            let _ = handle_join_http_connection(
                &mut stream,
                &verifier,
                reg_path.as_deref(),
                register_dns,
            )
            .await;
        });
    }
}

async fn handle_join_http_connection(
    stream: &mut TcpStream,
    verifier: &AuthVerifier,
    registry_path: Option<&Path>,
    register_dns: bool,
) -> Result<(), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if buf.len() > MAX_JOIN_REQUEST_BYTES {
            write_http_json(
                stream,
                413,
                "Payload Too Large",
                r#"{"error":"request too large"}"#,
            )
            .await?;
            return Ok(());
        }
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .map_err(|_| "Read timeout".to_string())?
            .map_err(|e| format!("Read error: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let head =
        String::from_utf8(buf[..header_end].to_vec()).map_err(|_| "Invalid UTF-8".to_string())?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let header_lines: Vec<&str> = lines.collect();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("");
    let (path, query) = raw_target.split_once('?').unwrap_or((raw_target, ""));

    if method == "GET" && (path == "/v1/health" || path == "/v1/domain/health") {
        return write_http_json(
            stream,
            200,
            "OK",
            r#"{"status":"ok","service":"sb-node-graph","api_version":"v1"}"#,
        )
        .await;
    }

    if method == "GET" && path == "/v1/machines" {
        let Some(token) = extract_bearer_token(&header_lines) else {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"missing bearer token"}"#,
            )
            .await;
        };
        let claims = match verifier.verify_token(token) {
            Ok(c) => c,
            Err(e) => {
                let msg = serde_json::json!({ "error": format!("authentication failed: {e}") })
                    .to_string();
                return write_http_json(stream, 401, "Unauthorized", &msg).await;
            }
        };
        if !claims
            .capabilities
            .iter()
            .any(|c| c == "domain:read" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks domain:read or domain:admin capability"}"#,
            )
            .await;
        }
        let reg_file = registry_path
            .map(PathBuf::from)
            .unwrap_or_else(|| local_domain_dir().join("machines.json"));
        let reg = fs::read_to_string(&reg_file)
            .ok()
            .and_then(|raw| serde_json::from_str::<DomainRegistry>(&raw).ok())
            .unwrap_or_default();
        let json =
            serde_json::json!({ "domain": reg.domain, "machines": reg.machines }).to_string();
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method == "GET" && path == "/v1/policies" {
        let store_path = registry_path
            .and_then(|p| p.parent())
            .map(|d| d.join("policies.json"))
            .unwrap_or_else(crate::policy_engine::default_policy_store_path);
        let os_filter = query_param(query, "os").and_then(parse_os_kind);
        let policies = match crate::policy_engine::PolicyStore::load(&store_path) {
            Ok(store) => store.list_policies(os_filter),
            Err(_) => Vec::new(),
        };
        let json = serde_json::json!({ "policies": policies }).to_string();
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method == "GET" && path == "/v1/policies/bundle" {
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let store_path = base_dir.join("policies.json");
        let key_path = base_dir.join("policy_authority.key");
        let pub_path = base_dir.join("policy_authority.pub");
        let store = match crate::policy_engine::PolicyStore::load(&store_path) {
            Ok(s) => s,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 404, "Not Found", &msg).await;
            }
        };
        let signing_key =
            match crate::policy_engine::ensure_policy_authority_keypair(&key_path, &pub_path) {
                Ok(k) => k,
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 500, "Internal Server Error", &msg).await;
                }
            };
        let ttl_hours = query_param(query, "ttl_hours")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(24);
        match store.sign_bundle(ttl_hours, &signing_key) {
            Ok(bundle) => {
                let json = serde_json::to_string(&bundle).map_err(|e| e.to_string())?;
                return write_http_json(stream, 200, "OK", &json).await;
            }
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        }
    }

    if method == "GET" && path.starts_with("/v1/policies/") {
        let policy_id = path.trim_start_matches("/v1/policies/");
        let store_path = registry_path
            .and_then(|p| p.parent())
            .map(|d| d.join("policies.json"))
            .unwrap_or_else(crate::policy_engine::default_policy_store_path);
        return match crate::policy_engine::PolicyStore::load(&store_path) {
            Ok(store) => match store.policies.get(policy_id) {
                Some(doc) => {
                    let json = serde_json::to_string(doc).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                None => {
                    write_http_json(stream, 404, "Not Found", r#"{"error":"policy not found"}"#)
                        .await
                }
            },
            Err(_) => {
                write_http_json(
                    stream,
                    404,
                    "Not Found",
                    r#"{"error":"policy store not found"}"#,
                )
                .await
            }
        };
    }

    if method == "DELETE" && path.starts_with("/v1/policies/") {
        let policy_id = path.trim_start_matches("/v1/policies/");
        let Some(token) = extract_bearer_token(&header_lines) else {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"missing bearer token"}"#,
            )
            .await;
        };
        let claims = match verifier.verify_token(token) {
            Ok(c) => c,
            Err(e) => {
                let msg = serde_json::json!({ "error": format!("authentication failed: {e}") })
                    .to_string();
                return write_http_json(stream, 401, "Unauthorized", &msg).await;
            }
        };
        if !claims
            .capabilities
            .iter()
            .any(|c| c == "policy:write" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks policy:write or domain:admin capability"}"#,
            )
            .await;
        }
        let store_path = registry_path
            .and_then(|p| p.parent())
            .map(|d| d.join("policies.json"))
            .unwrap_or_else(crate::policy_engine::default_policy_store_path);
        let mut store = match crate::policy_engine::PolicyStore::load(&store_path) {
            Ok(s) => s,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 404, "Not Found", &msg).await;
            }
        };
        let dry_run = query_param(query, "dry_run") == Some("true");
        let deleted = match store.delete_policy(policy_id) {
            Ok(d) => d,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 400, "Bad Request", &msg).await;
            }
        };
        if !deleted {
            return write_http_json(stream, 404, "Not Found", r#"{"error":"policy not found"}"#)
                .await;
        }
        if !dry_run {
            if let Err(e) = store.save(&store_path) {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        }
        let json = serde_json::json!({
            "dry_run": dry_run,
            "deleted": policy_id,
            "revision": store.revision
        })
        .to_string();
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method == "PUT" && path.starts_with("/v1/policies/") {
        let policy_id = path.trim_start_matches("/v1/policies/");
        let Some(token) = extract_bearer_token(&header_lines) else {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"missing bearer token"}"#,
            )
            .await;
        };
        let claims = match verifier.verify_token(token) {
            Ok(c) => c,
            Err(e) => {
                let msg = serde_json::json!({ "error": format!("authentication failed: {e}") })
                    .to_string();
                return write_http_json(stream, 401, "Unauthorized", &msg).await;
            }
        };
        if !claims
            .capabilities
            .iter()
            .any(|c| c == "policy:write" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks policy:write or domain:admin capability"}"#,
            )
            .await;
        }
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let mut doc: sb_core::policy::PolicyDocument = match serde_json::from_slice(&body) {
            Ok(d) => d,
            Err(e) => {
                let msg =
                    serde_json::json!({ "error": format!("Invalid PolicyDocument JSON: {e}") })
                        .to_string();
                return write_http_json(stream, 400, "Bad Request", &msg).await;
            }
        };
        if doc.id != policy_id {
            return write_http_json(
                stream,
                400,
                "Bad Request",
                r#"{"error":"body id does not match URL path id"}"#,
            )
            .await;
        }
        if let Err(e) = doc.validate() {
            let msg = serde_json::json!({ "error": e }).to_string();
            return write_http_json(stream, 400, "Bad Request", &msg).await;
        }
        let dry_run = query_param(query, "dry_run") == Some("true");
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let reg_file = registry_path
            .map(PathBuf::from)
            .unwrap_or_else(|| local_domain_dir().join("machines.json"));
        let domain = fs::read_to_string(&reg_file)
            .ok()
            .and_then(|raw| serde_json::from_str::<DomainRegistry>(&raw).ok())
            .map(|r| r.domain)
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "corp.eu".to_string());
        let store_path = base_dir.join("policies.json");
        let mut store =
            match crate::policy_engine::PolicyStore::load_or_create(&store_path, &domain) {
                Ok(s) => s,
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
        doc.updated_by = claims.subject;
        let saved = match store.upsert_policy(doc) {
            Ok(d) => d,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 400, "Bad Request", &msg).await;
            }
        };
        if !dry_run {
            if let Err(e) = store.save(&store_path) {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        }
        let json = serde_json::json!({
            "dry_run": dry_run,
            "revision": store.revision,
            "policy": saved
        })
        .to_string();
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method != "POST" || (path != "/v1/machines/join" && path != "/v1/domain/join") {
        return write_http_json(stream, 404, "Not Found", r#"{"error":"not found"}"#).await;
    }

    let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await?
    {
        Some(b) => b,
        None => return Ok(()),
    };
    let req: DomainJoinRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let msg = serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
            return write_http_json(stream, 400, "Bad Request", &msg).await;
        }
    };

    match process_join_request(&req, verifier, registry_path, register_dns) {
        Ok(resp) => {
            let json = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
            write_http_json(stream, 200, "OK", &json).await
        }
        Err(err) => {
            let status = if err.contains("authentication failed") {
                (401, "Unauthorized")
            } else if err.contains("lacks") {
                (403, "Forbidden")
            } else {
                (400, "Bad Request")
            };
            let msg = serde_json::json!({ "error": err }).to_string();
            write_http_json(stream, status.0, status.1, &msg).await
        }
    }
}

async fn write_http_json(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<(), String> {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("Write error: {e}"))
}

fn extract_bearer_token<'a>(headers: &[&'a str]) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (name, val) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("authorization") {
            let trimmed = val.trim();
            trimmed
                .strip_prefix("Bearer ")
                .or_else(|| trimmed.strip_prefix("bearer "))
                .map(str::trim)
                .filter(|t| !t.is_empty())
        } else {
            None
        }
    })
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(v)
        } else {
            None
        }
    })
}

fn parse_os_kind(raw: &str) -> Option<OsKind> {
    match raw.to_ascii_lowercase().as_str() {
        "linux" => Some(OsKind::Linux),
        "windows" => Some(OsKind::Windows),
        "macos" => Some(OsKind::MacOs),
        _ => None,
    }
}

async fn read_http_body(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    chunk: &mut [u8],
    header_end: usize,
    header_lines: &[&str],
) -> Result<Option<Vec<u8>>, String> {
    let content_length: usize = header_lines
        .iter()
        .find_map(|line| {
            let (name, val) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                val.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    if content_length == 0 || content_length > MAX_JOIN_REQUEST_BYTES {
        write_http_json(
            stream,
            400,
            "Bad Request",
            r#"{"error":"invalid or missing Content-Length"}"#,
        )
        .await?;
        return Ok(None);
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(chunk))
            .await
            .map_err(|_| "Body read timeout".to_string())?
            .map_err(|e| format!("Body read error: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > body_start + MAX_JOIN_REQUEST_BYTES {
            write_http_json(
                stream,
                413,
                "Payload Too Large",
                r#"{"error":"body too large"}"#,
            )
            .await?;
            return Ok(None);
        }
    }

    Ok(Some(
        buf[body_start..buf.len().min(body_start + content_length)].to_vec(),
    ))
}

async fn send_http_request(dc_addr: SocketAddr, http_req: &str) -> Result<Vec<u8>, String> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(dc_addr),
    )
    .await
    .map_err(|_| format!("Timed out connecting to Domain Controller {dc_addr}"))?
    .map_err(|e| format!("Failed to connect to Domain Controller {dc_addr}: {e}"))?;

    stream
        .write_all(http_req.as_bytes())
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("Failed reading DC response: {e}"))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > 512 * 1024 {
            return Err("DC response exceeded 512 KiB limit".to_string());
        }
    }

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response from DC".to_string())?;
    let head = std::str::from_utf8(&raw[..header_end]).unwrap_or("");
    let status_line = head.lines().next().unwrap_or("");
    let resp_body = &raw[header_end + 4..];

    if !status_line.contains(" 200 ") {
        let err_text = String::from_utf8_lossy(resp_body);
        return Err(format!("DC rejected request ({status_line}): {err_text}"));
    }

    Ok(resp_body.to_vec())
}

/// Sends a `DomainJoinRequest` to a remote Domain Controller (`host:port`) over HTTP/1.1.
pub async fn send_remote_join_request(
    dc_addr: SocketAddr,
    req: &DomainJoinRequest,
) -> Result<DomainJoinResponse, String> {
    let body = serde_json::to_string(req).map_err(|e| format!("Serialize error: {e}"))?;
    let http_req = format!(
        "POST /v1/machines/join HTTP/1.1\r\nHost: {dc_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let resp_body = send_http_request(dc_addr, &http_req).await?;
    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("Failed to parse DomainJoinResponse: {e}"))
}

/// Fetches the latest signed GPO bundle from a remote Domain Controller (`GET /v1/policies/bundle`).
pub async fn fetch_remote_policy_bundle(
    dc_addr: SocketAddr,
) -> Result<sb_core::policy::SignedPolicyBundle, String> {
    let http_req =
        format!("GET /v1/policies/bundle HTTP/1.1\r\nHost: {dc_addr}\r\nConnection: close\r\n\r\n");
    let resp_body = send_http_request(dc_addr, &http_req).await?;
    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("Failed to parse SignedPolicyBundle: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_auth::{AuthEngine, Keypair, MemoryRevocationStore};
    use sb_core::domain::OsKind;

    #[test]
    fn domain_join_enforces_user_capability_issues_certs_and_supports_revocation() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_domain_join_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&temp).unwrap();
        std::env::set_var("SB_HOME", &temp);
        // Ensure CA is initialized in isolated SB_HOME
        sb_ca::init_all(true).unwrap();

        let keypair = Keypair::generate();
        let store = std::sync::Arc::new(MemoryRevocationStore::new());
        let engine = AuthEngine::new(keypair, store.clone());
        let verifier =
            AuthVerifier::from_public_base64(&engine.public_key_base64(), store).unwrap();

        let (_sk1, pub1) = generate_local_machine_keypair();
        let (_sk2, pub2) = generate_local_machine_keypair();

        // 1. User without domain:join or admin role is rejected fail-closed
        let guest_tokens = engine
            .issue_session(
                "intern",
                vec!["guest".into()],
                vec!["mesh:read".into()],
                serde_json::json!({}),
            )
            .unwrap();
        let denied = process_join_request(
            &DomainJoinRequest {
                hostname: "app-01".into(),
                domain: "corp.eu".into(),
                os: OsKind::Linux,
                machine_public_key_b64: pub1.clone(),
                ssh_host_public_key: None,
                mesh_ip: None,
                join_token: guest_tokens.access_token,
            },
            &verifier,
            Some(&temp.join("machines.json")),
            false,
        );
        assert!(denied.is_err());

        // 2. Authorized user with domain:join succeeds and gets IP + X.509 cert + SSH User CA
        let admin_tokens = engine
            .issue_session(
                "anna.admin",
                vec!["operator".into()],
                vec!["domain:join".into()],
                serde_json::json!({}),
            )
            .unwrap();
        let joined = process_join_request(
            &DomainJoinRequest {
                hostname: "app-01".into(),
                domain: "corp.eu".into(),
                os: OsKind::Linux,
                machine_public_key_b64: pub1,
                ssh_host_public_key: None,
                mesh_ip: None,
                join_token: admin_tokens.access_token.clone(),
            },
            &verifier,
            Some(&temp.join("machines.json")),
            false,
        )
        .unwrap();

        assert_eq!(joined.fqdn, "app-01.corp.eu");
        assert_eq!(joined.joined_by, "anna.admin");
        assert_eq!(joined.mesh_ip, "10.42.0.10");
        assert!(joined.device_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(joined.root_ca_pem.contains("BEGIN CERTIFICATE"));
        assert!(joined.ssh_user_ca_pubkey.starts_with("ssh-ed25519 "));

        // 3. Different machine trying to hijack the same FQDN is rejected
        let hijack = process_join_request(
            &DomainJoinRequest {
                hostname: "app-01".into(),
                domain: "corp.eu".into(),
                os: OsKind::Linux,
                machine_public_key_b64: pub2,
                ssh_host_public_key: None,
                mesh_ip: None,
                join_token: admin_tokens.access_token,
            },
            &verifier,
            Some(&temp.join("machines.json")),
            false,
        );
        assert!(hijack.is_err());

        // 4. Revocation marks machine revoked
        let revoked = revoke_machine(
            "corp.eu",
            "app-01.corp.eu",
            "decommissioned",
            Some(&temp.join("machines.json")),
            false,
        )
        .unwrap();
        assert!(revoked.revoked);

        std::env::remove_var("SB_HOME");
        let _ = fs::remove_dir_all(&temp);
    }

    #[tokio::test]
    async fn remote_domain_join_over_tcp_succeeds_and_rejects_unauthorized() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_remote_join_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&temp).unwrap();
        std::env::set_var("SB_HOME", &temp);
        sb_ca::init_all(true).unwrap();

        let keypair = Keypair::generate();
        let store = Arc::new(MemoryRevocationStore::new());
        let engine = AuthEngine::new(keypair, store.clone());
        let verifier =
            Arc::new(AuthVerifier::from_public_base64(&engine.public_key_base64(), store).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dc_addr = listener.local_addr().unwrap();
        let reg_path = temp.join("machines.json");
        tokio::spawn(async move {
            let _ = serve_domain_join_on_listener(listener, verifier, Some(reg_path), false).await;
        });

        let (_sk, pub_b64) = generate_local_machine_keypair();
        let bad_req = DomainJoinRequest {
            hostname: "db-01".into(),
            domain: "corp.eu".into(),
            os: OsKind::Linux,
            machine_public_key_b64: pub_b64.clone(),
            ssh_host_public_key: None,
            mesh_ip: None,
            join_token: "sbt.invalid.token".into(),
        };
        assert!(send_remote_join_request(dc_addr, &bad_req).await.is_err());

        let admin_tokens = engine
            .issue_session("admin", vec!["admin".into()], vec![], serde_json::json!({}))
            .unwrap();
        let good_req = DomainJoinRequest {
            hostname: "db-01".into(),
            domain: "corp.eu".into(),
            os: OsKind::Linux,
            machine_public_key_b64: pub_b64,
            ssh_host_public_key: None,
            mesh_ip: None,
            join_token: admin_tokens.access_token,
        };
        let resp = send_remote_join_request(dc_addr, &good_req).await.unwrap();
        assert_eq!(resp.fqdn, "db-01.corp.eu");
        assert_eq!(resp.mesh_ip, "10.42.0.10");

        std::env::remove_var("SB_HOME");
        let _ = fs::remove_dir_all(&temp);
    }

    #[tokio::test]
    async fn remote_policy_graph_api_enforces_auth_dry_run_and_signed_bundle() {
        use sb_auth::crypto::Keypair;
        use sb_auth::{AuthEngine, MemoryRevocationStore};
        use sb_core::policy::{PolicyDocument, PolicyRule, PolicyScope};

        let temp = std::env::temp_dir().join(format!(
            "sb_node_policy_api_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let domain_dir = temp.join("domain");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&domain_dir).unwrap();

        let keypair = Keypair::generate();
        let store = Arc::new(MemoryRevocationStore::new());
        let engine = AuthEngine::new(keypair, store.clone());
        let verifier =
            Arc::new(AuthVerifier::from_public_base64(&engine.public_key_base64(), store).unwrap());

        let reg_path = domain_dir.join("machines.json");
        let reg = DomainRegistry {
            domain: "corp.eu".into(),
            machines: Vec::new(),
        };
        reg.save_to_path(&reg_path).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dc_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_domain_join_on_listener(listener, verifier, Some(reg_path), false).await;
        });

        let doc = PolicyDocument {
            id: "baseline-ssh".into(),
            name: "SSH Hardening".into(),
            description: "Cert-only SSH".into(),
            version: 1,
            scope: PolicyScope::Domain,
            target_os: vec![OsKind::Linux],
            rules: vec![PolicyRule::SshHardening {
                password_auth: false,
                permit_root_login: false,
                trusted_user_ca_keys: true,
            }],
            updated_at: String::new(),
            updated_by: String::new(),
        };
        let body = serde_json::to_string(&doc).unwrap();

        // 1. Unauthenticated PUT /v1/policies/baseline-ssh must fail with 401
        let unauth_req = format!(
            "PUT /v1/policies/baseline-ssh HTTP/1.1\r\nHost: {dc_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        assert!(send_http_request(dc_addr, &unauth_req).await.is_err());

        // 2. Authenticated dry-run does not persist policy
        let admin_tokens = engine
            .issue_session(
                "admin",
                vec!["admin".into()],
                vec!["policy:write".into()],
                serde_json::json!({}),
            )
            .unwrap();
        let dry_req = format!(
            "PUT /v1/policies/baseline-ssh?dry_run=true HTTP/1.1\r\nHost: {dc_addr}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            admin_tokens.access_token,
            body.len(),
            body
        );
        let dry_resp = send_http_request(dc_addr, &dry_req).await.unwrap();
        let dry_val: serde_json::Value = serde_json::from_slice(&dry_resp).unwrap();
        assert_eq!(dry_val["dry_run"], true);
        assert!(!domain_dir.join("policies.json").exists());

        // 3. Authenticated real PUT persists policy and GET /v1/policies/bundle returns valid signed bundle
        let real_req = format!(
            "PUT /v1/policies/baseline-ssh HTTP/1.1\r\nHost: {dc_addr}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            admin_tokens.access_token,
            body.len(),
            body
        );
        send_http_request(dc_addr, &real_req).await.unwrap();

        let bundle = fetch_remote_policy_bundle(dc_addr).await.unwrap();
        assert_eq!(bundle.domain, "corp.eu");
        assert_eq!(bundle.policies.len(), 1);
        let pub_b64 = fs::read_to_string(domain_dir.join("policy_authority.pub")).unwrap();
        crate::policy_engine::verify_policy_bundle(&bundle, "corp.eu", &pub_b64, 1).unwrap();

        // 4. GET /v1/policies/baseline-ssh returns the policy and DELETE removes it
        let get_req = format!(
            "GET /v1/policies/baseline-ssh HTTP/1.1\r\nHost: {dc_addr}\r\nConnection: close\r\n\r\n"
        );
        let get_resp = send_http_request(dc_addr, &get_req).await.unwrap();
        assert!(String::from_utf8_lossy(&get_resp).contains("SSH Hardening"));

        let del_req = format!(
            "DELETE /v1/policies/baseline-ssh HTTP/1.1\r\nHost: {dc_addr}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            admin_tokens.access_token
        );
        send_http_request(dc_addr, &del_req).await.unwrap();
        let bundle_after = fetch_remote_policy_bundle(dc_addr).await.unwrap();
        assert!(bundle_after.policies.is_empty());

        let _ = fs::remove_dir_all(&temp);
    }
}
