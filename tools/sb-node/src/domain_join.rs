use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static REVOCATION_HUB: OnceLock<crate::dc_discovery::RevocationBroadcaster> = OnceLock::new();

/// Returns the process-wide real-time revocation broadcaster.
pub fn revocation_hub() -> &'static crate::dc_discovery::RevocationBroadcaster {
    REVOCATION_HUB.get_or_init(crate::dc_discovery::RevocationBroadcaster::default)
}

pub const MAX_JOIN_REQUEST_BYTES: usize = 64 * 1024;
pub const DEFAULT_DEVICE_CERT_DAYS: u32 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenewedCertificate {
    pub machine_id: String,
    pub fqdn: String,
    pub device_cert_pem: String,
    pub validity_days: u32,
    pub issued_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrlEntry {
    pub machine_id: String,
    pub fqdn: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCrlBundle {
    pub domain: String,
    pub revision: u64,
    pub issued_at: String,
    pub revoked_machines: Vec<CrlEntry>,
    pub signature_b64: String,
}

/// Renews a joined machine's X.509 device certificate (default 30 days) fail-closed.
// [SECURITY-VERIFIED] CWE-295 / CWE-863 Mitigiert:
// Lehnt unbekannte oder gesperrte (`revoked == true`) Maschinen strikt ab, bevor ein neues Blatt-Zertifikat ausgestellt wird.
pub fn renew_machine_certificate(
    machine_id: &str,
    domain: &str,
    registry_path: Option<&Path>,
    validity_days: Option<u32>,
) -> Result<RenewedCertificate, String> {
    let clean_domain = validate_domain_name(domain)?;
    let default_path = DomainRegistry::path_for(&clean_domain)?;
    let reg_path = registry_path.unwrap_or(&default_path);
    let registry = DomainRegistry::load_from_path(reg_path, &clean_domain)?;
    let rec = registry
        .machines
        .iter()
        .find(|m| m.machine_id == machine_id)
        .ok_or_else(|| format!("Machine '{machine_id}' not found in domain '{clean_domain}'"))?;
    if rec.revoked {
        return Err(format!(
            "Machine '{machine_id}' is revoked and cannot renew certificates"
        ));
    }
    let days = validity_days
        .unwrap_or(DEFAULT_DEVICE_CERT_DAYS)
        .clamp(1, 90);
    let leaf = X509Ca::issue_leaf_certificate(&[rec.fqdn.clone(), rec.hostname.clone()], days)
        .map_err(|e| format!("Certificate renewal failed: {e}"))?;
    Ok(RenewedCertificate {
        machine_id: rec.machine_id.clone(),
        fqdn: rec.fqdn.clone(),
        device_cert_pem: leaf.cert_pem.clone(),
        validity_days: days,
        issued_at: Utc::now().to_rfc3339(),
    })
}

/// Builds and Ed25519-signs a global Certificate Revocation List (CRL) bundle for `domain`.
pub fn build_signed_crl(
    domain: &str,
    registry_path: Option<&Path>,
    signing_key: &SigningKey,
) -> Result<SignedCrlBundle, String> {
    let clean_domain = validate_domain_name(domain)?;
    let default_path = DomainRegistry::path_for(&clean_domain)?;
    let reg_path = registry_path.unwrap_or(&default_path);
    let registry = DomainRegistry::load_from_path(reg_path, &clean_domain)?;

    let mut revoked_machines: Vec<CrlEntry> = registry
        .machines
        .iter()
        .filter(|m| m.revoked)
        .map(|m| CrlEntry {
            machine_id: m.machine_id.clone(),
            fqdn: m.fqdn.clone(),
            reason: m
                .revoked_reason
                .clone()
                .unwrap_or_else(|| "revoked".to_string()),
        })
        .collect();
    revoked_machines.sort_by(|a, b| a.machine_id.cmp(&b.machine_id));

    let revision = Utc::now().timestamp().max(1) as u64;
    let issued_at = Utc::now().to_rfc3339();
    let canonical = serde_json::to_vec(&(&clean_domain, revision, &issued_at, &revoked_machines))
        .map_err(|e| format!("Failed to serialize CRL payload: {e}"))?;
    let sig = signing_key.sign(&canonical);
    Ok(SignedCrlBundle {
        domain: clean_domain,
        revision,
        issued_at,
        revoked_machines,
        signature_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    })
}

/// Verifies an Ed25519-signed CRL bundle fail-closed.
pub fn verify_signed_crl(
    bundle: &SignedCrlBundle,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(bundle.signature_b64.trim())
        .map_err(|_| "Invalid base64 CRL signature".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "CRL signature must be 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = serde_json::to_vec(&(
        &bundle.domain,
        bundle.revision,
        &bundle.issued_at,
        &bundle.revoked_machines,
    ))
    .map_err(|e| format!("Failed to serialize CRL payload: {e}"))?;
    verifying_key
        .verify(&canonical, &sig)
        .map_err(|_| "CRL Ed25519 signature verification failed".to_string())
}

/// Persistent registry of domain-joined machines for a single domain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainRegistry {
    pub domain: String,
    pub machines: Vec<MachineRecord>,
}

impl DomainRegistry {
    /// Returns the unified domain registry path under `~/.sb/domain/machines.json`.
    pub fn path_for(domain: &str) -> Result<PathBuf, String> {
        let _clean = validate_domain_name(domain)?;
        Ok(local_domain_dir().join("machines.json"))
    }

    /// Loads an existing registry or creates an empty one for `domain`.
    pub fn load_or_create(domain: &str) -> Result<Self, String> {
        let clean = validate_domain_name(domain)?;
        let path = Self::path_for(&clean)?;
        Self::load_from_path(&path, &clean)
    }

    pub fn load_from_path(path: &Path, domain: &str) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if let Ok(db) = open_domain_db(Some(parent)) {
                if let Ok(db_machines) = db.list_machines_internal(domain) {
                    if !db_machines.is_empty() {
                        return Ok(Self {
                            domain: domain.to_string(),
                            machines: db_machines,
                        });
                    }
                    if path.exists() {
                        let raw = fs::read_to_string(path).map_err(|e| {
                            format!("Failed to read domain registry {}: {e}", path.display())
                        })?;
                        let legacy: Self = serde_json::from_str(&raw).map_err(|e| {
                            format!("Failed to parse domain registry {}: {e}", path.display())
                        })?;
                        for m in &legacy.machines {
                            let _ = db.upsert_machine_internal(domain, m);
                        }
                        return Ok(legacy);
                    }
                }
            }
        }
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
            if let Ok(db) = open_domain_db(Some(parent)) {
                for m in &self.machines {
                    let _ = db.upsert_machine_internal(&self.domain, m);
                }
            }
        }
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

/// Opens the transactional, encrypted-at-rest `domain.db` (SQLite WAL) under `base_dir`
/// (defaults to `~/.sb/domain`).
pub fn open_domain_db(base_dir: Option<&Path>) -> Result<sb_db::SovereignDb, String> {
    let dir = base_dir.map(PathBuf::from).unwrap_or_else(local_domain_dir);
    let key_path = dir.join("domain_db.key");
    let db_path = dir.join("domain.db");
    let master_key = sb_db::MasterKey::load_or_create_file(&key_path).map_err(|e| e.to_string())?;
    sb_db::SovereignDb::open(&db_path, master_key).map_err(|e| e.to_string())
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
    let leaf =
        X509Ca::issue_leaf_certificate(&[fqdn.clone(), hostname.clone()], DEFAULT_DEVICE_CERT_DAYS)
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
    registry.machines.push(record.clone());
    if let Some(parent) = reg_path.parent() {
        if let Ok(db) = open_domain_db(Some(parent)) {
            if let Ok(ticket) = sb_db::verify_auth_token(&req.join_token, verifier, false) {
                let _ = db.register_machine_atomic(&ticket, &domain, record);
            }
        }
    }
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
    revocation_hub().publish(crate::dc_discovery::RevocationEvent::machine_revoked(
        &updated.machine_id,
        &domain,
    ));
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

    if method == "GET" && path == "/.well-known/openid-configuration" {
        let host = header_lines
            .iter()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case("host").then(|| v.trim())
            })
            .unwrap_or("127.0.0.1:8090");
        let scheme = if host.starts_with("127.0.0.1") || host.starts_with("localhost") {
            "http"
        } else {
            "https"
        };
        let spec = crate::oidc::discovery_document(&format!("{scheme}://{host}")).to_string();
        return write_http_json(stream, 200, "OK", &spec).await;
    }

    if method == "GET" && (path == "/.well-known/jwks.json" || path == "/oauth2/jwks.json") {
        let pub_path = sb_core::paths::sb_home().join("auth").join("auth.pub");
        let pub_b64 = match fs::read_to_string(&pub_path) {
            Ok(s) => s,
            Err(e) => {
                let msg =
                    serde_json::json!({ "error": format!("auth.pub not found: {e}") }).to_string();
                return write_http_json(stream, 404, "Not Found", &msg).await;
            }
        };
        return match crate::oidc::jwks_document(&pub_b64) {
            Ok(jwks) => write_http_json(stream, 200, "OK", &jwks.to_string()).await,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                write_http_json(stream, 500, "Internal Server Error", &msg).await
            }
        };
    }

    if method == "GET" && path == "/v1/domain/crl" {
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let domain_name = query_param(query, "domain")
            .and_then(|d| validate_domain_name(d).ok())
            .unwrap_or_else(|| "corp.eu".to_string());
        let key_path = base_dir.join("policy_authority.key");
        let signing_key = if let Ok(raw) = fs::read_to_string(&key_path) {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(raw.trim()) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    SigningKey::from_bytes(&arr)
                } else {
                    SigningKey::generate(&mut OsRng)
                }
            } else {
                SigningKey::generate(&mut OsRng)
            }
        } else {
            SigningKey::generate(&mut OsRng)
        };
        return match build_signed_crl(&domain_name, registry_path, &signing_key) {
            Ok(bundle) => {
                let json = serde_json::to_string(&bundle).unwrap_or_default();
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                write_http_json(stream, 500, "Internal Server Error", &msg).await
            }
        };
    }

    if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/cert/renew") {
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
        let machine_id = path
            .trim_start_matches("/v1/machines/")
            .trim_end_matches("/cert/renew")
            .trim();
        if !claims.has_capability("domain:join")
            && !claims.has_role("admin")
            && claims.subject != machine_id
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"missing permission to renew certificate"}"#,
            )
            .await;
        }
        let domain_name = query_param(query, "domain")
            .and_then(|d| validate_domain_name(d).ok())
            .unwrap_or_else(|| "corp.eu".to_string());
        return match renew_machine_certificate(machine_id, &domain_name, registry_path, None) {
            Ok(renewed) => {
                let json = serde_json::to_string(&renewed).unwrap_or_default();
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let status = if e.contains("revoked") { 403 } else { 404 };
                let reason = if status == 403 {
                    "Forbidden"
                } else {
                    "Not Found"
                };
                let msg = serde_json::json!({ "error": e }).to_string();
                write_http_json(stream, status, reason, &msg).await
            }
        };
    }

    if method == "POST" && path == "/v1/auth/code" {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
            .any(|c| c == "directory:write" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks directory:write or domain:admin"}"#,
            )
            .await;
        }
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let target_user = payload["username"].as_str().unwrap_or("");
        let clean_user = match sb_core::identity::validate_username(target_user) {
            Ok(u) => u,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 400, "Bad Request", &msg).await;
            }
        };
        let caps: Vec<String> = payload["capabilities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let ttl = payload["ttl_seconds"].as_i64().unwrap_or(300);
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let code_path = base_dir.join("login_codes.json");
        let mut store = crate::oidc::LoginCodeStore::load(&code_path).unwrap_or_default();
        let code = store.issue_code(&clean_user, caps, ttl);
        if let Err(e) = store.save(&code_path) {
            let msg = serde_json::json!({ "error": e }).to_string();
            return write_http_json(stream, 500, "Internal Server Error", &msg).await;
        }
        let json = serde_json::json!({ "username": clean_user, "code": code, "ttl_seconds": ttl.clamp(60, 900) }).to_string();
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method == "POST" && path == "/v1/auth/exchange" {
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let code = payload["code"].as_str().unwrap_or("");
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let code_path = base_dir.join("login_codes.json");
        let mut store = crate::oidc::LoginCodeStore::load(&code_path).unwrap_or_default();
        let auth_dir = sb_core::paths::sb_home().join("auth");
        let key_b64 = match fs::read_to_string(auth_dir.join("auth.key")) {
            Ok(s) => s,
            Err(e) => {
                let msg =
                    serde_json::json!({ "error": format!("Missing auth.key: {e}") }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        };
        let keypair = match sb_auth::crypto::Keypair::from_secret_base64(key_b64.trim()) {
            Ok(k) => k,
            Err(e) => {
                let msg =
                    serde_json::json!({ "error": format!("Invalid auth.key: {e}") }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        };
        let rev_store = match sb_auth::FileRevocationStore::open(auth_dir.join("revocations.json"))
        {
            Ok(r) => Arc::new(r),
            Err(e) => {
                let msg = serde_json::json!({ "error": format!("Revocation store error: {e}") })
                    .to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        };
        let engine = sb_auth::AuthEngine::new(keypair, rev_store);
        return match crate::oidc::exchange_login_code_for_session(
            code,
            &mut store,
            &engine,
            vec!["user".into()],
        ) {
            Ok(tokens) => {
                let _ = store.save(&code_path);
                let _ = crate::audit_log::append_audit_event(
                    &base_dir.join("audit.jsonl"),
                    "oidc",
                    "auth.login",
                    "browser-session",
                    "ok",
                    serde_json::json!({}),
                );
                let json = session_tokens_json(&tokens);
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                write_http_json(stream, 401, "Unauthorized", &msg).await
            }
        };
    }

    if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/auth") {
        let machine_id = path
            .trim_start_matches("/v1/machines/")
            .trim_end_matches("/auth");
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let ts = payload
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let sig_b64 = payload
            .get("signature_b64")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if (Utc::now().timestamp() - ts).abs() > 120 {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"machine auth timestamp expired or skewed (>120s)"}"#,
            )
            .await;
        }
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let reg_path = registry_path
            .map(PathBuf::from)
            .unwrap_or_else(|| base_dir.join("machines.json"));
        let registry = match DomainRegistry::load_from_path(&reg_path, "corp.eu") {
            Ok(r) => r,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        };
        let Some(machine) = registry
            .machines
            .iter()
            .find(|m| m.machine_id == machine_id)
        else {
            return write_http_json(stream, 404, "Not Found", r#"{"error":"machine not found"}"#)
                .await;
        };
        if machine.revoked {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"machine is revoked"}"#,
            )
            .await;
        }
        let Ok(vk) = parse_public_key(&machine.machine_public_key_b64) else {
            return write_http_json(
                stream,
                500,
                "Internal Server Error",
                r#"{"error":"corrupt machine public key"}"#,
            )
            .await;
        };
        let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(sig_b64.trim()) else {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"invalid signature encoding"}"#,
            )
            .await;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"invalid signature length"}"#,
            )
            .await;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let msg_to_verify = format!("machine_auth:{machine_id}:{ts}");
        if vk.verify_strict(msg_to_verify.as_bytes(), &sig).is_err() {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"machine signature verification failed"}"#,
            )
            .await;
        }
        let engine = match load_local_auth_engine() {
            Ok(e) => e,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        };
        return match engine.issue_session(
            &machine.fqdn,
            vec!["machines".into()],
            vec!["domain:join".into(), "laps:write".into()],
            serde_json::json!({ "machine_id": machine.machine_id }),
        ) {
            Ok(tokens) => {
                let json = session_tokens_json(&tokens);
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg =
                    serde_json::json!({ "error": format!("Token issue failed: {e}") }).to_string();
                write_http_json(stream, 500, "Internal Server Error", &msg).await
            }
        };
    }

    if method == "POST" && path == "/v1/auth/login" {
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let username = payload["username"].as_str().unwrap_or("").trim();
        let password = payload["password"].as_str().unwrap_or("");
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        if let Some(retry_secs) = check_login_lockout(username).await {
            let msg = serde_json::json!({
                "error": format!("Zu viele fehlgeschlagene Anmeldeversuche. Bitte in {retry_secs}s erneut versuchen.")
            })
            .to_string();
            return write_http_json(stream, 429, "Too Many Requests", &msg).await;
        }
        let creds = crate::oidc::CredentialStore::load(&base_dir.join("credentials.json"))
            .unwrap_or_default();
        if !creds.verify(username, password) {
            let locked = record_login_failure(username).await;
            if locked {
                let _ = crate::audit_log::append_audit_event(
                    &base_dir.join("audit.jsonl"),
                    username,
                    "auth.lockout",
                    "password",
                    "denied",
                    serde_json::json!({ "reason": "max_failed_attempts" }),
                );
            }
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"invalid username or password"}"#,
            )
            .await;
        }
        clear_login_failures(username).await;
        let dir = crate::directory_users::IdentityDirectory::load_or_create(
            &base_dir.join("users.json"),
            "skulls-and-bones.sb",
        )
        .unwrap_or_default();
        let Some(user) = dir.users.get(username) else {
            return write_http_json(stream, 401, "Unauthorized", r#"{"error":"user not found"}"#)
                .await;
        };
        if !user.enabled {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"user account is disabled"}"#,
            )
            .await;
        }
        let engine = match load_local_auth_engine() {
            Ok(e) => e,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        };
        let mut caps = vec!["domain:read".to_string(), "directory:read".to_string()];
        if user.groups.iter().any(|g| g == "admins") {
            caps.extend([
                "domain:admin".into(),
                "domain:join".into(),
                "directory:write".into(),
                "policy:write".into(),
                "audit:read".into(),
                "dns:write".into(),
                "vault:write".into(),
                "laps:read".into(),
            ]);
        } else {
            use crate::directory_users::DelegatedPermission as DP;
            if dir.has_delegated_permission(&user.username, DP::LapsReveal) {
                caps.push("laps:read".into());
            }
            if dir.has_delegated_permission(&user.username, DP::PolicyManage) {
                caps.push("policy:write".into());
            }
            if dir.has_delegated_permission(&user.username, DP::UserManage)
                || dir.has_delegated_permission(&user.username, DP::GroupManage)
            {
                caps.push("directory:write".into());
            }
            if dir.has_delegated_permission(&user.username, DP::AuditRead) {
                caps.push("audit:read".into());
            }
        }
        let passkeys_path = base_dir.join("passkeys.json");
        let mut pk_store = crate::passkey::PasskeyStore::load(&passkeys_path).unwrap_or_default();
        if pk_store.user_has_passkey(&user.username) {
            let rp_id = header_lines
                .iter()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim().eq_ignore_ascii_case("host").then(|| v.trim())
                })
                .and_then(|h| h.split(':').next())
                .unwrap_or("console.skulls-and-bones.org");
            if let Ok(opts) = pk_store.start_authentication(&user.username, rp_id) {
                let _ = pk_store.save(&passkeys_path);
                let msg = serde_json::json!({
                    "mfa_required": true,
                    "mfa_method": "passkey",
                    "username": user.username,
                    "options": opts,
                })
                .to_string();
                return write_http_json(stream, 202, "Accepted", &msg).await;
            }
        }
        return match engine.issue_session(
            &user.username,
            user.groups.clone(),
            caps,
            serde_json::json!({}),
        ) {
            Ok(tokens) => {
                let _ = crate::audit_log::append_audit_event(
                    &base_dir.join("audit.jsonl"),
                    &user.username,
                    "auth.login",
                    "password",
                    "ok",
                    serde_json::json!({}),
                );
                let json = session_tokens_json(&tokens);
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg =
                    serde_json::json!({ "error": format!("Token issue failed: {e}") }).to_string();
                write_http_json(stream, 500, "Internal Server Error", &msg).await
            }
        };
    }

    if crate::dc_routes::handle_dc_extended_routes(
        stream,
        method,
        path,
        &header_lines,
        &mut buf,
        &mut chunk,
        header_end,
        registry_path,
    )
    .await?
    {
        return Ok(());
    }

    if method == "POST" && path == "/v1/auth/refresh" {
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let refresh_token = payload["refresh_token"].as_str().unwrap_or("");
        let engine = match load_local_auth_engine() {
            Ok(e) => e,
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
        };
        return match engine.refresh_session(refresh_token) {
            Ok(tokens) => {
                let json = session_tokens_json(&tokens);
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg =
                    serde_json::json!({ "error": format!("Refresh failed: {e}") }).to_string();
                write_http_json(stream, 401, "Unauthorized", &msg).await
            }
        };
    }

    if method == "POST" && path == "/v1/me/password" {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let new_pw = payload["password"].as_str().unwrap_or("");
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let creds_path = base_dir.join("credentials.json");
        let mut creds = crate::oidc::CredentialStore::load(&creds_path).unwrap_or_default();
        if let Err(e) = creds.set_password(&claims.subject, new_pw) {
            let msg = serde_json::json!({ "error": e }).to_string();
            return write_http_json(stream, 400, "Bad Request", &msg).await;
        }
        if let Err(e) = creds.save(&creds_path) {
            let msg = serde_json::json!({ "error": e }).to_string();
            return write_http_json(stream, 500, "Internal Server Error", &msg).await;
        }
        let _ = crate::audit_log::append_audit_event(
            &base_dir.join("audit.jsonl"),
            &claims.subject,
            "user.password_update",
            &claims.subject,
            "ok",
            serde_json::json!({}),
        );
        return write_http_json(stream, 200, "OK", r#"{"status":"password_updated"}"#).await;
    }

    if method == "GET" && (path == "/v1/auth/userinfo" || path == "/oauth2/userinfo") {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let dir = crate::directory_users::IdentityDirectory::load_or_create(
            &base_dir.join("users.json"),
            "corp.eu",
        )
        .unwrap_or_default();
        let json = if let Some(u) = dir.users.get(&claims.subject) {
            serde_json::json!({
                "sub": u.username,
                "name": u.display_name,
                "email": u.email,
                "groups": u.groups,
            })
            .to_string()
        } else {
            serde_json::json!({ "sub": claims.subject, "groups": claims.roles }).to_string()
        };
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/heartbeat"))
        || (method == "GET" && path == "/v1/fleet/health")
        || path.starts_with("/v1/packages")
    {
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let fleet_path = base_dir.join("fleet.json");
        let audit_path = base_dir.join("audit.jsonl");

        if method == "GET" && path == "/v1/packages" {
            let token_opt = extract_bearer_token(&header_lines).or_else(|| {
                if path.ends_with("/ws") {
                    query_param(query, "token")
                } else {
                    None
                }
            });
            let Some(token) = token_opt else {
                return write_http_json(
                    stream,
                    401,
                    "Unauthorized",
                    r#"{"error":"missing bearer token"}"#,
                )
                .await;
            };
            if let Err(e) = verifier.verify_token(token) {
                let msg = serde_json::json!({ "error": format!("authentication failed: {e}") })
                    .to_string();
                return write_http_json(stream, 401, "Unauthorized", &msg).await;
            }
            let store = crate::fleet::FleetStore::load(&fleet_path).unwrap_or_default();
            let list = if let Some(mid) = query_param(query, "machine_id") {
                store.packages_for_machine(mid)
            } else {
                store.packages.values().cloned().collect()
            };
            let json = serde_json::json!({ "packages": list }).to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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

        if method == "GET" && path == "/v1/fleet/health" {
            if !claims
                .capabilities
                .iter()
                .any(|c| c == "domain:read" || c == "domain:admin")
            {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks domain:read or domain:admin"}"#,
                )
                .await;
            }
            let store = crate::fleet::FleetStore::load(&fleet_path).unwrap_or_default();
            let laps_meta = crate::laps::LapsMetaStore::load(&base_dir.join("laps_meta.json"))
                .unwrap_or_default();
            let laps_pending = laps_meta
                .entries
                .values()
                .filter(|e| e.rotate_pending)
                .count();
            let heartbeats: Vec<&crate::fleet::MachineHeartbeat> =
                store.heartbeats.values().collect();
            let json = serde_json::json!({
                "heartbeats": heartbeats,
                "laps_rotate_pending": laps_pending,
                "package_count": store.packages.len(),
            })
            .to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/heartbeat") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/heartbeat");
            if !claims
                .capabilities
                .iter()
                .any(|c| c == "domain:join" || c == "domain:admin")
            {
                return write_problem_json(
                    stream,
                    403,
                    "Forbidden",
                    "missing-capability",
                    "Forbidden",
                    "token lacks domain:join or domain:admin",
                    path,
                )
                .await;
            }
            // [SECURITY-HYPOTHESIS] CWE-639 (IDOR): Any machine with domain:join could post
            // heartbeats for another machine_id.
            // [SECURITY-VERIFIED] Enforces subject binding unless caller holds admin role/capability.
            if claims.subject != machine_id
                && !claims.has_role("admin")
                && !claims.has_capability("domain:admin")
            {
                return write_problem_json(
                    stream,
                    403,
                    "Forbidden",
                    "machine-id-mismatch",
                    "Forbidden",
                    "token subject does not match target machine_id",
                    path,
                )
                .await;
            }
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let mut hb: crate::fleet::MachineHeartbeat = match serde_json::from_slice(&body) {
                Ok(h) => h,
                Err(e) => {
                    let msg =
                        serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            hb.machine_id = machine_id.to_string();
            let hb_fqdn = hb.fqdn.clone();
            let mut store = crate::fleet::FleetStore::load(&fleet_path).unwrap_or_default();
            store.record_heartbeat(hb);
            let _ = store.save(&fleet_path);

            let laps_meta = crate::laps::LapsMetaStore::load(&base_dir.join("laps_meta.json"))
                .unwrap_or_default();
            let mut actions: Vec<String> = Vec::new();
            let reg_path = registry_path
                .map(PathBuf::from)
                .unwrap_or_else(|| base_dir.join("machines.json"));
            if let Ok(reg) = DomainRegistry::load_from_path(&reg_path, "corp.eu") {
                if reg
                    .machines
                    .iter()
                    .any(|m| m.machine_id == machine_id && m.revoked)
                {
                    actions.push("machine_offboard".to_string());
                }
            }
            if let Some(entry) = laps_meta.entries.get(machine_id) {
                if entry.rotate_requested || entry.rotate_pending {
                    actions.push("laps_rotate".to_string());
                }
            }
            if let Ok(users_dir) = crate::directory_users::IdentityDirectory::load_or_create(
                &base_dir.join("users.json"),
                "corp.eu",
            ) {
                for u in users_dir.users.values() {
                    if !crate::os_auth_broker::is_protected_system_account(&u.username)
                        && (!u.enabled
                            || users_dir
                                .evaluate_machine_login(&u.username, machine_id, &hb_fqdn)
                                .is_err())
                    {
                        actions.push(format!("offboard_user:{}", u.username));
                    }
                }
            }
            let resp = serde_json::json!({
                "status": "recorded",
                "actions": actions,
            })
            .to_string();
            return write_http_json(stream, 200, "OK", &resp).await;
        }

        if method == "PUT" && path.starts_with("/v1/packages/") {
            if !claims
                .capabilities
                .iter()
                .any(|c| c == "policy:write" || c == "domain:admin")
            {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks policy:write or domain:admin"}"#,
                )
                .await;
            }
            let pkg_id = path.trim_start_matches("/v1/packages/");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let mut pkg: crate::fleet::PackageManifest = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(e) => {
                    let msg =
                        serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            pkg.id = pkg_id.to_string();
            let mut store = crate::fleet::FleetStore::load(&fleet_path).unwrap_or_default();
            return match store.upsert_package(pkg) {
                Ok(saved) => {
                    let _ = store.save(&fleet_path);
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "package.upsert",
                        &saved.id,
                        "ok",
                        serde_json::json!({ "rollout_percent": saved.rollout_percent, "version": saved.version }),
                    );
                    let json = serde_json::to_string(&saved).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }
    }

    if path.starts_with("/v1/machines/")
        && (path.ends_with("/laps")
            || path.ends_with("/laps/reveal")
            || path.ends_with("/laps/rotate-request"))
    {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let vault_dir = base_dir.join("vaults").join("laps");
        let meta_path = base_dir.join("laps_meta.json");
        let audit_path = base_dir.join("audit.jsonl");

        if method == "GET" && path.ends_with("/laps") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/laps");
            if !claims
                .capabilities
                .iter()
                .any(|c| c == "domain:read" || c == "domain:admin" || c == "laps:read")
            {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks laps:read or domain:admin"}"#,
                )
                .await;
            }
            let meta_store = crate::laps::LapsMetaStore::load(&meta_path).unwrap_or_default();
            return match meta_store.entries.get(machine_id) {
                Some(m) => {
                    let json = serde_json::to_string(m).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                None => {
                    write_http_json(
                        stream,
                        404,
                        "Not Found",
                        r#"{"error":"no LAPS entry for machine"}"#,
                    )
                    .await
                }
            };
        }

        if method == "POST" && path.ends_with("/laps/rotate-request") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/laps/rotate-request");
            if !claims
                .capabilities
                .iter()
                .any(|c| c == "laps:write" || c == "domain:admin")
            {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks laps:write or domain:admin"}"#,
                )
                .await;
            }
            return match crate::laps::mark_rotate_requested(machine_id, &meta_path) {
                Ok(meta) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "laps.rotate_request",
                        machine_id,
                        "ok",
                        serde_json::json!({ "rotate_requested": meta.rotate_requested }),
                    );
                    let json = serde_json::to_string(&meta).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        if method == "PUT" && path.ends_with("/laps") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/laps");
            if !claims
                .capabilities
                .iter()
                .any(|c| c == "domain:join" || c == "domain:admin" || c == "laps:write")
            {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks laps:write or domain:admin"}"#,
                )
                .await;
            }
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let account = payload["local_account"].as_str().unwrap_or("sb-rescue");
            let password = payload["password"].as_str().unwrap_or("");
            let passphrase = payload["passphrase"].as_str().unwrap_or("");
            let ttl_days = payload["ttl_days"].as_i64().unwrap_or(30);
            return match crate::laps::store_laps_password(
                machine_id, account, password, passphrase, ttl_days, &vault_dir, &meta_path,
            ) {
                Ok(meta) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "laps.rotate",
                        machine_id,
                        "ok",
                        serde_json::json!({ "account": meta.local_account, "version": meta.version }),
                    );
                    let json = serde_json::to_string(&meta).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        if method == "POST" && path.ends_with("/laps/reveal") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/laps/reveal");
            if !claims
                .capabilities
                .iter()
                .any(|c| c == "laps:read" || c == "domain:admin")
            {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks laps:read or domain:admin"}"#,
                )
                .await;
            }
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let passphrase = payload["passphrase"].as_str().unwrap_or("");
            return match crate::laps::reveal_laps_password(
                machine_id, passphrase, &vault_dir, &meta_path,
            ) {
                Ok((password, meta)) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "laps.reveal",
                        machine_id,
                        "ok",
                        serde_json::json!({ "account": meta.local_account }),
                    );
                    let json = serde_json::json!({
                        "machine_id": meta.machine_id,
                        "local_account": meta.local_account,
                        "password": password,
                        "rotate_pending": meta.rotate_pending,
                    })
                    .to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 403, "Forbidden", &msg).await
                }
            };
        }
    }

    if method == "GET" && path == "/v1/machines" {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
            return write_http_json(
                stream,
                401,
                "Unauthorized",
                r#"{"error":"missing bearer token"}"#,
            )
            .await;
        };
        if let Err(e) = verifier.verify_token(token) {
            let msg =
                serde_json::json!({ "error": format!("authentication failed: {e}") }).to_string();
            return write_http_json(stream, 401, "Unauthorized", &msg).await;
        }
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
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        if !dry_run {
            let _ = crate::audit_log::append_audit_event(
                &base_dir.join("audit.jsonl"),
                &saved.updated_by,
                "policy.put",
                &saved.id,
                "ok",
                serde_json::json!({ "revision": store.revision }),
            );
        }
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method == "GET" && path == "/v1/audit/events" {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
            .any(|c| c == "audit:read" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks audit:read or domain:admin capability"}"#,
            )
            .await;
        }
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let audit_path = base_dir.join("audit.jsonl");
        let limit = query_param(query, "limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(50)
            .clamp(1, 500);
        let events = crate::audit_log::read_recent_events(&audit_path, limit).unwrap_or_default();
        let chain_valid = crate::audit_log::verify_audit_chain(&audit_path).is_ok();
        let json = serde_json::json!({
            "chain_valid": chain_valid,
            "events": events,
        })
        .to_string();
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method == "POST" && path.starts_with("/v1/users/") && path.ends_with("/offboard") {
        let username = path
            .trim_start_matches("/v1/users/")
            .trim_end_matches("/offboard");
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
            .any(|c| c == "directory:write" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks directory:write or domain:admin capability"}"#,
            )
            .await;
        }
        let revoke_machines = query_param(query, "revoke_machines") == Some("true");
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        return match offboard_user(
            username,
            &claims.subject,
            revoke_machines,
            Some(&base_dir),
            registry_path,
        ) {
            Ok(report) => {
                let json = serde_json::to_string(&report).map_err(|e| e.to_string())?;
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                write_http_json(stream, 404, "Not Found", &msg).await
            }
        };
    }

    if path == "/v1/me/elevate"
        || path == "/v1/me/elevations"
        || path.starts_with("/v1/rbac/rules")
        || path.starts_with("/v1/apps")
    {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let users_dir = crate::directory_users::IdentityDirectory::load_or_create(
            &base_dir.join("users.json"),
            "corp.eu",
        )
        .unwrap_or_default();
        let Some(user) = users_dir.users.get(&claims.subject) else {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"user not found in directory"}"#,
            )
            .await;
        };
        if !user.enabled {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"user account is disabled"}"#,
            )
            .await;
        }
        let rbac_path = base_dir.join("rbac.json");
        let audit_path = base_dir.join("audit.jsonl");
        let mut store = crate::rbac::RbacStore::load(&rbac_path).unwrap_or_default();
        let is_admin = claims.capabilities.iter().any(|c| c == "domain:admin");

        if method == "GET" && path == "/v1/me/elevations" {
            let active = store.active_elevations_for(&claims.subject);
            let json = serde_json::json!({ "elevations": active }).to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        if method == "POST" && path == "/v1/me/elevate" {
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let rule_id = payload["rule_id"].as_str().unwrap_or("");
            let reason = payload["reason"].as_str().unwrap_or("");
            let ttl = payload["ttl_seconds"].as_u64().unwrap_or(1800);
            return match store.request_elevation(user, rule_id, reason, ttl) {
                Ok(elev) => {
                    let _ = store.save(&rbac_path);
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "rbac.elevate",
                        rule_id,
                        "ok",
                        serde_json::json!({ "reason": elev.reason, "expires_at": elev.expires_at }),
                    );
                    let json = serde_json::to_string(&elev).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 403, "Forbidden", &msg).await
                }
            };
        }

        if method == "GET" && path == "/v1/rbac/rules" {
            if !is_admin {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"requires domain:admin capability"}"#,
                )
                .await;
            }
            let rules: Vec<&crate::rbac::ElevationRule> = store.rules.values().collect();
            let json = serde_json::json!({ "rules": rules }).to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        if method == "PUT" && path.starts_with("/v1/rbac/rules/") {
            if !is_admin {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"requires domain:admin capability"}"#,
                )
                .await;
            }
            let rule_id = path.trim_start_matches("/v1/rbac/rules/");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let mut rule: crate::rbac::ElevationRule = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    let msg =
                        serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            rule.id = rule_id.to_string();
            return match store.upsert_rule(rule) {
                Ok(saved) => {
                    let _ = store.save(&rbac_path);
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "rbac.rule_upsert",
                        &saved.id,
                        "ok",
                        serde_json::json!({ "eligible_groups": saved.eligible_groups }),
                    );
                    let json = serde_json::to_string(&saved).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        if method == "GET" && path == "/v1/apps" {
            let apps: Vec<&crate::rbac::CompanyApp> = store
                .apps
                .values()
                .filter(|a| a.is_visible_to(user, is_admin))
                .collect();
            let json = serde_json::json!({ "apps": apps }).to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        if method == "PUT" && path.starts_with("/v1/apps/") {
            if !is_admin {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"requires domain:admin capability"}"#,
                )
                .await;
            }
            let app_id = path.trim_start_matches("/v1/apps/");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let mut app: crate::rbac::CompanyApp = match serde_json::from_slice(&body) {
                Ok(a) => a,
                Err(e) => {
                    let msg =
                        serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            app.id = app_id.to_string();
            return match store.upsert_app(app) {
                Ok(saved) => {
                    let _ = store.save(&rbac_path);
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "app.upsert",
                        &saved.id,
                        "ok",
                        serde_json::json!({ "url": saved.url }),
                    );
                    let json = serde_json::to_string(&saved).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        if method == "DELETE" && path.starts_with("/v1/apps/") {
            if !is_admin {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"requires domain:admin capability"}"#,
                )
                .await;
            }
            let app_id = path.trim_start_matches("/v1/apps/");
            if store.apps.remove(app_id).is_some() {
                let _ = store.save(&rbac_path);
                let json = serde_json::json!({ "deleted": app_id }).to_string();
                return write_http_json(stream, 200, "OK", &json).await;
            }
            return write_http_json(stream, 404, "Not Found", r#"{"error":"app not found"}"#).await;
        }
    }

    if path.starts_with("/v1/me/vault") || path.starts_with("/v1/vault/team") {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let users_path = base_dir.join("users.json");
        let users_dir =
            crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
                .unwrap_or_default();
        let Some(user) = users_dir.users.get(&claims.subject) else {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"user not found in directory"}"#,
            )
            .await;
        };
        if !user.enabled {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"user account is disabled"}"#,
            )
            .await;
        }
        let vaults_root = base_dir.join("vaults");
        let audit_path = base_dir.join("audit.jsonl");

        // Personal Vault (/v1/me/vault)
        if method == "GET" && path == "/v1/me/vault" {
            return match crate::vault_manager::list_personal_vault(&claims.subject, &vaults_root) {
                Ok(entries) => {
                    let json = serde_json::json!({ "entries": entries }).to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        if method == "PUT" && path.starts_with("/v1/me/vault/") {
            let key = path.trim_start_matches("/v1/me/vault/");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => {
                    let msg =
                        serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            let label = payload["label"].as_str().unwrap_or("");
            let secret = payload["secret"].as_str().unwrap_or("");
            let passphrase = payload["passphrase"].as_str().unwrap_or("");
            return match crate::vault_manager::put_personal_secret(
                &claims.subject,
                key,
                label,
                secret,
                passphrase,
                &vaults_root,
            ) {
                Ok(meta) => {
                    let json = serde_json::to_string(&meta).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        if method == "POST" && path.starts_with("/v1/me/vault/") && path.ends_with("/reveal") {
            let key = path
                .trim_start_matches("/v1/me/vault/")
                .trim_end_matches("/reveal");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let passphrase = payload["passphrase"].as_str().unwrap_or("");
            return match crate::vault_manager::reveal_personal_secret(
                &claims.subject,
                key,
                passphrase,
                &vaults_root,
            ) {
                Ok(secret) => {
                    let json = serde_json::json!({ "key": key, "secret": secret }).to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 403, "Forbidden", &msg).await
                }
            };
        }

        if method == "DELETE" && path.starts_with("/v1/me/vault/") {
            let key = path.trim_start_matches("/v1/me/vault/");
            return match crate::vault_manager::delete_personal_secret(
                &claims.subject,
                key,
                &vaults_root,
            ) {
                Ok(true) => {
                    let json = serde_json::json!({ "deleted": key }).to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Ok(false) => {
                    write_http_json(stream, 404, "Not Found", r#"{"error":"secret not found"}"#)
                        .await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        // Team Vault (/v1/vault/team?group=<g> or /v1/vault/team/<g>/<key>[/reveal])
        let is_vault_admin = claims
            .capabilities
            .iter()
            .any(|c| c == "domain:admin" || c == "vault:admin");

        if method == "GET" && path == "/v1/vault/team" {
            let group = query_param(query, "group").unwrap_or("");
            if !is_vault_admin && !user.groups.iter().any(|g| g == group) {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"not a member of target group"}"#,
                )
                .await;
            }
            return match crate::vault_manager::list_team_vault(group, &vaults_root) {
                Ok(entries) => {
                    let json =
                        serde_json::json!({ "group": group, "entries": entries }).to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }

        if let Some(rest) = path.strip_prefix("/v1/vault/team/") {
            let is_reveal = method == "POST" && rest.ends_with("/reveal");
            let trimmed = if is_reveal {
                rest.trim_end_matches("/reveal")
            } else {
                rest
            };
            let Some((group, key)) = trimmed.split_once('/') else {
                return write_http_json(
                    stream,
                    404,
                    "Not Found",
                    r#"{"error":"expected /v1/vault/team/{group}/{key}"}"#,
                )
                .await;
            };
            let is_member = user.groups.iter().any(|g| g == group);
            if !is_vault_admin && !is_member {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"not a member of target group"}"#,
                )
                .await;
            }

            if method == "PUT" {
                let can_write =
                    is_vault_admin || claims.capabilities.iter().any(|c| c == "vault:write");
                if !can_write {
                    return write_http_json(
                        stream,
                        403,
                        "Forbidden",
                        r#"{"error":"token lacks vault:write or domain:admin capability"}"#,
                    )
                    .await;
                }
                let body =
                    match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                        .await?
                    {
                        Some(b) => b,
                        None => return Ok(()),
                    };
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let label = payload["label"].as_str().unwrap_or("");
                let secret = payload["secret"].as_str().unwrap_or("");
                let passphrase = payload["passphrase"].as_str().unwrap_or("");
                return match crate::vault_manager::put_team_secret(
                    group,
                    key,
                    label,
                    secret,
                    passphrase,
                    &claims.subject,
                    &vaults_root,
                ) {
                    Ok(meta) => {
                        let _ = crate::audit_log::append_audit_event(
                            &audit_path,
                            &claims.subject,
                            "vault.team_write",
                            &format!("{group}/{key}"),
                            "ok",
                            serde_json::json!({ "version": meta.version }),
                        );
                        let json = serde_json::to_string(&meta).map_err(|e| e.to_string())?;
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err(e) => {
                        let msg = serde_json::json!({ "error": e }).to_string();
                        write_http_json(stream, 400, "Bad Request", &msg).await
                    }
                };
            }

            if is_reveal {
                let body =
                    match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                        .await?
                    {
                        Some(b) => b,
                        None => return Ok(()),
                    };
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let passphrase = payload["passphrase"].as_str().unwrap_or("");
                return match crate::vault_manager::reveal_team_secret(
                    group,
                    key,
                    passphrase,
                    &vaults_root,
                ) {
                    Ok(secret) => {
                        let _ = crate::audit_log::append_audit_event(
                            &audit_path,
                            &claims.subject,
                            "vault.team_read",
                            &format!("{group}/{key}"),
                            "ok",
                            serde_json::json!({}),
                        );
                        let json =
                            serde_json::json!({ "group": group, "key": key, "secret": secret })
                                .to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err(e) => {
                        let msg = serde_json::json!({ "error": e }).to_string();
                        write_http_json(stream, 403, "Forbidden", &msg).await
                    }
                };
            }
        }
    }

    if (method == "GET" && path == "/v1/me")
        || (method == "PUT" && path == "/v1/me/ssh-key")
        || (method == "POST" && path == "/v1/me/ssh-cert")
    {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let users_path = base_dir.join("users.json");
        let mut dir =
            match crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
            {
                Ok(d) => d,
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 500, "Internal Server Error", &msg).await;
                }
            };

        if method == "GET" && path == "/v1/me" {
            let Some(user) = dir.users.get(&claims.subject) else {
                return write_http_json(
                    stream,
                    404,
                    "Not Found",
                    r#"{"error":"user not found in directory"}"#,
                )
                .await;
            };
            if !user.enabled {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"user account is disabled"}"#,
                )
                .await;
            }
            let reg_file = registry_path
                .map(PathBuf::from)
                .unwrap_or_else(|| base_dir.join("machines.json"));
            let machines: Vec<MachineRecord> = fs::read_to_string(&reg_file)
                .ok()
                .and_then(|raw| serde_json::from_str::<DomainRegistry>(&raw).ok())
                .map(|r| {
                    r.machines
                        .into_iter()
                        .filter(|m| m.joined_by == claims.subject)
                        .collect()
                })
                .unwrap_or_default();
            let json = serde_json::json!({
                "user": user,
                "machines": machines,
            })
            .to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        if method == "PUT" && path == "/v1/me/ssh-key" {
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => {
                    let msg =
                        serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            let raw_key = payload["ssh_public_key"].as_str().unwrap_or("");
            let validated_key = match sb_core::identity::validate_openssh_pubkey(raw_key) {
                Ok(k) => k,
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            let Some(user) = dir.users.get_mut(&claims.subject) else {
                return write_http_json(
                    stream,
                    404,
                    "Not Found",
                    r#"{"error":"user not found in directory"}"#,
                )
                .await;
            };
            if !user.enabled {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"user account is disabled"}"#,
                )
                .await;
            }
            user.ssh_public_key = Some(validated_key);
            user.updated_at = Utc::now().to_rfc3339();
            let updated = user.clone();
            if let Err(e) = dir.save(&users_path) {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 500, "Internal Server Error", &msg).await;
            }
            let _ = crate::audit_log::append_audit_event(
                &base_dir.join("audit.jsonl"),
                &claims.subject,
                "user.ssh_key_update",
                &claims.subject,
                "ok",
                serde_json::json!({}),
            );
            let json = serde_json::to_string(&updated).map_err(|e| e.to_string())?;
            return write_http_json(stream, 200, "OK", &json).await;
        }

        // POST /v1/me/ssh-cert
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let req: sb_core::identity::SshUserCertRequest =
            serde_json::from_slice(&body).unwrap_or(sb_core::identity::SshUserCertRequest {
                ssh_public_key: None,
                ttl_seconds: 8 * 3600,
            });
        return match dir.issue_user_ssh_cert(
            &claims.subject,
            req.ssh_public_key.as_deref(),
            req.ttl_seconds,
        ) {
            Ok(resp) => {
                let _ = crate::audit_log::append_audit_event(
                    &base_dir.join("audit.jsonl"),
                    &claims.subject,
                    "user.ssh_cert",
                    &claims.subject,
                    "ok",
                    serde_json::json!({ "ttl_seconds": resp.ttl_seconds }),
                );
                let json = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                write_http_json(stream, 400, "Bad Request", &msg).await
            }
        };
    }

    if method == "GET" && (path == "/v1/users" || path == "/v1/groups" || path == "/v1/ous") {
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
            .any(|c| c == "directory:read" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks directory:read or domain:admin capability"}"#,
            )
            .await;
        }
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let users_path = base_dir.join("users.json");
        let dir = crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
            .unwrap_or_default();
        let json = if path == "/v1/users" {
            let users: Vec<&sb_core::identity::DomainUser> = dir.users.values().collect();
            serde_json::json!({ "domain": dir.domain, "users": users }).to_string()
        } else if path == "/v1/groups" {
            let groups: Vec<&sb_core::identity::DomainGroup> = dir.groups.values().collect();
            serde_json::json!({ "domain": dir.domain, "groups": groups }).to_string()
        } else {
            let ous: Vec<&crate::directory_users::OrganizationalUnit> = dir.ous.values().collect();
            serde_json::json!({ "domain": dir.domain, "ous": ous }).to_string()
        };
        return write_http_json(stream, 200, "OK", &json).await;
    }

    if method == "POST" && (path == "/v1/ous" || path == "/v1/groups") {
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
            .any(|c| c == "directory:write" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks directory:write or domain:admin capability"}"#,
            )
            .await;
        }
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let users_path = base_dir.join("users.json");
        let mut dir =
            match crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
            {
                Ok(d) => d,
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 500, "Internal Server Error", &msg).await;
                }
            };
        if path == "/v1/ous" {
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let ou_path = payload["path"].as_str().unwrap_or("/");
            let desc = payload["description"].as_str().unwrap_or("");
            return match dir.upsert_ou(ou_path, desc) {
                Ok(ou) => {
                    let _ = dir.save(&users_path);
                    let json = serde_json::to_string(&ou).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        } else {
            let group: sb_core::identity::DomainGroup = match serde_json::from_slice(&body) {
                Ok(g) => g,
                Err(e) => {
                    let msg = serde_json::json!({ "error": format!("Invalid group JSON: {e}") })
                        .to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            };
            return match dir.upsert_group(group) {
                Ok(g) => {
                    let _ = dir.save(&users_path);
                    let json = serde_json::to_string(&g).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    write_http_json(stream, 400, "Bad Request", &msg).await
                }
            };
        }
    }

    if method == "POST" && path.starts_with("/v1/users/") && path.ends_with("/ssh-cert") {
        let username = path
            .trim_start_matches("/v1/users/")
            .trim_end_matches("/ssh-cert");
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
        let is_admin = claims
            .capabilities
            .iter()
            .any(|c| c == "directory:admin" || c == "domain:admin");
        if !is_admin && claims.subject != username {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"forbidden: only the user or directory:admin may issue user SSH certificates"}"#,
            )
            .await;
        }
        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let req: sb_core::identity::SshUserCertRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                let msg = serde_json::json!({ "error": format!("Invalid JSON: {e}") }).to_string();
                return write_http_json(stream, 400, "Bad Request", &msg).await;
            }
        };
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let users_path = base_dir.join("users.json");
        let dir =
            match crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
            {
                Ok(d) => d,
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 500, "Internal Server Error", &msg).await;
                }
            };
        return match dir.issue_user_ssh_cert(
            username,
            req.ssh_public_key.as_deref(),
            req.ttl_seconds,
        ) {
            Ok(resp) => {
                let json = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
                write_http_json(stream, 200, "OK", &json).await
            }
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                write_http_json(stream, 400, "Bad Request", &msg).await
            }
        };
    }

    if (method == "PUT" || method == "DELETE") && path.starts_with("/v1/users/") {
        let username = path.trim_start_matches("/v1/users/");
        let token_opt = extract_bearer_token(&header_lines).or_else(|| {
            if path.ends_with("/ws") {
                query_param(query, "token")
            } else {
                None
            }
        });
        let Some(token) = token_opt else {
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
            .any(|c| c == "directory:write" || c == "domain:admin")
        {
            return write_http_json(
                stream,
                403,
                "Forbidden",
                r#"{"error":"token lacks directory:write or domain:admin capability"}"#,
            )
            .await;
        }
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
        let users_path = base_dir.join("users.json");
        let mut dir =
            match crate::directory_users::IdentityDirectory::load_or_create(&users_path, &domain) {
                Ok(d) => d,
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 500, "Internal Server Error", &msg).await;
                }
            };

        if method == "DELETE" {
            match dir.delete_user(username) {
                Ok(true) => {
                    let _ = dir.save(&users_path);
                    let json = serde_json::json!({ "deleted": username }).to_string();
                    return write_http_json(stream, 200, "OK", &json).await;
                }
                Ok(false) => {
                    return write_http_json(
                        stream,
                        404,
                        "Not Found",
                        r#"{"error":"user not found"}"#,
                    )
                    .await;
                }
                Err(e) => {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 400, "Bad Request", &msg).await;
                }
            }
        }

        let body =
            match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines).await? {
                Some(b) => b,
                None => return Ok(()),
            };
        let user: sb_core::identity::DomainUser = match serde_json::from_slice(&body) {
            Ok(u) => u,
            Err(e) => {
                let msg = serde_json::json!({ "error": format!("Invalid DomainUser JSON: {e}") })
                    .to_string();
                return write_http_json(stream, 400, "Bad Request", &msg).await;
            }
        };
        if user.username != username {
            return write_http_json(
                stream,
                400,
                "Bad Request",
                r#"{"error":"body username does not match URL path"}"#,
            )
            .await;
        }
        match dir.upsert_user(user) {
            Ok(saved) => {
                if let Err(e) = dir.save(&users_path) {
                    let msg = serde_json::json!({ "error": e }).to_string();
                    return write_http_json(stream, 500, "Internal Server Error", &msg).await;
                }
                let _ = crate::audit_log::append_audit_event(
                    &base_dir.join("audit.jsonl"),
                    &claims.subject,
                    "user.upsert",
                    &saved.username,
                    "ok",
                    serde_json::json!({ "groups": saved.groups }),
                );
                let json = serde_json::to_string(&saved).map_err(|e| e.to_string())?;
                return write_http_json(stream, 200, "OK", &json).await;
            }
            Err(e) => {
                let msg = serde_json::json!({ "error": e }).to_string();
                return write_http_json(stream, 400, "Bad Request", &msg).await;
            }
        }
    }

    if (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/ssh/session"))
        || (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/os-auth"))
        || (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/ssh/pty"))
        || (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/files/list"))
        || (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/files/read"))
        || (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/files/write"))
        || (method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/tunnel/open"))
        || (method == "GET" && path.starts_with("/v1/machines/") && path.ends_with("/relay/poll"))
        || (method == "POST"
            && path.starts_with("/v1/machines/")
            && path.ends_with("/relay/result"))
        || (path.starts_with("/v1/machines/") && path.contains("/relay/tunnel/"))
        || (path.starts_with("/v1/machines/") && path.contains("/relay/pty/"))
        || path.starts_with("/v1/ssh/sessions/")
        || path.starts_with("/v1/ssh/pty/")
        || path.starts_with("/v1/tunnels/")
    {
        let claims = if method == "GET" && path.starts_with("/v1/ssh/pty/") && path.ends_with("/ws")
        {
            if let Some(ticket) = query_param(query, "ticket") {
                let pid = path
                    .trim_start_matches("/v1/ssh/pty/")
                    .trim_end_matches("/ws");
                match crate::web_ssh::consume_pty_ws_ticket(ticket, pid).await {
                    Ok(c) => c,
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        return write_http_json(stream, code, "Unauthorized", &msg).await;
                    }
                }
            } else {
                return write_http_json(
                    stream,
                    401,
                    "Unauthorized",
                    r#"{"error":"missing single-use websocket ticket"}"#,
                )
                .await;
            }
        } else {
            let Some(token) = extract_bearer_token(&header_lines) else {
                return write_http_json(
                    stream,
                    401,
                    "Unauthorized",
                    r#"{"error":"missing bearer token"}"#,
                )
                .await;
            };
            match verifier.verify_token(token) {
                Ok(c) => c,
                Err(e) => {
                    let msg = serde_json::json!({ "error": format!("authentication failed: {e}") })
                        .to_string();
                    return write_http_json(stream, 401, "Unauthorized", &msg).await;
                }
            }
        };
        let base_dir = registry_path
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(local_domain_dir);
        let audit_path = base_dir.join("audit.jsonl");

        if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/os-auth") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/os-auth");
            if !claims.has_capability("domain:join") && !claims.has_role("admin") {
                return write_problem_json(
                    stream,
                    403,
                    "Forbidden",
                    "missing-capability",
                    "Forbidden",
                    "token lacks domain:join or admin",
                    path,
                )
                .await;
            }
            // [SECURITY-HYPOTHESIS] CWE-639 (IDOR): Machine A could query /os-auth for Machine B
            // to bypass allowed_machines restrictions or harvest offline verifiers.
            // [SECURITY-VERIFIED] Enforces claims.sub == machine_id unless caller is domain admin.
            if claims.subject != machine_id
                && !claims.has_role("admin")
                && !claims.has_capability("domain:admin")
            {
                return write_problem_json(
                    stream,
                    403,
                    "Forbidden",
                    "machine-id-mismatch",
                    "Forbidden",
                    "token subject does not match target machine_id",
                    path,
                )
                .await;
            }
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let username = payload["username"].as_str().unwrap_or("").trim();
            let password = payload["password"].as_str().unwrap_or("");
            if let Some(retry_secs) = check_login_lockout(username).await {
                let detail =
                    format!("Zu viele Fehlversuche. Bitte in {retry_secs}s erneut versuchen.");
                return write_problem_json(
                    stream,
                    429,
                    "Too Many Requests",
                    "login-rate-limited",
                    "Too Many Requests",
                    &detail,
                    path,
                )
                .await;
            }
            let creds = crate::oidc::CredentialStore::load(&base_dir.join("credentials.json"))
                .unwrap_or_default();
            if !creds.verify(username, password) {
                let _ = record_login_failure(username).await;
                let _ = crate::audit_log::append_audit_event(
                    &audit_path,
                    username,
                    "os.login",
                    machine_id,
                    "denied",
                    serde_json::json!({ "reason": "invalid_credentials" }),
                );
                return write_problem_json(
                    stream,
                    401,
                    "Unauthorized",
                    "invalid-credentials",
                    "Unauthorized",
                    "Benutzername oder Passwort ungültig",
                    path,
                )
                .await;
            }
            clear_login_failures(username).await;

            let reg_file = registry_path
                .map(PathBuf::from)
                .unwrap_or_else(|| local_domain_dir().join("machines.json"));
            let reg: DomainRegistry = fs::read_to_string(&reg_file)
                .ok()
                .and_then(|r| serde_json::from_str(&r).ok())
                .unwrap_or_default();
            let Some(machine) = reg
                .machines
                .iter()
                .find(|m| m.machine_id == machine_id && !m.revoked)
            else {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"Maschine unbekannt oder widerrufen"}"#,
                )
                .await;
            };
            let users_path = base_dir.join("users.json");
            let dir =
                crate::directory_users::IdentityDirectory::load_or_create(&users_path, &reg.domain)
                    .unwrap_or_default();
            return match dir.evaluate_machine_login(username, machine_id, &machine.fqdn) {
                Ok((user, is_local_admin)) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &user.username,
                        "os.login",
                        machine_id,
                        "ok",
                        serde_json::json!({
                            "fqdn": machine.fqdn,
                            "is_local_admin": is_local_admin,
                            "ou": user.ou,
                        }),
                    );
                    let verifier_hash = creds.hashes.get(&user.username).cloned();
                    let json = serde_json::json!({
                        "allowed": true,
                        "username": user.username,
                        "display_name": user.display_name,
                        "ou": user.ou,
                        "groups": user.groups,
                        "is_local_admin": is_local_admin,
                        "offline_verifier": verifier_hash,
                    })
                    .to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err(err) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        username,
                        "os.login",
                        machine_id,
                        "denied",
                        serde_json::json!({ "reason": err }),
                    );
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(stream, 403, "Forbidden", &msg).await
                }
            };
        }

        if method == "GET" && path.starts_with("/v1/machines/") && path.ends_with("/relay/poll") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/relay/poll");
            if !claims.has_capability("domain:join") && !claims.has_role("admin") {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks domain:join or admin"}"#,
                )
                .await;
            }
            let wait_secs: u64 = query_param(query, "wait")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(20)
                .min(25);
            let cmd = crate::web_ssh::poll_relay_command(machine_id, wait_secs).await;
            let json = serde_json::json!({ "command": cmd }).to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/relay/result")
        {
            if !claims.has_capability("domain:join") && !claims.has_role("admin") {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks domain:join or admin"}"#,
                )
                .await;
            }
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let cmd_id = payload.get("cmd_id").and_then(|v| v.as_str()).unwrap_or("");
            let result = crate::web_ssh::WebSshExecResult {
                exit_code: payload
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(-1) as i32,
                stdout: payload
                    .get("stdout")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                stderr: payload
                    .get("stderr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                cwd: payload
                    .get("cwd")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            let recorded = crate::web_ssh::submit_relay_result(cmd_id, result).await;
            let json = serde_json::json!({ "recorded": recorded }).to_string();
            return write_http_json(stream, 200, "OK", &json).await;
        }

        if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/ssh/session") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/ssh/session");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let ssh_user = payload.get("ssh_user").and_then(|v| v.as_str());
            return match crate::web_ssh::open_web_ssh_session(
                &claims, machine_id, ssh_user, &base_dir,
            )
            .await
            {
                Ok(info) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "ssh.web_session_open",
                        machine_id,
                        "ok",
                        serde_json::json!({
                            "session_id": info.session_id,
                            "ssh_user": info.ssh_user,
                            "mesh_ip": info.mesh_ip,
                        }),
                    );
                    let json = serde_json::to_string(&info).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err((code, err)) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "ssh.web_session_open",
                        machine_id,
                        "denied",
                        serde_json::json!({ "error": err }),
                    );
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(
                        stream,
                        code,
                        if code == 403 { "Forbidden" } else { "Error" },
                        &msg,
                    )
                    .await
                }
            };
        }

        if method == "POST" && path.starts_with("/v1/ssh/sessions/") && path.ends_with("/exec") {
            let sid = path
                .trim_start_matches("/v1/ssh/sessions/")
                .trim_end_matches("/exec");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let command = payload
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            return match crate::web_ssh::exec_web_ssh_command(&claims, sid, command).await {
                Ok(res) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "ssh.web_exec",
                        sid,
                        "ok",
                        serde_json::json!({ "exit_code": res.exit_code }),
                    );
                    let json = serde_json::to_string(&res).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err((code, err)) => {
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(stream, code, "Error", &msg).await
                }
            };
        }

        if method == "DELETE" && path.starts_with("/v1/ssh/sessions/") {
            let sid = path.trim_start_matches("/v1/ssh/sessions/");
            return match crate::web_ssh::close_web_ssh_session(&claims, sid).await {
                Ok(closed) => {
                    let json = serde_json::json!({ "closed": closed }).to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err((code, err)) => {
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(stream, code, "Error", &msg).await
                }
            };
        }

        if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/ssh/pty") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/ssh/pty");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let ssh_user = payload.get("ssh_user").and_then(|v| v.as_str());
            let cols = payload
                .get("cols")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())
                .unwrap_or(100);
            let rows = payload
                .get("rows")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())
                .unwrap_or(30);
            return match crate::web_ssh::open_pty_session(
                &claims, machine_id, ssh_user, cols, rows, &base_dir,
            )
            .await
            {
                Ok(info) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "ssh.pty_open",
                        machine_id,
                        "ok",
                        serde_json::json!({
                            "pty_id": info.pty_id,
                            "ssh_user": info.ssh_user,
                            "cols": info.cols,
                            "rows": info.rows,
                        }),
                    );
                    let json = serde_json::to_string(&info).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err((code, err)) => {
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(
                        stream,
                        code,
                        if code == 403 { "Forbidden" } else { "Error" },
                        &msg,
                    )
                    .await
                }
            };
        }

        if method == "POST"
            && path.starts_with("/v1/machines/")
            && (path.ends_with("/files/list")
                || path.ends_with("/files/read")
                || path.ends_with("/files/write"))
        {
            let (machine_id, kind) = if let Some(m) = path.strip_suffix("/files/list") {
                (m.trim_start_matches("/v1/machines/"), "file_list")
            } else if let Some(m) = path.strip_suffix("/files/read") {
                (m.trim_start_matches("/v1/machines/"), "file_read")
            } else {
                let m = path.strip_suffix("/files/write").unwrap_or("");
                (m.trim_start_matches("/v1/machines/"), "file_write")
            };
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let body_str = String::from_utf8_lossy(&body).into_owned();
            return match crate::web_ssh::exec_relay_file_op(
                &claims, machine_id, kind, &body_str, &base_dir,
            )
            .await
            {
                Ok(val) => {
                    let json = val.to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err((code, err)) => {
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(stream, code, "Error", &msg).await
                }
            };
        }

        if path.starts_with("/v1/ssh/pty/") {
            let tail = path.trim_start_matches("/v1/ssh/pty/");
            if method == "POST" && tail.ends_with("/ticket") {
                let pid = tail.trim_end_matches("/ticket");
                return match crate::web_ssh::issue_pty_ws_ticket(&claims, pid).await {
                    Ok(ticket) => {
                        let json = serde_json::json!({ "ticket": ticket }).to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
            if method == "GET" && tail.ends_with("/ws") {
                let pid = tail.trim_end_matches("/ws");
                return handle_browser_pty_ws(stream, &header_lines, &claims, pid).await;
            }
            if method == "POST" && tail.ends_with("/input") {
                let pid = tail.trim_end_matches("/input");
                let body =
                    match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                        .await?
                    {
                        Some(b) => b,
                        None => return Ok(()),
                    };
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let data_b64 = payload
                    .get("data_b64")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let bytes = if data_b64.is_empty() {
                    Vec::new()
                } else {
                    match base64::engine::general_purpose::STANDARD.decode(data_b64) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg =
                                serde_json::json!({ "error": format!("invalid base64: {e}") })
                                    .to_string();
                            return write_http_json(stream, 400, "Bad Request", &msg).await;
                        }
                    }
                };
                let resize = match (
                    payload
                        .get("cols")
                        .and_then(|v| v.as_u64())
                        .and_then(|n| u16::try_from(n).ok()),
                    payload
                        .get("rows")
                        .and_then(|v| v.as_u64())
                        .and_then(|n| u16::try_from(n).ok()),
                ) {
                    (Some(c), Some(r)) => Some((c, r)),
                    _ => None,
                };
                let close = payload
                    .get("close")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                return match crate::web_ssh::push_pty_input(&claims, pid, bytes, resize, close)
                    .await
                {
                    Ok(()) => write_http_json(stream, 200, "OK", r#"{"ok":true}"#).await,
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
            if method == "GET" && tail.ends_with("/output") {
                let pid = tail.trim_end_matches("/output");
                let wait_secs = query_param(query, "wait")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(15)
                    .min(25);
                return match crate::web_ssh::pull_pty_output(&claims, pid, wait_secs).await {
                    Ok((data, closed)) => {
                        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                        let json = serde_json::json!({
                            "data_b64": data_b64,
                            "closed": closed,
                        })
                        .to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
            if method == "DELETE" && !tail.contains('/') {
                return match crate::web_ssh::close_pty_session(&claims, tail).await {
                    Ok(closed) => {
                        let json = serde_json::json!({ "closed": closed }).to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
        }

        if path.starts_with("/v1/machines/") && path.contains("/relay/pty/") {
            let rest = path.trim_start_matches("/v1/machines/");
            let Some((_machine_id, tail)) = rest.split_once("/relay/pty/") else {
                return write_http_json(stream, 404, "Not Found", r#"{"error":"not found"}"#).await;
            };
            if !claims.has_capability("domain:join") && !claims.has_role("admin") {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks domain:join or admin"}"#,
                )
                .await;
            }
            if method == "GET" && tail.ends_with("/ws") {
                let pid = tail.trim_end_matches("/ws");
                return handle_agent_pty_ws(stream, &header_lines, &claims, pid).await;
            }
            if method == "POST" && tail.ends_with("/output") {
                let pid = tail.trim_end_matches("/output");
                let body =
                    match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                        .await?
                    {
                        Some(b) => b,
                        None => return Ok(()),
                    };
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let data_b64 = payload
                    .get("data_b64")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let eof = payload
                    .get("eof")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let bytes = if data_b64.is_empty() {
                    Vec::new()
                } else {
                    base64::engine::general_purpose::STANDARD
                        .decode(data_b64)
                        .unwrap_or_default()
                };
                return match crate::web_ssh::push_pty_output(&claims, pid, bytes, eof).await {
                    Ok(()) => write_http_json(stream, 200, "OK", r#"{"ok":true}"#).await,
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
            if method == "GET" && tail.ends_with("/input") {
                let pid = tail.trim_end_matches("/input");
                let wait_secs = query_param(query, "wait")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(15)
                    .min(25);
                return match crate::web_ssh::pull_pty_input(&claims, pid, wait_secs).await {
                    Ok((data, resize, closed)) => {
                        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                        let resize_json =
                            resize.map(|(c, r)| serde_json::json!({ "cols": c, "rows": r }));
                        let json = serde_json::json!({
                            "data_b64": data_b64,
                            "resize": resize_json,
                            "closed": closed,
                        })
                        .to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
        }

        if method == "POST" && path.starts_with("/v1/machines/") && path.ends_with("/tunnel/open") {
            let machine_id = path
                .trim_start_matches("/v1/machines/")
                .trim_end_matches("/tunnel/open");
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let target_port = payload
                .get("target_port")
                .and_then(|v| v.as_u64())
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(0);
            return match crate::web_ssh::open_relay_tunnel(
                &claims,
                machine_id,
                target_port,
                &base_dir,
            )
            .await
            {
                Ok(info) => {
                    let _ = crate::audit_log::append_audit_event(
                        &audit_path,
                        &claims.subject,
                        "tunnel.open",
                        machine_id,
                        "ok",
                        serde_json::json!({
                            "tunnel_id": info.tunnel_id,
                            "target_port": info.target_port,
                        }),
                    );
                    let json = serde_json::to_string(&info).map_err(|e| e.to_string())?;
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err((code, err)) => {
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(
                        stream,
                        code,
                        if code == 403 { "Forbidden" } else { "Error" },
                        &msg,
                    )
                    .await
                }
            };
        }

        if method == "POST"
            && path.starts_with("/v1/machines/")
            && (path.ends_with("/files/list")
                || path.ends_with("/files/read")
                || path.ends_with("/files/write"))
        {
            let (machine_id, kind) = if let Some(m) = path.strip_suffix("/files/list") {
                (m.trim_start_matches("/v1/machines/"), "file_list")
            } else if let Some(m) = path.strip_suffix("/files/read") {
                (m.trim_start_matches("/v1/machines/"), "file_read")
            } else {
                let m = path.strip_suffix("/files/write").unwrap_or("");
                (m.trim_start_matches("/v1/machines/"), "file_write")
            };
            let body = match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                .await?
            {
                Some(b) => b,
                None => return Ok(()),
            };
            let body_str = String::from_utf8_lossy(&body).into_owned();
            return match crate::web_ssh::exec_relay_file_op(
                &claims, machine_id, kind, &body_str, &base_dir,
            )
            .await
            {
                Ok(val) => {
                    let json = val.to_string();
                    write_http_json(stream, 200, "OK", &json).await
                }
                Err((code, err)) => {
                    let msg = serde_json::json!({ "error": err }).to_string();
                    write_http_json(stream, code, "Error", &msg).await
                }
            };
        }

        if path.starts_with("/v1/machines/") && path.contains("/relay/tunnel/") {
            let rest = path.trim_start_matches("/v1/machines/");
            let Some((_machine_id, tail)) = rest.split_once("/relay/tunnel/") else {
                return write_http_json(stream, 404, "Not Found", r#"{"error":"not found"}"#).await;
            };
            if !claims.has_capability("domain:join") && !claims.has_role("admin") {
                return write_http_json(
                    stream,
                    403,
                    "Forbidden",
                    r#"{"error":"token lacks domain:join or admin"}"#,
                )
                .await;
            }
            if method == "POST" && tail.ends_with("/push") {
                let tid = tail.trim_end_matches("/push");
                let body =
                    match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                        .await?
                    {
                        Some(b) => b,
                        None => return Ok(()),
                    };
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let data_b64 = payload
                    .get("data_b64")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let eof = payload
                    .get("eof")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data_b64)
                    .map_err(|e| format!("invalid base64: {e}"))
                    .unwrap_or_default();
                return match crate::web_ssh::push_tunnel_data(&claims, tid, true, bytes, eof).await
                {
                    Ok(()) => write_http_json(stream, 200, "OK", r#"{"ok":true}"#).await,
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
            if method == "GET" && tail.ends_with("/pull") {
                let tid = tail.trim_end_matches("/pull");
                let wait_secs = query_param(query, "wait")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(15)
                    .min(25);
                return match crate::web_ssh::pull_tunnel_data(&claims, tid, true, wait_secs).await {
                    Ok((data, closed)) => {
                        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                        let json = serde_json::json!({
                            "data_b64": data_b64,
                            "closed": closed,
                        })
                        .to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
        }

        if path.starts_with("/v1/tunnels/") {
            let tail = path.trim_start_matches("/v1/tunnels/");
            if method == "POST" && tail.ends_with("/push") {
                let tid = tail.trim_end_matches("/push");
                let body =
                    match read_http_body(stream, &mut buf, &mut chunk, header_end, &header_lines)
                        .await?
                    {
                        Some(b) => b,
                        None => return Ok(()),
                    };
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let data_b64 = payload
                    .get("data_b64")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let eof = payload
                    .get("eof")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
                    Ok(b) => b,
                    Err(e) => {
                        let msg = serde_json::json!({ "error": format!("invalid base64: {e}") })
                            .to_string();
                        return write_http_json(stream, 400, "Bad Request", &msg).await;
                    }
                };
                return match crate::web_ssh::push_tunnel_data(&claims, tid, false, bytes, eof).await
                {
                    Ok(()) => write_http_json(stream, 200, "OK", r#"{"ok":true}"#).await,
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
            if method == "GET" && tail.ends_with("/pull") {
                let tid = tail.trim_end_matches("/pull");
                let wait_secs = query_param(query, "wait")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(15)
                    .min(25);
                return match crate::web_ssh::pull_tunnel_data(&claims, tid, false, wait_secs).await
                {
                    Ok((data, closed)) => {
                        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                        let json = serde_json::json!({
                            "data_b64": data_b64,
                            "closed": closed,
                        })
                        .to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
            if method == "DELETE" && !tail.contains('/') {
                return match crate::web_ssh::close_relay_tunnel(&claims, tail).await {
                    Ok(closed) => {
                        let json = serde_json::json!({ "closed": closed }).to_string();
                        write_http_json(stream, 200, "OK", &json).await
                    }
                    Err((code, err)) => {
                        let msg = serde_json::json!({ "error": err }).to_string();
                        write_http_json(stream, code, "Error", &msg).await
                    }
                };
            }
        }
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

/// Summary returned by 1-click user offboarding (`POST /v1/users/{username}/offboard`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffboardReport {
    pub username: String,
    pub user_disabled: bool,
    pub revoked_machines: Vec<String>,
    pub timestamp: String,
}

/// Atomically offboards a domain user: disables their account, revokes their joined machines,
/// and records a hash-chained `user.offboard` audit event.
pub fn offboard_user(
    username: &str,
    actor: &str,
    revoke_machines: bool,
    base_dir: Option<&Path>,
    registry_path: Option<&Path>,
) -> Result<OffboardReport, String> {
    let dir_root = base_dir.map(PathBuf::from).unwrap_or_else(local_domain_dir);
    let users_path = dir_root.join("users.json");
    let mut users_dir =
        crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")?;
    let disabled_user = users_dir.disable_user(username)?;
    users_dir.save(&users_path)?;

    let mut revoked_machines = Vec::new();
    if revoke_machines {
        let reg_file = registry_path
            .map(PathBuf::from)
            .unwrap_or_else(|| dir_root.join("machines.json"));
        if reg_file.exists() {
            if let Ok(raw) = fs::read_to_string(&reg_file) {
                if let Ok(mut reg) = serde_json::from_str::<DomainRegistry>(&raw) {
                    for m in &mut reg.machines {
                        if !m.revoked && m.joined_by == disabled_user.username {
                            m.revoked = true;
                            m.revoked_reason =
                                Some(format!("User {} offboarded", disabled_user.username));
                            revoked_machines.push(m.fqdn.clone());
                        }
                    }
                    let _ = reg.save_to_path(&reg_file);
                }
            }
        }
    }

    let audit_path = dir_root.join("audit.jsonl");
    let rbac_path = dir_root.join("rbac.json");
    if let Ok(mut rbac_store) = crate::rbac::RbacStore::load(&rbac_path) {
        if rbac_store.revoke_user_elevations(&disabled_user.username) > 0 {
            let _ = rbac_store.save(&rbac_path);
        }
    }
    let _ = crate::audit_log::append_audit_event(
        &audit_path,
        actor,
        "user.offboard",
        &disabled_user.username,
        "ok",
        serde_json::json!({
            "revoke_machines": revoke_machines,
            "revoked_machines": revoked_machines,
        }),
    );
    revocation_hub().publish(crate::dc_discovery::RevocationEvent::user_offboarded(
        &disabled_user.username,
        &users_dir.domain,
    ));

    Ok(OffboardReport {
        username: disabled_user.username,
        user_disabled: true,
        revoked_machines,
        timestamp: Utc::now().to_rfc3339(),
    })
}

pub(crate) fn session_tokens_json(tokens: &sb_auth::SessionTokens) -> String {
    serde_json::json!({
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at,
    })
    .to_string()
}

pub(crate) fn load_local_auth_engine() -> Result<sb_auth::AuthEngine, String> {
    let auth_dir = sb_core::paths::sb_home().join("auth");
    let key_b64 = fs::read_to_string(auth_dir.join("auth.key"))
        .map_err(|e| format!("Missing auth.key: {e}"))?;
    let keypair = sb_auth::crypto::Keypair::from_secret_base64(key_b64.trim())
        .map_err(|e| format!("Invalid auth.key: {e}"))?;
    let rev_store = sb_auth::FileRevocationStore::open(auth_dir.join("revocations.json"))
        .map_err(|e| format!("Revocation store error: {e}"))?;
    Ok(sb_auth::AuthEngine::new(keypair, Arc::new(rev_store)))
}

async fn write_problem_json(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    type_slug: &str,
    title: &str,
    detail: &str,
    instance: &str,
) -> Result<(), String> {
    let body = serde_json::json!({
        "type": format!("https://console.skulls-and-bones.org/problems/{type_slug}"),
        "title": title,
        "status": code,
        "detail": detail,
        "instance": instance,
        "error": detail,
    })
    .to_string();
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("Write error: {e}"))
}

pub(crate) async fn write_http_json(
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

pub(crate) fn extract_bearer_token<'a>(headers: &[&'a str]) -> Option<&'a str> {
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

pub(crate) async fn read_http_body(
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

async fn read_http_response_from_stream<S>(mut stream: S, http_req: &str) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
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

/// Sends an HTTP/1.1 or HTTPS (TLS 1.2/1.3) request to `endpoint` (`https://host`, `http://host:port`, or `host:port`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** MITM interception of domain-join tokens or signed policy bundles
///   over the public internet.
/// - **CVE / CWE Mapping:** CWE-295 (Improper Certificate Validation), CWE-319 (Cleartext
///   Transmission of Sensitive Information).
/// - **Likelihood & Exploitability:** High (8/10) for remote Mobile/Homeoffice joins.
/// - **Applied Mitigation:** Uses `tokio-rustls` with `webpki-roots` for full X.509 PKI
///   certificate verification and SNI on `https://` endpoints.
pub async fn send_endpoint_request(
    endpoint: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Vec<u8>, String> {
    send_endpoint_request_with_bearer(endpoint, method, path, body, None).await
}

/// Sends an HTTP/1.1 or HTTPS (TLS 1.3 WebPKI) request with optional Bearer token.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Header injection (`\r`/`\n`) via untrusted bearer token.
/// - **CVE / CWE Mapping:** CWE-113 (HTTP Response/Request Splitting).
/// - **Likelihood & Exploitability:** Medium (5/10).
/// - **Applied Mitigation:** Rejects `\r`, `\n`, and NUL in bearer tokens before constructing
///   the `Authorization` header.
pub async fn send_endpoint_request_with_bearer(
    endpoint: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    bearer_token: Option<&str>,
) -> Result<Vec<u8>, String> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let (use_tls, authority) = if let Some(rest) = trimmed.strip_prefix("https://") {
        (true, rest.split('/').next().unwrap_or(rest))
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        (false, rest.split('/').next().unwrap_or(rest))
    } else {
        (false, trimmed)
    };

    let (host, port) = if authority.starts_with('[') {
        // IPv6 [::1]:port
        if let Some((h, p)) = authority.rsplit_once("]:") {
            (
                format!("{h}]"),
                p.parse::<u16>().map_err(|_| "Invalid port".to_string())?,
            )
        } else {
            (authority.to_string(), if use_tls { 443 } else { 8443 })
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (
            h.to_string(),
            p.parse::<u16>().map_err(|_| "Invalid port".to_string())?,
        )
    } else {
        (authority.to_string(), if use_tls { 443 } else { 8443 })
    };

    let mut http_req =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    if let Some(tok) = bearer_token {
        let clean = tok.trim();
        if clean.contains('\r') || clean.contains('\n') || clean.contains('\0') {
            return Err("Invalid bearer token characters".into());
        }
        http_req.push_str(&format!("Authorization: Bearer {clean}\r\n"));
    }
    if let Some(b) = body {
        http_req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            b.len(),
            b
        ));
    } else {
        http_req.push_str("\r\n");
    }

    let addr_str = format!("{host}:{port}");
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr_str),
    )
    .await
    .map_err(|_| format!("Timed out connecting to Domain Controller {addr_str}"))?
    .map_err(|e| format!("Failed to connect to Domain Controller {addr_str}: {e}"))?;

    if use_tls {
        static TLS_CONNECTOR: std::sync::OnceLock<tokio_rustls::TlsConnector> =
            std::sync::OnceLock::new();
        let connector = TLS_CONNECTOR
            .get_or_init(|| {
                let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let tls_cfg = Arc::new(
                    tokio_rustls::rustls::ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth(),
                );
                tokio_rustls::TlsConnector::from(tls_cfg)
            })
            .clone();
        let server_name = rustls_pki_types::ServerName::try_from(host.clone())
            .map_err(|e| format!("Invalid TLS server name '{host}': {e}"))?;
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS handshake with '{host}' failed: {e}"))?;
        read_http_response_from_stream(tls_stream, &http_req).await
    } else {
        read_http_response_from_stream(tcp, &http_req).await
    }
}

/// Sends a `DomainJoinRequest` to a remote Domain Controller (`https://host` or `host:port`).
pub async fn send_remote_join_request(
    dc_endpoint: &str,
    req: &DomainJoinRequest,
) -> Result<DomainJoinResponse, String> {
    let body = serde_json::to_string(req).map_err(|e| format!("Serialize error: {e}"))?;
    let resp_body =
        send_endpoint_request(dc_endpoint, "POST", "/v1/machines/join", Some(&body)).await?;
    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("Failed to parse DomainJoinResponse: {e}"))
}

/// Fetches the latest signed GPO bundle from a remote Domain Controller (`GET /v1/policies/bundle`).
pub async fn fetch_remote_policy_bundle(
    dc_endpoint: &str,
) -> Result<sb_core::policy::SignedPolicyBundle, String> {
    let resp_body = send_endpoint_request(dc_endpoint, "GET", "/v1/policies/bundle", None).await?;
    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("Failed to parse SignedPolicyBundle: {e}"))
}

/// Posts a machine compliance heartbeat (GPO revision, LAPS rotation timestamp, service state)
/// to `POST /v1/machines/<machine_id>/heartbeat` and returns pending remote actions.
pub async fn send_remote_heartbeat(
    dc_endpoint: &str,
    bearer_token: &str,
    hb: &crate::fleet::MachineHeartbeat,
) -> Result<Vec<String>, String> {
    let body = serde_json::to_string(hb).map_err(|e| format!("Serialize heartbeat error: {e}"))?;
    let path = format!("/v1/machines/{}/heartbeat", hb.machine_id);
    let resp_bytes = send_endpoint_request_with_bearer(
        dc_endpoint,
        "POST",
        &path,
        Some(&body),
        Some(bearer_token),
    )
    .await?;
    let val: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap_or_default();
    let actions = val
        .get("actions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(actions)
}

/// Uploads a newly rotated LAPS password to the Domain Controller (`PUT /v1/machines/<id>/laps`)
/// so admins can reveal it from the Web Console.
pub async fn upload_rotated_laps_to_dc(
    dc_endpoint: &str,
    bearer_token: &str,
    machine_id: &str,
    local_account: &str,
    password: &str,
    passphrase: &str,
    ttl_days: i64,
) -> Result<(), String> {
    let path = format!("/v1/machines/{machine_id}/laps");
    let body = serde_json::json!({
        "local_account": local_account,
        "password": password,
        "passphrase": passphrase,
        "ttl_days": ttl_days,
    })
    .to_string();
    send_endpoint_request_with_bearer(dc_endpoint, "PUT", &path, Some(&body), Some(bearer_token))
        .await?;
    Ok(())
}

/// Long-polls the DC for a queued Web SSH relay command (`GET /v1/machines/<id>/relay/poll`).
pub async fn poll_remote_relay_command(
    dc_endpoint: &str,
    bearer_token: &str,
    machine_id: &str,
    wait_secs: u64,
) -> Result<Option<crate::web_ssh::RelayCommand>, String> {
    let path = format!("/v1/machines/{machine_id}/relay/poll?wait={wait_secs}");
    let bytes =
        send_endpoint_request_with_bearer(dc_endpoint, "GET", &path, None, Some(bearer_token))
            .await?;
    let val: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid relay poll response: {e}"))?;
    match val.get("command") {
        Some(v) if !v.is_null() => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|e| format!("Invalid relay command JSON: {e}")),
        _ => Ok(None),
    }
}

/// Posts the local execution result of a relayed command back to the DC.
pub async fn post_remote_relay_result(
    dc_endpoint: &str,
    bearer_token: &str,
    machine_id: &str,
    cmd_id: &str,
    result: &crate::web_ssh::WebSshExecResult,
) -> Result<(), String> {
    let path = format!("/v1/machines/{machine_id}/relay/result");
    let body = serde_json::json!({
        "cmd_id": cmd_id,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "cwd": result.cwd,
    })
    .to_string();
    send_endpoint_request_with_bearer(dc_endpoint, "POST", &path, Some(&body), Some(bearer_token))
        .await?;
    Ok(())
}

/// Pushes TCP payload bytes from the agent to the DC tunnel buffer.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Unauthenticated or cross-machine tunnel injection.
/// - **CWE Mapping:** CWE-284 (Improper Access Control).
/// - **Likelihood & Exploitability:** Low (2/10); requires valid `machine:<id>` bearer token.
/// - **Applied Mitigation:** Authenticates via short-lived `machine.key` bearer token and TLS.
pub async fn agent_push_tunnel_data(
    dc_endpoint: &str,
    bearer_token: &str,
    machine_id: &str,
    tunnel_id: &str,
    data: &[u8],
    eof: bool,
) -> Result<(), String> {
    let path = format!("/v1/machines/{machine_id}/relay/tunnel/{tunnel_id}/push");
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let body = serde_json::json!({
        "data_b64": data_b64,
        "eof": eof,
    })
    .to_string();
    send_endpoint_request_with_bearer(dc_endpoint, "POST", &path, Some(&body), Some(bearer_token))
        .await?;
    Ok(())
}

/// Pulls client->agent TCP payload bytes from the DC tunnel buffer.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Cross-machine data snooping or unbounded long-poll blocking.
/// - **CWE Mapping:** CWE-284 (Improper Access Control), CWE-400 (Resource Consumption).
/// - **Likelihood & Exploitability:** Low (2/10); requires valid `machine:<id>` bearer token.
/// - **Applied Mitigation:** Server clamps `wait` and enforces `machine:<id>` subject check.
pub async fn agent_pull_tunnel_data(
    dc_endpoint: &str,
    bearer_token: &str,
    machine_id: &str,
    tunnel_id: &str,
    wait_secs: u64,
) -> Result<(Vec<u8>, bool), String> {
    let path = format!("/v1/machines/{machine_id}/relay/tunnel/{tunnel_id}/pull?wait={wait_secs}");
    let bytes =
        send_endpoint_request_with_bearer(dc_endpoint, "GET", &path, None, Some(bearer_token))
            .await?;
    let val: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid tunnel pull response: {e}"))?;
    let data_b64 = val.get("data_b64").and_then(|v| v.as_str()).unwrap_or("");
    let closed = val.get("closed").and_then(|v| v.as_bool()).unwrap_or(false);
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| format!("Invalid tunnel base64: {e}"))?;
    Ok((data, closed))
}

/// Pushes raw PTY stdout/stderr bytes from the agent to the DC buffer.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Cross-machine PTY output injection.
/// - **CWE Mapping:** CWE-284 (Improper Access Control).
/// - **Likelihood & Exploitability:** Low (2/10); requires valid `machine:<id>` bearer token.
/// - **Applied Mitigation:** Authenticates via `machine.key` bearer token over TLS.
pub async fn agent_push_pty_output(
    dc_endpoint: &str,
    bearer_token: &str,
    machine_id: &str,
    pty_id: &str,
    data: &[u8],
    eof: bool,
) -> Result<(), String> {
    let path = format!("/v1/machines/{machine_id}/relay/pty/{pty_id}/output");
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let body = serde_json::json!({
        "data_b64": data_b64,
        "eof": eof,
    })
    .to_string();
    send_endpoint_request_with_bearer(dc_endpoint, "POST", &path, Some(&body), Some(bearer_token))
        .await?;
    Ok(())
}

/// Pulls queued browser keystrokes and resize events from the DC PTY buffer.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Cross-machine keystroke interception.
/// - **CWE Mapping:** CWE-284 (Improper Access Control).
/// - **Likelihood & Exploitability:** Low (2/10); requires valid `machine:<id>` bearer token.
/// - **Applied Mitigation:** Server enforces `machine:<id>` subject check and caps long-poll wait.
pub async fn agent_pull_pty_input(
    dc_endpoint: &str,
    bearer_token: &str,
    machine_id: &str,
    pty_id: &str,
    wait_secs: u64,
) -> Result<(Vec<u8>, Option<(u16, u16)>, bool), String> {
    let path = format!("/v1/machines/{machine_id}/relay/pty/{pty_id}/input?wait={wait_secs}");
    let bytes =
        send_endpoint_request_with_bearer(dc_endpoint, "GET", &path, None, Some(bearer_token))
            .await?;
    let val: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid PTY pull response: {e}"))?;
    let data_b64 = val.get("data_b64").and_then(|v| v.as_str()).unwrap_or("");
    let closed = val.get("closed").and_then(|v| v.as_bool()).unwrap_or(false);
    let resize = val.get("resize").and_then(|r| {
        let cols = r
            .get("cols")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())?;
        let rows = r
            .get("rows")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())?;
        Some((cols, rows))
    });
    let data = if data_b64.is_empty() {
        Vec::new()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| format!("Invalid PTY base64: {e}"))?
    };
    Ok((data, resize, closed))
}

#[allow(clippy::type_complexity)]
static LOGIN_FAILURES: std::sync::OnceLock<
    tokio::sync::RwLock<std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>,
> = std::sync::OnceLock::new();

fn login_failures() -> &'static tokio::sync::RwLock<
    std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>,
> {
    LOGIN_FAILURES.get_or_init(|| tokio::sync::RwLock::new(std::collections::HashMap::new()))
}

async fn check_login_lockout(username: &str) -> Option<i64> {
    let key = username.trim().to_ascii_lowercase();
    if key.is_empty() {
        return None;
    }
    let now = chrono::Utc::now();
    let mut guard = login_failures().write().await;
    guard.retain(|_, (_, until)| *until > now - chrono::Duration::minutes(10));
    if let Some((count, until)) = guard.get(&key) {
        if *count >= 5 && *until > now {
            return Some((*until - now).num_seconds().max(1));
        }
    }
    None
}

async fn record_login_failure(username: &str) -> bool {
    let key = username.trim().to_ascii_lowercase();
    if key.is_empty() {
        return false;
    }
    let now = chrono::Utc::now();
    let mut guard = login_failures().write().await;
    let entry = guard
        .entry(key)
        .or_insert((0, now + chrono::Duration::minutes(5)));
    if entry.1 <= now && entry.0 < 5 {
        entry.0 = 0;
    }
    entry.0 += 1;
    entry.1 = now + chrono::Duration::minutes(5);
    entry.0 >= 5
}

async fn clear_login_failures(username: &str) {
    let key = username.trim().to_ascii_lowercase();
    if !key.is_empty() {
        login_failures().write().await.remove(&key);
    }
}

/// Persistent HTTP/1.1 keep-alive client over TLS (or local TCP) for low-latency PTY streaming.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Cleartext credential leakage or unbounded response buffering on long-lived sockets.
/// - **CWE Mapping:** CWE-319 (Cleartext Transmission), CWE-400 (Resource Consumption).
/// - **Likelihood & Exploitability:** Low (2/10); uses pinned `webpki_roots` TLS 1.2/1.3 and bounded buffers.
/// - **Applied Mitigation:** Uses `cached_tls_connector()`, enforces 512 KiB max response size, and reconnects cleanly on EOF.
pub struct PersistentDcClient {
    #[allow(dead_code)]
    endpoint: String,
    use_tls: bool,
    host: String,
    port: u16,
    stream: Option<Box<dyn AsyncReadWriteUnpin + Send>>,
}

pub trait AsyncReadWriteUnpin: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> AsyncReadWriteUnpin for T {}

impl PersistentDcClient {
    pub fn new(endpoint: &str) -> Result<Self, String> {
        let trimmed = endpoint.trim().trim_end_matches('/');
        let (use_tls, authority) = if let Some(rest) = trimmed.strip_prefix("https://") {
            (true, rest.split('/').next().unwrap_or(rest))
        } else if let Some(rest) = trimmed.strip_prefix("http://") {
            (false, rest.split('/').next().unwrap_or(rest))
        } else {
            (false, trimmed)
        };
        let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
            (
                h.to_string(),
                p.parse::<u16>().map_err(|_| "Invalid port".to_string())?,
            )
        } else {
            (authority.to_string(), if use_tls { 443 } else { 8443 })
        };
        Ok(Self {
            endpoint: trimmed.to_string(),
            use_tls,
            host,
            port,
            stream: None,
        })
    }

    async fn ensure_connected(&mut self) -> Result<(), String> {
        if self.stream.is_some() {
            return Ok(());
        }
        let addr_str = format!("{}:{}", self.host, self.port);
        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&addr_str),
        )
        .await
        .map_err(|_| format!("Timed out connecting to {addr_str}"))?
        .map_err(|e| format!("Failed connecting to {addr_str}: {e}"))?;
        let _ = tcp.set_nodelay(true);

        if self.use_tls {
            static TLS_CONNECTOR: std::sync::OnceLock<tokio_rustls::TlsConnector> =
                std::sync::OnceLock::new();
            let connector = TLS_CONNECTOR
                .get_or_init(|| {
                    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    let tls_cfg = Arc::new(
                        tokio_rustls::rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth(),
                    );
                    tokio_rustls::TlsConnector::from(tls_cfg)
                })
                .clone();
            let server_name = rustls_pki_types::ServerName::try_from(self.host.clone())
                .map_err(|e| format!("Invalid TLS server name '{}': {e}", self.host))?;
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("TLS handshake failed: {e}"))?;
            self.stream = Some(Box::new(tls_stream));
        } else {
            self.stream = Some(Box::new(tcp));
        }
        Ok(())
    }

    pub async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
        bearer_token: &str,
    ) -> Result<Vec<u8>, String> {
        for attempt in 0..2 {
            self.ensure_connected().await?;
            let mut req = format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAuthorization: Bearer {bearer_token}\r\n",
                self.host
            );
            if let Some(b) = body {
                req.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}",
                    b.len()
                ));
            } else {
                req.push_str("\r\n");
            }

            let res = self.send_and_read_one(&req).await;
            match res {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    self.stream = None;
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }
        Err("Persistent DC request failed".to_string())
    }

    async fn send_and_read_one(&mut self, req: &str) -> Result<Vec<u8>, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let s = self.stream.as_mut().ok_or("not connected")?;
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write error: {e}"))?;
        s.flush().await.map_err(|e| format!("flush error: {e}"))?;

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos;
            }
            let n = s
                .read(&mut tmp)
                .await
                .map_err(|e| format!("read error: {e}"))?;
            if n == 0 {
                return Err("EOF before response headers".to_string());
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 32 * 1024 {
                return Err("Response headers too large".to_string());
            }
        };

        let header_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let status_line = header_str.lines().next().unwrap_or("").to_string();
        let mut content_len: Option<usize> = None;
        let mut close_after = false;
        let mut is_chunked = false;
        for line in header_str.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_len = v.trim().parse::<usize>().ok();
                } else if k.trim().eq_ignore_ascii_case("connection")
                    && v.trim().eq_ignore_ascii_case("close")
                {
                    close_after = true;
                } else if k.trim().eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
                {
                    is_chunked = true;
                }
            }
        }

        let body_start = header_end + 4;
        let body = if is_chunked {
            // Fall back to one-shot read for chunked responses and drop socket afterward.
            close_after = true;
            loop {
                let n = s.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 512 * 1024 {
                    break;
                }
            }
            decode_chunked_body(&buf[body_start..])
        } else if let Some(len) = content_len {
            if len > 512 * 1024 {
                return Err("DC response exceeded 512 KiB limit".to_string());
            }
            while buf.len() < body_start + len {
                let n = s
                    .read(&mut tmp)
                    .await
                    .map_err(|e| format!("read body: {e}"))?;
                if n == 0 {
                    return Err("EOF in response body".to_string());
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            buf[body_start..body_start + len].to_vec()
        } else {
            close_after = true;
            loop {
                let n = s.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 512 * 1024 {
                    break;
                }
            }
            buf[body_start..].to_vec()
        };

        if close_after {
            self.stream = None;
        }
        if !status_line.contains(" 200 ") && !status_line.contains(" 201 ") {
            let err_txt = String::from_utf8_lossy(&body);
            return Err(format!("DC rejected request ({status_line}): {err_txt}"));
        }
        Ok(body)
    }

    pub async fn push_pty_output(
        &mut self,
        bearer_token: &str,
        machine_id: &str,
        pty_id: &str,
        data: &[u8],
        eof: bool,
    ) -> Result<(), String> {
        let path = format!("/v1/machines/{machine_id}/relay/pty/{pty_id}/output");
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let body = serde_json::json!({
            "data_b64": data_b64,
            "eof": eof,
        })
        .to_string();
        self.request("POST", &path, Some(&body), bearer_token)
            .await?;
        Ok(())
    }

    pub async fn pull_pty_input(
        &mut self,
        bearer_token: &str,
        machine_id: &str,
        pty_id: &str,
        wait_secs: u64,
    ) -> Result<(Vec<u8>, Option<(u16, u16)>, bool), String> {
        let path = format!("/v1/machines/{machine_id}/relay/pty/{pty_id}/input?wait={wait_secs}");
        let bytes = self.request("GET", &path, None, bearer_token).await?;
        let val: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Invalid PTY pull response: {e}"))?;
        let data_b64 = val.get("data_b64").and_then(|v| v.as_str()).unwrap_or("");
        let closed = val.get("closed").and_then(|v| v.as_bool()).unwrap_or(false);
        let resize = val.get("resize").and_then(|r| {
            let cols = r
                .get("cols")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())?;
            let rows = r
                .get("rows")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())?;
            Some((cols, rows))
        });
        let data = if data_b64.is_empty() {
            Vec::new()
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(data_b64)
                .map_err(|e| format!("Invalid PTY base64: {e}"))?
        };
        Ok((data, resize, closed))
    }
}

fn decode_chunked_body(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
        let size_str = String::from_utf8_lossy(&raw[..pos]);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let Ok(sz) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        if sz == 0 {
            break;
        }
        let start = pos + 2;
        if raw.len() < start + sz + 2 {
            break;
        }
        out.extend_from_slice(&raw[start..start + sz]);
        raw = &raw[start + sz + 2..];
    }
    out
}

async fn upgrade_ws_stream<'a>(
    stream: &'a mut TcpStream,
    header_lines: &[&str],
) -> Result<tokio_tungstenite::WebSocketStream<&'a mut TcpStream>, String> {
    use sha1::{Digest, Sha1};

    let ws_key = header_lines
        .iter()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("sec-websocket-key") {
                Some(v.trim())
            } else {
                None
            }
        })
        .ok_or_else(|| "missing Sec-WebSocket-Key".to_string())?;

    // Conforms to RFC 6455 §4.2.2 Sec-WebSocket-Accept derivation.
    let mut hasher = Sha1::new();
    hasher.update(ws_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("WS handshake write error: {e}"))?;
    let _ = stream.set_nodelay(true);

    Ok(tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await)
}

async fn handle_browser_pty_ws(
    stream: &mut TcpStream,
    header_lines: &[&str],
    claims: &sb_auth::claims::SovereignClaims,
    pty_id: &str,
) -> Result<(), String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    if let Err((code, err)) = crate::web_ssh::verify_pty_owner(claims, pty_id).await {
        let msg = serde_json::json!({ "error": err }).to_string();
        return write_http_json(stream, code, "Error", &msg).await;
    }
    let ws = upgrade_ws_stream(stream, header_lines).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    loop {
        tokio::select! {
            incoming = ws_rx.next() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if crate::web_ssh::push_pty_input(claims, pty_id, bytes.to_vec(), None, false).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(txt))) => {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
                            let resize = val.get("resize").and_then(|r| {
                                let c = r.get("cols").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok())?;
                                let r_ = r.get("rows").and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok())?;
                                Some((c, r_))
                            });
                            if resize.is_some() {
                                let _ = crate::web_ssh::push_pty_input(claims, pty_id, Vec::new(), resize, false).await;
                            }
                        } else {
                            let _ = crate::web_ssh::push_pty_input(claims, pty_id, txt.as_bytes().to_vec(), None, false).await;
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = ws_tx.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    _ => {}
                }
            }
            outgoing = crate::web_ssh::pull_pty_output(claims, pty_id, 25) => {
                match outgoing {
                    Ok((data, closed)) => {
                        if !data.is_empty() && ws_tx.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                        if closed {
                            let _ = ws_tx.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}

async fn handle_agent_pty_ws(
    stream: &mut TcpStream,
    header_lines: &[&str],
    claims: &sb_auth::claims::SovereignClaims,
    pty_id: &str,
) -> Result<(), String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    if !claims.has_capability("domain:join") && !claims.has_role("admin") {
        return write_http_json(stream, 403, "Forbidden", r#"{"error":"forbidden"}"#).await;
    }
    let ws = upgrade_ws_stream(stream, header_lines).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    loop {
        tokio::select! {
            incoming = ws_rx.next() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if crate::web_ssh::push_pty_output(claims, pty_id, bytes.to_vec(), false).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = ws_tx.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                        let _ = crate::web_ssh::push_pty_output(claims, pty_id, Vec::new(), true).await;
                        break;
                    }
                    _ => {}
                }
            }
            outgoing = crate::web_ssh::pull_pty_input(claims, pty_id, 25) => {
                match outgoing {
                    Ok((data, resize, closed)) => {
                        if let Some((c, r)) = resize {
                            let msg = serde_json::json!({ "resize": { "cols": c, "rows": r } }).to_string();
                            if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                                break;
                            }
                        }
                        if !data.is_empty() && ws_tx.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                        if closed {
                            let _ = ws_tx.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}

/// Authenticates a joined machine using its local Ed25519 `machine.key` (`POST /v1/machines/<id>/auth`)
/// and returns a fresh short-lived bearer token for agent heartbeats, LAPS sync, and relay polling.
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Long-running agents failing after user `access_token` expiry (15m)
///   or replay of captured machine authentication requests.
/// - **CVE / CWE Mapping:** CWE-294 (Authentication Bypass by Capture-replay), CWE-287.
/// - **Likelihood & Exploitability:** Medium (6/10).
/// - **Applied Mitigation:** Signs `"machine_auth:<machine_id>:<unix_ts>"` with the machine's
///   Ed25519 private key; DC enforces a `±120s` timestamp window, active non-revoked membership,
///   and strict Ed25519 verification against the enrolled `machine_public_key_b64`.
pub async fn authenticate_with_machine_key(
    dc_endpoint: &str,
    machine_id: &str,
    signing_key: &SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let ts = Utc::now().timestamp();
    let msg = format!("machine_auth:{machine_id}:{ts}");
    let sig = signing_key.sign(msg.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let body = serde_json::json!({
        "timestamp": ts,
        "signature_b64": sig_b64,
    })
    .to_string();
    let path = format!("/v1/machines/{machine_id}/auth");
    let resp_bytes = send_endpoint_request(dc_endpoint, "POST", &path, Some(&body)).await?;
    let val: serde_json::Value = serde_json::from_slice(&resp_bytes)
        .map_err(|e| format!("Invalid machine auth response: {e}"))?;
    val.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "Machine auth response missing access_token".to_string())
}

#[cfg(test)]
async fn send_http_request(dc_addr: SocketAddr, http_req: &str) -> Result<Vec<u8>, String> {
    let tcp = TcpStream::connect(dc_addr)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    read_http_response_from_stream(tcp, http_req).await
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
        assert!(send_remote_join_request(&dc_addr.to_string(), &bad_req)
            .await
            .is_err());

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
        let resp = send_remote_join_request(&dc_addr.to_string(), &good_req)
            .await
            .unwrap();
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

        let bundle = fetch_remote_policy_bundle(&dc_addr.to_string())
            .await
            .unwrap();
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
        let bundle_after = fetch_remote_policy_bundle(&dc_addr.to_string())
            .await
            .unwrap();
        assert!(bundle_after.policies.is_empty());

        let _ = fs::remove_dir_all(&temp);
    }

    #[tokio::test]
    async fn self_service_me_endpoints_enforce_auth_and_update_ssh_key() {
        use sb_auth::crypto::Keypair;
        use sb_auth::{AuthEngine, MemoryRevocationStore};
        use sb_core::identity::DomainUser;

        let temp = std::env::temp_dir().join(format!(
            "sb_node_me_test_{}_{}",
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

        let users_path = domain_dir.join("users.json");
        let mut users_dir =
            crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
                .unwrap();
        users_dir
            .upsert_user(DomainUser {
                username: "bob.dev".into(),
                display_name: "Bob Dev".into(),
                email: "bob@corp.eu".into(),
                ou: "/".into(),
                groups: vec!["engineering".into()],
                ssh_public_key: None,
                enabled: true,
                created_at: String::new(),
                updated_at: String::new(),
            })
            .unwrap();
        users_dir.save(&users_path).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dc_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_domain_join_on_listener(listener, verifier, Some(reg_path), false).await;
        });

        let bob_tokens = engine
            .issue_session(
                "bob.dev",
                vec!["user".into()],
                vec![],
                serde_json::json!({}),
            )
            .unwrap();

        // GET /v1/me succeeds with Bob's own token
        let me_req = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {dc_addr}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            bob_tokens.access_token
        );
        let me_resp = send_http_request(dc_addr, &me_req).await.unwrap();
        assert!(String::from_utf8_lossy(&me_resp).contains("bob@corp.eu"));

        // PUT /v1/me/ssh-key updates Bob's key and logs an audit event
        let key_body = serde_json::json!({
            "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyDataHere123456 bob@corp.eu"
        })
        .to_string();
        let key_req = format!(
            "PUT /v1/me/ssh-key HTTP/1.1\r\nHost: {dc_addr}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            bob_tokens.access_token,
            key_body.len(),
            key_body
        );
        let key_resp = send_http_request(dc_addr, &key_req).await.unwrap();
        assert!(String::from_utf8_lossy(&key_resp).contains("bob@corp.eu"));

        let events = crate::audit_log::read_all_events(&domain_dir.join("audit.jsonl")).unwrap();
        assert_eq!(events.last().unwrap().action, "user.ssh_key_update");

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn offboard_user_preserves_shared_machines_when_revoke_machines_is_false() {
        let temp = std::env::temp_dir().join(format!(
            "sb_node_shared_offboard_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        let reg_path = temp.join("machines.json");
        let users_path = temp.join("users.json");

        let mut reg = DomainRegistry::load_from_path(&reg_path, "corp.eu").unwrap();
        reg.machines.push(MachineRecord {
            machine_id: "mach_shared01".into(),
            hostname: "ws01".into(),
            domain: "corp.eu".into(),
            fqdn: "ws01.corp.eu".into(),
            os: OsKind::Windows,
            machine_public_key_b64: String::new(),
            mesh_ip: "100.64.0.10".into(),
            joined_by: "alice.admin".into(),
            joined_at: "2026-11-20T00:00:00Z".into(),
            revoked: false,
            revoked_reason: None,
        });
        std::fs::write(&reg_path, serde_json::to_string_pretty(&reg).unwrap()).unwrap();

        let mut users =
            crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
                .unwrap();
        users
            .upsert_user(sb_core::identity::DomainUser {
                username: "alice.admin".into(),
                display_name: "Alice".into(),
                email: "alice@corp.eu".into(),
                ou: "/".into(),
                groups: vec!["admins".into()],
                ssh_public_key: None,
                enabled: true,
                created_at: String::new(),
                updated_at: String::new(),
            })
            .unwrap();
        users.save(&users_path).unwrap();

        let report =
            offboard_user("alice.admin", "admin", false, Some(&temp), Some(&reg_path)).unwrap();
        assert!(report.user_disabled);
        assert_eq!(report.revoked_machines.len(), 0);

        let updated_reg = DomainRegistry::load_from_path(&reg_path, "corp.eu").unwrap();
        assert!(!updated_reg.machines[0].revoked);

        let updated_users =
            crate::directory_users::IdentityDirectory::load_or_create(&users_path, "corp.eu")
                .unwrap();
        assert!(updated_users
            .evaluate_machine_login("alice.admin", "mach_shared01", "ws01.corp.eu")
            .is_err());

        let _ = fs::remove_dir_all(&temp);
    }
}
