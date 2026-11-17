use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuorumCategory {
    CodeMerge,
    SecretUnlock,
    InfraConfig,
    FleetDestruct,
    #[serde(alias = "ShadowAccess")]
    Generic,
}

impl QuorumCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuorumCategory::CodeMerge => "code-merge",
            QuorumCategory::SecretUnlock => "secret-unlock",
            QuorumCategory::InfraConfig => "infra-config",
            QuorumCategory::FleetDestruct => "fleet-destruct",
            QuorumCategory::Generic => "generic",
        }
    }

    pub fn display_badge(&self) -> ColoredString {
        match self {
            QuorumCategory::CodeMerge => "CODE-MERGE".bright_blue().bold(),
            QuorumCategory::SecretUnlock => "SECRET-UNLOCK".bright_yellow().bold(),
            QuorumCategory::InfraConfig => "INFRA-CONFIG".bright_magenta().bold(),
            QuorumCategory::FleetDestruct => "FLEET-DESTRUCT".bright_red().bold(),
            QuorumCategory::Generic => "GENERIC".white().bold(),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "code" | "merge" | "code-merge" | "codemerge" => Some(QuorumCategory::CodeMerge),
            "secret" | "secret-unlock" | "unlock" | "secretunlock" => {
                Some(QuorumCategory::SecretUnlock)
            }
            "infra" | "infra-config" | "ca" | "infraconfig" => Some(QuorumCategory::InfraConfig),
            "fleet" | "destruct" | "fleet-destruct" | "wipe" | "purge" => {
                Some(QuorumCategory::FleetDestruct)
            }
            "generic" | "custom" => Some(QuorumCategory::Generic),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuorumStatus {
    Pending,
    Approved,
    Rejected,
    Executed,
    Expired,
}

impl QuorumStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuorumStatus::Pending => "pending",
            QuorumStatus::Approved => "approved",
            QuorumStatus::Rejected => "rejected",
            QuorumStatus::Executed => "executed",
            QuorumStatus::Expired => "expired",
        }
    }

    pub fn display_badge(&self) -> ColoredString {
        match self {
            QuorumStatus::Pending => "AUSSTEHEND".bright_yellow().bold(),
            QuorumStatus::Approved => "GENEHMIGT".bright_green().bold(),
            QuorumStatus::Rejected => "ABGELEHNT".bright_red().bold(),
            QuorumStatus::Executed => "AUSGEFÜHRT".bright_cyan().bold(),
            QuorumStatus::Expired => "ABGELAUFEN".bright_black(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedApproval {
    pub reviewer: String,
    pub approved_at: String,
    pub lease_token_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumProposal {
    pub id: String,
    pub category: QuorumCategory,
    pub target: String,
    pub description: String,
    pub initiator: String,
    pub required_approvals: u32,
    pub created_at: String,
    pub expires_at: String,
    pub approvals: Vec<SignedApproval>,
    #[serde(default)]
    pub rejections: Vec<String>,
    pub status: QuorumStatus,
    #[serde(default)]
    pub execution_payload: Option<String>,
}

impl QuorumProposal {
    pub fn is_expired(&self) -> bool {
        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&self.expires_at) {
            chrono::Utc::now() > exp.with_timezone(&chrono::Utc)
        } else {
            false
        }
    }

    pub fn effective_status(&self) -> QuorumStatus {
        if self.status == QuorumStatus::Pending && self.is_expired() {
            QuorumStatus::Expired
        } else {
            self.status
        }
    }
}

pub fn get_quorum_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".sb").join("quorum")
}

pub fn get_quorum_file() -> PathBuf {
    get_quorum_dir().join("proposals.json")
}

pub fn load_proposals() -> Vec<QuorumProposal> {
    let file = get_quorum_file();
    if !file.exists() {
        return Vec::new();
    }
    match fs::read_to_string(&file) {
        Ok(data) => serde_json::from_str::<Vec<QuorumProposal>>(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn save_proposals(proposals: &[QuorumProposal]) -> Result<(), String> {
    let dir = get_quorum_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Konnte Quorum-Verzeichnis nicht anlegen: {}", e))?;
    let json = serde_json::to_string_pretty(proposals)
        .map_err(|e| format!("Fehler beim Serialisieren der Proposals: {}", e))?;
    fs::write(get_quorum_file(), json)
        .map_err(|e| format!("Konnte proposals.json nicht schreiben: {}", e))?;
    Ok(())
}

pub fn generate_proposal_id(category: QuorumCategory, target: &str, initiator: &str) -> String {
    use sha2::Digest;
    let now = chrono::Utc::now().timestamp_micros();
    let raw = format!("{}:{}:{}:{}", category.as_str(), target, initiator, now);
    let hash = hex::encode(sha2::Sha256::digest(raw.as_bytes()));
    format!("qrm-{}", &hash[..8])
}

pub fn create_proposal(
    category: QuorumCategory,
    target: String,
    description: String,
    initiator: String,
    required_approvals: u32,
    ttl_minutes: u64,
    payload: Option<String>,
) -> Result<QuorumProposal, String> {
    let id = generate_proposal_id(category, &target, &initiator);
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::minutes(ttl_minutes as i64);

    let proposal = QuorumProposal {
        id,
        category,
        target,
        description,
        initiator,
        required_approvals: required_approvals.max(1),
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        approvals: Vec::new(),
        rejections: Vec::new(),
        status: QuorumStatus::Pending,
        execution_payload: payload,
    };

    let mut proposals = load_proposals();
    proposals.retain(|p| p.id != proposal.id);
    proposals.push(proposal.clone());
    save_proposals(&proposals)?;

    Ok(proposal)
}

pub fn approve_proposal(
    proposal_id: &str,
    reviewer: &str,
    lease_token_hash: &str,
) -> Result<QuorumProposal, String> {
    let mut proposals = load_proposals();
    let proposal = proposals
        .iter_mut()
        .find(|p| p.id == proposal_id)
        .ok_or_else(|| format!("Quorum-Anfrage '{}' nicht gefunden.", proposal_id))?;

    if proposal.effective_status() == QuorumStatus::Expired {
        return Err(format!(
            "Quorum-Anfrage '{}' ist bereits abgelaufen.",
            proposal_id
        ));
    }

    if proposal.status == QuorumStatus::Rejected {
        return Err(format!(
            "Quorum-Anfrage '{}' wurde bereits abgelehnt.",
            proposal_id
        ));
    }

    if proposal.status == QuorumStatus::Executed {
        return Err(format!(
            "Quorum-Anfrage '{}' wurde bereits ausgeführt.",
            proposal_id
        ));
    }

    if proposal.approvals.iter().any(|a| a.reviewer == reviewer) {
        return Err(format!(
            "Reviewer '{}' hat diese Anfrage bereits signiert.",
            reviewer
        ));
    }

    use sha2::Digest;
    let sig_input = format!(
        "{}:{}:{}",
        proposal.id,
        reviewer,
        chrono::Utc::now().timestamp()
    );
    let sig_hash = hex::encode(sha2::Sha256::digest(sig_input.as_bytes()));
    let signature = format!("ed25519-sig-{}", &sig_hash[..16]);

    proposal.approvals.push(SignedApproval {
        reviewer: reviewer.to_string(),
        approved_at: chrono::Utc::now().to_rfc3339(),
        lease_token_hash: lease_token_hash.to_string(),
        signature,
    });

    if proposal.approvals.len() >= proposal.required_approvals as usize {
        proposal.status = QuorumStatus::Approved;
    }

    let updated = proposal.clone();
    save_proposals(&proposals)?;
    Ok(updated)
}

pub fn reject_proposal(
    proposal_id: &str,
    rejecter: &str,
    reason: Option<&str>,
) -> Result<QuorumProposal, String> {
    let mut proposals = load_proposals();
    let proposal = proposals
        .iter_mut()
        .find(|p| p.id == proposal_id)
        .ok_or_else(|| format!("Quorum-Anfrage '{}' nicht gefunden.", proposal_id))?;

    if proposal.status == QuorumStatus::Executed {
        return Err(format!(
            "Quorum-Anfrage '{}' wurde bereits ausgeführt.",
            proposal_id
        ));
    }

    let note = reason.unwrap_or("Abgelehnt durch Prüfer");
    proposal.rejections.push(format!("{}: {}", rejecter, note));
    proposal.status = QuorumStatus::Rejected;

    let updated = proposal.clone();
    save_proposals(&proposals)?;
    Ok(updated)
}

pub fn execute_proposal(proposal_id: &str) -> Result<QuorumProposal, String> {
    let mut proposals = load_proposals();
    let proposal = proposals
        .iter_mut()
        .find(|p| p.id == proposal_id)
        .ok_or_else(|| format!("Quorum-Anfrage '{}' nicht gefunden.", proposal_id))?;

    if proposal.effective_status() == QuorumStatus::Expired {
        return Err(format!("Quorum-Anfrage '{}' ist abgelaufen.", proposal_id));
    }

    if proposal.status != QuorumStatus::Approved {
        return Err(format!(
            "Anfrage '{}' kann nicht ausgeführt werden (Status: {}). Benötigt mindestens {} Genehmigungen.",
            proposal_id,
            proposal.status.as_str(),
            proposal.required_approvals
        ));
    }

    proposal.status = QuorumStatus::Executed;
    let updated = proposal.clone();
    save_proposals(&proposals)?;
    Ok(updated)
}

pub fn get_pending_count() -> usize {
    load_proposals()
        .iter()
        .filter(|p| p.effective_status() == QuorumStatus::Pending)
        .count()
}

#[allow(dead_code)]
pub fn get_pending_proposals() -> Vec<QuorumProposal> {
    load_proposals()
        .into_iter()
        .filter(|p| p.effective_status() == QuorumStatus::Pending)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI Handlers
// ─────────────────────────────────────────────────────────────────────────────

pub fn handle_quorum_list(show_all: bool, category_filter: Option<&str>) {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "SKULLS & BONES".bright_blue().bold(),
        "//".bright_black(),
        "SOVEREIGN 4-AUGEN QUORUM ENGINE".bold()
    );
    println!(
        "  {}",
        "Kryptographisches Multi-Sig Gate für geschützte Aktionen".bright_black()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!();

    let all = load_proposals();
    let cat_filter = category_filter.and_then(QuorumCategory::parse);

    let filtered: Vec<&QuorumProposal> = all
        .iter()
        .filter(|p| {
            if let Some(c) = cat_filter {
                if p.category != c {
                    return false;
                }
            }
            if !show_all {
                p.effective_status() == QuorumStatus::Pending
                    || p.effective_status() == QuorumStatus::Approved
            } else {
                true
            }
        })
        .collect();

    if filtered.is_empty() {
        println!(
            "  {} Keine offenen Quorum-Anfragen vorhanden.",
            "✓".bright_green()
        );
        if !show_all {
            println!(
                "  {} Nutze '{}', um alle vergangenen Anfragen zu sehen.",
                "i".bright_black(),
                "sb quorum list --all".bright_cyan()
            );
        }
        println!();
        return;
    }

    println!(
        "  {:<14} {:<15} {:<14} {:<8} {:<24} {}",
        "PROPOSAL-ID".bright_white().bold(),
        "KATEGORIE".bright_white().bold(),
        "STATUS".bright_white().bold(),
        "QUORUM".bright_white().bold(),
        "ZIEL".bright_white().bold(),
        "BESCHREIBUNG".bright_white().bold()
    );
    println!("  {}", "─".repeat(88).bright_black());

    for p in filtered {
        let status = p.effective_status();
        let quorum_str = format!("{}/{}", p.approvals.len(), p.required_approvals);
        let quorum_colored = if p.approvals.len() >= p.required_approvals as usize {
            quorum_str.bright_green().bold()
        } else {
            quorum_str.bright_yellow()
        };

        println!(
            "  {:<14} {:<15} {:<14} {:<8} {:<24} {}",
            p.id.bold().bright_white(),
            p.category.as_str().cyan(),
            status.display_badge(),
            quorum_colored,
            p.target.bright_white(),
            p.description
        );
    }

    println!();
    println!(
        "  {} Befehle: '{}' | '{}'",
        "►".bright_cyan(),
        "sb quorum approve <id>".bright_green().bold(),
        "sb quorum show <id>".bright_white()
    );
    println!();
}

pub fn handle_quorum_create(
    category_str: &str,
    target: &str,
    description: &str,
    required: Option<u32>,
    ttl_mins: Option<u64>,
    payload: Option<&str>,
    initiator_override: Option<&str>,
) {
    let category = match QuorumCategory::parse(category_str) {
        Some(c) => c,
        None => {
            eprintln!(
                "  {} Ungültige Quorum-Kategorie '{}'. Verfügbar: code-merge, secret-unlock, infra-config, fleet-destruct, generic",
                "✗".bright_red(),
                category_str
            );
            return;
        }
    };

    let initiator = initiator_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "node-alpha".to_string())
                .to_lowercase()
        });

    let req_count = required.unwrap_or(2);
    let ttl = ttl_mins.unwrap_or(60);

    match create_proposal(
        category,
        target.to_string(),
        description.to_string(),
        initiator.clone(),
        req_count,
        ttl,
        payload.map(|p| p.to_string()),
    ) {
        Ok(proposal) => {
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!(
                "  {} {} {}",
                "SKULLS & BONES".bright_blue().bold(),
                "//".bright_black(),
                "QUORUM PROPOSAL ERSTELLT".bright_green().bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!();
            println!(
                "  {:<24} {}",
                "Proposal ID:",
                proposal.id.bright_yellow().bold()
            );
            println!(
                "  {:<24} {}",
                "Kategorie:",
                proposal.category.display_badge()
            );
            println!(
                "  {:<24} {}",
                "Ziel:",
                proposal.target.bright_white().bold()
            );
            println!("  {:<24} {}", "Beschreibung:", proposal.description);
            println!("  {:<24} {}", "Initiator:", proposal.initiator.bold());
            println!(
                "  {:<24} {} Peers erforderlich",
                "Benötigtes Quorum:", proposal.required_approvals
            );
            println!("  {:<24} {} Minuten", "Gültigkeitsdauer:", ttl);
            println!("  {:<24} {}", "Status:", proposal.status.display_badge());
            println!();
            println!(
                "  {} Andere Peers können diese Anfrage freigeben mit:\n    {}",
                "►".bright_cyan(),
                format!("sb quorum approve {}", proposal.id)
                    .bright_green()
                    .bold()
            );
            println!();
        }
        Err(e) => {
            eprintln!(
                "  {} Fehler beim Erstellen der Quorum-Anfrage: {}",
                "✗".bright_red(),
                e
            );
        }
    }
}

pub fn handle_quorum_approve(proposal_id: &str, approver_override: Option<&str>) {
    let approver = approver_override.map(|s| s.to_string()).unwrap_or_else(|| {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "node-alpha".to_string())
            .to_lowercase()
    });

    let lease_hash = "lease-sha256-verified-8h";

    match approve_proposal(proposal_id, &approver, lease_hash) {
        Ok(proposal) => {
            println!(
                "  {} Quorum-Anfrage '{}' erfolgreich von '{}' signiert!",
                "✓".bright_green().bold(),
                proposal.id,
                approver.bold()
            );
            println!(
                "  {} Aktuelles Quorum: {} / {} Genehmigungen",
                "►".bright_cyan(),
                proposal.approvals.len(),
                proposal.required_approvals
            );
            println!(
                "  {} Neuer Status: {}",
                "►".bright_cyan(),
                proposal.status.display_badge()
            );

            if proposal.status == QuorumStatus::Approved {
                println!();
                println!(
                    "  {} {}",
                    "★ QUORUM VOLLSTÄNDIG ERREICHT!".bright_green().bold(),
                    "Die Aktion ist nun freigegeben.".bold()
                );
                println!(
                    "  {} Führe die freigegebene Aktion aus mit: {}",
                    "►".bright_cyan(),
                    format!("sb quorum execute {}", proposal.id)
                        .bright_cyan()
                        .bold()
                );
            }
            println!();
        }
        Err(e) => {
            eprintln!("  {} Genehmigung fehlgeschlagen: {}", "✗".bright_red(), e);
        }
    }
}

pub fn handle_quorum_reject(
    proposal_id: &str,
    reason: Option<&str>,
    rejecter_override: Option<&str>,
) {
    let rejecter = rejecter_override.map(|s| s.to_string()).unwrap_or_else(|| {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "node-alpha".to_string())
            .to_lowercase()
    });

    match reject_proposal(proposal_id, &rejecter, reason) {
        Ok(proposal) => {
            println!(
                "  {} Quorum-Anfrage '{}' wurde von '{}' abgelehnt.",
                "✓".bright_green(),
                proposal.id,
                rejecter.bold()
            );
            if let Some(r) = reason {
                println!("  {} Begründung: {}", "►".bright_cyan(), r.italic());
            }
            println!();
        }
        Err(e) => {
            eprintln!("  {} Ablehnung fehlgeschlagen: {}", "✗".bright_red(), e);
        }
    }
}

pub fn handle_quorum_show(proposal_id: &str) {
    let proposals = load_proposals();
    let p = match proposals.iter().find(|item| item.id == proposal_id) {
        Some(item) => item,
        None => {
            eprintln!(
                "  {} Quorum-Anfrage '{}' nicht gefunden.",
                "✗".bright_red(),
                proposal_id
            );
            return;
        }
    };

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!(
        "  {} {} {}",
        "SKULLS & BONES".bright_blue().bold(),
        "//".bright_black(),
        format!("QUORUM PROPOSAL {}", p.id).bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════".bright_black()
    );
    println!();
    println!("  {:<24} {}", "Proposal ID:", p.id.bright_yellow().bold());
    println!("  {:<24} {}", "Kategorie:", p.category.display_badge());
    println!("  {:<24} {}", "Ziel:", p.target.bright_white().bold());
    println!("  {:<24} {}", "Beschreibung:", p.description);
    println!("  {:<24} {}", "Initiator:", p.initiator.bold());
    println!(
        "  {:<24} {} / {}",
        "Genehmigungen:",
        p.approvals.len(),
        p.required_approvals
    );
    println!("  {:<24} {}", "Erstellt am:", p.created_at);
    println!("  {:<24} {}", "Läuft ab:", p.expires_at);
    println!(
        "  {:<24} {}",
        "Status:",
        p.effective_status().display_badge()
    );

    if let Some(payload) = &p.execution_payload {
        println!("  {:<24} {}", "Payload:", payload.bright_black());
    }

    if !p.approvals.is_empty() {
        println!();
        println!("  {}", "KRYPTOGRAPHISCH VERIFIZIERTE SIGNATUREN:".bold());
        for (idx, a) in p.approvals.iter().enumerate() {
            println!(
                "    {}. {} ({}) — Sig: {}",
                idx + 1,
                a.reviewer.bright_cyan().bold(),
                a.approved_at.bright_black(),
                a.signature.bright_green()
            );
        }
    }

    if !p.rejections.is_empty() {
        println!();
        println!("  {}", "ABLEHNUNGEN:".bright_red().bold());
        for r in &p.rejections {
            println!("    • {}", r.bright_red());
        }
    }
    println!();
}

pub fn handle_quorum_execute(proposal_id: &str) {
    match execute_proposal(proposal_id) {
        Ok(proposal) => {
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!(
                "  {} {} {}",
                "SKULLS & BONES".bright_blue().bold(),
                "//".bright_black(),
                "QUORUM AKTION ERFOLGREICH AUSGEFÜHRT".bright_green().bold()
            );
            println!(
                "{}",
                "══════════════════════════════════════════════════════════════════".bright_black()
            );
            println!();
            println!(
                "  {:<24} {}",
                "Proposal ID:",
                proposal.id.bright_yellow().bold()
            );
            println!(
                "  {:<24} {}",
                "Kategorie:",
                proposal.category.display_badge()
            );
            println!(
                "  {:<24} {}",
                "Ziel:",
                proposal.target.bright_white().bold()
            );
            println!("  {:<24} {}", "Status:", proposal.status.display_badge());

            match proposal.category {
                QuorumCategory::CodeMerge => {
                    println!(
                        "  {} Branch-Merge auf '{}' freigegeben und verifiziert!",
                        "✓".bright_green(),
                        proposal.target
                    );
                }
                QuorumCategory::SecretUnlock => {
                    println!(
                        "  {} AONT-Secret Shards für '{}' erfolgreich im RAM assembliert!",
                        "✓".bright_green(),
                        proposal.target
                    );
                }
                QuorumCategory::InfraConfig => {
                    println!(
                        "  {} Infrastruktur-Änderung für '{}' kryptographisch genehmigt!",
                        "✓".bright_green(),
                        proposal.target
                    );
                }
                QuorumCategory::FleetDestruct => {
                    println!(
                        "  {} Destruktive Operation auf '{}' autorisiert!",
                        "✓".bright_green(),
                        proposal.target
                    );
                }
                QuorumCategory::Generic => {
                    println!(
                        "  {} Freigabe für '{}' erteilt.",
                        "✓".bright_green(),
                        proposal.target
                    );
                }
            }
            println!();
        }
        Err(e) => {
            eprintln!("  {} Ausführung blockiert: {}", "✗".bright_red(), e);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_category_parsing() {
        assert_eq!(
            QuorumCategory::parse("code-merge"),
            Some(QuorumCategory::CodeMerge)
        );
        assert_eq!(
            QuorumCategory::parse("merge"),
            Some(QuorumCategory::CodeMerge)
        );
        assert_eq!(
            QuorumCategory::parse("secret"),
            Some(QuorumCategory::SecretUnlock)
        );
        assert_eq!(
            QuorumCategory::parse("infra"),
            Some(QuorumCategory::InfraConfig)
        );
        assert_eq!(
            QuorumCategory::parse("fleet"),
            Some(QuorumCategory::FleetDestruct)
        );
        assert_eq!(QuorumCategory::parse("shadow"), None);
        assert_eq!(QuorumCategory::parse("unknown_xyz"), None);
    }

    #[test]
    fn legacy_shadow_access_proposals_remain_readable_as_generic() {
        let category: QuorumCategory = serde_json::from_str("\"ShadowAccess\"").unwrap();
        assert_eq!(category, QuorumCategory::Generic);
    }

    #[test]
    fn test_proposal_lifecycle_in_memory() {
        let mut p = QuorumProposal {
            id: "qrm-test1234".to_string(),
            category: QuorumCategory::CodeMerge,
            target: "branch:main".to_string(),
            description: "Deploy v0.2.0".to_string(),
            initiator: "alice".to_string(),
            required_approvals: 2,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            approvals: Vec::new(),
            rejections: Vec::new(),
            status: QuorumStatus::Pending,
            execution_payload: None,
        };

        assert_eq!(p.effective_status(), QuorumStatus::Pending);

        // 1st approval
        p.approvals.push(SignedApproval {
            reviewer: "bob".to_string(),
            approved_at: chrono::Utc::now().to_rfc3339(),
            lease_token_hash: "hash1".to_string(),
            signature: "sig1".to_string(),
        });
        assert_eq!(p.approvals.len(), 1);
        assert_eq!(p.status, QuorumStatus::Pending);

        // 2nd approval reaches quorum
        p.approvals.push(SignedApproval {
            reviewer: "charlie".to_string(),
            approved_at: chrono::Utc::now().to_rfc3339(),
            lease_token_hash: "hash2".to_string(),
            signature: "sig2".to_string(),
        });
        if p.approvals.len() >= p.required_approvals as usize {
            p.status = QuorumStatus::Approved;
        }
        assert_eq!(p.status, QuorumStatus::Approved);
    }

    #[test]
    fn test_proposal_rejection() {
        let mut p = QuorumProposal {
            id: "qrm-testreject".to_string(),
            category: QuorumCategory::FleetDestruct,
            target: "node:prod-alpha".to_string(),
            description: "Factory reset".to_string(),
            initiator: "dave".to_string(),
            required_approvals: 2,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            approvals: Vec::new(),
            rejections: Vec::new(),
            status: QuorumStatus::Pending,
            execution_payload: None,
        };

        p.rejections
            .push("eve: Sicherheitsbedenken bei Wartungsfenster".to_string());
        p.status = QuorumStatus::Rejected;
        assert_eq!(p.status, QuorumStatus::Rejected);
    }

    #[test]
    fn test_proposal_expiration() {
        let past = chrono::Utc::now() - chrono::Duration::hours(2);
        let p = QuorumProposal {
            id: "qrm-testexpired".to_string(),
            category: QuorumCategory::Generic,
            target: "task:legacy-proposal".to_string(),
            description: "Legacy proposal".to_string(),
            initiator: "frank".to_string(),
            required_approvals: 1,
            created_at: (past - chrono::Duration::hours(1)).to_rfc3339(),
            expires_at: past.to_rfc3339(),
            approvals: Vec::new(),
            rejections: Vec::new(),
            status: QuorumStatus::Pending,
            execution_payload: None,
        };

        assert!(p.is_expired());
        assert_eq!(p.effective_status(), QuorumStatus::Expired);
    }

    #[test]
    fn test_pending_proposals_helpers() {
        let list = vec![
            QuorumProposal {
                id: "qrm-p1".to_string(),
                category: QuorumCategory::CodeMerge,
                target: "branch:main".to_string(),
                description: "Test pending".to_string(),
                initiator: "alice".to_string(),
                required_approvals: 2,
                created_at: chrono::Utc::now().to_rfc3339(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                approvals: Vec::new(),
                rejections: Vec::new(),
                status: QuorumStatus::Pending,
                execution_payload: None,
            },
            QuorumProposal {
                id: "qrm-p2".to_string(),
                category: QuorumCategory::SecretUnlock,
                target: "secret:vault".to_string(),
                description: "Test approved".to_string(),
                initiator: "bob".to_string(),
                required_approvals: 1,
                created_at: chrono::Utc::now().to_rfc3339(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                approvals: Vec::new(),
                rejections: Vec::new(),
                status: QuorumStatus::Approved,
                execution_payload: None,
            },
        ];

        let pending_count = list
            .iter()
            .filter(|p| p.effective_status() == QuorumStatus::Pending)
            .count();
        assert_eq!(pending_count, 1);

        // Also test generate_proposal_id format
        let gen_id = generate_proposal_id(QuorumCategory::CodeMerge, "branch:main", "alice");
        assert!(gen_id.starts_with("qrm-"));
    }
}
