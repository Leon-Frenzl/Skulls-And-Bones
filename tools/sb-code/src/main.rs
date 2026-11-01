#![allow(dead_code)]

use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod anchor;
mod ast;
mod baseline;
mod crdt;
mod dev_workspace;
mod escape;
mod fastcdc;
mod ingress;
mod ipc;
mod language;
mod logger;
mod merkle;
mod mesh_sync;
mod runner;
mod session;
mod stream;
mod sync;
mod tui;
mod vcs;
mod web;

use ast::AstLockTable;
use runner::{ExecutionTarget, RunnerState};
use session::{get_active_callsign, CodeSession};
use vcs::VcsEngine;

/// Liefert den Dateinamen eines (Unix- oder Windows-)Pfades für kompakte Ausgaben.
fn short_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn print_json_envelope<T: serde::Serialize>(command: &str, data: &T) {
    let envelope = serde_json::json!({
        "schema_version": 1,
        "command": command,
        "data": data,
    });
    match serde_json::to_string_pretty(&envelope) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{} JSON-Ausgabe fehlgeschlagen: {error}", "FEHLER:".red());
            std::process::exit(1);
        }
    }
}

fn build_repository_context(
    engine: &VcsEngine,
    max_chars: usize,
) -> Result<serde_json::Value, String> {
    if max_chars < 512 {
        return Err("--max-chars must be at least 512".to_string());
    }
    let status = engine.status()?;
    let commits = engine.log(Some(5))?;
    let mut data = serde_json::json!({
        "workspace": engine.workspace_root().display().to_string(),
        "active_branch": status.current_branch,
        "head_commit_id": status.head_commit.as_ref().map(|commit| commit.commit_id.clone()),
        "status": {
            "clean": status.is_clean,
            "modified": status.modified_count,
            "added": status.added_count,
            "deleted": status.deleted_count,
            "changed_paths": status.changes.iter().take(40).map(|change| change.rel_path.clone()).collect::<Vec<_>>(),
            "additional_changed_paths": status.changes.len().saturating_sub(40),
        },
        "recent_commits": commits.iter().map(|commit| serde_json::json!({
            "commit_id": commit.commit_id,
            "message": commit.message,
            "timestamp": commit.timestamp,
        })).collect::<Vec<_>>(),
        "diffs": [],
        "truncated": !status.changes.is_empty(),
    });
    let envelope_size = |data: &serde_json::Value| {
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "command": "context",
            "data": data,
        }))
        .map(|serialized| serialized.chars().count())
        .map_err(|error| format!("Could not size repository context: {error}"))
    };
    if envelope_size(&data)? > max_chars {
        return Err(format!(
            "Repository summary exceeds --max-chars={max_chars}; increase the limit"
        ));
    }

    let mut diffs = Vec::new();
    let truncated = status.changes.len() > 40;
    for change in status.changes.iter().take(40) {
        let diff = engine.diff_file(&change.rel_path)?;
        let patch = diff
            .lines
            .iter()
            .map(|line| {
                let prefix = match line.change_type.as_str() {
                    "+" => "+",
                    "-" => "-",
                    _ => " ",
                };
                format!("{prefix}{}", line.text)
            })
            .collect::<Vec<_>>()
            .join("\n");
        diffs.push(serde_json::json!({
            "path": diff.rel_path,
            "status": diff.status,
            "patch": patch,
        }));
        data["diffs"] = serde_json::Value::Array(diffs.clone());
        data["truncated"] = serde_json::Value::Bool(truncated);
        if envelope_size(&data)? > max_chars {
            diffs.pop();
            data["diffs"] = serde_json::Value::Array(diffs.clone());
            data["truncated"] = serde_json::Value::Bool(true);
            break;
        }
    }
    Ok(data)
}

fn print_repository_context(data: &serde_json::Value, max_chars: usize) {
    let output = format!(
        "# Repository context\n\n- Workspace: {}\n- Branch: {}\n- HEAD: {}\n- Working tree: {}\n\n## Geänderte Dateien\n{}\n\n## Letzte Commits\n{}\n\n## Diff-Auszüge\n{}\n",
        data["workspace"].as_str().unwrap_or(""),
        data["active_branch"].as_str().unwrap_or(""),
        data["head_commit_id"].as_str().unwrap_or("uncommitted repository"),
        if data["status"]["clean"].as_bool().unwrap_or(false) {
            "clean"
        } else {
            "dirty"
        },
        data["status"]["changed_paths"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join("\n"),
        data["recent_commits"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|commit| format!(
                "- {} {}",
                commit["commit_id"].as_str().unwrap_or(""),
                commit["message"].as_str().unwrap_or("")
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        data["diffs"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|diff| format!(
                "### {} ({})\n{}",
                diff["path"].as_str().unwrap_or(""),
                diff["status"].as_str().unwrap_or(""),
                diff["patch"].as_str().unwrap_or("")
            ))
            .collect::<Vec<_>>()
            .join("\n\n")
    );
    let clipped = output.chars().take(max_chars).collect::<String>();
    if output.chars().count() > max_chars {
        const MARKER: &str = "\n[Ausgabe gekürzt]";
        let body_limit = max_chars.saturating_sub(MARKER.chars().count());
        let body = output.chars().take(body_limit).collect::<String>();
        print!("{body}{MARKER}");
    } else {
        print!("{clipped}");
    }
}

/// Lädt den `.sbignore` Analyse-Filter; mit `bypass` (Flag `--all`) wird kein Filter angewendet.
fn load_analysis_filter(root: &std::path::Path, bypass: bool) -> sync::AnalysisFilter {
    if bypass {
        return sync::AnalysisFilter::default();
    }
    sync::AnalysisFilter::load(root).unwrap_or_else(|e| {
        eprintln!(
            "{} .sbignore konnte nicht gelesen werden: {e}",
            "WARNUNG:".yellow()
        );
        sync::AnalysisFilter::default()
    })
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "sb-code",
    author = "Skulls & Bones Lab <dev@skulls-and-bones.org>",
    version,
    about = "S&B Code — Sovereign Unified Code Engine: AST Scopes, Live Swarm & BLAKE3 Merkle VCS",
    long_about = "S&B Code vereint dezentrale Echtzeit-Kollaboration mit AST-Scoped Methoden-Isolation, einer Stable Shadow Baseline gegen zerschossene Builds und einem BLAKE3 Merkle-DAG Versionskontrollsystem mit inhaltsadressierten Commits und Trees."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialisiert ein Sovereign VCS Repository im Workspace
    Init {
        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Startet eine neue Live-Swarm Session als Host
    Host {
        /// Name der Swarm-Session
        #[arg(short, long, default_value = "alpha-swarm")]
        session: String,

        /// Standard-Ausführungsziel (local, node, host)
        #[arg(short, long, default_value = "local")]
        target: String,

        /// Startet im Hintergrund ohne TUI Cockpit
        #[arg(long)]
        no_tui: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Tritt einer bestehenden Swarm-Session im Mesh bei
    Join {
        /// Name der Swarm-Session
        session: String,

        /// Host Callsign
        #[arg(short, long)]
        host: Option<String>,

        /// Standard-Ausführungsziel
        #[arg(short, long, default_value = "local")]
        target: String,

        /// Startet ohne TUI Cockpit
        #[arg(long)]
        no_tui: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Führt einen Befehl im Swarm-Kontext aus (Local, Fleet Node oder Host)
    Run {
        /// Ausführungsziel (local, node, host)
        #[arg(short, long, default_value = "local")]
        target: String,

        /// Auszuführender Befehl samt Parametern (z.B. 'sb code run -- cargo test')
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Erstellt einen inhaltsadressierten BLAKE3 Merkle-Commit
    Commit {
        /// Commit-Nachricht
        #[arg(short, long)]
        message: String,

        /// Nur die angegebenen Dateien/Verzeichnisse übernehmen
        #[arg(long = "only", value_name = "PATH")]
        only_paths: Vec<String>,

        /// Nur benannte AST-Scopes übernehmen; Format DATEI=NAME_ODER_ID
        #[arg(long = "scope", value_name = "DATEI=ZIEL")]
        scopes: Vec<String>,

        /// Änderungen prüfen und Auswahl anzeigen, ohne einen Commit zu erstellen
        #[arg(long)]
        dry_run: bool,

        /// Commit-Datensatz als JSON ausgeben
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Erstellt einen benannten lokalen Checkpoint als normalen Commit
    Checkpoint {
        /// Eindeutiger Checkpoint-Name
        name: String,

        /// Optionale Commit-Nachricht
        #[arg(short, long)]
        message: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Zeigt den Commit-Verlauf des sovereign Repositories an
    Log {
        /// Maximale Anzahl an Commits
        #[arg(short, long)]
        limit: Option<usize>,

        /// ASCII-Grafik mit Branch-/Merge-Kanten anzeigen
        #[arg(long)]
        graph: bool,

        /// Ausgabe im versionierten JSON-Envelope
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Zeigt einen Commit und seine Änderungen gegenüber dem ersten Eltern-Commit
    Show {
        /// Vollständige oder eindeutige Präfix-ID
        commit: String,

        /// Ausgabe im versionierten JSON-Envelope
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Erklärt die Änderungshistorie eines AST-Scopes (keine personenbezogene Zuordnung)
    Why {
        /// Quelldatei im Repository
        file: String,

        /// Scope-Name oder Scope-ID
        target: String,

        /// Ausgabe im versionierten JSON-Envelope
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Heatmap & Code-Churn: Zeigt die am häufigsten geänderten Funktionen und Hotspot-Dateien
    Heatmap {
        /// Maximale Anzahl zu analysierender Commits (Standard: alle)
        #[arg(short, long)]
        limit: Option<usize>,

        /// Top N Hotspots anzeigen (Standard: 20)
        #[arg(short, long, default_value_t = 20)]
        top: usize,

        /// Ausgabe als strukturiertes JSON für KI-Agenten und Dashboards
        #[arg(long)]
        json: bool,

        /// Ignoriert den .sbignore Analyse-Filter
        #[arg(long)]
        all: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Logische Kopplung: Zeigt Dateien, die historisch fast immer zusammen geändert werden
    Coupling {
        /// Optionaler Filter auf eine bestimmte Datei
        file: Option<String>,

        /// Maximale Anzahl an Commits (Standard: alle)
        #[arg(short, long)]
        limit: Option<usize>,

        /// Mindestanzahl gemeinsamer Änderungen für eine Kopplung (Standard: 2)
        #[arg(short, long, default_value_t = 2)]
        min: usize,

        /// Ausgabe als strukturiertes JSON für KI-Agenten
        #[arg(long)]
        json: bool,

        /// Ignoriert den .sbignore Analyse-Filter
        #[arg(long)]
        all: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Zeigt Änderungen (Diff) zwischen Arbeitsverzeichnis und HEAD oder für eine Datei
    Diff {
        /// Optional zu prüfende Datei (z. B. src/main.rs)
        file: Option<String>,

        /// Ausgabe im versionierten JSON-Envelope
        #[arg(long)]
        json: bool,

        /// AST-Scopes statt nur Zeilenänderungen zusammenfassen
        #[arg(long)]
        scopes: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Verwaltet Branches im Sovereign VCS (auflisten oder erstellen)
    Branch {
        /// Name des neu zu erstellenden Branches
        name: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Wechselt zu einem Branch oder rollt auf einen historischen Commit zurück
    Checkout {
        /// Ziel-Branch oder Commit-ID
        target: String,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Rollback: Setzt den aktiven Branch oder eine Datei sicher auf einen vorherigen Commit zurück
    Rollback {
        /// Anzahl der Commits, die zurückgerollt werden sollen (Standard: 1)
        #[arg(short, long, default_value_t = 1)]
        steps: usize,

        /// Ziel-Commit-ID für gezielten Rollback
        #[arg(long)]
        to: Option<String>,

        /// Nur eine bestimmte Datei auf den Stand des vorherigen Commits zurücksetzen
        #[arg(short, long)]
        file: Option<String>,

        /// Erzwingt Rollback auch bei uncommitteten lokalen Änderungen
        #[arg(long)]
        force: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Vergleicht AST-Scopes mit einem anderen Branch als Ghost-Image
    Ghost {
        /// Vergleichs-Branch
        other: String,

        /// Optionaler Scope-Name oder Scope-ID
        #[arg(long)]
        scope: Option<String>,

        /// Ausgabe im versionierten JSON-Envelope
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Erstellt eine unverbindliche Vorschau für eine AST-Branch-Integration
    Plan {
        /// Vergleichs-Branch
        other: String,

        /// Gibt den vollständigen Plan als JSON aus
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Integriert konfliktfreie AST-Änderungen aus einem Branch
    Integrate {
        /// Quell-Branch
        other: String,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Verwalten und lösen persistierte Scope-Konflikte einer Integration
    Conflicts {
        #[command(subcommand)]
        action: ConflictAction,
    },

    /// Verwaltet isolierte Arbeitsverzeichnisse mit gemeinsamem sb-code-Objektspeicher
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },

    /// Überträgt Commits über einen autorisierten sb-mesh Stream
    Push {
        /// Mesh, in dem der aufrufende Peer Mitglied ist
        #[arg(long)]
        source_mesh: String,

        /// Ziel-Mesh mit laufendem sb-code syncd
        #[arg(long, default_value = "dev-mesh")]
        target_mesh: String,

        /// UDP-Adresse des sb-node Anchors
        #[arg(long = "anchor")]
        anchor_addr: SocketAddr,

        /// Optionale Cross-Mesh Capability-Token-Datei (JSON)
        #[arg(long)]
        capability_token: Option<PathBuf>,

        /// Branch, der synchronisiert werden soll (Standard: aktueller Branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Ziel-Port des auf dem Anchor erreichbaren sb-code syncd
        #[arg(long, default_value_t = mesh_sync::CODE_SYNC_PORT)]
        service_port: u16,

        /// Optionaler logischer Dev-Mesh Workspace (z. B. 'dev/tools/sb-core')
        #[arg(long)]
        workspace_id: Option<String>,

        /// Eigene Caller Node-ID (Standard: lokales Callsign)
        #[arg(long)]
        node_id: Option<String>,

        /// Erwarteter Branch HEAD zur Erkennung und Vermeidung von Divergenz (CAS)
        #[arg(long)]
        expected_head: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Zieht Commits über einen autorisierten sb-mesh Stream
    Pull {
        /// Mesh, in dem der aufrufende Peer Mitglied ist
        #[arg(long)]
        source_mesh: String,

        /// Ziel-Mesh mit laufendem sb-code syncd
        #[arg(long, default_value = "dev-mesh")]
        target_mesh: String,

        /// UDP-Adresse des sb-node Anchors
        #[arg(long = "anchor")]
        anchor_addr: SocketAddr,

        /// Optionale Cross-Mesh Capability-Token-Datei (JSON)
        #[arg(long)]
        capability_token: Option<PathBuf>,

        /// Branch, der synchronisiert werden soll (Standard: aktueller Branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Ziel-Port des auf dem Anchor erreichbaren sb-code syncd
        #[arg(long, default_value_t = mesh_sync::CODE_SYNC_PORT)]
        service_port: u16,

        /// Optionaler logischer Dev-Mesh Workspace (z. B. 'dev/tools/sb-core')
        #[arg(long)]
        workspace_id: Option<String>,

        /// Eigene Caller Node-ID (Standard: lokales Callsign)
        #[arg(long)]
        node_id: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Verwaltet logische Dev-Mesh-Namespaces und Replikationsrichtlinien je Tool
    DevWorkspace {
        #[command(subcommand)]
        action: DevWorkspaceAction,
    },

    /// Bündelt Dev-Mesh-Setup: Route (sb-node), Voraussetzungs-Check und syncd in einem Schritt
    Serve {
        /// Ziel-Mesh, in dem der Code-Sync angeboten wird
        #[arg(long)]
        mesh: String,

        /// Quell-Mesh der Route (Standard: gleiches Mesh)
        #[arg(long)]
        source_mesh: Option<String>,

        /// Lokaler TCP-Endpunkt; darf nur Loopback sein
        #[arg(long, default_value = "127.0.0.1:58832")]
        bind: SocketAddr,

        /// Repository-Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Startet den loopback-only Mesh-Sync-Endpunkt (Port 58832)
    Syncd {
        /// Lokaler TCP-Endpunkt; darf nur Loopback sein
        #[arg(long, default_value = "127.0.0.1:58832")]
        bind: SocketAddr,

        /// Repository-Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Startet den schreibgeschützten, loopback-only Webviewer für ein Repository
    Web {
        /// Lokaler TCP-Endpunkt; darf nur Loopback sein
        #[arg(long, default_value = "127.0.0.1:58835")]
        bind: SocketAddr,

        /// Repository-Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Öffnet einen lokalen Loopback-Tunnel zum Webviewer in einem Mesh
    WebProxy {
        /// Mesh, in dem der aufrufende Peer Mitglied ist
        #[arg(long)]
        source_mesh: String,

        /// Ziel-Mesh, in dem sb-node den Webviewer anbietet
        #[arg(long, default_value = "dev-mesh")]
        target_mesh: String,

        /// UDP-Adresse des sb-node Anchors
        #[arg(long = "anchor")]
        anchor_addr: SocketAddr,

        /// Lokaler TCP-Endpunkt; darf nur Loopback sein
        #[arg(long, default_value = "127.0.0.1:58836")]
        listen: SocketAddr,

        /// Lokales Repository für Push/Pull über den Mesh-Sync
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Optionale Cross-Mesh Capability-Token-Datei (JSON)
        #[arg(long)]
        capability_token: Option<PathBuf>,

        /// Ziel-Port des auf dem Anchor erreichbaren sb-code syncd
        #[arg(long, default_value_t = mesh_sync::CODE_SYNC_PORT)]
        service_port: u16,
    },

    /// Zeigt Status im lokalen Legacy-Test-Anchor-Store (kein Mesh-Status)
    RemoteStatus {
        /// Name des Anchors im Swarm (Standard: hetzner-anchor)
        #[arg(short, long)]
        anchor: Option<String>,

        /// Zu prüfender Branch (Standard: aktueller Branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Vergleicht Branch-Heads und gemeinsam geänderte Scopes mit einem Mesh
    Divergence {
        #[arg(long)]
        source_mesh: String,
        #[arg(long, default_value = "dev-mesh")]
        target_mesh: String,
        #[arg(long = "anchor")]
        anchor_addr: SocketAddr,
        #[arg(long)]
        capability_token: Option<PathBuf>,
        /// Ziel-Port des auf dem Anchor erreichbaren sb-code syncd
        #[arg(long, default_value_t = mesh_sync::CODE_SYNC_PORT)]
        service_port: u16,
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Analysiert AST-Scopes (Methoden, Structs, Klassen) in einer Quelldatei
    Scopes {
        /// Zu analysierende Quelldatei (z.B. src/main.rs oder OrderService.java)
        file: PathBuf,

        /// Ausgabe als strukturiertes JSON für KI-Agenten und Tools
        #[arg(long)]
        json: bool,
    },

    /// Extrahiert präzisen AST-Scope Kontext (Code-Block samt Imports) für KIs und Entwickler
    Context {
        /// Zu analysierende Quelldatei (z.B. src/main.rs)
        file: Option<PathBuf>,

        /// Ziel: Methoden-/Funktionsname (z.B. resolve_ssh) oder Zeilennummer (z.B. 42)
        target: Option<String>,

        /// Repository-Änderungskontext für Reviews und KI-Agenten ausgeben
        #[arg(long)]
        repo: bool,

        /// Zusätzliche Kontextzeilen vor und nach dem Scope
        #[arg(short, long, default_value_t = 0)]
        padding: usize,

        /// Ausgabe als strukturiertes JSON für KI-Agenten
        #[arg(long)]
        json: bool,

        /// Maximale Zeichenanzahl der Repository-Kontextausgabe (Standard: 20000)
        #[arg(long, default_value_t = 20_000)]
        max_chars: usize,

        /// Optionaler Arbeitsordner für --repo
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Strukturelles Modul-Skelett: alle AST-Symbole mit Typ, Signatur und Zeilenbereich
    Outline {
        /// Zu analysierende Quelldatei (z.B. src/main.rs)
        file: PathBuf,

        /// Ausgabe als strukturiertes JSON für KI-Agenten
        #[arg(long)]
        json: bool,
    },

    /// AST-Scope sperren, um kollidierende Edits von Swarm-Peers zu verhindern
    Lock {
        /// Zu sperrende Datei (z.B. src/main.rs)
        file: PathBuf,

        /// Ziel: Zeilennummer (z.B. 42) oder Methoden-/Funktionsname (z.B. calculate_total)
        target: String,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// AST-Scope Sperre freigeben
    Unlock {
        /// Datei (z.B. src/main.rs)
        file: PathBuf,

        /// Optionales Ziel (Zeilennummer oder Name). Wenn weggelassen, werden alle eigenen Locks der Datei freigegeben.
        target: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Listet alle aktiven AST-Scope-Sperren im Swarm auf
    Locks {
        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Dezentrales Live Swarm Code-Streaming
    Stream {
        #[command(subcommand)]
        action: StreamAction,
    },

    /// Zeigt den Status von Arbeitsverzeichnis, Branch, Live-Session und Merkle-Tree an
    Status {
        /// Ausgabe als strukturiertes JSON für KI-Agenten
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Zeigt detaillierte Speicherbelegung, Objektzahlen und Deduplikationsstatistiken des Repositories an
    Stats {
        /// Ausgabe als strukturiertes JSON für KI-Agenten und Skripte
        #[arg(long)]
        json: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Öffnet das interaktive Terminal-Cockpit (Ratatui TUI)
    Tui {
        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Veröffentlicht das aktuelle Projekt als P2P Code-Stream im Swarm
    Publish {
        /// Optionaler Projektname (Standard: Verzeichnisname)
        #[arg(short, long)]
        project: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Abonniert einen P2P Code-Stream aus dem Mesh Swarm
    Subscribe {
        /// Name des zu abonnierenden Projekts (z.B. 'shop-api')
        project: String,

        /// Optionaler Zielordner
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Erkennt lokale Entwicklungs-Server und zeigt deren Sovereign Mesh Ingress URLs
    Ingress,

    /// Sovereign Egress & Tunnel: Gibt lokale Webdienste ohne Port-Forwarding über das S&B Gateway frei
    Escape {
        #[command(subcommand)]
        action: EscapeAction,
    },

    /// Generiert Shell-Autovervollständigungen
    Completions {
        /// Ziel-Shell (bash, zsh, fish, powershell)
        shell: clap_complete::Shell,
    },

    /// Verifiziert die kryptographische Ed25519-Signatur eines Commits oder des aktuellen HEAD
    Verify {
        /// Commit-ID (Standard: HEAD)
        commit: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Exportiert oder importiert ein souveränes Merkle-VCS Bundle (.sbbundle) zur Sicherung und Wiederherstellung
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
}

#[derive(Subcommand, Debug)]
enum BundleAction {
    /// Exportiert einen Branch samt Commits, Scopes und Blobs in eine .sbbundle-Datei
    Export {
        /// Zieldatei (Standard: <branch>.sbbundle)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Zu exportierender Branch (Standard: aktueller Branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Optionaler Basis-Commit für inkrementellen Export
        #[arg(long)]
        since: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Importiert ein .sbbundle und stellt Commits, Scopes und optional den Worktree wieder her
    Import {
        /// Pfad zur .sbbundle-Datei
        file: PathBuf,

        /// Ziel-Branch (Standard: im Bundle-Manifest gespeicherter Branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Schreibt den wiederhergestellten Stand direkt in das Arbeitsverzeichnis
        #[arg(long)]
        checkout: bool,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum DevWorkspaceAction {
    /// Registriert einen neuen Dev-Mesh-Workspace mit Richtlinie
    Register {
        /// Logische Workspace-ID (z. B. 'dev/tools/sb-core')
        #[arg(long)]
        id: String,
        /// Projektname (z. B. 'sb-core')
        #[arg(long)]
        project: String,
        /// Pfad zum lokalen Repository dieses Tools
        #[arg(long)]
        path: PathBuf,
        /// Node ID des alleinigen Schreibers (Authoritative Writer)
        #[arg(long)]
        writer: String,
        /// Erlaubte Replikat-Peers (kann mehrfach angegeben werden)
        #[arg(long = "replica")]
        replicas: Vec<String>,
        /// Optionaler Pfad zur workspaces.json Registry
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Listet alle registrierten Dev-Mesh Workspaces und Richtlinien auf
    List {
        /// Optionaler Pfad zur workspaces.json Registry
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Zeigt oder prüft die Richtlinie eines Workspaces
    Policy {
        /// Workspace-ID (z. B. 'dev/tools/sb-core')
        id: String,
        /// Optionaler Pfad zur workspaces.json Registry
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Startet den Multi-Workspace syncd Daemon
    Syncd {
        /// Pfad zur workspaces.json Registry
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Lokaler Loopback TCP-Endpunkt (Standard: 127.0.0.1:58832)
        #[arg(long, default_value = "127.0.0.1:58832")]
        bind: SocketAddr,
    },
}

#[derive(Subcommand, Debug)]
enum ConflictAction {
    /// Erzeugt einen persistierten 3-Wege-Konfliktzustand aus einem Branch-Plan
    Begin {
        other: String,
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Listet gespeicherte Scope-Konflikte samt Basis-, Current- und Other-Inhalt
    List {
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Wählt für einen Scope den Current- oder Other-Inhalt
    Resolve {
        scope_id: String,
        #[arg(long = "use", value_parser = ["current", "other"])]
        choice: String,
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Wendet Auto-Änderungen und alle explizit aufgelösten Scopes an
    Finalize {
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Verwirft einen veralteten oder nicht mehr benötigten Konfliktzustand
    Discard {
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum WorkspaceAction {
    /// Erstellt einen isolierten Workspace auf einem vorhandenen Branch
    Add {
        branch: String,
        path: PathBuf,
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Listet alle registrierten Workspaces samt isolierter Portbereiche
    List {
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Entfernt einen registrierten Workspace; geänderte Dateien erfordern --force
    Remove {
        path: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
    /// Entfernt Registry-Einträge, deren Workspace-Verzeichnis nicht mehr existiert
    Prune {
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum StreamAction {
    /// Zeigt oder erzeugt dezentrale AST-annotierte Live-Swarm-Diffs ohne Versions-Commits
    Diff {
        /// Optional zu prüfende Datei
        file: Option<PathBuf>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Veröffentlicht das aktuelle Projekt als P2P Code-Stream (Alias für 'publish')
    Publish {
        /// Optionaler Projektname
        #[arg(short, long)]
        project: Option<String>,

        /// Optionaler Arbeitsordner
        #[arg(short, long)]
        workspace: Option<PathBuf>,
    },

    /// Abonniert einen P2P Code-Stream aus dem Swarm (Alias für 'subscribe')
    Subscribe {
        /// Name des Projekts
        project: String,

        /// Optionaler Zielordner
        #[arg(short, long)]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum EscapeAction {
    /// Gibt einen lokalen Port über einen Sovereign Tunnel an ein Escape Space Gateway frei
    Share {
        /// Lokaler Port (z.B. 3000, 5173, 8080)
        port: u16,

        /// Öffentliche Domain des Escape Spaces (z.B. 'preview.myteam.io')
        #[arg(long = "as")]
        domain: String,

        /// Gateway Tunnel-Port-Adresse (Standard: 127.0.0.1:58910 oder IP:58910)
        #[arg(short, long, default_value = "127.0.0.1:58910")]
        gateway: String,
    },

    /// Listet alle registrierten Escape Spaces und ihren Tunnel-Status auf
    List,

    /// Aktiviert oder deaktiviert den Sovereign-Tunnel-Modus für einen Escape Space
    Tunnel {
        /// Space ID oder Domain
        space: String,

        /// Tunnel-Modus aktivieren (--enable) oder deaktivieren (--disable)
        #[arg(long)]
        enable: bool,
    },
}

fn main() {
    std::thread::Builder::new()
        .name("sb-code-runtime".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let cli = Cli::parse();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(8 * 1024 * 1024)
                .build()
                .expect("Failed to create sb-code Tokio runtime");
            runtime.block_on(run(cli));
        })
        .expect("Failed to start sb-code runtime thread")
        .join()
        .expect("sb-code runtime thread panicked");
}

async fn run(cli: Cli) {
    match cli.command {
        Commands::Host {
            session,
            target,
            no_tui,
            workspace,
        } => {
            let my_callsign = get_active_callsign();
            let code_session = CodeSession::new_host(&session, &my_callsign);
            let session_arc = Arc::new(Mutex::new(code_session));
            let lock_table = Arc::new(Mutex::new(AstLockTable::new()));

            let exec_target = parse_target(&target);
            let runner_state = Arc::new(Mutex::new(RunnerState {
                target: exec_target,
                ..Default::default()
            }));

            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

            if let Err(e) = ipc::start_ipc_server(
                Arc::clone(&session_arc),
                Arc::clone(&runner_state),
                Arc::clone(&lock_table),
                ipc::DEFAULT_CODE_IPC_PORT,
            )
            .await
            {
                eprintln!("{} Failed to start IPC server: {}", "WARN:".yellow(), e);
            }

            if no_tui {
                println!("{}", "⚡ S&B Code Swarm Host gestartet".green().bold());
                println!("Session:    {}", session.cyan().bold());
                println!("Host:       {}", my_callsign.yellow());
                println!("Target:     {}", target.magenta());
                println!("Workspace:  {}", root.display());
                println!("AST Scopes: METHOD/FN-LEVEL ACTIVE");
                println!("IPC Server: 127.0.0.1:{}", ipc::DEFAULT_CODE_IPC_PORT);
                println!("\nDrücke Strg+C zum Beenden.");
                tokio::signal::ctrl_c().await.unwrap();
            } else {
                if let Err(e) = tui::run_tui(session_arc, runner_state, lock_table, &root) {
                    eprintln!("{} TUI error: {}", "ERROR:".red(), e);
                }
            }
        }

        Commands::Join {
            session,
            host,
            target,
            no_tui,
            workspace,
        } => {
            let my_callsign = get_active_callsign();
            let host_callsign = host.unwrap_or_else(|| "sentinel-prime".to_string());
            let code_session = CodeSession::join(&session, &my_callsign, &host_callsign);
            let session_arc = Arc::new(Mutex::new(code_session));
            let lock_table = Arc::new(Mutex::new(AstLockTable::new()));

            let exec_target = parse_target(&target);
            let runner_state = Arc::new(Mutex::new(RunnerState {
                target: exec_target,
                ..Default::default()
            }));

            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

            if let Err(e) = ipc::start_ipc_server(
                Arc::clone(&session_arc),
                Arc::clone(&runner_state),
                Arc::clone(&lock_table),
                ipc::DEFAULT_CODE_IPC_PORT + 1,
            )
            .await
            {
                eprintln!("{} Failed to start IPC server: {}", "WARN:".yellow(), e);
            }

            if no_tui {
                println!("{}", "⚡ S&B Code Swarm Member verbunden".green().bold());
                println!("Session:    {}", session.cyan().bold());
                println!("Callsign:   {}", my_callsign.yellow());
                println!("Host:       {}", host_callsign.magenta());
                println!("Workspace:  {}", root.display());
                println!("\nDrücke Strg+C zum Beenden.");
                tokio::signal::ctrl_c().await.unwrap();
            } else {
                if let Err(e) = tui::run_tui(session_arc, runner_state, lock_table, &root) {
                    eprintln!("{} TUI error: {}", "ERROR:".red(), e);
                }
            }
        }

        Commands::Run { target, command } => {
            if command.is_empty() {
                eprintln!(
                    "{} Kein Befehl angegeben. Beispiel: sb code run -- cargo test",
                    "FEHLER:".red()
                );
                std::process::exit(1);
            }

            let exec_target = parse_target(&target);
            let runner_state = Arc::new(Mutex::new(RunnerState {
                target: exec_target,
                ..Default::default()
            }));

            println!(
                "{} Führe aus auf [{}]: {}",
                "⚡ S&B Code:".cyan().bold(),
                target.magenta().bold(),
                command.join(" ").bold()
            );

            match runner::execute_command(runner_state, command).await {
                Ok(code) => {
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Init { workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            match VcsEngine::init(&root) {
                Ok(engine) => {
                    println!(
                        "{} Sovereign VCS erfolgreich initialisiert in {}",
                        "✓".green().bold(),
                        root.display()
                    );
                    println!(
                        "Branch: {}",
                        engine
                            .current_branch()
                            .unwrap_or_else(|_| "main".to_string())
                            .yellow()
                    );
                }
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Commit {
            message,
            only_paths,
            scopes,
            dry_run,
            json,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(_) if !dry_run => match VcsEngine::init(&root) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("{} {}", "FEHLER:".red(), e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!(
                        "{} Repository konnte nicht geöffnet werden: {e}",
                        "FEHLER:".red()
                    );
                    std::process::exit(1);
                }
            };

            let scope_specs = scopes
                .iter()
                .map(|spec| {
                    let (file, target) = spec.split_once('=').ok_or_else(|| {
                        format!("Ungültiger --scope-Wert '{spec}'; erwartet DATEI=ZIEL")
                    })?;
                    if file.is_empty() || target.is_empty() {
                        return Err(format!("Ungültiger --scope-Wert '{spec}'"));
                    }
                    Ok((file.to_string(), target.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|error| {
                    eprintln!("{} {error}", "FEHLER:".red());
                    std::process::exit(2);
                });

            if dry_run {
                let status = engine.status().unwrap_or_else(|error| {
                    eprintln!("{} Statusprüfung fehlgeschlagen: {error}", "FEHLER:".red());
                    std::process::exit(1);
                });
                let selected_paths = engine
                    .preview_commit_selection(&only_paths, &scope_specs)
                    .unwrap_or_else(|error| {
                        eprintln!("{} Commit-Auswahl ungültig: {error}", "FEHLER:".red());
                        std::process::exit(2);
                    });
                let selected = status
                    .changes
                    .iter()
                    .filter(|change| selected_paths.contains(&change.rel_path))
                    .collect::<Vec<_>>();
                if json {
                    print_json_envelope(
                        "commit_preflight",
                        &serde_json::json!({
                            "message": message,
                            "branch": status.current_branch,
                            "head_commit_id": status.head_commit.as_ref().map(|commit| &commit.commit_id),
                            "selected_changes": selected,
                            "selected_paths": selected_paths,
                            "scope_selections": scope_specs,
                            "selection_valid": true,
                        }),
                    );
                } else {
                    println!("Commit-Vorschau: {}", message.bold());
                    for change in &selected {
                        println!("  {:<8} {}", change.status, change.rel_path);
                    }
                    println!("{} Dateiänderung(en) ausgewählt.", selected.len());
                    for (file, target) in &scope_specs {
                        println!("  scope    {file} = {target}");
                    }
                    println!("Auswahl geprüft; es wurde kein Commit erzeugt.");
                }
                return;
            }

            let author = get_active_callsign();
            let result = if only_paths.is_empty() && scope_specs.is_empty() {
                engine.commit(&message, &author)
            } else {
                engine.commit_selected(&message, &author, &only_paths, &scope_specs)
            };
            match result {
                Ok(commit) => {
                    if json {
                        print_json_envelope("commit", &commit);
                        return;
                    }
                    println!(
                        "{}",
                        "✓ Merkle-DAG Commit erfolgreich erstellt".green().bold()
                    );
                    println!("Commit ID:  {}", commit.commit_id.cyan().bold());
                    println!(
                        "Branch:     {}",
                        engine
                            .current_branch()
                            .unwrap_or_else(|_| "main".to_string())
                            .yellow()
                    );
                    println!("Author:     {}", commit.author_callsign.yellow());
                    println!(
                        "Tree Hash:  {}...",
                        &commit.tree_hash[..16.min(commit.tree_hash.len())]
                    );
                    let sig_status = commit.signature_status();
                    let sig_display = if sig_status.contains("valide") {
                        sig_status.green().bold()
                    } else if sig_status == "nicht signiert" {
                        sig_status.bright_black()
                    } else {
                        sig_status.yellow()
                    };
                    println!("Signatur:   {}", sig_display);
                    println!("Message:    {}", commit.message.white().bold());
                }
                Err(e) => {
                    eprintln!(
                        "{} Fehler beim Erstellen des Commits: {}",
                        "FEHLER:".red(),
                        e
                    );
                    std::process::exit(1);
                }
            }
        }

        Commands::Checkpoint {
            name,
            message,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut engine = VcsEngine::open(&root).unwrap_or_else(|error| {
                eprintln!(
                    "{} Repository konnte nicht geöffnet werden: {error}",
                    "FEHLER:".red()
                );
                std::process::exit(1);
            });
            match engine.create_checkpoint(&name, message.as_deref(), &get_active_callsign()) {
                Ok((commit, reference)) => println!(
                    "{} Checkpoint '{}' auf Commit {} gespeichert ({})",
                    "✓".green().bold(),
                    name,
                    commit.commit_id,
                    reference.display()
                ),
                Err(error) => {
                    eprintln!("{} {error}", "FEHLER:".red());
                    std::process::exit(1);
                }
            }
        }

        Commands::Log {
            limit,
            graph,
            json,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            match VcsEngine::open(&root) {
                Ok(engine) => {
                    let branch = engine
                        .current_branch()
                        .unwrap_or_else(|_| "main".to_string());
                    let commits = engine.log(limit).unwrap_or_else(|error| {
                        eprintln!(
                            "{} Fehler beim Laden der Historie: {error}",
                            "FEHLER:".red()
                        );
                        std::process::exit(1);
                    });
                    let branches = engine.branch_head_ids().unwrap_or_else(|error| {
                        eprintln!(
                            "{} Branch-Referenzen konnten nicht gelesen werden: {error}",
                            "FEHLER:".red()
                        );
                        std::process::exit(1);
                    });
                    if json {
                        print_json_envelope(
                            "log",
                            &serde_json::json!({
                                "active_branch": branch,
                                "commits": commits,
                                "branches": branches.iter().map(|(name, id)| serde_json::json!({"name": name, "head_commit_id": id})).collect::<Vec<_>>(),
                                "graph": graph,
                            }),
                        );
                        return;
                    }
                    println!(
                        "\n{}",
                        "=== S&B Code · Merkle Commit Historie ===".cyan().bold()
                    );
                    println!("Aktiver Branch: {}", branch.yellow().bold());
                    if commits.is_empty() {
                        println!("Keine Commits vorhanden. Erstelle den ersten mit 'sb code commit -m \"...\"'");
                    } else {
                        let head_id = commits.first().map(|c| c.commit_id.as_str());
                        for (index, c) in commits.iter().enumerate() {
                            let is_head = head_id == Some(c.commit_id.as_str());
                            let head_badge = if is_head {
                                " (HEAD)".green().bold()
                            } else {
                                "".normal()
                            };
                            if graph {
                                let branch_names = branches
                                    .iter()
                                    .filter(|(_, id)| id == &c.commit_id)
                                    .map(|(name, _)| name.as_str())
                                    .collect::<Vec<_>>();
                                let junction = if index + 1 == commits.len() {
                                    "└─"
                                } else {
                                    "├─"
                                };
                                println!(
                                    "{} commit {}{}{}",
                                    junction,
                                    c.commit_id.yellow().bold(),
                                    head_badge,
                                    if branch_names.is_empty() {
                                        String::new()
                                    } else {
                                        format!(" ({})", branch_names.join(", "))
                                    }
                                );
                                if c.parent_ids.len() > 1 {
                                    for parent in c.parent_ids.iter().skip(1) {
                                        println!(
                                            "│   └─ merge parent {}",
                                            &parent[..8.min(parent.len())]
                                        );
                                    }
                                }
                                if index + 1 < commits.len() {
                                    println!("│");
                                }
                            } else {
                                println!(
                                    "\n● commit {}{}",
                                    c.commit_id.yellow().bold(),
                                    head_badge
                                );
                            }
                            println!("  Author:     {}", c.author_callsign.cyan());
                            println!(
                                "  Date:       {}",
                                c.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                            );
                            println!(
                                "  Tree BLAKE3: {}...",
                                &c.tree_hash[..16.min(c.tree_hash.len())]
                            );
                            let sig_status = c.signature_status();
                            let sig_display = if sig_status.contains("valide") {
                                sig_status.green()
                            } else if sig_status == "nicht signiert" {
                                sig_status.bright_black()
                            } else {
                                sig_status.yellow()
                            };
                            println!("  Signatur:   {}", sig_display);
                            println!("  \n    {}", c.message.white().bold());
                        }
                    }
                    println!();
                }
                Err(_) => {
                    println!(
                        "{} Repository ist nicht initialisiert. Führe 'sb code init' aus.",
                        "INFO:".yellow()
                    );
                }
            }
        }

        Commands::Show {
            commit,
            json,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = VcsEngine::open(&root).unwrap_or_else(|error| {
                eprintln!(
                    "{} Repository konnte nicht geöffnet werden: {error}",
                    "FEHLER:".red()
                );
                std::process::exit(1);
            });
            let show = engine.show_commit(&commit).unwrap_or_else(|error| {
                eprintln!("{} {error}", "FEHLER:".red());
                std::process::exit(1);
            });
            if json {
                print_json_envelope("show", &show);
            } else {
                println!(
                    "\ncommit {}{}\nDate: {}\nMessage: {}\n",
                    show.commit.commit_id.bold(),
                    show.parent_commit_id
                        .as_ref()
                        .map(|parent| format!("\nParent: {parent}"))
                        .unwrap_or_default(),
                    show.commit.timestamp,
                    show.commit.message
                );
                for change in show.changes {
                    println!("{} {}", change.status, change.rel_path);
                    for line in change.lines {
                        let prefix = match line.change_type.as_str() {
                            "+" => "+",
                            "-" => "-",
                            _ => " ",
                        };
                        println!("{prefix}{}", line.text);
                    }
                }
            }
        }

        Commands::Why {
            file,
            target,
            json,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = VcsEngine::open(&root).unwrap_or_else(|error| {
                eprintln!(
                    "{} Repository konnte nicht geöffnet werden: {error}",
                    "FEHLER:".red()
                );
                std::process::exit(1);
            });
            let history = engine.why_scope(&file, &target).unwrap_or_else(|error| {
                eprintln!("{} {error}", "FEHLER:".red());
                std::process::exit(1);
            });
            if json {
                print_json_envelope("why", &history);
            } else {
                println!(
                    "Scope-Historie: {} in {} ({})",
                    history.target, history.file_path, history.scope_id
                );
                for change in history.changes {
                    println!(
                        "{} {} {} [{}-{}] {}",
                        change.timestamp,
                        &change.commit_id[..8.min(change.commit_id.len())],
                        change.status,
                        change.start_line.unwrap_or_default(),
                        change.end_line.unwrap_or_default(),
                        change.message
                    );
                }
                println!("Historische Callsigns sind keine verifizierte Identitätsaussage.");
            }
        }

        Commands::Heatmap {
            limit,
            top,
            json,
            workspace,
            all,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "{} Repository konnte nicht geöffnet werden: {e}",
                        "FEHLER:".red()
                    );
                    std::process::exit(1);
                }
            };

            let filter = load_analysis_filter(&root, all);
            let report = match engine.heatmap(limit, &filter) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} Heatmap-Berechnung fehlgeschlagen: {e}", "FEHLER:".red());
                    std::process::exit(1);
                }
            };

            if json {
                print_json_envelope("heatmap", &report);
                return;
            }

            println!(
                "\n{}",
                "=== S&B Code · AST Scope Heatmap & Churn Analyse ==="
                    .cyan()
                    .bold()
            );
            if filter.rule_count() > 0 {
                println!(
                    "{}",
                    format!(
                        ".sbignore aktiv ({} Regeln, --all zum Deaktivieren)",
                        filter.rule_count()
                    )
                    .bright_black()
                );
            }
            println!(
                "Analysierte Commits: {} | Getrackte AST-Scopes: {}",
                report.commits_analyzed.to_string().yellow().bold(),
                report.total_scopes_tracked.to_string().cyan()
            );

            println!(
                "\n{}",
                "── Top Geänderte Funktionen & Scopes (Code Churn) ────".bright_black()
            );
            if report.hot_scopes.is_empty() {
                println!("  Keine Änderungen in den analysierten Commits festgestellt.");
            } else {
                let max_changes = report
                    .hot_scopes
                    .first()
                    .map(|s| s.change_count)
                    .unwrap_or(1)
                    .max(1);
                for s in report.hot_scopes.iter().take(top) {
                    let bar_len =
                        ((s.change_count as f64 / max_changes as f64) * 8.0).round() as usize;
                    let filled_bar = "█".repeat(bar_len);
                    let empty_bar = "░".repeat(8usize.saturating_sub(bar_len));
                    let bar_display = format!("[{filled_bar}{empty_bar}]");
                    let colored_bar = if s.change_count >= 3 {
                        bar_display.red()
                    } else if s.change_count == 2 {
                        bar_display.yellow()
                    } else {
                        bar_display.green()
                    };

                    println!(
                        "  {:<8} {:<24} {:<10} {:>2}x geändert {}  {}",
                        s.status,
                        s.name.bold(),
                        format!("({})", s.kind).bright_black(),
                        s.change_count.to_string().cyan(),
                        colored_bar,
                        s.file_path.bright_black()
                    );
                }
            }

            println!(
                "\n{}",
                "── Hotspot-Dateien ───────────────────────────────────".bright_black()
            );
            for f in report.hot_files.iter().take(10) {
                println!(
                    "  • {:>2}x Commits  {}",
                    f.change_count.to_string().yellow().bold(),
                    f.file_path
                );
            }
            println!();
        }

        Commands::Coupling {
            file,
            limit,
            min,
            json,
            workspace,
            all,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "{} Repository konnte nicht geöffnet werden: {e}",
                        "FEHLER:".red()
                    );
                    std::process::exit(1);
                }
            };

            let filter = load_analysis_filter(&root, all);
            let report = match engine.coupling(limit, file.as_deref(), min.max(1), &filter) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} Kopplungsanalyse fehlgeschlagen: {e}", "FEHLER:".red());
                    std::process::exit(1);
                }
            };

            if json {
                print_json_envelope("coupling", &report);
                return;
            }

            println!(
                "\n{}",
                "=== S&B Code · Logische Kopplung (Co-Change Analyse) ==="
                    .cyan()
                    .bold()
            );
            if filter.rule_count() > 0 {
                println!(
                    "{}",
                    format!(
                        ".sbignore aktiv ({} Regeln, --all zum Deaktivieren)",
                        filter.rule_count()
                    )
                    .bright_black()
                );
            }
            println!(
                "Analysierte Commits: {} | Mindest-Co-Changes: {}{}",
                report.commits_analyzed.to_string().yellow().bold(),
                min.max(1).to_string().cyan(),
                report
                    .target_filter
                    .as_ref()
                    .map(|f| format!(" | Filter: {}", f.bold()))
                    .unwrap_or_default()
            );

            if report.couplings.is_empty() {
                println!("\n  Keine signifikanten Kopplungen gefunden.\n");
                return;
            }

            println!(
                "\n{}",
                "── Gekoppelte Dateien ────────────────────────────────".bright_black()
            );
            for c in report.couplings.iter().take(25) {
                let max_conf = c.confidence_a_to_b.max(c.confidence_b_to_a);
                let badge = if max_conf >= 0.8 {
                    "STARK ".red().bold()
                } else if max_conf >= 0.5 {
                    "MITTEL".yellow().bold()
                } else {
                    "SCHWACH".green()
                };
                println!(
                    "  {badge} {:>3}x gemeinsam  {}  ⇄  {}",
                    c.co_changes.to_string().cyan(),
                    c.file_a.bold(),
                    c.file_b.bold()
                );
                println!(
                    "         {} → {}: {:>3.0}%   |   {} → {}: {:>3.0}%",
                    short_name(&c.file_a).bright_black(),
                    short_name(&c.file_b).bright_black(),
                    c.confidence_a_to_b * 100.0,
                    short_name(&c.file_b).bright_black(),
                    short_name(&c.file_a).bright_black(),
                    c.confidence_b_to_a * 100.0
                );
            }

            if let Some(top) = report
                .couplings
                .iter()
                .find(|c| c.confidence_a_to_b.max(c.confidence_b_to_a) >= 0.8)
            {
                println!(
                    "\n{} Wird '{}' geändert, sollte '{}' mitgeprüft werden (historisch eng gekoppelt).",
                    "TIPP:".yellow().bold(),
                    top.file_a,
                    top.file_b
                );
            }
            println!();
        }

        Commands::Diff {
            file,
            json,
            scopes,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };
            if scopes {
                let scope_changes = engine.diff_scopes(file.as_deref()).unwrap_or_else(|error| {
                    eprintln!("{} AST-Diff fehlgeschlagen: {error}", "FEHLER:".red());
                    std::process::exit(1);
                });
                if json {
                    print_json_envelope("diff_scopes", &scope_changes);
                } else if scope_changes.is_empty() {
                    println!("{}", "Keine AST-Scope-Änderungen.".green());
                } else {
                    for change in scope_changes {
                        println!(
                            "{:<8} {}::{}  HEAD {:?}-{:?} → Arbeitsstand {:?}-{:?}",
                            change.status,
                            change.file_path,
                            change.name,
                            change.old_start_line,
                            change.old_end_line,
                            change.new_start_line,
                            change.new_end_line
                        );
                    }
                }
                return;
            }
            if let Some(target_file) = file {
                let diff = engine.diff_file(&target_file).unwrap_or_else(|error| {
                    eprintln!("{} {error}", "FEHLER:".red());
                    std::process::exit(1);
                });
                if json {
                    print_json_envelope("diff", &diff);
                    return;
                }
                {
                    let diff = Ok::<_, String>(diff);
                    match diff {
                        Ok(diff) => {
                            println!(
                                "\n{} Diff für '{}' (Status: {}):",
                                "►".cyan().bold(),
                                diff.rel_path.bold(),
                                diff.status.yellow()
                            );
                            for line in &diff.lines {
                                match line.change_type.as_str() {
                                    "+" => println!("{}", format!("+ {}", line.text).green()),
                                    "-" => println!("{}", format!("- {}", line.text).red()),
                                    _ => println!("  {}", line.text.bright_black()),
                                }
                            }
                            println!();
                        }
                        Err(e) => {
                            eprintln!("{} {}", "FEHLER:".red(), e);
                            std::process::exit(1);
                        }
                    }
                }
            } else {
                let st = engine.status().unwrap_or_else(|error| {
                    eprintln!("{} {error}", "FEHLER:".red());
                    std::process::exit(1);
                });
                let diffs = st
                    .changes
                    .iter()
                    .map(|change| engine.diff_file(&change.rel_path))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap_or_else(|error| {
                        eprintln!("{} {error}", "FEHLER:".red());
                        std::process::exit(1);
                    });
                if json {
                    print_json_envelope("diff", &serde_json::json!({"status": st, "files": diffs}));
                    return;
                }
                {
                    if st.is_clean {
                        println!("{}", "Keine Änderungen im Arbeitsverzeichnis.".green());
                    } else {
                        for diff in &diffs {
                            {
                                println!(
                                    "\n{} --- a/{} +++ b/{}",
                                    "diff --git".bold(),
                                    diff.rel_path,
                                    diff.rel_path
                                );
                                for line in &diff.lines {
                                    match line.change_type.as_str() {
                                        "+" => println!("{}", format!("+ {}", line.text).green()),
                                        "-" => {
                                            println!("{}", format!("- {}", line.text).red())
                                        }
                                        _ => println!("  {}", line.text.bright_black()),
                                    }
                                }
                            }
                        }
                        println!();
                    }
                }
            }
        }

        Commands::Branch { name, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };
            if let Some(new_branch) = name {
                match engine.create_branch(&new_branch) {
                    Ok(_) => println!(
                        "{} Branch '{}' erfolgreich erstellt.",
                        "✓".green().bold(),
                        new_branch.cyan().bold()
                    ),
                    Err(e) => {
                        eprintln!("{} {}", "FEHLER:".red(), e);
                        std::process::exit(1);
                    }
                }
            } else {
                match engine.branch_list() {
                    Ok(branches) => {
                        let current = engine.current_branch().unwrap_or_default();
                        println!("\n{}", "Sovereign Branches:".cyan().bold());
                        for b in branches {
                            if b == current {
                                println!("* {}", b.green().bold());
                            } else {
                                println!("  {}", b);
                            }
                        }
                        println!();
                    }
                    Err(e) => {
                        eprintln!("{} {}", "FEHLER:".red(), e);
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Checkout { target, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };
            match engine.checkout(&target) {
                Ok(_) => println!(
                    "{} Erfolgreich zu '{}' gewechselt.",
                    "✓".green().bold(),
                    target.cyan().bold()
                ),
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Rollback {
            steps,
            to,
            file,
            force,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };
            match engine.rollback(steps, to.as_deref(), file.as_deref(), force) {
                Ok(report) => {
                    println!(
                        "\n{} Rollback erfolgreich durchgeführt:",
                        "✓".green().bold()
                    );
                    println!("  Branch:          {}", report.branch.yellow().bold());
                    println!(
                        "  Vorheriger HEAD: {}",
                        report.previous_commit_id[..8.min(report.previous_commit_id.len())]
                            .bright_black()
                    );
                    println!(
                        "  Neuer HEAD:      {}",
                        report.target_commit_id[..8.min(report.target_commit_id.len())]
                            .cyan()
                            .bold()
                    );
                    if let Some(f) = report.single_file {
                        println!("  Datei:           {}", f.bold());
                    }
                    println!("  Status:          {}\n", report.message.green());
                }
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Ghost {
            other,
            scope,
            json,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(engine) => engine,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            match engine.compare_branch_scopes(&other) {
                Ok(comparison) => {
                    let changes = comparison
                        .changes
                        .iter()
                        .filter(|change| {
                            scope.as_ref().map_or(true, |filter| {
                                change.name.contains(filter) || change.scope_id.contains(filter)
                            })
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    if json {
                        print_json_envelope(
                            "ghost",
                            &serde_json::json!({
                                "current_branch": comparison.current_branch,
                                "other_branch": comparison.other_branch,
                                "base_commit": comparison.base_commit,
                                "current_commit": comparison.current_commit,
                                "other_commit": comparison.other_commit,
                                "changes": changes,
                                "semantic_compatibility": "not_verified",
                            }),
                        );
                        return;
                    }
                    println!(
                        "\n{} {} ⇄ {} (gemeinsame Basis: {})",
                        "AST Ghost Image:".cyan().bold(),
                        comparison.current_branch.yellow(),
                        comparison.other_branch.yellow(),
                        &comparison.base_commit[..8]
                    );
                    if changes.is_empty() {
                        println!("  Keine abweichenden AST-Scopes gefunden.");
                    }
                    for change in &changes {
                        println!(
                            "\n  {} {} [{}]",
                            change.name.bold(),
                            change.file_path,
                            change.status
                        );
                        if let Some(base) = &change.base {
                            println!("  --- gemeinsame Basis\n{base}");
                        }
                        if let Some(current) = &change.current {
                            println!("  +++ {}\n{current}", comparison.current_branch);
                        }
                        if let Some(ghost) = &change.other {
                            println!("  👻 +++ {}\n{ghost}", comparison.other_branch);
                        }
                    }
                    println!("\n  Ghost-Vergleich ist statisch; semantische Kompatibilität ist nicht garantiert.\n");
                }
                Err(error) => {
                    eprintln!(
                        "{} AST-Vergleich fehlgeschlagen: {}",
                        "FEHLER:".red(),
                        error
                    );
                    std::process::exit(1);
                }
            }
        }

        Commands::Plan {
            other,
            json,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(engine) => engine,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            match engine.plan_branch_integration(&other) {
                Ok(plan) if json => print_json_envelope("plan", &plan),
                Ok(plan) => {
                    println!(
                        "\n{} {} ⇄ {}",
                        "AST Integration Plan:".cyan().bold(),
                        plan.current_branch.yellow(),
                        plan.other_branch.yellow()
                    );
                    println!(
                        "Basis: {} | Current: {} | Other: {}",
                        &plan.base_commit[..8],
                        &plan.current_commit[..8],
                        &plan.other_commit[..8]
                    );
                    for entry in &plan.auto_mergeable {
                        println!(
                            "  {} {} [{}] — {}",
                            "AUTO".green().bold(),
                            entry.change.name,
                            entry.action,
                            entry.reason
                        );
                    }
                    for entry in &plan.manual_required {
                        println!(
                            "  {} {} [{}] — {}",
                            "MANUAL".yellow().bold(),
                            entry.change.name,
                            entry.change.status,
                            entry.reason
                        );
                    }
                    for reason in &plan.blocked_reasons {
                        println!("  {} {reason}", "BLOCKED:".red().bold());
                    }
                    if !plan.test_scope_candidates.is_empty() {
                        println!(
                            "Mögliche Test-Scopes (heuristisch): {}",
                            plan.test_scope_candidates.join(", ")
                        );
                    }
                    println!("{}", plan.semantic_validation);
                    println!(
                        "Anwendbar: {}\n",
                        if plan.ready_to_integrate {
                            "ja"
                        } else {
                            "nein"
                        }
                    );
                    if !plan.ready_to_integrate {
                        std::process::exit(1);
                    }
                }
                Err(error) => {
                    eprintln!("{} Planerstellung fehlgeschlagen: {error}", "FEHLER:".red());
                    std::process::exit(1);
                }
            }
        }

        Commands::Integrate { other, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut engine = match VcsEngine::open(&root) {
                Ok(engine) => engine,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            match engine.integrate_branch_scopes(&other, &get_active_callsign()) {
                Ok(commit) => println!(
                    "{} Branch '{}' integriert. Merge-Commit: {}",
                    "✓".green().bold(),
                    other.cyan().bold(),
                    commit.commit_id
                ),
                Err(error) => {
                    eprintln!("{} Integration abgebrochen: {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            }
        }

        Commands::Conflicts { action } => {
            let workspace = match &action {
                ConflictAction::Begin { workspace, .. }
                | ConflictAction::List { workspace }
                | ConflictAction::Resolve { workspace, .. }
                | ConflictAction::Finalize { workspace }
                | ConflictAction::Discard { workspace } => workspace.clone().unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                }),
            };
            let mut engine = match VcsEngine::open(&workspace) {
                Ok(engine) => engine,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            let result = match action {
                ConflictAction::Begin { other, .. } => {
                    engine.prepare_integration_conflicts(&other).map(|state| {
                        println!(
                            "Persistierte {} Scope-Konflikte für {} ⇄ {} in .sb/conflicts.json",
                            state.conflicts.len(),
                            state.current_branch,
                            state.other_branch
                        );
                        for conflict in state.conflicts {
                            println!(
                                "  {} [{}]",
                                conflict.entry.change.scope_id, conflict.entry.change.status
                            );
                        }
                    })
                }
                ConflictAction::List { .. } => engine.integration_conflicts().and_then(|state| {
                    let state =
                        state.ok_or_else(|| "No pending integration conflicts".to_string())?;
                    println!(
                        "Pending integration: {} ⇄ {} (base {})",
                        state.current_branch, state.other_branch, state.base_commit
                    );
                    for conflict in state.conflicts {
                        println!(
                            "\n{} [{}] resolution={}",
                            conflict.entry.change.scope_id,
                            conflict.entry.change.status,
                            conflict
                                .resolution
                                .as_ref()
                                .map(|resolution| format!("{resolution:?}").to_lowercase())
                                .unwrap_or_else(|| "pending".to_string())
                        );
                        println!(
                            "--- base\n{}",
                            conflict.entry.change.base.as_deref().unwrap_or("(absent)")
                        );
                        println!(
                            "--- current\n{}",
                            conflict
                                .entry
                                .change
                                .current
                                .as_deref()
                                .unwrap_or("(absent)")
                        );
                        println!(
                            "--- other\n{}",
                            conflict.entry.change.other.as_deref().unwrap_or("(absent)")
                        );
                    }
                    Ok(())
                }),
                ConflictAction::Resolve {
                    scope_id, choice, ..
                } => {
                    let resolution = match choice.as_str() {
                        "current" => vcs::ConflictResolution::Current,
                        "other" => vcs::ConflictResolution::Other,
                        _ => unreachable!("clap validates the conflict resolution"),
                    };
                    engine
                        .resolve_integration_conflict(&scope_id, resolution)
                        .map(|state| {
                            println!(
                                "Resolved '{}' from {}; {}/{} decisions complete.",
                                scope_id,
                                choice,
                                state
                                    .conflicts
                                    .iter()
                                    .filter(|item| item.resolution.is_some())
                                    .count(),
                                state.conflicts.len()
                            );
                        })
                }
                ConflictAction::Finalize { .. } => engine
                    .finalize_integration_conflicts(&get_active_callsign())
                    .map(|commit| {
                        println!("Integration finalized: {}", commit.commit_id);
                    }),
                ConflictAction::Discard { .. } => {
                    engine.discard_integration_conflicts().map(|removed| {
                        if removed {
                            println!("Persistierter Integrationskonflikt verworfen.");
                        } else {
                            println!("Kein persistierter Integrationskonflikt vorhanden.");
                        }
                    })
                }
            };
            if let Err(error) = result {
                eprintln!("{} Conflict operation failed: {}", "FEHLER:".red(), error);
                std::process::exit(1);
            }
        }

        Commands::Workspace { action } => {
            let repository_root = match &action {
                WorkspaceAction::Add { workspace, .. }
                | WorkspaceAction::List { workspace }
                | WorkspaceAction::Remove { workspace, .. }
                | WorkspaceAction::Prune { workspace } => workspace.clone().unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                }),
            };
            let engine = match VcsEngine::open(&repository_root) {
                Ok(engine) => engine,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            let result = match action {
                WorkspaceAction::Add { branch, path, .. } => engine
                    .add_managed_workspace(&branch, &path)
                    .map(|workspace| {
                        println!("Managed Workspace erstellt:");
                        println!("  Pfad:   {}", workspace.path.display());
                        println!("  Branch: {}", workspace.branch);
                        println!("  VCS:    {}", workspace.repository_vcs_dir.display());
                        println!(
                            "  Ports:  code={} drive={} ast-lock={} dev-server={}",
                            workspace.ports.code_sync,
                            workspace.ports.drive_sync,
                            workspace.ports.ast_lock_sync,
                            workspace.ports.dev_server
                        );
                    }),
                WorkspaceAction::Remove { path, force, .. } => engine
                    .remove_managed_workspace(&path, force)
                    .map(|()| println!("Managed Workspace entfernt: {}", path.display())),
                WorkspaceAction::List { .. } => engine.managed_workspaces().map(|workspaces| {
                    if workspaces.is_empty() {
                        println!("Keine Managed Workspaces registriert.");
                    }
                    for workspace in workspaces {
                        println!(
                            "{} [{}] code={} drive={} ast-lock={} dev-server={}",
                            workspace.path.display(),
                            workspace.branch,
                            workspace.ports.code_sync,
                            workspace.ports.drive_sync,
                            workspace.ports.ast_lock_sync,
                            workspace.ports.dev_server
                        );
                    }
                }),
                WorkspaceAction::Prune { .. } => engine.prune_managed_workspaces().map(|paths| {
                    if paths.is_empty() {
                        println!("Keine verwaisten Workspace-Registrierungen gefunden.");
                    } else {
                        for path in &paths {
                            println!("Verwaisten Workspace-Eintrag entfernt: {}", path.display());
                        }
                    }
                }),
            };
            if let Err(error) = result {
                eprintln!("{} Workspace operation failed: {}", "FEHLER:".red(), error);
                std::process::exit(1);
            }
        }

        Commands::Push {
            source_mesh,
            target_mesh,
            anchor_addr,
            capability_token,
            branch,
            service_port,
            workspace_id,
            node_id,
            expected_head,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };
            let target_branch = match branch {
                Some(branch) => branch,
                None => match engine.current_branch() {
                    Ok(branch) => branch,
                    Err(error) => {
                        eprintln!(
                            "{} Branch konnte nicht aufgelöst werden: {}",
                            "FEHLER:".red(),
                            error
                        );
                        std::process::exit(1);
                    }
                },
            };
            let token = match mesh_sync::read_capability_token(capability_token.as_deref()) {
                Ok(token) => token,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            let caller = node_id.unwrap_or_else(get_active_callsign);
            match mesh_sync::push_workspace_on_port(
                &engine,
                &source_mesh,
                &target_mesh,
                anchor_addr,
                service_port,
                &target_branch,
                workspace_id.as_deref(),
                Some(&caller),
                expected_head.as_deref(),
                token,
            )
            .await
            {
                Ok(report) => {
                    println!("{} Mesh Push erfolgreich!", "✓".green().bold());
                    if let Some(ref wid) = workspace_id {
                        println!("  Workspace:  {}", wid.cyan().bold());
                    }
                    println!("  Ziel-Mesh:  {}", report.anchor.cyan());
                    println!("  Branch:     {}", report.branch.yellow().bold());
                    println!(
                        "  Commits:    {}",
                        report.commits_synced.to_string().green()
                    );
                    println!("  Blobs:      {}", report.blobs_synced.to_string().green());
                    println!("  Neuer HEAD: {}", report.new_head.yellow());
                }
                Err(e) => {
                    eprintln!("{} Push fehlgeschlagen: {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Pull {
            source_mesh,
            target_mesh,
            anchor_addr,
            capability_token,
            branch,
            service_port,
            workspace_id,
            node_id,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };
            let target_branch = match branch {
                Some(branch) => branch,
                None => match engine.current_branch() {
                    Ok(branch) => branch,
                    Err(error) => {
                        eprintln!(
                            "{} Branch konnte nicht aufgelöst werden: {}",
                            "FEHLER:".red(),
                            error
                        );
                        std::process::exit(1);
                    }
                },
            };
            let token = match mesh_sync::read_capability_token(capability_token.as_deref()) {
                Ok(token) => token,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            let caller = node_id.unwrap_or_else(get_active_callsign);
            match mesh_sync::pull_workspace_on_port(
                &mut engine,
                &source_mesh,
                &target_mesh,
                anchor_addr,
                service_port,
                &target_branch,
                workspace_id.as_deref(),
                Some(&caller),
                token,
            )
            .await
            {
                Ok(report) => {
                    println!("{} Mesh Pull erfolgreich!", "✓".green().bold());
                    if let Some(ref wid) = workspace_id {
                        println!("  Workspace:  {}", wid.cyan().bold());
                    }
                    println!("  Ziel-Mesh:  {}", report.anchor.cyan());
                    println!("  Branch:     {}", report.branch.yellow().bold());
                    println!(
                        "  Commits:    {}",
                        report.commits_synced.to_string().green()
                    );
                    println!("  Blobs:      {}", report.blobs_synced.to_string().green());
                    println!("  Neuer HEAD: {}", report.new_head.yellow());
                }
                Err(e) => {
                    eprintln!("{} Pull fehlgeschlagen: {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::DevWorkspace { action } => match action {
            DevWorkspaceAction::Register {
                id,
                project,
                path,
                writer,
                replicas,
                registry,
            } => {
                let reg_path = registry.unwrap_or_else(|| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".sb")
                        .join("dev_workspaces.json")
                });
                let mut reg = crate::dev_workspace::DevWorkspaceRegistry::load_from_file(&reg_path)
                    .unwrap_or_default();
                let policy = match crate::dev_workspace::DevWorkspacePolicy::new(
                    &id, &project, &writer, replicas,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{} {}", "FEHLER:".red(), e);
                        std::process::exit(1);
                    }
                };
                let entry = crate::dev_workspace::DevWorkspaceEntry {
                    workspace_id: id.clone(),
                    repo_path: path,
                    policy,
                };
                if let Err(e) = reg.register(entry) {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
                if let Err(e) = reg.save_to_file(&reg_path) {
                    eprintln!("{} Konnte Registry nicht speichern: {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
                println!(
                    "{} Dev-Mesh-Workspace '{}' erfolgreich registriert.",
                    "✓".green().bold(),
                    id.cyan()
                );
            }
            DevWorkspaceAction::List { registry } => {
                let reg_path = registry.unwrap_or_else(|| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".sb")
                        .join("dev_workspaces.json")
                });
                let reg = crate::dev_workspace::DevWorkspaceRegistry::load_from_file(&reg_path)
                    .unwrap_or_default();
                println!(
                    "\n{}",
                    "═══ Registrierte Dev-Mesh Workspaces ═══".cyan().bold()
                );
                if reg.workspaces.is_empty() {
                    println!("  Keine Workspaces registriert.");
                } else {
                    for (id, entry) in &reg.workspaces {
                        println!(
                            "  • {:<24} (Projekt: {}, Writer: {})",
                            id.green().bold(),
                            entry.policy.project_name.yellow(),
                            entry.policy.authoritative_writer.cyan()
                        );
                        println!(
                            "    Pfad:      {}",
                            entry.repo_path.display().to_string().dimmed()
                        );
                        println!("    Replicas:  {:?}", entry.policy.allowed_replicas);
                    }
                }
                println!();
            }
            DevWorkspaceAction::Policy { id, registry } => {
                let reg_path = registry.unwrap_or_else(|| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".sb")
                        .join("dev_workspaces.json")
                });
                let reg =
                    match crate::dev_workspace::DevWorkspaceRegistry::load_from_file(&reg_path) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("{} {}", "FEHLER:".red(), e);
                            std::process::exit(1);
                        }
                    };
                match reg.get(&id) {
                    Some(entry) => {
                        println!(
                            "\n{}",
                            format!("═══ Dev-Mesh Workspace Policy: {} ═══", id)
                                .cyan()
                                .bold()
                        );
                        println!(
                            "  Workspace ID:         {}",
                            entry.policy.workspace_id.green()
                        );
                        println!(
                            "  Projekt:              {}",
                            entry.policy.project_name.yellow()
                        );
                        println!(
                            "  Authoritative Writer: {}",
                            entry.policy.authoritative_writer.bold().cyan()
                        );
                        println!(
                            "  Allowed Replicas:     {:?}",
                            entry.policy.allowed_replicas
                        );
                        println!(
                            "  Fast-Forward Zwang:   {}",
                            entry.policy.require_fast_forward
                        );
                        println!("  Policy-Version:       {}", entry.policy.policy_version);
                        println!();
                    }
                    None => {
                        eprintln!("{} Workspace '{}' nicht gefunden.", "FEHLER:".red(), id);
                        std::process::exit(1);
                    }
                }
            }
            DevWorkspaceAction::Syncd { registry, bind } => {
                let reg_path = registry.unwrap_or_else(|| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".sb")
                        .join("dev_workspaces.json")
                });
                if let Err(e) = mesh_sync::run_multi_syncd(reg_path, bind).await {
                    eprintln!(
                        "{} Multi-Workspace syncd fehlgeschlagen: {}",
                        "FEHLER:".red(),
                        e
                    );
                    std::process::exit(1);
                }
            }
        },

        Commands::Serve {
            mesh,
            source_mesh,
            bind,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            // CVE-Threat: Exposing the sync endpoint beyond loopback / unauthenticated cross-mesh route.
            // Hardening: loopback-only bind enforced; route is explicit source->target (no wildcard).
            if !bind.ip().is_loopback() {
                eprintln!("{} syncd darf nur an Loopback binden.", "FEHLER:".red());
                std::process::exit(1);
            }
            if let Err(error) = VcsEngine::open(&root) {
                eprintln!(
                    "{} {} (zuerst 'sb-code init' im Workspace ausführen)",
                    "FEHLER:".red(),
                    error
                );
                std::process::exit(1);
            }
            let source = source_mesh.unwrap_or_else(|| mesh.clone());
            println!("[1/3] Route {} -> {} (Port 58832)", source, mesh);
            match std::process::Command::new("sb-node")
                .args(["route", "add-code", "--source-mesh", &source, "--target-mesh", &mesh])
                .status()
            {
                Ok(s) if s.success() => {}
                _ => eprintln!(
                    "{} Route nicht gesetzt. Manuell: sb-node route add-code --source-mesh {} --target-mesh {}",
                    "WARNUNG:".yellow(),
                    source,
                    mesh
                ),
            }
            println!(
                "[2/3] Mitglieder, die pushen/pullen sollen, benötigen die Capabilities stream:transfer und code:sync (Rolle Developer enthält stream:transfer)."
            );
            println!("[3/3] Starte syncd auf {} ...", bind);
            if let Err(error) = mesh_sync::run_syncd(root, bind).await {
                eprintln!("{} syncd fehlgeschlagen: {}", "FEHLER:".red(), error);
                std::process::exit(1);
            }
        }

        Commands::Syncd { bind, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let default_bind: SocketAddr = "127.0.0.1:58832"
                .parse()
                .expect("valid default sync endpoint");
            let bind = if bind == default_bind {
                match VcsEngine::open(&root) {
                    Ok(engine) => engine
                        .assigned_workspace_ports()
                        .map(|ports| SocketAddr::from(([127, 0, 0, 1], ports.code_sync)))
                        .unwrap_or(bind),
                    Err(error) => {
                        eprintln!("{} {}", "FEHLER:".red(), error);
                        std::process::exit(1);
                    }
                }
            } else {
                bind
            };
            if let Err(error) = mesh_sync::run_syncd(root, bind).await {
                eprintln!("{} syncd fehlgeschlagen: {}", "FEHLER:".red(), error);
                std::process::exit(1);
            }
        }

        Commands::Web { .. } => {
            eprintln!(
                "{} Der Skel-basierte Webviewer wurde im Rahmen der Kern-Konsolidierung entfernt.",
                "HINWEIS:".yellow()
            );
            std::process::exit(0);
        }

        Commands::WebProxy {
            source_mesh,
            target_mesh,
            anchor_addr,
            listen,
            workspace,
            capability_token,
            service_port,
        } => {
            if let Err(error) = web::run_mesh_proxy(
                &source_mesh,
                &target_mesh,
                anchor_addr,
                listen,
                workspace,
                capability_token,
                service_port,
            )
            .await
            {
                eprintln!(
                    "{} Webviewer-Tunnel fehlgeschlagen: {error}",
                    "FEHLER:".red()
                );
                std::process::exit(1);
            }
        }

        Commands::RemoteStatus {
            anchor,
            branch,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("{} {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };
            let anchor_name = anchor.unwrap_or_else(|| "hetzner-anchor".to_string());
            let target_branch = branch.unwrap_or_else(|| {
                engine
                    .current_branch()
                    .unwrap_or_else(|_| "main".to_string())
            });
            match engine.get_remote_status(&anchor_name, &target_branch) {
                Ok(status) => {
                    println!(
                        "\n{}",
                        "=== S&B Code · Swarm Synchronisationsstatus ==="
                            .cyan()
                            .bold()
                    );
                    println!("  Anchor:         {}", status.anchor.cyan());
                    println!("  Branch:         {}", status.branch.yellow().bold());
                    println!(
                        "  Lokaler HEAD:   {}",
                        status.local_head.as_deref().unwrap_or("<none>")
                    );
                    println!(
                        "  Remote HEAD:    {}",
                        status.remote_head.as_deref().unwrap_or("<none>")
                    );
                    if status.in_sync {
                        println!(
                            "  Status:         {}",
                            "Vollständig synchronisiert ✓".green().bold()
                        );
                    } else {
                        println!(
                            "  Voraus:         {} Commits",
                            status.ahead.to_string().yellow()
                        );
                        println!(
                            "  Hinterher:      {} Commits",
                            status.behind.to_string().red()
                        );
                    }
                    println!();
                }
                Err(e) => {
                    eprintln!("{} Statusabfrage fehlgeschlagen: {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Divergence {
            source_mesh,
            target_mesh,
            anchor_addr,
            capability_token,
            service_port,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(engine) => engine,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            let token = match mesh_sync::read_capability_token(capability_token.as_deref()) {
                Ok(token) => token,
                Err(error) => {
                    eprintln!("{} {}", "FEHLER:".red(), error);
                    std::process::exit(1);
                }
            };
            match mesh_sync::branch_divergence_on_port(
                &engine,
                &source_mesh,
                &target_mesh,
                anchor_addr,
                service_port,
                token,
            )
            .await
            {
                Ok(report) if report.remote_branch_count == 0 => {
                    println!("Remote syncd meldet keine Branches.");
                }
                Ok(report) if report.divergences.is_empty() => {
                    println!(
                        "Alle {} Remote-Branch-Heads sind mit dem lokalen Repository synchron.",
                        report.remote_branch_count
                    );
                }
                Ok(report) => {
                    for divergence in report.divergences {
                        println!(
                            "\nBranch {}: local={} remote={}",
                            divergence.branch.cyan().bold(),
                            divergence.local_head.as_deref().unwrap_or("<missing>"),
                            divergence.remote_head
                        );
                        if let (Some(local), Some(remote)) =
                            (divergence.local_commits, divergence.remote_commits)
                        {
                            println!("  Divergenz: {local} lokale / {remote} Remote-Commits");
                        }
                        for scope in divergence.overlapping_scopes {
                            println!(
                                "  WARNUNG: Beide Seiten änderten {} [{}]",
                                scope.scope_id.yellow().bold(),
                                scope.file_path
                            );
                        }
                        if let Some(note) = divergence.comparison_note {
                            println!("  Hinweis: {note}");
                        }
                    }
                }
                Err(error) => {
                    eprintln!(
                        "{} Mesh-Divergenzabfrage fehlgeschlagen: {error}",
                        "FEHLER:".red()
                    );
                    std::process::exit(1);
                }
            }
        }

        Commands::Scopes { file, json } => {
            if !file.exists() {
                eprintln!(
                    "{} Datei '{}' existiert nicht.",
                    "FEHLER:".red(),
                    file.display()
                );
                std::process::exit(1);
            }
            let content = match std::fs::read_to_string(&file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{} Kann Datei nicht lesen: {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };

            let scopes = match ast::parse_live_ast_scopes(&file.to_string_lossy(), &content) {
                Ok(scopes) => scopes,
                Err(error) => {
                    eprintln!(
                        "{} Parser konnte Scopes nicht bereitstellen: {}",
                        "FEHLER:".red(),
                        error
                    );
                    std::process::exit(1);
                }
            };

            if json {
                print_json_envelope("scopes", &scopes);
                return;
            }

            println!(
                "\n{} AST-Scopes in '{}':",
                "►".cyan().bold(),
                file.display()
            );
            for s in &scopes {
                let container_badge = if s.is_container {
                    " [CONTAINER - UNLOCKED]".yellow()
                } else {
                    " [ISOLATED SCOPE]".green()
                };
                println!(
                    "  • {:<12} {:<24} (Zeilen {}-{}){}",
                    format!("{}", s.kind).cyan(),
                    s.name.bold(),
                    s.start_line,
                    s.end_line,
                    container_badge
                );
            }
            println!();
        }

        Commands::Context {
            file,
            target,
            repo,
            padding,
            json,
            max_chars,
            workspace,
        } => {
            if repo {
                let root = workspace.unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                let engine = VcsEngine::open(&root).unwrap_or_else(|error| {
                    eprintln!(
                        "{} Repository konnte nicht geöffnet werden: {error}",
                        "FEHLER:".red()
                    );
                    std::process::exit(1);
                });
                let context =
                    build_repository_context(&engine, max_chars).unwrap_or_else(|error| {
                        eprintln!(
                            "{} Repository-Kontext fehlgeschlagen: {error}",
                            "FEHLER:".red()
                        );
                        std::process::exit(1);
                    });
                if json {
                    print_json_envelope("context", &context);
                } else {
                    print_repository_context(&context, max_chars);
                }
                return;
            }
            let file = file.unwrap_or_else(|| {
                eprintln!(
                    "{} Datei fehlt; nutze `context --repo` für Repository-Kontext.",
                    "FEHLER:".red()
                );
                std::process::exit(2);
            });
            let target = target.unwrap_or_else(|| {
                eprintln!("{} Scope-Ziel fehlt.", "FEHLER:".red());
                std::process::exit(2);
            });
            if !file.exists() {
                eprintln!(
                    "{} Datei '{}' existiert nicht.",
                    "FEHLER:".red(),
                    file.display()
                );
                std::process::exit(1);
            }
            let content = match std::fs::read_to_string(&file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{} Kann Datei nicht lesen: {}", "FEHLER:".red(), e);
                    std::process::exit(1);
                }
            };

            let scopes = match ast::parse_live_ast_scopes(&file.to_string_lossy(), &content) {
                Ok(s) => s,
                Err(error) => {
                    eprintln!(
                        "{} Parser konnte Scopes nicht analysieren: {}",
                        "FEHLER:".red(),
                        error
                    );
                    std::process::exit(1);
                }
            };

            let line_target = target.parse::<usize>().ok();
            let matched_scope = scopes.iter().find(|s| {
                if let Some(target_line) = line_target {
                    target_line >= s.start_line && target_line <= s.end_line
                } else {
                    s.name == target
                        || s.name.contains(&target)
                        || s.id.ends_with(&format!("::{target}"))
                }
            });

            let target_scope = match matched_scope {
                Some(s) => s,
                None => {
                    eprintln!(
                        "{} Kein AST-Scope für Ziel '{}' in '{}' gefunden.",
                        "FEHLER:".red(),
                        target,
                        file.display()
                    );
                    std::process::exit(1);
                }
            };

            let lines: Vec<&str> = content.lines().collect();
            let start_idx = target_scope
                .start_line
                .saturating_sub(1)
                .saturating_sub(padding);
            let end_idx = (target_scope.end_line + padding).min(lines.len());
            let snippet = if start_idx < end_idx && start_idx < lines.len() {
                lines[start_idx..end_idx].join("\n")
            } else {
                String::new()
            };

            // Sammle Imports als zusätzlichen Kontext
            let imports: Vec<String> = scopes
                .iter()
                .filter(|s| s.kind == ast::AstScopeKind::Imports)
                .filter_map(|s| {
                    let s_start = s.start_line.saturating_sub(1);
                    let s_end = s.end_line.min(lines.len());
                    if s_start < s_end && s_start < lines.len() {
                        Some(lines[s_start..s_end].join("\n"))
                    } else {
                        None
                    }
                })
                .collect();

            if json {
                let context_dto = serde_json::json!({
                    "file_path": file.to_string_lossy(),
                    "scope_id": target_scope.id,
                    "name": target_scope.name,
                    "kind": format!("{}", target_scope.kind),
                    "start_line": target_scope.start_line,
                    "end_line": target_scope.end_line,
                    "imports": imports,
                    "snippet": snippet,
                });
                print_json_envelope("context_scope", &context_dto);
            } else {
                println!(
                    "\n{} AST Context: {} ({}: {}-{}) in '{}'",
                    "►".cyan().bold(),
                    target_scope.name.bold(),
                    format!("{}", target_scope.kind).cyan(),
                    target_scope.start_line,
                    target_scope.end_line,
                    file.display()
                );
                if !imports.is_empty() {
                    println!(
                        "{}",
                        "── Imports ───────────────────────────────────────".bright_black()
                    );
                    for imp in &imports {
                        println!("{imp}");
                    }
                }
                println!(
                    "{}",
                    "── Scope Implementation ──────────────────────────".bright_black()
                );
                println!("{snippet}\n");
            }
        }

        Commands::Outline { file, json } => {
            let outline = match VcsEngine::outline(&file) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("{} {e}", "FEHLER:".red());
                    std::process::exit(1);
                }
            };

            if json {
                print_json_envelope("outline", &outline);
                return;
            }

            println!(
                "\n{} Modul: {} ({} Zeilen, {} Symbole)",
                "►".cyan().bold(),
                outline.file_path.bold(),
                outline.total_lines,
                outline.items.len()
            );

            // Tiefe über Container-Verschachtelung bestimmen (Stack der End-Zeilen offener Container).
            let mut items = outline.items.clone();
            items.sort_by_key(|i| (i.start_line, std::cmp::Reverse(i.end_line)));
            let mut open_containers: Vec<usize> = Vec::new();
            for item in &items {
                while open_containers
                    .last()
                    .is_some_and(|&end| item.start_line > end)
                {
                    open_containers.pop();
                }
                let depth = open_containers.len();
                let indent = "│   ".repeat(depth);
                let kind_badge = match item.kind.to_lowercase().as_str() {
                    k if k.contains("struct") || k.contains("enum") => {
                        format!("{:<9}", item.kind).magenta().bold()
                    }
                    k if k.contains("trait") || k.contains("impl") => {
                        format!("{:<9}", item.kind).blue().bold()
                    }
                    k if k.contains("fn") || k.contains("function") || k.contains("method") => {
                        format!("{:<9}", item.kind).green()
                    }
                    k if k.contains("mod") || k.contains("test") => {
                        format!("{:<9}", item.kind).yellow()
                    }
                    _ => format!("{:<9}", item.kind).cyan(),
                };
                let sig = item.signature.trim_end_matches('{').trim_end();
                println!(
                    "{}├── {} {}  {}",
                    indent.bright_black(),
                    kind_badge,
                    sig,
                    format!("[L{}-{}]", item.start_line, item.end_line).bright_black()
                );
                if item.is_container {
                    open_containers.push(item.end_line);
                }
            }
            println!();
        }

        Commands::Lock {
            file,
            target,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let file_path = if file.is_absolute() {
                file
            } else {
                root.join(&file)
            };

            if !file_path.is_file() {
                eprintln!(
                    "{} Datei '{}' existiert nicht.",
                    "FEHLER:".red().bold(),
                    file_path.display()
                );
                std::process::exit(1);
            }

            let content = match std::fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "{} Datei konnte nicht gelesen werden: {}",
                        "FEHLER:".red().bold(),
                        e
                    );
                    std::process::exit(1);
                }
            };

            let rel_path = file_path
                .strip_prefix(&root)
                .unwrap_or(&file_path)
                .to_string_lossy()
                .replace('\\', "/");
            let scopes = match ast::parse_live_ast_scopes(&rel_path, &content) {
                Ok(scopes) => scopes,
                Err(error) => {
                    eprintln!(
                        "{} Parser konnte Scopes nicht bereitstellen: {}",
                        "FEHLER:".red(),
                        error
                    );
                    std::process::exit(1);
                }
            };

            let scope = match ast::find_scope_by_name_or_line(&scopes, &target) {
                Some(s) => s,
                None => {
                    eprintln!(
                        "{} Kein passender AST-Scope für '{}' in '{}' gefunden.",
                        "FEHLER:".red().bold(),
                        target,
                        rel_path
                    );
                    println!("  Verfügbare Scopes in {}:", rel_path.cyan());
                    for s in &scopes {
                        println!(
                            "  • {:<12} {:<24} (Zeilen {}-{})",
                            format!("{}", s.kind).cyan(),
                            s.name.bold(),
                            s.start_line,
                            s.end_line
                        );
                    }
                    std::process::exit(1);
                }
            };

            if scope.is_container {
                println!("{} Scope '{}' ({}) ist ein Container. Container-Scopes werden nicht exklusiv gesperrt, damit Methoden darin parallel bearbeitet werden können.",
                    "INFO:".yellow().bold(), scope.name.bold(), scope.kind);
                return;
            }

            let my_callsign = get_active_callsign();
            let now_unix = chrono::Utc::now().timestamp();
            let mut lock_table = AstLockTable::load_from_workspace(&root);

            match lock_table.claim(scope, &my_callsign, now_unix) {
                Ok(_) => {
                    let _ = lock_table.save_to_workspace(&root);

                    // Snapshot baseline for this scope
                    let lines: Vec<&str> = content.lines().collect();
                    if scope.start_line > 0 && scope.start_line <= lines.len() {
                        let end = scope.end_line.min(lines.len());
                        let scope_code = lines[scope.start_line - 1..end].join("\n");
                        let mut baseline = baseline::BaselineCache::load_from_workspace(&root);
                        baseline.save_stable_scope(&scope.id, &scope_code);
                        let _ = baseline.save_to_workspace(&root);
                    }

                    println!("\n{}", "── S&B Sovereign AST-Scope Lock ──".bold().cyan());
                    println!("  {} AST-Scope erfolgreich gesperrt!", "✔".green().bold());
                    println!("  ► Scope ID:    {}", scope.id.bold().yellow());
                    println!("  ► Name:        {} ({})", scope.name.bold(), scope.kind);
                    println!("  ► Zeilen:      {}-{}", scope.start_line, scope.end_line);
                    println!("  ► Inhaber:     {}", my_callsign.bold().white());
                    println!("  ► Lease TTL:   180s (Automatisches Heartbeat bei Tastatureingabe)");
                    println!("  ► Shadow:      Stable Baseline Cache gesichert (.sb/baseline_cache.json)");
                    println!();
                }
                Err(e) => {
                    eprintln!("{} Sperrung fehlgeschlagen: {}", "FEHLER:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Unlock {
            file,
            target,
            workspace,
        } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let my_callsign = get_active_callsign();
            let mut lock_table = AstLockTable::load_from_workspace(&root);
            let rel_path = file.to_string_lossy().replace('\\', "/");

            let mut released = 0;
            if let Some(ref t) = target {
                let full_path = root.join(&file);
                let scope_id = if full_path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&full_path) {
                        ast::parse_live_ast_scopes(&rel_path, &content)
                            .ok()
                            .and_then(|scopes| {
                                ast::find_scope_by_name_or_line(&scopes, t)
                                    .map(|scope| scope.id.clone())
                            })
                    } else {
                        None
                    }
                } else {
                    None
                }
                .unwrap_or_else(|| {
                    if t.contains("::") {
                        t.clone()
                    } else {
                        format!("{}::{}", rel_path, t)
                    }
                });

                if let Some(lock) = lock_table.locks.get(&scope_id) {
                    if lock.locked_by == my_callsign {
                        lock_table.release(&scope_id, &my_callsign);
                        released += 1;
                        println!(
                            "  {} Lock auf '{}' freigegeben.",
                            "✔".green().bold(),
                            scope_id.yellow()
                        );
                    } else {
                        eprintln!(
                            "{} Scope '{}' ist von '{}' gesperrt, nicht von dir ({}).",
                            "FEHLER:".red().bold(),
                            scope_id,
                            lock.locked_by,
                            my_callsign
                        );
                        std::process::exit(1);
                    }
                } else {
                    println!(
                        "{} Kein aktiver Lock für '{}' gefunden.",
                        "INFO:".yellow().bold(),
                        scope_id
                    );
                }
            } else {
                let keys_to_release: Vec<String> = lock_table
                    .locks
                    .iter()
                    .filter(|(k, v)| k.starts_with(&rel_path) && v.locked_by == my_callsign)
                    .map(|(k, _)| k.clone())
                    .collect();

                for key in keys_to_release {
                    lock_table.release(&key, &my_callsign);
                    released += 1;
                    println!(
                        "  {} Lock auf '{}' freigegeben.",
                        "✔".green().bold(),
                        key.yellow()
                    );
                }
            }

            if released > 0 {
                let _ = lock_table.save_to_workspace(&root);
                println!(
                    "{} {} Lock(s) erfolgreich freigegeben.",
                    "✔".green().bold(),
                    released
                );
            } else if target.is_none() {
                println!(
                    "{} Keine aktiven Locks von '{}' in '{}' gefunden.",
                    "INFO:".yellow().bold(),
                    my_callsign,
                    rel_path
                );
            }
        }

        Commands::Locks { workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let lock_table = AstLockTable::load_from_workspace(&root);
            let now_unix = chrono::Utc::now().timestamp();
            let active_locks = lock_table.list_active_locks(now_unix);

            println!(
                "\n{}",
                "=== S&B Code · Aktive Swarm AST-Scope Locks ==="
                    .cyan()
                    .bold()
            );
            if active_locks.is_empty() {
                println!("  Keine aktiven Locks im Swarm. Alle AST-Scopes sind frei editierbar.\n");
            } else {
                println!(
                    "  {:<45} {:<16} {:<12} {}",
                    "AST-Scope ID".bold(),
                    "Inhaber".bold(),
                    "TTL Rest".bold(),
                    "Status".bold()
                );
                println!("  {}", "─".repeat(82).bright_black());
                for (lock, remaining_ttl) in active_locks {
                    let my_callsign = get_active_callsign();
                    let is_mine = lock.locked_by == my_callsign;
                    let status_badge = if is_mine {
                        "MEIN LOCK (EXCLUSIVE)".green().bold()
                    } else {
                        "GESPERRT (PEER)".red().bold()
                    };
                    println!(
                        "  • {:<43} {:<16} {:>4}s       {}",
                        lock.scope_id.yellow(),
                        lock.locked_by.cyan().bold(),
                        remaining_ttl,
                        status_badge
                    );
                }
                println!();
            }
        }

        Commands::Stream { action } => match action {
            StreamAction::Diff { file, workspace } => {
                let root = workspace.unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                let author = get_active_callsign();
                let locks = AstLockTable::load_from_workspace(&root);

                let packets = if let Some(target_file) = file {
                    let file_path = if target_file.is_absolute() {
                        target_file
                            .strip_prefix(&root)
                            .unwrap_or(&target_file)
                            .to_path_buf()
                    } else {
                        target_file
                    };
                    let rel = file_path.to_string_lossy().replace('\\', "/");
                    match stream::generate_ast_annotated_diff(&root, &rel, &author, &locks) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!(
                                "{} Fehler bei Diff-Generierung: {}",
                                "FEHLER:".red().bold(),
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                } else {
                    match stream::generate_workspace_ast_diffs(&root, &author, &locks) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!(
                                "{} Fehler beim Scannen des Workspace: {}",
                                "FEHLER:".red().bold(),
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                };

                println!(
                    "\n{}",
                    "=== S&B Sovereign Live Swarm Diff Stream ===".cyan().bold()
                );
                if packets.is_empty() {
                    println!("  Keine ungesendeten Code-Änderungen im Arbeitsbereich.\n");
                } else {
                    println!(
                        "  ► {} AST-Diff-Paket(e) bereit für Swarm-Streaming:",
                        packets.len().to_string().green().bold()
                    );
                    for p in &packets {
                        let lock_badge = if p.is_locked {
                            if let Some(ref lby) = p.locked_by {
                                if lby == &author {
                                    format!("[🔒 Locked by You ({})]", lby).green().bold()
                                } else {
                                    format!("[🔒 LOCKED BY PEER ({})]", lby).red().bold()
                                }
                            } else {
                                "[🔒 Locked]".yellow().bold()
                            }
                        } else {
                            "[🔓 Unlocked Scope]".bright_black()
                        };

                        println!(
                            "\n  ── {} :: {} ── {}",
                            p.file_path.cyan().bold(),
                            p.scope_name.yellow().bold(),
                            lock_badge
                        );
                        println!("  Scope ID: {}", p.scope_id.dimmed());
                        for line in p.diff_hunk.lines() {
                            if line.starts_with('+') {
                                println!("    {}", line.green());
                            } else if line.starts_with('-') {
                                println!("    {}", line.red());
                            } else {
                                println!("    {}", line.bright_black());
                            }
                        }
                    }
                    println!();
                }
            }
            StreamAction::Publish { project, workspace } => {
                let root = workspace.unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                if let Err(e) = stream::publish_project(&root, project).await {
                    eprintln!("{} {}", "FEHLER:".red().bold(), e);
                    std::process::exit(1);
                }
            }
            StreamAction::Subscribe { project, path } => {
                if let Err(e) = stream::subscribe_project(&project, path).await {
                    eprintln!("{} {}", "FEHLER:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        },

        Commands::Status { json, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let my_callsign = get_active_callsign();
            let lease_ttl = session::get_active_lease_ttl();

            if json {
                let vcs_status = if VcsEngine::is_initialized(&root) {
                    let engine = VcsEngine::open(&root).unwrap_or_else(|error| {
                        eprintln!(
                            "{} Repository konnte nicht geöffnet werden: {error}",
                            "FEHLER:".red()
                        );
                        std::process::exit(1);
                    });
                    Some(engine.status().unwrap_or_else(|error| {
                        eprintln!(
                            "{} Repository-Status fehlgeschlagen: {error}",
                            "FEHLER:".red()
                        );
                        std::process::exit(1);
                    }))
                } else {
                    None
                };
                let status_dto = serde_json::json!({
                    "callsign": my_callsign,
                    "lease_ttl_seconds": lease_ttl,
                    "ast_engine": "method-scopes",
                    "baseline_mode": "shadow-baseline",
                    "ipc_port": ipc::DEFAULT_CODE_IPC_PORT,
                    "vcs": vcs_status,
                });
                print_json_envelope("status", &status_dto);
                return;
            }

            println!(
                "\n{}",
                "=== Skulls & Bones · Sovereign Code Status ==="
                    .cyan()
                    .bold()
            );
            println!("Callsign:       {}", my_callsign.yellow().bold());
            match lease_ttl {
                Some(ttl) => {
                    let hours = ttl / 3600;
                    let mins = (ttl % 3600) / 60;
                    println!(
                        "Lease TTL:      {} ({:02}h {:02}m remaining)",
                        "ACTIVE".green(),
                        hours,
                        mins
                    );
                }
                None => {
                    println!(
                        "Lease TTL:      {} (Starte mit 'sb lease')",
                        "INACTIVE".yellow()
                    );
                }
            }
            println!("AST Engine:     Method/Function-level Scopes (Container-safe)");
            println!("Baseline Mode:  Stable Shadow Baseline (Dual-View Active)");
            println!("VCS Merkle:     BLAKE3 DAG; Commits unsigned");
            println!("Transport:      Pure WireGuard + Noise_IK UDP P2P");
            println!("IPC Socket:     127.0.0.1:{}", ipc::DEFAULT_CODE_IPC_PORT);

            if VcsEngine::is_initialized(&root) {
                if let Ok(engine) = VcsEngine::open(&root) {
                    if let Ok(st) = engine.status() {
                        println!("\n{}", "--- Sovereign VCS Arbeitsbereich ---".cyan());
                        println!("Branch:         {}", st.current_branch.yellow().bold());
                        let head_str = st
                            .head_commit
                            .as_ref()
                            .map(|c| {
                                format!(
                                    "{} ({})",
                                    &c.commit_id[..8.min(c.commit_id.len())],
                                    c.message
                                )
                            })
                            .unwrap_or_else(|| "Keine Commits".to_string());
                        println!("HEAD:           {}", head_str);
                        if st.is_clean {
                            println!(
                                "Arbeitsstand:   {}",
                                "Sauber (Keine uncommitteten Änderungen)".green()
                            );
                        } else {
                            println!(
                                "Änderungen:     {} modifiziert, {} hinzugefügt, {} gelöscht",
                                st.modified_count.to_string().yellow(),
                                st.added_count.to_string().green(),
                                st.deleted_count.to_string().red()
                            );
                            for ch in st.changes.iter().take(15) {
                                let badge = match ch.status.as_str() {
                                    "modified" => "MOD".yellow(),
                                    "added" => "NEU".green(),
                                    "deleted" => "DEL".red(),
                                    _ => "???".normal(),
                                };
                                println!("  [{}] {}", badge, ch.rel_path);
                            }
                            if st.changes.len() > 15 {
                                println!("  ... und {} weitere Dateien", st.changes.len() - 15);
                            }
                        }
                    }
                }
            }
            println!();
        }

        Commands::Stats { json, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

            if !VcsEngine::is_initialized(&root) {
                eprintln!(
                    "{} Kein Sovereign VCS Repository in '{}' initialisiert.",
                    "FEHLER:".red(),
                    root.display()
                );
                std::process::exit(1);
            }

            let engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "{} Repository konnte nicht geöffnet werden: {e}",
                        "FEHLER:".red()
                    );
                    std::process::exit(1);
                }
            };

            let stats = match engine.storage_stats() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{} Speicheranalyse fehlgeschlagen: {e}", "FEHLER:".red());
                    std::process::exit(1);
                }
            };

            if json {
                print_json_envelope("stats", &stats);
                return;
            }

            println!(
                "\n{}",
                "=== Skulls & Bones · VCS Speicher- & Datenanalyse ==="
                    .cyan()
                    .bold()
            );
            println!("Arbeitsbereich: {}", stats.workspace_root);
            println!("Aktiver Branch: {}", stats.active_branch.yellow().bold());
            if let Some(ref head) = stats.head_commit_id {
                println!("HEAD Commit:    {}", &head[..8.min(head.len())].cyan());
            }

            println!(
                "\n{}",
                "── Objekt- & Speicherbelegung (.sb/vcs) ──────────────".bright_black()
            );
            println!(
                "  • {:<18} {:>6} Objekte   {:>10}",
                "Commits:".bold(),
                stats.commits.count,
                format_bytes(stats.commits.total_bytes).yellow()
            );
            println!(
                "  • {:<18} {:>6} Objekte   {:>10}",
                "Trees:".bold(),
                stats.trees.count,
                format_bytes(stats.trees.total_bytes)
            );
            println!(
                "  • {:<18} {:>6} Objekte   {:>10}",
                "Blobs (Raw):".bold(),
                stats.blobs.count,
                format_bytes(stats.blobs.total_bytes)
            );
            println!(
                "  • {:<18} {:>6} Chunks    {:>10}",
                "FastCDC Chunks:".bold(),
                stats.chunks.count,
                format_bytes(stats.chunks.total_bytes).green()
            );
            println!(
                "  • {:<18} {:>6} Manifests {:>10}",
                "Chunk-Manifeste:".bold(),
                stats.chunk_manifests.count,
                format_bytes(stats.chunk_manifests.total_bytes)
            );
            println!(
                "{}",
                "───────────────────────────────────────────────────────".bright_black()
            );
            println!(
                "  {:<20} {:>6} Objekte   {:>10}",
                "Gesamtspeicher:".bold(),
                stats.total_objects,
                format_bytes(stats.total_vcs_bytes).cyan().bold()
            );

            println!(
                "\n{}",
                "── Deduplikation & Effizienz ──────────────────────────".bright_black()
            );
            if let Some(ratio) = stats.deduplication_ratio {
                println!(
                    "  Deduplikationsrate:   {:.2}x (Rohdaten vs. FastCDC Chunks)",
                    ratio
                );
            } else {
                println!("  Deduplikationsrate:   keine Chunks im Speicher");
            }
            println!(
                "  Ø Commit-Objektgröße: {}",
                format_bytes(stats.average_commit_bytes)
            );

            if stats.average_commit_bytes > 500_000 {
                println!(
                    "  {} Hoher AST-Scope Overhead erkannt (~{} pro Commit). Inline Scope Snapshots.",
                    "HINWEIS:".yellow().bold(),
                    format_bytes(stats.average_commit_bytes)
                );
            }
            println!();
        }

        Commands::Tui { workspace } => {
            let my_callsign = get_active_callsign();
            let code_session = CodeSession::new_host("alpha-swarm", &my_callsign);
            let session_arc = Arc::new(Mutex::new(code_session));
            let lock_table = Arc::new(Mutex::new(AstLockTable::new()));
            let runner_state = Arc::new(Mutex::new(RunnerState::default()));
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

            if let Err(e) = tui::run_tui(session_arc, runner_state, lock_table, &root) {
                eprintln!("{} TUI error: {}", "ERROR:".red(), e);
            }
        }

        Commands::Publish { project, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            if let Err(e) = stream::publish_project(&root, project).await {
                eprintln!("{} {}", "FEHLER:".red().bold(), e);
                std::process::exit(1);
            }
        }

        Commands::Subscribe { project, path } => {
            if let Err(e) = stream::subscribe_project(&project, path).await {
                eprintln!("{} {}", "FEHLER:".red().bold(), e);
                std::process::exit(1);
            }
        }

        Commands::Ingress => {
            let endpoints = ingress::detect_ingress_endpoints();
            ingress::print_ingress_report(&endpoints);
        }

        Commands::Escape { action } => match action {
            EscapeAction::Share {
                port,
                domain,
                gateway,
            } => {
                if let Err(e) = escape::validate_target_port(port) {
                    eprintln!(
                        "{} Ungültiger Ziel-Port {}: {}",
                        "FEHLER:".red().bold(),
                        port,
                        e
                    );
                    std::process::exit(1);
                }
                let clean_domain = match escape::validate_domain(&domain) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!(
                            "{} Ungültige Domain '{}': {}",
                            "FEHLER:".red().bold(),
                            domain,
                            e
                        );
                        std::process::exit(1);
                    }
                };
                let callsign = get_active_callsign();

                println!();
                println!(
                    "{}",
                    "  ⚡ Skulls & Bones — Sovereign Tunnel Hub (Zero-Cloud)"
                        .cyan()
                        .bold()
                );
                println!(
                    "{}",
                    "  ─────────────────────────────────────────────────────────────"
                        .bright_black()
                );
                println!(
                    "  🌐 Externe Domain:  {}",
                    format!("https://{}", clean_domain).green().bold()
                );
                println!(
                    "  🔒 Lokaler Port:     {}",
                    format!("127.0.0.1:{}", port).yellow().bold()
                );
                println!("  🚀 Gateway Hub:      {}", gateway.bright_magenta());
                println!("  🔑 Peer Callsign:    {}", callsign.bright_white());
                println!(
                    "  🛡️  Airgap Status:   {}",
                    "100% Hermetisch (Keine Cloud-Relays / Kein Port-Forwarding)".bright_cyan()
                );
                println!(
                    "{}",
                    "  ─────────────────────────────────────────────────────────────"
                        .bright_black()
                );
                println!("  Warte auf eingehende Gateway-Streams... (Ctrl+C zum Beenden)\n");

                let client = match escape::SovereignTunnelClient::new(
                    &clean_domain,
                    port,
                    &gateway,
                    &callsign,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!(
                            "{} Tunnel-Initialisierungsfehler: {}",
                            "FEHLER:".red().bold(),
                            e
                        );
                        std::process::exit(1);
                    }
                };

                let mut store = escape::EscapeSpaceStore::load();
                let _ = store.set_tunnel_mode(&clean_domain, true, Some(callsign.clone()));

                let running_flag = client.running.clone();
                tokio::spawn(async move {
                    tokio::signal::ctrl_c().await.ok();
                    println!(
                        "\n  {} Sovereign Tunnel wird ordnungsgemäß beendet...",
                        "⚡".yellow()
                    );
                    running_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                });

                if let Err(e) = client.run().await {
                    eprintln!("{} Tunnel-Fehler: {}", "FEHLER:".red().bold(), e);
                    std::process::exit(1);
                }
            }

            EscapeAction::List => {
                let store = escape::EscapeSpaceStore::load();
                println!();
                println!(
                    "{}",
                    "  🌐 Registrierte Sovereign Escape Spaces".cyan().bold()
                );
                println!("{}", "  ─────────────────────────────────────────────────────────────────────────────".bright_black());
                if store.spaces.is_empty() {
                    println!("  Keine Escape Spaces konfiguriert. Erstelle einen mit:");
                    println!(
                        "    {}",
                        "sb escape share 3000 --as preview.example.com".yellow()
                    );
                } else {
                    for sp in &store.spaces {
                        let tunnel_badge = if sp.is_tunnel {
                            format!(
                                "⚡ SOVEREIGN TUNNEL [{}]",
                                sp.tunnel_peer.as_deref().unwrap_or("Aktiv")
                            )
                            .yellow()
                            .bold()
                        } else {
                            format!("🖥️ NODE LOKAL (Port {})", sp.target_port).green()
                        };
                        println!(
                            "  • {:<30} ➔ {:<28} [{}]",
                            sp.domain.bold(),
                            tunnel_badge,
                            sp.status
                        );
                    }
                }
                println!("{}", "  ─────────────────────────────────────────────────────────────────────────────\n".bright_black());
            }

            EscapeAction::Tunnel { space, enable } => {
                let mut store = escape::EscapeSpaceStore::load();
                let peer = if enable {
                    Some(get_active_callsign())
                } else {
                    None
                };
                match store.set_tunnel_mode(&space, enable, peer) {
                    Ok(updated) => {
                        let st = if updated.is_tunnel {
                            "AKTIVIERT".green().bold()
                        } else {
                            "DEAKTIVIERT".red().bold()
                        };
                        println!(
                            "  {} Sovereign Tunnel für '{}' ist nun {}.",
                            "✓".green().bold(),
                            updated.domain,
                            st
                        );
                    }
                    Err(e) => {
                        eprintln!("{} {}", "FEHLER:".red().bold(), e);
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "sb-code", &mut std::io::stdout());
        }

        Commands::Verify { commit, workspace } => {
            let root = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let engine = match VcsEngine::open(&root) {
                Ok(e) => e,
                Err(err) => {
                    eprintln!(
                        "{} Sovereign VCS Repository nicht gefunden: {}",
                        "FEHLER:".red(),
                        err
                    );
                    std::process::exit(1);
                }
            };
            let target_commit = if let Some(id) = commit {
                match engine.get_commit(&id) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("{} Commit '{}' nicht gefunden: {}", "FEHLER:".red(), id, e);
                        std::process::exit(1);
                    }
                }
            } else {
                match engine.head_commit() {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        eprintln!("{} Keine Commits im Repository vorhanden.", "FEHLER:".red());
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!(
                            "{} Fehler beim Lesen des HEAD-Commits: {}",
                            "FEHLER:".red(),
                            e
                        );
                        std::process::exit(1);
                    }
                }
            };

            println!(
                "\n{}",
                "=== S&B Code · Ed25519 Commit-Signaturprüfung ==="
                    .cyan()
                    .bold()
            );
            println!("Commit ID:  {}", target_commit.commit_id.yellow().bold());
            println!("Author:     {}", target_commit.author_callsign.cyan());
            println!(
                "Date:       {}",
                target_commit.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!("Message:    {}", target_commit.message.white().bold());

            match target_commit.verify_signature() {
                Ok(verifying_key) => {
                    let pk_hex = hex::encode(verifying_key.as_bytes());
                    println!("\n{}", "✓ KRYPTOGRAPHISCH GÜLTIG (Ed25519)".green().bold());
                    println!("Signer Public Key: {}", pk_hex.bright_green());
                }
                Err(err) => {
                    let status = target_commit.signature_status();
                    if status == "nicht signiert" {
                        println!("\n{} Commit ist nicht signiert.", "INFO:".yellow());
                    } else {
                        eprintln!(
                            "\n{} Signaturprüfung fehlgeschlagen: {}",
                            "FEHLER:".red().bold(),
                            err
                        );
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Bundle { action } => {
            match action {
                BundleAction::Export {
                    out,
                    branch,
                    since,
                    workspace,
                } => {
                    let root = workspace.unwrap_or_else(|| {
                        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                    });
                    let engine = match VcsEngine::open(&root) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!(
                                "{} Sovereign VCS Repository nicht gefunden: {}",
                                "FEHLER:".red(),
                                e
                            );
                            std::process::exit(1);
                        }
                    };
                    let target_branch = match branch {
                        Some(b) => b,
                        None => match engine.current_branch() {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!(
                                    "{} Konnte aktuellen Branch nicht ermitteln: {}",
                                    "FEHLER:".red(),
                                    e
                                );
                                std::process::exit(1);
                            }
                        },
                    };
                    match engine.export_bundle(&target_branch, since.as_deref()) {
                        Ok(bundle_bytes) => {
                            let out_path = out.unwrap_or_else(|| {
                                PathBuf::from(format!("{}.sbbundle", target_branch))
                            });
                            if let Err(e) = fs::write(&out_path, &bundle_bytes) {
                                eprintln!(
                                    "{} Konnte Bundle-Datei nicht schreiben: {}",
                                    "FEHLER:".red(),
                                    e
                                );
                                std::process::exit(1);
                            }
                            println!(
                                "{}",
                                "✓ Souveränes Merkle-Bundle erfolgreich exportiert!"
                                    .green()
                                    .bold()
                            );
                            println!("  Branch:    {}", target_branch.yellow().bold());
                            println!("  Datei:     {}", out_path.display().to_string().cyan());
                            println!(
                                "  Größe:     {} Bytes ({:.1} KB)",
                                bundle_bytes.len(),
                                bundle_bytes.len() as f64 / 1024.0
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{} Fehler beim Exportieren des Bundles: {}",
                                "FEHLER:".red(),
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                }

                BundleAction::Import {
                    file,
                    branch,
                    checkout,
                    workspace,
                } => {
                    let root = workspace.unwrap_or_else(|| {
                        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                    });
                    let mut engine = match VcsEngine::open(&root) {
                        Ok(e) => e,
                        Err(_) => match VcsEngine::init(&root) {
                            Ok(e) => e,
                            Err(e) => {
                                eprintln!(
                                    "{} Konnte Repository nicht öffnen oder initialisieren: {}",
                                    "FEHLER:".red(),
                                    e
                                );
                                std::process::exit(1);
                            }
                        },
                    };
                    let bundle_bytes = match fs::read(&file) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!(
                                "{} Konnte Bundle-Datei '{}' nicht lesen: {}",
                                "FEHLER:".red(),
                                file.display(),
                                e
                            );
                            std::process::exit(1);
                        }
                    };
                    let target_branch = match branch {
                        Some(b) => b,
                        None => {
                            peek_bundle_branch(&bundle_bytes).unwrap_or_else(|| "main".to_string())
                        }
                    };
                    match engine.import_bundle(&bundle_bytes, &target_branch) {
                        Ok(report) => {
                            println!(
                                "{}",
                                "✓ Souveränes Merkle-Bundle erfolgreich importiert!"
                                    .green()
                                    .bold()
                            );
                            println!(
                                "  Branch:                  {}",
                                target_branch.yellow().bold()
                            );
                            println!(
                                "  Neuer HEAD:              {}",
                                report.new_head.cyan().bold()
                            );
                            println!("  Commits synchronisiert:  {}", report.commits_synced);
                            println!("  Blobs synchronisiert:    {}", report.blobs_synced);
                            if checkout {
                                match engine.checkout(&target_branch) {
                                    Ok(()) => {
                                        println!("{}", "✓ Arbeitsverzeichnis erfolgreich auf Branch aktualisiert.".green());
                                    }
                                    Err(e) => {
                                        eprintln!("{} Import erfolgreich, aber Checkout fehlgeschlagen: {}", "WARNUNG:".yellow(), e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "{} Fehler beim Importieren des Bundles: {}",
                                "FEHLER:".red(),
                                e
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }
}

fn peek_bundle_branch(bundle_bytes: &[u8]) -> Option<String> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    let dec = GzDecoder::new(Cursor::new(bundle_bytes));
    let mut archive = tar::Archive::new(dec);
    if let Ok(entries) = archive.entries() {
        for entry in entries.flatten() {
            if entry
                .path()
                .ok()?
                .to_string_lossy()
                .ends_with("manifest.json")
            {
                let manifest: serde_json::Value = serde_json::from_reader(entry).ok()?;
                return manifest
                    .get("branch")
                    .and_then(|b| b.as_str())
                    .map(str::to_string);
            }
        }
    }
    None
}

fn parse_target(s: &str) -> ExecutionTarget {
    let lower = s.to_lowercase();
    if lower == "local" {
        ExecutionTarget::Local
    } else if lower == "host" {
        ExecutionTarget::Host
    } else if lower.starts_with("node") {
        let node_id = lower
            .strip_prefix("node:")
            .unwrap_or("sb-node-01")
            .to_string();
        ExecutionTarget::Node { node_id }
    } else {
        ExecutionTarget::Node {
            node_id: s.to_string(),
        }
    }
}
