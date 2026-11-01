use clap::{Parser, Subcommand};
use colored::*;
use sb_db::{server::validate_loopback_bind, Database, DbClient, DbServer, DEFAULT_PORT};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Parser)]
#[command(name = "sb-db")]
#[command(
    about = "💀 Sovereign DB — Embedded Document-KV Store, Native TTL, Secondary Indexes & Reactive Watch",
    version
)]
struct Cli {
    /// Path to the single .sbdb database file (local mode)
    #[arg(short, long, global = true)]
    db: Option<PathBuf>,

    /// Connect to a remote Sovereign Database TCP server instead of local file
    #[arg(long, global = true)]
    remote: Option<String>,

    /// Connect to a Sovereign Database in a target mesh via Cross-Mesh Bridge (e.g. 'database-mesh')
    #[arg(long, global = true)]
    cross_mesh: Option<String>,

    /// Source mesh name when connecting via cross-mesh (default: 'app-mesh')
    #[arg(long, global = true, default_value = "app-mesh")]
    source_mesh: String,

    /// Anchor UDP dispatcher address for cross-mesh bridge (default: 127.0.0.1:58888)
    #[arg(long, global = true, default_value = "127.0.0.1:58888")]
    anchor: String,

    /// Optional Schnorr capability token (JSON string)
    #[arg(long, global = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Subcommand)]
enum Commands {
    /// Start the loopback-only Sovereign Database TCP server
    Serve {
        /// Custom socket address to bind (default: 127.0.0.1:58830)
        #[arg(short, long)]
        bind: Option<SocketAddr>,
    },

    /// Open an interactive REPL session connected to a remote or cross-mesh Sovereign Database
    Connect {
        /// Remote server TCP address (default: 127.0.0.1:58830)
        #[arg(default_value = "127.0.0.1:58830")]
        addr: String,

        /// Connect across meshes to a target mesh database (e.g. 'database-mesh')
        #[arg(long)]
        cross_mesh: Option<String>,

        /// Source mesh identity (default: 'app-mesh')
        #[arg(long, default_value = "app-mesh")]
        source_mesh: String,

        /// Anchor UDP dispatcher address (default: 127.0.0.1:58888)
        #[arg(long, default_value = "127.0.0.1:58888")]
        anchor: String,

        /// Optional Schnorr capability token (JSON string)
        #[arg(long)]
        token: Option<String>,
    },

    /// Retrieve a document or nested JSON field by key (e.g. 'users:alice' or 'users:alice.profile.age')
    Get {
        /// Key name or nested path
        key: String,
    },

    /// Store a JSON document or primitive at key
    Set {
        /// Key name or nested path
        key: String,

        /// JSON value string (e.g. '{"name": "Alice"}' or '"admin"' or '42')
        value: String,

        /// Optional Time-To-Live in seconds (e.g. --ttl 3600)
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Delete a document by key
    Del {
        /// Key name to delete
        key: String,
    },

    /// Scan documents matching prefix
    Scan {
        /// Key prefix to filter by (default: scan all keys)
        #[arg(default_value = "")]
        prefix: String,
    },

    /// Find documents using a secondary index in O(1)
    Find {
        /// Collection prefix (e.g. 'users:')
        prefix: String,

        /// Indexed field name (e.g. 'role')
        field: String,

        /// Value to search for
        value: String,
    },

    /// Manage secondary indexes
    Index {
        #[command(subcommand)]
        action: IndexAction,
    },

    /// Live-stream database mutations in real time (Change Data Capture)
    Tail {
        /// Optional key pattern to filter by (e.g. 'users:*')
        #[arg(default_value = "*")]
        pattern: String,
    },

    /// Compact database file to reclaim disk space
    Compact,

    /// Show database metrics and file statistics
    Stats,

    /// Launch interactive terminal cockpit (local mode)
    Tui,
}

#[derive(Clone, Subcommand)]
enum IndexAction {
    /// Create a secondary index on a field
    Create {
        /// Collection prefix (e.g. 'users:')
        prefix: String,

        /// Field name to index (e.g. 'role' or 'profile.age')
        field: String,
    },
    /// Drop a secondary index
    Drop {
        /// Collection prefix (e.g. 'users:')
        prefix: String,

        /// Field name
        field: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Some(Commands::Serve { bind }) = cli.command.as_ref() {
        if let Err(error) = resolve_serve_bind(*bind) {
            eprintln!("  {} {}", "✗".bright_red().bold(), error);
            std::process::exit(2);
        }
    }

    // ── 1. Cross-Mesh Client Dispatch ─────────────────────────────────────────
    if let Some(target_mesh) = &cli.cross_mesh {
        match establish_cross_mesh_stream(
            &cli.source_mesh,
            target_mesh,
            &cli.anchor,
            cli.token.clone(),
        )
        .await
        {
            Ok(stream) => {
                let client = DbClient::from_stream(stream);
                let target_display = format!("cross-mesh:{} via {}", target_mesh, cli.source_mesh);
                match &cli.command {
                    Some(Commands::Connect { .. }) | None => {
                        if let Err(e) = run_repl(client, &target_display).await {
                            eprintln!("  {} REPL Error: {}", "✗".bright_red().bold(), e);
                            std::process::exit(1);
                        }
                    }
                    Some(cmd) => {
                        if let Err(e) = handle_remote_cli(client, Some(cmd.clone())).await {
                            eprintln!("  {} Cross-Mesh DB Error: {}", "✗".bright_red().bold(), e);
                            std::process::exit(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "  {} Cross-Mesh Bridge Error: {}",
                    "✗".bright_red().bold(),
                    e
                );
                std::process::exit(1);
            }
        }
        return;
    }

    // ── 2. Remote TCP Client CLI Dispatch ─────────────────────────────────────
    if let Some(remote_addr) = &cli.remote {
        match DbClient::connect_str(remote_addr).await {
            Ok(client) => {
                let target_display = remote_addr.clone();
                match &cli.command {
                    Some(Commands::Connect { .. }) | None => {
                        if let Err(e) = run_repl(client, &target_display).await {
                            eprintln!("  {} REPL Error: {}", "✗".bright_red().bold(), e);
                            std::process::exit(1);
                        }
                    }
                    Some(cmd) => {
                        if let Err(e) = handle_remote_cli(client, Some(cmd.clone())).await {
                            eprintln!("  {} Remote DB Error: {}", "✗".bright_red().bold(), e);
                            std::process::exit(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("  {} Remote DB Error: {}", "✗".bright_red().bold(), e);
                std::process::exit(1);
            }
        }
        return;
    }

    // ── 3. Dedicated Connect Subcommand (REPL) ────────────────────────────────
    if let Some(Commands::Connect {
        addr,
        cross_mesh,
        source_mesh,
        anchor,
        token,
    }) = &cli.command
    {
        if let Some(target_mesh) = cross_mesh {
            match establish_cross_mesh_stream(source_mesh, target_mesh, anchor, token.clone()).await
            {
                Ok(stream) => {
                    let client = DbClient::from_stream(stream);
                    let target_display = format!("cross-mesh:{} via {}", target_mesh, source_mesh);
                    if let Err(e) = run_repl(client, &target_display).await {
                        eprintln!("  {} REPL Error: {}", "✗".bright_red().bold(), e);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  {} Cross-Mesh Connection Error: {}",
                        "✗".bright_red().bold(),
                        e
                    );
                    std::process::exit(1);
                }
            }
        } else {
            match DbClient::connect_str(addr).await {
                Ok(client) => {
                    if let Err(e) = run_repl(client, addr).await {
                        eprintln!("  {} REPL Error: {}", "✗".bright_red().bold(), e);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("  {} Connect Error: {}", "✗".bright_red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        return;
    }

    // ── 4. Resolve Database File Path (Local Mode) ────────────────────────────
    let db_path = cli.db.unwrap_or_else(|| {
        let current_dir_db = std::path::PathBuf::from("data.sbdb");
        if current_dir_db.exists() {
            current_dir_db
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".sb")
                .join("db")
                .join("store.sbdb")
        }
    });

    let db = match Database::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!(
                "  {} Failed to open database at '{}': {}",
                "✗".bright_red().bold(),
                db_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            if let Err(e) = sb_db::tui::run_tui(db) {
                eprintln!("TUI Error: {}", e);
            }
            return;
        }
    };

    match command {
        Commands::Serve { bind } => {
            let bind_addr = match resolve_serve_bind(bind) {
                Ok(addr) => addr,
                Err(error) => {
                    eprintln!("  {} {}", "✗".bright_red().bold(), error);
                    std::process::exit(2);
                }
            };
            println!("\x1b[1;36m══════════════════════════════════════════════════════════════════\x1b[0m");
            println!("\x1b[1;36m  SKULLS & BONES // SOVEREIGN DATABASE DAEMON\x1b[0m");
            println!("\x1b[1;36m══════════════════════════════════════════════════════════════════\x1b[0m");
            println!(
                "  Database File:        {}",
                db_path.display().to_string().cyan()
            );
            println!("  Protocol:             Sovereign Wire Protocol (CRC32 Framing)");
            println!(
                "  TCP Bind:             {} (loopback only)",
                bind_addr.to_string().yellow()
            );
            if bind_addr == SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)) {
                println!(
                    "  Mesh Gateway:         sb-node may expose this as database-mesh:{}",
                    DEFAULT_PORT
                );
                println!(
                    "  Mesh Authorization:   active mesh membership + stream:transfer required\n"
                );
            } else {
                println!(
                    "  Mesh Gateway:         unavailable; sb-node uses 127.0.0.1:{}\n",
                    DEFAULT_PORT
                );
            }

            let server = DbServer::new(Arc::new(db));
            if let Err(e) = server.run(bind_addr).await {
                eprintln!("  {} Server fatal error: {}", "✗".bright_red().bold(), e);
                std::process::exit(1);
            }
        }

        Commands::Connect { .. } => unreachable!(),

        Commands::Get { key } => {
            if let Some((main_key, path)) = key.split_once('.') {
                match db.get_path(main_key, path) {
                    Some(val) => {
                        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default())
                    }
                    None => {
                        eprintln!(
                            "\x1b[33mField '{}' in '{}' not found\x1b[0m",
                            path, main_key
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                match db.get(&key) {
                    Some(val) => {
                        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default())
                    }
                    None => {
                        eprintln!("\x1b[33mKey '{}' not found\x1b[0m", key);
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Set { key, value, ttl } => {
            let json_val: serde_json::Value = match serde_json::from_str(&value) {
                Ok(v) => v,
                Err(_) => serde_json::Value::String(value),
            };

            let res = if let Some(secs) = ttl {
                db.set_with_ttl(&key, &json_val, Duration::from_secs(secs))
            } else if let Some((main_key, path)) = key.split_once('.') {
                db.set_path(main_key, path, json_val)
            } else {
                db.set(&key, &json_val)
            };

            match res {
                Ok(_) => println!("\x1b[1;32m[✓] OK ({})\x1b[0m", key),
                Err(e) => {
                    eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Del { key } => match db.delete(&key) {
            Ok(true) => println!("\x1b[1;32m[✓] Deleted: {}\x1b[0m", key),
            Ok(false) => println!("\x1b[33m[-] Key '{}' not found\x1b[0m", key),
            Err(e) => {
                eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e);
                std::process::exit(1);
            }
        },

        Commands::Scan { prefix } => {
            let items = db.scan(&prefix);
            println!(
                "\x1b[1;36m💀 SCAN '{}' ({} results)\x1b[0m",
                prefix,
                items.len()
            );
            for (k, v) in items {
                println!(
                    "{:<28} {}",
                    k,
                    serde_json::to_string(&v).unwrap_or_default()
                );
            }
        }

        Commands::Find {
            prefix,
            field,
            value,
        } => {
            let parsed_val: serde_json::Value =
                serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value));
            let results = db.find(&prefix, &field, &parsed_val);
            println!(
                "\x1b[1;36m💀 FIND IN '{}' WHERE {} == {} ({} matches)\x1b[0m",
                prefix,
                field,
                parsed_val,
                results.len()
            );
            for (k, v) in results {
                println!(
                    "{:<28} {}",
                    k,
                    serde_json::to_string(&v).unwrap_or_default()
                );
            }
        }

        Commands::Index { action } => match action {
            IndexAction::Create { prefix, field } => match db.create_index(&prefix, &field) {
                Ok(_) => println!(
                    "\x1b[1;32m[✓] Index created on '{}' for field '{}'\x1b[0m",
                    prefix, field
                ),
                Err(e) => eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e),
            },
            IndexAction::Drop { prefix, field } => match db.drop_index(&prefix, &field) {
                Ok(true) => println!(
                    "\x1b[1;32m[✓] Index dropped on '{}' for field '{}'\x1b[0m",
                    prefix, field
                ),
                Ok(false) => println!("\x1b[33m[-] Index not found\x1b[0m"),
                Err(e) => eprintln!("\x1b[31m[!] Error: {}\x1b[0m", e),
            },
        },

        Commands::Tail { pattern } => {
            println!(
                "\x1b[1;36m💀 TAILING MUTATIONS MATCHING '{}' (Press Ctrl+C to stop)...\x1b[0m",
                pattern
            );
            let mut receiver = db.watch();

            while let Ok(event) = receiver.recv().await {
                if event.matches_pattern(&pattern) {
                    let ts = chrono::DateTime::from_timestamp_millis(event.timestamp as i64)
                        .map(|d| d.format("%H:%M:%S%.3f").to_string())
                        .unwrap_or_default();

                    match event.kind {
                        sb_db::EventKind::Set => {
                            println!(
                                "\x1b[32m[{}] SET {}\x1b[0m -> {}",
                                ts,
                                event.key,
                                serde_json::to_string(&event.new_value.unwrap_or_default())
                                    .unwrap_or_default()
                            );
                        }
                        sb_db::EventKind::Delete => {
                            println!("\x1b[31m[{}] DEL {}\x1b[0m", ts, event.key);
                        }
                    }
                }
            }
        }

        Commands::Compact => {
            println!(
                "\x1b[1;36m[*] Compacting database file '{}'...\x1b[0m",
                db_path.display()
            );
            match db.compact() {
                Ok(reclaimed) => println!(
                    "\x1b[1;32m[✓] Compaction complete! Reclaimed {} bytes.\x1b[0m",
                    reclaimed
                ),
                Err(e) => eprintln!("\x1b[31m[!] Compaction error: {}\x1b[0m", e),
            }
        }

        Commands::Stats => {
            let stats = match db.stats() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error getting stats: {}", e);
                    return;
                }
            };

            print_stats(&stats);
        }

        Commands::Tui => {
            if let Err(e) = sb_db::tui::run_tui(db) {
                eprintln!("\x1b[31mTUI Error: {}\x1b[0m", e);
            }
        }
    }
}

fn print_stats(stats: &sb_db::DbStats) {
    println!("\x1b[1;36m══════════════════════════════════════════════════════════════════\x1b[0m");
    println!("\x1b[1;36m  SKULLS & BONES // SOVEREIGN DB METRICS\x1b[0m");
    println!("\x1b[1;36m══════════════════════════════════════════════════════════════════\x1b[0m");
    println!("  Database File:        {}", stats.path.display());
    println!("  Active Keys:          {}", stats.key_count);
    println!("  Secondary Indexes:    {}", stats.index_count);
    println!(
        "  File Size:            {:.2} KB ({} bytes)",
        stats.file_size_bytes as f64 / 1024.0,
        stats.file_size_bytes
    );
    println!("  Committed Tx Count:   {}", stats.last_tx_id);
    println!("\n  Schnellbefehle: 'sb-db tui' · 'sb-db scan' · 'sb-db tail' · 'sb-db compact'\n");
}

async fn handle_remote_cli<S>(
    mut client: DbClient<S>,
    command: Option<Commands>,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let cmd = match command {
        Some(c) => c,
        None => Commands::Stats,
    };

    match cmd {
        Commands::Get { key } => {
            if let Some((main_key, path)) = key.split_once('.') {
                match client.get_path(main_key, path).await? {
                    Some(val) => println!("{}", serde_json::to_string_pretty(&val)?),
                    None => {
                        eprintln!(
                            "\x1b[33mField '{}' in '{}' not found\x1b[0m",
                            path, main_key
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                match client.get(&key).await? {
                    Some(val) => println!("{}", serde_json::to_string_pretty(&val)?),
                    None => {
                        eprintln!("\x1b[33mKey '{}' not found\x1b[0m", key);
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Set { key, value, ttl } => {
            let json_val: serde_json::Value = match serde_json::from_str(&value) {
                Ok(v) => v,
                Err(_) => serde_json::Value::String(value),
            };

            if let Some(secs) = ttl {
                client.set_with_ttl(&key, json_val, secs).await?;
            } else if let Some((main_key, path)) = key.split_once('.') {
                client.set_path(main_key, path, json_val).await?;
            } else {
                client.set(&key, json_val).await?;
            }
            println!("\x1b[1;32m[✓] OK ({})\x1b[0m", key);
        }
        Commands::Del { key } => {
            let deleted = client.delete(&key).await?;
            if deleted {
                println!("\x1b[1;32m[✓] Deleted: {}\x1b[0m", key);
            } else {
                println!("\x1b[33m[-] Key '{}' not found\x1b[0m", key);
            }
        }
        Commands::Scan { prefix } => {
            let items = client.scan(&prefix).await?;
            println!(
                "\x1b[1;36m💀 REMOTE SCAN '{}' ({} results)\x1b[0m",
                prefix,
                items.len()
            );
            for (k, v) in items {
                println!("{:<28} {}", k, serde_json::to_string(&v)?);
            }
        }
        Commands::Find {
            prefix,
            field,
            value,
        } => {
            let parsed_val: serde_json::Value =
                serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value));
            let results = client.find(&prefix, &field, parsed_val.clone()).await?;
            println!(
                "\x1b[1;36m💀 REMOTE FIND IN '{}' WHERE {} == {} ({} matches)\x1b[0m",
                prefix,
                field,
                parsed_val,
                results.len()
            );
            for (k, v) in results {
                println!("{:<28} {}", k, serde_json::to_string(&v)?);
            }
        }
        Commands::Index { action } => match action {
            IndexAction::Create { prefix, field } => {
                client.create_index(&prefix, &field).await?;
                println!(
                    "\x1b[1;32m[✓] Remote index created on '{}' for field '{}'\x1b[0m",
                    prefix, field
                );
            }
            IndexAction::Drop { prefix, field } => {
                client.drop_index(&prefix, &field).await?;
                println!(
                    "\x1b[1;32m[✓] Remote index dropped on '{}' for field '{}'\x1b[0m",
                    prefix, field
                );
            }
        },
        Commands::Tail { pattern } => {
            println!(
                "\x1b[1;36m💀 REMOTE TAIL '{}' (Press Ctrl+C to stop)...\x1b[0m",
                pattern
            );
            let mut stream = client.watch(&pattern).await?;
            while let Ok(event) = stream.next_event().await {
                let ts = chrono::DateTime::from_timestamp_millis(event.timestamp as i64)
                    .map(|d| d.format("%H:%M:%S%.3f").to_string())
                    .unwrap_or_default();
                match event.kind {
                    sb_db::EventKind::Set => {
                        println!(
                            "\x1b[32m[{}] SET {}\x1b[0m -> {}",
                            ts,
                            event.key,
                            serde_json::to_string(&event.new_value.unwrap_or_default())?
                        );
                    }
                    sb_db::EventKind::Delete => {
                        println!("\x1b[31m[{}] DEL {}\x1b[0m", ts, event.key);
                    }
                }
            }
        }
        Commands::Compact => {
            let reclaimed = client.compact().await?;
            println!(
                "\x1b[1;32m[✓] Remote compaction complete! Reclaimed {} bytes.\x1b[0m",
                reclaimed
            );
        }
        Commands::Stats => {
            let stats = client.stats().await?;
            print_stats(&stats);
        }
        Commands::Serve { .. } | Commands::Connect { .. } | Commands::Tui => {
            eprintln!(
                "  {} This command cannot be run in remote mode.",
                "✗".bright_red().bold()
            );
        }
    }
    Ok(())
}

async fn run_repl<S>(
    mut client: DbClient<S>,
    target_display: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    println!("\x1b[1;36m══════════════════════════════════════════════════════════════════\x1b[0m");
    println!("\x1b[1;36m  SKULLS & BONES // SOVEREIGN DATABASE REPL CLIENT\x1b[0m");
    println!("\x1b[1;36m══════════════════════════════════════════════════════════════════\x1b[0m");
    println!(
        "  Target: {}\n  Commands: get, set, del, scan, find, stats, compact, ping, exit\n",
        target_display.cyan()
    );

    let stdin = io::stdin();
    let mut line = String::new();

    loop {
        print!("sb-db [{}]> ", target_display.yellow());
        io::stdout().flush()?;
        line.clear();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        match parts[0].to_lowercase().as_str() {
            "exit" | "quit" | "q" => {
                println!("  Bye!");
                break;
            }
            "ping" => match client.ping().await {
                Ok(_) => println!("  PONG"),
                Err(e) => eprintln!("  Error: {}", e),
            },
            "get" => {
                if parts.len() < 2 {
                    println!("  Usage: get <key[.path]>");
                    continue;
                }
                let key = parts[1];
                if let Some((main_key, path)) = key.split_once('.') {
                    match client.get_path(main_key, path).await {
                        Ok(Some(v)) => {
                            println!("  {}", serde_json::to_string_pretty(&v).unwrap_or_default())
                        }
                        Ok(None) => println!("  (nil)"),
                        Err(e) => eprintln!("  Error: {}", e),
                    }
                } else {
                    match client.get(key).await {
                        Ok(Some(v)) => {
                            println!("  {}", serde_json::to_string_pretty(&v).unwrap_or_default())
                        }
                        Ok(None) => println!("  (nil)"),
                        Err(e) => eprintln!("  Error: {}", e),
                    }
                }
            }
            "set" => {
                if parts.len() < 3 {
                    println!("  Usage: set <key[.path]> <json_value>");
                    continue;
                }
                let key = parts[1];
                let raw_val = parts[2..].join(" ");
                let val: serde_json::Value =
                    serde_json::from_str(&raw_val).unwrap_or(serde_json::Value::String(raw_val));
                if let Some((main_key, path)) = key.split_once('.') {
                    match client.set_path(main_key, path, val).await {
                        Ok(_) => println!("  OK"),
                        Err(e) => eprintln!("  Error: {}", e),
                    }
                } else {
                    match client.set(key, val).await {
                        Ok(_) => println!("  OK"),
                        Err(e) => eprintln!("  Error: {}", e),
                    }
                }
            }
            "del" => {
                if parts.len() < 2 {
                    println!("  Usage: del <key>");
                    continue;
                }
                match client.delete(parts[1]).await {
                    Ok(true) => println!("  (deleted)"),
                    Ok(false) => println!("  (not found)"),
                    Err(e) => eprintln!("  Error: {}", e),
                }
            }
            "scan" => {
                let prefix = if parts.len() > 1 { parts[1] } else { "" };
                match client.scan(prefix).await {
                    Ok(items) => {
                        println!("  {} result(s):", items.len());
                        for (k, v) in items {
                            println!(
                                "  {:<24} {}",
                                k,
                                serde_json::to_string(&v).unwrap_or_default()
                            );
                        }
                    }
                    Err(e) => eprintln!("  Error: {}", e),
                }
            }
            "find" => {
                if parts.len() < 4 {
                    println!("  Usage: find <prefix> <field> <value>");
                    continue;
                }
                let prefix = parts[1];
                let field = parts[2];
                let raw_val = parts[3];
                let val: serde_json::Value = serde_json::from_str(raw_val)
                    .unwrap_or(serde_json::Value::String(raw_val.to_string()));
                match client.find(prefix, field, val).await {
                    Ok(results) => {
                        println!("  {} match(es):", results.len());
                        for (k, v) in results {
                            println!(
                                "  {:<24} {}",
                                k,
                                serde_json::to_string(&v).unwrap_or_default()
                            );
                        }
                    }
                    Err(e) => eprintln!("  Error: {}", e),
                }
            }
            "compact" => match client.compact().await {
                Ok(bytes) => println!("  Compacted: reclaimed {} bytes", bytes),
                Err(e) => eprintln!("  Error: {}", e),
            },
            "stats" => match client.stats().await {
                Ok(s) => print_stats(&s),
                Err(e) => eprintln!("  Error: {}", e),
            },
            other => {
                println!("  Unknown command: '{}'. Type 'help' or 'exit'.", other);
            }
        }
    }

    Ok(())
}

async fn establish_cross_mesh_stream(
    source_mesh: &str,
    target_mesh: &str,
    anchor_str: &str,
    token_str: Option<String>,
) -> Result<sb_mesh::client::CrossMeshStream, Box<dyn std::error::Error>> {
    let anchor_addr: SocketAddr = anchor_str
        .parse()
        .map_err(|e| format!("Ungültige Anchor-Adresse '{}': {}", anchor_str, e))?;

    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let id_file = home.join(".sb-mesh").join("identity.json");
    let identity = Arc::new(
        sb_mesh::identity::NodeIdentity::load_or_generate(&id_file).unwrap_or_else(|_| {
            sb_mesh::identity::NodeIdentity::load_or_generate_default().unwrap()
        }),
    );

    let parsed_token = token_str
        .map(|token| serde_json::from_str::<sb_mesh::acl::CapabilityToken>(&token))
        .transpose()?;

    println!(
        "  {} Initialisiere MeshClient für Quell-Mesh '{}'...",
        "►".bright_cyan(),
        source_mesh.bright_white().bold()
    );
    println!(
        "  {} Verbinde mit Anchor Dispatcher: {}",
        "►".bright_cyan(),
        anchor_addr.to_string().bright_yellow()
    );

    let client = sb_mesh::client::MeshClient::connect(sb_mesh::client::MeshClientConfig {
        mesh_name: source_mesh.to_string(),
        swarm_topic: format!("sbm-swarm-{}", source_mesh),
        anchor_addr,
        identity,
        local_bind_port: None,
    })
    .await
    .map_err(|e| format!("MeshClient Initialisierungsfehler: {}", e))?;

    println!(
        "  {} Öffne Virtual Cross-Mesh Stream ➔ Ziel-Mesh '{}' (Port {})...",
        "🔒".bright_blue(),
        target_mesh.bright_green().bold(),
        sb_db::DEFAULT_PORT
    );

    let stream = client
        .open_cross_mesh_stream(target_mesh, sb_db::DEFAULT_PORT, parsed_token)
        .await
        .map_err(|e| format!("Cross-Mesh Stream Aufbau fehlgeschlagen: {}", e))?;

    println!(
        "  {} Cross-Mesh Virtual Stream aktiv [Session #{}]!",
        "✓".bright_green().bold(),
        stream.session_id
    );

    Ok(stream)
}

fn resolve_serve_bind(bind: Option<SocketAddr>) -> Result<SocketAddr, String> {
    let addr = bind.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)));
    validate_loopback_bind(addr)
        .map(|()| addr)
        .map_err(|error| format!("{error}. Use the sb-node mesh gateway for remote access."))
}

#[cfg(test)]
mod serve_bind_tests {
    use super::resolve_serve_bind;
    use sb_db::DEFAULT_PORT;
    use std::net::SocketAddr;

    #[test]
    fn defaults_to_local_mesh_gateway_endpoint() {
        assert_eq!(
            resolve_serve_bind(None).unwrap(),
            SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT))
        );
    }

    #[test]
    fn accepts_loopback_addresses() {
        assert_eq!(
            resolve_serve_bind(Some("127.0.0.1:12345".parse().unwrap())).unwrap(),
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_serve_bind(Some("[::1]:12345".parse().unwrap())).unwrap(),
            "[::1]:12345".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_non_loopback_addresses() {
        assert!(resolve_serve_bind(Some("0.0.0.0:58830".parse().unwrap())).is_err());
        assert!(resolve_serve_bind(Some("[::]:58830".parse().unwrap())).is_err());
    }
}
