use colored::Colorize;
use sb_drive::PeerFilesystem;

pub async fn handle_drive_ls(peer: &str, path: Option<&str>) {
    let target_path = path.unwrap_or("/");
    println!(
        "{} Listing directory on peer '{}' at path '{}'...",
        "●".cyan(),
        peer.yellow().bold(),
        target_path.white().bold()
    );

    match PeerFilesystem::list_directory(peer.to_string(), path.map(|s| s.to_string())).await {
        Ok(res) => {
            println!(
                "{} Found {} entries on peer '{}' (path: {}):",
                "✓".green().bold(),
                res.items.len().to_string().cyan().bold(),
                res.peer.yellow(),
                res.current_path.white()
            );
            println!(
                "{:<12} {:<10} {:<10} {:<20} {}",
                "PERMISSIONS".bold(),
                "TYPE".bold(),
                "SIZE".bold(),
                "MODIFIED".bold(),
                "NAME".bold()
            );
            println!("{}", "─".repeat(70).dimmed());

            for item in res.items {
                let type_badge = if item.is_dir {
                    "[DIR]".blue().bold()
                } else if item.is_symlink {
                    "[SYM]".magenta()
                } else {
                    format!("[{}]", item.file_type).dimmed()
                };

                let size_str = if item.is_dir {
                    "-".to_string()
                } else if item.size_bytes < 1024 {
                    format!("{} B", item.size_bytes)
                } else if item.size_bytes < 1024 * 1024 {
                    format!("{:.1} KB", item.size_bytes as f64 / 1024.0)
                } else {
                    format!("{:.1} MB", item.size_bytes as f64 / (1024.0 * 1024.0))
                };

                let name_colored = if item.is_dir {
                    format!("{}/", item.name).bright_blue().bold()
                } else {
                    item.name.white()
                };

                println!(
                    "{:<12} {:<10} {:<10} {:<20} {}",
                    item.permissions.dimmed(),
                    type_badge,
                    size_str.dimmed(),
                    item.modified.dimmed(),
                    name_colored
                );
            }
        }
        Err(e) => {
            eprintln!("{} Failed to list directory: {}", "✗".red().bold(), e);
        }
    }
}

pub async fn handle_drive_cat(peer: &str, path: &str) {
    println!(
        "{} Reading file '{}' from peer '{}'...",
        "●".cyan(),
        path.white().bold(),
        peer.yellow().bold()
    );

    match PeerFilesystem::read_file(peer.to_string(), path.to_string()).await {
        Ok(res) => {
            if res.is_binary {
                println!(
                    "{} Binary file detected ({} bytes). Cannot display in terminal directly.",
                    "!".yellow().bold(),
                    res.size_bytes
                );
                println!(
                    "  Tip: Use 'sb drive get {} {}' to download it to local cache.",
                    peer, path
                );
            } else {
                println!("{}", "─".repeat(70).dimmed());
                print!("{}", res.content);
                println!("\n{}", "─".repeat(70).dimmed());
                println!(
                    "{} Read {} bytes successfully.",
                    "✓".green(),
                    res.size_bytes
                );
            }
        }
        Err(e) => {
            eprintln!("{} Failed to read file: {}", "✗".red().bold(), e);
        }
    }
}

pub async fn handle_drive_write(peer: &str, path: &str, content: &str) {
    println!(
        "{} Writing {} bytes to '{}' on peer '{}'...",
        "●".cyan(),
        content.len(),
        path.white().bold(),
        peer.yellow().bold()
    );

    match PeerFilesystem::write_file(
        peer.to_string(),
        path.to_string(),
        content.to_string(),
        None,
    )
    .await
    {
        Ok(true) => {
            println!("{} File written successfully.", "✓".green().bold());
        }
        Ok(false) => {
            eprintln!("{} Peer accepted request but returned false.", "✗".yellow());
        }
        Err(e) => {
            eprintln!("{} Failed to write file: {}", "✗".red().bold(), e);
        }
    }
}

pub async fn handle_drive_get(peer: &str, path: &str) {
    println!(
        "{} Downloading '{}' from peer '{}' to local Sovereign Ghost Cache...",
        "●".cyan(),
        path.white().bold(),
        peer.yellow().bold()
    );

    match PeerFilesystem::download_to_cache(peer.to_string(), path.to_string()).await {
        Ok(cached_path) => {
            println!(
                "{} Download complete!\n  Local Cache Path: {}",
                "✓".green().bold(),
                cached_path.yellow().bold()
            );
        }
        Err(e) => {
            eprintln!("{} Failed to download file: {}", "✗".red().bold(), e);
        }
    }
}
