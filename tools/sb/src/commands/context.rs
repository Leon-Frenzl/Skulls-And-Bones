use crate::cli::ContextAction;
use crate::context::{self, ContextStore};
use colored::*;

pub fn sync_mesh_network_with_context(context_name: &str, mesh_swarm: Option<&str>) {
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let networks_path = home.join(".sb-mesh").join("networks.json");
    if networks_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&networks_path) {
            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&content) {
                let target_info =
                    if let Some(networks) = json.get("networks").and_then(|n| n.as_object()) {
                        let target_net = if networks.contains_key(context_name) {
                            Some(context_name.to_string())
                        } else if let Some(swarm) = mesh_swarm {
                            networks.iter().find_map(|(k, v)| {
                                if v.get("swarm_topic").and_then(|s| s.as_str()) == Some(swarm) {
                                    Some(k.clone())
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        };

                        target_net.map(|name| {
                            let subnet = networks
                                .get(&name)
                                .and_then(|n| n.get("overlay_subnet"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("10.240.0.0/16")
                                .to_string();
                            (name, subnet)
                        })
                    } else {
                        None
                    };

                if let Some((net_name, subnet)) = target_info {
                    json["active_network"] = serde_json::Value::String(net_name.clone());
                    if let Ok(serialized) = serde_json::to_string_pretty(&json) {
                        let _ = std::fs::write(&networks_path, serialized);
                        println!(
                            "    └─ Mesh-Overlay: '{}' aktiviert [{}]",
                            net_name.bright_magenta().bold(),
                            subnet.bright_yellow()
                        );
                    }
                }
            }
        }
    }
}

pub fn handle_use_cmd(name: &str) {
    let store = ContextStore::new();
    match store.switch_to(name) {
        Ok(ctx) => {
            println!(
                "  {} Aktiver Kontext gewechselt zu '{}' [{}].",
                "✓".green().bold(),
                ctx.name.bright_white().bold(),
                ctx.env.bright_green()
            );
            if let Some(srv) = ctx.target_server {
                println!("    └─ Zielserver: {}", srv.cyan());
            }
            if let Some(ws) = ctx.workspace_root {
                println!("    └─ Workspace:  {}", ws.display());
            }

            // Multi-Mesh & Forge Synchronisation
            println!(
                "    └─ Forge-Session: Environment '{}' synchronisiert",
                ctx.env.bright_green().bold()
            );
            sync_mesh_network_with_context(&ctx.name, ctx.mesh_swarm.as_deref());
        }
        Err(e) => {
            eprintln!("  {} {}", "✗".red().bold(), e);
            std::process::exit(1);
        }
    }
}

pub fn handle_context_cmd(action: Option<ContextAction>) {
    let store = ContextStore::new();
    match action {
        None | Some(ContextAction::List) => {
            let contexts = store.list_all();
            let active = store.get_active();
            context::print_context_list(&contexts, &active.name);
        }
        Some(ContextAction::Current) => {
            let active = store.get_active();
            println!();
            println!("{}", "  🌟 Aktiver Sovereign Kontext".cyan().bold());
            println!("  ───────────────────────────────────────────");
            println!("  Name:         {}", active.name.bright_white().bold());
            println!("  Beschreibung: {}", active.description);
            println!("  Environment:  {}", active.env.bright_green());
            if let Some(srv) = active.target_server {
                println!("  Ziel-Server:  {}", srv.cyan());
            }
            if let Some(ws) = active.workspace_root {
                println!("  Workspace:    {}", ws.display());
            }
            if let Some(swarm) = active.mesh_swarm {
                println!("  Swarm Topic:  {}", swarm.bright_magenta());
            }
            println!("  Erstellt am:  {}", active.created_at.bright_black());
            println!("  Zuletzt am:   {}", active.last_used_at.bright_black());
            println!("  ───────────────────────────────────────────\n");
        }
        Some(ContextAction::Use { name }) => {
            handle_use_cmd(&name);
        }
        Some(ContextAction::Create {
            name,
            desc,
            env,
            workspace,
            server,
            swarm,
        }) => match store.create(&name, desc, Some(env), workspace, server, swarm) {
            Ok(ctx) => {
                println!(
                    "  {} Kontext '{}' erfolgreich angelegt.",
                    "✓".green().bold(),
                    ctx.name.bright_white().bold()
                );
                println!(
                    "    Aktiviere ihn mit: {}\n",
                    format!("sb use {}", ctx.name).yellow().bold()
                );
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                std::process::exit(1);
            }
        },
        Some(ContextAction::Remove { name }) => match store.remove(&name) {
            Ok(()) => {
                println!("  {} Kontext '{}' gelöscht.\n", "✓".green().bold(), name);
            }
            Err(e) => {
                eprintln!("  {} {}", "✗".red().bold(), e);
                std::process::exit(1);
            }
        },
    }
}
