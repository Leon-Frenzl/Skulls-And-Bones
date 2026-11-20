use crate::logs;
use colored::*;

pub fn handle_logs_cmd(
    server: Option<String>,
    service: Option<String>,
    follow: bool,
    lines: usize,
    local: bool,
) {
    if local {
        logs::stream_local_logs(lines);
        return;
    }

    if let Some(target) = sb_core::TargetResolver::resolve_node_or_default(server.as_deref()) {
        if let Err(e) =
            logs::stream_remote_logs_to_target(&target, service.as_deref(), lines, follow)
        {
            sb_core::logfmt::warn(
                "ERR_SB_REMOTE_LOGS",
                "sb.logs",
                "Remote logs fetch failed; falling back to local audit logs",
                &[("error", &e.to_string())],
            );
            println!("  {} Fallback auf lokale Audit-Logs...", "ℹ".cyan());
            logs::stream_local_logs(lines);
        }
    } else {
        logs::stream_local_logs(lines);
    }
}
