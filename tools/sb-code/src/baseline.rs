use crate::ast::{AstLockTable, AstScope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cache storing the last known stable, compiling AST code blocks.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BaselineCache {
    /// Mapping: scope_id -> stable code content
    pub stable_nodes: HashMap<String, String>,
}

impl BaselineCache {
    pub fn new() -> Self {
        Self {
            stable_nodes: HashMap::new(),
        }
    }

    /// Stores a verified, compiling version of an AST scope.
    pub fn save_stable_scope(&mut self, scope_id: &str, content: &str) {
        self.stable_nodes
            .insert(scope_id.to_string(), content.to_string());
    }

    /// Retrieves the stable baseline version of a scope.
    pub fn get_stable_scope(&self, scope_id: &str) -> Option<&str> {
        let direct = self.stable_nodes.get(scope_id).map(|s| s.as_str());
        if direct.is_some() {
            return direct;
        }
        if let Some(stripped) = scope_id.strip_suffix("#0") {
            self.stable_nodes.get(stripped).map(|s| s.as_str())
        } else {
            let with_zero = format!("{}#0", scope_id);
            self.stable_nodes.get(&with_zero).map(|s| s.as_str())
        }
    }

    /// Loads baseline cache from .sb/baseline_cache.json in workspace.
    pub fn load_from_workspace(workspace: &std::path::Path) -> Self {
        let path = workspace.join(".sb").join("baseline_cache.json");
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(cache) = serde_json::from_str::<Self>(&data) {
                    return cache;
                }
            }
        }
        Self::new()
    }

    /// Persists baseline cache to .sb/baseline_cache.json in workspace.
    pub fn save_to_workspace(&self, workspace: &std::path::Path) -> Result<(), String> {
        let sb_dir = workspace.join(".sb");
        let _ = std::fs::create_dir_all(&sb_dir);
        let path = sb_dir.join("baseline_cache.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Fehler beim Serialisieren der Baseline: {}", e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Fehler beim Schreiben von baseline_cache.json: {}", e))?;
        Ok(())
    }

    /// Synthesizes the view of a file for a specific peer.
    /// If an AST scope is actively locked by someone else, replaces that scope with the stable baseline!
    pub fn render_dual_view(
        &self,
        raw_content: &str,
        scopes: &[AstScope],
        locks: &AstLockTable,
        viewer_peer: &str,
        now_unix: i64,
    ) -> String {
        let lines: Vec<&str> = raw_content.lines().collect();
        let mut output_lines = Vec::new();
        let mut line_idx = 1;

        while line_idx <= lines.len() {
            // Check if line_idx starts an AST scope locked by another peer
            let locked_scope = scopes.iter().find(|s| {
                s.start_line == line_idx
                    && locks
                        .is_locked_by_other(&s.id, viewer_peer, now_unix)
                        .is_some()
            });

            if let Some(scope) = locked_scope {
                // Someone else has locked this scope!
                // If we have a stable baseline for this scope, inject it instead of the unfinished code
                if let Some(stable_code) = self.get_stable_scope(&scope.id) {
                    for stable_line in stable_code.lines() {
                        output_lines.push(stable_line.to_string());
                    }
                } else {
                    // Fallback to existing code lines if no previous baseline recorded yet
                    for i in scope.start_line..=scope.end_line.min(lines.len()) {
                        output_lines.push(lines[i - 1].to_string());
                    }
                }
                // Advance line_idx past the locked scope
                line_idx = scope.end_line + 1;
            } else {
                output_lines.push(lines[line_idx - 1].to_string());
                line_idx += 1;
            }
        }

        output_lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::AstScopeKind;

    #[test]
    fn test_dual_view_compilation_isolation() {
        let mut baseline = BaselineCache::new();

        // 1. Initial stable state
        let scope_id = "src/lib.rs::fn:add";
        let stable_code = "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}";
        baseline.save_stable_scope(scope_id, stable_code);

        // 2. Peer A is currently typing broken/incomplete code
        let raw_work_in_progress = "use std::io;\n\npub fn add(a: i32, b: i32) -> i32 {\n    let unclosed = \n}\n\npub fn sub(a: i32, b: i32) -> i32 {\n    a - b\n}";

        let scopes = vec![
            AstScope {
                id: scope_id.to_string(),
                name: "add".to_string(),
                kind: AstScopeKind::Function,
                start_line: 3,
                end_line: 5,
                is_container: false,
            },
            AstScope {
                id: "src/lib.rs::fn:sub".to_string(),
                name: "sub".to_string(),
                kind: AstScopeKind::Function,
                start_line: 7,
                end_line: 9,
                is_container: false,
            },
        ];

        let mut locks = AstLockTable::new();
        // Peer A ("sentinel-prime") has locked fn add
        locks.claim(&scopes[0], "sentinel-prime", 1000).unwrap();

        // 3. View for Peer A (the author): Sees their own work-in-progress code
        let view_author = baseline.render_dual_view(
            raw_work_in_progress,
            &scopes,
            &locks,
            "sentinel-prime",
            1000,
        );
        assert!(view_author.contains("let unclosed ="));

        // 4. View for Peer B ("apex-vanguard"): Sees the STABLE baseline!
        // Peer B's build does NOT see "let unclosed =" and remains completely green!
        let view_colleague =
            baseline.render_dual_view(raw_work_in_progress, &scopes, &locks, "apex-vanguard", 1000);
        assert!(!view_colleague.contains("let unclosed ="));
        assert!(view_colleague.contains("a + b"));
        assert!(view_colleague.contains("pub fn sub"));
    }
}
