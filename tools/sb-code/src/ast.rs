use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of AST scope within a source file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AstScopeKind {
    Function,
    Method,
    Struct,
    ClassContainer,
    Impl,
    Module,
    Imports,
    Field,
    Opaque,
    Unknown,
}

impl std::fmt::Display for AstScopeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AstScopeKind::Function => write!(f, "function"),
            AstScopeKind::Method => write!(f, "method"),
            AstScopeKind::Struct => write!(f, "struct"),
            AstScopeKind::ClassContainer => write!(f, "class (container)"),
            AstScopeKind::Impl => write!(f, "impl"),
            AstScopeKind::Module => write!(f, "mod"),
            AstScopeKind::Imports => write!(f, "imports"),
            AstScopeKind::Field => write!(f, "field"),
            AstScopeKind::Opaque => write!(f, "opaque"),
            AstScopeKind::Unknown => write!(f, "block"),
        }
    }
}

/// An identified syntactic scope in the code AST.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstScope {
    pub id: String,
    pub name: String,
    pub kind: AstScopeKind,
    pub start_line: usize,
    pub end_line: usize,
    pub is_container: bool,
}

/// An active lock claimed on an AST scope by a Swarm peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AstScopeLock {
    pub scope_id: String,
    pub locked_by: String,
    pub acquired_at: i64,
    pub last_heartbeat: i64,
    pub ttl_seconds: i64,
}

impl AstScopeLock {
    pub fn is_expired(&self, now_unix: i64) -> bool {
        (now_unix - self.last_heartbeat) > self.ttl_seconds
    }
}

/// Table tracking all active AST scope locks in the workspace.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AstLockTable {
    pub locks: HashMap<String, AstScopeLock>,
}

impl AstLockTable {
    pub fn new() -> Self {
        Self {
            locks: HashMap::new(),
        }
    }

    /// Attempts to claim an exclusive lock on an AST scope.
    pub fn claim(&mut self, scope: &AstScope, peer: &str, now_unix: i64) -> Result<(), String> {
        if scope.kind == AstScopeKind::Opaque || scope.id.contains("::opaque:") {
            return Err(format!(
                "AST-Scope '{}' ist Opaque und kann nicht zuverlässig exklusiv gesperrt werden",
                scope.id
            ));
        }
        // Container scopes (like class declarations) can never be exclusively locked!
        if scope.is_container {
            return Ok(());
        }

        self.cleanup_expired(now_unix);

        if let Some(existing) = self.locks.get(&scope.id) {
            if existing.locked_by != peer && !existing.is_expired(now_unix) {
                return Err(format!(
                    "AST-Scope '{}' ist gesperrt durch '{}' (TTL: {}s verbleibend)",
                    scope.id,
                    existing.locked_by,
                    existing.ttl_seconds - (now_unix - existing.last_heartbeat)
                ));
            }
        }

        self.locks.insert(
            scope.id.clone(),
            AstScopeLock {
                scope_id: scope.id.clone(),
                locked_by: peer.to_string(),
                acquired_at: now_unix,
                last_heartbeat: now_unix,
                ttl_seconds: 180, // 3 minutes TTL
            },
        );

        Ok(())
    }

    /// Releases an AST scope lock owned by the peer.
    pub fn release(&mut self, scope_id: &str, peer: &str) {
        if let Some(lock) = self.locks.get(scope_id) {
            if lock.locked_by == peer {
                self.locks.remove(scope_id);
            }
        }
    }

    /// Heartbeat refresh when the user is actively typing.
    pub fn heartbeat(&mut self, scope_id: &str, peer: &str, now_unix: i64) {
        if let Some(lock) = self.locks.get_mut(scope_id) {
            if lock.locked_by == peer {
                lock.last_heartbeat = now_unix;
            }
        }
    }

    /// Removes expired locks.
    pub fn cleanup_expired(&mut self, now_unix: i64) {
        self.locks.retain(|_, lock| !lock.is_expired(now_unix));
    }

    /// Checks if a scope is locked by another peer.
    pub fn is_locked_by_other(
        &self,
        scope_id: &str,
        current_peer: &str,
        now_unix: i64,
    ) -> Option<&AstScopeLock> {
        let lock = self.locks.get(scope_id).or_else(|| {
            if let Some(stripped) = scope_id.strip_suffix("#0") {
                self.locks.get(stripped)
            } else {
                let with_zero = format!("{}#0", scope_id);
                self.locks.get(&with_zero)
            }
        });
        lock.and_then(|lock| {
            if lock.locked_by != current_peer && !lock.is_expired(now_unix) {
                Some(lock)
            } else {
                None
            }
        })
    }

    /// Loads active locks from .sb/ast_locks.json in workspace.
    pub fn load_from_workspace(workspace: &std::path::Path) -> Self {
        let path = workspace.join(".sb").join("ast_locks.json");
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(table) = serde_json::from_str::<Self>(&data) {
                    return table;
                }
            }
        }
        Self::new()
    }

    /// Persists active locks to .sb/ast_locks.json in workspace.
    pub fn save_to_workspace(&self, workspace: &std::path::Path) -> Result<(), String> {
        let sb_dir = workspace.join(".sb");
        let _ = std::fs::create_dir_all(&sb_dir);
        let path = sb_dir.join("ast_locks.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Fehler beim Serialisieren der Locks: {}", e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Fehler beim Schreiben von ast_locks.json: {}", e))?;
        Ok(())
    }

    /// Returns all unexpired locks with their remaining TTL in seconds.
    pub fn list_active_locks(&self, now_unix: i64) -> Vec<(&AstScopeLock, i64)> {
        let mut list = Vec::new();
        for lock in self.locks.values() {
            if !lock.is_expired(now_unix) {
                let remaining = (lock.ttl_seconds - (now_unix - lock.last_heartbeat)).max(0);
                list.push((lock, remaining));
            }
        }
        list.sort_by(|a, b| a.0.scope_id.cmp(&b.0.scope_id));
        list
    }
}

/// Parses editable live scopes through the same versioned language registry as VCS snapshots.
pub fn parse_live_ast_scopes(file_path: &str, content: &str) -> Result<Vec<AstScope>, String> {
    Ok(crate::language::parse_source(file_path, content)?.scopes)
}

/// Finds the best matching scope by function/class name or line number.
pub fn find_scope_by_name_or_line<'a>(
    scopes: &'a [AstScope],
    target: &str,
) -> Option<&'a AstScope> {
    if let Ok(line_num) = target.parse::<usize>() {
        return resolve_innermost_scope(scopes, line_num);
    }

    let target_clean = target.trim().to_lowercase();
    // 1. Exact name match
    if let Some(s) = scopes
        .iter()
        .find(|s| s.name.to_lowercase() == target_clean)
    {
        return Some(s);
    }
    // 2. Contains match
    if let Some(s) = scopes
        .iter()
        .find(|s| s.name.to_lowercase().contains(&target_clean))
    {
        return Some(s);
    }
    // 3. ID contains match
    scopes
        .iter()
        .find(|s| s.id.to_lowercase().contains(&target_clean))
}

/// Extracts AST scopes from source code content.
pub fn parse_ast_scopes(file_path: &str, content: &str) -> Vec<AstScope> {
    let mut scopes = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    // Line-by-line semantic block parser (Rust, Java, Python, Go, JS/TS)
    let mut i = 0;
    let total = lines.len();

    while i < total {
        let line = lines[i].trim();

        // 1. Imports block
        if line.starts_with("use ") || line.starts_with("import ") || line.starts_with("package ") {
            let start = i + 1;
            while i < total
                && (lines[i].trim().starts_with("use ")
                    || lines[i].trim().starts_with("import ")
                    || lines[i].trim().starts_with("package ")
                    || lines[i].trim().is_empty())
            {
                i += 1;
            }
            let end = i;
            scopes.push(AstScope {
                id: format!("{}::imports", file_path),
                name: "imports".to_string(),
                kind: AstScopeKind::Imports,
                start_line: start,
                end_line: end,
                is_container: false,
            });
            continue;
        }

        // 2. Class Container (Java, C#, Python, TS) - NOT exclusively locked
        if (line.contains("class ") || line.contains("interface ")) && line.contains('{') {
            let name = extract_identifier(line, "class ")
                .or_else(|| extract_identifier(line, "interface "))
                .unwrap_or_else(|| "AnonymousClass".to_string());

            scopes.push(AstScope {
                id: format!("{}::class:{}", file_path, name),
                name: name.clone(),
                kind: AstScopeKind::ClassContainer,
                start_line: i + 1,
                end_line: total,    // container spans whole file
                is_container: true, // Container flag protects methods inside!
            });
            i += 1;
            continue;
        }

        // 3. Methods & Functions
        if is_function_or_method(line) {
            let start = i + 1;
            let name = extract_function_name(line);
            i = find_scope_end(&lines, i);
            let end = i;

            scopes.push(AstScope {
                id: format!("{}::fn:{}", file_path, name),
                name,
                kind: AstScopeKind::Method,
                start_line: start,
                end_line: end.max(start),
                is_container: false,
            });
            continue;
        }

        // 4. Struct / Enum
        if (line.starts_with("struct ")
            || line.starts_with("pub struct ")
            || line.starts_with("enum ")
            || line.starts_with("pub enum "))
            && line.contains('{')
        {
            let start = i + 1;
            let name = extract_identifier(line, "struct ")
                .or_else(|| extract_identifier(line, "enum "))
                .unwrap_or_else(|| "AnonymousStruct".to_string());

            i = find_scope_end(&lines, i);
            let end = i;

            scopes.push(AstScope {
                id: format!("{}::struct:{}", file_path, name),
                name,
                kind: AstScopeKind::Struct,
                start_line: start,
                end_line: end.max(start),
                is_container: false,
            });
            continue;
        }

        i += 1;
    }

    scopes
}

#[derive(Default)]
struct SourceLexState {
    block_comment_depth: usize,
    string: Option<StringState>,
}

struct StringState {
    delimiter: char,
    raw_hashes: Option<usize>,
    triple: bool,
    escaped: bool,
}

fn find_scope_end(lines: &[&str], start: usize) -> usize {
    let mut state = SourceLexState::default();
    let mut depth = 0usize;
    let mut saw_opening_brace = false;

    for (line_index, line) in lines.iter().enumerate().skip(start) {
        let delta = scan_brace_delta(line, &mut state);
        if delta > 0 {
            saw_opening_brace = true;
            depth = depth.saturating_add(delta as usize);
        } else if delta < 0 {
            depth = depth.saturating_sub(delta.unsigned_abs() as usize);
        }
        if saw_opening_brace && depth == 0 {
            return line_index + 1;
        }
        if !saw_opening_brace && line_index == start {
            return start + 1;
        }
    }
    lines.len()
}

fn scan_brace_delta(line: &str, state: &mut SourceLexState) -> i32 {
    // CVE-Threat: Braces in comments or literals can truncate an AST scope.
    // Analysis: Naive character counting can mis-bound a patch and touch neighboring code.
    // Hardening: Count braces only in lexical code, tracking comments and string delimiters.
    let chars = line.chars().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut delta = 0i32;
    while index < chars.len() {
        if state.block_comment_depth > 0 {
            if chars.get(index) == Some(&'/') && chars.get(index + 1) == Some(&'*') {
                state.block_comment_depth += 1;
                index += 2;
            } else if chars.get(index) == Some(&'*') && chars.get(index + 1) == Some(&'/') {
                state.block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if let Some(string) = state.string.as_mut() {
            if let Some(raw_hashes) = string.raw_hashes {
                if chars[index] == string.delimiter
                    && (0..raw_hashes).all(|offset| chars.get(index + 1 + offset) == Some(&'#'))
                {
                    index += 1 + raw_hashes;
                    state.string = None;
                } else {
                    index += 1;
                }
                continue;
            }

            if string.triple {
                if chars[index] == string.delimiter
                    && chars.get(index + 1) == Some(&string.delimiter)
                    && chars.get(index + 2) == Some(&string.delimiter)
                {
                    index += 3;
                    state.string = None;
                } else {
                    index += 1;
                }
                continue;
            }

            if string.escaped {
                string.escaped = false;
                index += 1;
            } else if chars[index] == '\\' {
                string.escaped = true;
                index += 1;
            } else if chars[index] == string.delimiter {
                state.string = None;
                index += 1;
            } else {
                index += 1;
            }
            continue;
        }

        if chars[index] == '/' && chars.get(index + 1) == Some(&'/') {
            break;
        }
        if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
            state.block_comment_depth = 1;
            index += 2;
            continue;
        }
        if chars[index] == '#'
            && chars.get(index + 1) != Some(&'[')
            && !(chars.get(index + 1) == Some(&'!') && chars.get(index + 2) == Some(&'['))
        {
            break;
        }

        let raw_prefix = if chars[index] == 'r' {
            Some(index + 1)
        } else if chars[index] == 'b' && chars.get(index + 1) == Some(&'r') {
            Some(index + 2)
        } else {
            None
        };
        if let Some(mut cursor) = raw_prefix {
            while chars.get(cursor) == Some(&'#') {
                cursor += 1;
            }
            if chars.get(cursor) == Some(&'"') {
                state.string = Some(StringState {
                    delimiter: '"',
                    raw_hashes: Some(cursor - raw_prefix.unwrap()),
                    triple: false,
                    escaped: false,
                });
                index = cursor + 1;
                continue;
            }
        }

        let delimiter = chars[index];
        if delimiter == '"' || delimiter == '`' || delimiter == '\'' {
            let triple = delimiter == '"'
                && chars.get(index + 1) == Some(&'"')
                && chars.get(index + 2) == Some(&'"');
            if delimiter != '\'' || has_short_char_literal(&chars, index) {
                state.string = Some(StringState {
                    delimiter,
                    raw_hashes: None,
                    triple,
                    escaped: false,
                });
                index += if triple { 3 } else { 1 };
                continue;
            }
        }

        match delimiter {
            '{' => delta += 1,
            '}' => delta -= 1,
            _ => {}
        }
        index += 1;
    }
    delta
}

fn has_short_char_literal(chars: &[char], start: usize) -> bool {
    let mut escaped = false;
    for index in start + 1..chars.len().min(start + 5) {
        if escaped {
            escaped = false;
        } else if chars[index] == '\\' {
            escaped = true;
        } else if chars[index] == '\'' {
            return true;
        }
    }
    false
}

/// Returns non-overlapping recognized scopes and opaque gaps covering the file.
pub fn parse_ast_scopes_with_opaque(file_path: &str, content: &str) -> Vec<AstScope> {
    let line_count = content.split_inclusive('\n').count();
    if line_count == 0 {
        return Vec::new();
    }

    let mut recognized = parse_ast_scopes(file_path, content)
        .into_iter()
        .filter(|scope| !scope.is_container)
        .collect::<Vec<_>>();
    recognized.sort_by_key(|scope| (scope.start_line, scope.end_line));
    if recognized.iter().any(|scope| {
        scope.start_line == 0 || scope.start_line > scope.end_line || scope.end_line > line_count
    }) || recognized
        .windows(2)
        .any(|pair| pair[0].end_line >= pair[1].start_line)
    {
        return vec![AstScope {
            id: format!("{file_path}::opaque:start->end"),
            name: "opaque region (start … end)".to_string(),
            kind: AstScopeKind::Opaque,
            start_line: 1,
            end_line: line_count,
            is_container: false,
        }];
    }

    let mut occurrences = HashMap::<String, usize>::new();
    let recognized = recognized
        .into_iter()
        .map(|mut scope| {
            let occurrence = occurrences.entry(scope.id.clone()).or_default();
            let stable_id = format!("{}#{}", scope.id, *occurrence);
            *occurrence += 1;
            scope.id = stable_id;
            scope
        })
        .collect::<Vec<_>>();

    let mut complete = Vec::with_capacity(recognized.len() * 2 + 1);
    let mut next_line = 1usize;
    for (index, scope) in recognized.iter().enumerate() {
        if next_line < scope.start_line {
            let previous = index
                .checked_sub(1)
                .and_then(|previous| recognized.get(previous))
                .map(|previous| previous.id.as_str())
                .unwrap_or("start");
            if let Some(opaque) = opaque_gap(
                file_path,
                previous,
                &scope.id,
                next_line,
                scope.start_line - 1,
                content,
            ) {
                complete.push(opaque);
            }
        }
        next_line = scope.end_line.saturating_add(1);
        complete.push(scope.clone());
    }
    if next_line <= line_count {
        let previous = recognized
            .last()
            .map(|scope| scope.id.as_str())
            .unwrap_or("start");
        if let Some(opaque) = opaque_gap(file_path, previous, "end", next_line, line_count, content)
        {
            complete.push(opaque);
        }
    }
    complete
}

fn opaque_gap(
    file_path: &str,
    previous: &str,
    next: &str,
    start_line: usize,
    end_line: usize,
    content: &str,
) -> Option<AstScope> {
    let lines = content.split_inclusive('\n').collect::<Vec<_>>();
    let gap = lines.get(start_line.saturating_sub(1)..end_line)?;
    let first = gap.iter().position(|line| !line.trim().is_empty())?;
    let last = gap.iter().rposition(|line| !line.trim().is_empty())?;
    Some(AstScope {
        id: format!("{file_path}::opaque:{previous}->{next}"),
        name: format!("opaque region ({previous} … {next})"),
        kind: AstScopeKind::Opaque,
        start_line: start_line + first,
        end_line: start_line + last,
        is_container: false,
    })
}

/// Resolves the innermost non-container AST scope for a given line number.
pub fn resolve_innermost_scope<'a>(scopes: &'a [AstScope], line: usize) -> Option<&'a AstScope> {
    // Find non-container scopes that enclose the line, with smallest span
    scopes
        .iter()
        .filter(|s| !s.is_container && line >= s.start_line && line <= s.end_line)
        .min_by_key(|s| s.end_line - s.start_line)
}

fn is_function_or_method(line: &str) -> bool {
    let l = line.trim();
    if l.starts_with("//")
        || l.starts_with("/*")
        || l.starts_with('*')
        || (l.starts_with('#') && !l.starts_with("#["))
    {
        return false;
    }
    let signature_head = l.split_once('(').map(|(head, _)| head).unwrap_or(l);
    let has_declaration_prefix = l.starts_with("fn ")
        || l.starts_with("def ")
        || l.starts_with("async fn ")
        || l.starts_with("async def ")
        || l.starts_with("func ")
        || l.starts_with("function ")
        || l.starts_with("export function ")
        || ((l.starts_with("pub ") || l.starts_with("pub(")) && signature_head.contains("fn "))
        || l.starts_with("public ")
        || l.starts_with("private ")
        || l.starts_with("protected ");
    has_declaration_prefix
        && l.contains('(')
        && (l.contains(')') || l.contains('{'))
        && !signature_head.contains('=')
        && !l.contains("class ")
}

fn extract_function_name(line: &str) -> String {
    let mut s = line.trim();
    if let Some(pos) = s.find('(') {
        s = &s[..pos];
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts.last().copied().unwrap_or("anonymous").to_string()
}

fn extract_identifier(line: &str, keyword: &str) -> Option<String> {
    let pos = line.find(keyword)?;
    let rest = &line[pos + keyword.len()..];
    let ident = rest
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()?
        .trim();
    if ident.is_empty() {
        None
    } else {
        Some(ident.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_scopes_cover_non_whitespace_gaps_without_overlapping_code_scopes() {
        let source =
            "// module header\nconst VALUE: u32 = 1;\n\npub fn alpha() { 1 }\n// trailing note\n";
        let scopes = parse_ast_scopes_with_opaque("src/lib.rs", source);
        let mut ranges = scopes
            .iter()
            .map(|scope| (scope.start_line, scope.end_line))
            .collect::<Vec<_>>();
        ranges.sort_unstable();

        assert!(scopes
            .iter()
            .any(|scope| scope.kind == AstScopeKind::Opaque && scope.name.contains("start")));
        assert!(scopes
            .iter()
            .any(|scope| scope.kind == AstScopeKind::Method && scope.name == "alpha"));
        assert!(scopes
            .iter()
            .any(|scope| scope.kind == AstScopeKind::Opaque && scope.name.contains("end")));
        assert!(ranges.windows(2).all(|pair| pair[0].1 < pair[1].0));
    }

    #[test]
    fn unsupported_syntax_is_preserved_as_an_opaque_scope() {
        let source = "macro_rules! generated {\n    ($item:item) => { $item };\n}\n";
        let scopes = parse_ast_scopes_with_opaque("src/lib.rs", source);
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].kind, AstScopeKind::Opaque);
        assert_eq!((scopes[0].start_line, scopes[0].end_line), (1, 3));
    }

    #[test]
    fn braces_inside_strings_and_comments_do_not_end_a_scope_early() {
        let source = "pub fn alpha() {\n    let text = \"}\";\n    /* } */\n    // }\n    let raw = r#\"}\"#;\n}\npub fn beta() { 2 }\n";
        let scopes = parse_ast_scopes("src/lib.rs", source);
        let alpha = scopes.iter().find(|scope| scope.name == "alpha").unwrap();
        let beta = scopes.iter().find(|scope| scope.name == "beta").unwrap();
        assert_eq!(alpha.end_line, 6);
        assert_eq!(beta.start_line, 7);
    }

    #[test]
    fn declaration_like_text_in_comments_is_not_classified_as_code() {
        let source = "// fn fake() { }\nconst NOTE: &str = \"fn also_fake() { }\";\n";
        assert!(parse_ast_scopes("src/lib.rs", source).is_empty());
        let complete = parse_ast_scopes_with_opaque("src/lib.rs", source);
        assert_eq!(complete.len(), 1);
        assert_eq!(complete[0].kind, AstScopeKind::Opaque);
    }

    #[test]
    fn test_java_class_method_granularity() {
        let java_code = r#"
package com.example;
import java.util.List;

public class OrderService {
    private int timeout = 5000;

    public void calculateTotal(Order order) {
        int sum = 0;
        sum += order.getPrice();
    }

    public void processPayment(Payment payment) {
        payment.charge();
    }
}
"#;

        let scopes = parse_ast_scopes("src/OrderService.java", java_code);

        // Class is detected as container
        let class_scope = scopes
            .iter()
            .find(|s| s.kind == AstScopeKind::ClassContainer)
            .unwrap();
        assert!(class_scope.is_container);
        assert_eq!(class_scope.name, "OrderService");

        // Two independent methods are detected
        let calc_method = scopes
            .iter()
            .find(|s| s.name.contains("calculateTotal"))
            .unwrap();
        assert!(!calc_method.is_container);
        assert_eq!(calc_method.kind, AstScopeKind::Method);

        let pay_method = scopes
            .iter()
            .find(|s| s.name.contains("processPayment"))
            .unwrap();
        assert!(!pay_method.is_container);

        // Resolving line in calculateTotal returns method scope, NOT class container
        let scope = resolve_innermost_scope(&scopes, 9).unwrap();
        assert_eq!(scope.name, calc_method.name);
    }

    #[test]
    fn test_ast_lock_table_claim_and_ttl() {
        let mut table = AstLockTable::new();
        let scope = AstScope {
            id: "src/auth.rs::fn:login".to_string(),
            name: "login".to_string(),
            kind: AstScopeKind::Function,
            start_line: 10,
            end_line: 20,
            is_container: false,
        };

        // Sentinel claims lock at t=1000
        assert!(table.claim(&scope, "sentinel-prime", 1000).is_ok());

        // Apex tries to claim same scope -> rejected
        assert!(table.claim(&scope, "apex-vanguard", 1050).is_err());

        // Apex checks if locked by other
        assert!(table
            .is_locked_by_other(&scope.id, "apex-vanguard", 1050)
            .is_some());
        assert!(table
            .is_locked_by_other(&scope.id, "sentinel-prime", 1050)
            .is_none());

        // Sentinel releases -> Apex can now claim
        table.release(&scope.id, "sentinel-prime");
        assert!(table.claim(&scope, "apex-vanguard", 1100).is_ok());
    }

    #[test]
    fn opaque_scope_cannot_be_claimed_as_a_live_lock() {
        let mut table = AstLockTable::new();
        let opaque = AstScope {
            id: "src/main.py::opaque:start->end".to_string(),
            name: "opaque region".to_string(),
            kind: AstScopeKind::Opaque,
            start_line: 1,
            end_line: 3,
            is_container: false,
        };

        let result = table.claim(&opaque, "alice", 1000);
        assert!(result.unwrap_err().contains("Opaque"));
        assert!(table.locks.is_empty());
    }

    #[test]
    fn live_scope_parser_uses_tree_sitter_and_rejects_unknown_language_for_locking() {
        let rust = parse_live_ast_scopes("src/lib.rs", "pub fn build() { 1 }\n").unwrap();
        let function = rust.iter().find(|scope| scope.name == "build").unwrap();
        assert_eq!(function.id, "src/lib.rs::fn:build#0");
        assert_eq!(function.kind, AstScopeKind::Function);

        let python = parse_live_ast_scopes("src/main.py", "def build():\n    return 1\n").unwrap();
        assert_eq!(python[0].kind, AstScopeKind::Opaque);
        let mut locks = AstLockTable::new();
        assert!(locks.claim(&python[0], "alice", 1000).is_err());
    }

    #[test]
    fn test_zombie_lock_expiration() {
        let mut table = AstLockTable::new();
        let scope = AstScope {
            id: "src/auth.rs::fn:verify".to_string(),
            name: "verify".to_string(),
            kind: AstScopeKind::Function,
            start_line: 30,
            end_line: 40,
            is_container: false,
        };

        // Claimed at t=1000 (TTL = 180s, expires at 1180)
        table.claim(&scope, "sentinel-prime", 1000).unwrap();

        // At t=1100, still locked
        assert!(table
            .is_locked_by_other(&scope.id, "apex-vanguard", 1100)
            .is_some());

        // At t=1200 (>1180), lock has expired!
        assert!(table
            .is_locked_by_other(&scope.id, "apex-vanguard", 1200)
            .is_none());

        // Apex can claim without error
        assert!(table.claim(&scope, "apex-vanguard", 1200).is_ok());
    }
}
