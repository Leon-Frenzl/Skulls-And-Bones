use crate::ast::{AstScope, AstScopeKind};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use tree_sitter::{Language, Node, Parser};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeSpan {
    pub name: String,
    pub kind: AstScopeKind,
    pub start_line: usize,
    pub end_line: usize,
    pub is_container: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSource {
    pub parser_id: String,
    pub parser_version: u32,
    pub parser_diagnostic: Option<String>,
    pub scopes: Vec<AstScope>,
}

pub trait LanguageAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn version(&self) -> u32;
    fn extensions(&self) -> &'static [&'static str];
    fn parse(&self, source: &str) -> Result<Vec<ScopeSpan>, String>;
}

#[derive(Default)]
pub struct LanguageRegistry {
    adapters: HashMap<String, Arc<dyn LanguageAdapter>>,
}

impl LanguageRegistry {
    pub fn with_builtin_adapters() -> Result<Self, String> {
        let mut registry = Self::default();
        registry.register(Box::new(RustAdapter))?;
        registry.register(Box::new(TypeScriptAdapter { tsx: false }))?;
        registry.register(Box::new(TypeScriptAdapter { tsx: true }))?;
        registry.register(Box::new(JavaAdapter))?;
        Ok(registry)
    }

    pub fn register(&mut self, adapter: Box<dyn LanguageAdapter>) -> Result<(), String> {
        let extensions = adapter
            .extensions()
            .iter()
            .map(|extension| normalize_extension(extension))
            .collect::<Result<Vec<_>, _>>()?;
        if extensions.is_empty() {
            return Err(format!(
                "Language adapter '{}' must register at least one extension",
                adapter.id()
            ));
        }
        let mut seen = HashSet::new();
        for extension in &extensions {
            if !seen.insert(extension) {
                return Err(format!(
                    "Language adapter '{}' lists extension '{}' more than once",
                    adapter.id(),
                    extension
                ));
            }
            if self.adapters.contains_key(extension.as_str()) {
                return Err(format!(
                    "A language adapter is already registered for '{}'",
                    extension
                ));
            }
        }
        let adapter: Arc<dyn LanguageAdapter> = Arc::from(adapter);
        for extension in extensions {
            self.adapters.insert(extension, Arc::clone(&adapter));
        }
        Ok(())
    }

    pub fn parse(&self, file_path: &str, source: &str) -> Result<ParsedSource, String> {
        let extension = Path::new(file_path)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{}", value.to_ascii_lowercase()));
        let Some(adapter) = extension
            .as_ref()
            .and_then(|extension| self.adapters.get(extension))
        else {
            let diagnostic = extension
                .map(|extension| format!("No parser registered for '{}'", extension))
                .unwrap_or_else(|| "File has no recognizable extension".to_string());
            return Ok(opaque_source(
                file_path,
                source,
                "opaque-no-parser",
                1,
                Some(diagnostic),
            ));
        };

        match adapter.parse(source) {
            Ok(spans) => Ok(parsed_source(
                file_path,
                source,
                adapter.id(),
                adapter.version(),
                spans,
            )),
            Err(error) => Ok(opaque_source(
                file_path,
                source,
                adapter.id(),
                adapter.version(),
                Some(error),
            )),
        }
    }
}

static DEFAULT_REGISTRY: OnceLock<RwLock<LanguageRegistry>> = OnceLock::new();

fn default_registry() -> Result<&'static RwLock<LanguageRegistry>, String> {
    if let Some(registry) = DEFAULT_REGISTRY.get() {
        return Ok(registry);
    }
    let registry = LanguageRegistry::with_builtin_adapters()?;
    let _ = DEFAULT_REGISTRY.set(RwLock::new(registry));
    DEFAULT_REGISTRY
        .get()
        .ok_or_else(|| "Failed to initialize the language registry".to_string())
}

pub fn register_language_adapter(adapter: Box<dyn LanguageAdapter>) -> Result<(), String> {
    default_registry()?
        .write()
        .map_err(|_| "Language registry lock is poisoned".to_string())?
        .register(adapter)
}

pub fn parse_source(file_path: &str, source: &str) -> Result<ParsedSource, String> {
    default_registry()?
        .read()
        .map_err(|_| "Language registry lock is poisoned".to_string())?
        .parse(file_path, source)
}

pub fn parse_outline_containers(file_path: &str, source: &str) -> Result<Vec<ScopeSpan>, String> {
    let is_rust = Path::new(file_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));
    if !is_rust {
        return Ok(Vec::new());
    }

    Ok(parse_tree_sitter(source, Grammar::Rust)?
        .into_iter()
        .filter(|span| span.is_container)
        .collect())
}

fn normalize_extension(extension: &str) -> Result<String, String> {
    let normalized = extension.to_ascii_lowercase();
    if !normalized.starts_with('.')
        || normalized.len() < 2
        || normalized
            .chars()
            .skip(1)
            .any(|character| matches!(character, '/' | '\\'))
    {
        return Err(format!("Invalid language file extension '{}'", extension));
    }
    Ok(normalized)
}

fn parsed_source(
    file_path: &str,
    source: &str,
    parser_id: &str,
    parser_version: u32,
    spans: Vec<ScopeSpan>,
) -> ParsedSource {
    let line_count = source.split_inclusive('\n').count();
    if line_count == 0 {
        return ParsedSource {
            parser_id: parser_id.to_string(),
            parser_version,
            parser_diagnostic: None,
            scopes: Vec::new(),
        };
    }

    let mut recognized = spans
        .into_iter()
        .filter(|span| !span.is_container)
        .map(|span| AstScope {
            id: String::new(),
            name: span.name,
            kind: span.kind,
            start_line: span.start_line,
            end_line: span.end_line,
            is_container: false,
        })
        .collect::<Vec<_>>();
    recognized.sort_by_key(|scope| (scope.start_line, scope.end_line));
    if recognized.iter().any(|scope| {
        scope.start_line == 0 || scope.start_line > scope.end_line || scope.end_line > line_count
    }) || recognized
        .windows(2)
        .any(|pair| pair[0].end_line >= pair[1].start_line)
    {
        return opaque_source(
            file_path,
            source,
            parser_id,
            parser_version,
            Some("Parser emitted invalid or overlapping scope ranges".to_string()),
        );
    }

    let mut occurrences = HashMap::<String, usize>::new();
    for scope in &mut recognized {
        let base_id = match scope.kind {
            AstScopeKind::Function | AstScopeKind::Method => {
                format!("{file_path}::fn:{}", scope.name)
            }
            AstScopeKind::Struct => format!("{file_path}::struct:{}", scope.name),
            AstScopeKind::Imports => format!("{file_path}::imports"),
            AstScopeKind::Field => format!("{file_path}::field:{}", scope.name),
            _ => format!("{file_path}::{}:{}", scope.kind, scope.name),
        };
        let occurrence = occurrences.entry(base_id.clone()).or_default();
        scope.id = format!("{base_id}#{}", *occurrence);
        *occurrence += 1;
    }

    let mut scopes = Vec::with_capacity(recognized.len() * 2 + 1);
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
                source,
            ) {
                scopes.push(opaque);
            }
        }
        next_line = scope.end_line.saturating_add(1);
        scopes.push(scope.clone());
    }
    if next_line <= line_count {
        let previous = recognized
            .last()
            .map(|scope| scope.id.as_str())
            .unwrap_or("start");
        if let Some(opaque) = opaque_gap(file_path, previous, "end", next_line, line_count, source)
        {
            scopes.push(opaque);
        }
    }
    ParsedSource {
        parser_id: parser_id.to_string(),
        parser_version,
        parser_diagnostic: None,
        scopes,
    }
}

fn opaque_source(
    file_path: &str,
    source: &str,
    parser_id: &str,
    parser_version: u32,
    parser_diagnostic: Option<String>,
) -> ParsedSource {
    let line_count = source.split_inclusive('\n').count();
    let scopes = if line_count == 0 || source.trim().is_empty() {
        Vec::new()
    } else {
        vec![AstScope {
            id: format!("{file_path}::opaque:start->end"),
            name: "opaque region (start … end)".to_string(),
            kind: AstScopeKind::Opaque,
            start_line: 1,
            end_line: line_count,
            is_container: false,
        }]
    };
    ParsedSource {
        parser_id: parser_id.to_string(),
        parser_version,
        parser_diagnostic,
        scopes,
    }
}

fn opaque_gap(
    file_path: &str,
    previous: &str,
    next: &str,
    start_line: usize,
    end_line: usize,
    source: &str,
) -> Option<AstScope> {
    let lines = source.split_inclusive('\n').collect::<Vec<_>>();
    let text = lines[start_line - 1..end_line].concat();
    if text.trim().is_empty() {
        return None;
    }
    Some(AstScope {
        id: format!("{file_path}::opaque:{previous}->{next}"),
        name: format!("opaque region ({start_line} … {end_line})"),
        kind: AstScopeKind::Opaque,
        start_line,
        end_line,
        is_container: false,
    })
}

#[derive(Clone, Copy)]
enum Grammar {
    Rust,
    TypeScript,
    Tsx,
    Java,
}

fn parse_tree_sitter(source: &str, grammar: Grammar) -> Result<Vec<ScopeSpan>, String> {
    let language: Language = match grammar {
        Grammar::Rust => tree_sitter_rust::LANGUAGE.into(),
        Grammar::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Grammar::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Grammar::Java => tree_sitter_java::LANGUAGE.into(),
    };
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| format!("Could not initialize grammar: {error}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "Tree-sitter did not produce a syntax tree".to_string())?;
    if tree.root_node().has_error() {
        return Err("Syntax tree contains error or missing nodes".to_string());
    }
    let mut spans = Vec::new();
    collect_scopes(tree.root_node(), source, grammar, &mut spans)?;
    Ok(spans)
}

fn collect_scopes(
    node: Node<'_>,
    source: &str,
    grammar: Grammar,
    spans: &mut Vec<ScopeSpan>,
) -> Result<(), String> {
    let kind = node.kind();
    let recognized = match grammar {
        Grammar::Rust => match kind {
            "impl_item" => Some((
                node.utf8_text(source.as_bytes())
                    .map_err(|error| format!("Could not read syntax node: {error}"))?
                    .lines()
                    .next()
                    .unwrap_or("impl")
                    .trim()
                    .trim_end_matches('{')
                    .trim()
                    .to_string(),
                AstScopeKind::Impl,
                true,
            )),
            "mod_item" if node.child_by_field_name("body").is_some() => {
                Some((node_name(node, source, kind)?, AstScopeKind::Module, true))
            }
            "function_item" => Some((
                node_name(node, source, "function_item")?,
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "impl_item")
                {
                    AstScopeKind::Method
                } else {
                    AstScopeKind::Function
                },
                false,
            )),
            "struct_item" | "enum_item" => {
                Some((node_name(node, source, kind)?, AstScopeKind::Struct, false))
            }
            "use_declaration" => Some(("imports".to_string(), AstScopeKind::Imports, false)),
            _ => None,
        },
        Grammar::TypeScript | Grammar::Tsx => match kind {
            "function_declaration" => Some((
                node_name(node, source, kind)?,
                AstScopeKind::Function,
                false,
            )),
            "method_definition" | "abstract_method_signature" => {
                Some((node_name(node, source, kind)?, AstScopeKind::Method, false))
            }
            "import_statement" => Some(("imports".to_string(), AstScopeKind::Imports, false)),
            _ => None,
        },
        Grammar::Java => match kind {
            "method_declaration" | "constructor_declaration" => {
                Some((node_name(node, source, kind)?, AstScopeKind::Method, false))
            }
            "field_declaration" => {
                Some((node_name(node, source, kind)?, AstScopeKind::Field, false))
            }
            "import_declaration" => Some(("imports".to_string(), AstScopeKind::Imports, false)),
            _ => None,
        },
    };
    if let Some((name, scope_kind, is_container)) = recognized {
        spans.push(ScopeSpan {
            name,
            kind: scope_kind,
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
            is_container,
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_scopes(child, source, grammar, spans)?;
    }
    Ok(())
}

fn node_name(node: Node<'_>, source: &str, fallback: &str) -> Result<String, String> {
    let Some(name) = node.child_by_field_name("name") else {
        return Ok(format!("{fallback}@{}", node.start_position().row + 1));
    };
    let text = name
        .utf8_text(source.as_bytes())
        .map_err(|error| format!("Could not read syntax node name: {error}"))?;
    Ok(text.to_string())
}

#[derive(Clone)]
struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn id(&self) -> &'static str {
        "tree-sitter-rust@0.24.2"
    }

    fn version(&self) -> u32 {
        1
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".rs"]
    }

    fn parse(&self, source: &str) -> Result<Vec<ScopeSpan>, String> {
        parse_tree_sitter(source, Grammar::Rust)
    }
}

#[derive(Clone)]
struct TypeScriptAdapter {
    tsx: bool,
}

impl LanguageAdapter for TypeScriptAdapter {
    fn id(&self) -> &'static str {
        if self.tsx {
            "tree-sitter-tsx@0.23.2"
        } else {
            "tree-sitter-typescript@0.23.2"
        }
    }

    fn version(&self) -> u32 {
        1
    }

    fn extensions(&self) -> &'static [&'static str] {
        if self.tsx {
            &[".tsx"]
        } else {
            &[".ts"]
        }
    }

    fn parse(&self, source: &str) -> Result<Vec<ScopeSpan>, String> {
        parse_tree_sitter(
            source,
            if self.tsx {
                Grammar::Tsx
            } else {
                Grammar::TypeScript
            },
        )
    }
}

#[derive(Clone)]
struct JavaAdapter;

impl LanguageAdapter for JavaAdapter {
    fn id(&self) -> &'static str {
        "tree-sitter-java@0.23.5"
    }

    fn version(&self) -> u32 {
        1
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".java"]
    }

    fn parse(&self, source: &str) -> Result<Vec<ScopeSpan>, String> {
        parse_tree_sitter(source, Grammar::Java)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_sitter_adapters_extract_non_overlapping_scopes() {
        let registry = LanguageRegistry::with_builtin_adapters().unwrap();
        let rust = registry
            .parse("src/lib.rs", "pub fn alpha() { 1 }\n")
            .unwrap();
        assert_eq!(rust.parser_id, "tree-sitter-rust@0.24.2");
        assert!(rust.scopes.iter().any(|scope| scope.name == "alpha"));

        let typescript = registry
            .parse("src/service.ts", "export function run() { return 1; }\n")
            .unwrap();
        assert!(typescript
            .scopes
            .iter()
            .any(|scope| scope.kind == AstScopeKind::Function && scope.name == "run"));

        let java = registry
            .parse(
                "src/Service.java",
                "class Service { int run() { return 1; } }\n",
            )
            .unwrap();
        assert!(java
            .scopes
            .iter()
            .any(|scope| scope.kind == AstScopeKind::Method && scope.name == "run"));
    }

    #[test]
    fn unsupported_or_invalid_sources_remain_opaque() {
        let registry = LanguageRegistry::with_builtin_adapters().unwrap();
        let unknown = registry
            .parse("src/main.py", "def run():\n    return 1\n")
            .unwrap();
        assert_eq!(unknown.scopes[0].kind, AstScopeKind::Opaque);
        assert!(unknown.parser_diagnostic.is_some());

        let invalid = registry
            .parse("src/lib.rs", "pub fn unfinished( {\n")
            .unwrap();
        assert_eq!(invalid.scopes[0].kind, AstScopeKind::Opaque);
        assert!(invalid.parser_diagnostic.is_some());
    }

    #[test]
    fn extension_collisions_are_rejected() {
        let mut registry = LanguageRegistry::with_builtin_adapters().unwrap();
        assert!(registry.register(Box::new(RustAdapter)).is_err());
    }

    #[test]
    fn custom_language_adapter_can_be_registered_without_core_changes() {
        #[derive(Clone)]
        struct ExampleAdapter;

        impl LanguageAdapter for ExampleAdapter {
            fn id(&self) -> &'static str {
                "example-parser@1"
            }

            fn version(&self) -> u32 {
                1
            }

            fn extensions(&self) -> &'static [&'static str] {
                &[".example"]
            }

            fn parse(&self, _source: &str) -> Result<Vec<ScopeSpan>, String> {
                Ok(vec![ScopeSpan {
                    name: "entry".to_string(),
                    kind: AstScopeKind::Function,
                    start_line: 1,
                    end_line: 1,
                    is_container: false,
                }])
            }
        }

        let mut registry = LanguageRegistry::with_builtin_adapters().unwrap();
        registry.register(Box::new(ExampleAdapter)).unwrap();
        let parsed = registry.parse("src/main.example", "entry").unwrap();
        assert_eq!(parsed.parser_id, "example-parser@1");
        assert_eq!(parsed.scopes[0].name, "entry");
    }
}
