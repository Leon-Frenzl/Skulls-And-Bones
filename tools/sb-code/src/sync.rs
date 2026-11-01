use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const STRICT_EXCLUSIONS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    ".env",
    ".sb",
    "dist",
    "build",
    "bin",
    "obj",
    "__pycache__",
    ".idea",
    ".vscode",
    "identity.sbkey",
    "lease.json",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub rel_path: String,
    pub blake3_hash: String,
    pub size_bytes: u64,
    pub is_dir: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FileTreeSnapshot {
    pub entries: HashMap<String, FileEntry>,
    pub root_blake3: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeDelta {
    pub added: Vec<FileEntry>,
    pub modified: Vec<FileEntry>,
    pub deleted: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct IgnoreRule {
    pub pattern: String,
    pub is_negation: bool,
    pub dir_only: bool,
    pub has_slash: bool,
}

#[derive(Clone, Debug)]
pub struct IgnoreRuleSet {
    pub rules: Vec<IgnoreRule>,
    pub source: IgnoreSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IgnoreSource {
    SbIgnore,
    DefaultKernelOnly,
}

impl IgnoreRuleSet {
    pub fn load(root: &Path) -> std::io::Result<Self> {
        let path = root.join(".sbignore");
        match fs::read_to_string(&path) {
            Ok(content) => Ok(Self::from_str(&content, IgnoreSource::SbIgnore)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                rules: Vec::new(),
                source: IgnoreSource::DefaultKernelOnly,
            }),
            Err(error) => Err(error),
        }
    }

    pub fn from_str(content: &str, source: IgnoreSource) -> Self {
        let mut rules = Vec::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (is_negation, mut pattern_str) = if line.starts_with('!') {
                (true, &line[1..])
            } else {
                (false, line)
            };

            pattern_str = pattern_str.trim();
            if pattern_str.is_empty() {
                continue;
            }

            let dir_only = pattern_str.ends_with('/');
            let clean_pattern = pattern_str.trim_end_matches('/').trim_start_matches('/');
            let has_slash = clean_pattern.contains('/');

            rules.push(IgnoreRule {
                pattern: clean_pattern.to_lowercase(),
                is_negation,
                dir_only,
                has_slash,
            });
        }

        Self { rules, source }
    }

    pub fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let normalized = rel_path.replace('\\', "/").to_lowercase();
        let file_name = normalized.split('/').last().unwrap_or(&normalized);

        // 1. Kernel Level Security Filter (Always active and non-negotiable)
        if is_kernel_excluded(file_name) || normalized.split('/').any(is_kernel_excluded) {
            return true;
        }

        // 2. Evaluate user/project rules from .sbignore.
        self.matches_rules(rel_path, is_dir)
    }

    /// Evaluates only the project rules (gitignore-style, last match wins), without kernel exclusions.
    pub fn matches_rules(&self, rel_path: &str, is_dir: bool) -> bool {
        let normalized = rel_path.replace('\\', "/").to_lowercase();
        let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);

        let mut ignored = false;
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                // Directory rules also apply to every file below that directory.
                let mut segments: Vec<&str> = normalized.split('/').collect();
                segments.pop();
                let dir_match = if rule.has_slash {
                    (1..=segments.len())
                        .any(|n| match_glob(&rule.pattern, &segments[..n].join("/")))
                } else {
                    segments.iter().any(|seg| match_glob(&rule.pattern, seg))
                };
                if dir_match {
                    ignored = !rule.is_negation;
                }
                continue;
            }

            let matches = if rule.has_slash {
                match_glob(&rule.pattern, &normalized)
            } else {
                match_glob(&rule.pattern, file_name)
                    || normalized
                        .split('/')
                        .any(|seg| match_glob(&rule.pattern, seg))
            };

            if matches {
                ignored = !rule.is_negation;
            }
        }

        ignored
    }
}

/// Analysis filter loaded from `.sbignore`.
///
/// `.sbignore` controls both files excluded from tracking/sync and files hidden from analytics.
#[derive(Clone, Debug)]
pub struct AnalysisFilter {
    rules: IgnoreRuleSet,
}

impl Default for AnalysisFilter {
    fn default() -> Self {
        Self {
            rules: IgnoreRuleSet {
                rules: Vec::new(),
                source: IgnoreSource::DefaultKernelOnly,
            },
        }
    }
}

impl AnalysisFilter {
    pub const FILE_NAME: &'static str = ".sbignore";

    /// Loads `.sbignore` from the workspace root; a missing file yields an empty filter.
    pub fn load(root: &Path) -> std::io::Result<Self> {
        match fs::read_to_string(root.join(Self::FILE_NAME)) {
            Ok(content) => Ok(Self::from_str(&content)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }

    pub fn from_str(content: &str) -> Self {
        Self {
            rules: IgnoreRuleSet::from_str(content, IgnoreSource::SbIgnore),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.rules.len()
    }

    /// Returns true if the given repository-relative file path is hidden from analytics.
    pub fn is_filtered(&self, rel_path: &str) -> bool {
        !self.rules.rules.is_empty() && self.rules.matches_rules(rel_path, false)
    }
}

pub fn match_glob(pattern: &str, text: &str) -> bool {
    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_p = None;
    let mut star_t = 0;

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_p = Some(p_idx);
            p_idx += 1;
            star_t = t_idx;
        } else if let Some(sp) = star_p {
            p_idx = sp + 1;
            star_t += 1;
            t_idx = star_t;
        } else {
            return false;
        }
    }
    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }
    p_idx == p_bytes.len()
}

impl FileTreeSnapshot {
    pub fn scan(root: &Path) -> std::io::Result<Self> {
        let ignore_rules = IgnoreRuleSet::load(root)?;
        Self::scan_with_rules(root, &ignore_rules)
    }

    pub fn scan_with_rules(root: &Path, ignore_rules: &IgnoreRuleSet) -> std::io::Result<Self> {
        let mut entries = HashMap::new();
        let mut all_hashes = Vec::new();

        if root.exists() && root.is_dir() {
            Self::scan_dir_recursive(root, root, ignore_rules, &mut entries, &mut all_hashes)?;
        }

        all_hashes.sort();
        let mut hasher = blake3::Hasher::new();
        for h in &all_hashes {
            hasher.update(h.as_bytes());
        }
        let root_blake3 = hasher.finalize().to_hex().to_string();

        Ok(Self {
            entries,
            root_blake3,
        })
    }

    // CVE-Threat: A workspace symlink could make commits disclose files outside the workspace.
    // Analysis: This traversal supplies both local commits and bundles sent to other peers.
    // Hardening: Ignore rules run first; remaining symlinks are rejected without following them.
    fn scan_dir_recursive(
        base: &Path,
        current: &Path,
        ignore_rules: &IgnoreRuleSet,
        entries: &mut HashMap<String, FileEntry>,
        all_hashes: &mut Vec<String>,
    ) -> std::io::Result<()> {
        let read_dir = fs::read_dir(current)?;

        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let is_dir = file_type.is_dir();

            let rel_path = path
                .strip_prefix(base)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
                .to_string_lossy()
                .replace('\\', "/");

            if ignore_rules.is_ignored(&rel_path, is_dir) {
                continue;
            }

            if file_type.is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Workspace symlinks are not supported: {}", rel_path),
                ));
            }
            let metadata = fs::symlink_metadata(&path)?;
            if is_dir {
                entries.insert(
                    rel_path.clone(),
                    FileEntry {
                        rel_path: rel_path.clone(),
                        blake3_hash: "directory".to_string(),
                        size_bytes: 0,
                        is_dir: true,
                    },
                );
                Self::scan_dir_recursive(base, &path, ignore_rules, entries, all_hashes)?;
            } else if metadata.is_file() {
                let content = fs::read(&path)?;
                let hash = blake3::hash(&content).to_hex().to_string();
                all_hashes.push(format!("{}:{}", rel_path, hash));

                entries.insert(
                    rel_path.clone(),
                    FileEntry {
                        rel_path,
                        blake3_hash: hash,
                        size_bytes: metadata.len(),
                        is_dir: false,
                    },
                );
            }
        }

        Ok(())
    }

    pub fn diff(&self, target: &FileTreeSnapshot) -> TreeDelta {
        let mut delta = TreeDelta::default();

        for (path, target_entry) in &target.entries {
            match self.entries.get(path) {
                None => delta.added.push(target_entry.clone()),
                Some(local_entry) => {
                    if local_entry.blake3_hash != target_entry.blake3_hash {
                        delta.modified.push(target_entry.clone());
                    }
                }
            }
        }

        for path in self.entries.keys() {
            if !target.entries.contains_key(path) {
                delta.deleted.push(path.clone());
            }
        }

        delta
    }
}

pub fn is_kernel_excluded(name: &str) -> bool {
    let lower = name.to_lowercase();
    for excluded in STRICT_EXCLUSIONS {
        if lower == *excluded || lower.starts_with(&format!("{}.", excluded)) {
            return true;
        }
    }
    if lower.ends_with(".sbkey") || lower.starts_with(".env") || lower.ends_with(".tmp") {
        return true;
    }
    false
}

pub fn is_excluded(name: &str) -> bool {
    is_kernel_excluded(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_strict_kernel_exclusions() {
        assert!(is_kernel_excluded("target"));
        assert!(is_kernel_excluded(".git"));
        assert!(is_kernel_excluded("node_modules"));
        assert!(is_kernel_excluded(".env"));
        assert!(is_kernel_excluded(".env.local"));
        assert!(is_kernel_excluded("identity.sbkey"));
        assert!(is_kernel_excluded("lease.json"));

        assert!(!is_kernel_excluded("src"));
        assert!(!is_kernel_excluded("Cargo.toml"));
        assert!(!is_kernel_excluded("main.rs"));
    }

    #[test]
    fn test_sbignore_matching() {
        let rules_content = r#"
# Comments should be ignored
*.log
temp/
docs/*.draft
!docs/important.draft
        "#;
        let set = IgnoreRuleSet::from_str(rules_content, IgnoreSource::SbIgnore);

        assert!(set.is_ignored("server.log", false));
        assert!(set.is_ignored("sub/dir/app.log", false));
        assert!(set.is_ignored("temp", true));
        assert!(set.is_ignored("docs/test.draft", false));
        assert!(!set.is_ignored("docs/important.draft", false));
        assert!(!set.is_ignored("src/main.rs", false));

        // Kernel protection always active regardless of rules
        assert!(set.is_ignored(".env", false));
        assert!(set.is_ignored("secret.sbkey", false));
    }

    #[test]
    fn unreadable_sbignore_is_an_error() {
        let temp_dir =
            std::env::temp_dir().join(format!("sb_code_ignore_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(temp_dir.join(".sbignore")).unwrap();
        assert!(IgnoreRuleSet::load(&temp_dir).is_err());
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn sbignore_rules_apply_to_tracking_and_analytics() {
        let temp_dir =
            std::env::temp_dir().join(format!("sb_code_ignore_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join(".sbignore"), "*.tmp\n").unwrap();

        let tracking_filter = IgnoreRuleSet::load(&temp_dir).unwrap();
        let analysis_filter = AnalysisFilter::load(&temp_dir).unwrap();
        assert!(tracking_filter.is_ignored("debug.tmp", false));
        assert!(analysis_filter.is_filtered("debug.tmp"));

        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_file_tree_scan_and_diff() {
        let temp_dir = std::env::temp_dir().join(format!("sb_code_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(temp_dir.join("src")).unwrap();
        fs::create_dir_all(temp_dir.join("target")).unwrap();
        fs::create_dir_all(temp_dir.join("logs")).unwrap();

        // Create .sbignore
        let mut f_ignore = File::create(temp_dir.join(".sbignore")).unwrap();
        writeln!(f_ignore, "logs/\n*.bak").unwrap();

        let mut f1 = File::create(temp_dir.join("src/lib.rs")).unwrap();
        writeln!(f1, "pub fn hello() -> &'static str {{ \"world\" }}").unwrap();

        let mut f_target = File::create(temp_dir.join("target/debug.bin")).unwrap();
        writeln!(f_target, "binary junk").unwrap();

        let mut f_log = File::create(temp_dir.join("logs/debug.log")).unwrap();
        writeln!(f_log, "log info").unwrap();

        let mut f_bak = File::create(temp_dir.join("src/lib.rs.bak")).unwrap();
        writeln!(f_bak, "backup").unwrap();

        let snapshot1 = FileTreeSnapshot::scan(&temp_dir).unwrap();
        assert!(
            !snapshot1.entries.contains_key("target/debug.bin"),
            "target should be excluded by kernel"
        );
        assert!(
            !snapshot1.entries.contains_key("logs/debug.log"),
            "logs should be excluded by .sbignore"
        );
        assert!(
            !snapshot1.entries.contains_key("src/lib.rs.bak"),
            "*.bak should be excluded by .sbignore"
        );
        assert!(
            snapshot1.entries.contains_key("src/lib.rs"),
            "src/lib.rs must be included"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(windows)]
    #[test]
    fn file_tree_scan_rejects_workspace_symlinks() {
        use std::os::windows::fs::symlink_dir;

        let root =
            std::env::temp_dir().join(format!("sb_code_symlink_root_{}", uuid::Uuid::new_v4()));
        let outside =
            std::env::temp_dir().join(format!("sb_code_symlink_outside_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        if symlink_dir(&outside, root.join("external")).is_err() {
            let _ = fs::remove_dir_all(&root);
            let _ = fs::remove_dir_all(&outside);
            return;
        }

        assert!(FileTreeSnapshot::scan(&root).is_err());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }
}
