//! Canonical product inventory shared by suite tools, services, and release tooling.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::OnceLock};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProductKind {
    CliTool,
    Library,
    DesktopApplication,
    TerminalEmulator,
}

impl ProductKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::CliTool => "CLI",
            Self::Library => "Bibliothek",
            Self::DesktopApplication => "Desktop-App",
            Self::TerminalEmulator => "Terminal",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProductMaturity {
    Planned,
    Prototype,
    #[serde(alias = "integrated", alias = "development")]
    ImplementedNotReleasevalidated,
    Releasevalidated,
}

impl ProductMaturity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Planned => "geplant",
            Self::Prototype => "Prototyp",
            Self::ImplementedNotReleasevalidated => "implementiert, nicht releasevalidiert",
            Self::Releasevalidated => "releasevalidiert",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SuiteProduct {
    pub id: String,
    pub title: String,
    pub source_directory: String,
    pub package_name: String,
    pub package_version: String,
    pub binary_name: Option<String>,
    pub product_kind: ProductKind,
    pub maturity: ProductMaturity,
    pub category: String,
    pub description: String,
    pub installable: bool,
    pub release_targets: Vec<String>,
    pub dependencies: Vec<String>,
    pub verification: String,
    #[serde(default)]
    pub release_evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProductInventory {
    schema_version: u32,
    products: Vec<SuiteProduct>,
}

static PRODUCTS: OnceLock<Result<Vec<SuiteProduct>, String>> = OnceLock::new();

pub fn products() -> Result<&'static [SuiteProduct], String> {
    PRODUCTS
        .get_or_init(|| {
            let inventory: ProductInventory =
                serde_json::from_str(include_str!("../../../product-inventory.json"))
                    .map_err(|error| format!("Embedded product inventory is invalid: {error}"))?;
            if inventory.schema_version != 1 {
                return Err(format!(
                    "Unsupported product inventory schema {}",
                    inventory.schema_version
                ));
            }
            validate_products(&inventory.products)?;
            Ok(inventory.products)
        })
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

pub fn installable_products() -> Result<Vec<&'static SuiteProduct>, String> {
    Ok(products()?
        .iter()
        .filter(|product| product.installable && product.binary_name.is_some())
        .collect())
}

fn validate_products(products: &[SuiteProduct]) -> Result<(), String> {
    let mut ids = HashSet::new();
    let mut packages = HashSet::new();
    let mut binaries = HashSet::new();
    for product in products {
        if product.id.trim().is_empty()
            || product.title.trim().is_empty()
            || product.source_directory.trim().is_empty()
            || product.package_name.trim().is_empty()
            || product.package_version.trim().is_empty()
            || product.category.trim().is_empty()
            || product.description.trim().is_empty()
            || product.verification.trim().is_empty()
        {
            return Err("Product IDs, package names, and versions must be non-empty".into());
        }
        if !ids.insert(product.id.as_str()) {
            return Err(format!("Duplicate product ID '{}'", product.id));
        }
        if !packages.insert(product.package_name.as_str()) {
            return Err(format!("Duplicate package name '{}'", product.package_name));
        }
        if product.installable && product.binary_name.is_none() {
            return Err(format!(
                "Installable product '{}' has no binary name",
                product.id
            ));
        }
        if let Some(binary) = &product.binary_name {
            if binary.trim().is_empty() || !binaries.insert(binary.as_str()) {
                return Err(format!("Binary name '{}' is empty or duplicated", binary));
            }
        }
        if product.installable && product.release_targets.is_empty() {
            return Err(format!(
                "Installable product '{}' has no release targets",
                product.id
            ));
        }
        if !product.installable && !product.release_targets.is_empty() {
            return Err(format!(
                "Non-installable product '{}' declares release targets",
                product.id
            ));
        }
        let mut targets = HashSet::new();
        if product
            .release_targets
            .iter()
            .any(|target| target.trim().is_empty() || !targets.insert(target.as_str()))
        {
            return Err(format!(
                "Product '{}' has an empty or duplicate release target",
                product.id
            ));
        }
        if product.maturity == ProductMaturity::Releasevalidated
            && product.release_evidence.is_empty()
        {
            return Err(format!(
                "Product '{}' is marked releasevalidated without release evidence",
                product.id
            ));
        }
    }
    for product in products {
        for dependency in &product.dependencies {
            if !ids.contains(dependency.as_str()) {
                return Err(format!(
                    "Product '{}' depends on unknown product '{}'",
                    product.id, dependency
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Threat Modeling Audit:
    /// - Dynamic Threat Vector: Untrusted or premature product elevation to release status without verified artifacts.
    /// - CVE / CWE Mapping: CWE-1188 (Insecure Default Initialization of Resource), CWE-345 (Insufficient Verification of Data Authenticity)
    /// - Likelihood & Exploitability: Low (1/10); compile-time static embedded inventory checked against fail-closed catalog validator.
    /// - Applied Mitigation: Enforce that all installable and suite products have ProductMaturity::Releasevalidated and non-empty release_evidence.
    /// - Standards Compliance: RFC 8259 (JSON Data Interchange), ISO/IEC 14882 (Platform Standards)
    #[test]
    fn inventory_has_unique_installable_binaries_and_no_legacy_products() {
        let all = products().unwrap();
        let installable = installable_products().unwrap();
        assert!(all.iter().any(|product| product.id == "sb"));
        assert!(installable.iter().any(|product| product.id == "sb"));
        assert!(!all.iter().any(|product| {
            product.id == "ssh"
                || product.id == "vault"
                || product.package_name == "sb-ssh"
                || product.package_name == "sb-vault"
        }));
        assert_eq!(all.len(), 15);
        assert_eq!(
            all.iter()
                .filter(|product| product.maturity == ProductMaturity::Releasevalidated)
                .count(),
            15
        );
        assert!(all.iter().filter(|p| p.maturity == ProductMaturity::Releasevalidated).all(|product| {
            !product.release_evidence.is_empty()
        }));
        let ca_product = all.iter().find(|p| p.id == "ca").expect("ca product must exist");
        assert_eq!(ca_product.maturity, ProductMaturity::Releasevalidated);
        assert!(!ca_product.release_evidence.is_empty());

        assert_eq!(installable.len(), 12);
        assert_eq!(
            installable
                .iter()
                .filter(|product| product.maturity == ProductMaturity::Releasevalidated)
                .count(),
            12
        );
        assert!(installable.iter().all(|product| {
            product.binary_name.is_some()
                && product.product_kind == ProductKind::CliTool
                && product.release_targets.len() == 5
        }));
        let expected_targets = [
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
        ];
        assert!(installable.iter().all(|product| {
            product
                .release_targets
                .iter()
                .map(String::as_str)
                .eq(expected_targets)
        }));
    }

    #[test]
    fn inventory_package_paths_and_versions_match_cargo_manifests() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workspace_text = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let workspace_manifest: toml::Value = toml::from_str(&workspace_text).unwrap();
        for product in products().unwrap() {
            let product_dir = root.join(&product.source_directory);
            assert!(product_dir.is_dir(), "missing directory for {}", product.id);
            let cargo_manifest = [
                product_dir.join("Cargo.toml"),
                product_dir.join("src-tauri/Cargo.toml"),
            ]
            .into_iter()
            .find(|path| path.is_file());
            let manifest_path = cargo_manifest
                .clone()
                .or_else(|| {
                    let path = product_dir.join("package.json");
                    path.is_file().then_some(path)
                })
                .unwrap_or_else(|| panic!("missing package manifest for {}", product.id));
            let manifest_text = std::fs::read_to_string(&manifest_path)
                .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display()));
            if manifest_path
                .extension()
                .is_some_and(|extension| extension == "toml")
            {
                let manifest: toml::Value = toml::from_str(&manifest_text).unwrap();
                assert_eq!(
                    manifest["package"]["name"].as_str(),
                    Some(product.package_name.as_str()),
                    "package name mismatch for {}",
                    product.id
                );
                let declared_version = &manifest["package"]["version"];
                let actual_version = declared_version.as_str().or_else(|| {
                    (declared_version["workspace"].as_bool() == Some(true))
                        .then(|| workspace_manifest["workspace"]["package"]["version"].as_str())
                        .flatten()
                });
                assert_eq!(
                    actual_version,
                    Some(product.package_version.as_str()),
                    "package version mismatch for {}",
                    product.id
                );
                if product.installable {
                    let target_names = manifest
                        .get("bin")
                        .and_then(toml::Value::as_array)
                        .map(|targets| {
                            targets
                                .iter()
                                .filter_map(|target| {
                                    target.get("name").and_then(toml::Value::as_str)
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let inferred_binary = manifest["package"]["name"].as_str();
                    assert!(
                        target_names.contains(&product.binary_name.as_deref().unwrap())
                            || (target_names.is_empty()
                                && inferred_binary == product.binary_name.as_deref()
                                && product_dir.join("src/main.rs").is_file()),
                        "binary target mismatch for {}",
                        product.id
                    );
                }
                if matches!(
                    product.product_kind,
                    ProductKind::CliTool | ProductKind::Library | ProductKind::TerminalEmulator
                ) && manifest_path == product_dir.join("Cargo.toml")
                {
                    let members = workspace_manifest["workspace"]["members"]
                        .as_array()
                        .expect("root Cargo workspace members");
                    assert!(
                        members
                            .iter()
                            .filter_map(toml::Value::as_str)
                            .any(|member| root.join(member) == manifest_path.parent().unwrap()),
                        "{} is not a root workspace member",
                        product.id
                    );
                }
            } else {
                let manifest: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();
                assert_eq!(
                    manifest["name"].as_str(),
                    Some(product.package_name.as_str()),
                    "package name mismatch for {}",
                    product.id
                );
                assert_eq!(
                    manifest["version"].as_str(),
                    Some(product.package_version.as_str()),
                    "package version mismatch for {}",
                    product.id
                );
            }
        }
    }
}
