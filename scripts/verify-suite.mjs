import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error("Run this verifier with `npm run verify:suite` so the npm CLI path is available.");
  process.exit(1);
}

const run = (label, command, args, options = {}) => {
  console.log(`\n==> ${label}`);
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: "inherit",
    shell: options.shell ?? false,
    env: options.env ?? process.env,
  });

  if (result.error) {
    console.error(`${label} could not start: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`${label} failed with exit code ${result.status ?? "unknown"}.`);
    process.exit(result.status ?? 1);
  }
};

const readJson = (filePath) => JSON.parse(fs.readFileSync(path.join(root, filePath), "utf8"));
const tomlSections = (contents, header) => {
  const lines = contents.split(/\r?\n/);
  return lines.flatMap((line, index) => {
    if (line.trim() !== header) return [];
    let end = index + 1;
    while (end < lines.length && !lines[end].trim().startsWith("[")) end += 1;
    return [lines.slice(index + 1, end).join("\n")];
  });
};
const tomlSection = (contents, header) => tomlSections(contents, header)[0] ?? "";

const inventoryDocument = readJson("product-inventory.json");
const inventory = inventoryDocument.products;
if (!Array.isArray(inventory) || inventory.length === 0) {
  console.error("product-inventory.json must define at least one product.");
  process.exit(1);
}

const uniqueValues = (values, description) => {
  if (new Set(values).size !== values.length) {
    console.error(`Duplicate ${description} found in product-inventory.json.`);
    process.exit(1);
  }
};

uniqueValues(inventory.map((product) => product.id), "product ID");
uniqueValues(inventory.map((product) => product.source_directory), "source directory");

const productDirectories = inventory.map((product) => product.source_directory);
const supportDirectories = inventoryDocument.support_directories;
if (!Array.isArray(supportDirectories) || supportDirectories.some((directory) => typeof directory !== "string")) {
  console.error("product-inventory.json must classify every non-product tools directory in support_directories.");
  process.exit(1);
}
uniqueValues([...productDirectories, ...supportDirectories], "product or support directory");
const actualToolDirectories = fs.readdirSync(path.join(root, "tools"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => `tools/${entry.name}`);
const classifiedToolDirectories = new Set([...productDirectories, ...supportDirectories]);
const unclassifiedToolDirectories = actualToolDirectories.filter((directory) => !classifiedToolDirectories.has(directory));
const missingToolDirectories = [...classifiedToolDirectories].filter((directory) => !actualToolDirectories.includes(directory));
if (unclassifiedToolDirectories.length > 0 || missingToolDirectories.length > 0) {
  console.error([
    "Tool-directory inventory is incomplete.",
    unclassifiedToolDirectories.length > 0 ? `Unclassified: ${unclassifiedToolDirectories.join(", ")}` : "",
    missingToolDirectories.length > 0 ? `Missing: ${missingToolDirectories.join(", ")}` : "",
  ].filter(Boolean).join("\n"));
  process.exit(1);
}

const separateSurfaces = inventoryDocument.separate_surfaces;
if (
  !Array.isArray(separateSurfaces) ||
  separateSurfaces.some((surface) =>
    !surface ||
    typeof surface.id !== "string" ||
    typeof surface.source_directory !== "string" ||
    typeof surface.delivery_model !== "string" ||
    typeof surface.reason !== "string" ||
    surface.reason.trim() === ""
  )
) {
  console.error("product-inventory.json must explicitly classify non-tool delivery surfaces.");
  process.exit(1);
}
uniqueValues(separateSurfaces.map((surface) => surface.id), "separate surface ID");
uniqueValues(separateSurfaces.map((surface) => surface.source_directory), "separate surface directory");
for (const surface of separateSurfaces) {
  if (!fs.existsSync(path.join(root, surface.source_directory))) {
    console.error(`${surface.id}: missing separate delivery surface ${surface.source_directory}.`);
    process.exit(1);
  }
  if (productDirectories.includes(surface.source_directory) || supportDirectories.includes(surface.source_directory)) {
    console.error(`${surface.id}: separate delivery surface overlaps an inventoried tools directory.`);
    process.exit(1);
  }
}

const appCatalog = inventoryDocument.desktop_app_catalog;
if (
  !appCatalog ||
  !Array.isArray(appCatalog.optional_native_clients) ||
  !Array.isArray(appCatalog.excluded_products) ||
  appCatalog.optional_native_clients.some((id) => typeof id !== "string") ||
  appCatalog.excluded_products.some((product) =>
    !product || typeof product.id !== "string" || typeof product.reason !== "string" || product.reason.trim() === ""
  )
) {
  console.error("product-inventory.json must explicitly classify Mesh app-catalog clients and exclusions.");
  process.exit(1);
}
const appCatalogIds = [
  ...appCatalog.optional_native_clients,
  ...appCatalog.excluded_products.map((product) => product.id),
];
uniqueValues(appCatalogIds, "desktop app-catalog product");
const desktopProductIds = inventory
  .filter((product) => product.product_kind === "desktop_application")
  .map((product) => product.id);
if (
  desktopProductIds.length !== appCatalogIds.length ||
  desktopProductIds.some((id) => !appCatalogIds.includes(id))
) {
  console.error("Every desktop application must be listed as an optional native Mesh client or explicitly excluded.");
  process.exit(1);
}
for (const id of appCatalog.optional_native_clients) {
  const product = inventory.find((candidate) => candidate.id === id);
  if (!product || product.product_kind !== "desktop_application") {
    console.error(`Mesh app-catalog client ${id} is not a known desktop application.`);
    process.exit(1);
  }
}
for (const excluded of appCatalog.excluded_products) {
  const product = inventory.find((candidate) => candidate.id === excluded.id);
  if (
    !product ||
    product.product_kind !== "desktop_application" ||
    excluded.reason.trim() === ""
  ) {
    console.error(`Desktop app-catalog exclusion ${excluded.id} must name a known desktop application and explain why.`);
    process.exit(1);
  }
}

const workspaceManifest = fs.readFileSync(path.join(root, "Cargo.toml"), "utf8");
const workspacePackage = tomlSection(workspaceManifest, "[workspace.package]");
const workspaceVersion = workspacePackage.match(/^version\s*=\s*"([^"]+)"/m)?.[1];

const checkCargoManifest = (product, manifestPath) => {
  const absolutePath = path.join(root, manifestPath);
  if (!fs.existsSync(absolutePath)) {
    console.error(`${product.id}: missing Cargo manifest ${manifestPath}.`);
    process.exit(1);
  }
  const manifest = fs.readFileSync(absolutePath, "utf8");
  const packageSection = tomlSection(manifest, "[package]");
  const name = packageSection.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
  const directVersion = packageSection.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  const version = directVersion ?? (packageSection.match(/^version\.workspace\s*=\s*true/m) ? workspaceVersion : undefined);

  if (name !== product.package_name || version !== product.package_version) {
    console.error(
      `${product.id}: inventory expects ${product.package_name}@${product.package_version}, ` +
      `but ${manifestPath} declares ${name ?? "no package name"}@${version ?? "no version"}.`,
    );
    process.exit(1);
  }
};

const desktopProducts = inventory.filter((product) => product.product_kind === "desktop_application");
for (const product of inventory) {
  const sourcePath = path.join(root, product.source_directory);
  if (!fs.existsSync(sourcePath)) {
    console.error(`${product.id}: missing source directory ${product.source_directory}.`);
    process.exit(1);
  }
  if (typeof product.verification !== "string" || product.verification.trim() === "") {
    console.error(`${product.id}: missing verification command in product-inventory.json.`);
    process.exit(1);
  }
  if (!Array.isArray(product.release_targets) || !Array.isArray(product.dependencies)) {
    console.error(`${product.id}: release_targets and dependencies must be arrays.`);
    process.exit(1);
  }

  const directCargoManifest = path.join(product.source_directory, "Cargo.toml");
  const tauriCargoManifest = path.join(product.source_directory, "src-tauri", "Cargo.toml");
  const isNativeDesktop = product.product_kind === "desktop_application"
    && fs.existsSync(path.join(root, directCargoManifest));
  const manifestPath = product.product_kind === "desktop_application" && !isNativeDesktop
    ? tauriCargoManifest
    : directCargoManifest;
  if (product.id === "ui") {
    const pkg = readJson(path.join(product.source_directory, "package.json"));
    if (pkg.name !== product.package_name || pkg.version !== product.package_version) {
      console.error(`${product.id}: package.json identity or version does not match product-inventory.json.`);
      process.exit(1);
    }
  } else {
    checkCargoManifest(product, manifestPath);
    if (product.binary_name !== null) {
      const manifest = fs.readFileSync(path.join(root, manifestPath), "utf8");
      const binaryNames = tomlSections(manifest, "[[bin]]")
        .map((section) => section.match(/^name\s*=\s*"([^"]+)"/m)?.[1])
        .filter(Boolean);
      const sourceHasDefaultBinary = product.binary_name === product.package_name
        && fs.existsSync(path.join(sourcePath, "src", "main.rs"));
      const sourceHasNamedBinary = fs.existsSync(path.join(sourcePath, "src", "bin", `${product.binary_name}.rs`))
        || fs.existsSync(path.join(sourcePath, "src", "bin", product.binary_name, "main.rs"));
      if (!binaryNames.includes(product.binary_name) && !sourceHasDefaultBinary && !sourceHasNamedBinary) {
        console.error(`${product.id}: binary ${product.binary_name} is missing from ${manifestPath}.`);
        process.exit(1);
      }
    }
  }

  if (product.product_kind === "desktop_application") {
    const packagePath = path.join(product.source_directory, "package.json");
    if (appCatalog.optional_native_clients.includes(product.id)) {
      if (!isNativeDesktop || fs.existsSync(path.join(root, tauriCargoManifest)) || fs.existsSync(path.join(root, packagePath))) {
        console.error(`${product.id}: optional Mesh desktop client must be a pure native Rust crate without Tauri or package.json.`);
        process.exit(1);
      }
    } else {
      if (!fs.existsSync(path.join(root, packagePath))) {
        console.error(`${product.id}: missing frontend package.json ${packagePath}.`);
        process.exit(1);
      }
      const pkg = readJson(packagePath);
      if (pkg.version !== product.package_version) {
        console.error(`${product.id}: frontend package.json version does not match product-inventory.json.`);
        process.exit(1);
      }
    }
  }
}

console.log(
  `Validated ${inventory.length} products, ${actualToolDirectories.length} tool directories, ` +
  `and ${appCatalog.optional_native_clients.length} optional Mesh app clients ` +
  `(${appCatalog.excluded_products.length} explicit exclusion), plus ${separateSurfaces.length} separate delivery surface(s).`,
);

const cargo = (label, args) => run(label, "cargo", args);
const npmRun = (label, prefix, args) => run(label, process.execPath, [npmCli, "--prefix", prefix, ...args], {
  env: { ...process.env, NPM_CONFIG_ALLOW_SCRIPTS: "" },
});

cargo("Rust formatting", ["fmt", "--all", "--", "--check"]);
cargo("Root Rust workspace check", ["check", "--workspace"]);
cargo("Root Rust workspace tests", ["test", "--workspace"]);

const tauriDesktopProducts = [];
for (const product of desktopProducts) {
  const app = product.source_directory;
  const directManifest = `${app}/Cargo.toml`;
  if (fs.existsSync(path.join(root, directManifest))) {
    cargo(`${app} native Rust formatting`, ["fmt", "--manifest-path", directManifest, "--", "--check"]);
    cargo(`${app} native Rust check`, ["check", "--manifest-path", directManifest]);
    cargo(`${app} native Rust tests`, ["test", "--manifest-path", directManifest]);
  } else {
    const manifestPath = `${app}/src-tauri/Cargo.toml`;
    cargo(`${app} Tauri check`, ["check", "--manifest-path", manifestPath]);
    cargo(`${app} Tauri tests`, ["test", "--manifest-path", manifestPath]);
    tauriDesktopProducts.push(product);
  }
}

for (const product of tauriDesktopProducts) {
  npmRun(`${product.source_directory} frontend build`, product.source_directory, ["run", "build"]);
}
npmRun("Website build", "website", ["run", "build"]);
// NetGrid lint removed with desktop apps
// SKEL E2E tests removed with skel

const auditTargets = [
  ...tauriDesktopProducts.map((product) => [product.title, product.source_directory]),
  
  ["Website", "website"],
];
uniqueValues(auditTargets.map(([, directory]) => directory), "npm audit target");
for (const [label, directory] of auditTargets) {
  npmRun(`${label} dependency audit`, directory, ["audit", "--audit-level=high"]);
}

console.log("\nSuite verification passed.");
