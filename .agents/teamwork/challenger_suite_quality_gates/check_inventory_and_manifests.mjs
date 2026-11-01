import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve('c:/Users/leonf/Documents/Projekte/Skulls-And-Bones');
const readJson = (filePath) => JSON.parse(fs.readFileSync(path.join(root, filePath), 'utf8'));

const tomlSections = (contents, header) => {
  const lines = contents.split(/\r?\n/);
  return lines.flatMap((line, index) => {
    if (line.trim() !== header) return [];
    let end = index + 1;
    while (end < lines.length && !lines[end].trim().startsWith('[')) end += 1;
    return [lines.slice(index + 1, end).join('\n')];
  });
};
const tomlSection = (contents, header) => tomlSections(contents, header)[0] ?? '';

const inventoryDocument = readJson('product-inventory.json');
const inventory = inventoryDocument.products;
console.log('Product count:', inventory.length);

const toolDirs = fs.readdirSync(path.join(root, 'tools'), { withFileTypes: true })
  .filter(e => e.isDirectory())
  .map(e => `tools/${e.name}`);
console.log('Tool directories count:', toolDirs.length);

if (inventory.length !== 14) {
  throw new Error(`Expected 14 products, found ${inventory.length}`);
}
if (toolDirs.length !== 14) {
  throw new Error(`Expected 14 tool directories, found ${toolDirs.length}`);
}

const workspaceManifest = fs.readFileSync(path.join(root, 'Cargo.toml'), 'utf8');
const workspacePackage = tomlSection(workspaceManifest, '[workspace.package]');
const workspaceVersion = workspacePackage.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
console.log('Workspace package version:', workspaceVersion);

for (const p of inventory) {
  const manifestPath = path.join(p.source_directory, 'Cargo.toml');
  if (!fs.existsSync(path.join(root, manifestPath))) {
    throw new Error(`Missing manifest for ${p.id} at ${manifestPath}`);
  }
  const manifest = fs.readFileSync(path.join(root, manifestPath), 'utf8');
  const pkgSec = tomlSection(manifest, '[package]');
  const name = pkgSec.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
  const directVersion = pkgSec.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  const version = directVersion ?? (pkgSec.match(/^version\.workspace\s*=\s*true/m) ? workspaceVersion : undefined);
  if (name !== p.package_name || version !== p.package_version) {
    throw new Error(`Mismatch in ${p.id}: expected ${p.package_name}@${p.package_version}, got ${name}@${version}`);
  }
  console.log(`[OK] Product ${p.id}: ${name}@${version} (${p.maturity})`);
}

console.log('All 14 crates validated against product-inventory.json and Cargo manifests.');
