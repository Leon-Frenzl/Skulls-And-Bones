import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve('c:/Users/leonf/Documents/Projekte/Skulls-And-Bones');
const inventory = JSON.parse(fs.readFileSync(path.join(root, 'product-inventory.json'), 'utf8')).products;

console.log(`Starting individual verification of all ${inventory.length} crates...`);

const results = [];

for (const product of inventory) {
  console.log(`\nVerifying ${product.id} (${product.package_name}): "${product.verification}"`);
  const parts = product.verification.split(';');
  let passed = true;
  let details = '';

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const cmd = tokens[0];
    const args = tokens.slice(1);

    const res = spawnSync(cmd, args, { cwd: root, shell: true });
    if (res.status !== 0) {
      passed = false;
      details = `Command failed: ${trimmed} with code ${res.status}\n${res.stderr.toString()}`;
      break;
    }
  }

  results.push({ id: product.id, package_name: product.package_name, passed, details });
  console.log(`  -> ${passed ? 'PASSED' : 'FAILED'}`);
}

console.log('\n--- SUMMARY ---');
let allPassed = true;
for (const r of results) {
  console.log(`[${r.passed ? 'PASS' : 'FAIL'}] ${r.id} (${r.package_name})`);
  if (!r.passed) {
    allPassed = false;
    console.error(`  ${r.details}`);
  }
}

if (!allPassed) {
  process.exit(1);
} else {
  console.log('\nAll 14 individual verification commands succeeded.');
}
