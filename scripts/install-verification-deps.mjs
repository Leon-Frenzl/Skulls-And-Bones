import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error("Run this installer with `npm run install:verify-deps` so the npm CLI path is available.");
  process.exit(1);
}

const inventory = JSON.parse(fs.readFileSync(path.join(root, "product-inventory.json"), "utf8"));
if (!Array.isArray(inventory.products) || inventory.products.length === 0) {
  console.error("product-inventory.json must define at least one product.");
  process.exit(1);
}

const directories = [
  ...inventory.products
    .filter((product) =>
      product.product_kind === "desktop_application"
      && fs.existsSync(path.join(root, product.source_directory, "package.json"))
    )
    .map((product) => product.source_directory),
  "website",
];

for (const directory of directories) {
  const lockPath = path.join(root, directory, "package-lock.json");
  if (!fs.existsSync(lockPath)) {
    console.error(`Missing npm lockfile: ${path.relative(root, lockPath)}.`);
    process.exit(1);
  }
  console.log(`\n==> Installing locked dependencies for ${directory}`);
  const result = spawnSync(process.execPath, [npmCli, "ci", "--prefix", directory], {
    cwd: root,
    stdio: "inherit",
  });
  if (result.error) {
    console.error(`npm ci could not start for ${directory}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`npm ci failed for ${directory} with exit code ${result.status ?? "unknown"}.`);
    process.exit(result.status ?? 1);
  }
}
