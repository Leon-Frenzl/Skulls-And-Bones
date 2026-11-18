// Installs the UI workspaces with `npm ci`, isolated from the user-level .npmrc.
// Newer npm refuses project installs when ~/.npmrc contains `allow-scripts` (EALLOWSCRIPTS).
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const emptyRc = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sb-npmrc-")), ".npmrc");
fs.writeFileSync(emptyRc, "");

const env = { ...process.env, npm_config_userconfig: emptyRc };
for (const key of Object.keys(env)) {
  if (key.toLowerCase().startsWith("npm_config_allow")) {
    delete env[key];
  }
}
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
let status = 0;

for (const dir of ["tools/netgrid", "website"]) {
  const r = spawnSync(npm, ["--prefix", dir, "--userconfig", emptyRc, "ci"], {
    env,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (r.status !== 0) {
    status = r.status || 1;
    break;
  }
}

fs.rmSync(path.dirname(emptyRc), { recursive: true, force: true });
process.exit(status);
