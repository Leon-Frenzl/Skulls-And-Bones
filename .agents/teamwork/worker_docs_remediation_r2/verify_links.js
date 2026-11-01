const fs = require('fs');
const path = require('path');

const targetFiles = [
  'brain/vision.md',
  'tools/sb-mesh/TODO.md',
  'docs/SKEL_FRAMEWORK.md',
  'tools/README.md',
  'tools/sb-code/BEST_PRACTICES.md'
];

let errors = 0;

for (const tf of targetFiles) {
  const content = fs.readFileSync(tf, 'utf8');
  console.log(`=== Checking: ${tf} ===`);
  
  // 1. file:/// check
  if (content.includes('file:///')) {
    console.error(`ERROR: file:/// found in ${tf}`);
    errors++;
  }
  
  // 2. zero-trust check
  const zt = content.match(/zero[- ]?trust/gi);
  if (zt) {
    console.log(`NOTE: zero-trust found in ${tf}: ${JSON.stringify(zt)}`);
  }
  
  // 3. Link resolution check
  const dir = path.dirname(tf);
  const regex = /\[.*?\]\((.*?)\)/g;
  let m;
  while ((m = regex.exec(content)) !== null) {
    const target = m[1].split('#')[0]; // strip anchor
    if (!target || target.startsWith('http') || target.startsWith('mailto:')) continue;
    const resolved = path.resolve(dir, target);
    const exists = fs.existsSync(resolved);
    if (!exists) {
      console.error(`BROKEN LINK in ${tf}: (${m[1]}) -> ${resolved}`);
      errors++;
    } else {
      console.log(`  OK link: ${m[1]}`);
    }
  }
}

console.log(`Finished verification. Errors: ${errors}`);
if (errors > 0) process.exit(1);
