import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

const root = new URL('../src/', import.meta.url).pathname;
const violations = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await walk(path);
      continue;
    }
    if (!/\.(ts|tsx)$/.test(entry.name) || /\.test\.(ts|tsx)$/.test(entry.name)) {
      continue;
    }
    const source = await readFile(path, 'utf8');
    const lines = source.split('\n');
    lines.forEach((line, index) => {
      if (/^\s*(export\s+)?(const|let)\s+(mock|fake)[A-Za-z0-9_]*/.test(line)) {
        violations.push(`${relative(root, path)}:${index + 1}: explicit mock/fake declaration`);
      }
      if (/console\.(log|warn|error|info|debug)\s*\(/.test(line)) {
        violations.push(`${relative(root, path)}:${index + 1}: direct console call`);
      }
    });
  }
}

await walk(root);
if (violations.length > 0) {
  process.stderr.write(`${violations.join('\n')}\n`);
  process.exit(1);
}
