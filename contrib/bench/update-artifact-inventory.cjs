'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..'), archive = path.join(root, 'bench-results');
const file = path.join(archive, 'artifact-inventory.json');
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const old = JSON.parse(fs.readFileSync(file));
if (process.argv.includes('--check')) {
  const committed = old.files.filter(f => f.in_git);
  for (const entry of committed) {
    const data = fs.readFileSync(path.join(archive, entry.path));
    assert.equal(data.length, entry.bytes, entry.path);
    assert.equal(hash(data), entry.sha256, entry.path);
  }
  console.log(`Verified ${committed.length} archived files`);
} else {
  assert(process.argv.length === 2, 'usage: node contrib/bench/update-artifact-inventory.cjs [--check]');
  const tracked = new Set(execFileSync('git', ['ls-files', '-z', 'bench-results'], {cwd: root, encoding: 'utf8'})
    .split('\0').filter(Boolean).map(f => f.slice('bench-results/'.length)));
  const entries = new Map(old.files.map(f => [f.path, {...f, in_git: tracked.has(f.path)}]));
  function walk(dir) {
    for (const d of fs.readdirSync(dir, {withFileTypes: true})) {
      const full = path.join(dir, d.name), relative = path.relative(archive, full);
      if (d.isDirectory()) {
        if (!['.git', 'target', 'node_modules'].includes(d.name)) walk(full);
      } else if (d.isFile() && full !== file) {
        const entry = {path: relative, bytes: fs.statSync(full).size, in_git: tracked.has(relative)};
        if (entry.in_git) entry.sha256 = hash(fs.readFileSync(full));
        entries.set(relative, entry);
      }
    }
  }
  walk(archive);
  entries.delete('artifact-inventory.json');
  fs.writeFileSync(file, JSON.stringify({scope: 'Completed benchmark and analysis archives through 2026-09-28, including failed/superseded cases labeled in their reports.',
    raw_artifacts: old.raw_artifacts, files: [...entries.values()].sort((a, b) => a.path.localeCompare(b.path))}, null, 2) + '\n');
  console.log(`Indexed ${entries.size} archive files (${tracked.size - 1} tracked, excluding this inventory)`);
}
