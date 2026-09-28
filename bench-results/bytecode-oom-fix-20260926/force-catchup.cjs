'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const output = path.join(__dirname, 'sync-injection.json');
const binary = path.join(__dirname, 'tempo');
const group = '/sys/fs/cgroup/system.slice/tempo-e2e-b-feature-1.scope';
const pid = fs.readFileSync(`${group}/cgroup.procs`, 'utf8').trim().split(/\s+/).find(pid =>
  fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0')[0] === binary);
assert.ok(pid, 'no owned follower');
assert.ok(!fs.existsSync(output), 'refusing a second injection');
const record = {pid, binary, pause_seconds: 120, started_at: new Date().toISOString(),
  reason: 'Force the observed pipeline-sync failure path during warmup. Natural follower execution had not entered pipeline sync.'};
const save = () => fs.writeFileSync(output, JSON.stringify(record, null, 2) + '\n');
let resumed = false;
function resume() {
  if (resumed) return;
  assert.equal(fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0')[0], binary);
  execFileSync('sudo', ['-n', 'kill', '-CONT', pid]);
  resumed = true;
  record.resumed_at = new Date().toISOString();
  save();
}
process.on('SIGTERM', () => {resume(); process.exit(1);});
process.on('SIGINT', () => {resume(); process.exit(1);});
process.on('exit', resume);
save();
execFileSync('sudo', ['-n', 'kill', '-STOP', pid]);
setTimeout(resume, 120000);
