'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {spawn, spawnSync} = require('node:child_process');

function cleanup(plan) {
  for (const name of fs.readdirSync('bench-results').filter(name => /^20\d{6}-/.test(name))) {
    const dir = path.join('bench-results', name);
    let config;
    try { config = JSON.parse(fs.readFileSync(path.join(dir, 'summary-config.json'))); } catch { continue; }
    if (!config.benchmark_id?.startsWith(plan.benchmark_id + '-')) continue;
    for (const file of fs.readdirSync(dir).filter(file => /^state-path-observer-.*\.jsonl$/.test(file)))
      fs.writeFileSync(path.join(dir, file.replace(/\.jsonl$/, '.stop')), 'stop\n');
  }
  const sides = plan.options.run_side === 'comparison' ? ['baseline', 'feature'] : [plan.options.run_side];
  const units = sides.flatMap(side => Array.from({length: plan.options.run_pairs}, (_, i) =>
    ['a', 'b'].map(node => `tempo-e2e-${node}-${side}-${i + 1}.scope`))).flat();
  spawnSync('sudo', ['-n', 'systemctl', 'stop', ...units], {stdio: 'ignore', timeout: 30000});
}

function finish(planPath, code, cleanupRun = cleanup) {
  const dir = path.dirname(planPath), manifestPath = path.join(dir, 'manifest.json');
  const plan = JSON.parse(fs.readFileSync(planPath));
  const manifest = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath)) : {cases: []};
  if (code === 0 && manifest.status !== 'complete') code = 1;
  if (code !== 0) {
    // The parent flock is still held here. Never clean up a competing suite.
    if (manifest.status === 'running') cleanupRun(plan);
    manifest.status = 'failed';
    manifest.exit_code = code;
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  }
  fs.writeFileSync(path.join(dir, 'exit-code'), String(code) + '\n');
  return code;
}

if (require.main === module) {
  const [nu, planPath] = process.argv.slice(2);
  // Inherit streams: buffering large node logs would change the memory-pressure benchmark.
  const child = spawn(nu, ['--no-config-file', '-c', 'source bench-e2e.nu; run-state-access-suite $env.STATE_ACCESS_SUITE_PLAN'],
    {stdio: 'inherit', env: {...process.env, STATE_ACCESS_SUITE_PLAN: planPath}});
  child.on('error', error => console.error(error));
  child.on('close', code => { process.exitCode = finish(planPath, code ?? 1); });
}
module.exports = {finish};
