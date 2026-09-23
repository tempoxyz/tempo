const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { main } = require('./bench-e2e-classify');

for (const configured of [false, true]) {
  test(`CPU allocation summary: ${configured ? 'isolated vs shared' : 'legacy'}`, t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-cpu-summary-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const config = { run_pairs: 2 };
    if (configured) config.cpu_layout = {
      baseline: { a: '0,16', b: '1,17', txgen: '', txgen_cores: 0 },
      feature: { a: '0', b: '1', txgen: '2,3', txgen_cores: 2 },
    };
    fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify({
      config, per_run: [], results: { baseline: {}, feature: {} },
    }));
    main(dir);
    const markdown = fs.readFileSync(path.join(dir, 'summary.md'), 'utf8');
    if (configured) {
      assert.match(markdown, /baseline CPUs: validator a `0,16`, validator b `1,17`, txgen `shared\/unpinned`/);
      assert.match(markdown, /feature CPUs: validator a `0`, validator b `1`, txgen `2,3` \(2 dedicated physical cores\)/);
      const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json')));
      assert.deepEqual(summary.config.cpu_layout, config.cpu_layout);
    } else {
      assert.doesNotMatch(markdown, /CPUs:/);
    }
  });
}
