const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(process.argv[2] || __dirname);
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json')));
assert(manifest.finished_at);
assert.equal(manifest.runs.length, 18);
const result = {generated_at: new Date().toISOString(), decimal_GB: true, devices: {}};
for (const device of ['builder', 'follower']) {
  const rows = manifest.runs.filter(row => row.device === device);
  for (const row of rows) {
    const data = JSON.parse(fs.readFileSync(path.join(root, `${row.name}.json`)));
    const j = data.jobs[0];
    assert.equal(j.error, 0);
    assert.equal(j.write.io_bytes, 0);
    assert.equal(j.trim.io_bytes, 0);
    assert.equal(j.iodepth_level[String(row.depth)], 100);
  }
  const get = (rw, bs, depth) => rows.find(row => row.rw === rw && row.bs === bs && row.depth === depth);
  const random4 = get('randread', '4k', 1);
  const random24 = get('randread', '24k', 1);
  const random28 = get('randread', '28k', 1);
  const delta24 = random28.latency_us - random4.latency_us;
  const sequential = get('read', '128k', 32).GB_s;
  result.devices[device] = {
    sequential_28k_qd1_GB_s: get('read', '28k', 1).GB_s,
    sequential_128k_qd1_GB_s: get('read', '128k', 1).GB_s,
    sequential_128k_qd32_GB_s: sequential,
    sequential_1m_qd1_GB_s: get('read', '1m', 1).GB_s,
    sequential_1m_qd32_GB_s: get('read', '1m', 32).GB_s,
    random_4k_qd1_us: random4.latency_us,
    random_24k_qd1_us: random24.latency_us,
    random_28k_qd1_us: random28.latency_us,
    additional_24KiB_us: delta24,
    marginal_4k_to_28k_GB_s: 24 * 1024 / (delta24 * 1000),
    marginal_4k_to_24k_GB_s: 20 * 1024 / ((random24.latency_us - random4.latency_us) * 1000),
    additional_24KiB_at_peak_sequential_us: 24 * 1024 / (sequential * 1000),
  };
}
fs.writeFileSync(path.join(root, 'summary.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
