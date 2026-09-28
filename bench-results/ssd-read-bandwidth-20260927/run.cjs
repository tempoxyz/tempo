const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const out = __dirname;
const command = (exe, args) => cp.execFileSync(exe, args, {encoding: 'utf8'});
if (process.argv[2] !== '--locked') {
  const run = cp.spawnSync('flock', ['--nonblock', '/tmp/tempo-general-state-access-20260922.lock',
    process.execPath, __filename, '--locked'], {stdio: 'inherit'});
  process.exit(run.status ?? 1);
}
const devices = [
  {name: 'builder', role: 'a', cpu: 0, nvme: 'nvme1'},
  {name: 'follower', role: 'b', cpu: 8, nvme: 'nvme2'},
];
const cases = [
  ['read', '4k', 1], ['read', '28k', 1],
  ['read', '128k', 1], ['read', '1m', 1],
  ['read', '128k', 32], ['read', '1m', 32],
  ['randread', '4k', 1], ['randread', '24k', 1], ['randread', '28k', 1],
];
const manifest = {started_at: new Date().toISOString(), readonly: true, direct: true,
  offset: 8 * 2 ** 30, size: 32 * 2 ** 30, runtime_s: 10, ramp_time_s: 2,
  fio: command('fio', ['--version']).trim(), devices: [], runs: []};
const save = () => fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
for (const d of devices) {
  const file = `/reth-bench-${d.role}/tempo_e2e_100000mb_state_access_isolated_roles_history_paths/db/mdbx.dat`;
  const before = fs.statSync(file);
  const layout = command('filefrag', ['-v', file]);
  fs.writeFileSync(path.join(out, `${d.name}-extents.txt`), layout);
  const extents = layout.split('\n').map(line => line.match(/^\s*\d+:\s*(\d+)\.\.\s*(\d+):\s*(\d+)\.\.\s*(\d+):\s*(\d+):/)).filter(Boolean);
  let covered = manifest.offset;
  for (const e of extents) {
    const start = Number(e[1]) * 4096, end = (Number(e[2]) + 1) * 4096;
    if (end <= covered) continue;
    if (covered >= manifest.offset + manifest.size) break;
    assert(start <= covered && !/unwritten|delalloc|unknown_loc/.test(e.input), `unallocated test range: ${e.input}`);
    covered = end;
  }
  assert(covered >= manifest.offset + manifest.size, 'test range is not fully allocated');
  const link = `/sys/class/nvme/${d.nvme}/device`;
  manifest.devices.push({...d, file, size: before.size, mtime_ms: before.mtimeMs,
    link_speed: fs.readFileSync(`${link}/current_link_speed`, 'utf8').trim(),
    link_width: fs.readFileSync(`${link}/current_link_width`, 'utf8').trim()});
  for (const [rw, bs, depth] of cases) {
    const name = `${d.name}-${rw}-${bs}-qd${depth}`;
    const output = path.join(out, `${name}.json`);
    assert(!fs.existsSync(output), `refusing to overwrite ${output}`);
    const args = ['--readonly', `--name=${name}`, `--filename=${file}`, '--allow_file_create=0',
      `--rw=${rw}`, `--bs=${bs}`, '--direct=1', '--invalidate=0', '--ioengine=libaio',
      `--iodepth=${depth}`, '--numjobs=1', `--cpus_allowed=${d.cpu}`, '--offset=8G', '--size=32G',
      '--runtime=10', '--ramp_time=2', '--time_based=1', '--randrepeat=1', '--randseed=216',
      '--eta=never', '--output-format=json', `--output=${output}`];
    const started = new Date().toISOString();
    console.log(`${started} starting ${name}`);
    const run = cp.spawnSync('fio', args, {encoding: 'utf8', timeout: 120000});
    fs.writeFileSync(path.join(out, `${name}.stderr`), run.stderr || '');
    assert.equal(run.status, 0, run.stderr || run.error?.message);
    const data = JSON.parse(fs.readFileSync(output, 'utf8'));
    assert.equal(data.jobs.length, 1);
    const j = data.jobs[0];
    assert.equal(j.error, 0);
    assert.equal(j.write.io_bytes, 0);
    assert.equal(j.trim.io_bytes, 0);
    assert(j.read.io_bytes > 0 && j.read.runtime >= 9900);
    assert(data.disk_util.some(disk => disk.read_ios > 0));
    const result = {name, device: d.name, rw, bs, depth, started, finished: new Date().toISOString(),
      args, GB_s: j.read.bw_bytes / 1e9, GiB_s: j.read.bw_bytes / 2 ** 30,
      IOPS: j.read.iops, latency_us: j.read.lat_ns.mean / 1000,
      completion_us: j.read.clat_ns.mean / 1000,
      p50_completion_us: j.read.clat_ns.percentile['50.000000'] / 1000,
      p99_completion_us: j.read.clat_ns.percentile['99.000000'] / 1000,
      achieved_depth: j.iodepth_level};
    manifest.runs.push(result); save();
    console.log(`${name}: ${result.GB_s.toFixed(3)} GB/s, ${result.latency_us.toFixed(2)} us/request`);
  }
  const after = fs.statSync(file);
  assert.equal(after.size, before.size);
  assert.equal(after.mtimeMs, before.mtimeMs);
}
manifest.finished_at = new Date().toISOString(); save();
