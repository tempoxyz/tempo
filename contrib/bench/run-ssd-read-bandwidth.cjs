'use strict';
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
function options(args) {
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--locked') { opts.locked = true; continue; }
    assert(['--builder-file', '--follower-file', '--output', '--builder-cpu', '--follower-cpu'].includes(args[i]) &&
      args[i + 1] && !args[i + 1].startsWith('--'), `invalid option: ${args[i]}`);
    opts[args[i].slice(2)] = args[++i];
  }
  for (const key of ['builder-file', 'follower-file', 'output']) assert(opts[key], `required: --${key}`);
  for (const key of ['builder-cpu', 'follower-cpu']) if (opts[key]) assert.match(opts[key], /^\d+$/);
  return opts;
}
function main(args) {
  if (args.includes('--help')) {
    console.log('node contrib/bench/run-ssd-read-bandwidth.cjs --builder-file MDBX_FILE --follower-file MDBX_FILE --output NEW_DIRECTORY [--builder-cpu 0] [--follower-cpu 8]');
    return;
  }
  const opts = options(args);
  if (!opts.locked) {
    const result = cp.spawnSync('flock', ['--nonblock', '/tmp/tempo-general-state-access-20260922.lock',
      process.execPath, __filename, ...args, '--locked'], {stdio: 'inherit'});
    process.exitCode = result.status ?? 1; return;
  }
  const command = (exe, argv) => cp.execFileSync(exe, argv, {encoding: 'utf8'});
  assert.equal(command('systemctl', ['list-units', '--no-legend', '--state=active', 'tempo-e2e-*.scope']).trim(), '',
    'benchmark scopes are active');
  const out = path.resolve(opts.output);
  assert(!fs.existsSync(out), `refusing to overwrite results directory: ${out}`);
  const manifest = {started_at: new Date().toISOString(), readonly: true, direct: true,
    offset: 8 * 2 ** 30, size: 32 * 2 ** 30, runtime_s: 10, ramp_time_s: 2,
    fio: command('fio', ['--version']).trim(), devices: [], runs: []};
  fs.mkdirSync(out, {recursive: true});
  const save = () => fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  const cases = [['read', '4k', 1], ['read', '28k', 1], ['read', '128k', 1], ['read', '1m', 1],
    ['read', '128k', 32], ['read', '1m', 32], ['randread', '4k', 1], ['randread', '24k', 1], ['randread', '28k', 1]];
  for (const name of ['builder', 'follower']) {
    const file = fs.realpathSync(opts[`${name}-file`]), before = fs.statSync(file);
    assert(before.isFile() && before.size >= manifest.offset + manifest.size, 'requires a populated regular file >= 40 GiB');
    // Force 4 KiB extent units, independent of the filesystem's block size.
    const layout = command('filefrag', ['-v', '-b4096', file]);
    fs.writeFileSync(path.join(out, `${name}-extents.txt`), layout);
    let covered = manifest.offset;
    for (const line of layout.split('\n')) {
      const e = line.match(/^\s*\d+:\s*(\d+)\.\.\s*(\d+):\s*\d+\.\.\s*\d+:\s*\d+:/);
      if (!e) continue;
      const start = Number(e[1]) * 4096, end = (Number(e[2]) + 1) * 4096;
      if (end <= covered) continue;
      if (covered >= manifest.offset + manifest.size) break;
      assert(start <= covered && !/unwritten|delalloc|unknown_loc/.test(line), `unallocated test range: ${line}`);
      covered = end;
    }
    assert(covered >= manifest.offset + manifest.size, 'test range is not fully allocated');
    manifest.devices.push({name, file, cpu: opts[`${name}-cpu`] ?? null, size: before.size, mtime_ms: before.mtimeMs});
    for (const [rw, bs, depth] of cases) {
      const id = `${name}-${rw}-${bs}-qd${depth}`, output = path.join(out, `${id}.json`);
      const argv = ['--readonly', `--name=${id}`, `--filename=${file}`, '--allow_file_create=0',
        `--rw=${rw}`, `--bs=${bs}`, '--direct=1', '--invalidate=0', '--ioengine=libaio',
        `--iodepth=${depth}`, '--numjobs=1', '--offset=8G', '--size=32G', '--runtime=10', '--ramp_time=2',
        '--time_based=1', '--randrepeat=1', '--randseed=216', '--eta=never', '--output-format=json', `--output=${output}`,
        ...(opts[`${name}-cpu`] ? [`--cpus_allowed=${opts[`${name}-cpu`]}`] : [])];
      console.log(`Starting ${id}`);
      const started = new Date().toISOString(), result = cp.spawnSync('fio', argv, {encoding: 'utf8', timeout: 120000});
      fs.writeFileSync(path.join(out, `${id}.stderr`), result.stderr || '');
      assert.equal(result.status, 0, result.stderr || result.error?.message);
      const data = JSON.parse(fs.readFileSync(output)), j = data.jobs[0];
      assert.equal(data.jobs.length, 1); assert.equal(j.error, 0);
      assert.equal(j.write.io_bytes, 0); assert.equal(j.trim.io_bytes, 0);
      assert(j.read.io_bytes > 0 && j.read.runtime >= 9900);
      assert(data.disk_util.some(d => d.read_ios > 0), 'no physical reads');
      manifest.runs.push({name: id, device: name, rw, bs, depth, args: argv, started, finished: new Date().toISOString(),
        GB_s: j.read.bw_bytes / 1e9, GiB_s: j.read.bw_bytes / 2 ** 30, IOPS: j.read.iops,
        latency_us: j.read.lat_ns.mean / 1000, completion_us: j.read.clat_ns.mean / 1000,
        p50_completion_us: j.read.clat_ns.percentile['50.000000'] / 1000,
        p99_completion_us: j.read.clat_ns.percentile['99.000000'] / 1000, achieved_depth: j.iodepth_level});
      save();
    }
    const after = fs.statSync(file);
    assert.equal(after.size, before.size); assert.equal(after.mtimeMs, before.mtimeMs);
  }
  manifest.finished_at = new Date().toISOString(); save();
}
if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = {options};
