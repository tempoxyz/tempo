#!/usr/bin/env node
// Offline CLI contract matrix. Run against the built binary, including Tempo's
// download wrapper and tracing parse. Planning must not fetch or install archives.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const tempo = resolve(process.argv[2] ?? 'target/debug/tempo');
const root = mkdtempSync(join(tmpdir(), 'tempo-download-cli-'));
let passed = 0;
let failed = 0;

function check(label, fn) {
  try {
    fn();
    passed++;
  } catch (error) {
    failed++;
    console.error(`FAIL ${label}: ${error.message}`);
  }
}

function run(args) {
  const result = spawnSync(tempo, ['download', '--color', 'never', ...args], {
    cwd: root,
    // Keep default data/log paths isolated from the developer's real node.
    env: { ...process.env, XDG_DATA_HOME: root, XDG_CACHE_HOME: root },
    encoding: 'utf8',
    timeout: 10_000,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `terminated by ${result.signal}`);
  return result;
}

function plan(args, chainId, consensus = true) {
  const result = run(['--print-plan-json', '--log.stdout.filter', 'off', ...args]);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.chainId, chainId);
  assert.equal(output.block, 42);
  assert.ok(output.archives.some(a => a.fileName === 'state.tar.zst'));
  assert.equal(output.archives.some(a => a.component === 'consensus'), consensus);
}

try {
  const manifests = new Map();
  for (const chainId of [4217, 42431]) {
    const archive = file => ({
      file, size: 1, decompressed_size: 1,
      output_files: [{ path: 'db/fixture', size: 1, blake3: '00'.repeat(32) }],
    });
    const manifest = join(root, `${chainId}.json`);
    writeFileSync(manifest, JSON.stringify({
      block: 42, chain_id: chainId, storage_version: 2, timestamp: 0,
      components: { state: archive('state.tar.zst') },
      consensus: {
        execution_finalized_height: 40, execution_finalized_digest: `0x${'00'.repeat(32)}`,
        tip_finalization_height: 42, tip_finalization_digest: `0x${'00'.repeat(32)}`,
        anchor_finalization_height: 41, anchor_finalization_digest: `0x${'00'.repeat(32)}`,
        consensus_archive: archive('consensus.tar.zst'),
      },
    }));
    manifests.set(chainId, manifest);
  }

  // Cartesian product: 2 chains x 2 sources x 2 chain-flag states x
  // 4 selection modes x 4 resumable forms = 128 independently reported cases.
  // The Moderato/omitted-chain rows reproduce the Shopify regression.
  const target = join(root, 'download');
  for (const [chainId, manifest] of manifests) {
    for (const source of ['--manifest-path', '--manifest-url']) {
      const location = source === '--manifest-url' ? pathToFileURL(manifest).href : manifest;
      for (const chain of [[], ['--chain', chainId === 4217 ? 'mainnet' : 'moderato']]) {
        for (const selection of [[], ['--minimal'], ['--archive'], ['--with-txs']]) {
          for (const resumable of [[], ['--resumable'], ['--resumable=true'], ['--resumable=false']]) {
            const args = [source, location, '--datadir', target, '-y', ...chain, ...selection, ...resumable];
            check(`chain=${chainId} ${args.join(' ')}`, () => {
              plan(args, chainId);
              assert.ok(!existsSync(target), 'planning created the destination');
            });
          }
        }
      }
    }
  }

  const manifest = manifests.get(42431);
  check('Shopify archive flags without --chain', () => plan([
    '--manifest-url', pathToFileURL(manifest).href, '--datadir', target,
    '-y', '--archive', '--resumable', '--download-concurrency', '32',
  ], 42431));
  const base = ['--manifest-path', manifest, '--chain', 'moderato', '--datadir', target];
  // Omit each optional flag independently; also retain supported aliases and
  // Tempo-only flags so disappearing flags fail even when parsing stays permissive.
  const valid = [
    // Full pruning can depend on the selected chain's hardforks, so keep an
    // explicit matching chain for this case rather than treating it as optional.
    ['full preset', ['-y', '--full']],
    ['without -y', ['--archive']],
    ['all alias', ['-y', '--all']],
    ['long non-interactive', ['--non-interactive']],
    ['concurrency', ['-y', '--download-concurrency', '32']],
    ['retry backoff', ['-y', '--retry-backoff', '500ms']],
    ['force', ['-y', '--force']],
    ['without rocksdb', ['-y', '--archive', '--without-rocksdb']],
    ['senders dependency satisfied', ['-y', '--with-txs', '--with-senders']],
    ['consensus directory', ['-y', '--consensus.datadir', join(root, 'consensus')]],
    ['explicit consensus enabled', ['-y', '--skip-consensus=false']],
    ['skip consensus', ['-y', '--skip-consensus'], false],
    ['explicit skip consensus', ['-y', '--skip-consensus=true'], false],
  ];
  for (const [label, flags, consensus = true] of valid) {
    check(label, () => plan([...base, ...flags], 42431, consensus));
  }
  for (const datadir of [[], ['--datadir', 'default']]) {
    check(`matching chain with datadir ${datadir.join(' ') || 'omitted'}`, () =>
      plan(['--manifest-path', manifest, '--chain', 'moderato', '-y', ...datadir], 42431));
    check(`mismatched chain with datadir ${datadir.join(' ') || 'omitted'}`, () => {
      const result = run(['--manifest-path', manifest, '--chain', 'mainnet', '-y', '--print-plan-json', ...datadir]);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /Snapshot chain ID 42431 does not match selected chain ID 4217/);
    });
  }

  // A nonzero exit alone is insufficient: an invalid CLI might parse and then
  // fail at runtime. Require clap's exit code and the relevant diagnostic.
  const invalid = [
    ['senders require transactions', ['--with-senders'], /required arguments.*not provided/s],
    ['conflicting presets', ['--minimal', '--archive'], /cannot be used with/],
    ['preset with component', ['--minimal', '--with-txs'], /cannot be used with/],
    ['conflicting sources', ['--manifest-url', 'file:///unused.json'], /cannot be used with/],
    ['list with manifest', ['--list'], /cannot be used with/],
    ['unknown flag', ['--not-a-download-flag'], /unexpected argument/],
  ];
  for (const [label, flags, diagnostic] of invalid) {
    check(label, () => {
      const result = run([...base, ...flags]);
      assert.equal(result.status, 2, result.stderr);
      assert.match(result.stderr, diagnostic);
    });
  }
  for (const flag of ['--chain', '--datadir', '--manifest-path', '--manifest-url',
    '--consensus.datadir', '--download-concurrency', '--retry-backoff', '--with-txs-since']) {
    check(`${flag} requires a value`, () => {
      const result = run([flag]);
      assert.equal(result.status, 2, result.stderr);
      assert.match(result.stderr, /a value is required/);
      assert.ok(result.stderr.includes(flag), result.stderr);
    });
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log(`Download CLI matrix: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
