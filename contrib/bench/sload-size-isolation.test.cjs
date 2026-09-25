'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {createHash} = require('node:crypto');
const {makePlan, checkMemory, MEMORY, ORDER} = require('./run-sload-size-isolation.cjs');
const {selectTraceCandidates, validateHistorySamples} = require('./state-path-observer.cjs');

test('isolation plans form a two-by-two with identical memory, prefetch and corpus settings', () => {
  const base = {configuration: {duration:1200, warmup:600, tps:1000, accounts:1000,
    fixture_requirements:{snapshot_suffix:'history_paths'}, cases:[]}, options:{feature_binary:'/same/tempo'}};
  const before = structuredClone(base);
  assert.equal(new Set(ORDER.map(x => `${x.reads}-${x.prewarming}`)).size, 4);
  for (const item of ORDER) {
    const plan = makePlan(base, item, 'test');
    assert.equal(plan.configuration.cases[0].operations_per_transaction, item.reads);
    assert.equal(plan.configuration.cases[0].scenario, item.reads === 128 ? 'history_read' : 'state_access_dependent');
    assert.equal(plan.configuration.cases[0].minimum_history_advanced_fraction, item.reads === 128 ? 0.9 : 0);
    assert.equal(plan.options.feature_args.includes('--builder.disable-prewarming'), !item.prewarming);
    assert.equal(plan.options.feature_args.includes('--engine.disable-prewarming'), !item.prewarming);
    assert.equal(plan.options.feature_env, 'RETH_BYTECODE_PREFETCH=1');
    assert.equal(plan.options.node_memory, '20G');
    assert.equal(plan.options.node_swap_limit, '0');
    assert.equal(plan.options.allow_first_sload_samples, item.reads === 4096);
    assert.deepEqual(plan.configuration.fixture_requirements, base.configuration.fixture_requirements);
  }
  assert.deepEqual(base, before);
});

test('large-SLOAD control can audit single-tx blocks without weakening history bypass gates', () => {
  const single = Array.from({length:8}, (_,i) => ({number:i,tx_count:1}));
  assert.throws(() => selectTraceCandidates(single, true, 'state_access_dependent'));
  const result = selectTraceCandidates(single, true, 'state_access_dependent', true);
  assert.deepEqual(result.candidates, single);
  assert.equal(result.policy, 'large-sload-control-first-allowed');
  for (const scenario of ['history_read','history_code','history_write'])
    assert.throws(() => selectTraceCandidates(single, true, scenario, true));
  const multi = single.map(b => ({...b, tx_count:2}));
  assert.equal(selectTraceCandidates(multi, true, 'state_access_dependent', true).policy, 'non-first-required');
  const first = [{history_advanced:false, parent_state_mismatch_fraction:0}];
  assert.throws(() => validateHistorySamples(first, 'non-first-required'));
  validateHistorySamples(first, result.policy);
  assert.throws(() => validateHistorySamples([{history_advanced:true,parent_state_mismatch_fraction:0}], result.policy));
  validateHistorySamples([{history_advanced:true,parent_state_mismatch_fraction:1}], 'non-first-required');
});

test('isolation evidence rejects wrong caps, swap, OOM and missing measurements', () => {
  const good = {memory_limits:{'memory.max':String(MEMORY), 'memory.current':String(MEMORY),
    'memory.swap.max':'0', 'memory.swap.current':'0'}, memory_events:{oom:0, oom_kill:0}};
  checkMemory(good);
  for (const field of ['memory.max','memory.swap.max','memory.swap.current']) {
    const bad = structuredClone(good); bad.memory_limits[field] = '1024';
    assert.throws(() => checkMemory(bad));
  }
  for (const field of ['oom','oom_kill']) {
    const bad = structuredClone(good); bad.memory_events[field] = 1;
    assert.throws(() => checkMemory(bad));
  }
  assert.throws(() => checkMemory({}));
});

test('native dispatcher forwards optional memory controls without changing defaults', () => {
  const source = fs.readFileSync('bench-e2e.nu', 'utf8');
  assert.match(source, /--node-memory \(\$options\.node_memory\? \| default ""\)/);
  assert.match(source, /--node-swap-limit \(\$options\.node_swap_limit\? \| default ""\)/);
  assert.match(source, /MemorySwapMax=\(\$swap\)/);
  assert.match(source, /memory: \(if \$node_memory == "" \{ \$E2E_A_MEMORY \}/);
  assert.match(source, /--cache-evict-tool \(\$options\.cache_evict_tool\? \| default ""\)/);
});

test('targeted eviction verifies residency without altering file contents', {skip: process.platform !== 'linux'}, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tempo-cache-evict-test-'));
  try {
    const binary = path.join(dir, 'evict'), file = path.join(dir, 'data');
    execFileSync('cc', ['-std=c11','-O2','-Wall','-Wextra','-Werror','contrib/bench/evict-benchmark-file-cache.c','-o',binary]);
    const data = Buffer.alloc(16 * 2 ** 20, 42);
    fs.writeFileSync(file, data);
    const result = JSON.parse(execFileSync(binary, [file], {encoding:'utf8'}));
    assert.equal(result.bytes, data.length);
    assert.ok(result.resident_before > 0);
    assert.ok(result.resident_after <= 16);
    assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'), createHash('sha256').update(data).digest('hex'));
  } finally {fs.rmSync(dir, {recursive:true, force:true});}
});
