'use strict';
const assert = require('node:assert/strict');

function gasBetween(blocks, from, to) {
  assert.ok(Number.isSafeInteger(from) && from >= 0 && Number.isSafeInteger(to) && to >= from);
  const selected = blocks.filter(block => block.number > from && block.number <= to);
  assert.equal(selected.length, to - from, 'canonical report does not cover durable/backlog interval');
  let gas = 0n;
  for (const [i, block] of selected.entries()) {
    assert.equal(block.number, from + i + 1, 'non-contiguous durable/backlog interval');
    gas += BigInt(block.gas_used);
  }
  assert.ok(gas <= BigInt(Number.MAX_SAFE_INTEGER));
  return Number(gas);
}

function summarizeDurability(rows, node, blocks, from, to) {
  const points = rows.filter(row => row.nodes[node]?.persisted && row.nodes[node].unix_ms >= from && row.nodes[node].unix_ms <= to)
    .map(row => ({unix_ms: row.nodes[node].unix_ms, state: row.nodes[node].persisted.state, producer: row.nodes.a.head}));
  assert.ok(points.length >= 2, 'insufficient durable observations');
  for (let i = 0; i < points.length; i++) {
    const p = points[i];
    assert.ok(Number.isSafeInteger(p.state) && p.state >= 0 && Number.isSafeInteger(p.producer) && p.producer >= p.state, 'invalid durable/producer head');
    if (i) assert.ok(p.unix_ms > points[i-1].unix_ms && p.state >= points[i-1].state && p.producer >= points[i-1].producer, 'durable/producer progress regressed');
  }
  const first = points[0], last = points.at(-1), seconds = (last.unix_ms - first.unix_ms) / 1000;
  const durableGas = gasBetween(blocks, first.state, last.state);
  const producedGas = gasBetween(blocks, first.producer, last.producer);
  const backlog = points.map(p => ({unix_ms: p.unix_ms, blocks: p.producer-p.state, gas: gasBetween(blocks, p.state, p.producer)}));
  return {from_unix_ms: first.unix_ms, to_unix_ms: last.unix_ms, duration_seconds: seconds,
    first_state: first.state, last_state: last.state, persisted_gas: durableGas, produced_gas: producedGas,
    persisted_mgas_per_second: durableGas / seconds / 1e6, produced_mgas_per_second: producedGas / seconds / 1e6,
    producer_backlog_blocks: {first: backlog[0].blocks, last: backlog.at(-1).blocks, max: Math.max(...backlog.map(p=>p.blocks))},
    producer_backlog_gas: {first: backlog[0].gas, last: backlog.at(-1).gas, max: Math.max(...backlog.map(p=>p.gas))},
    backlog, scope: 'Canonical gas crossed by the durable state/trie frontier in the observed wall window. Batched commits are stepwise; a growing producer-to-durable backlog is not sustainable chain throughput. This is not an EVM execution-only rate.'};
}

module.exports = {gasBetween, summarizeDurability};
