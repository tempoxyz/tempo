import assert from 'node:assert/strict'
import { zone } from './runtime.mjs'

const { chainId } = await zone()
const rpcBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] })
for (const url of ['http://127.0.0.1:9545', 'http://127.0.0.1:13000/api/rpc']) {
  const response = await fetch(url, {
    method: 'POST', body: rpcBody,
    headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(30_000),
  })
  assert.equal(response.status, 200, url)
  assert.equal(Number(BigInt((await response.json()).result)), chainId, url)
}
const query = new URL('http://127.0.0.1:18080/query')
query.searchParams.set('chainId', String(chainId))
query.searchParams.set('sql', 'SELECT num FROM blocks ORDER BY num DESC LIMIT 1')
const indexed = await fetch(query, { signal: AbortSignal.timeout(30_000) })
assert.equal(indexed.status, 200)
const result = await indexed.json()
assert.equal(result.ok, true)
assert.ok(result.rows.length > 0, 'TIDX must have indexed a block')
for (const url of [
  `http://127.0.0.1:18787/v1/blocks?chainId=${chainId}&limit=5`,
  'http://127.0.0.1:18080/status',
  'http://127.0.0.1:13000/',
]) {
  const response = await fetch(url, { signal: AbortSignal.timeout(60_000) })
  assert.equal(response.status, 200, `${url}: ${await response.text()}`)
}
console.log(`Local stack passed: chain ${chainId}, indexed blocks, API, explorer, and same-origin RPC`)
