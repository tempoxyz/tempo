// Runs the actual pinned viem Relay implementation, not a handwritten JavaScript port.
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'
import { readFile } from 'node:fs/promises'
import { createClient, custom } from 'viem'

const root = process.env.VIEM_REFERENCE_DIR
assert(root, 'Set VIEM_REFERENCE_DIR to the pinned viem source checkout described in README.md')
const Relay = await import(pathToFileURL(resolve(root, 'src/tempo/Relay.ts')).href)
const fixture = JSON.parse(await readFile(new URL('../multisig-fixtures.json', import.meta.url)))
const broadcasts = []
const transactions = new Map()
const { Hash } = await import('ox')
const store = new Map()
const storage = {
  async getItem(key) { return store.get(key) ?? null },
  async setItem(key, value) { store.set(key, value) },
  async removeItem(key) { store.delete(key) },
  async compareAndSet(key, expected, value) {
    if ((store.get(key) ?? null) !== expected) return false
    if (value === null) store.delete(key)
    else store.set(key, value)
    return true
  },
}
const client = createClient({ chain: { id: 1337 }, transport: custom({
  async request({ method, params }) {
    if (method === 'eth_blockNumber') return '0x1'
    if (method === 'eth_call') return `0x${'00'.repeat(32)}`
    if (method === 'eth_sendRawTransaction') {
      broadcasts.push(params[0])
      const hash = Hash.keccak256(params[0])
      transactions.set(hash, { hash, transactionHash: hash, status: '0x1' })
      return hash
    }
    if (method === 'eth_getTransactionByHash' || method === 'eth_getTransactionReceipt') return transactions.get(params[0]) ?? null
    throw new Error(`Unexpected reference RPC: ${method}`)
  },
}, { retryCount: 0 }) })
const relay = Relay.create({ client, plugins: [Relay.multisig({ store: storage })] })
const requests = Array.from({ length: 20 }, (_, i) => relay.request({ method: 'multisig_approveRawTransaction', params: [fixture.signed[i % 2]] }))
assert.deepEqual(await Promise.all(requests), Array(20).fill(fixture.hash))
assert.deepEqual(broadcasts, [fixture.final])
const operation = await relay.request({ method: 'multisig_getOperation', params: [fixture.hash] })
assert.equal(operation.status, 'success')
assert.equal(operation.weight, 2)
const pending = await relay.request({ method: 'multisig_approveKeyAuthorization', params: [{ keyAuthorization: fixture.rpcAuthorization[0] }] })
assert.equal(pending.status, 'pending')
const complete = await relay.request({ method: 'multisig_approveKeyAuthorization', params: [{ hash: fixture.authorizationHash, signature: fixture.authorizationApprovals[1] }] })
assert.equal(complete.keyAuthorization, fixture.finalAuthorization)
console.log('Pinned viem Relay reference: transaction and key-authorization fixtures passed')
