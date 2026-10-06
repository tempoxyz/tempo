import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createClient, http } from 'viem'
import { Actions } from 'viem/tempo'
import { MultisigOperation } from 'ox/tempo'

const fixture = JSON.parse(await readFile(new URL('../multisig-fixtures.json', import.meta.url)))
const client = createClient({ transport: http(process.argv[2], { retryCount: 0 }) })
const hashes = await Promise.all(Array.from({ length: 20 }, (_, i) => client.request({ method: 'multisig_approveRawTransaction', params: [fixture.signed[i % 2]] })))
assert.deepEqual(hashes, Array(20).fill(fixture.hash))
const operation = await Actions.multisig.getOperation(client, { hash: fixture.hash })
assert.equal(operation.status, 'success')
assert.equal(operation.weight, 2)
const config = await Actions.multisig.getConfig(client, { address: fixture.account })
assert.equal(config.threshold, 2)
const pending = MultisigOperation.fromRpc(await client.request({ method: 'multisig_approveKeyAuthorization', params: [{ keyAuthorization: fixture.rpcAuthorization[0] }] }))
assert.equal(pending.status, 'pending')
const complete = MultisigOperation.fromRpc(await client.request({ method: 'multisig_approveKeyAuthorization', params: [{ hash: fixture.authorizationHash, signature: fixture.authorizationApprovals[1] }] }))
assert.equal(complete.status, 'success')
assert.equal(complete.keyAuthorization, fixture.finalAuthorization)
const receipt = await client.request({ method: 'eth_getTransactionReceipt', params: [fixture.hash] })
assert.equal(receipt.multisig.status, 'success')
assert.equal(receipt.transactionHash, operation.transactionHash)
console.log('Unchanged viem and ox HTTP native multisig flow passed (simulated protocol-capable downstream)')
