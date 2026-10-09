import assert from 'node:assert/strict'
import { createPublicClient, createWalletClient, http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { tempoLocalnet } from 'viem/chains'
import { Actions, withRelay } from 'viem/tempo'
import { Transaction, TxEnvelopeTempo } from 'ox/tempo'

const rpc = process.env.TEMPO_RPC_URL ?? 'http://127.0.0.1:8545'
const relay = process.env.TEMPO_RELAY_URL ?? 'http://127.0.0.1:8547'
for (const endpoint of [rpc, relay]) {
  assert(['127.0.0.1', '[::1]', 'localhost'].includes(new URL(endpoint).hostname),
    'Interop tests are restricted to loopback endpoints')
}
const publicClient = createPublicClient({ chain: tempoLocalnet, transport: http(rpc) })
assert.equal(await publicClient.getChainId(), 1337)
const account = privateKeyToAccount(`0x${'03'.repeat(32)}`)
const wallet = createWalletClient({
  account,
  chain: tempoLocalnet,
  transport: withRelay(http(rpc), http(relay)),
})
const hash = await wallet.sendTransaction({
  calls: [{ to: account.address, value: 0n, data: '0x' }],
  feePayer: true,
  nonceKey: 1n,
  nonce: Number(await Actions.nonce.getNonce(publicClient, { account: account.address, nonceKey: 1n })),
})
const receipt = await publicClient.waitForTransactionReceipt({ hash })
assert.equal(receipt.status, 'success')
assert.notEqual(receipt.feePayer?.toLowerCase(), account.address.toLowerCase())
assert.equal(receipt.feePayer?.toLowerCase(), '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266')
const sent = await publicClient.getTransaction({ hash })
assert.equal(sent.from.toLowerCase(), account.address.toLowerCase())
assert.equal(sent.type, 'tempo')
console.log(`viem withRelay sponsored a transaction: ${hash}`)

const unsigned = await wallet.request({
  method: 'eth_fillTransaction',
  params: [{ from: account.address, calls: [{ to: account.address }], feePayer: true }],
})
assert.equal(unsigned.capabilities.sponsored, true)
const parsed = TxEnvelopeTempo.from(Transaction.fromRpc(unsigned.tx))
assert(parsed.feePayerSignature)
console.log('viem/ox parsed the relay fill response and fee-payer signature')
