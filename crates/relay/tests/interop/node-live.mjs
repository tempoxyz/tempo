import assert from 'node:assert/strict'
import { createPublicClient, createWalletClient, http, parseAbi } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { tempoLocalnet } from 'viem/chains'

const rpc = process.env.TEMPO_RELAY_URL ?? 'http://127.0.0.1:8547'
assert(['127.0.0.1', '[::1]', 'localhost'].includes(new URL(rpc).hostname))
const publicClient = createPublicClient({ chain: tempoLocalnet, transport: http(rpc, { retryCount: 0 }) })
for (let attempt = 0; attempt < 60; attempt++) {
  try {
    assert.equal(await publicClient.getChainId(), 1337)
    break
  } catch (error) {
    if (attempt === 59) throw error
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
}
const account = privateKeyToAccount(`0x${'03'.repeat(32)}`)
const sponsor = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266'
const token = '0x20c0000000000000000000000000000000000000'
const abi = parseAbi(['function balanceOf(address) view returns (uint256)'])
const balance = address => publicClient.readContract({ address: token, abi, functionName: 'balanceOf', args: [address] })
const senderBefore = await balance(account.address)
const sponsorBefore = await balance(sponsor)
const wallet = createWalletClient({ account, chain: tempoLocalnet, transport: http(rpc) })
for (const parameters of [{ nonceKey: 1n, nonce: 0 }, {}]) {
  const hash = await wallet.sendTransaction({ calls: [{ to: account.address, value: 0n, data: '0x' }], feePayer: true, ...parameters })
  const receipt = await publicClient.waitForTransactionReceipt({ hash, checkReplacement: false, timeout: 20000, pollingInterval: 250 })
  assert.equal(receipt.transactionHash, hash)
  assert.equal(receipt.status, 'success')
  assert.equal(receipt.feePayer?.toLowerCase(), sponsor)
  console.log(JSON.stringify({ test: 'node-integrated-relay', hash, blockNumber: String(receipt.blockNumber), feePayer: receipt.feePayer }))
}
assert.equal(await balance(account.address), senderBefore)
assert(await balance(sponsor) < sponsorBefore)
console.log('Automatic tempo node --dev relay sponsorship passed with plain http')
