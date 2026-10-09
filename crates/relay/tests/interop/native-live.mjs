import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createPublicClient, createWalletClient, encodeFunctionData, http, parseAbi } from 'viem'
import { mnemonicToAccount } from 'viem/accounts'
import { tempoLocalnet } from 'viem/chains'
import { Account, Actions } from 'viem/tempo'
import { MultisigConfig } from 'ox/tempo'

const upstream = process.env.TEMPO_RPC_URL ?? 'http://127.0.0.1:8545'
const rpc = process.env.TEMPO_RELAY_URL ?? 'http://127.0.0.1:8547'
for (const endpoint of [upstream, rpc])
  assert(['127.0.0.1', '[::1]', 'localhost'].includes(new URL(endpoint).hostname))
assert(process.env.TEMPO_RELAY_BINARY, 'Provide the rebuilt standalone relay binary')
const directory = await mkdtemp(join(tmpdir(), 'tempo-relay-native-'))
const publicClient = createPublicClient({ chain: tempoLocalnet, transport: http(rpc, { retryCount: 0, timeout: 10000 }) })
let relay
const start = async () => {
  relay = spawn(process.env.TEMPO_RELAY_BINARY, ['--dev', '--upstream', upstream, '--listen', new URL(rpc).host, '--store', `sqlite://${join(directory, 'relay.sqlite')}`], { stdio: ['ignore', 'inherit', 'inherit'] })
  for (let attempt = 0; attempt < 60; attempt++) {
    assert.equal(relay.exitCode, null, 'Relay exited during startup')
    try {
      assert.equal(await publicClient.getChainId(), 1337)
      return
    } catch (error) {
      if (attempt === 59) throw error
      await new Promise(resolve => setTimeout(resolve, 1000))
    }
  }
}
const stop = async () => {
  if (relay && relay.exitCode === null) {
    const exited = once(relay, 'exit')
    relay.kill('SIGINT')
    await exited
  }
}
const receiptFor = async hash => {
  const receipt = await publicClient.waitForTransactionReceipt({ hash, checkReplacement: false, timeout: 30000, pollingInterval: 250 })
  assert.equal(receipt.transactionHash, hash)
  assert.equal(receipt.status, 'success')
  return receipt
}
try {
  await start()
  const owners = [Account.fromSecp256k1(`0x${'01'.repeat(32)}`), Account.fromSecp256k1(`0x${'02'.repeat(32)}`)]
  const account = Account.fromMultisig({ owners: owners.map(owner => owner.address), threshold: 2 })
  const wallet = createWalletClient({ account, chain: tempoLocalnet, transport: http(rpc, { retryCount: 0 }) })
  const fundingWallet = createWalletClient({ account: mnemonicToAccount('test test test test test test test test test test test junk'), chain: tempoLocalnet, transport: http(rpc) })
  const token = '0x20c0000000000000000000000000000000000000'
  const abi = parseAbi(['function balanceOf(address) view returns (uint256)', 'function transfer(address,uint256) returns (bool)'])
  const balance = address => publicClient.readContract({ address: token, abi, functionName: 'balanceOf', args: [address] })
  const fundingHash = await fundingWallet.sendTransaction({ calls: [{ to: token, data: encodeFunctionData({ abi, functionName: 'transfer', args: [account.address, 2_000_000n] }) }], feePayer: false, nonceKey: 1n, nonce: 0 })
  await receiptFor(fundingHash)
  assert.equal(await balance(account.address), 2_000_000n)
  assert.equal(await Actions.multisig.getConfigCommitment(publicClient, { account: account.address }), `0x${'00'.repeat(32)}`)
  const recipient = Account.fromSecp256k1(`0x${'04'.repeat(32)}`).address
  const operationHash = await wallet.sendTransaction({ owner: owners[0], calls: [{ to: token, data: encodeFunctionData({ abi, functionName: 'transfer', args: [recipient, 1_000_000n] }) }], nonceKey: 1n, nonce: 0, feePayer: true })
  const pending = await Actions.multisig.getOperation(publicClient, { hash: operationHash })
  assert.equal(pending.status, 'pending')
  assert.equal(pending.weight, 1)
  assert.equal(await publicClient.request({ method: 'eth_getTransactionReceipt', params: [operationHash] }), null)
  console.log(JSON.stringify({ test: 'native-multisig-first-approval', operationHash, account: account.address, weight: pending.weight }))
  await stop()
  await start()
  const restored = await Actions.multisig.getOperation(publicClient, { hash: operationHash })
  assert.equal(restored.status, 'pending')
  assert.equal(restored.weight, 1)
  const request = await wallet.prepareTransactionRequest({ hash: operationHash, owner: owners[1] })
  const signedTransaction = await wallet.signTransaction(request)
  const serializedTransaction = await tempoLocalnet.serializers.transactionEnvelope({ serializedTransaction: signedTransaction, transaction: request })
  const approvals = await Promise.all(Array.from({ length: 8 }, () => wallet.sendRawTransaction({ serializedTransaction })))
  assert.deepEqual(approvals, Array(8).fill(operationHash))
  const operation = await Actions.multisig.getOperation(publicClient, { hash: operationHash })
  assert.equal(operation.status, 'success')
  assert.equal(operation.weight, 2)
  const receipt = await receiptFor(operation.transactionHash)
  assert.equal(receipt.from.toLowerCase(), account.address.toLowerCase())
  assert.equal(receipt.feePayer?.toLowerCase(), fundingWallet.account.address.toLowerCase())
  assert.equal(await balance(account.address), 1_000_000n)
  assert.equal(await balance(recipient), 1_000_000n)
  const commitment = await Actions.multisig.getConfigCommitment(publicClient, { account: account.address })
  assert.equal(commitment, MultisigConfig.getCommitment(account.config))
  const config = await Actions.multisig.getConfig(publicClient, { address: account.address })
  assert.equal(config.threshold, 2)
  assert.equal(config.version, 0n)
  await stop()
  await start()
  const completed = await Actions.multisig.getOperation(publicClient, { hash: operationHash })
  assert.equal(completed.transactionHash, operation.transactionHash)
  assert.equal(completed.status, 'success')
  console.log(JSON.stringify({ test: 'live-native-multisig-passed', operationHash, transactionHash: receipt.transactionHash, account: account.address, recipient, commitment, senderFeePaid: '0', concurrentApprovals: approvals.length, pendingRestart: true, completedRestart: true }))
  const accessKey = Account.fromSecp256k1(`0x${'05'.repeat(32)}`, { access: account.address })
  const pendingGrant = await Actions.accessKey.signAuthorization(publicClient, { account, owner: owners[0], accessKey, expiry: Math.floor(Date.now() / 1000) + 3600, limits: [{ token, limit: 500_000n }] })
  assert.equal(pendingGrant.status, 'pending')
  assert.equal(pendingGrant.multisig.weight, 1)
  const grant = await Actions.accessKey.signAuthorization(publicClient, { hash: pendingGrant.hash, owner: owners[1] })
  assert.equal(grant.status, 'success')
  assert.equal(grant.multisig.weight, 2)
  const accessWallet = createWalletClient({ account: accessKey, chain: tempoLocalnet, transport: http(rpc) })
  const accessHash = await accessWallet.sendTransaction({ keyAuthorization: grant, calls: [{ to: token, data: encodeFunctionData({ abi, functionName: 'transfer', args: [recipient, 500_000n] }) }], nonceKey: 2n, nonce: 0, feePayer: true })
  await receiptFor(accessHash)
  assert.equal(await balance(account.address), 500_000n)
  assert.equal(await balance(recipient), 1_500_000n)
  const metadata = await Actions.accessKey.getMetadata(publicClient, { account: account.address, accessKey })
  assert.equal(metadata.isRevoked, false)
  assert.equal(metadata.address.toLowerCase(), accessKey.accessKeyAddress.toLowerCase())
  console.log(JSON.stringify({ test: 'live-native-key-grant-passed', account: account.address, accessKey: accessKey.accessKeyAddress, authorizationHash: grant.hash, transactionHash: accessHash, weight: grant.multisig.weight }))
  const nextConfig = { threshold: 1, owners: [{ owner: owners[0].address, weight: 1 }] }
  const rotation = Actions.multisig.updateConfig.call({ currentConfig: account.config, nextConfig })
  const rotationHash = await wallet.sendTransaction({ owner: owners[0], calls: [{ to: rotation.address, data: rotation.data }], nonceKey: 1n, nonce: 1, feePayer: true })
  assert.equal((await Actions.multisig.getOperation(publicClient, { hash: rotationHash })).status, 'pending')
  assert.equal(await wallet.sendTransaction({ hash: rotationHash, owner: owners[1] }), rotationHash)
  const rotatedOperation = await Actions.multisig.getOperation(publicClient, { hash: rotationHash })
  await receiptFor(rotatedOperation.transactionHash)
  const rotatedConfig = await Actions.multisig.getConfig(publicClient, { address: account.address })
  assert.equal(rotatedConfig.threshold, 1)
  assert.equal(rotatedConfig.version, 1n)
  assert.equal(await Actions.multisig.getConfigCommitment(publicClient, { account: account.address }), MultisigConfig.getCommitment(rotatedConfig))
  const rotatedAccount = Account.fromMultisig({ address: account.address, ...rotatedConfig })
  const rotatedWallet = createWalletClient({ account: rotatedAccount, chain: tempoLocalnet, transport: http(rpc) })
  const rotatedHash = await rotatedWallet.sendTransaction({ owner: owners[0], calls: [{ to: account.address, data: '0x' }], nonceKey: 1n, nonce: 2, feePayer: true })
  const singleOwnerOperation = await Actions.multisig.getOperation(publicClient, { hash: rotatedHash })
  assert.equal(singleOwnerOperation.status, 'success')
  await receiptFor(singleOwnerOperation.transactionHash)
  console.log(JSON.stringify({ test: 'live-native-config-rotation-passed', account: account.address, rotationHash, version: String(rotatedConfig.version), threshold: rotatedConfig.threshold, singleOwnerTransactionHash: singleOwnerOperation.transactionHash }))
} finally {
  await stop()
}
