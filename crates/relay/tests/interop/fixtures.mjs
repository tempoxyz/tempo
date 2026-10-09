import { privateKeyToAccount } from 'viem/accounts'
import { Account } from 'viem/tempo'
import { MultisigConfig, MultisigOperation, TxEnvelopeTempo, KeyAuthorization, SignatureEnvelope } from 'ox/tempo'

const owners = [1, 2].map(i => privateKeyToAccount(`0x${i.toString(16).padStart(2, '0').repeat(32)}`))
  .sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()))
const config = MultisigConfig.from({ owners: owners.map(owner => ({ owner: owner.address, weight: 1 })), threshold: 2 })
const account = MultisigConfig.getAddress(config, { factory: '0x7171717171717171717171717171717171717171' })
const transaction = TxEnvelopeTempo.from({ chainId: 1337n, gas: 300000n, maxFeePerGas: 20000000000n,
  calls: [{ to: account, value: 0n, data: '0x' }], nonce: 0n })
const unsigned = TxEnvelopeTempo.serialize(transaction)
const hash = MultisigOperation.getHash({ account, config, transaction: unsigned, type: 'transaction' })
const approvals = await Promise.all(owners.map(owner => owner.sign({ hash })))
const signed = approvals.map(approval => TxEnvelopeTempo.serialize(transaction, {
  signature: { type: 'multisig', account, config, signatures: [SignatureEnvelope.from(approval)] },
}))
const authorization = KeyAuthorization.from({ chainId: 1337n, type: 'secp256k1', address: owners[0].address, account })
const unsignedAuthorization = KeyAuthorization.serialize(authorization)
const authorizationHash = MultisigOperation.getHash({ account, config, keyAuthorization: unsignedAuthorization, type: 'keyAuthorization' })
const authorizationApprovals = await Promise.all(owners.map(owner => owner.sign({ hash: authorizationHash })))
const signedAuthorization = authorizationApprovals.map(approval => KeyAuthorization.serialize({ ...authorization,
  signature: { type: 'multisig', account, config, signatures: [SignatureEnvelope.from(approval)] },
}))
const sponsoredTransaction = TxEnvelopeTempo.from({ ...transaction, feePayerSignature: null })
const sponsoredUnsigned = TxEnvelopeTempo.serialize(sponsoredTransaction)
const sponsoredHash = MultisigOperation.getHash({ account, config, transaction: sponsoredUnsigned, type: 'transaction' })
const sponsoredApprovals = await Promise.all(owners.map(owner => owner.sign({ hash: sponsoredHash })))
const sponsoredSigned = sponsoredApprovals.map(approval => TxEnvelopeTempo.serialize(sponsoredTransaction, {
  format: 'feePayer', sender: account,
  signature: { type: 'multisig', account, config, signatures: [SignatureEnvelope.from(approval)] },
}))
const finalAuthorization = KeyAuthorization.serialize({ ...authorization, signature: { type: 'multisig', account, config, signatures: authorizationApprovals.map(SignatureEnvelope.from) } })
const nativeGrantTransaction = TxEnvelopeTempo.from({ ...sponsoredTransaction, maxFeePerGas: 100_000_000n, keyAuthorization: KeyAuthorization.deserialize(finalAuthorization), nonceKey: 2n })
const accessKey = Account.fromSecp256k1(`0x${'01'.repeat(32)}`, { access: account })
const nativeGrantSignature = await accessKey.sign({ hash: TxEnvelopeTempo.getSignPayload(nativeGrantTransaction) })
const nativeGrantSigned = TxEnvelopeTempo.serialize(nativeGrantTransaction, { format: 'feePayer', sender: account, signature: SignatureEnvelope.from(nativeGrantSignature) })
console.log(JSON.stringify({ config: MultisigConfig.toRpc(config), account, commitment: MultisigConfig.getCommitment(config),
  unsigned, hash, approvals, signed,
  final: TxEnvelopeTempo.serialize(transaction, { signature: { type: 'multisig', account, config, signatures: approvals.map(SignatureEnvelope.from) } }),
  unsignedAuthorization, authorizationHash, authorizationApprovals, signedAuthorization,
  rpcAuthorization: signedAuthorization.map(value => KeyAuthorization.toRpc(KeyAuthorization.deserialize(value))),
  sponsoredHash, sponsoredSigned,
  finalAuthorization,
  nativeGrantSigned,
}, null, 2))
