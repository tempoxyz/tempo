// Proves a test token in both forms and writes the vectors tempo-zk verifies.
//
// Usage: node scripts/vectors.ts <wasm> <zkey> <verification-key.json> <out.json>

import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as snarkjs from 'snarkjs'
import * as Encoding from '../src/encoding.ts'
import * as Hashing from '../src/hashing.ts'
import * as Inputs from '../src/inputs.ts'
import * as Tokens from '../test/tokens.ts'

const [wasm, zkey, vkPath, out] = process.argv.slice(2)
if (!wasm || !zkey || !vkPath || !out)
  throw new Error('usage: node scripts/vectors.ts <wasm> <zkey> <verification-key.json> <out.json>')

const verificationKey = JSON.parse(fs.readFileSync(vkPath, 'utf8')) as Encoding.VerifyingKey
const key = Tokens.generateKey()
const iss = 'https://accounts.google.com'
const aud = '1234567890-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com'
const sub = '110169484474386276334'
const iat = 1_760_000_000
const salt = 0x1d2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60n
const accessKeyId = 0x6e4b2c1f0a9d8e7c6b5a4f3e2d1c0b0a99887766n
const validUntil = BigInt(iat + 540)
const digest = BigInt(`0x${crypto.createHash('sha256').update('tempo dev message').digest('hex')}`)

const statement = {
  addressSeed: Hashing.addressSeed({ aud, salt, sub }),
  issuer: Hashing.issuer(iss),
  keyHash: Hashing.keyHash(key.modulus),
}

async function prove(commitA: bigint, commitB: bigint) {
  const blinding = BigInt(`0x${crypto.randomBytes(31).toString('hex')}`)
  const nonce = Hashing.nonce({ blinding, commitA, commitB })
  const payload = Tokens.google({ aud, exp: iat + 3_600, iat, iss, nonce, sub })
  const token = Tokens.sign({ key, payload })
  const inputs = Inputs.build({ blinding, commitA, commitB, modulus: key.modulus, salt, token })
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasm!, zkey!)
  if (!(await snarkjs.groth16.verify(verificationKey, publicSignals, proof)))
    throw new Error('snarkjs rejected its own proof')

  const publicInput = Hashing.publicInput({ ...statement, commitA, commitB, issuedAt: BigInt(iat) })
  if (BigInt(publicSignals[0]!) !== publicInput) throw new Error('public input mismatch')
  return { proof: hex(Encoding.proof(proof)), publicInput: word(publicInput) }
}

const signature = await prove(accessKeyId, validUntil)
const message = await prove(digest % Hashing.scalarField, Hashing.messageTag)

const shared = {
  addressSeed: word(statement.addressSeed),
  issuedAt: iat,
  issuer: word(statement.issuer),
  keyHash: word(statement.keyHash),
}
const vectors = {
  verifyingKey: hex(Encoding.verifyingKey(verificationKey)),
  signature: {
    ...shared,
    accessKeyId: hex(Hashing.bigintToBytes(accessKeyId, 20)),
    validUntil: Number(validUntil),
    ...signature,
  },
  message: { ...shared, digest: word(digest), ...message },
}
fs.writeFileSync(out, `${JSON.stringify(vectors, null, 2)}\n`)

const { curve_bn128 } = globalThis as { curve_bn128?: { terminate(): Promise<void> } | null }
await curve_bn128?.terminate()

function word(value: bigint): string {
  return hex(Hashing.bigintToBytes(value, 32))
}

function hex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes).toString('hex')}`
}
