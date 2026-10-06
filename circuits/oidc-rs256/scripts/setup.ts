// Runs a development Groth16 setup: a fixed beacon over a Powers of Tau transcript, so anyone can
// rebuild the same key. Its trapdoor is public, so the key is for tests only; TIP-1133 defines the
// production ceremony.
//
// Usage: node scripts/setup.ts <r1cs> <ptau> <out-dir>

import * as fs from 'node:fs'
import * as path from 'node:path'
import * as snarkjs from 'snarkjs'

const [r1cs, ptau, out] = process.argv.slice(2)
if (!r1cs || !ptau || !out) throw new Error('usage: node scripts/setup.ts <r1cs> <ptau> <out-dir>')

const logger = {
  debug() {},
  error: console.error,
  info: console.log,
  warn: console.warn,
}

fs.mkdirSync(out, { recursive: true })
const initial = path.join(out, 'oidc_rs256_0000.zkey')
const final = path.join(out, 'oidc_rs256.zkey')

await snarkjs.zKey.newZKey(r1cs, ptau, initial, logger)
// A fixed beacon, standing in for the announced randomness of a real ceremony.
await snarkjs.zKey.beacon(
  initial,
  final,
  'development beacon',
  '0000000000000000000000000000000000000000000000000000000000001133',
  10,
  logger,
)
fs.rmSync(initial)

const verificationKey = await snarkjs.zKey.exportVerificationKey(final, logger)
fs.writeFileSync(path.join(out, 'verification_key.json'), JSON.stringify(verificationKey, null, 2))

const { curve_bn128 } = globalThis as { curve_bn128?: { terminate(): Promise<void> } | null }
await curve_bn128?.terminate()
