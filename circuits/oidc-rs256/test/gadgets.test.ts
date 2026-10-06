import * as assert from 'node:assert/strict'
import * as crypto from 'node:crypto'
import * as path from 'node:path'
import { after, before, describe, test } from 'node:test'
import * as Harness from './harness.ts'

const circuits = path.join(Harness.root, 'test', 'circuits')

after(Harness.terminate)

describe('Base64UrlChar and JsonChar', () => {
  let circuit: Harness.Circuit
  before(async () => {
    circuit = await Harness.compile(path.join(circuits, 'chars.circom'))
  })

  test('classify every byte', async () => {
    const bytes = Array.from({ length: 256 }, (_, i) => i)
    const witness = await circuit.witness({ bytes })
    const outputs = circuit.outputs(witness)
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    for (const byte of bytes) {
      const char = String.fromCharCode(byte)
      const index = alphabet.indexOf(char)
      assert.equal(outputs[byte], index >= 0 ? 1n : 0n, `base64 valid ${byte}`)
      assert.equal(outputs[256 + byte], BigInt(Math.max(index, 0)), `base64 value ${byte}`)

      const json = outputs.slice(512 + 9 * byte, 512 + 9 * byte + 9)
      const allowed = /^[{}[\],:"0-9A-Za-z\-+.]$/.test(char) && byte < 0x80
      const expected = [
        char === '"',
        char === '\\',
        char === '{',
        char === '}',
        char === '[',
        char === ']',
        char === ',',
        allowed,
        byte >= 0x20,
      ].map((flag) => (flag ? 1n : 0n))
      assert.deepEqual(json, expected, `json classes ${byte}`)
    }
  })
})

describe('ShiftLeft and PrefixMask', () => {
  let circuit: Harness.Circuit
  before(async () => {
    circuit = await Harness.compile(path.join(circuits, 'array.circom'))
  })

  test('shift every amount and mask every length', async () => {
    const values = Array.from({ length: 40 }, (_, i) => BigInt(1000 + i))
    for (let shift = 0; shift < 64; shift++) {
      const len = shift % 13
      const witness = await circuit.witness({ in: values, len, shift })
      const outputs = circuit.outputs(witness)
      const expected = Array.from({ length: 9 }, (_, k) => values[k + shift] ?? 0n)
      assert.deepEqual(outputs.slice(0, 9), expected)
      assert.deepEqual(
        outputs.slice(9),
        Array.from({ length: 12 }, (_, i) => (i < len ? 1n : 0n)),
      )
    }
  })

  test('reject a mask longer than its array', async () => {
    const values = Array.from({ length: 40 }, () => 0n)
    await assert.rejects(circuit.witness({ in: values, len: 13, shift: 0 }))
  })

  test('reject a shift out of range', async () => {
    const values = Array.from({ length: 40 }, () => 0n)
    await assert.rejects(circuit.witness({ in: values, len: 0, shift: 64 }))
  })
})

describe('ModMulCheck, ModSquareCheck, and BigLessThan', () => {
  let circuit: Harness.Circuit
  before(async () => {
    circuit = await Harness.compile(path.join(circuits, 'bigint.circom'))
  })

  function inputs(a: bigint, b: bigint, m: bigint) {
    return {
      a: limbs(a),
      b: limbs(b),
      m: limbs(m),
      q: limbs((a * b) / m),
      r: limbs((a * b) % m),
      sq: limbs((a * a) / m),
      sr: limbs((a * a) % m),
    }
  }

  test('accept products of random values', async () => {
    for (let i = 0; i < 8; i++) {
      const m = random(2048) | (1n << 2047n)
      const a = random(2048) % m
      const b = random(2048) % m
      const witness = await circuit.witness(inputs(a, b, m))
      assert.equal(circuit.outputs(witness)[0], a < b ? 1n : 0n)
      assert.ok(await circuit.check(witness))
    }
  })

  test('accept extreme values', async () => {
    const m = (1n << 2048n) - 1n
    for (const [a, b] of [
      [m - 1n, m - 1n],
      [0n, m - 1n],
      [m - 1n, 0n],
      [1n, 1n],
    ] as const) {
      const witness = await circuit.witness(inputs(a, b, m))
      assert.equal(circuit.outputs(witness)[0], a < b ? 1n : 0n)
    }
  })

  test('reject a wrong remainder or quotient', async () => {
    const m = random(2048) | (1n << 2047n)
    const a = random(2048) % m
    const b = random(2048) % m
    const valid = inputs(a, b, m)
    await assert.rejects(circuit.witness({ ...valid, r: limbs((a * b + 1n) % m) }))
    await assert.rejects(circuit.witness({ ...valid, q: limbs((a * b) / m + 1n) }))
    await assert.rejects(circuit.witness({ ...valid, sr: limbs((a * a + 1n) % m) }))
  })

  test('accept an unreduced remainder', async () => {
    // The checks prove integer identities only; the RSA chain needs congruence, not reduction.
    const m = random(2048) | (1n << 2047n)
    const a = random(2048) % m
    const b = random(2048) % m
    const witness = await circuit.witness({
      ...inputs(a, b, m),
      q: limbs((a * b) / m - 1n),
      r: limbs(((a * b) % m) + m),
    })
    assert.ok(await circuit.check(witness))
  })
})

describe('Sha256Bytes', () => {
  let circuit: Harness.Circuit
  before(async () => {
    circuit = await Harness.compile(path.join(circuits, 'sha256.circom'))
  })

  test('match SHA-256 at block boundaries', async () => {
    const message = crypto.randomBytes(200)
    for (const len of [
      0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 183, 184, 199, 200,
    ]) {
      const input = new Uint8Array(200)
      input.set(message.subarray(0, len))
      const witness = await circuit.witness({ in: [...input], len })
      const digest = crypto.createHash('sha256').update(message.subarray(0, len)).digest()
      const bits = [...digest].flatMap((byte) =>
        Array.from({ length: 8 }, (_, u) => BigInt((byte >> (7 - u)) & 1)),
      )
      assert.deepEqual(circuit.outputs(witness), bits, `length ${len}`)
    }
  })

  test('reject nonzero bytes past the length', async () => {
    const input = new Uint8Array(200)
    input[10] = 1
    await assert.rejects(circuit.witness({ in: [...input], len: 10 }))
  })

  test('reject a length past the maximum', async () => {
    await assert.rejects(circuit.witness({ in: [...new Uint8Array(200)], len: 201 }))
  })
})

function limbs(value: bigint): bigint[] {
  return Array.from({ length: 17 }, (_, i) => (value >> BigInt(121 * i)) & ((1n << 121n) - 1n))
}

function random(bits: number): bigint {
  return BigInt(`0x${crypto.randomBytes(bits / 8).toString('hex')}`)
}
