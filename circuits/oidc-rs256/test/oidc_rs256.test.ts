import * as assert from 'node:assert/strict'
import * as crypto from 'node:crypto'
import * as path from 'node:path'
import { after, before, describe, test } from 'node:test'
import * as Hashing from '../src/hashing.ts'
import * as Inputs from '../src/inputs.ts'
import * as Harness from './harness.ts'
import * as Tokens from './tokens.ts'

const iat = 1_760_000_000
const exp = iat + 3_600
const accessKey = 0x6e4b2c1f0a9d8e7c6b5a4f3e2d1c0b0a99887766n
const validUntil = BigInt(iat + 540)
const salt = 0x1d2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60n
const blinding = 0x2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091n
const aud = '1234567890-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com'
const sub = '110169484474386276334'

let circuit: Harness.Circuit
const key = Tokens.generateKey()

before(async () => {
  circuit = await Harness.compile(path.join(Harness.root, 'circuits', 'main.circom'))
})
after(Harness.terminate)

describe('OidcRs256', () => {
  describe('accepts', () => {
    for (const [name, layout, iss] of [
      ['Google', Tokens.google, 'https://accounts.google.com'],
      ['Google without https://', Tokens.google, 'accounts.google.com'],
      ['Apple', Tokens.apple, 'https://appleid.apple.com'],
      [
        'Microsoft',
        Tokens.microsoft,
        'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
      ],
    ] as const) {
      test(`${name} in the signature form`, async () => {
        const proof = signatureForm()
        const token = Tokens.sign({ key, payload: layout({ ...proof.claims, iss }) })
        const output = await publicOutput({ ...proof, token })
        assert.equal(output, expected({ ...proof, iss }))
      })
    }

    test('the message form', async () => {
      const commitA = BigInt(`0x${crypto.randomBytes(32).toString('hex')}`) % Hashing.scalarField
      const commitB = Hashing.messageTag
      const nonce = Hashing.nonce({ blinding, commitA, commitB })
      const claims = { aud, exp, iat, nonce, sub }
      const token = Tokens.sign({ key, payload: Tokens.google(claims) })
      const output = await publicOutput({ commitA, commitB, token })
      assert.equal(
        output,
        expected({ claims, commitA, commitB, iss: 'https://accounts.google.com' }),
      )
    })

    test('the same issuer with and without https://', () => {
      assert.equal(
        Hashing.issuer('https://accounts.google.com'),
        Hashing.issuer('accounts.google.com'),
      )
    })

    test('a witness satisfying every R1CS constraint', async () => {
      const proof = signatureForm()
      const token = Tokens.sign({ key, payload: Tokens.google(proof.claims) })
      const witness = await circuit.witness(inputs({ ...proof, token }))
      assert.ok(await circuit.check(witness))
    })

    for (const [name, iss] of [
      ['a normalized iss of 128 bytes', `https://${'a'.repeat(128)}`],
      ['an iss of 128 bytes without https://', 'a'.repeat(128)],
    ] as const) {
      test(name, async () => {
        const proof = signatureForm()
        const token = Tokens.sign({ key, payload: Tokens.google({ ...proof.claims, iss }) })
        assert.equal(await publicOutput({ ...proof, token }), expected({ ...proof, iss }))
      })
    }

    test('an aud of 128 bytes and a sub of 64 bytes', async () => {
      const proof = signatureForm()
      const claims = { ...proof.claims, aud: 'a'.repeat(128), sub: '1'.repeat(64) }
      const token = Tokens.sign({ key, payload: Tokens.apple(claims) })
      assert.equal(
        await publicOutput({ ...proof, token }),
        expected({ ...proof, claims, iss: 'https://appleid.apple.com' }),
      )
    })

    test('a signed input of 1,024 bytes', async () => {
      const proof = signatureForm()
      const token = filled({ claims: proof.claims, length: 1024 })
      assert.equal(token.split('.').slice(0, 2).join('.').length, 1024)
      assert.equal(
        await publicOutput({ ...proof, token }),
        expected({ ...proof, iss: 'https://accounts.google.com' }),
      )
    })

    test('a payload filling the signed input after a short header', async () => {
      const proof = signatureForm()
      const token = filled({ claims: proof.claims, header: '{}', length: 1024 })
      assert.equal(
        await publicOutput({ ...proof, token }),
        expected({ ...proof, iss: 'https://accounts.google.com' }),
      )
    })
  })

  describe('rejects', () => {
    const iss = 'https://accounts.google.com'

    /** Signs a Google token whose payload text is rewritten by `edit`. */
    function edited(edit: (payload: string) => string): { proof: Proof; token: string } {
      const proof = signatureForm()
      const payload = edit(Tokens.google(proof.claims))
      return { proof, token: Tokens.sign({ key, payload }) }
    }

    test('a duplicate top-level member', async () => {
      const { proof, token } = edited((p) => p.replace('"sub":', '"sub":"0","sub":'))
      await rejectsIn(publicOutput({ ...proof, token }), 'TopLevelMember')
    })

    test('a required member only inside a nested object', async () => {
      const { proof, token } = edited((p) => p.replace(`"sub":"${sub}"`, `"x":{"sub":"${sub}"}`))
      await rejectsIn(publicOutput({ ...proof, token }), 'TopLevelMember')
    })

    test('a member name only inside a string', async () => {
      const { proof, token } = edited((p) =>
        p.replace(`"sub":"${sub}"`, `"x":"\\",\\"sub\\":\\"${sub}"`),
      )
      await rejectsIn(publicOutput({ ...proof, token }), 'TopLevelMember')
    })

    test('an escaped value', async () => {
      const { proof, token } = edited((p) => p.replace(`"sub":"${sub}"`, `"sub":"${sub}\\u0031"`))
      await rejectsIn(publicOutput({ ...proof, token }), 'StringValue')
    })

    test('an escaped member name', async () => {
      const { proof, token } = edited((p) => p.replace('"email":', '"\\u0065mail":'))
      await rejectsIn(publicOutput({ ...proof, token }), 'JsonObject')
    })

    test('whitespace outside strings', async () => {
      const { proof, token } = edited((p) => p.replace('"sub":', '"sub": '))
      await rejectsIn(publicOutput({ ...proof, token }), 'JsonObject')
    })

    test('an array aud', async () => {
      const { proof, token } = edited((p) => p.replace(`"aud":"${aud}"`, `"aud":["${aud}"]`))
      await rejectsIn(publicOutput({ ...proof, token }), 'StringValue')
    })

    test('a missing exp', async () => {
      const { proof, token } = edited((p) => p.replace(`,"exp":${exp}`, ''))
      await rejectsIn(publicOutput({ ...proof, token }), 'TopLevelMember')
    })

    test('a string exp', async () => {
      const { proof, token } = edited((p) => p.replace(`"exp":${exp}`, `"exp":"${exp}"`))
      await rejectsIn(publicOutput({ ...proof, token }), 'Num2Bits')
    })

    test('an iat of 11 digits', async () => {
      const { proof, token } = edited((p) => p.replace(`"iat":${iat}`, `"iat":1${iat}`))
      await rejectsIn(publicOutput({ ...proof, token }), 'PrefixMask')
    })

    test('valid_until after exp', async () => {
      const commitB = BigInt(exp + 1)
      const nonce = Hashing.nonce({ blinding, commitA: accessKey, commitB })
      const token = Tokens.sign({ key, payload: Tokens.google({ aud, exp, iat, nonce, sub }) })
      await rejectsIn(publicOutput({ commitA: accessKey, commitB, token }), 'OidcRs256')
    })

    test('a different iat', async () => {
      const proof = signatureForm()
      const token = Tokens.sign({ key, payload: Tokens.google(proof.claims) })
      const claims = { ...proof.claims, iat: iat + 1 }
      assert.notEqual(await publicOutput({ ...proof, token }), expected({ ...proof, claims, iss }))
    })

    test('a nonce for another access key', async () => {
      const proof = signatureForm()
      const token = Tokens.sign({ key, payload: Tokens.google(proof.claims) })
      await rejectsIn(publicOutput({ ...proof, commitA: accessKey + 1n, token }), 'OidcRs256')
    })

    test('a token for one form proved as the other', async () => {
      const proof = signatureForm()
      const token = Tokens.sign({ key, payload: Tokens.google(proof.claims) })
      await rejectsIn(publicOutput({ ...proof, commitB: Hashing.messageTag, token }), 'OidcRs256')
    })

    test('commitments out of range in the signature form', async () => {
      for (const [commitA, commitB] of [
        [1n << 160n, validUntil],
        [accessKey, (1n << 64n) + 1n],
      ] as const) {
        const nonce = Hashing.nonce({ blinding, commitA, commitB })
        const token = Tokens.sign({ key, payload: Tokens.google({ aud, exp, iat, nonce, sub }) })
        await rejectsIn(publicOutput({ commitA, commitB, token }), 'Num2Bits')
      }
    })

    test('a modulus that does not match key_hash', async () => {
      const proof = signatureForm()
      const token = Tokens.sign({ key, payload: Tokens.google(proof.claims) })
      const other = Tokens.generateKey()
      // s >= n' fails the bound first; otherwise the final multiplication fails.
      await rejectsIn(
        publicOutput({ ...proof, modulus: other.modulus, token }),
        'OidcRs256',
        ...finalMultiplication,
      )
      assert.notEqual(
        await publicOutput({ ...proof, token }),
        Hashing.publicInput({
          addressSeed: Hashing.addressSeed({ aud, salt, sub }),
          commitA: accessKey,
          commitB: validUntil,
          issuedAt: BigInt(iat),
          issuer: Hashing.issuer(iss),
          keyHash: Hashing.keyHash(other.modulus),
        }),
      )
    })

    test('a tampered signature', async () => {
      const proof = signatureForm()
      const [header, payload, signature] = Tokens.sign({
        key,
        payload: Tokens.google(proof.claims),
      }).split('.')
      const bytes = Buffer.from(signature!, 'base64url')
      bytes[100]! ^= 1
      const token = `${header}.${payload}.${bytes.toString('base64url')}`
      await rejectsIn(publicOutput({ ...proof, token }), ...finalMultiplication)
    })

    test('s >= n', async () => {
      const proof = signatureForm()
      const token = Tokens.sign({ key, payload: Tokens.google(proof.claims) })
      const signature = Hashing.bytesToBigint(Buffer.from(token.split('.')[2]!, 'base64url'))
      const values = inputs({ ...proof, token })
      const unreduced = signature + key.modulus
      const { quotients, remainders } = Inputs.rsaHints({
        modulus: key.modulus,
        signature: unreduced,
      })
      await assert.rejects(
        circuit.witness({
          ...values,
          rsaQuotient: quotients.map(Inputs.limbs),
          rsaRemainder: remainders.map(Inputs.limbs),
          signature: Inputs.limbs(unreduced),
        }),
      )
    })

    test('a 2047-bit modulus', async () => {
      const short = Tokens.generateKey(2047)
      const proof = signatureForm()
      const token = Tokens.sign({ key: short, payload: Tokens.google(proof.claims) })
      await rejectsIn(publicOutput({ ...proof, modulus: short.modulus, token }), 'OidcRs256')
    })

    test('nonzero bytes after L', async () => {
      const proof = signatureForm()
      const token = Tokens.sign({ key, payload: Tokens.google(proof.claims) })
      const values = inputs({ ...proof, token })
      values.signedInput[Number(values.signedInputLen)] = '65'
      await rejectsIn(circuit.witness(values), 'Sha256Bytes')
    })

    test('two dots', async () => {
      const { header, payload, proof } = encoded()
      const signedInput = `${header}.${payload.slice(0, 8)}.${payload.slice(8)}`
      const token = Tokens.signRaw({ key, signedInput })
      await rejectsIn(publicOutput({ ...proof, token }), 'OidcRs256')
    })

    test('a byte outside the base64url alphabet', async () => {
      const { header, payload, proof } = encoded()
      const padding = '='.repeat((4 - (payload.length % 4)) % 4) || '=='
      const token = Tokens.signRaw({ key, signedInput: `${header}.${payload}${padding}` })
      await rejectsIn(publicOutput({ ...proof, token }), 'OidcRs256')
    })

    test('a payload length of 1 mod 4', async () => {
      const { header, payload, proof } = encoded()
      const extra = 'A'.repeat((((1 - payload.length) % 4) + 4) % 4 || 4)
      const signedInput = `${header}.${payload}${extra}`
      assert.equal((signedInput.length - header.length - 1) % 4, 1)
      const token = Tokens.signRaw({ key, signedInput })
      await rejectsIn(publicOutput({ ...proof, token }), 'OidcRs256')
    })

    for (const [name, field, value, template] of [
      ['a normalized iss of 129 bytes', 'iss', `https://${'a'.repeat(129)}`, 'PrefixMask'],
      ['an iss of 129 bytes without https://', 'iss', 'a'.repeat(129), 'Num2Bits'],
      ['an aud of 129 bytes', 'aud', 'a'.repeat(129), 'PrefixMask'],
      ['a sub of 65 bytes', 'sub', '1'.repeat(65), 'PrefixMask'],
      ['a nonce of 44 bytes', 'nonce', `${signatureForm().claims.nonce}A`, 'OidcRs256'],
    ] as const) {
      test(name, async () => {
        const proof = signatureForm()
        const claims = { ...proof.claims, [field]: value }
        const token = Tokens.sign({ key, payload: Tokens.apple(claims) })
        await rejectsIn(publicOutput({ ...proof, token }), template)
      })
    }

    test('a signed input over 1,024 bytes', () => {
      const proof = signatureForm()
      const token = filled({ claims: proof.claims, length: 1025 })
      assert.throws(() => inputs({ ...proof, token }), /signed input is 1025 bytes/)
    })
  })
})

type Proof = {
  claims: Tokens.Claims
  commitA: bigint
  commitB: bigint
}

/** The encoded header and payload of a Google token in the signature form. */
function encoded(): { header: string; payload: string; proof: Proof } {
  const proof = signatureForm()
  const [header, payload] = Tokens.sign({ key, payload: Tokens.google(proof.claims) }).split('.')
  return { header: header!, payload: payload!, proof }
}

/** Claims and commitments for an access key in the signature form. */
function signatureForm(): Proof {
  const nonce = Hashing.nonce({ blinding, commitA: accessKey, commitB: validUntil })
  return { claims: { aud, exp, iat, nonce, sub }, commitA: accessKey, commitB: validUntil }
}

type Statement = {
  commitA: bigint
  commitB: bigint
  modulus?: bigint | undefined
  token: string
}

/** Builds circuit inputs for a token. */
function inputs(options: Statement): Inputs.Inputs {
  const { commitA, commitB, token } = options
  return Inputs.build({
    blinding,
    commitA,
    commitB,
    modulus: options.modulus ?? key.modulus,
    salt,
    token,
  })
}

/** Runs the circuit on a token and returns public_input. */
async function publicOutput(options: Statement): Promise<bigint> {
  const witness = await circuit.witness(inputs(options))
  return circuit.outputs(witness)[0]!
}

/** Failure traces of s^65537 mod n differing from the encoded digest. */
const finalMultiplication = [
  ['Num2Bits', 'CarryToZero', 'ModMulCheck'],
  ['CarryToZero', 'ModMulCheck'],
] as const

/**
 * Expects a witness failure whose template trace, from the innermost template outward, starts
 * with one of `traces`. A string names the innermost template alone.
 */
async function rejectsIn(
  promise: Promise<unknown>,
  ...traces: readonly (string | readonly string[])[]
) {
  await assert.rejects(promise, (error: Error) => {
    const templates = [...error.message.matchAll(/Error in template (\w+?)_\d+ line/g)].map(
      (match) => match[1],
    )
    const matches = traces.some((trace) =>
      [trace].flat().every((template, i) => templates[i] === template),
    )
    assert.ok(matches, error.message)
    return true
  })
}

/** Signs a Google token padded with a filler claim to `length` signed bytes. */
function filled(options: { claims: Tokens.Claims; header?: string; length: number }): string {
  const { claims, length } = options
  for (let kid = 0; kid < 4; kid++) {
    const header = options.header ?? `{"alg":"RS256","kid":"${'k'.repeat(kid + 1)}","typ":"JWT"}`
    for (let filler = 0; filler < 1024; filler++) {
      const payload = Tokens.google(claims).replace('{', `{"x":"${'x'.repeat(filler)}",`)
      const token = Tokens.sign({ header, key, payload })
      const signed = token.split('.').slice(0, 2).join('.').length
      if (signed === length) return token
      if (signed > length) break
    }
  }
  throw new Error(`no filler reaches ${length} signed bytes`)
}

/** The public input nodes compute for the same statement. */
function expected(options: Proof & { iss: string }): bigint {
  const { claims, commitA, commitB, iss } = options
  return Hashing.publicInput({
    addressSeed: Hashing.addressSeed({ aud: claims.aud, salt, sub: claims.sub }),
    commitA,
    commitB,
    issuedAt: BigInt(claims.iat),
    issuer: Hashing.issuer(iss),
    keyHash: Hashing.keyHash(key.modulus),
  })
}
