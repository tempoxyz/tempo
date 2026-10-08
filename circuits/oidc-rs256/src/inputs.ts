// Builds the OIDC RS256 v1 circuit's private inputs from an ID token.

import * as Hashing from './hashing.ts'

/** Limits and limb layout fixed by the circuit. */
export const limits = {
  /** Bits per RSA limb. */
  limbBits: 121,
  /** RSA limbs per 2048-bit value. */
  limbs: 17,
  /** Longest `base64url(header) || "." || base64url(payload)`. */
  maxSignedInputLen: 1024,
} as const

/** Circuit inputs, as decimal strings. */
export type Inputs = {
  audLen: string
  blinding: string
  commitA: string
  commitB: string
  expLen: string
  iatLen: string
  issLen: string
  modulus: string[]
  rsaQuotient: string[][]
  rsaRemainder: string[][]
  salt: string
  signature: string[]
  signedInput: string[]
  signedInputLen: string
  subLen: string
}

/**
 * Builds circuit inputs for a compact JWS token. Hints follow the token as written, so a token
 * the circuit rejects still produces inputs.
 */
export function build(options: build.Options): Inputs {
  const { blinding, commitA, commitB, modulus, salt, token } = options
  // The signature follows the last dot and the payload the first, so malformed signed inputs
  // still produce inputs.
  const end = token.lastIndexOf('.')
  const start = token.indexOf('.')
  if (start < 0 || start === end) throw new Error('token is not a compact JWS')
  const payload = token.slice(start + 1, end)
  const signature = token.slice(end + 1)

  const signedInput = new TextEncoder().encode(token.slice(0, end))
  if (signedInput.length > limits.maxSignedInputLen)
    throw new Error(`signed input is ${signedInput.length} bytes`)
  const padded = new Uint8Array(limits.maxSignedInputLen)
  padded.set(signedInput)

  const s = Hashing.bytesToBigint(Buffer.from(signature, 'base64url'))
  const { quotients, remainders } = rsaHints({ modulus, signature: s })

  const members = topLevelMembers(Buffer.from(payload, 'base64url'))
  return {
    audLen: String(members.aud?.length ?? 0),
    blinding: blinding.toString(),
    commitA: commitA.toString(),
    commitB: commitB.toString(),
    expLen: String(members.exp?.length ?? 0),
    iatLen: String(members.iat?.length ?? 0),
    issLen: String(members.iss?.length ?? 0),
    modulus: limbs(modulus),
    rsaQuotient: quotients.map(limbs),
    rsaRemainder: remainders.map(limbs),
    salt: salt.toString(),
    signature: limbs(s),
    signedInput: [...padded].map(String),
    signedInputLen: String(signedInput.length),
    subLen: String(members.sub?.length ?? 0),
  }
}

export declare namespace build {
  type Options = {
    /** A random field element chosen by the wallet. */
    blinding: bigint
    /** `access_key_id`, or the message digest reduced into the field. */
    commitA: bigint
    /** `valid_until`, or `Hashing.messageTag`. */
    commitB: bigint
    /** The RSA modulus of the key that signed the token. */
    modulus: bigint
    /** The salt from the salt service. */
    salt: bigint
    /** The compact JWS ID token. */
    token: string
  }
}

/** Splits `value` into 121-bit limbs, least significant first. */
export function limbs(value: bigint): string[] {
  const mask = (1n << BigInt(limits.limbBits)) - 1n
  return Array.from({ length: limits.limbs }, (_, i) =>
    ((value >> BigInt(i * limits.limbBits)) & mask).toString(),
  )
}

/** Quotients and remainders of the 16 squarings and the final multiplication of `s^65537 mod n`. */
export function rsaHints(options: rsaHints.Options): rsaHints.Hints {
  const { modulus, signature } = options
  const quotients: bigint[] = []
  const remainders: bigint[] = []
  let x = signature
  for (let i = 0; i < 16; i++) {
    quotients.push((x * x) / modulus)
    x = (x * x) % modulus
    remainders.push(x)
  }
  quotients.push((x * signature) / modulus)
  return { quotients, remainders }
}

export declare namespace rsaHints {
  type Options = {
    modulus: bigint
    signature: bigint
  }
  type Hints = {
    quotients: bigint[]
    remainders: bigint[]
  }
}

type Member = {
  /** Raw length: string bytes between the quotes, or leading digits. */
  length: number
  /** Index of the value's first byte. */
  offset: number
}

/** Finds the first top-level `iss`, `aud`, `sub`, `nonce`, `iat`, and `exp` members as written. */
export function topLevelMembers(payload: Uint8Array): Partial<Record<string, Member>> {
  const members: Partial<Record<string, Member>> = {}
  let depth = 0
  let inString = false
  let escaped = false
  let nameStart = -1
  for (let i = 0; i < payload.length; i++) {
    const byte = payload[i]!
    if (inString) {
      if (escaped) escaped = false
      else if (byte === 0x5c) escaped = true
      else if (byte === 0x22) {
        inString = false
        if (nameStart >= 0 && payload[i + 1] === 0x3a) {
          const name = new TextDecoder().decode(payload.subarray(nameStart + 1, i))
          if (!(name in members)) members[name] = value(payload, i + 2)
        }
        nameStart = -1
      }
      continue
    }
    if (byte === 0x22) {
      inString = true
      const previous = payload[i - 1]
      if (depth === 1 && (previous === 0x7b || previous === 0x2c)) nameStart = i
    } else if (byte === 0x7b || byte === 0x5b) depth++
    else if (byte === 0x7d || byte === 0x5d) depth--
  }
  return members
}

function value(payload: Uint8Array, offset: number): Member {
  if (payload[offset] === 0x22) {
    let end = offset + 1
    while (end < payload.length && payload[end] !== 0x22) end += payload[end] === 0x5c ? 2 : 1
    return { length: end - offset - 1, offset }
  }
  let end = offset
  while (end < payload.length && payload[end]! >= 0x30 && payload[end]! <= 0x39) end++
  return { length: end - offset, offset }
}
