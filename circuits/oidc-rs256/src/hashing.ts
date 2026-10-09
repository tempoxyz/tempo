// TIP-1133 hashing rules, shared by the circuit's tests, wallets, and publishers.

import {
  poseidon1,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
} from 'poseidon-lite'

/** Size of the BN254 scalar field. */
export const scalarField =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** `commit_b` of the message form; exceeds any `valid_until`. */
export const messageTag = 1n << 64n

/** Scheme id of the OIDC RS256 v1 circuit. */
export const scheme = 1n

/** Namespace tag of OIDC addresses. */
export const namespace = 1n

const poseidons = [
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
] as const

/** circomlib Poseidon over 1 to 16 field elements. */
export function poseidon(inputs: readonly bigint[]): bigint {
  const hash = poseidons[inputs.length - 1]
  if (!hash) throw new Error(`Poseidon takes 1 to 16 inputs, got ${inputs.length}`)
  return hash([...inputs])
}

/** `hash_bytes(b, max_len)`: the length, then 31-byte big-endian chunks of `b` zero-padded. */
export function hashBytes(bytes: Uint8Array, maxLen: number): bigint {
  if (bytes.length > maxLen) throw new Error(`${bytes.length} bytes exceed ${maxLen}`)
  const chunks: bigint[] = []
  for (let offset = 0; offset < maxLen; offset += 31) {
    let chunk = 0n
    for (let t = 0; t < 31; t++) chunk = (chunk << 8n) | BigInt(bytes[offset + t] ?? 0)
    chunks.push(chunk)
  }
  return poseidon([BigInt(bytes.length), ...chunks])
}

/** `normalize_iss`: drops one leading `https://`. */
export function normalizeIss(iss: string): string {
  return iss.startsWith('https://') ? iss.slice('https://'.length) : iss
}

/** `issuer = hash_bytes(normalize_iss(iss), 128)`. */
export function issuer(iss: string): bigint {
  return hashBytes(utf8(normalizeIss(iss)), 128)
}

/** `key_hash = hash_bytes(n as 256 big-endian bytes, 256)`. */
export function keyHash(modulus: bigint): bigint {
  return hashBytes(bigintToBytes(modulus, 256), 256)
}

/** `address_seed = Poseidon(1, hash_bytes(sub, 64), hash_bytes(aud, 128), salt)`. */
export function addressSeed(options: addressSeed.Options): bigint {
  const { aud, salt, sub } = options
  return poseidon([namespace, hashBytes(utf8(sub), 64), hashBytes(utf8(aud), 128), salt])
}

export declare namespace addressSeed {
  type Options = {
    /** The token's `aud`. */
    aud: string
    /** The salt from the salt service. */
    salt: bigint
    /** The token's `sub`. */
    sub: string
  }
}

/** `nonce = base64url(be32(Poseidon(commit_a, commit_b, blinding)))`, 43 characters. */
export function nonce(options: nonce.Options): string {
  const { blinding, commitA, commitB } = options
  const hash = poseidon([commitA, commitB, blinding])
  return Buffer.from(bigintToBytes(hash, 32)).toString('base64url')
}

export declare namespace nonce {
  type Options = {
    /** A random field element chosen by the wallet. */
    blinding: bigint
    /** `access_key_id`, or the message digest reduced into the field. */
    commitA: bigint
    /** `valid_until`, or `messageTag`. */
    commitB: bigint
  }
}

/** `public_input = Poseidon(1, issuer, key_hash, address_seed, commit_a, commit_b, issued_at)`. */
export function publicInput(options: publicInput.Options): bigint {
  const { addressSeed, commitA, commitB, issuedAt, issuer, keyHash } = options
  return poseidon([scheme, issuer, keyHash, addressSeed, commitA, commitB, issuedAt])
}

export declare namespace publicInput {
  type Options = {
    addressSeed: bigint
    commitA: bigint
    commitB: bigint
    /** The token's `iat`. */
    issuedAt: bigint
    issuer: bigint
    keyHash: bigint
  }
}

/** Encodes `value` as `length` big-endian bytes. */
export function bigintToBytes(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(8 * length))
    throw new Error(`${value} does not fit in ${length} bytes`)
  const bytes = new Uint8Array(length)
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return bytes
}

/** Decodes big-endian bytes. */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}
