// Converts snarkjs Groth16 output into the TIP-1131 point encoding: EIP-197 uncompressed points
// with 32-byte big-endian coordinates and F_p^2 elements written (c1, c0).

import * as Hashing from './hashing.ts'

/** An affine G1 point as snarkjs writes it: `[x, y, "1"]`. */
export type G1 = readonly [x: string, y: string, z: string]

/** An affine G2 point as snarkjs writes it: `[[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]`. */
export type G2 = readonly [
  x: readonly [string, string],
  y: readonly [string, string],
  z: readonly [string, string],
]

/** A snarkjs Groth16 proof. */
export type Proof = {
  pi_a: G1
  pi_b: G2
  pi_c: G1
}

/** A snarkjs Groth16 verifying key. */
export type VerifyingKey = {
  IC: readonly G1[]
  nPublic: number
  vk_alpha_1: G1
  vk_beta_2: G2
  vk_delta_2: G2
  vk_gamma_2: G2
}

/** Encodes a proof as `A || B || C`, 256 bytes. */
export function proof(value: Proof): Uint8Array {
  return concat([g1(value.pi_a), g2(value.pi_b), g1(value.pi_c)])
}

/**
 * Encodes a verifying key with one public input as
 * `alpha || beta || gamma || delta || IC[0] || IC[1]`, 576 bytes.
 */
export function verifyingKey(value: VerifyingKey): Uint8Array {
  if (value.nPublic !== 1 || value.IC.length !== 2)
    throw new Error(`expected one public input, got ${value.nPublic}`)
  return concat([
    g1(value.vk_alpha_1),
    g2(value.vk_beta_2),
    g2(value.vk_gamma_2),
    g2(value.vk_delta_2),
    g1(value.IC[0]!),
    g1(value.IC[1]!),
  ])
}

function g1(point: G1): Uint8Array {
  if (point[2] !== '1') throw new Error('G1 point is not affine')
  return concat([coordinate(point[0]), coordinate(point[1])])
}

function g2(point: G2): Uint8Array {
  if (point[2][0] !== '1' || point[2][1] !== '0') throw new Error('G2 point is not affine')
  const [x, y] = point
  return concat([coordinate(x[1]), coordinate(x[0]), coordinate(y[1]), coordinate(y[0])])
}

function coordinate(value: string): Uint8Array {
  return Hashing.bigintToBytes(BigInt(value), 32)
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}
