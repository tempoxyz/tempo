// Test RSA keys and ID tokens in provider-like layouts.

import * as crypto from 'node:crypto'

export type Key = {
  modulus: bigint
  privateKey: crypto.KeyObject
}

/** Generates an RSA key with exponent 65537. */
export function generateKey(bits = 2048): Key {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicExponent: 65537,
  })
  const { n } = publicKey.export({ format: 'jwk' })
  return { modulus: BigInt(`0x${Buffer.from(n!, 'base64url').toString('hex')}`), privateKey }
}

/** The default protected header. */
export const header = '{"alg":"RS256","kid":"8e8fc8e556f7a76d08d35829d6f90ae2e12cfd0d","typ":"JWT"}'

/** Signs `signedInput` as written, so tests can sign malformed tokens. */
export function signRaw(options: signRaw.Options): string {
  const { key, signedInput } = options
  const signature = crypto.sign('sha256', Buffer.from(signedInput), key.privateKey)
  return `${signedInput}.${signature.toString('base64url')}`
}

export declare namespace signRaw {
  type Options = {
    key: Key
    signedInput: string
  }
}

/** Encodes and signs a header and payload, both given as raw JSON text. */
export function sign(options: sign.Options): string {
  const { key, payload } = options
  const encode = (text: string) => Buffer.from(text).toString('base64url')
  return signRaw({ key, signedInput: `${encode(options.header ?? header)}.${encode(payload)}` })
}

export declare namespace sign {
  type Options = {
    header?: string | undefined
    key: Key
    payload: string
  }
}

export type Claims = {
  aud: string
  exp: number
  iat: number
  iss?: string | undefined
  nonce: string
  sub: string
}

/** A Google ID token payload for the openid and email scopes. */
export function google(claims: Claims): string {
  const { aud, exp, iat, nonce, sub } = claims
  return JSON.stringify({
    iss: claims.iss ?? 'https://accounts.google.com',
    azp: aud,
    aud,
    sub,
    email: 'test.user@gmail.com',
    email_verified: true,
    at_hash: 'NnHZ8WqhVHYWv2DJ3eLEbg',
    nonce,
    iat,
    exp,
  })
}

/** An Apple ID token payload. */
export function apple(claims: Claims): string {
  const { aud, exp, iat, nonce, sub } = claims
  return JSON.stringify({
    iss: claims.iss ?? 'https://appleid.apple.com',
    aud,
    exp,
    iat,
    sub,
    nonce,
    c_hash: 'T2dGUuBDdqBKXGtCdYRtMQ',
    email: 'q2x8f7k9pz@privaterelay.appleid.com',
    email_verified: true,
    is_private_email: true,
    auth_time: iat,
    nonce_supported: true,
  })
}

/** A Microsoft identity platform v2.0 ID token payload. */
export function microsoft(claims: Claims): string {
  const { aud, exp, iat, nonce, sub } = claims
  return JSON.stringify({
    aud,
    iss:
      claims.iss ?? 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
    iat,
    nbf: iat,
    exp,
    aio: 'Df2UVXL1ix!lMCWMSOJBcFatzcGfvFGhjKv8q5g0x732dR5MB5BisvGQO7YWByjd8iQDLq!eGbIDakyp5mnOrcdq',
    name: 'Test User',
    nonce,
    oid: '00000000-0000-0000-66f3-3332eca7ea81',
    preferred_username: 'test.user@outlook.com',
    rh: '0.AXEA0tBs-jNQ_k2r1D0SNyMmYQIAAAAAAPEPzgAAAAAAAADCAAA.',
    sub,
    tid: '9188040d-6c67-4c5b-b112-36a304b66dad',
    uti: 'CRRq0tD3gUipWa3W5C9yAA',
    ver: '2.0',
  })
}
