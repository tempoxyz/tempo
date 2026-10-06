import { createHmac, createPublicKey, verify } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';

export const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const MESSAGE_TAG = 1n << 64n;
const poseidonReady = buildPoseidon();

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

export function field(value) {
  const result = BigInt(value);
  requireCondition(result >= 0n && result < SCALAR_FIELD, 'Non-canonical field element');
  return result;
}

export function be32(value) {
  const result = BigInt(value);
  requireCondition(result >= 0n && result < (1n << 256n), 'Value does not fit bytes32');
  return Buffer.from(result.toString(16).padStart(64, '0'), 'hex');
}

export async function poseidon(values) {
  requireCondition(values.length >= 1 && values.length <= 16, 'Invalid Poseidon arity');
  const implementation = await poseidonReady;
  return implementation.F.toObject(implementation(values.map(field)));
}

export async function hashBytes(input, maxLength) {
  const bytes = Buffer.from(input);
  requireCondition([64, 128, 256].includes(maxLength), 'Unsupported hash_bytes bound');
  requireCondition(bytes.length <= maxLength, 'hash_bytes length exceeds bound');
  const padded = Buffer.alloc(Math.ceil(maxLength / 31) * 31);
  bytes.copy(padded);
  const values = [BigInt(bytes.length)];
  for (let offset = 0; offset < padded.length; offset += 31) {
    values.push(BigInt(`0x${padded.subarray(offset, offset + 31).toString('hex')}`));
  }
  return poseidon(values);
}

export function normalizeIssuer(issuer) {
  requireCondition(typeof issuer === 'string', 'Issuer must be a string');
  return issuer.startsWith('https://') ? issuer.slice(8) : issuer;
}

export async function issuerHash(issuer) {
  return hashBytes(Buffer.from(normalizeIssuer(issuer)), 128);
}

export async function addressSeed(subject, audience, salt) {
  requireCondition(typeof subject === 'string' && typeof audience === 'string', 'Identity claims must be strings');
  return poseidon([1n, await hashBytes(Buffer.from(subject), 64), await hashBytes(Buffer.from(audience), 128), field(salt)]);
}

export function stableSalt(secret, issuer, audience, subject) {
  requireCondition(Buffer.isBuffer(secret) && secret.length >= 32, 'Salt secret must contain at least 32 bytes');
  for (const claim of [issuer, audience, subject]) {
    requireCondition(typeof claim === 'string' && !claim.includes('\0'), 'Invalid salt identity');
  }
  const digest = createHmac('sha256', secret).update(`${normalizeIssuer(issuer)}\0${audience}\0${subject}`).digest('hex');
  return BigInt(`0x${digest}`) % SCALAR_FIELD;
}

export async function signatureNonce(accessKeyId, validUntil, blinding) {
  requireCondition(BigInt(accessKeyId) >= 0n && BigInt(accessKeyId) < (1n << 160n), 'Invalid access-key ID');
  requireCondition(BigInt(validUntil) >= 0n && BigInt(validUntil) < MESSAGE_TAG, 'Invalid signature expiry');
  return be32(await poseidon([accessKeyId, validUntil, blinding])).toString('base64url');
}

export async function messageNonce(digest, blinding) {
  requireCondition(/^0x[0-9a-fA-F]{64}$/.test(digest), 'Expected bytes32 message digest');
  return be32(await poseidon([BigInt(digest) % SCALAR_FIELD, MESSAGE_TAG, blinding])).toString('base64url');
}

export async function messagePublicInput({ issuer, keyHash, addressSeed: seed, digest, issuedAt }) {
  requireCondition(/^0x[0-9a-fA-F]{64}$/.test(digest), 'Expected bytes32 message digest');
  return publicInput({ issuer, keyHash, addressSeed: seed, commitA: BigInt(digest) % SCALAR_FIELD, commitB: MESSAGE_TAG, issuedAt });
}

export async function publicInput({ issuer, keyHash, addressSeed: seed, commitA, commitB, issuedAt }) {
  requireCondition(BigInt(issuedAt) >= 0n && BigInt(issuedAt) < MESSAGE_TAG, 'Invalid issued_at');
  return poseidon([1n, issuer, keyHash, seed, commitA, commitB, issuedAt]);
}

export function zkAddress(publisherId, issuer, seed) {
  requireCondition(/^0x[0-9a-fA-F]{64}$/.test(publisherId), 'Invalid publisher ID');
  const preimage = Buffer.concat([Buffer.from([0x06, 0x01]), Buffer.from(publisherId.slice(2), 'hex'), be32(field(issuer)), be32(field(seed))]);
  return ethers.getAddress(`0x${ethers.keccak256(preimage).slice(-40)}`);
}

function decodeBase64url(value) {
  requireCondition(/^[A-Za-z0-9_-]+$/.test(value) && value.length % 4 !== 1, 'Invalid base64url');
  const decoded = Buffer.from(value, 'base64url');
  requireCondition(decoded.toString('base64url') === value, 'Non-canonical base64url');
  return decoded;
}

export function rsaModulus(jwk) {
  requireCondition(jwk.kty === 'RSA' && (!jwk.alg || jwk.alg === 'RS256'), 'Expected RS256 RSA key');
  const modulus = decodeBase64url(jwk.n);
  const exponent = decodeBase64url(jwk.e);
  requireCondition(modulus.length === 256 && (modulus[0] & 0x80) !== 0, 'Expected 2048-bit RSA modulus');
  requireCondition(exponent.toString('hex') === '010001', 'Expected RSA exponent 65537');
  return modulus;
}

function topLevelMembers(payload) {
  const source = payload.toString('utf8');
  requireCondition(Buffer.from(source).equals(payload), 'Invalid payload UTF-8');
  const parsed = JSON.parse(source);
  requireCondition(parsed !== null && !Array.isArray(parsed) && typeof parsed === 'object', 'Payload must be an object');
  const members = new Map();
  let depth = 0;
  let previous = '';
  for (let offset = 0; offset < source.length; offset++) {
    const character = source[offset];
    if (character === '"') {
      const start = offset;
      let escaped = false;
      for (offset++; offset < source.length; offset++) {
        if (source[offset] === '\\') {
          escaped = true;
          offset++;
        } else if (source[offset] === '"') break;
      }
      if (depth === 1 && (previous === '{' || previous === ',') && source[offset + 1] === ':') {
        requireCondition(!escaped, 'Escaped top-level member name');
        const name = JSON.parse(source.slice(start, offset + 1));
        requireCondition(!members.has(name), 'Duplicate top-level member');
        const valueStart = offset + 2;
        let valueEnd = valueStart;
        if (source[valueStart] === '"') {
          for (valueEnd++; valueEnd < source.length; valueEnd++) {
            if (source[valueEnd] === '\\') valueEnd++;
            else if (source[valueEnd] === '"') break;
          }
          valueEnd++;
        } else {
          while (valueEnd < source.length && !',}'.includes(source[valueEnd])) valueEnd++;
        }
        members.set(name, source.slice(valueStart, valueEnd));
      }
      previous = '"';
    } else {
      requireCondition(!/\s/.test(character), 'Whitespace outside payload strings');
      if (character === '{' || character === '[') depth++;
      if (character === '}' || character === ']') depth--;
      previous = character;
    }
  }
  for (const name of ['iss', 'aud', 'sub', 'nonce', 'iat', 'exp']) requireCondition(members.has(name), `Missing top-level ${name}`);
  for (const name of ['iss', 'aud', 'sub', 'nonce']) {
    const raw = members.get(name);
    requireCondition(raw.startsWith('"') && raw.endsWith('"') && !raw.includes('\\'), `Invalid ${name} string`);
  }
  for (const name of ['iat', 'exp']) requireCondition(/^[0-9]{1,10}$/.test(members.get(name)), `Invalid ${name} integer`);
  return parsed;
}

export async function tokenWitness({ token, jwk, salt, blinding, accessKeyId, validUntil, now, expectedIssuer, expectedAudience }) {
  requireCondition(typeof token === 'string' && token.split('.').length === 3, 'Expected compact JWS');
  const [header, payload, signature] = token.split('.');
  const signedInput = Buffer.from(`${header}.${payload}`);
  requireCondition(signedInput.length <= 1024, 'Signed input exceeds 1024 bytes');
  decodeBase64url(header);
  const payloadBytes = decodeBase64url(payload);
  requireCondition(payloadBytes.length <= 768, 'Payload exceeds 768 bytes');
  const claims = topLevelMembers(payloadBytes);
  requireCondition(normalizeIssuer(claims.iss) === normalizeIssuer(expectedIssuer), 'Unexpected issuer');
  requireCondition(claims.aud === expectedAudience, 'Unexpected audience');
  requireCondition(Number.isSafeInteger(now) && now >= 0, 'Invalid current timestamp');
  requireCondition(claims.iat <= now + 60 && BigInt(now) <= BigInt(validUntil), 'Token outside current validity window');
  requireCondition(BigInt(validUntil) >= BigInt(claims.iat) && BigInt(validUntil) - BigInt(claims.iat) <= 600n, 'Invalid 600-second signature window');
  requireCondition(BigInt(validUntil) <= BigInt(claims.exp), 'Signature expiry exceeds token exp');
  const nonce = await signatureNonce(accessKeyId, validUntil, blinding);
  requireCondition(claims.nonce === nonce, 'Nonce does not bind access key, expiry, and blinding');
  const modulus = rsaModulus(jwk);
  const signatureBytes = decodeBase64url(signature);
  requireCondition(signatureBytes.length === 256, 'Expected 256-byte RSA signature');
  const signatureInteger = BigInt(`0x${signatureBytes.toString('hex')}`);
  requireCondition(signatureInteger > 0n && signatureInteger < BigInt(`0x${modulus.toString('hex')}`), 'RSA signature out of range');
  requireCondition(verify('RSA-SHA256', signedInput, createPublicKey({ key: jwk, format: 'jwk' }), signatureBytes), 'Invalid RS256 signature');
  const issuer = await issuerHash(claims.iss);
  const keyHash = await hashBytes(modulus, 256);
  const seed = await addressSeed(claims.sub, claims.aud, salt);
  const input = await publicInput({ issuer, keyHash, addressSeed: seed, commitA: accessKeyId, commitB: validUntil, issuedAt: claims.iat });
  const paddedInput = Buffer.alloc(1024);
  signedInput.copy(paddedInput);
  return { issuer, keyHash, addressSeed: seed, publicInput: input, issuedAt: claims.iat, validUntil: BigInt(validUntil), signedInput: paddedInput, signedInputLength: signedInput.length, modulus, signature: signatureBytes, salt: field(salt), blinding: field(blinding), accessKeyId: BigInt(accessKeyId) };
}
