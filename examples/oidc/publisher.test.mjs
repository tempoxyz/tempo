import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { ethers } from 'ethers';
import { be32, hashBytes, rsaModulus } from './oidc.mjs';
import { publisherUpdate } from './publisher.mjs';

const publisherId = `0x${'11'.repeat(32)}`;
const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });

test('JWKS update deduplicates RSA modulus hashes and produces typed setKeys calldata', async () => {
  const update = await publisherUpdate({ keys: [key, { ...key, kid: 'duplicate' }, { kty: 'EC', alg: 'ES256' }] }, 'https://accounts.google.com', publisherId);
  assert.deepEqual(update.keyHashes, [`0x${be32(await hashBytes(rsaModulus(key), 256)).toString('hex')}`]);
  const contract = new ethers.Interface(['function setKeys(bytes32 publisherId, bytes32 issuer, bytes32[] keyHashes)']);
  const decoded = contract.decodeFunctionData('setKeys', update.data);
  assert.equal(decoded.publisherId, publisherId);
  assert.equal(decoded.issuer, update.issuer);
  assert.deepEqual([...decoded.keyHashes], update.keyHashes);
});

test('JWKS update fails closed on unsupported, encryption-only, malformed, or missing keys', async () => {
  for (const keys of [[], [{ ...key, alg: 'RS512' }], [{ ...key, use: 'enc' }], [{ kty: 'EC', alg: 'ES256' }]]) {
    await assert.rejects(publisherUpdate({ keys }, 'accounts.google.com', publisherId), /No supported/);
  }
  await assert.rejects(publisherUpdate({}, 'accounts.google.com', publisherId), /keys array/);
  await assert.rejects(publisherUpdate({ keys: [{ ...key, e: 'Aw' }] }, 'accounts.google.com', publisherId), /exponent/);
  await assert.rejects(publisherUpdate({ keys: [key] }, 'accounts.google.com', '0x01'), /publisher ID/);
});
