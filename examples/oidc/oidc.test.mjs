import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { SCALAR_FIELD, MESSAGE_TAG, addressSeed, be32, field, hashBytes, issuerHash, messageNonce, messagePublicInput, poseidon, publicInput, signatureNonce, stableSalt, tokenWitness, zkAddress } from './oidc.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = publicKey.export({ format: 'jwk' });
const parameters = { jwk, salt: 7n, blinding: 9n, accessKeyId: 42n, validUntil: 1540n, now: 1000, expectedIssuer: 'https://accounts.google.com', expectedAudience: 'tempo-test-client' };
const claims = { iss: parameters.expectedIssuer, aud: parameters.expectedAudience, sub: 'test-subject', nonce: await signatureNonce(parameters.accessKeyId, parameters.validUntil, parameters.blinding), iat: 1000, exp: 2000 };

function signedToken(payload, signingKey = privateKey) {
  const header = Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url');
  const signedInput = `${header}.${Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)).toString('base64url')}`;
  return `${signedInput}.${sign('RSA-SHA256', Buffer.from(signedInput), signingKey).toString('base64url')}`;
}

test('circomlib Poseidon reference vector', async () => {
  assert.equal(await poseidon([1n, 2n]), 7853200120776062878684798364095072458815029376092732009249414926327459813530n);
});

test('shared seven-input vectors match the native verifier in PR 8137', async () => {
  assert.equal(await poseidon([1n, 2n, 3n, 4n, 5n, 6n, 7n]), 12748163991115452309045839028154629052133952896122405799815156419278439301912n);
  assert.equal(await poseidon(Array(7).fill(0n)), 4650195440642623795323580690232682597343117209016245979902989581920340875814n);
  assert.equal(await poseidon([SCALAR_FIELD - 1n, 1n, (1n << 160n) - 1n, MESSAGE_TAG, 600n, 1700000000n, 123456789n]), 12417695477114946618717948556960537121882240102799095195289794398708817650015n);
});

test('message form reduces digests into the scalar field and separates signature nonces', async () => {
  const digest = `0x${be32(SCALAR_FIELD + 42n).toString('hex')}`;
  const message = await messageNonce(digest, 9n);
  assert.equal(message, be32(await poseidon([42n, MESSAGE_TAG, 9n])).toString('base64url'));
  assert.notEqual(message, await signatureNonce(42n, 1540n, 9n));
  assert.equal(await messagePublicInput({ issuer: 1n, keyHash: 2n, addressSeed: 3n, digest, issuedAt: 1000 }), await publicInput({ issuer: 1n, keyHash: 2n, addressSeed: 3n, commitA: 42n, commitB: MESSAGE_TAG, issuedAt: 1000 }));
  await assert.rejects(messageNonce('0x01', 9n), /bytes32/);
});

test('field and bytes32 boundaries', () => {
  assert.equal(field(SCALAR_FIELD - 1n), SCALAR_FIELD - 1n);
  assert.throws(() => field(SCALAR_FIELD), /Non-canonical/);
  assert.throws(() => field(-1n), /Non-canonical/);
  assert.equal(be32(1n).toString('hex'), `${'00'.repeat(31)}01`);
  assert.throws(() => be32(1n << 256n), /bytes32/);
});

test('hash_bytes zero padding, lengths, and bounds', async () => {
  assert.notEqual(await hashBytes(Buffer.from([1]), 64), await hashBytes(Buffer.from([1, 0]), 64));
  for (const bound of [64, 128, 256]) {
    assert.equal(typeof await hashBytes(Buffer.alloc(bound), bound), 'bigint');
    await assert.rejects(hashBytes(Buffer.alloc(bound + 1), bound), /length exceeds/);
  }
  await assert.rejects(hashBytes(Buffer.alloc(1), 1024), /Unsupported/);
  await assert.rejects(poseidon([SCALAR_FIELD]), /Non-canonical/);
});

test('issuer normalization, salt stability, and identity separation', async () => {
  assert.equal(await issuerHash('accounts.google.com'), await issuerHash('https://accounts.google.com'));
  const secret = Buffer.alloc(32, 5);
  const salt = stableSalt(secret, claims.iss, claims.aud, claims.sub);
  assert.equal(salt, stableSalt(secret, 'accounts.google.com', claims.aud, claims.sub));
  assert.notEqual(salt, stableSalt(secret, claims.iss, 'other-client', claims.sub));
  assert.notEqual(salt, stableSalt(secret, claims.iss, claims.aud, 'other-subject'));
  assert.throws(() => stableSalt(Buffer.alloc(16), claims.iss, claims.aud, claims.sub), /at least 32/);
  assert.throws(() => stableSalt(secret, claims.iss, 'bad\0aud', claims.sub), /Invalid salt/);
});

test('nonce is 43 characters and binds key, expiry, and blinding', async () => {
  assert.equal(claims.nonce.length, 43);
  for (const inputs of [[43n, 1540n, 9n], [42n, 1541n, 9n], [42n, 1540n, 10n]]) {
    assert.notEqual(await signatureNonce(...inputs), claims.nonce);
  }
  await assert.rejects(signatureNonce(1n << 160n, 1540n, 9n), /access-key/);
  await assert.rejects(signatureNonce(42n, MESSAGE_TAG, 9n), /expiry/);
});

test('address derivation is deterministic and separates publishers and identities', async () => {
  const publisher = `0x${'11'.repeat(32)}`;
  const issuer = await issuerHash(claims.iss);
  const seed = await addressSeed(claims.sub, claims.aud, 7n);
  const address = zkAddress(publisher, issuer, seed);
  assert.equal(zkAddress(publisher, issuer, seed), address);
  assert.notEqual(zkAddress(`0x${'22'.repeat(32)}`, issuer, seed), address);
  assert.notEqual(zkAddress(publisher, issuer, await addressSeed('another-subject', claims.aud, 7n)), address);
  assert.throws(() => zkAddress('0x01', issuer, seed), /publisher/);
});

test('genuine RS256 token creates a padded private witness, not a proof', async () => {
  const witness = await tokenWitness({ ...parameters, token: signedToken(claims) });
  assert.equal(witness.signedInput.length, 1024);
  assert.deepEqual(witness.signedInput.subarray(witness.signedInputLength), Buffer.alloc(1024 - witness.signedInputLength));
  assert.equal(witness.signature.length, 256);
  assert.equal(witness.modulus.length, 256);
  assert.equal(witness.issuer, await issuerHash(claims.iss));
  assert.equal(witness.addressSeed, await addressSeed(claims.sub, claims.aud, 7n));
  assert.equal(witness.publicInput, await publicInput({ issuer: witness.issuer, keyHash: witness.keyHash, addressSeed: witness.addressSeed, commitA: parameters.accessKeyId, commitB: parameters.validUntil, issuedAt: 1000 }));
  assert.equal('proof' in witness, false);
});

const malformedPayloads = [
  ['duplicate required member', `${JSON.stringify(claims).slice(0, -1)},"sub":"attacker"}`, /Duplicate/],
  ['nested-only subject', JSON.stringify({ ...claims, sub: undefined, nested: { sub: claims.sub } }), /Missing top-level sub/],
  ['escaped member name', JSON.stringify(claims).replace('"sub":', '"s\\u0075b":'), /Escaped top-level/],
  ['escaped subject', JSON.stringify(claims).replace('test-subject', 'test\\u002dsubject'), /Invalid sub/],
  ['whitespace outside strings', JSON.stringify(claims, null, 1), /Whitespace outside/],
  ['array audience', { ...claims, aud: [claims.aud] }, /Invalid aud/],
  ['missing exp', { ...claims, exp: undefined }, /Missing top-level exp/],
  ['expiry beyond exp', { ...claims, exp: 1500 }, /exceeds token exp/],
  ['future iat', { ...claims, iat: 1061 }, /current validity/],
  ['negative iat', { ...claims, iat: -1 }, /Invalid iat/],
  ['decimal iat', { ...claims, iat: 1000.5 }, /Invalid iat/],
  ['eleven-digit exp', { ...claims, exp: 10000000000 }, /Invalid exp/],
  ['other nonce', { ...claims, nonce: 'a'.repeat(43) }, /Nonce does not bind/],
  ['other issuer', { ...claims, iss: 'https://attacker.example' }, /Unexpected issuer/],
  ['other audience', { ...claims, aud: 'attacker-client' }, /Unexpected audience/],
  ['overlong subject', { ...claims, sub: 'a'.repeat(65) }, /length exceeds/],
  ['overlong signed input', { ...claims, extra: 'a'.repeat(1024) }, /Signed input exceeds/],
];

for (const [name, payload, rejection] of malformedPayloads) {
  test(`reject ${name}`, async () => {
    await assert.rejects(tokenWitness({ ...parameters, token: signedToken(payload) }), rejection);
  });
}

test('reject expired window and mismatched device key', async () => {
  const token = signedToken(claims);
  await assert.rejects(tokenWitness({ ...parameters, now: 1541, token }), /current validity/);
  await assert.rejects(tokenWitness({ ...parameters, accessKeyId: 43n, token }), /Nonce does not bind/);
  await assert.rejects(tokenWitness({ ...parameters, validUntil: 1601n, token }), /600-second/);
});

test('reject wrong RSA key, invalid exponent, zero signature, and malformed base64url', async () => {
  const token = signedToken(claims);
  const wrongKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
  await assert.rejects(tokenWitness({ ...parameters, jwk: wrongKey, token }), /Invalid RS256|out of range/);
  await assert.rejects(tokenWitness({ ...parameters, jwk: { ...jwk, e: 'Aw' }, token }), /exponent/);
  await assert.rejects(tokenWitness({ ...parameters, jwk: { ...jwk, n: Buffer.alloc(256, 1).toString('base64url') }, token }), /2048-bit/);
  const signingInput = token.slice(0, token.lastIndexOf('.') + 1);
  await assert.rejects(tokenWitness({ ...parameters, token: `${signingInput}${Buffer.alloc(256).toString('base64url')}` }), /out of range/);
  await assert.rejects(tokenWitness({ ...parameters, token: `${token}=` }), /base64url/);
  await assert.rejects(tokenWitness({ ...parameters, token: 'a.a.a' }), /base64url/);
});

test('accept nested unrelated claims and whitespace inside strings', async () => {
  const witness = await tokenWitness({ ...parameters, token: signedToken({ ...claims, nested: { sub: 'ignored', values: [1, 2] }, name: 'Test User' }) });
  assert.equal(witness.addressSeed, await addressSeed(claims.sub, claims.aud, 7n));
});
