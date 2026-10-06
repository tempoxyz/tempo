import { generateKeyPairSync, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { tokenWitness, signatureNonce, MESSAGE_TAG, field, be32, hashBytes, issuerHash, addressSeed, publicInput, messageNonce } from './oidc.mjs';

export function limbs(bytes) {
  let value = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
  return Array.from({ length: 17 }, () => { const limb = value & ((1n << 121n)-1n); value >>= 121n; return limb.toString(); });
}

export function positions(payload, allowMissing = false) {
  const source = payload.toString('utf8');
  const found = new Map();
  let depth = 0;
  let previous = '';
  for (let i = 0; i < source.length; i++) {
    const character = source[i];
    if (character === '"') {
      const start = i;
      let escaped = false;
      for (i++; i < source.length; i++) {
        if (!escaped && source[i] === '"') break;
        escaped = !escaped && source[i] === '\\';
      }
      if (depth === 1 && ['{', ','].includes(previous) && source[i+1] === ':') {
        const key = source.slice(start+1, i);
        const valueStart = i+2;
        if (['iss','aud','sub','nonce','iat','exp'].includes(key)) {
          let valueEnd = valueStart;
          if (source[valueStart] === '"') {
            valueEnd = source.indexOf('"', valueStart+1);
            found.set(key, [Buffer.byteLength(source.slice(0, start)), Buffer.byteLength(source.slice(valueStart+1, valueEnd))]);
          } else {
            while (valueEnd < source.length && !',}'.includes(source[valueEnd])) valueEnd++;
            found.set(key, [Buffer.byteLength(source.slice(0, start)), valueEnd-valueStart]);
          }
        }
      }
      previous = '"';
    } else {
      if ('{['.includes(character)) depth++;
      if ('}]'.includes(character)) depth--;
      previous = character;
    }
  }
  return ['iss','aud','sub','nonce','iat','exp'].map(key => {
    if (!found.has(key)) {
      if (allowMissing) return [0, key === 'nonce' ? 43 : 1];
      throw new Error(`Missing circuit member: ${key}`);
    }
    return found.get(key);
  });
}

export function circuitInput(witness, allowMissing = false) {
  const input = witness.signedInput.subarray(0, witness.signedInputLength);
  const period = input.indexOf(46);
  const payload = Buffer.from(input.subarray(period+1).toString(), 'base64url');
  const members = positions(payload, allowMissing);
  return {
    signed_input: [...witness.signedInput], signed_input_len: witness.signedInputLength, period, payload_len: payload.length,
    modulus: limbs(witness.modulus), signature: limbs(witness.signature),
    member_offsets: members.map(member => member[0]), member_lengths: members.map(member => member[1]),
    salt: witness.salt.toString(), blinding: witness.blinding.toString(),
    commit_a: witness.accessKeyId.toString(), commit_b: witness.validUntil.toString(), issued_at: witness.issuedAt.toString(),
    issuer: witness.issuer.toString(), key_hash: witness.keyHash.toString(), address_seed: witness.addressSeed.toString(), public_input: witness.publicInput.toString(),
  };
}

export async function fixture({ message = false, payloadTransform = value => value, issuer = 'https://accounts.example.invalid', audience = 'tempo-oidc-devnet', subject = 'synthetic-user', now = Math.floor(Date.now()/1000), accessKeyId = 0x70997970c51812dc3a010c7d01b50e0d17dc79c8n } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.alg = 'RS256'; jwk.kid = 'synthetic-devnet'; jwk.use = 'sig';
  const salt = 123n;
  const blinding = 456n;
  const validUntil = message ? MESSAGE_TAG : BigInt(now+540);
  const nonce = message ? await messageNonce(`0x${be32(accessKeyId).toString('hex')}`, blinding) : await signatureNonce(accessKeyId, validUntil, blinding);
  const payload = payloadTransform(JSON.stringify({ iss: issuer, aud: audience, sub: subject, nonce, iat: now, exp: now+3600 }));
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid })).toString('base64url');
  const signed = Buffer.from(`${header}.${Buffer.from(payload).toString('base64url')}`);
  const signature = sign('RSA-SHA256', signed, privateKey);
  const token = `${signed}.${signature.toString('base64url')}`;
  const claims = JSON.parse(payload);
  const modulus = Buffer.from(jwk.n, 'base64url');
  const issuerValue = await issuerHash(claims.iss);
  const keyHash = await hashBytes(modulus, 256);
  const seed = await addressSeed(claims.sub ?? subject, claims.aud ?? audience, salt);
  const padded = Buffer.alloc(1024); signed.copy(padded);
  const statement = await publicInput({ issuer: issuerValue, keyHash, addressSeed: seed, commitA: accessKeyId, commitB: validUntil, issuedAt: claims.iat });
  const witness = { signedInput: padded, signedInputLength: signed.length, modulus, signature, salt, blinding, accessKeyId, validUntil, issuedAt: claims.iat, issuer: issuerValue, keyHash, addressSeed: seed, publicInput: statement };
  if (!message && payloadTransform.toString() === (value => value).toString()) {
    await tokenWitness({ token, jwk, salt, blinding, accessKeyId, validUntil, now, expectedIssuer: issuer, expectedAudience: audience });
  }
  return { input: circuitInput(witness, true), token, jwk };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [mode, destination] = process.argv.slice(2);
  if (mode === 'fixture') {
    if (!destination) throw new Error('Usage: node witness.mjs fixture OUTPUT');
    await writeFile(destination, JSON.stringify(await fixture()));
  } else if (mode === 'token') {
    const options = JSON.parse(await readFile(destination, 'utf8'));
    const witness = await tokenWitness(options);
    process.stdout.write(JSON.stringify(circuitInput(witness)));
  } else throw new Error('Use fixture OUTPUT or token OPTIONS.json');
}
