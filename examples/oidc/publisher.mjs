import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { ethers } from 'ethers';
import { be32, hashBytes, issuerHash, rsaModulus } from './oidc.mjs';

const publisherInterface = new ethers.Interface(['function setKeys(bytes32 publisherId, bytes32 issuer, bytes32[] keyHashes)']);

export async function publisherUpdate(jwks, issuer, publisherId) {
  if (!Array.isArray(jwks.keys)) throw new Error('Expected JWKS keys array');
  if (!/^0x[0-9a-fA-F]{64}$/.test(publisherId)) throw new Error('Invalid publisher ID');
  const keys = jwks.keys.filter(key => key.kty === 'RSA' && (!key.alg || key.alg === 'RS256') && (!key.use || key.use === 'sig'));
  if (keys.length === 0) throw new Error('No supported RS256 signing keys; refusing to clear publisher');
  const hashes = await Promise.all(keys.map(async key => `0x${be32(await hashBytes(rsaModulus(key), 256)).toString('hex')}`));
  const keyHashes = [...new Set(hashes)].sort();
  if (keyHashes.length > 16) throw new Error('Publisher supports at most 16 keys per issuer');
  const issuerField = `0x${be32(await issuerHash(issuer)).toString('hex')}`;
  return {
    to: '0x1132000000000000000000000000000000000000',
    value: '0x0',
    publisherId,
    issuer: issuerField,
    keyHashes,
    data: publisherInterface.encodeFunctionData('setKeys', [publisherId, issuerField, keyHashes]),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { jwks: { type: 'string' }, issuer: { type: 'string' }, 'publisher-id': { type: 'string' } } });
  if (!values.jwks || !values.issuer || !values['publisher-id']) throw new Error('Usage: node publisher.mjs --jwks keys.json --issuer <issuer> --publisher-id <bytes32>');
  const jwks = JSON.parse(await readFile(values.jwks, 'utf8'));
  console.log(JSON.stringify(await publisherUpdate(jwks, values.issuer, values['publisher-id']), null, 2));
}
