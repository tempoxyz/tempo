import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { ethers } from 'ethers';
import { be32 } from './oidc.mjs';

export const PUBLISHER = '0x1132000000000000000000000000000000000000';
export const KEYCHAIN = '0xAAAAAAAA00000000000000000000000000000000';
export const USD = '0x20c0000000000000000000000000000000000000';
const BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export const hex32 = value => `0x${be32(value).toString('hex')}`;
export function quantity(value) { return BigInt(value) === 0n ? '0x' : ethers.toBeHex(BigInt(value)); }
function coordinate(value) {
  const integer = BigInt(value);
  if (integer < 0n || integer >= BASE_FIELD) throw new Error('Non-canonical curve coordinate');
  return be32(integer);
}
function g1(point) { return Buffer.concat([coordinate(point[0]), coordinate(point[1])]); }
function g2(point) { return Buffer.concat([coordinate(point[0][1]), coordinate(point[0][0]), coordinate(point[1][1]), coordinate(point[1][0])]); }
export function proofBytes(proof) {
  if (proof.protocol !== 'groth16' || proof.curve !== 'bn128') throw new Error('Expected BN254 Groth16 proof');
  return `0x${Buffer.concat([g1(proof.pi_a), g2(proof.pi_b), g1(proof.pi_c)]).toString('hex')}`;
}
export function verificationKeyBytes(vk) {
  if (vk.protocol !== 'groth16' || vk.curve !== 'bn128' || vk.nPublic !== 1 || vk.IC.length !== 2) throw new Error('Expected one-input BN254 Groth16 verifying key');
  return Buffer.concat([g1(vk.vk_alpha_1), g2(vk.vk_beta_2), g2(vk.vk_gamma_2), g2(vk.vk_delta_2), ...vk.IC.map(g1)]);
}

export function zkSignature({ input, publisherId, proof, digest, wallet }) {
  const fields = [quantity(1), publisherId, hex32(input.issuer), hex32(input.key_hash), hex32(input.address_seed), quantity(input.issued_at), quantity(input.commit_b), typeof proof === 'string' ? proof : proofBytes(proof)];
  const fieldsHash = ethers.keccak256(ethers.encodeRlp(fields));
  const signingHash = ethers.keccak256(ethers.concat([ethers.toUtf8Bytes('tempo:zk-signature'), digest, fieldsHash]));
  return ethers.concat(['0x06', ethers.encodeRlp([...fields, wallet.signingKey.sign(signingHash).serialized])]);
}

export function transactionFields({ calls, nonce = 0, keyAuthorization, validBefore = 0, gasLimit = 3_000_000 }) {
  const fields = [quantity(1337), '0x', quantity(1_000_000_000), quantity(gasLimit), calls.map(call => [call.to, '0x', call.data]), [], '0x', quantity(nonce), quantity(validBefore), '0x', USD, '0x', []];
  if (keyAuthorization) fields.push(keyAuthorization);
  return fields;
}
export const transactionDigest = fields => ethers.keccak256(ethers.concat(['0x76', ethers.encodeRlp(fields)]));
export const signedTransaction = (fields, signature) => ethers.concat(['0x76', ethers.encodeRlp([...fields, signature])]);
export function accessKeySignature(fields, account, wallet) {
  const digest = ethers.keccak256(ethers.concat(['0x04', transactionDigest(fields), account]));
  return ethers.concat(['0x04', account, wallet.signingKey.sign(digest).serialized]);
}
export function keyAuthorization(wallet, input, publisherId, proof) {
  const authorization = [quantity(1337), '0x', wallet.address, quantity(input.commit_b)];
  return [authorization, zkSignature({ input, publisherId, proof, digest: ethers.keccak256(ethers.encodeRlp(authorization)), wallet })];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [source, destination] = process.argv.slice(2);
  if (!source || !destination) throw new Error('Usage: node protocol.mjs VK.json VK.bin');
  await writeFile(destination, verificationKeyBytes(JSON.parse(await readFile(source, 'utf8'))));
}
