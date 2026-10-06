import { randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { verificationKeyBytes, proofBytes } from './protocol.mjs';
import { fixture } from './witness.mjs';

const [mode, directory, ptau] = process.argv.slice(2);
if (!directory) throw new Error('Usage: node setup.mjs setup ARTIFACTS PTAU | prove ARTIFACTS | verify ARTIFACTS PTAU');
await mkdir(directory, { recursive: true });
const file = name => path.join(directory, name);
if (mode === 'setup') {
  if (!ptau) throw new Error('Supply a verified Powers of Tau transcript');
  await snarkjs.zKey.newZKey(file('oidc.r1cs'), ptau, file('initial.zkey'));
  await snarkjs.zKey.contribute(file('initial.zkey'), file('devnet.zkey'), 'unaudited-single-contributor-devnet', randomBytes(64).toString('hex'));
  const vk = await snarkjs.zKey.exportVerificationKey(file('devnet.zkey'));
  await writeFile(file('vk.json'), JSON.stringify(vk));
  await writeFile(file('vk.bin'), verificationKeyBytes(vk));
  console.log('Generated a devnet-only key. This is not the TIP-1133 production ceremony.');
} else if (mode === 'prove') {
  const value = await fixture();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(value.input, file('oidc_js/oidc.wasm'), file('devnet.zkey'));
  const vk = JSON.parse(await readFile(file('vk.json'), 'utf8'));
  if (publicSignals.length !== 1 || publicSignals[0] !== value.input.public_input || !await snarkjs.groth16.verify(vk, publicSignals, proof)) throw new Error('Local proof verification failed');
  await writeFile(file('fixture-proof.json'), JSON.stringify({ ...value, proof, publicSignals, proofBytes: proofBytes(proof) }));
  console.log('Actual RSA token proof generated and verified; synthetic provider only.');
} else if (mode === 'verify') {
  if (!ptau || !await snarkjs.zKey.verifyFromR1cs(file('oidc.r1cs'), ptau, file('devnet.zkey'))) throw new Error('Devnet setup verification failed');
  console.log('Devnet setup verified against the full constraint system and Powers of Tau transcript.');
} else throw new Error('Unknown mode');
process.exit(0);
