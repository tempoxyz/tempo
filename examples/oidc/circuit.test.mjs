import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fixture } from './witness.mjs';

const artifacts = process.env.OIDC_ARTIFACTS;
test('TIP-1133 circuit accepts signed fixtures and rejects adversarial inputs independently of preflight', { skip: !artifacts }, async t => {
  const build = createRequire(import.meta.url)(path.resolve(artifacts, 'oidc_js/witness_calculator.js'));
  const calculator = await build(await readFile(path.resolve(artifacts, 'oidc_js/oidc.wasm')));
  const valid = await fixture();
  const validWitness = await calculator.calculateWTNSBin(valid.input, true);
  if (process.env.OIDC_WITNESS_PATH) await writeFile(process.env.OIDC_WITNESS_PATH, validWitness);
  for (const options of [
    { issuer: 'accounts.example.invalid' },
    { issuer: `https://${'i'.repeat(128)}`, audience: 'a'.repeat(128), subject: 's'.repeat(64) },
    { message: true },
    { payloadTransform: source => source.replace('"sub":', '"extra":{"sub":"nested","v":[1,true,null]},"sub":') },
  ]) {
    await t.test(`accept ${JSON.stringify(options)}`, async () => {
      const value = await fixture(options);
      await calculator.calculateWTNSBin(value.input, true);
    });
  }
  const changes = {
    'nonzero byte after signed length': input => input.signed_input[input.signed_input_len] = 65,
    'wrong signed length': input => input.signed_input_len--,
    'second dot': input => input.signed_input[0] = 46,
    'bad base64url': input => input.signed_input[0] = 61,
    'wrong payload length': input => input.payload_len--,
    'wrong claim offset': input => input.member_offsets[0]++,
    'wrong claim length': input => input.member_lengths[2]++,
    'wrong issuer': input => input.issuer = (BigInt(input.issuer)+1n).toString(),
    'wrong key hash': input => input.key_hash = (BigInt(input.key_hash)+1n).toString(),
    'wrong seed': input => input.address_seed = (BigInt(input.address_seed)+1n).toString(),
    'wrong issued_at': input => input.issued_at++,
    'different device key': input => input.commit_a = '1',
    'different expiry': input => input.commit_b = (BigInt(input.commit_b)-1n).toString(),
    'wrong blinding': input => input.blinding = '1',
    'wrong salt': input => input.salt = '1',
    'wrong public input': input => input.public_input = '1',
    'out-of-range RSA limb': input => input.signature[0] = (1n<<121n).toString(),
    'zero RSA signature': input => input.signature.fill('0'),
    'RSA signature equals modulus': input => input.signature = [...input.modulus],
    '2047-bit modulus': input => input.modulus[16] = (BigInt(input.modulus[16]) & ((1n<<111n)-1n)).toString(),
    'signature-to-message substitution': input => input.commit_b = (1n<<64n).toString(),
  };
  for (const [name, mutate] of Object.entries(changes)) {
    await t.test(`reject ${name}`, async () => {
      const input = structuredClone(valid.input);
      mutate(input);
      await assert.rejects(calculator.calculateWTNSBin(input, true));
    });
  }
  for (const [name, transform] of [
    ['duplicate subject', source => source.replace('"sub":', '"sub":"other","sub":')],
    ['nested-only subject', source => source.replace('"sub":"synthetic-user"', '"extra":{"sub":"synthetic-user"}')],
    ['escaped name', source => source.replace('"sub":', '"s\\u0075b":')],
    ['escaped value', source => source.replace('synthetic-user', 'synthetic\\u002duser')],
    ['whitespace', source => source.replace('"aud":', '"aud": ')],
    ['expiry before commitment', source => source.replace(/"exp":\d+/, '"exp":1')],
  ]) {
    await t.test(`reject signed ${name}`, async () => {
      const value = await fixture({ payloadTransform: transform });
      await assert.rejects(calculator.calculateWTNSBin(value.input, true));
    });
  }
});
