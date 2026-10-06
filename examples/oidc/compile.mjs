import { execFileSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const source = path.dirname(fileURLToPath(import.meta.url));
const destination = path.resolve(process.argv[2] ?? 'build');
await mkdir(destination, { recursive: true });
execFileSync(path.join(source, 'node_modules/.bin/circom2'), [
  path.join(source, 'circuits/oidc.circom'), '--r1cs', '--wasm', '--sym',
  '-l', path.join(source, 'node_modules'), '-o', destination,
], { stdio: 'inherit' });
// Circom emits CommonJS helpers even when their parent project uses ESM.
await writeFile(path.join(destination, 'oidc_js/package.json'), '{"type":"commonjs"}\n');
