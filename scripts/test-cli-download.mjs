import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createSnapshotProxy, fixtureDirectory } from './cli-download-proxy.mjs';

const [tempo, chainIdArgument, ...args] = process.argv.slice(2);
const chainId = Number(chainIdArgument);
assert(tempo && [42431, 4217].includes(chainId), 'usage: node test-cli-download.mjs <tempo> <42431|4217> [download args]');
const proxy = await createSnapshotProxy();
let directory;
try {
    directory = await mkdtemp(join(tmpdir(), 'tempo-cli-download-'));
    const env = { ...process.env };
    for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'SSL_CERT_DIR']) {
        delete env[name];
        delete env[name.toLowerCase()];
    }
    env.HTTPS_PROXY = proxy.url;
    env.SSL_CERT_FILE = fileURLToPath(new URL('ca.pem', fixtureDirectory));
    env.NO_COLOR = '1';
    const result = await new Promise((resolveExit, rejectExit) => {
        const child = spawn(resolve(tempo), [
            'download', '--datadir', join(directory, 'datadir'), '--archive', '-y',
            '--log.file.directory', join(directory, 'logs'), ...args,
        ], { env, timeout: 60_000, killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'pipe'] });
        let output = '';
        child.stdout.on('data', (chunk) => { output += chunk; });
        child.stderr.on('data', (chunk) => { output += chunk; });
        child.on('error', rejectExit);
        child.on('close', (code, signal) => resolveExit({ code, signal, output }));
    });
    assert.deepEqual(proxy.unexpected, [], 'unexpected proxy requests');
    assert.equal(result.code, 0, `tempo download failed (signal: ${result.signal})\n${result.output}`);
    const expectedPaths = [
        `/${chainId}/manifest.json`, `/${chainId}/state.tar.zst`, `/${chainId}/consensus.tar.zst`,
    ];
    if (!args.includes('--manifest-url')) expectedPaths.unshift('/api/snapshots');
    assert.deepEqual([...new Set(proxy.requests.map((request) => request.path))].sort(), expectedPaths.sort(), 'snapshot request paths');
    for (const path of expectedPaths) {
        assert(proxy.requests.some((request) => request.method === 'GET' && request.path === path), `missing GET ${path}`);
    }
    assert.equal(await readFile(join(directory, 'datadir/db/cli-smoke-test.txt'), 'utf8'), 'execution snapshot fixture\n');
    assert.equal(await readFile(join(directory, 'datadir/consensus/partition/cli-smoke-test.txt'), 'utf8'), 'consensus snapshot fixture\n');
    assert((await stat(join(directory, 'datadir/reth.toml'))).isFile(), 'missing generated reth.toml');
    console.log(`PASS: snapshot ${chainId}; requests: ${proxy.requests.map((request) => `${request.method} ${request.path}`).join(', ')}`);
} catch (error) {
    console.error(error.message);
    console.error(`Observed requests: ${JSON.stringify(proxy.requests)}`);
    process.exitCode = 1;
} finally {
    await proxy.close();
    if (directory) await rm(directory, { recursive: true, force: true });
}
