import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { request } from 'node:http';
import { test } from 'node:test';
import { connect } from 'node:tls';

import { createSnapshotProxy, fixtureDirectory, snapshotHost } from './cli-download-proxy.mjs';

const ca = await readFile(new URL('ca.pem', fixtureDirectory));

function throughProxy(proxy, path, { authority = `${snapshotHost}:443`, method = 'GET', headers = {}, trust = true } = {}) {
    return new Promise((resolve, reject) => {
        const tunnel = request(proxy.url, { method: 'CONNECT', path: authority });
        tunnel.on('error', reject);
        tunnel.on('connect', (response, socket, head) => {
            if (response.statusCode !== 200) {
                socket.destroy();
                resolve({ status: response.statusCode });
                return;
            }
            if (head.length) socket.unshift(head);
            const secure = connect({ socket, servername: snapshotHost, ...(trust ? { ca } : {}) });
            const chunks = [];
            secure.on('error', reject);
            secure.on('data', (chunk) => chunks.push(chunk));
            secure.on('end', () => {
                const raw = Buffer.concat(chunks);
                const boundary = raw.indexOf('\r\n\r\n');
                const lines = raw.subarray(0, boundary).toString().split('\r\n');
                resolve({
                    status: Number(lines[0].split(' ')[1]),
                    headers: Object.fromEntries(lines.slice(1).map((line) => {
                        const colon = line.indexOf(':');
                        return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
                    })),
                    body: raw.subarray(boundary + 4),
                });
            });
            secure.on('secureConnect', () => {
                const requestHeaders = { Host: snapshotHost, Connection: 'close', ...headers };
                secure.write(`${method} ${path} HTTP/1.1\r\n${Object.entries(requestHeaders).map(([name, value]) => `${name}: ${value}\r\n`).join('')}\r\n`);
            });
        });
        tunnel.end();
    });
}

test('discovery serves both chains and preserves chain-specific manifests', { timeout: 5000 }, async (context) => {
    const proxy = await createSnapshotProxy();
    context.after(() => proxy.close());
    const listing = await throughProxy(proxy, '/api/snapshots');
    assert.equal(listing.status, 200);
    assert.deepEqual(JSON.parse(listing.body).map((entry) => entry.chainId), [42431, 4217]);
    for (const chainId of [42431, 4217]) {
        const response = await throughProxy(proxy, `/${chainId}/manifest.json`);
        assert.equal(response.status, 200);
        assert.equal(JSON.parse(response.body).chain_id, chainId);
    }
    assert.deepEqual(proxy.unexpected, []);
    assert.deepEqual(proxy.requests.map((entry) => entry.path), ['/api/snapshots', '/42431/manifest.json', '/4217/manifest.json']);
});

test('archive responses support full downloads, HEAD, and byte ranges', { timeout: 5000 }, async (context) => {
    const proxy = await createSnapshotProxy();
    context.after(() => proxy.close());
    const expected = Buffer.from(await readFile(new URL('state.tar.zst.base64', fixtureDirectory), 'utf8'), 'base64');
    const full = await throughProxy(proxy, '/4217/state.tar.zst');
    assert.equal(full.status, 200);
    assert.deepEqual(full.body, expected);
    const partial = await throughProxy(proxy, '/4217/state.tar.zst', { headers: { Range: 'bytes=1-3' } });
    assert.equal(partial.status, 206);
    assert.equal(partial.headers['content-range'], `bytes 1-3/${expected.length}`);
    assert.deepEqual(partial.body, expected.subarray(1, 4));
    const resumed = await throughProxy(proxy, '/4217/state.tar.zst', { headers: { Range: 'bytes=3-' } });
    assert.equal(resumed.status, 206);
    assert.deepEqual(resumed.body, expected.subarray(3));
    const head = await throughProxy(proxy, '/4217/state.tar.zst', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.headers['content-length'], String(expected.length));
    assert.equal(head.body.length, 0);
    const invalid = await throughProxy(proxy, '/4217/state.tar.zst', { headers: { Range: 'bytes=999-' } });
    assert.equal(invalid.status, 416);
    assert.equal(invalid.headers['content-range'], `bytes */${expected.length}`);
});

test('unexpected routes, methods, hosts, and CONNECT targets are rejected', { timeout: 5000 }, async (context) => {
    const proxy = await createSnapshotProxy();
    context.after(() => proxy.close());
    assert.equal((await throughProxy(proxy, '/not-a-fixture')).status, 502);
    assert.equal((await throughProxy(proxy, '/api/snapshots', { method: 'POST' })).status, 502);
    assert.equal((await throughProxy(proxy, '/api/snapshots', { headers: { Host: 'unexpected.invalid' } })).status, 502);
    assert.equal((await throughProxy(proxy, '/', { authority: 'unexpected.invalid:443' })).status, 502);
    assert.deepEqual(proxy.unexpected, [
        `GET ${snapshotHost}/not-a-fixture`, `POST ${snapshotHost}/api/snapshots`,
        'GET unexpected.invalid/api/snapshots', 'CONNECT unexpected.invalid:443',
    ]);
});

test('HTTPS interception still requires trusting the test CA', { timeout: 5000 }, async (context) => {
    const proxy = await createSnapshotProxy();
    context.after(() => proxy.close());
    await assert.rejects(throughProxy(proxy, '/api/snapshots', { trust: false }), {
        code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    });
    assert.deepEqual(proxy.requests, []);
});
