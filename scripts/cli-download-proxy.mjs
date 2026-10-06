import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';

export const snapshotHost = 'snapshots.tempoxyz.dev';
export const fixtureDirectory = new URL('./fixtures/cli-download/', import.meta.url);

export async function createSnapshotProxy() {
    const manifest = JSON.parse(await readFile(new URL('manifest.json', fixtureDirectory), 'utf8'));
    const routes = new Map();
    const listing = [];
    for (const chainId of [42431, 4217]) {
        listing.push({
            chainId,
            block: 0,
            metadataUrl: `https://${snapshotHost}/${chainId}/manifest.json`,
        });
        routes.set(`/${chainId}/manifest.json`, {
            body: Buffer.from(JSON.stringify({ ...manifest, chain_id: chainId })),
            contentType: 'application/json',
        });
        for (const archive of ['state', 'consensus']) {
            routes.set(`/${chainId}/${archive}.tar.zst`, {
                body: Buffer.from(await readFile(new URL(`${archive}.tar.zst.base64`, fixtureDirectory), 'utf8'), 'base64'),
                contentType: 'application/octet-stream',
            });
        }
    }
    routes.set('/api/snapshots', {
        body: Buffer.from(JSON.stringify(listing)),
        contentType: 'application/json',
    });

    const requests = [];
    const unexpected = [];
    const sockets = new Set();
    const reject = (request, response) => {
        const description = `${request.method} ${request.headers.host ?? ''}${request.url}`;
        unexpected.push(description);
        response.writeHead(502).end(`Unexpected request: ${description}`);
    };
    const httpsServer = createHttpsServer({
        cert: await readFile(new URL('server.pem', fixtureDirectory)),
        key: await readFile(new URL('server.key', fixtureDirectory)),
    }, (request, response) => {
        requests.push({ method: request.method, path: request.url, range: request.headers.range });
        const route = routes.get(request.url);
        if (!route || !['GET', 'HEAD'].includes(request.method) ||
            ![snapshotHost, `${snapshotHost}:443`].includes(request.headers.host)) {
            reject(request, response);
            return;
        }
        const headers = { 'Content-Type': route.contentType, 'Accept-Ranges': 'bytes' };
        let body = route.body;
        let status = 200;
        if (request.headers.range) {
            const range = /^bytes=(\d+)-(\d*)$/.exec(request.headers.range);
            const start = range ? Number(range[1]) : -1;
            const end = range?.[2] ? Math.min(Number(range[2]), body.length - 1) : body.length - 1;
            if (start < 0 || start >= body.length || end < start) {
                response.writeHead(416, { 'Content-Range': `bytes */${body.length}` }).end();
                return;
            }
            headers['Content-Range'] = `bytes ${start}-${end}/${body.length}`;
            body = body.subarray(start, end + 1);
            status = 206;
        }
        response.writeHead(status, { ...headers, 'Content-Length': body.length });
        response.end(request.method === 'HEAD' ? undefined : body);
    });
    const proxy = createServer(reject);
    proxy.on('connection', (socket) => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
    });
    proxy.on('connect', (request, socket, head) => {
        if (request.url !== `${snapshotHost}:443`) {
            unexpected.push(`CONNECT ${request.url}`);
            socket.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
            return;
        }
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length) socket.unshift(head);
        httpsServer.emit('connection', socket);
    });
    await new Promise((resolve, rejectListen) => {
        proxy.once('error', rejectListen);
        proxy.listen(0, '127.0.0.1', resolve);
    });
    return {
        url: `http://127.0.0.1:${proxy.address().port}`,
        requests,
        unexpected,
        async close() {
            for (const socket of sockets) socket.destroy();
            await new Promise((resolve, rejectClose) => proxy.close((error) => error ? rejectClose(error) : resolve()));
        },
    };
}
