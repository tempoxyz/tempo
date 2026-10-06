import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { ethers } from 'ethers';
import { SCALAR_FIELD, signatureNonce, stableSalt, tokenWitness, zkAddress } from './oidc.mjs';
import { circuitInput } from './witness.mjs';
import { proofBytes } from './protocol.mjs';

export async function googleKeys() {
  const response = await fetch('https://accounts.google.com/.well-known/openid-configuration', { signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error('Google discovery failed');
  const metadata = await response.json();
  if (metadata.issuer !== 'https://accounts.google.com' || metadata.jwks_uri !== 'https://www.googleapis.com/oauth2/v3/certs') throw new Error('Unexpected Google discovery endpoints');
  const keys = await fetch(metadata.jwks_uri, { signal: AbortSignal.timeout(10000) });
  if (!keys.ok) throw new Error('Google JWKS retrieval failed');
  const jwks = await keys.json();
  if (!Array.isArray(jwks.keys)) throw new Error('Invalid Google JWKS');
  return jwks;
}

export function createRelay({ clientId, publisherId, saltSecret, artifacts, port = 8080, issuer = 'https://accounts.google.com', keys = googleKeys, prover, clock = () => Math.floor(Date.now()/1000) }) {
  if (!clientId || !/^0x[\da-fA-F]{64}$/.test(publisherId) || !Buffer.isBuffer(saltSecret) || saltSecret.length < 32) throw new Error('Configure a client ID, trusted publisher ID, and durable salt secret');
  const challenges = new Map();
  let busy = false;
  const origin = `http://127.0.0.1:${port}`;
  const source = path.dirname(fileURLToPath(import.meta.url));
  const prove = prover ?? (async input => {
    const result = await snarkjs.groth16.fullProve(input,path.join(artifacts,'oidc_js/oidc.wasm'),path.join(artifacts,'devnet.zkey'));
    const vk = JSON.parse(await readFile(path.join(artifacts,'vk.json'),'utf8'));
    if (result.publicSignals.length !== 1 || result.publicSignals[0] !== input.public_input || !await snarkjs.groth16.verify(vk,result.publicSignals,result.proof)) throw new Error('Generated proof did not verify');
    return result.proof;
  });
  return createServer(async (request,response) => {
    response.setHeader('Cache-Control','no-store');
    response.setHeader('X-Content-Type-Options','nosniff');
    response.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
    const json = (status,value) => { response.writeHead(status,{'Content-Type':'application/json'}); response.end(JSON.stringify(value)); };
    try {
      if (request.headers.host !== `127.0.0.1:${port}`) return json(403,{ error:'Unexpected Host' });
      if (request.method === 'POST' && (request.headers.origin !== origin || !request.headers['content-type']?.startsWith('application/json'))) return json(403,{error:'Same-origin JSON required'});
      const url = new URL(request.url,origin);
      for (const [id,challenge] of challenges) if (challenge.validUntil < clock()) challenges.delete(id);
      if (request.method === 'GET' && url.pathname === '/config') return json(200,{clientId,publisherId,issuer,chainId:1337,origin,now:clock(),synthetic:false});
      const staticFiles = new Map([['/','index.html'],['/browser.mjs','browser.mjs'],['/ethers.js','node_modules/ethers/dist/ethers.min.js']]);
      if (request.method === 'GET' && staticFiles.has(url.pathname)) {
        const body = await readFile(path.join(source,staticFiles.get(url.pathname)));
        response.writeHead(200,{'Content-Type':url.pathname === '/' ? 'text/html' : 'text/javascript', 'Content-Security-Policy':"default-src 'self'; script-src 'self' https://accounts.google.com/gsi/client; frame-src https://accounts.google.com; connect-src 'self' https://accounts.google.com; style-src 'self' https://accounts.google.com; object-src 'none'; base-uri 'none'"});
        response.end(body); return;
      }
      if (request.method !== 'POST' || !['/challenge','/prove','/rpc'].includes(url.pathname)) return json(404,{error:'Not found'});
      let body = '';
      for await (const chunk of request) { body += chunk; if (body.length > (url.pathname === '/rpc' ? 16384 : 4096)) throw new Error('Request too large'); }
      const input = JSON.parse(body);
      if (url.pathname === '/rpc') {
        const methods = new Set(['eth_chainId','eth_blockNumber','eth_getTransactionCount','eth_getTransactionReceipt','eth_getBlockByNumber','eth_call','eth_sendRawTransaction','eth_getBalance','eth_getTransactionByHash']);
        const batch = Array.isArray(input) ? input : [input];
        if (batch.length > 10 || batch.some(item => !methods.has(item.method))) throw new Error('RPC method not allowed');
        const check = await fetch('http://127.0.0.1:8545',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]}),signal:AbortSignal.timeout(5000)});
        if ((await check.json()).result !== '0x539') throw new Error('RPC must be private chain 1337');
        const upstream = await fetch('http://127.0.0.1:8545',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input),signal:AbortSignal.timeout(15000)});
        return json(upstream.status,await upstream.json());
      }
      if (url.pathname === '/challenge') {
        if (!ethers.isAddress(input.accessKey) || challenges.size >= 100) throw new Error('Invalid access key or challenge capacity exceeded');
        const id = randomBytes(32).toString('hex');
        const challenge = { accessKeyId:BigInt(input.accessKey), validUntil:clock()+540, blinding:BigInt(`0x${randomBytes(32).toString('hex')}`)%SCALAR_FIELD };
        challenges.set(id,challenge);
        return json(200,{id,nonce:await signatureNonce(challenge.accessKeyId,challenge.validUntil,challenge.blinding),validUntil:challenge.validUntil});
      }
      const challenge = challenges.get(input.id);
      if (!challenge || challenge.validUntil < clock()) throw new Error('Unknown, consumed, or expired challenge');
      if (busy) return json(429,{error:'Prover busy'});
      if (typeof input.token !== 'string' || input.token.length > 2048) throw new Error('Invalid token');
      busy = true;
      try {
      const [header,payload] = input.token.split('.');
      const untrustedHeader = JSON.parse(Buffer.from(header,'base64url'));
      const untrustedClaims = JSON.parse(Buffer.from(payload,'base64url'));
      const jwks = await keys();
      const jwk = jwks.keys.find(key => key.kid === untrustedHeader.kid && key.kty === 'RSA' && (!key.use || key.use === 'sig') && (!key.alg || key.alg === 'RS256'));
      if (!jwk || untrustedHeader.alg !== 'RS256') throw new Error('Untrusted signing key or algorithm');
      const salt = stableSalt(saltSecret,issuer,clientId,untrustedClaims.sub);
      const witness = await tokenWitness({ token:input.token,jwk,salt,blinding:challenge.blinding,accessKeyId:challenge.accessKeyId,validUntil:challenge.validUntil,now:clock(),expectedIssuer:issuer,expectedAudience:clientId });
      challenges.delete(input.id);
        const signals = circuitInput(witness);
        const proof = await prove(signals);
        if (clock() > challenge.validUntil) throw new Error('Proof completed after challenge expiry');
        return json(200,{ input: { issuer:signals.issuer,key_hash:signals.key_hash,address_seed:signals.address_seed,issued_at:signals.issued_at,commit_b:signals.commit_b,commit_a:signals.commit_a,public_input:signals.public_input }, proof:proofBytes(proof), account:zkAddress(publisherId,witness.issuer,witness.addressSeed),publisherId });
      } finally { busy = false; }
    } catch {
      if (!response.headersSent) json(400,{error:'Request rejected; token, identity, and witness details are never returned in errors'});
      else response.end();
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const artifacts = process.env.OIDC_ARTIFACTS;
  const saltSecret = await readFile(process.env.OIDC_SALT_FILE ?? '');
  const port = Number(process.env.OIDC_PORT ?? 8080);
  if (!artifacts || !Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Configure OIDC_ARTIFACTS and a valid local port');
  const server = createRelay({clientId:process.env.OIDC_CLIENT_ID,publisherId:process.env.OIDC_PUBLISHER_ID,saltSecret,artifacts,port});
  server.listen(port,'127.0.0.1',() => console.log(`Unaudited private OIDC demo: http://127.0.0.1:${port}. Do not use real funds.`));
}
