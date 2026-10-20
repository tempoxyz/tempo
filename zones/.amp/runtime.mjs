import { readFile, writeFile, access } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

export const root = resolve(import.meta.dirname, '..')
export const explorer = resolve(root, '.amp/deps/tempo-apps/apps/explorer')
const require = createRequire(resolve(explorer, 'package.json'))
export const dependency = (name) => import(pathToFileURL(require.resolve(name)).href)
export const zone = async () => JSON.parse(await readFile(resolve(root, '.amp/state/zone/zone.json'), 'utf8'))

async function rpc(url, method = 'eth_chainId', params = []) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(2000),
  })
  const body = await response.json()
  if (!response.ok || !body.result) throw new Error(`RPC unavailable: ${url}`)
  return body.result
}

if (process.argv[1] === import.meta.filename) {
  const [command, url] = process.argv.slice(2)
  if (command === 'seed-l1') {
    const path = resolve(root, '.amp/state/l1.json')
    try { await access(path); process.exit(0) } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    // Anvil's --init conflicts with --state. Seed its state format
    // once so later launches can restore blocks, receipts, and historical state.
    const genesis = JSON.parse(await readFile(resolve(root, '.amp/deps/l1-genesis.json'), 'utf8'))
    const accounts = Object.fromEntries(Object.entries(genesis.alloc).map(([address, account]) => [address, {
      nonce: Number(BigInt(account.nonce ?? 0)), balance: account.balance ?? '0x0',
      code: account.code ?? '0x', storage: account.storage ?? {},
    }]))
    await writeFile(path, JSON.stringify({ block: null, best_block_number: null, accounts }), { flag: 'wx' })
  } else if (command === 'ready') {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2000) })
      process.exit(response.ok ? 0 : 1)
    } catch { process.exit(1) }
  } else if (command === 'wait-rpc') {
    let ready = false
    for (let attempt = 0; attempt < 120; attempt++) {
      try { await rpc(url); ready = true; break } catch {}
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }
    if (!ready) throw new Error(`Timed out waiting for ${url}`)
  } else if (command === 'validate-zone') {
    const metadata = await zone()
    const code = await rpc('http://127.0.0.1:8545', 'eth_getCode', [metadata.portal, 'latest'])
    if (code === '0x') throw new Error('Saved zone portal is missing on L1; restore matching L1, zone, and indexer state')
  } else if (command === 'tidx-config') {
    const chainId = Number(BigInt(await rpc('http://127.0.0.1:9545')))
    if (chainId !== (await zone()).chainId) throw new Error('Zone metadata and RPC chain IDs differ')
    // Wait for PostgreSQL to accept queries, not just open its socket.
    const { Db } = await dependency('tapimo')
    const db = Db.postgres({ connectionString: 'postgres://orb:orb@127.0.0.1:15432/orb' })
    for (let attempt = 0; ; attempt++) {
      try { await db.migrate(); break } catch (error) {
        if (attempt === 119) throw error
        await new Promise((resolve) => setTimeout(resolve, 1000))
      }
    }
    await db.close()
    await writeFile(resolve(root, '.amp/state/tidx.toml'), `
[http]
enabled = true
bind = "127.0.0.1"
port = ${Number(process.env.PORT)}
[prometheus]
enabled = false
[[chains]]
name = "orb-zone"
chain_id = ${chainId}
rpc_url = "http://127.0.0.1:9545"
backfill = true
batch_size = 25
concurrency = 2
[chains.postgres]
url = "postgres://orb:orb@127.0.0.1:15432/orb_tidx"
[chains.clickhouse]
enabled = true
url = "http://127.0.0.1:18123"
`)
  } else throw new Error(`Unknown command: ${command}`)
}
