import { resolve } from 'node:path'
import { dependency, explorer, zone } from './runtime.mjs'

const { chainId, initialToken } = await zone()
const origin = process.env.PUBLIC_URL ?? `http://127.0.0.1:${process.env.PORT}`
process.env.VITE_TEMPO_ENV = 'zone-prover'
process.env.CLOUDFLARE_ENV = 'zone-prover'
process.env.VITE_BASE_URL = origin
process.env.ALLOWED_HOSTS = new URL(origin).hostname
process.chdir(explorer)
const { createServer, loadConfigFromFile, mergeConfig } = await dependency('vite')
const loaded = await loadConfigFromFile(
  { command: 'serve', mode: 'development' }, resolve(explorer, 'vite.config.ts'),
)
if (!loaded) throw new Error('Explorer Vite configuration could not be loaded')

// Adapt only this pinned dev checkout; leave the shared-network source untouched.
const local = {
  name: 'local-zone',
  enforce: 'pre',
  transform(code, id) {
    const file = id.split('?')[0]
    if (file === resolve(explorer, 'src/lib/zone-prover.ts')) return `
      export const ZONE_PROVER_CHAIN_ID = ${chainId};
      export const ZONE_PROVER_EXPLORER_URL = ${JSON.stringify(origin)};
      export const ZONE_PROVER_RPC_URL = 'http://127.0.0.1:9545';
      export const ZONE_PROVER_TIDX_URL = 'http://127.0.0.1:18080';
    `
    if (file === resolve(explorer, 'src/lib/server/network.ts')) return `
      export function getChainBackend(chainId, kind) {
        if (chainId !== ${chainId}) throw new Error('Only the local zone is configured');
        return { url: kind === 'rpc' ? 'http://127.0.0.1:9545' : 'http://127.0.0.1:18080', headers: {} };
      }
    `
    if (file === resolve(explorer, 'src/lib/server/env.ts'))
      return code.replace('https://api.tempo.xyz', 'http://127.0.0.1:18787')
    if (file === resolve(explorer, 'src/lib/chains.ts'))
      return code.replace('Tempo Prover Devnet', 'Local Tempo Zone')
        .replace('0x20c0000000000000000000000000000000000002', initialToken)
    if (file === resolve(explorer, 'src/lib/fee-token.ts'))
      return code.replace('return FEE_TOKEN_BY_CHAIN_ID[chainId]',
        `return chainId === ${chainId} ? '${initialToken}' : FEE_TOKEN_BY_CHAIN_ID[chainId]`)
  },
}
const server = await createServer(mergeConfig(loaded.config, {
  configFile: false,
  plugins: [local],
  server: {
    host: '127.0.0.1', port: Number(process.env.PORT), strictPort: true,
    allowedHosts: [new URL(origin).hostname],
    proxy: {
      '/api/rpc': { target: 'http://127.0.0.1:9545', changeOrigin: true, rewrite: () => '/' },
    },
  },
}))
await server.listen()
server.printUrls()
