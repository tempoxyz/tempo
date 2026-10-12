import { createServer } from 'node:http'
import { dependency, zone } from './runtime.mjs'

const { App, Db } = await dependency('tapimo')
const { data } = await dependency('tapimo/apps')
const { chainId } = await zone()
const db = Db.postgres({ connectionString: 'postgres://orb:orb@127.0.0.1:15432/orb' })
await db.migrate()
const app = App.create({
  auth: false,
  db,
  defaultChainId: chainId,
  rpc: { url: 'http://127.0.0.1:9545' },
  supportedChainIds: [chainId],
}).route('/', data({
  tidx: { baseUrl: 'http://127.0.0.1:18080' },
  verifiedTokens: false,
  webhook: false,
  zones: [],
}))
createServer(App.listener(app)).listen(Number(process.env.PORT), '127.0.0.1')
