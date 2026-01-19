import * as fs from 'node:fs'
import * as path from 'node:path'
import { Instance } from 'prool'
import { ModuleResolutionKind } from 'typescript'
import autoImport from 'unplugin-auto-import/vite'
import iconsResolver from 'unplugin-icons/resolver'
import icons from 'unplugin-icons/vite'
import { loadEnv } from 'vite'
import { defineConfig } from 'vocs'

function getTipsData() {
  const tipsDir = path.join(process.cwd(), 'pages/protocol/tips')
  if (!fs.existsSync(tipsDir)) return []

  const files = fs
    .readdirSync(tipsDir)
    .filter((file) => file.match(/^tip-\d+\.mdx$/))
    .sort((a, b) => {
      const numA = Number.parseInt(a.match(/tip-(\d+)/)?.[1] ?? '0', 10)
      const numB = Number.parseInt(b.match(/tip-(\d+)/)?.[1] ?? '0', 10)
      return numA - numB
    })

  return files
    .map((file) => {
      const content = fs.readFileSync(path.join(tipsDir, file), 'utf-8')
      const lines = content.split('\n')

      let title = ''
      let tipId = ''
      let status = 'Draft'

      for (const line of lines) {
        const headingMatch = line.match(/^#\s+(?:TIP-\d+:\s*)?(.+)$/)
        if (headingMatch?.[1] && !title) title = headingMatch[1].trim()

        const tipIdMatch = line.match(/\*\*TIP ID\*\*:\s*(TIP-\d+)/)
        if (tipIdMatch?.[1]) tipId = tipIdMatch[1]

        const statusMatch = line.match(/\*\*Status\*\*:\s*(\w+)/)
        if (statusMatch?.[1]) status = statusMatch[1]
      }

      if (!tipId) {
        const m = file.match(/tip-(\d+)/)
        if (m) tipId = `TIP-${m[1]}`
      }

      return {
        id: tipId,
        title,
        status,
        fileName: file,
      }
    })
    .filter((t) => t.id && t.title)
}

export default defineConfig({
  baseUrl: 'https://docs.tempo.xyz',
  head: () => (
    <>
      <meta
        content="width=device-width, initial-scale=1, maximum-scale=1"
        name="viewport"
      />
      {process.env['VERCEL_ENV'] === 'production' ? (
        <meta name="robots" content="index, follow" />
      ) : (
        <meta name="robots" content="noindex, nofollow" />
      )}
      <link rel="icon" href="/favicon.ico" sizes="32x32" />
      <link
        rel="icon"
        type="image/svg+xml"
        href="/favicon-light.svg"
        media="(prefers-color-scheme: light)"
      />
      <link
        rel="icon"
        type="image/svg+xml"
        href="/favicon-dark.svg"
        media="(prefers-color-scheme: dark)"
      />
      <link
        rel="icon"
        type="image/png"
        sizes="32x32"
        href="/favicon-32x32-light.png"
        media="(prefers-color-scheme: dark)"
      />
      <link
        rel="icon"
        type="image/png"
        sizes="32x32"
        href="/favicon-32x32-dark.png"
        media="(prefers-color-scheme: light)"
      />
      <link
        rel="icon"
        type="image/png"
        sizes="16x16"
        href="/favicon-16x16-light.png"
        media="(prefers-color-scheme: dark)"
      />
      <link
        rel="icon"
        type="image/png"
        sizes="16x16"
        href="/favicon-16x16-dark.png"
        media="(prefers-color-scheme: light)"
      />
      <link
        rel="apple-touch-icon"
        sizes="180x180"
        href="/favicon-light.png"
        media="(prefers-color-scheme: light)"
      />
      <link
        rel="apple-touch-icon"
        sizes="180x180"
        href="/favicon-dark.png"
        media="(prefers-color-scheme: dark)"
      />
      {process.env['VERCEL_ENV'] === 'production' && (
        <script src="/ph.js" type="text/javascript" />
      )}
    </>
  ),
  ogImageUrl: {
    '/': 'https://docs.tempo.xyz/og-docs.png',
    '/learn': 'https://docs.tempo.xyz/api/og?title=%title&description=%description',
    '/quickstart': 'https://docs.tempo.xyz/api/og?title=%title&description=%description',
    '/guide': 'https://docs.tempo.xyz/api/og?title=%title&description=%description',
    '/protocol': 'https://docs.tempo.xyz/api/og?title=%title&description=%description',
    '/sdk': 'https://docs.tempo.xyz/api/og?title=%title&description=%description',
  },
  title: 'Tempo',
  titleTemplate: '%s | Tempo Docs',
  description: 'Documentation for Tempo testnet and protocol specifications',
  logoUrl: {
    light: '/lockup-light.svg',
    dark: '/lockup-dark.svg',
  },
  iconUrl: {
    light: '/icon-light.png',
    dark: '/icon-dark.png',
  },
  rootDir: '.',
  banner: {
    content: (
      <div>
        <strong>Testnet migration:</strong> We've launched a new testnet. You'll
        need to update your RPC configuration and redeploy any contracts. The
        old testnet will be deprecated on March 8th.{' '}
        <a href="/network-upgrades" style={{ textDecoration: 'underline' }}>
          Learn more →
        </a>
      </div>
    ),
    dismissable: true,
  },
  socials: [
    {
      icon: 'github',
      link: 'https://github.com/tempoxyz',
    },
    {
      icon: 'x',
      link: 'https://twitter.com/tempo',
    },
  ],
  sidebar: {
    '/': [
      {
        text: 'Home',
        link: '/',
      },
      {
        text: 'Integrate Tempo Testnet',
        items: [
          {
            text: 'Overview',
            link: '/quickstart/integrate-tempo',
          },
          {
            text: 'Network Upgrades',
            link: '/network-upgrades',
          },
          {
            text: 'Connect to the Network',
            link: '/quickstart/connection-details',
          },
          {
            text: 'Get Faucet Funds',
            link: '/quickstart/faucet',
          },
          {
            text: 'Developer Tools',
            link: '/quickstart/developer-tools',
          },
          {
            text: 'EVM Differences',
            link: '/quickstart/evm-compatibility',
          },
          {
            text: 'Predeployed Contracts',
            link: '/quickstart/predeployed-contracts',
          },
          {
            text: 'Wallet Developers',
            link: '/quickstart/wallet-developers',
          },
        ],
      },
      {
        text: 'Start Building on Tempo',
        items: [
          {
            text: 'Use Tempo Transactions',
            link: '/guide/tempo-transaction',
          },
          {
            text: 'Create & Use Accounts',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/guide/use-accounts',
              },
              {
                text: 'Embed Passkey accounts',
                link: '/guide/use-accounts/embed-passkeys',
              },
              {
                text: 'Connect to wallets',
                link: '/guide/use-accounts/connect-to-wallets',
              },
              {
                text: 'Add funds to your balance',
                link: '/guide/use-accounts/add-funds',
              },
            ],
          },
          {
            text: 'Make Payments',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/guide/payments',
              },
              {
                text: 'Send a payment',
                link: '/guide/payments/send-a-payment',
              },
              {
                text: 'Accept a payment',
                link: '/guide/payments/accept-a-payment',
              },
              {
                text: 'Attach a transfer memo',
                link: '/guide/payments/transfer-memos',
              },
              {
                text: 'Pay fees in any stablecoin',
                link: '/guide/payments/pay-fees-in-any-stablecoin',
              },
              {
                text: 'Sponsor user fees',
                link: '/guide/payments/sponsor-user-fees',
              },
              {
                text: 'Send parallel transactions',
                link: '/guide/payments/send-parallel-transactions',
              },
              // {
              //   text: 'Start a subscription 🚧',
              //   disabled: true,
              //   link: '/guide/payments/start-a-subscription',
              // },
              // {
              //   text: 'Private payments 🚧',
              //   disabled: true,
              //   link: '/guide/payments/private-payments',
              // },
            ],
          },
          {
            text: 'Issue Stablecoins',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/guide/issuance',
              },
              {
                text: 'Create a stablecoin',
                link: '/guide/issuance/create-a-stablecoin',
              },
              {
                text: 'Mint stablecoins',
                link: '/guide/issuance/mint-stablecoins',
              },
              {
                text: 'Use your stablecoin for fees',
                link: '/guide/issuance/use-for-fees',
              },
              {
                text: 'Distribute rewards',
                link: '/guide/issuance/distribute-rewards',
              },
              {
                text: 'Manage your stablecoin',
                link: '/guide/issuance/manage-stablecoin',
              },
            ],
          },
          {
            text: 'Exchange Stablecoins',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/guide/stablecoin-dex',
              },
              {
                text: 'Managing fee liquidity',
                link: '/guide/stablecoin-dex/managing-fee-liquidity',
              },
              {
                text: 'Executing swaps',
                link: '/guide/stablecoin-dex/executing-swaps',
              },
              {
                text: 'View the orderbook',
                link: '/guide/stablecoin-dex/view-the-orderbook',
              },
              {
                text: 'Providing liquidity',
                link: '/guide/stablecoin-dex/providing-liquidity',
              },
            ],
          },
        ],
      },
      {
        text: 'Tempo Protocol Specs',
        items: [
          {
            text: 'Overview',
            link: '/protocol',
          },
          {
            text: 'TIP-20 Tokens',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/protocol/tip20/overview',
              },
              {
                text: 'Specification',
                link: '/protocol/tip20/spec',
              },
              {
                text: 'Reference Implementation',
                link: 'https://github.com/tempoxyz/tempo/blob/main/docs/specs/src/TIP20.sol',
              },
              {
                text: 'Rust Implementation',
                link: 'https://github.com/tempoxyz/tempo/tree/main/crates/precompiles/src/tip20',
              },
            ],
          },
          {
            text: 'TIP-20 Rewards',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/protocol/tip20-rewards/overview',
              },
              {
                text: 'Specification',
                link: '/protocol/tip20-rewards/spec',
              },
            ],
          },
          {
            text: 'TIP-403 Policies',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/protocol/tip403/overview',
              },
              {
                text: 'Specification',
                link: '/protocol/tip403/spec',
              },
              {
                text: 'Reference Implementation',
                link: 'https://github.com/tempoxyz/tempo/blob/main/docs/specs/src/TIP403Registry.sol',
              },
              {
                text: 'Rust Implementation',
                link: 'https://github.com/tempoxyz/tempo/tree/main/crates/precompiles/src/tip403_registry',
              },
            ],
          },
          {
            text: 'Fees',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/protocol/fees',
              },
              {
                text: 'Specification',
                link: '/protocol/fees/spec-fee',
              },
              {
                text: 'Fee AMM',
                collapsed: true,
                items: [
                  {
                    text: 'Overview',
                    link: '/protocol/fees/fee-amm',
                  },
                  {
                    text: 'Specification',
                    link: '/protocol/fees/spec-fee-amm',
                  },
                  {
                    text: 'Reference Implementation',
                    link: 'https://github.com/tempoxyz/tempo/blob/main/docs/specs/src/FeeManager.sol',
                  },
                  {
                    text: 'Rust Implementation',
                    link: 'https://github.com/tempoxyz/tempo/tree/main/crates/precompiles/src/tip_fee_manager',
                  },
                ],
              },
            ],
          },
          {
            text: 'Tempo Transactions',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/protocol/transactions',
              },
              {
                text: 'Specification',
                link: '/protocol/transactions/spec-tempo-transaction',
              },
              {
                text: 'Account Keychain Precompile Specification',
                link: '/protocol/transactions/AccountKeychain',
              },
              {
                text: 'Rust Implementation',
                link: 'https://github.com/tempoxyz/tempo/blob/main/crates/primitives/src/transaction/tempo_transaction.rs',
              },
            ],
          },
          {
            text: 'Blockspace',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/protocol/blockspace/overview',
              },
              {
                text: 'Payment Lane Specification',
                link: '/protocol/blockspace/payment-lane-specification',
              },
              {
                text: 'Subblock Specification',
                link: '/protocol/blockspace/subblock-specification',
              },
            ],
          },
          {
            text: 'Stablecoin DEX',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/protocol/exchange',
              },
              {
                text: 'Specification',
                link: '/protocol/exchange/spec',
              },
              {
                text: 'pathUSD',
                link: '/protocol/exchange/pathUSD',
              },
              {
                text: 'Executing Swaps',
                link: '/protocol/exchange/executing-swaps',
              },
              {
                text: 'Providing Liquidity',
                link: '/protocol/exchange/providing-liquidity',
              },
              {
                text: 'DEX Balance',
                link: '/protocol/exchange/exchange-balance',
              },
              {
                text: 'Reference Implementation',
                link: 'https://github.com/tempoxyz/tempo/blob/main/docs/specs/src/StablecoinExchange.sol',
              },
              {
                text: 'Rust Implementation',
                link: 'https://github.com/tempoxyz/tempo/tree/main/crates/precompiles/src/stablecoin_exchange',
              },
            ],
          },
          {
            text: 'TIPs',
            link: '/protocol/tips',
          },
        ],
      },
      {
        text: 'Tempo SDKs',
        collapsed: true,
        items: [
          {
            text: 'Overview',
            link: '/sdk',
          },
          {
            text: 'TypeScript',
            link: '/sdk/typescript',
            collapsed: true,
            items: [
              {
                text: 'Overview',
                link: '/sdk/typescript',
              },
              {
                text: 'Viem Reference',
                link: 'https://viem.sh/tempo',
              },
              {
                text: 'Wagmi Reference',
                link: 'https://wagmi.sh/tempo',
              },
              {
                text: 'Server Reference',
                items: [
                  {
                    text: 'Handlers',
                    items: [
                      {
                        text: 'Overview',
                        link: '/sdk/typescript/server/handlers',
                      },
                      {
                        text: 'compose',
                        link: '/sdk/typescript/server/handler.compose',
                      },
                      {
                        text: 'feePayer',
                        link: '/sdk/typescript/server/handler.feePayer',
                      },
                      {
                        text: 'keyManager',
                        link: '/sdk/typescript/server/handler.keyManager',
                      },
                    ],
                  },
                ],
              },
              {
                text: 'Prool Reference',
                items: [
                  {
                    text: 'Setup',
                    link: '/sdk/typescript/prool/setup',
                  },
                ],
              },
            ],
          },
          {
            text: 'Go',
            link: '/sdk/go',
          },
          {
            text: 'Foundry',
            link: '/sdk/foundry',
          },
          {
            text: 'Rust',
            link: '/sdk/rust',
          },
        ],
      },
      {
        text: 'Run a Tempo Node',
        collapsed: true,
        items: [
          {
            text: 'Overview',
            link: '/guide/node',
          },
          {
            text: 'System Requirements',
            link: '/guide/node/system-requirements',
          },
          {
            text: 'Installation',
            link: '/guide/node/installation',
          },
          {
            text: 'Running an RPC Node',
            link: '/guide/node/rpc',
          },
          {
            text: 'Running a validator',
            link: '/guide/node/validator',
          },
        ],
      },
      // {
      //   text: 'Infrastructure & Tooling',
      //   items: [
      //     {
      //       text: 'Overview',
      //       link: '/guide/infrastructure',
      //     },
      //     {
      //       text: 'Data Indexers',
      //       link: '/guide/infrastructure/data-indexers',
      //     },
      //     {
      //       text: 'Developer Tools',
      //       link: '/guide/infrastructure/developer-tools',
      //     },
      //     {
      //       text: 'Node Providers',
      //       link: '/guide/infrastructure/node-providers',
      //     },
      //   ],
      // },
    ],
    '/learn': [
      {
        text: 'Home',
        link: '/learn',
      },
      {
        text: 'Partners',
        link: '/learn/partners',
      },
      {
        text: 'Blog',
        link: 'https://tempo.xyz/blog',
      },
      {
        text: 'Stablecoins',
        items: [
          {
            text: 'Overview',
            link: '/learn/stablecoins',
          },
          {
            text: 'Remittances',
            link: '/learn/use-cases/remittances',
          },
          {
            text: 'Global Payouts',
            link: '/learn/use-cases/global-payouts',
          },
          {
            text: 'Embedded Finance',
            link: '/learn/use-cases/embedded-finance',
          },
          {
            text: 'Tokenized Deposits',
            link: '/learn/use-cases/tokenized-deposits',
          },
          {
            text: 'Microtransactions',
            link: '/learn/use-cases/microtransactions',
          },
          {
            text: 'Agentic Commerce',
            link: '/learn/use-cases/agentic-commerce',
          },
        ],
      },
      {
        text: 'Tempo',
        items: [
          {
            text: 'Overview',
            link: '/learn/tempo',
          },
          {
            text: 'Native Stablecoins',
            link: '/learn/tempo/native-stablecoins',
          },
          {
            text: 'Modern Transactions',
            link: '/learn/tempo/modern-transactions',
          },
          {
            text: 'Performance',
            link: '/learn/tempo/performance',
          },
          {
            text: 'Onchain FX',
            link: '/learn/tempo/fx',
          },
          {
            text: 'Privacy',
            link: '/learn/tempo/privacy',
          },
        ],
      },
    ],
  },
  topNav: [
    { text: 'Learn', link: '/learn' },
    {
      text: 'Docs',
      link: '/',
      match(path) {
        if (path.startsWith('/learn')) return false
        return true
      },
    },
    { text: 'Ecosystem', link: 'https://tempo.xyz/ecosystem' },
    { text: 'Blog', link: 'https://tempo.xyz/blog' },
  ],
  twoslash:
    // biome-ignore lint/style/noNonNullAssertion: _
    process.env['DISABLE_TWOSLASH']! === 'true'
      ? false
      : {
          compilerOptions: {
            moduleResolution: ModuleResolutionKind.Bundler,
          },
        },
  vite: {
    plugins: [
      {
        name: 'virtual-tips',
        resolveId(id) {
          if (id === 'virtual:tips-data') return '\0virtual:tips-data'
          return undefined
        },
        load(id) {
          if (id === '\0virtual:tips-data') {
            const tips = getTipsData()
            return `export const tips = ${JSON.stringify(tips)}`
          }
          return undefined
        },
      },
      {
        name: 'tempo-node',
        async configureServer(_server) {
          if (
            !('VITE_ENVIRONMENT' in process.env) ||
            process.env['VITE_ENVIRONMENT'] !== 'local'
          )
            return
          const instance = Instance.tempo({
            dev: { blockTime: '500ms' },
            port: 8545,
          })
          console.log('→ starting tempo node...')
          await instance.start()
          console.log('√ tempo node started on port 8545')
        },
      },
      {
        name: 'api-routes',
        configureServer(server) {
          const env = loadEnv(server.config.mode, process.cwd(), '')

          // Set process.env for development
          Object.keys(env).forEach((key) => {
            if (process.env[key] === undefined) {
              process.env[key] = env[key]
            }
          })

          server.middlewares.use(async (req, res, next) => {
            if (req.url === '/api/index-supply' && req.method === 'POST') {
              try {
                let body = ''
                req.on('data', (chunk) => {
                  body += chunk.toString()
                })

                await new Promise((resolve) => {
                  req.on('end', resolve)
                })

                const parsedBody = JSON.parse(body)

                // Import and execute the index supply serverless function
                const handler = (await import('./api/index-supply.js')).default

                const mockRes = {
                  statusCode: 200,
                  headers: {} as Record<string, string>,
                  setHeader(key: string, value: string) {
                    this.headers[key] = value
                    return this
                  },
                  status(code: number) {
                    this.statusCode = code
                    return this
                  },
                  json(data: unknown) {
                    res.setHeader('Content-Type', 'application/json')
                    res.statusCode = this.statusCode
                    Object.entries(this.headers).forEach(([key, value]) => {
                      res.setHeader(key, value)
                    })
                    res.end(JSON.stringify(data))
                    return this
                  },
                  end() {
                    res.end()
                    return this
                  },
                }

                const mockReq = {
                  method: req.method,
                  headers: req.headers as Record<string, string>,
                  body: parsedBody,
                }

                // biome-ignore lint/suspicious/noExplicitAny: Local mock request
                await handler(mockReq as any, mockRes as any)
              } catch (error) {
                console.error('API route error:', error)
                res.statusCode = 500
                res.setHeader('Content-Type', 'application/json')
                res.end(
                  JSON.stringify({
                    error:
                      error instanceof Error
                        ? error.message
                        : 'Internal server error',
                  }),
                )
              }
              return
            }
            next()
          })
        },
      },
      icons({ compiler: 'jsx', jsx: 'react' }),
      autoImport({
        dts: './auto-imports.d.ts',
        dirs: ['components'],
        resolvers: [
          iconsResolver({
            enabledCollections: [
              // https://icones.js.org/collection/lucide
              'lucide',
            ],
            extension: 'jsx',
            prefix: false,
          }),
        ],
      }),
    ],
  },
})
