import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Instance } from 'prool'
import { ModuleResolutionKind } from 'typescript'
import autoImport from 'unplugin-auto-import/vite'
import iconsResolver from 'unplugin-icons/resolver'
import icons from 'unplugin-icons/vite'
import { loadEnv } from 'vite'
import { defineConfig } from 'vocs'

const twoslashSupportFile = readFileSync(
  join(process.cwd(), 'snippets', 'twoslash-env.d.ts'),
  'utf-8',
)

export default defineConfig({
  head() {
    return (
      <>
        <meta
          content="width=device-width, initial-scale=1, maximum-scale=1"
          name="viewport"
        />
        <meta content="Documentation ⋅ Tempo" property="og:title" />
        <meta content="/og-docs.png" property="og:image" />
        <meta content="image/png" property="og:image:type" />
        <meta content="1200" property="og:image:width" />
        <meta content="630" property="og:image:height" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="Documentation ⋅ Tempo" />
        <meta name="twitter:image" content="/og-docs.png" />
        <link rel="icon" href="/favicon.ico" sizes="32x32" />
        <link rel="icon" type="image/svg+xml" href="/favicon-light.svg" media="(prefers-color-scheme: light)" />
        <link rel="icon" type="image/svg+xml" href="/favicon-dark.svg" media="(prefers-color-scheme: dark)" />
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32-light.png" media="(prefers-color-scheme: dark)" />
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32-dark.png" media="(prefers-color-scheme: light)" />
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16-light.png" media="(prefers-color-scheme: dark)" />
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16-dark.png" media="(prefers-color-scheme: light)" />
        <link rel="apple-touch-icon" sizes="180x180" href="/favicon-light.png" media="(prefers-color-scheme: light)" />
        <link rel="apple-touch-icon" sizes="180x180" href="/favicon-dark.png" media="(prefers-color-scheme: dark)" />
      </>
    )
  },
  title: 'Documentation ⋅ Tempo',
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
        ],
      },
      {
        text: 'Start Building on Tempo',
        items: [
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
                link: '/guide/stablecoin-exchange',
              },
              {
                text: 'Managing fee liquidity',
                link: '/guide/stablecoin-exchange/managing-fee-liquidity',
              },
              {
                text: 'Executing swaps',
                link: '/guide/stablecoin-exchange/executing-swaps',
              },
              {
                text: 'View the orderbook',
                link: '/guide/stablecoin-exchange/view-the-orderbook',
              },
              {
                text: 'Providing liquidity',
                link: '/guide/stablecoin-exchange/providing-liquidity',
              },
            ],
          },
          {
            text: 'Wallet Developers',
            link: '/guide/wallet-developers',
          }
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
                text: 'Default Delegation Specification',
                link: '/protocol/transactions/spec-default-delegation',
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
                text: 'Sub-block Specification',
                link: '/protocol/blockspace/sub-block-specification',
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
            text: 'Running the Node',
            link: '/guide/node/usage',
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
    '/sdk/typescript': {
      backLink: true,
      items: [
        {
          text: 'Overview',
          link: '/sdk/typescript',
        },
        {
          text: 'Viem Reference',
          items: [
            {
              text: 'Setup',
              link: '/sdk/typescript/viem/setup',
            },
            {
              text: 'Accounts',
              collapsed: true,
              items: [
                {
                  text: 'Overview',
                  link: '/sdk/typescript/viem/accounts',
                },
                {
                  text: 'fromWebAuthnP256',
                  link: '/sdk/typescript/viem/account.fromWebAuthnP256',
                },
                {
                  text: 'fromWebCryptoP256',
                  link: '/sdk/typescript/viem/account.fromWebCryptoP256',
                },
                {
                  text: 'fromSecp256k1',
                  link: '/sdk/typescript/viem/account.fromSecp256k1',
                },
                {
                  text: 'fromP256',
                  link: '/sdk/typescript/viem/account.fromP256',
                },
              ],
            },
            {
              text: 'Actions',
              collapsed: true,
              items: [
                {
                  text: 'Overview',
                  link: '/sdk/typescript/viem/actions',
                },
                {
                  text: 'AMM',
                  items: [
                    {
                      text: 'burn',
                      link: '/sdk/typescript/viem/amm.burn',
                    },
                    {
                      text: 'getLiquidityBalance',
                      link: '/sdk/typescript/viem/amm.getLiquidityBalance',
                    },
                    {
                      text: 'getPool',
                      link: '/sdk/typescript/viem/amm.getPool',
                    },
                    {
                      text: 'mint',
                      link: '/sdk/typescript/viem/amm.mint',
                    },
                    {
                      text: 'rebalanceSwap',
                      link: '/sdk/typescript/viem/amm.rebalanceSwap',
                    },
                    {
                      text: 'watchBurn',
                      link: '/sdk/typescript/viem/amm.watchBurn',
                    },
                    {
                      text: 'watchFeeSwap',
                      link: '/sdk/typescript/viem/amm.watchFeeSwap',
                    },
                    {
                      text: 'watchMint',
                      link: '/sdk/typescript/viem/amm.watchMint',
                    },
                    {
                      text: 'watchRebalanceSwap',
                      link: '/sdk/typescript/viem/amm.watchRebalanceSwap',
                    },
                  ],
                },
                {
                  text: 'Fee',
                  items: [
                    {
                      text: 'getUserToken',
                      link: '/sdk/typescript/viem/fee.getUserToken',
                    },
                    {
                      text: 'setUserToken',
                      link: '/sdk/typescript/viem/fee.setUserToken',
                    },
                    {
                      text: 'watchSetUserToken',
                      link: '/sdk/typescript/viem/fee.watchSetUserToken',
                    },
                  ],
                },
                {
                  text: 'Nonce',
                  items: [
                    {
                      text: 'getNonce',
                      link: '/sdk/typescript/viem/nonce.getNonce',
                    },
                    {
                      text: 'getNonceKeyCount',
                      link: '/sdk/typescript/viem/nonce.getNonceKeyCount',
                    },
                    {
                      text: 'watchActiveKeyCountChanged',
                      link: '/sdk/typescript/viem/nonce.watchActiveKeyCountChanged',
                    },
                    {
                      text: 'watchNonceIncremented',
                      link: '/sdk/typescript/viem/nonce.watchNonceIncremented',
                    },
                  ],
                },
                {
                  text: 'Policy',
                  items: [
                    {
                      text: 'create',
                      link: '/sdk/typescript/viem/policy.create',
                    },
                    {
                      text: 'getData',
                      link: '/sdk/typescript/viem/policy.getData',
                    },
                    {
                      text: 'isAuthorized',
                      link: '/sdk/typescript/viem/policy.isAuthorized',
                    },
                    {
                      text: 'modifyBlacklist',
                      link: '/sdk/typescript/viem/policy.modifyBlacklist',
                    },
                    {
                      text: 'modifyWhitelist',
                      link: '/sdk/typescript/viem/policy.modifyWhitelist',
                    },
                    {
                      text: 'setAdmin',
                      link: '/sdk/typescript/viem/policy.setAdmin',
                    },
                    {
                      text: 'watchAdminUpdated',
                      link: '/sdk/typescript/viem/policy.watchAdminUpdated',
                    },
                    {
                      text: 'watchBlacklistUpdated',
                      link: '/sdk/typescript/viem/policy.watchBlacklistUpdated',
                    },
                    {
                      text: 'watchCreate',
                      link: '/sdk/typescript/viem/policy.watchCreate',
                    },
                    {
                      text: 'watchWhitelistUpdated',
                      link: '/sdk/typescript/viem/policy.watchWhitelistUpdated',
                    },
                  ],
                },
                {
                  text: 'Faucet',
                  items: [
                    {
                      text: 'fund',
                      link: '/sdk/typescript/viem/faucet.fund',
                    },
                  ],
                },
                {
                  text: 'Reward',
                  items: [
                    {
                      text: 'claim',
                      link: '/sdk/typescript/viem/reward.claim',
                    },
                    {
                      text: 'getTotalPerSecond',
                      link: '/sdk/typescript/viem/reward.getTotalPerSecond',
                    },
                    {
                      text: 'getUserRewardInfo',
                      link: '/sdk/typescript/viem/reward.getUserRewardInfo',
                    },
                    {
                      text: 'setRecipient',
                      link: '/sdk/typescript/viem/reward.setRecipient',
                    },
                    {
                      text: 'start',
                      link: '/sdk/typescript/viem/reward.start',
                    },
                    {
                      text: 'watchRewardRecipientSet',
                      link: '/sdk/typescript/viem/reward.watchRewardRecipientSet',
                    },
                    {
                      text: 'watchRewardScheduled',
                      link: '/sdk/typescript/viem/reward.watchRewardScheduled',
                    },
                  ],
                },
                {
                  text: 'Stablecoin Exchange',
                  items: [
                    {
                      text: 'buy',
                      link: '/sdk/typescript/viem/dex.buy',
                    },
                    {
                      text: 'cancel',
                      link: '/sdk/typescript/viem/dex.cancel',
                    },
                    {
                      text: 'createPair',
                      link: '/sdk/typescript/viem/dex.createPair',
                    },
                    {
                      text: 'getBalance',
                      link: '/sdk/typescript/viem/dex.getBalance',
                    },
                    {
                      text: 'getBuyQuote',
                      link: '/sdk/typescript/viem/dex.getBuyQuote',
                    },
                    {
                      text: 'getOrder',
                      link: '/sdk/typescript/viem/dex.getOrder',
                    },
                    {
                      text: 'getTickLevel',
                      link: '/sdk/typescript/viem/dex.getTickLevel',
                    },
                    {
                      text: 'getSellQuote',
                      link: '/sdk/typescript/viem/dex.getSellQuote',
                    },
                    {
                      text: 'place',
                      link: '/sdk/typescript/viem/dex.place',
                    },
                    {
                      text: 'placeFlip',
                      link: '/sdk/typescript/viem/dex.placeFlip',
                    },
                    {
                      text: 'sell',
                      link: '/sdk/typescript/viem/dex.sell',
                    },
                    {
                      text: 'watchFlipOrderPlaced',
                      link: '/sdk/typescript/viem/dex.watchFlipOrderPlaced',
                    },
                    {
                      text: 'watchOrderCancelled',
                      link: '/sdk/typescript/viem/dex.watchOrderCancelled',
                    },
                    {
                      text: 'watchOrderFilled',
                      link: '/sdk/typescript/viem/dex.watchOrderFilled',
                    },
                    {
                      text: 'watchOrderPlaced',
                      link: '/sdk/typescript/viem/dex.watchOrderPlaced',
                    },
                    {
                      text: 'withdraw',
                      link: '/sdk/typescript/viem/dex.withdraw',
                    },
                  ],
                },
                {
                  text: 'Token',
                  items: [
                    {
                      text: 'approve',
                      link: '/sdk/typescript/viem/token.approve',
                    },
                    {
                      text: 'burn',
                      link: '/sdk/typescript/viem/token.burn',
                    },
                    {
                      text: 'burnBlocked',
                      link: '/sdk/typescript/viem/token.burnBlocked',
                    },
                    {
                      text: 'changeTransferPolicy',
                      link: '/sdk/typescript/viem/token.changeTransferPolicy',
                    },
                    {
                      text: 'create',
                      link: '/sdk/typescript/viem/token.create',
                    },
                    {
                      text: 'getAllowance',
                      link: '/sdk/typescript/viem/token.getAllowance',
                    },
                    {
                      text: 'getBalance',
                      link: '/sdk/typescript/viem/token.getBalance',
                    },
                    {
                      text: 'getMetadata',
                      link: '/sdk/typescript/viem/token.getMetadata',
                    },
                    {
                      text: 'grantRoles',
                      link: '/sdk/typescript/viem/token.grantRoles',
                    },
                    {
                      text: 'hasRole',
                      link: '/sdk/typescript/viem/token.hasRole',
                    },
                    {
                      text: 'mint',
                      link: '/sdk/typescript/viem/token.mint',
                    },
                    {
                      text: 'pause',
                      link: '/sdk/typescript/viem/token.pause',
                    },
                    {
                      text: 'renounceRoles',
                      link: '/sdk/typescript/viem/token.renounceRoles',
                    },
                    {
                      text: 'revokeRoles',
                      link: '/sdk/typescript/viem/token.revokeRoles',
                    },
                    {
                      text: 'setRoleAdmin',
                      link: '/sdk/typescript/viem/token.setRoleAdmin',
                    },
                    {
                      text: 'setSupplyCap',
                      link: '/sdk/typescript/viem/token.setSupplyCap',
                    },
                    {
                      text: 'transfer',
                      link: '/sdk/typescript/viem/token.transfer',
                    },
                    {
                      text: 'unpause',
                      link: '/sdk/typescript/viem/token.unpause',
                    },
                    {
                      text: 'watchAdminRole',
                      link: '/sdk/typescript/viem/token.watchAdminRole',
                    },
                    {
                      text: 'watchApprove',
                      link: '/sdk/typescript/viem/token.watchApprove',
                    },
                    {
                      text: 'watchBurn',
                      link: '/sdk/typescript/viem/token.watchBurn',
                    },
                    {
                      text: 'watchCreate',
                      link: '/sdk/typescript/viem/token.watchCreate',
                    },
                    {
                      text: 'watchMint',
                      link: '/sdk/typescript/viem/token.watchMint',
                    },
                    {
                      text: 'watchRole',
                      link: '/sdk/typescript/viem/token.watchRole',
                    },
                    {
                      text: 'watchTransfer',
                      link: '/sdk/typescript/viem/token.watchTransfer',
                    },
                  ],
                },
              ],
            },
            {
              text: 'Transports',
              collapsed: true,
              items: [
                {
                  text: 'Overview',
                  link: '/sdk/typescript/viem/transports',
                },
                {
                  text: 'withFeePayer',
                  link: '/sdk/typescript/viem/transport.withFeePayer',
                },
              ],
            },
          ],
        },
        {
          text: 'Wagmi Reference',
          items: [
            {
              text: 'Setup',
              link: '/sdk/typescript/wagmi/setup',
            },
            {
              text: 'Connectors',
              collapsed: true,
              items: [
                {
                  text: 'Overview',
                  link: '/sdk/typescript/wagmi/connectors',
                },
                {
                  text: 'dangerous_secp256k1',
                  link: '/sdk/typescript/wagmi/connectors/dangerous_secp256k1',
                },
                {
                  text: 'webAuthn',
                  link: '/sdk/typescript/wagmi/connectors/webAuthn',
                },
              ],
            },
            {
              text: 'Actions',
              collapsed: true,
              items: [
                {
                  text: 'Overview',
                  link: '/sdk/typescript/wagmi/actions',
                },
                {
                  text: 'AMM',
                  items: [
                    {
                      text: 'burn',
                      link: '/sdk/typescript/wagmi/actions/amm.burn',
                    },
                    {
                      text: 'getLiquidityBalance',
                      link: '/sdk/typescript/wagmi/actions/amm.getLiquidityBalance',
                    },
                    {
                      text: 'getPool',
                      link: '/sdk/typescript/wagmi/actions/amm.getPool',
                    },
                    {
                      text: 'mint',
                      link: '/sdk/typescript/wagmi/actions/amm.mint',
                    },
                    {
                      text: 'rebalanceSwap',
                      link: '/sdk/typescript/wagmi/actions/amm.rebalanceSwap',
                    },
                    {
                      text: 'watchBurn',
                      link: '/sdk/typescript/wagmi/actions/amm.watchBurn',
                    },
                    {
                      text: 'watchFeeSwap',
                      link: '/sdk/typescript/wagmi/actions/amm.watchFeeSwap',
                    },
                    {
                      text: 'watchMint',
                      link: '/sdk/typescript/wagmi/actions/amm.watchMint',
                    },
                    {
                      text: 'watchRebalanceSwap',
                      link: '/sdk/typescript/wagmi/actions/amm.watchRebalanceSwap',
                    },
                  ],
                },
                {
                  text: 'Fee',
                  items: [
                    {
                      text: 'getUserToken',
                      link: '/sdk/typescript/wagmi/actions/fee.getUserToken',
                    },
                    {
                      text: 'setUserToken',
                      link: '/sdk/typescript/wagmi/actions/fee.setUserToken',
                    },
                    {
                      text: 'watchSetUserToken',
                      link: '/sdk/typescript/wagmi/actions/fee.watchSetUserToken',
                    },
                  ],
                },
                {
                  text: 'Nonce',
                  items: [
                    {
                      text: 'getNonce',
                      link: '/sdk/typescript/wagmi/actions/nonce.getNonce',
                    },
                    {
                      text: 'getNonceKeyCount',
                      link: '/sdk/typescript/wagmi/actions/nonce.getNonceKeyCount',
                    },
                    {
                      text: 'watchActiveKeyCountChanged',
                      link: '/sdk/typescript/wagmi/actions/nonce.watchActiveKeyCountChanged',
                    },
                    {
                      text: 'watchNonceIncremented',
                      link: '/sdk/typescript/wagmi/actions/nonce.watchNonceIncremented',
                    },
                  ],
                },
                {
                  text: 'Policy',
                  items: [
                    {
                      text: 'create',
                      link: '/sdk/typescript/wagmi/actions/policy.create',
                    },
                    {
                      text: 'getData',
                      link: '/sdk/typescript/wagmi/actions/policy.getData',
                    },
                    {
                      text: 'isAuthorized',
                      link: '/sdk/typescript/wagmi/actions/policy.isAuthorized',
                    },
                    {
                      text: 'modifyBlacklist',
                      link: '/sdk/typescript/wagmi/actions/policy.modifyBlacklist',
                    },
                    {
                      text: 'modifyWhitelist',
                      link: '/sdk/typescript/wagmi/actions/policy.modifyWhitelist',
                    },
                    {
                      text: 'setAdmin',
                      link: '/sdk/typescript/wagmi/actions/policy.setAdmin',
                    },
                    {
                      text: 'watchAdminUpdated',
                      link: '/sdk/typescript/wagmi/actions/policy.watchAdminUpdated',
                    },
                    {
                      text: 'watchBlacklistUpdated',
                      link: '/sdk/typescript/wagmi/actions/policy.watchBlacklistUpdated',
                    },
                    {
                      text: 'watchCreate',
                      link: '/sdk/typescript/wagmi/actions/policy.watchCreate',
                    },
                    {
                      text: 'watchWhitelistUpdated',
                      link: '/sdk/typescript/wagmi/actions/policy.watchWhitelistUpdated',
                    },
                  ],
                },
                {
                  text: 'Faucet',
                  items: [
                    {
                      text: 'fund',
                      link: '/sdk/typescript/wagmi/actions/faucet.fund',
                    },
                  ],
                },
                {
                  text: 'Reward',
                  items: [
                    {
                      text: 'claim',
                      link: '/sdk/typescript/wagmi/actions/reward.claim',
                    },
                    {
                      text: 'getTotalPerSecond',
                      link: '/sdk/typescript/wagmi/actions/reward.getTotalPerSecond',
                    },
                    {
                      text: 'getUserRewardInfo',
                      link: '/sdk/typescript/wagmi/actions/reward.getUserRewardInfo',
                    },
                    {
                      text: 'setRecipient',
                      link: '/sdk/typescript/wagmi/actions/reward.setRecipient',
                    },
                    {
                      text: 'start',
                      link: '/sdk/typescript/wagmi/actions/reward.start',
                    },
                    {
                      text: 'watchRewardRecipientSet',
                      link: '/sdk/typescript/wagmi/actions/reward.watchRewardRecipientSet',
                    },
                    {
                      text: 'watchRewardScheduled',
                      link: '/sdk/typescript/wagmi/actions/reward.watchRewardScheduled',
                    },
                  ],
                },
                {
                  text: 'Stablecoin Exchange',
                  items: [
                    {
                      text: 'buy',
                      link: '/sdk/typescript/wagmi/actions/dex.buy',
                    },
                    {
                      text: 'cancel',
                      link: '/sdk/typescript/wagmi/actions/dex.cancel',
                    },
                    {
                      text: 'createPair',
                      link: '/sdk/typescript/wagmi/actions/dex.createPair',
                    },
                    {
                      text: 'getBalance',
                      link: '/sdk/typescript/wagmi/actions/dex.getBalance',
                    },
                    {
                      text: 'getBuyQuote',
                      link: '/sdk/typescript/wagmi/actions/dex.getBuyQuote',
                    },
                    {
                      text: 'getOrder',
                      link: '/sdk/typescript/wagmi/actions/dex.getOrder',
                    },
                    {
                      text: 'getTickLevel',
                      link: '/sdk/typescript/wagmi/actions/dex.getTickLevel',
                    },
                    {
                      text: 'getSellQuote',
                      link: '/sdk/typescript/wagmi/actions/dex.getSellQuote',
                    },
                    {
                      text: 'place',
                      link: '/sdk/typescript/wagmi/actions/dex.place',
                    },
                    {
                      text: 'placeFlip',
                      link: '/sdk/typescript/wagmi/actions/dex.placeFlip',
                    },
                    {
                      text: 'sell',
                      link: '/sdk/typescript/wagmi/actions/dex.sell',
                    },
                    {
                      text: 'watchFlipOrderPlaced',
                      link: '/sdk/typescript/wagmi/actions/dex.watchFlipOrderPlaced',
                    },
                    {
                      text: 'watchOrderCancelled',
                      link: '/sdk/typescript/wagmi/actions/dex.watchOrderCancelled',
                    },
                    {
                      text: 'watchOrderFilled',
                      link: '/sdk/typescript/wagmi/actions/dex.watchOrderFilled',
                    },
                    {
                      text: 'watchOrderPlaced',
                      link: '/sdk/typescript/wagmi/actions/dex.watchOrderPlaced',
                    },
                    {
                      text: 'withdraw',
                      link: '/sdk/typescript/wagmi/actions/dex.withdraw',
                    },
                  ],
                },
                {
                  text: 'Token',
                  items: [
                    {
                      text: 'approve',
                      link: '/sdk/typescript/wagmi/actions/token.approve',
                    },
                    {
                      text: 'burn',
                      link: '/sdk/typescript/wagmi/actions/token.burn',
                    },
                    {
                      text: 'burnBlocked',
                      link: '/sdk/typescript/wagmi/actions/token.burnBlocked',
                    },
                    {
                      text: 'changeTransferPolicy',
                      link: '/sdk/typescript/wagmi/actions/token.changeTransferPolicy',
                    },
                    {
                      text: 'create',
                      link: '/sdk/typescript/wagmi/actions/token.create',
                    },
                    {
                      text: 'getAllowance',
                      link: '/sdk/typescript/wagmi/actions/token.getAllowance',
                    },
                    {
                      text: 'getBalance',
                      link: '/sdk/typescript/wagmi/actions/token.getBalance',
                    },
                    {
                      text: 'getMetadata',
                      link: '/sdk/typescript/wagmi/actions/token.getMetadata',
                    },
                    {
                      text: 'grantRoles',
                      link: '/sdk/typescript/wagmi/actions/token.grantRoles',
                    },
                    {
                      text: 'hasRole',
                      link: '/sdk/typescript/wagmi/actions/token.hasRole',
                    },
                    {
                      text: 'mint',
                      link: '/sdk/typescript/wagmi/actions/token.mint',
                    },
                    {
                      text: 'pause',
                      link: '/sdk/typescript/wagmi/actions/token.pause',
                    },
                    {
                      text: 'renounceRoles',
                      link: '/sdk/typescript/wagmi/actions/token.renounceRoles',
                    },
                    {
                      text: 'revokeRoles',
                      link: '/sdk/typescript/wagmi/actions/token.revokeRoles',
                    },
                    {
                      text: 'setRoleAdmin',
                      link: '/sdk/typescript/wagmi/actions/token.setRoleAdmin',
                    },
                    {
                      text: 'setSupplyCap',
                      link: '/sdk/typescript/wagmi/actions/token.setSupplyCap',
                    },
                    {
                      text: 'transfer',
                      link: '/sdk/typescript/wagmi/actions/token.transfer',
                    },
                    {
                      text: 'unpause',
                      link: '/sdk/typescript/wagmi/actions/token.unpause',
                    },
                    {
                      text: 'watchAdminRole',
                      link: '/sdk/typescript/wagmi/actions/token.watchAdminRole',
                    },
                    {
                      text: 'watchApprove',
                      link: '/sdk/typescript/wagmi/actions/token.watchApprove',
                    },
                    {
                      text: 'watchBurn',
                      link: '/sdk/typescript/wagmi/actions/token.watchBurn',
                    },
                    {
                      text: 'watchCreate',
                      link: '/sdk/typescript/wagmi/actions/token.watchCreate',
                    },
                    {
                      text: 'watchMint',
                      link: '/sdk/typescript/wagmi/actions/token.watchMint',
                    },
                    {
                      text: 'watchRole',
                      link: '/sdk/typescript/wagmi/actions/token.watchRole',
                    },
                    {
                      text: 'watchTransfer',
                      link: '/sdk/typescript/wagmi/actions/token.watchTransfer',
                    },
                  ],
                },
              ],
            },
            {
              text: 'Key Managers',
              collapsed: true,
              items: [
                {
                  text: 'Overview',
                  link: '/sdk/typescript/wagmi/keyManagers',
                },
                {
                  text: 'http',
                  link: '/sdk/typescript/wagmi/keyManagers/http',
                },
                {
                  text: 'localStorage',
                  link: '/sdk/typescript/wagmi/keyManagers/localStorage',
                },
              ],
            },
            {
              text: 'Hooks',
              collapsed: true,
              items: [
                {
                  text: 'Overview',
                  link: '/sdk/typescript/wagmi/hooks',
                },
                {
                  text: 'AMM',
                  items: [
                    {
                      text: 'useBurn',
                      link: '/sdk/typescript/wagmi/hooks/amm.useBurn',
                    },
                    {
                      text: 'useLiquidityBalance',
                      link: '/sdk/typescript/wagmi/hooks/amm.useLiquidityBalance',
                    },
                    {
                      text: 'useMint',
                      link: '/sdk/typescript/wagmi/hooks/amm.useMint',
                    },
                    {
                      text: 'usePool',
                      link: '/sdk/typescript/wagmi/hooks/amm.usePool',
                    },
                    {
                      text: 'useRebalanceSwap',
                      link: '/sdk/typescript/wagmi/hooks/amm.useRebalanceSwap',
                    },
                    {
                      text: 'useWatchBurn',
                      link: '/sdk/typescript/wagmi/hooks/amm.useWatchBurn',
                    },
                    {
                      text: 'useWatchFeeSwap',
                      link: '/sdk/typescript/wagmi/hooks/amm.useWatchFeeSwap',
                    },
                    {
                      text: 'useWatchMint',
                      link: '/sdk/typescript/wagmi/hooks/amm.useWatchMint',
                    },
                    {
                      text: 'useWatchRebalanceSwap',
                      link: '/sdk/typescript/wagmi/hooks/amm.useWatchRebalanceSwap',
                    },
                  ],
                },
                {
                  text: 'Fee',
                  items: [
                    {
                      text: 'useSetUserToken',
                      link: '/sdk/typescript/wagmi/hooks/fee.useSetUserToken',
                    },
                    {
                      text: 'useUserToken',
                      link: '/sdk/typescript/wagmi/hooks/fee.useUserToken',
                    },
                    {
                      text: 'useWatchSetUserToken',
                      link: '/sdk/typescript/wagmi/hooks/fee.useWatchSetUserToken',
                    },
                  ],
                },
                {
                  text: 'Nonce',
                  items: [
                    {
                      text: 'useNonce',
                      link: '/sdk/typescript/wagmi/hooks/nonce.useNonce',
                    },
                    {
                      text: 'useNonceKeyCount',
                      link: '/sdk/typescript/wagmi/hooks/nonce.useNonceKeyCount',
                    },
                    {
                      text: 'useWatchActiveKeyCountChanged',
                      link: '/sdk/typescript/wagmi/hooks/nonce.useWatchActiveKeyCountChanged',
                    },
                    {
                      text: 'useWatchNonceIncremented',
                      link: '/sdk/typescript/wagmi/hooks/nonce.useWatchNonceIncremented',
                    },
                  ],
                },
                {
                  text: 'Policy',
                  items: [
                    {
                      text: 'useCreate',
                      link: '/sdk/typescript/wagmi/hooks/policy.useCreate',
                    },
                    {
                      text: 'useData',
                      link: '/sdk/typescript/wagmi/hooks/policy.useData',
                    },
                    {
                      text: 'useIsAuthorized',
                      link: '/sdk/typescript/wagmi/hooks/policy.useIsAuthorized',
                    },
                    {
                      text: 'useModifyBlacklist',
                      link: '/sdk/typescript/wagmi/hooks/policy.useModifyBlacklist',
                    },
                    {
                      text: 'useModifyWhitelist',
                      link: '/sdk/typescript/wagmi/hooks/policy.useModifyWhitelist',
                    },
                    {
                      text: 'useSetAdmin',
                      link: '/sdk/typescript/wagmi/hooks/policy.useSetAdmin',
                    },
                    {
                      text: 'useWatchAdminUpdated',
                      link: '/sdk/typescript/wagmi/hooks/policy.useWatchAdminUpdated',
                    },
                    {
                      text: 'useWatchBlacklistUpdated',
                      link: '/sdk/typescript/wagmi/hooks/policy.useWatchBlacklistUpdated',
                    },
                    {
                      text: 'useWatchCreate',
                      link: '/sdk/typescript/wagmi/hooks/policy.useWatchCreate',
                    },
                    {
                      text: 'useWatchWhitelistUpdated',
                      link: '/sdk/typescript/wagmi/hooks/policy.useWatchWhitelistUpdated',
                    },
                  ],
                },
                {
                  text: 'Faucet',
                  items: [
                    {
                      text: 'useFund',
                      link: '/sdk/typescript/wagmi/hooks/faucet.useFund',
                    },
                  ],
                },
                {
                  text: 'Reward',
                  items: [
                    {
                      text: 'useClaim',
                      link: '/sdk/typescript/wagmi/hooks/reward.useClaim',
                    },
                    {
                      text: 'useGetTotalPerSecond',
                      link: '/sdk/typescript/wagmi/hooks/reward.useGetTotalPerSecond',
                    },
                    {
                      text: 'useSetRecipient',
                      link: '/sdk/typescript/wagmi/hooks/reward.useSetRecipient',
                    },
                    {
                      text: 'useStart',
                      link: '/sdk/typescript/wagmi/hooks/reward.useStart',
                    },
                    {
                      text: 'useUserRewardInfo',
                      link: '/sdk/typescript/wagmi/hooks/reward.useUserRewardInfo',
                    },
                    {
                      text: 'useWatchRewardRecipientSet',
                      link: '/sdk/typescript/wagmi/hooks/reward.useWatchRewardRecipientSet',
                    },
                    {
                      text: 'useWatchRewardScheduled',
                      link: '/sdk/typescript/wagmi/hooks/reward.useWatchRewardScheduled',
                    },
                  ],
                },
                {
                  text: 'Stablecoin Exchange',
                  items: [
                    {
                      text: 'useBalance',
                      link: '/sdk/typescript/wagmi/hooks/dex.useBalance',
                    },
                    {
                      text: 'useBuy',
                      link: '/sdk/typescript/wagmi/hooks/dex.useBuy',
                    },
                    {
                      text: 'useBuyQuote',
                      link: '/sdk/typescript/wagmi/hooks/dex.useBuyQuote',
                    },
                    {
                      text: 'useCancel',
                      link: '/sdk/typescript/wagmi/hooks/dex.useCancel',
                    },
                    {
                      text: 'useCreatePair',
                      link: '/sdk/typescript/wagmi/hooks/dex.useCreatePair',
                    },
                    {
                      text: 'useOrder',
                      link: '/sdk/typescript/wagmi/hooks/dex.useOrder',
                    },
                    {
                      text: 'usePlace',
                      link: '/sdk/typescript/wagmi/hooks/dex.usePlace',
                    },
                    {
                      text: 'usePlaceFlip',
                      link: '/sdk/typescript/wagmi/hooks/dex.usePlaceFlip',
                    },
                    {
                      text: 'useTickLevel',
                      link: '/sdk/typescript/wagmi/hooks/dex.useTickLevel',
                    },
                    {
                      text: 'useSell',
                      link: '/sdk/typescript/wagmi/hooks/dex.useSell',
                    },
                    {
                      text: 'useSellQuote',
                      link: '/sdk/typescript/wagmi/hooks/dex.useSellQuote',
                    },
                    {
                      text: 'useWatchFlipOrderPlaced',
                      link: '/sdk/typescript/wagmi/hooks/dex.useWatchFlipOrderPlaced',
                    },
                    {
                      text: 'useWatchOrderCancelled',
                      link: '/sdk/typescript/wagmi/hooks/dex.useWatchOrderCancelled',
                    },
                    {
                      text: 'useWatchOrderFilled',
                      link: '/sdk/typescript/wagmi/hooks/dex.useWatchOrderFilled',
                    },
                    {
                      text: 'useWatchOrderPlaced',
                      link: '/sdk/typescript/wagmi/hooks/dex.useWatchOrderPlaced',
                    },
                    {
                      text: 'useWithdraw',
                      link: '/sdk/typescript/wagmi/hooks/dex.useWithdraw',
                    },
                  ],
                },
                {
                  text: 'Token',
                  items: [
                    {
                      text: 'useGetAllowance',
                      link: '/sdk/typescript/wagmi/hooks/token.useGetAllowance',
                    },
                    {
                      text: 'useApprove',
                      link: '/sdk/typescript/wagmi/hooks/token.useApprove',
                    },
                    {
                      text: 'useGetBalance',
                      link: '/sdk/typescript/wagmi/hooks/token.useGetBalance',
                    },
                    {
                      text: 'useBurn',
                      link: '/sdk/typescript/wagmi/hooks/token.useBurn',
                    },
                    {
                      text: 'useBurnBlocked',
                      link: '/sdk/typescript/wagmi/hooks/token.useBurnBlocked',
                    },
                    {
                      text: 'useChangeTransferPolicy',
                      link: '/sdk/typescript/wagmi/hooks/token.useChangeTransferPolicy',
                    },
                    {
                      text: 'useCreate',
                      link: '/sdk/typescript/wagmi/hooks/token.useCreate',
                    },
                    {
                      text: 'useGrantRoles',
                      link: '/sdk/typescript/wagmi/hooks/token.useGrantRoles',
                    },
                    {
                      text: 'useHasRole',
                      link: '/sdk/typescript/wagmi/hooks/token.useHasRole',
                    },
                    {
                      text: 'useGetMetadata',
                      link: '/sdk/typescript/wagmi/hooks/token.useGetMetadata',
                    },
                    {
                      text: 'useMint',
                      link: '/sdk/typescript/wagmi/hooks/token.useMint',
                    },
                    {
                      text: 'usePause',
                      link: '/sdk/typescript/wagmi/hooks/token.usePause',
                    },
                    {
                      text: 'useRenounceRoles',
                      link: '/sdk/typescript/wagmi/hooks/token.useRenounceRoles',
                    },
                    {
                      text: 'useRevokeRoles',
                      link: '/sdk/typescript/wagmi/hooks/token.useRevokeRoles',
                    },
                    {
                      text: 'useSetRoleAdmin',
                      link: '/sdk/typescript/wagmi/hooks/token.useSetRoleAdmin',
                    },
                    {
                      text: 'useSetSupplyCap',
                      link: '/sdk/typescript/wagmi/hooks/token.useSetSupplyCap',
                    },
                    {
                      text: 'useTransfer',
                      link: '/sdk/typescript/wagmi/hooks/token.useTransfer',
                    },
                    {
                      text: 'useUnpause',
                      link: '/sdk/typescript/wagmi/hooks/token.useUnpause',
                    },
                    {
                      text: 'useWatchAdminRole',
                      link: '/sdk/typescript/wagmi/hooks/token.useWatchAdminRole',
                    },
                    {
                      text: 'useWatchApprove',
                      link: '/sdk/typescript/wagmi/hooks/token.useWatchApprove',
                    },
                    {
                      text: 'useWatchBurn',
                      link: '/sdk/typescript/wagmi/hooks/token.useWatchBurn',
                    },
                    {
                      text: 'useWatchCreate',
                      link: '/sdk/typescript/wagmi/hooks/token.useWatchCreate',
                    },
                    {
                      text: 'useWatchMint',
                      link: '/sdk/typescript/wagmi/hooks/token.useWatchMint',
                    },
                    {
                      text: 'useWatchRole',
                      link: '/sdk/typescript/wagmi/hooks/token.useWatchRole',
                    },
                    {
                      text: 'useWatchTransfer',
                      link: '/sdk/typescript/wagmi/hooks/token.useWatchTransfer',
                    },
                  ],
                },
              ],
            },
          ],
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
          extraFiles: {
            'twoslash-env.d.ts': twoslashSupportFile,
          },
        },
  vite: {
    plugins: [
      {
        name: 'tempo-node',
        async configureServer(_server) {
          if (
            !('VITE_LOCAL' in process.env) ||
            process.env['VITE_LOCAL'] === 'false'
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
