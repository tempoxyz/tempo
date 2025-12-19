import { QueryClient } from '@tanstack/react-query'
import { tempoDevnet, tempoLocal, tempoTestnet } from 'tempo.ts/chains'
import { withFeePayer } from 'tempo.ts/viem'
import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
import {
  type CreateConfigParameters,
  createConfig,
  createStorage,
  http,
  webSocket,
} from 'wagmi'

const feeToken = '0x20c0000000000000000000000000000000000001'

const tempoDevnetChain = {
  ...tempoDevnet({ feeToken }),
  id: 42429,
  rpcUrls: {
    default: {
      http: ['https://rpc.devnet.tempoxyz.dev'],
      webSocket: ['wss://rpc.devnet.tempoxyz.dev'],
    },
  },
}

export function getConfig(options: getConfig.Options = {}) {
  const { multiInjectedProviderDiscovery } = options
  return createConfig({
    batch: {
      multicall: false,
    },
    chains: [
      import.meta.env.VITE_ENVIRONMENT === 'local'
        ? tempoLocal({ feeToken })
        : import.meta.env.VITE_ENVIRONMENT === 'devnet'
          ? tempoDevnetChain
          : tempoTestnet({ feeToken }),
    ],
    connectors: [
      webAuthn({
        grantAccessKey: true,
        keyManager: KeyManager.localStorage(),
      }),
    ],
    multiInjectedProviderDiscovery,
    storage: createStorage({
      storage: typeof window !== 'undefined' ? localStorage : undefined,
      key: 'tempo-docs',
    }),
    transports: {
      [tempoTestnet.id]:
        import.meta.env.VITE_ENVIRONMENT === 'devnet'
          ? withFeePayer(
              webSocket(tempoDevnetChain.rpcUrls.default.webSocket[0], {
                keepAlive: { interval: 1_000 },
              }),
              http('https://sponsor.devnet.tempo.xyz'),
              { policy: 'sign-only' },
            )
          : withFeePayer(
              webSocket('wss://rpc.testnet.tempo.xyz', {
                keepAlive: { interval: 1_000 },
              }),
              http('https://sponsor.testnet.tempo.xyz'),
              { policy: 'sign-only' },
            ),
      [tempoLocal.id]: http(undefined, { batch: true }),
    },
  })
}

export namespace getConfig {
  export type Options = Partial<
    Pick<CreateConfigParameters, 'multiInjectedProviderDiscovery'>
  >
}

export const config = getConfig()

export const queryClient = new QueryClient()

declare module 'wagmi' {
  interface Register {
    config: typeof config
  }
}
