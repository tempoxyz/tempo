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
          ? tempoDevnet({ feeToken })
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
      [tempoTestnet.id]: withFeePayer(
        webSocket('wss://rpc.testnet.tempo.xyz', {
          keepAlive: { interval: 1_000 },
        }),
        http('https://sponsor.testnet.tempo.xyz'),
        { policy: 'sign-only' },
      ),
      [tempoLocal.id]:
        import.meta.env.VITE_ENVIRONMENT === 'devnet'
          ? withFeePayer(
              webSocket('wss://devnet.tempoxyz.dev', {
                keepAlive: { interval: 1_000 },
              }),
              http('https://sponsor.devnet.tempo.xyz'),
              { policy: 'sign-only' },
            )
          : http(undefined, {
              batch: true,
            }),
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
