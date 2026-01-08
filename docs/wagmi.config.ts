import { QueryClient } from '@tanstack/react-query'
import { tempoDevnet, tempoLocalnet, tempoTestnet } from 'viem/chains'
import { withFeePayer } from 'viem/tempo'
import {
  type CreateConfigParameters,
  createConfig,
  createStorage,
  http,
  webSocket,
} from 'wagmi'
import { KeyManager, webAuthn } from 'wagmi/tempo'

const feeToken = '0x20c0000000000000000000000000000000000001'

export function getConfig(options: getConfig.Options = {}) {
  const { multiInjectedProviderDiscovery } = options
  return createConfig({
    batch: {
      multicall: false,
    },
    chains: [
      import.meta.env.VITE_ENVIRONMENT === 'local'
        ? tempoLocalnet.extend({ feeToken })
        : import.meta.env.VITE_ENVIRONMENT === 'devnet'
          ? tempoDevnet.extend({ feeToken })
          : tempoTestnet.extend({ feeToken }),
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
      [tempoDevnet.id]: withFeePayer(
        webSocket(tempoDevnet.rpcUrls.default.webSocket[0], {
          keepAlive: { interval: 1_000 },
        }),
        http('https://sponsor.devnet.tempo.xyz'),
        { policy: 'sign-only' },
      ),
      [tempoLocalnet.id]: http(undefined, { batch: true }),
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
