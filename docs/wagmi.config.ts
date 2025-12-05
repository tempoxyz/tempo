import { QueryClient } from '@tanstack/react-query'
import { tempoLocal, tempoTestnet } from 'tempo.ts/chains'
import { withFeePayer } from 'tempo.ts/viem'
import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
import {
  type CreateConfigParameters,
  createConfig,
  createStorage,
  http,
  noopStorage,
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
      import.meta.env.VITE_LOCAL !== 'true'
        ? tempoTestnet({ feeToken })
        : tempoLocal({ feeToken }),
    ],
    connectors: [
      webAuthn({
        grantAccessKey: true,
        keyManager: KeyManager.localStorage(),
      }),
    ],
    multiInjectedProviderDiscovery,
    storage: createStorage({
      storage:
        typeof window !== 'undefined' ? window.localStorage : noopStorage,
    }),
    transports: {
      [tempoTestnet.id]: withFeePayer(
        webSocket('wss://rpc-orchestra.testnet.tempo.xyz/zealous-mayer', {
          keepAlive: { interval: 1_000 },
        }),
        http('https://sponsor.testnet.tempo.xyz'),
        { policy: 'sign-only' },
      ),
      [tempoLocal.id]: http(undefined, {
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
