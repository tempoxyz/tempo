// @ts-nocheck
// biome-ignore-all lint: snippet
// biome-ignore-all format: snippet

// [!region setup]
import { tempoTestnet } from 'viem/chains'
import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
import { createConfig, http } from 'wagmi'

export const config = createConfig({
  connectors: [
    webAuthn({
      keyManager: KeyManager.localStorage(),
    }),
  ],
  chains: [tempoTestnet],
  multiInjectedProviderDiscovery: false,
  transports: {
    [tempoTestnet.id]: http(),
  },
})

// [!endregion setup]

// [!region withFeePayer]
import { tempoTestnet } from 'viem/chains'
import { withFeePayer } from 'viem/tempo'
import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
import { createConfig, http } from 'wagmi'

export const config = createConfig({
  connectors: [
    webAuthn({
      keyManager: KeyManager.localStorage(),
    }),
  ],
  chains: [tempoTestnet],
  multiInjectedProviderDiscovery: false,
  transports: {
    [tempoTestnet.id]: withFeePayer(
      http(),
      http('https://sponsor.testnet.tempo.xyz'),
    ),
  },
})
// [!endregion withFeePayer]
