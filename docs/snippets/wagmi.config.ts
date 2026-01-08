// @ts-nocheck
// biome-ignore-all lint: snippet
// biome-ignore-all format: snippet

import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
// [!region setup]
import { tempoTestnet } from 'viem/chains'
import { createConfig, http } from 'wagmi'
import { KeyManager, webAuthn } from 'wagmi/tempo'

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

import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
// [!region withFeePayer]
import { tempoTestnet } from 'viem/chains'
import { withFeePayer } from 'viem/tempo'
import { createConfig, http } from 'wagmi'
import { KeyManager, webAuthn } from 'wagmi/tempo'

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
      http('https://sponsor.moderato.tempo.xyz'),
    ),
  },
})
// [!endregion withFeePayer]
