// @ts-nocheck
// biome-ignore-all lint: snippet
// biome-ignore-all format: snippet

import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
// [!region setup]
import { tempo } from 'viem/chains'
import { createConfig, http } from 'wagmi'
import { KeyManager, webAuthn } from 'wagmi/tempo'

export const config = createConfig({
  connectors: [
    webAuthn({
      keyManager: KeyManager.localStorage(),
    }),
  ],
  chains: [tempo],
  multiInjectedProviderDiscovery: false,
  transports: {
    [tempo.id]: http('https://{user}:{pass}@rpc.tempo.xyz'),
  },
})

// [!endregion setup]

import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
// [!region withFeePayer]
import { tempo } from 'viem/chains'
import { withFeePayer } from 'viem/tempo'
import { createConfig, http } from 'wagmi'
import { KeyManager, webAuthn } from 'wagmi/tempo'

export const config = createConfig({
  connectors: [
    webAuthn({
      keyManager: KeyManager.localStorage(),
    }),
  ],
  chains: [tempo],
  multiInjectedProviderDiscovery: false,
  transports: {
    [tempo.id]: withFeePayer(
      http('https://{user}:{pass}@rpc.tempo.xyz'),
      http('https://sponsor.tempo.xyz'),
    ),
  },
})
// [!endregion withFeePayer]
