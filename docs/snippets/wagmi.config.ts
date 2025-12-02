// [!region setup]
import { tempo } from 'tempo.ts/chains'
import { KeyManager, webAuthn } from 'tempo.ts/wagmi'
import { createConfig, http } from 'wagmi'

export const config = createConfig({
  connectors: [
    webAuthn({
      keyManager: KeyManager.localStorage(),
    }),
  ],
  chains: [tempo({ feeToken: '0x20c0000000000000000000000000000000000001' })],
  multiInjectedProviderDiscovery: false,
  transports: {
    [tempo.id]: http(),
  },
})
// [!endregion setup]
