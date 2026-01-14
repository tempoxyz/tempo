// @ts-nocheck
// [!region setup]

import { createClient, http, publicActions, walletActions } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { tempo } from 'viem/chains'
import { tempoActions } from 'viem/tempo'

export const client = createClient({
  account: privateKeyToAccount('0x...'),
  chain: tempo,
  transport: http('https://username:password@rpc.tempo.xyz'),
})
  .extend(publicActions)
  .extend(walletActions)
  .extend(tempoActions())
// [!endregion setup]
