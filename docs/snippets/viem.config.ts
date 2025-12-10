// [!region setup]
import { tempo } from 'tempo.ts/chains'
import { tempoActions } from 'tempo.ts/viem'
import { createClient, http, publicActions, walletActions } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

export const client = createClient({
  account: privateKeyToAccount('0x...'),
  chain: tempo({ feeToken: '0x20c0000000000000000000000000000000000001' }),
  transport: http(),
})
  .extend(publicActions)
  .extend(walletActions)
  .extend(tempoActions())
// [!endregion setup]
