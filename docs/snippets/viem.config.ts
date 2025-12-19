// [!region setup]
// @noErrors
import { tempoTestnet } from 'viem/chains'
import { tempoActions } from 'viem/tempo'
import { createClient, http, publicActions, walletActions } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

export const client = createClient({
  account: privateKeyToAccount('0x...'),
  chain: tempoTestnet.extend({ feeToken: '0x20c0000000000000000000000000000000000001' }),
  transport: http(),
})
  .extend(publicActions)
  .extend(walletActions)
  .extend(tempoActions())
// [!endregion setup]
