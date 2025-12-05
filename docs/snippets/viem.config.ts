// [!region setup]
import { tempo } from 'tempo.ts/chains'
import { tempoActions } from 'tempo.ts/viem'
import { createClient, http, publicActions, walletActions } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

const credentials = `${process.env['TEMPO_USERNAME']}:${process.env['TEMPO_PASSWORD']}`

export const client = createClient({
  account: privateKeyToAccount('0x...'),
  chain: tempo({ feeToken: '0x20c0000000000000000000000000000000000001' }),
  transport: http(undefined, {
    fetchOptions: {
      headers: {
        Authorization: `Basic ${btoa(credentials)}`,
      },
    },
  }),
})
  .extend(publicActions)
  .extend(walletActions)
  .extend(tempoActions())
// [!endregion setup]
