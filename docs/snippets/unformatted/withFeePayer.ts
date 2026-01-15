// [!region client]
import { createClient, http, walletActions } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { tempoModerato } from 'viem/chains'
import { withFeePayer } from 'viem/tempo'

const client = createClient({
  account: privateKeyToAccount('0x...'),
  chain: tempoModerato,
  transport: withFeePayer( // [!code hl]
    http(), // [!code hl]
    http('http://localhost:3000'), // [!code hl]
    { policy: 'sign-only' }, // [!code hl]
  ), // [!code hl]
}).extend(walletActions)
// [!endregion client]

// [!region usage]
// Regular transaction
const receipt1 = await client.sendTransactionSync({
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbb',
})

// Sponsored transaction // [!code hl]
const receipt2 = await client.sendTransactionSync({ // [!code hl]
  feePayer: true, // [!code hl]
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbb', // [!code hl]
}) // [!code hl]
// [!endregion usage]

// [!region server]
import { createClient, http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { tempoModerato } from 'viem/chains'
import { Handler } from 'tempo.ts/server'

const client = createClient({
  chain: tempoModerato.extend({ 
    feeToken: '0x20c0000000000000000000000000000000000001' 
  }),
  transport: http(),
})

const handler = Handler.feePayer({ // [!code hl]
  account: privateKeyToAccount('0x...'), // [!code hl]
  client, // [!code hl]
}) // [!code hl]

const server = createServer(handler.listener)
server.listen(3000)
// [!endregion server]