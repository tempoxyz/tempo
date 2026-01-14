// [!region viem]
// @errors: 2307
import { client } from './viem.config'

const { receipt } = await client.fee.setUserTokenSync({
  token: '0x20c0000000000000000000000000000000000001',
})

console.log('Transaction hash:', receipt.transactionHash)
// @log: Transaction hash: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
// [!endregion viem]

// [!region wagmi-hooks]
// @errors: 2307
import { Hooks } from 'wagmi/tempo'

const { data: result, mutate } = Hooks.fee.useSetUserTokenSync()

// Call `mutate` in response to user action (e.g. button click, form submission)
mutate({
  token: '0x20c0000000000000000000000000000000000001',
})

console.log('Transaction hash:', result.receipt.transactionHash)
// @log: Transaction hash: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
// [!endregion wagmi-hooks]

