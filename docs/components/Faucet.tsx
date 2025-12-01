import { useQuery } from '@tanstack/react-query'
import { Hex } from 'ox'
import * as React from 'react'
import { Abis } from 'tempo.ts/viem'
import { Actions, Hooks } from 'tempo.ts/wagmi'
import { type Address, formatUnits, parseEventLogs } from 'viem'
import { useAccount, useConfig } from 'wagmi'
import LucideDollarSign from '~icons/lucide/dollar-sign'

import { Container } from './Container'
import { Button, StringFormatter } from './guides/Demo'

export function Faucet() {
  const { address } = useAccount()
  const config = useConfig()

  const [lastAddress, setLastAddress] = React.useState<Address | undefined>(
    undefined,
  )

  const fund = Hooks.faucet.useFundSync()
  const receivedTokens = useQuery({
    enabled: Boolean(fund.data),
    queryKey: ['receivedTokens', fund.data] as const,
    async queryFn({ queryKey }) {
      const [, receipts] = queryKey
      if (!receipts) throw new Error('receipts not found')
      const events = receipts.flatMap((receipt) =>
        parseEventLogs({
          abi: Abis.tip20,
          eventName: 'Transfer',
          logs: receipt.logs,
          args: {
            to: lastAddress,
          },
        }),
      )
      return await Promise.all(
        events.map(async (event) => {
          const metadata = await Actions.token.getMetadata(config, {
            token: event.address,
          })
          return {
            amount: formatUnits(event.args.amount, metadata.decimals),
            name: metadata.name,
          }
        }),
      )
    },
  })

  return (
    <Container>
      <div className="flex flex-col justify-between gap-3">
        <header className="flex items-center justify-between">
          <div className="flex flex-col gap-2">
            <div className="flex gap-3 text-[16px] dark:text-white font-normal text-black -tracking-[1%]">
              <div className="text-[13px] dark:text-white text-black size-7 rounded-full text-center flex items-center justify-center tabular-nums opacity-40 group-data-[completed=true]:opacity-100 bg-gray4">
                <LucideDollarSign className="text-gray12" />
              </div>
              Fund address
            </div>
            <div className="text-[14px] text-gray9 -tracking-[1%] leading-normal">
              Enter an address below to receive testnet tokens. This action is{' '}
              <span className="dark:text-white text-black">free</span>.
            </div>
          </div>
        </header>

        <form
          onSubmit={(event) => {
            event.preventDefault()
            const formData = new FormData(event.target as HTMLFormElement)
            const address = formData.get('address')
            Hex.assert(address)
            fund.mutate({ account: address })
            setLastAddress(address)
          }}
        >
          <div className="flex gap-2">
            <input
              autoCapitalize="none"
              autoComplete="off"
              autoCorrect="off"
              className="w-full h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-medium -tracking-[2%] placeholder-gray9 text-black dark:text-white"
              defaultValue={address}
              name="address"
              required
              spellCheck={false}
              placeholder="0x1A60E1922C498c6fD690dB24543fb6Cf0e15F2E7"
            />
            <Button
              variant="accent"
              type="submit"
              disabled={fund.isPending || receivedTokens.isFetching}
            >
              <div className="px-2!">
                {fund.isPending || receivedTokens.isFetching
                  ? 'Funding...'
                  : 'Fund'}
              </div>
            </Button>
          </div>
        </form>

        {fund.isSuccess && lastAddress && receivedTokens.data && (
          // TODO: add link to explorer (address).
          <div className="flex flex-col text-[13px] text-gray9 gap-1">
            <div>
              Address{' '}
              <span className="dark:text-white text-black">
                {StringFormatter.truncate(lastAddress, {
                  start: 6,
                  end: 4,
                })}
              </span>{' '}
              successfully funded with:
            </div>
            <div className="flex flex-col gap-2">
              {receivedTokens.data?.map((token) => (
                // TODO: add link to explorer (receipt).
                <div className="leading-none">
                  → {new Intl.NumberFormat().format(Number(token.amount))}{' '}
                  <span className="dark:text-white text-black">
                    {token.name}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {fund.error && (
          <div className="bg-destructiveTint text-destructive rounded py-2 px-3 text-[14px] -tracking-[2%] leading-normal font-normal">
            {'shortMessage' in fund.error
              ? fund.error.shortMessage
              : (fund.error as Error).message}
          </div>
        )}
      </div>
    </Container>
  )
}
