import { Actions, Addresses } from 'viem/tempo'
import { Hooks } from 'tempo.ts/wagmi'
import { formatUnits, parseUnits } from 'viem'
import { useConnection, useConnectionEffect, useSendCallsSync } from 'wagmi'

import { Button, ExplorerLink } from '../../Demo'
import { alphaUsd, betaUsd } from '../../tokens'

export function BuySwap({ onSuccess }: { onSuccess?: () => void }) {
  const { address } = useConnection()

  const { data: tokenInMetadata } = Hooks.token.useGetMetadata({
    token: betaUsd,
  })
  const { data: tokenOutMetadata } = Hooks.token.useGetMetadata({
    token: alphaUsd,
  })

  const amount = parseUnits('10', tokenInMetadata?.decimals || 6)

  const { data: quote } = Hooks.dex.useBuyQuote({
    tokenIn: betaUsd,
    tokenOut: alphaUsd,
    amountOut: amount,
    query: {
      enabled: !!address,
      refetchInterval: 1000,
    },
  })

  // Calculate 0.5% slippage tolerance
  const slippageTolerance = 0.005
  const maxAmountIn = quote
    ? (quote * BigInt(Math.floor((1 + slippageTolerance) * 1000))) / 1000n
    : 0n

  const sendCalls = useSendCallsSync({
    mutation: {
      onSuccess: () => {
        onSuccess?.()
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      sendCalls.reset()
    },
  })

  const calls = [
    Actions.token.approve.call({
      spender: Addresses.stablecoinExchange,
      amount: maxAmountIn,
      token: betaUsd,
    }),
    Actions.dex.buy.call({
      amountOut: amount,
      maxAmountIn,
      tokenIn: betaUsd,
      tokenOut: alphaUsd,
    }),
  ]

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Buy 10 AlphaUSD with BetaUSD</h3>
        <Button
          variant={sendCalls.isSuccess ? 'default' : 'accent'}
          disabled={!address}
          onClick={() => {
            sendCalls.sendCallsSync({
              calls,
            })
          }}
          type="button"
          className="text-[14px] -tracking-[2%] font-normal"
        >
          {sendCalls.isPending ? 'Buying...' : 'Buy'}
        </Button>
      </div>
      {quote && address && (
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-start gap-1">
            <span className="text-gray11 text-[14px]">Quote:</span>
            <span className="text-gray12 text-[14px]">
              10 {tokenOutMetadata?.name} ={' '}
              {formatUnits(quote, tokenInMetadata?.decimals || 6)}{' '}
              {tokenInMetadata?.name}
            </span>
          </div>
          {sendCalls.isSuccess && sendCalls.data && (
            <ExplorerLink
              hash={
                sendCalls.data.receipts?.at(0)?.transactionHash as `0x${string}`
              }
            />
          )}
        </div>
      )}
    </div>
  )
}
