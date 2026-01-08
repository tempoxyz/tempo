import * as React from 'react'
import { Hooks } from 'wagmi/tempo'
import { type Log, parseUnits } from 'viem'
import { Actions, Addresses } from 'viem/tempo'
import { useConnection, useConnectionEffect, useSendCallsSync } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd, pathUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function PlaceOrder(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const { setData, clearData, getData } = useDemoContext()

  const orderId = getData('orderId')

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: alphaUsd,
  })

  const sendCalls = useSendCallsSync()

  useConnectionEffect({
    onDisconnect() {
      sendCalls.reset()
      clearData('orderId')
    },
  })

  // Extract and store orderId after successful order placement
  React.useEffect(() => {
    if (sendCalls.isSuccess && sendCalls.data?.receipts?.[0]) {
      try {
        const {
          args: { orderId },
        } = Actions.dex.place.extractEvent(
          sendCalls.data.receipts[0].logs as Log[],
        )
        console.log('orderId', orderId)
        setData('orderId', orderId)
      } catch (error) {
        console.error('Failed to extract orderId:', error)
      }
    }
  }, [sendCalls.isSuccess, sendCalls.data, setData])

  const amount = parseUnits('100', metadata?.decimals || 6)

  const calls = [
    Actions.token.approve.call({
      spender: Addresses.stablecoinExchange,
      amount,
      token: pathUsd,
    }),
    Actions.dex.place.call({
      amount,
      tick: 0,
      token: alphaUsd,
      type: 'buy',
    }),
  ]

  const active = React.useMemo(() => {
    return !!address && !orderId
  }, [address, orderId])

  return (
    <Step
      active={active && (last ? true : !sendCalls.isSuccess)}
      completed={sendCalls.isSuccess || !!orderId}
      actions={
        <Button
          variant={
            active ? (sendCalls.isSuccess ? 'default' : 'accent') : 'default'
          }
          disabled={!active}
          onClick={() => {
            sendCalls.sendCallsSync({
              calls,
            })
          }}
          type="button"
          className="text-[14px] -tracking-[2%] font-normal"
        >
          {sendCalls.isPending ? 'Placing Order...' : 'Place Order'}
        </Button>
      }
      number={stepNumber}
      title="Approve spend and place buy order for 100 AlphaUSD"
    >
      {sendCalls.isSuccess && sendCalls.data && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <ExplorerLink
              hash={
                sendCalls.data.receipts?.at(0)?.transactionHash as `0x${string}`
              }
            />
          </div>
        </div>
      )}
    </Step>
  )
}
