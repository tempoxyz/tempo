import * as React from 'react'
import { Tick } from 'viem/tempo'
import { Hooks } from 'tempo.ts/wagmi'
import { formatUnits } from 'viem'
import { useDemoContext } from '../../../DemoContext'
import { Button, Step } from '../../Demo'
import type { DemoStepProps } from '../types'

export function QueryOrder(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { getData } = useDemoContext()
  const [hasQueried, setHasQueried] = React.useState(false)
  const [isQuerying, setIsQuerying] = React.useState(false)

  const orderId = getData('orderId')

  const {
    data: order,
    refetch,
    isSuccess,
  } = Hooks.dex.useOrder({
    orderId: orderId || 0n,
  })

  // Reset query state when orderId changes or becomes undefined
  React.useEffect(() => {
    if (!orderId) {
      setHasQueried(false)
      setIsQuerying(false)
    }
  }, [orderId])

  const active = React.useMemo(() => {
    return !!orderId
  }, [orderId])

  const handleQuery = async () => {
    setIsQuerying(true)
    await refetch()
    setHasQueried(true)
    setIsQuerying(false)
  }

  return (
    <Step
      active={active && (last ? true : !hasQueried)}
      completed={hasQueried}
      actions={
        <Button
          variant={active ? (hasQueried ? 'default' : 'accent') : 'default'}
          disabled={!active || isQuerying}
          onClick={handleQuery}
          type="button"
          className="text-[14px] -tracking-[2%] font-normal"
        >
          {isQuerying
            ? 'Querying...'
            : hasQueried
              ? 'Query Again'
              : 'Query Order'}
        </Button>
      }
      number={stepNumber}
      title={`Query order details${orderId ? ` (ID: ${orderId})` : ''}`}
    >
      {hasQueried && isSuccess && order && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex flex-col gap-3 text-sm">
              {/* Order Type and Price */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-gray11 text-xs uppercase tracking-wider mb-1">
                    Type
                  </div>
                  <div className="font-medium">
                    {order.isFlip ? 'Flip ' : 'Limit '}
                    {order.isBid ? (
                      <span className="text-green-11">Buy</span>
                    ) : (
                      <span className="text-red-11">Sell</span>
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-gray11 text-xs uppercase tracking-wider mb-1">
                    Price
                  </div>
                  <div className="font-mono">
                    ${Tick.toPrice(order.tick)}{' '}
                    <span className="text-gray11 text-xs">
                      (tick: {order.tick})
                    </span>
                  </div>
                </div>
              </div>

              {/* Amounts */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-gray11 text-xs uppercase tracking-wider mb-1">
                    Original Amount
                  </div>
                  <div className="font-mono">
                    {formatUnits(order.amount, 6)} AlphaUSD
                  </div>
                </div>
                <div>
                  <div className="text-gray11 text-xs uppercase tracking-wider mb-1">
                    Remaining
                  </div>
                  <div className="font-mono">
                    {formatUnits(order.remaining, 6)} AlphaUSD
                  </div>
                </div>
              </div>

              {/* Fill Progress */}
              {order.amount > 0n && order.amount !== order.remaining && (
                <div>
                  <div className="text-gray11 text-xs uppercase tracking-wider mb-1">
                    Fill Progress
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 bg-gray-3 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-accent-9 transition-all"
                        style={{
                          width: `${Math.max(0, Math.min(100, Number(((order.amount - order.remaining) * 10000n) / order.amount) / 100))}%`,
                        }}
                      />
                    </div>
                    <span className="text-xs font-mono">
                      {Math.max(
                        0,
                        Math.min(
                          100,
                          Number(
                            ((order.amount - order.remaining) * 10000n) /
                              order.amount,
                          ) / 100,
                        ),
                      ).toFixed(1)}
                      %
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </Step>
  )
}
