import * as React from 'react'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import type { DemoStepProps } from '../types'

export function CancelOrder(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const { getData, clearData } = useDemoContext()

  const orderId = getData('orderId')
  const cancelOrder = Hooks.dex.useCancelSync()

  useConnectionEffect({
    onDisconnect() {
      cancelOrder.reset()
    },
  })

  // Clear orderId from context after successful cancellation
  React.useEffect(() => {
    if (cancelOrder.isSuccess) {
      clearData('orderId')
    }
  }, [cancelOrder.isSuccess, clearData])

  const active = React.useMemo(() => {
    return !!address && !!orderId
  }, [address, orderId])

  return (
    <Step
      active={active && (last ? true : !cancelOrder.isSuccess)}
      completed={cancelOrder.isSuccess}
      actions={
        <Button
          variant={
            active ? (cancelOrder.isSuccess ? 'default' : 'accent') : 'default'
          }
          disabled={!active}
          onClick={() => {
            if (orderId) {
              cancelOrder.mutate({ orderId })
            }
          }}
          type="button"
          className="text-[14px] -tracking-[2%] font-normal"
        >
          {cancelOrder.isPending ? 'Canceling...' : 'Cancel Order'}
        </Button>
      }
      number={stepNumber}
      title="Cancel the order"
    >
      {cancelOrder.isSuccess && cancelOrder.data && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <ExplorerLink hash={cancelOrder.data.receipt.transactionHash} />
            <div className="mt-2 text-xs text-gray-600">
              Order #{orderId?.toString()} has been cancelled. Refunded tokens
              are in your exchange balance.
            </div>
          </div>
        </div>
      )}
    </Step>
  )
}
