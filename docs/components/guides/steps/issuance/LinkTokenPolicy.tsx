import * as React from 'react'
import { Hooks } from 'wagmi/tempo'
import { useConnectionEffect } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function LinkTokenPolicy(props: DemoStepProps) {
  const { stepNumber } = props
  const { data } = useDemoContext()
  const [expanded, setExpanded] = React.useState(false)

  const { tokenAddress, policyId } = data

  const { data: metadata, refetch: refetchMetadata } =
    Hooks.token.useGetMetadata({
      token: tokenAddress,
    })

  const linkPolicy = Hooks.token.useChangeTransferPolicySync({
    mutation: {
      onSuccess() {
        refetchMetadata()
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      linkPolicy.reset()
    },
  })

  const handleLinkPolicy = async () => {
    if (!tokenAddress || !policyId) return

    await linkPolicy.mutateAsync({
      policyId,
      token: tokenAddress,
      feeToken: alphaUsd,
    })
  }

  const isLinking = linkPolicy.isPending
  const isComplete = linkPolicy.isSuccess
  const hasError = linkPolicy.isError

  return (
    <Step
      active={!!tokenAddress && !!policyId && !isComplete}
      completed={isComplete}
      actions={
        expanded ? (
          <Button
            variant="default"
            onClick={() => setExpanded(false)}
            className="text-[14px] -tracking-[2%] font-normal"
            type="button"
          >
            Hide
          </Button>
        ) : (
          <Button
            variant={
              tokenAddress && policyId && !isComplete ? 'accent' : 'default'
            }
            disabled={!tokenAddress || !policyId || isComplete}
            onClick={() => setExpanded(true)}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Enter details
          </Button>
        )
      }
      number={stepNumber}
      title={`Link the policy to ${metadata ? metadata.name : 'your token'}.`}
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-2">
              <div className="flex flex-col flex-1">
                <div className="text-[13px] -tracking-[1%] text-gray9 mb-2">
                  This will link the transfer policy to{' '}
                  {metadata ? metadata.name : 'your token'}, enforcing the
                  blacklist.
                </div>
              </div>
            </div>

            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-4">
              <Button
                variant="accent"
                onClick={handleLinkPolicy}
                disabled={isLinking}
                type="button"
                className="text-[14px] -tracking-[2%] font-normal"
              >
                {isLinking ? 'Linking...' : 'Link Policy'}
              </Button>
            </div>

            {hasError && (
              <div className="text-[13px] text-red-500 mt-2">
                Failed to link policy. Please try again.
              </div>
            )}

            {isComplete && linkPolicy.data && (
              <ExplorerLink hash={linkPolicy.data.receipt.transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
