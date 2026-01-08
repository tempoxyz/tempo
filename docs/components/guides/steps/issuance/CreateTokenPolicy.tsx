import * as React from 'react'
import { useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, FAKE_RECIPIENT, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function CreateTokenPolicy(props: DemoStepProps) {
  const { stepNumber, flowDependencies = [] } = props
  const { data, setData, checkFlowDependencies } = useDemoContext()
  const [expanded, setExpanded] = React.useState(false)

  const { tokenAddress } = data

  const createPolicy = Hooks.policy.useCreateSync({
    mutation: {
      onSuccess(result) {
        setData('policyId', result.policyId)
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      createPolicy.reset()
    },
  })

  const handleCreatePolicy = async () => {
    if (!tokenAddress) return

    await createPolicy.mutateAsync({
      addresses: [FAKE_RECIPIENT],
      type: 'blacklist',
      feeToken: alphaUsd,
    })
  }

  const isCreating = createPolicy.isPending
  const isComplete = createPolicy.isSuccess
  const hasError = createPolicy.isError

  const active =
    !!tokenAddress && !isComplete && checkFlowDependencies(flowDependencies)

  return (
    <Step
      active={active}
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
            variant={active ? 'accent' : 'default'}
            disabled={!active}
            onClick={() => setExpanded(true)}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Enter details
          </Button>
        )
      }
      number={stepNumber}
      title="Create a transfer policy."
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-2">
              <div className="flex flex-col flex-1">
                <div className="text-[13px] -tracking-[1%] text-gray9 mb-2">
                  This will create a blacklist policy that blocks{' '}
                  {FAKE_RECIPIENT} from sending or receiving tokens.
                </div>
              </div>
            </div>

            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-4">
              <Button
                variant="accent"
                onClick={handleCreatePolicy}
                disabled={isCreating}
                type="button"
                className="text-[14px] -tracking-[2%] font-normal"
              >
                {isCreating ? 'Creating...' : 'Create Policy'}
              </Button>
            </div>

            {hasError && (
              <div className="text-[13px] text-red-500 mt-2">
                Failed to create policy. Please try again.
              </div>
            )}

            {isComplete && createPolicy.data && (
              <ExplorerLink hash={createPolicy.data.receipt.transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
