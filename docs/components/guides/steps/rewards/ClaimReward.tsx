import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'
import { REWARD_AMOUNT } from './Constants'

export function ClaimReward(props: DemoStepProps) {
  const { stepNumber, last = false, flowDependencies = [] } = props
  const { address } = useConnection()
  const { getData, checkFlowDependencies } = useDemoContext()
  const queryClient = useQueryClient()
  const tokenAddress = getData('tokenAddress')

  const [expanded, setExpanded] = React.useState(true)

  const { data: balance } = Hooks.token.useGetBalance({
    account: address,
    token: tokenAddress,
  })

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })

  const claim = Hooks.reward.useClaimSync({
    mutation: {
      onSettled() {
        queryClient.refetchQueries({ queryKey: ['getBalance'] })
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      setExpanded(true)
      claim.reset()
    },
  })

  const flowDependenciesMet = checkFlowDependencies(flowDependencies)

  const active = React.useMemo(() => {
    const activeWithBalance = Boolean(
      address && balance && balance > 0n && tokenAddress && flowDependenciesMet,
    )
    if (last) return activeWithBalance
    return activeWithBalance && !claim.isSuccess
  }, [
    address,
    balance,
    tokenAddress,
    flowDependenciesMet,
    claim.isSuccess,
    last,
  ])

  return (
    <Step
      active={active}
      completed={claim.isSuccess}
      number={stepNumber}
      title="Claim your rewards."
      error={claim.error}
      actions={
        claim.isSuccess ? (
          <Button
            variant="default"
            onClick={() => setExpanded(!expanded)}
            className="text-[14px] -tracking-[2%] font-normal"
            type="button"
          >
            {expanded ? 'Hide' : 'Show'}
          </Button>
        ) : (
          <Button
            variant={active ? 'accent' : 'default'}
            disabled={!active || claim.isPending}
            onClick={() => {
              if (!tokenAddress) return
              claim.mutate({
                token: tokenAddress,
                feeToken: alphaUsd,
              })
            }}
          >
            {claim.isPending ? 'Claiming...' : 'Claim'}
          </Button>
        )
      }
    >
      {claim.data && expanded && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="text-[13px] text-gray9 -tracking-[2%]">
              Successfully claimed {REWARD_AMOUNT} {metadata?.name ?? 'token'}.
            </div>
            <ExplorerLink hash={claim.data.receipt.transactionHash} />
          </div>
        </div>
      )}
    </Step>
  )
}
