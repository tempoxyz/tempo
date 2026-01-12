import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { parseUnits } from 'viem'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'
import { REWARD_AMOUNT, REWARD_RECIPIENT_UNSET } from './Constants'

export function DistributeReward(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const { getData, setData } = useDemoContext()
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

  const { data: rewardInfo } = Hooks.reward.useUserRewardInfo({
    token: tokenAddress,
    account: address,
  })

  const distribute = Hooks.reward.useStartSync({
    mutation: {
      onSettled(data) {
        queryClient.refetchQueries({ queryKey: ['getUserRewardInfo'] })
        queryClient.refetchQueries({ queryKey: ['getBalance'] })
        if (data) {
          setData('rewardId', data.id)
        }
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      setExpanded(true)
      distribute.reset()
    },
  })

  const active = React.useMemo(() => {
    const activeWithBalance = Boolean(
      address &&
        balance &&
        balance > 0n &&
        tokenAddress &&
        metadata &&
        !!rewardInfo &&
        rewardInfo.rewardRecipient !== REWARD_RECIPIENT_UNSET,
    )
    if (last) return activeWithBalance
    return activeWithBalance && !distribute.isSuccess
  }, [
    address,
    balance,
    tokenAddress,
    metadata,
    distribute.isSuccess,
    last,
    rewardInfo,
  ])

  return (
    <Step
      active={active}
      completed={distribute.isSuccess}
      number={stepNumber}
      title={`Distribute a reward of ${REWARD_AMOUNT} ${metadata?.name || 'tokens'}.`}
      error={distribute.error}
      actions={
        distribute.isSuccess ? (
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
            disabled={!active || distribute.isPending || !metadata}
            onClick={() => {
              if (!tokenAddress || !metadata) return
              distribute.mutate({
                amount: parseUnits(REWARD_AMOUNT, metadata.decimals),
                token: tokenAddress,
                feeToken: alphaUsd,
              })
            }}
          >
            {distribute.isPending ? 'Distributing...' : 'Distribute Reward'}
          </Button>
        )
      }
    >
      {distribute.data && expanded && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="text-[13px] text-gray9 -tracking-[2%]">
              Successfully distributed reward.
            </div>
            <ExplorerLink hash={distribute.data.receipt.transactionHash} />
          </div>
        </div>
      )}
    </Step>
  )
}
