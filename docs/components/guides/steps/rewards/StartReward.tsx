import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { useAccount, useAccountEffect } from 'wagmi'
import { useQueryClient } from '@tanstack/react-query'
import { parseUnits } from 'viem'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

const REWARD_AMOUNT = '50'

export function StartReward(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useAccount()
  const { getData, setData } = useDemoContext()
  const queryClient = useQueryClient()
  const tokenAddress = getData('tokenAddress')

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

  const start = Hooks.reward.useStartSync({
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

  useAccountEffect({
    onDisconnect() {
      start.reset()
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
        rewardInfo.rewardRecipient !==
          '0x0000000000000000000000000000000000000000',
    )
    if (last) return activeWithBalance
    return activeWithBalance && !start.isSuccess
  }, [
    address,
    balance,
    tokenAddress,
    metadata,
    start.isSuccess,
    last,
    rewardInfo,
  ])

  return (
    <Step
      active={active}
      completed={start.isSuccess}
      number={stepNumber}
      title={`Start a reward of ${REWARD_AMOUNT} tokens.`}
      error={start.error}
      actions={
        !start.isSuccess && (
          <Button
            variant={active ? 'accent' : 'default'}
            disabled={!active || start.isPending || !metadata}
            onClick={() => {
              if (!tokenAddress || !metadata) return
              start.mutate({
                amount: parseUnits(REWARD_AMOUNT, metadata.decimals),
                token: tokenAddress,
                feeToken: alphaUsd,
              })
            }}
          >
            {start.isPending ? 'Starting...' : 'Start Reward'}
          </Button>
        )
      }
    >
      {start.data && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="text-[13px] text-gray9 -tracking-[2%]">
              Successfully started reward distribution of {REWARD_AMOUNT}{' '}
              tokens.
            </div>
            <ExplorerLink hash={start.data.receipt.transactionHash} />
          </div>
        </div>
      )}
    </Step>
  )
}
