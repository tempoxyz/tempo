import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { formatUnits } from 'viem'
import { useAccount, useAccountEffect } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function ClaimReward(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useAccount()
  const { getData } = useDemoContext()
  const queryClient = useQueryClient()
  const tokenAddress = getData('tokenAddress')

  const { data: balance } = Hooks.token.useGetBalance({
    account: address,
    token: tokenAddress,
  })

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })

  const { data: rewardInfo, isLoading: rewardInfoLoading } =
    Hooks.reward.useUserRewardInfo({
      token: tokenAddress,
      account: address,
    })

  const claim = Hooks.reward.useClaimSync({
    mutation: {
      onSettled() {
        queryClient.refetchQueries({ queryKey: ['getUserRewardInfo'] })
        queryClient.refetchQueries({ queryKey: ['getBalance'] })
      },
    },
  })

  useAccountEffect({
    onDisconnect() {
      claim.reset()
    },
  })

  const hasClaimableRewards = Boolean(
    rewardInfo?.rewardBalance && rewardInfo.rewardBalance > 0n,
  )

  const active = React.useMemo(() => {
    const activeWithBalance = Boolean(
      address && balance && balance > 0n && tokenAddress && hasClaimableRewards,
    )
    if (last) return activeWithBalance
    return activeWithBalance && !claim.isSuccess
  }, [
    address,
    balance,
    tokenAddress,
    hasClaimableRewards,
    claim.isSuccess,
    last,
  ])

  const formatBalance = (value: bigint | undefined) => {
    if (!value || !metadata) return '0'
    return formatUnits(value, metadata.decimals)
  }

  return (
    <Step
      active={active}
      completed={claim.isSuccess}
      number={stepNumber}
      title="View and claim your rewards."
      error={claim.error}
      actions={
        !claim.isSuccess && (
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
      {active && !claim.isSuccess && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            {rewardInfoLoading ? (
              <div className="text-[13px] text-gray9 -tracking-[2%]">
                Loading reward info...
              </div>
            ) : rewardInfo ? (
              <div className="bg-gray2 rounded-[10px] p-4 text-[13px] -tracking-[2%] leading-snug flex flex-col gap-2">
                <div className="flex justify-between">
                  <span className="text-gray9">Reward Recipient:</span>
                  <span className="text-primary font-medium font-mono text-[11px]">
                    {rewardInfo.rewardRecipient === address
                      ? 'You'
                      : `${rewardInfo.rewardRecipient.slice(0, 6)}...${rewardInfo.rewardRecipient.slice(-4)}`}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray9">Claimable Rewards:</span>
                  <span className="text-primary font-medium">
                    {formatBalance(rewardInfo.rewardBalance)}{' '}
                    {metadata?.symbol ?? ''}
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-[13px] text-gray9 -tracking-[2%]">
                No reward info available.
              </div>
            )}
          </div>
        </div>
      )}
      {claim.data && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="text-[13px] text-gray9 -tracking-[2%]">
              Successfully claimed your rewards.
            </div>
            <ExplorerLink hash={claim.data.receipt.transactionHash} />
          </div>
        </div>
      )}
    </Step>
  )
}
