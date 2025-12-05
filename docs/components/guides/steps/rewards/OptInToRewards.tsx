import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { useAccount, useAccountEffect } from 'wagmi'
import { useQueryClient } from '@tanstack/react-query'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function OptInToRewards(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useAccount()
  const { getData } = useDemoContext()
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

  const setRecipient = Hooks.reward.useSetRecipientSync({
    mutation: {
      onSettled() {
        queryClient.refetchQueries({ queryKey: ['getUserRewardInfo'] })
      },
    },
  })

  useAccountEffect({
    onDisconnect() {
      setExpanded(true)
      setRecipient.reset()
    },
  })

  const active = React.useMemo(() => {
    const activeWithBalance = Boolean(
      address && balance && balance > 0n && tokenAddress,
    )
    if (last) return activeWithBalance
    return activeWithBalance && !setRecipient.isSuccess
  }, [address, balance, tokenAddress, setRecipient.isSuccess, last])

  return (
    <Step
      active={active}
      completed={setRecipient.isSuccess}
      number={stepNumber}
      title={`Opt in to receive ${metadata?.name || 'token'} rewards.`}
      error={setRecipient.error}
      actions={
        setRecipient.isSuccess ? (
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
            disabled={!active || setRecipient.isPending}
            onClick={() => {
              if (!address || !tokenAddress) return
              setRecipient.mutate({
                recipient: address,
                token: tokenAddress,
                feeToken: alphaUsd,
              })
            }}
          >
            {setRecipient.isPending ? 'Opting in...' : 'Opt In'}
          </Button>
        )
      }
    >
      {setRecipient.data && expanded && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="text-[13px] text-gray9 -tracking-[2%]">
              Successfully opted in to rewards.
            </div>
            <ExplorerLink hash={setRecipient.data.receipt.transactionHash} />
          </div>
        </div>
      )}
    </Step>
  )
}
