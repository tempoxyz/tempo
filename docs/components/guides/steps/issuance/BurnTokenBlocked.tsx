import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { parseUnits } from 'viem'
import { useAccount, useAccountEffect } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, FAKE_RECIPIENT, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function BurnTokenBlocked(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useAccount()
  const { getData } = useDemoContext()
  const queryClient = useQueryClient()

  const [expanded, setExpanded] = React.useState(false)

  // Get the address of the token created in a previous step
  const tokenAddress = getData('tokenAddress')

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })
  const { data: hasRole } = Hooks.token.useHasRole({
    account: address,
    token: tokenAddress,
    role: 'burnBlocked',
  })
  const { data: recipientBalance } = Hooks.token.useGetBalance({
    account: FAKE_RECIPIENT,
    token: tokenAddress,
  })

  const burnBlocked = Hooks.token.useBurnBlockedSync({
    mutation: {
      onSettled() {
        queryClient.refetchQueries({ queryKey: ['getBalance'] })
      },
    },
  })
  useAccountEffect({
    onDisconnect() {
      setExpanded(false)
      burnBlocked.reset()
    },
  })

  const handleBurnBlocked = () => {
    if (!tokenAddress || !address || !metadata) return

    burnBlocked.mutate({
      amount: parseUnits('100', metadata.decimals),
      from: FAKE_RECIPIENT,
      token: tokenAddress,
      feeToken: alphaUsd,
    })
  }

  const hasSufficientBalance =
    recipientBalance &&
    metadata &&
    recipientBalance >= parseUnits('100', metadata.decimals)

  const active = React.useMemo(() => {
    return Boolean(
      tokenAddress &&
        hasRole &&
        hasSufficientBalance &&
        metadata.transferPolicyId &&
        metadata.transferPolicyId !== 1n,
    )
  }, [tokenAddress, hasRole, hasSufficientBalance, metadata])

  return (
    <Step
      active={active && (last ? true : !burnBlocked.isSuccess)}
      completed={burnBlocked.isSuccess}
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
              active
                ? burnBlocked.isSuccess
                  ? 'default'
                  : 'accent'
                : 'default'
            }
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
      title={`Burn 100 ${metadata ? metadata.name : 'tokens'} from blocked address.`}
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-2">
              <div className="flex flex-col flex-2">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="blockedAddress"
                >
                  Blocked address
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  data-1p-ignore
                  type="text"
                  name="blockedAddress"
                  value={FAKE_RECIPIENT}
                  disabled={true}
                  onChange={(_e) => {}}
                  placeholder="0x..."
                />
              </div>
              <Button
                variant={address ? 'accent' : 'default'}
                disabled={!address}
                onClick={handleBurnBlocked}
                type="button"
                className="text-[14px] -tracking-[2%] font-normal"
              >
                {burnBlocked.isPending ? 'Burning...' : 'Burn'}
              </Button>
            </div>
            {burnBlocked.isSuccess && burnBlocked.data && (
              <ExplorerLink hash={burnBlocked.data.receipt.transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
