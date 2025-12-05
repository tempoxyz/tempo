import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { parseUnits } from 'viem'
import { useAccount, useAccountEffect } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

const validatorToken = alphaUsd

export function MintFeeAmmLiquidity(
  props: DemoStepProps & { waitForBalance: boolean },
) {
  const { stepNumber, last = false, waitForBalance = true } = props
  const { address } = useAccount()
  const { getData } = useDemoContext()
  const queryClient = useQueryClient()

  // Get the address of the token created in a previous step
  const tokenAddress = getData('tokenAddress')

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })
  const { data: tokenBalance } = Hooks.token.useGetBalance({
    account: address,
    token: tokenAddress,
  })
  const mintFeeLiquidity = Hooks.amm.useMintSync({
    mutation: {
      onSettled() {
        queryClient.refetchQueries({ queryKey: ['getPool'] })
        queryClient.refetchQueries({ queryKey: ['getLiquidityBalance'] })
      },
    },
  })
  useAccountEffect({
    onDisconnect() {
      mintFeeLiquidity.reset()
    },
  })

  const active = React.useMemo(() => {
    const balanceCheck = waitForBalance
      ? Boolean(tokenBalance && tokenBalance > 0n)
      : true
    return Boolean(address && tokenAddress && balanceCheck)
  }, [address, tokenAddress, tokenBalance])

  return (
    <Step
      active={active && (last ? true : !mintFeeLiquidity.isSuccess)}
      completed={mintFeeLiquidity.isSuccess}
      actions={
        <Button
          variant={
            active
              ? mintFeeLiquidity.isSuccess
                ? 'default'
                : 'accent'
              : 'default'
          }
          disabled={!active}
          onClick={() => {
            if (!address || !tokenAddress) return
            mintFeeLiquidity.mutate({
              userTokenAddress: tokenAddress,
              validatorTokenAddress: validatorToken,
              validatorTokenAmount: parseUnits('100', 6),
              to: address,
              feeToken: alphaUsd,
            })
          }}
          type="button"
          className="text-[14px] -tracking-[2%] font-normal"
        >
          Add Liquidity
        </Button>
      }
      number={stepNumber}
      title={`Mint 100 pathUSD of Fee Liquidity for ${metadata ? metadata.name : 'your token'}.`}
    >
      {mintFeeLiquidity.data && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <ExplorerLink
              hash={mintFeeLiquidity.data.receipt.transactionHash}
            />
          </div>
        </div>
      )}
    </Step>
  )
}
