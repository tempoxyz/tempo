import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { parseUnits } from 'viem'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

const validatorToken = alphaUsd

export function BurnFeeAmmLiquidity(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const { getData } = useDemoContext()
  const queryClient = useQueryClient()

  const tokenAddress = getData('tokenAddress')

  const { data: lpBalance } = Hooks.amm.useLiquidityBalance({
    address,
    userToken: tokenAddress,
    validatorToken,
  })

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })
  const { data: validatorMetadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })

  const burnLiquidity = Hooks.amm.useBurnSync({
    mutation: {
      onSettled() {
        queryClient.refetchQueries({ queryKey: ['getPool'] })
        queryClient.refetchQueries({ queryKey: ['getLiquidityBalance'] })
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      burnLiquidity.reset()
    },
  })

  const hasSufficientBalance =
    lpBalance && lpBalance >= parseUnits('10', validatorMetadata?.decimals || 6)
  const active = React.useMemo(() => {
    return Boolean(address && tokenAddress && hasSufficientBalance)
  }, [address, tokenAddress, hasSufficientBalance])

  return (
    <Step
      active={active && (last ? true : !burnLiquidity.isSuccess)}
      completed={burnLiquidity.isSuccess}
      actions={
        <Button
          variant={
            active
              ? burnLiquidity.isSuccess
                ? 'default'
                : 'accent'
              : 'default'
          }
          disabled={!active}
          onClick={() => {
            if (!address || !tokenAddress) return
            burnLiquidity.mutate({
              userToken: tokenAddress,
              validatorToken,
              liquidity: parseUnits('10', validatorMetadata?.decimals || 6),
              to: address,
              feeToken: alphaUsd,
            })
          }}
          type="button"
          className="text-[14px] -tracking-[2%] font-normal"
        >
          Burn Liquidity
        </Button>
      }
      number={stepNumber}
      title={`Burn 10 LP tokens from ${metadata ? metadata.name : 'your token'} pool.`}
    >
      {burnLiquidity.data && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <ExplorerLink hash={burnLiquidity.data.receipt.transactionHash} />
          </div>
        </div>
      )}
    </Step>
  )
}
