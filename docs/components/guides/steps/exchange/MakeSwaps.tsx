import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { parseUnits } from 'viem'
import { useAccount, useAccountEffect } from 'wagmi'

import { Step } from '../../Demo'
import { alphaUsd, betaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'
import { BuySwap } from './BuySwap'
import { SellSwap } from './SellSwap'

export function MakeSwaps({ stepNumber, last = false }: DemoStepProps) {
  const { address } = useAccount()
  const [buyCompleted, setBuyCompleted] = React.useState(false)
  const [sellCompleted, setSellCompleted] = React.useState(false)

  const { data: alphaUsdMetadata } = Hooks.token.useGetMetadata({
    token: alphaUsd,
  })
  const { data: betaUsdMetadata } = Hooks.token.useGetMetadata({
    token: betaUsd,
  })
  const { data: alphaUsdBalance } = Hooks.token.useGetBalance({
    account: address,
    token: alphaUsd,
  })
  const { data: betaUsdBalance } = Hooks.token.useGetBalance({
    account: address,
    token: betaUsd,
  })

  const active = React.useMemo(() => {
    return (
      !!address &&
      (alphaUsdBalance || 0n) >
        parseUnits('11', alphaUsdMetadata?.decimals || 6) &&
      (betaUsdBalance || 0n) > parseUnits('11', betaUsdMetadata?.decimals || 6)
    )
  }, [
    address,
    alphaUsdBalance,
    betaUsdBalance,
    alphaUsdMetadata?.decimals,
    betaUsdMetadata?.decimals,
  ])

  const completed = buyCompleted && sellCompleted

  useAccountEffect({
    onDisconnect() {
      setBuyCompleted(false)
      setSellCompleted(false)
    },
  })

  return (
    <Step
      active={active && (last ? true : !completed)}
      completed={completed}
      number={stepNumber}
      title="Make Swaps"
    >
      {(active || completed) && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex flex-col gap-6">
              <BuySwap onSuccess={() => setBuyCompleted(true)} />
              <SellSwap onSuccess={() => setSellCompleted(true)} />
            </div>
          </div>
        </div>
      )}
    </Step>
  )
}
