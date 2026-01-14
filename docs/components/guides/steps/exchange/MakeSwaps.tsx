import * as React from 'react'
import { parseUnits } from 'viem'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'

import { Step } from '../../Demo'
import { betaUsd, DONOTUSE } from '../../tokens'
import type { DemoStepProps } from '../types'
import { BuySwap } from './BuySwap'
import { SellSwap } from './SellSwap'

export function MakeSwaps({ stepNumber, last = false }: DemoStepProps) {
  const { address } = useConnection()
  const [buyCompleted, setBuyCompleted] = React.useState(false)
  const [sellCompleted, setSellCompleted] = React.useState(false)

  const { data: DONOTUSEMetadata } = Hooks.token.useGetMetadata({
    token: DONOTUSE,
  })
  const { data: betaUsdMetadata } = Hooks.token.useGetMetadata({
    token: betaUsd,
  })
  const { data: DONOTUSEBalance } = Hooks.token.useGetBalance({
    account: address,
    token: DONOTUSE,
  })
  const { data: betaUsdBalance } = Hooks.token.useGetBalance({
    account: address,
    token: betaUsd,
  })

  const active = React.useMemo(() => {
    return (
      !!address &&
      (DONOTUSEBalance || 0n) >
        parseUnits('11', DONOTUSEMetadata?.decimals || 6) &&
      (betaUsdBalance || 0n) > parseUnits('11', betaUsdMetadata?.decimals || 6)
    )
  }, [
    address,
    DONOTUSEBalance,
    betaUsdBalance,
    DONOTUSEMetadata?.decimals,
    betaUsdMetadata?.decimals,
  ])

  const completed = buyCompleted && sellCompleted

  useConnectionEffect({
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
