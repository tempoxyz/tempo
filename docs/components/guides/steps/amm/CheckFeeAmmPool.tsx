import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { formatUnits } from 'viem'
import { useConnection } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import { Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

const validatorToken = alphaUsd

export function CheckFeeAmmPool(props: DemoStepProps) {
  const { stepNumber } = props
  const { address } = useConnection()
  const { getData } = useDemoContext()

  const tokenAddress = getData('tokenAddress')

  const { data: pool } = Hooks.amm.usePool({
    userToken: tokenAddress,
    validatorToken,
  })

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

  const active = React.useMemo(() => {
    return Boolean(
      address && tokenAddress && pool && lpBalance && lpBalance > 0n,
    )
  }, [address, tokenAddress, pool, lpBalance])

  return (
    <Step
      active={active}
      completed={active}
      number={stepNumber}
      title={`View Fee AMM pool for ${metadata ? metadata.name : 'your token'}.`}
    >
      {active && pool && lpBalance && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="mt-2 mb-3 p-3 rounded-lg bg-gray2 text-[13px] -tracking-[1%]">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    Your LP Balance
                  </span>
                  <span className="text-gray12">
                    {formatUnits(lpBalance, validatorMetadata?.decimals || 6)}{' '}
                    LP tokens
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    Validator Token Reserves
                  </span>
                  <span className="text-gray12">
                    {formatUnits(
                      pool.reserveValidatorToken,
                      validatorMetadata?.decimals || 6,
                    )}{' '}
                    AlphaUSD
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    User Token Reserves
                  </span>
                  <span className="text-gray12">
                    {formatUnits(
                      pool.reserveUserToken,
                      metadata?.decimals || 6,
                    )}{' '}
                    {metadata?.symbol || ''}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </Step>
  )
}
