import * as React from 'react'
import type { Address } from 'viem'
import { useAccount } from 'wagmi'
import { TokenSelector } from '../../../TokenSelector'
import { Step } from '../../Demo'
import { alphaUsd, betaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function SelectFeeToken(props: DemoStepProps) {
  const { stepNumber } = props
  const { address } = useAccount()
  const [feeToken, setFeeToken] = React.useState<Address>(alphaUsd)

  const active = Boolean(address)
  const completed = Boolean(address && feeToken)

  return (
    <Step
      active={active}
      completed={completed}
      number={stepNumber}
      title="Select a fee token."
    >
      {address && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            <TokenSelector
              tokens={[alphaUsd, betaUsd]}
              value={feeToken}
              onChange={setFeeToken}
              name="feeToken"
            />
          </div>
        </div>
      )}
    </Step>
  )
}
