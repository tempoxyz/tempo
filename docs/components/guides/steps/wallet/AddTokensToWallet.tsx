import * as React from 'react'
import { useConnection, useWatchAsset } from 'wagmi'
import { Button, Step } from '../../Demo'
import { alphaUsd, betaUsd, pathUsd, thetaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

type Token = {
  address: `0x${string}`
  symbol: string
  decimals: number
  image?: string
}

const TOKENS: Token[] = [
  { address: alphaUsd, symbol: 'AlphaUSD', decimals: 6 },
  { address: betaUsd, symbol: 'BetaUSD', decimals: 6 },
  { address: thetaUsd, symbol: 'ThetaUSD', decimals: 6 },
  { address: pathUsd, symbol: 'PathUSD', decimals: 6 },
]

function AddTokenButton(props: {
  token: Token
  disabled: boolean
  onSuccess: () => void
  isAdded: boolean
}) {
  const { token, disabled, onSuccess, isAdded } = props
  const { watchAsset, isPending, isSuccess } = useWatchAsset()

  React.useEffect(() => {
    if (isSuccess && !isAdded) {
      onSuccess()
    }
  }, [isSuccess, isAdded, onSuccess])

  return (
    <Button
      variant="default"
      disabled={disabled || isPending || isAdded}
      onClick={() =>
        watchAsset({
          type: 'ERC20',
          options: {
            address: token.address,
            symbol: token.symbol,
            decimals: token.decimals,
            image: token.image,
          },
        })
      }
    >
      {isAdded
        ? `${token.symbol} Added!`
        : isPending
          ? 'Adding...'
          : `Add ${token.symbol}`}
    </Button>
  )
}

export function AddTokensToWallet(props: DemoStepProps) {
  const { stepNumber = 3, last = false } = props
  const { address, connector } = useConnection()
  const hasNonWebAuthnWallet = Boolean(address && connector?.id !== 'webAuthn')

  const [addedTokens, setAddedTokens] = React.useState<Set<string>>(new Set())
  const [expanded, setExpanded] = React.useState(false)
  const allTokensAdded = addedTokens.size === TOKENS.length

  const active = React.useMemo(() => {
    if (last) return hasNonWebAuthnWallet
    return hasNonWebAuthnWallet && !allTokensAdded
  }, [hasNonWebAuthnWallet, allTokensAdded, last])

  const completed = hasNonWebAuthnWallet && allTokensAdded

  const actions = React.useMemo(() => {
    return (
      <Button
        variant={active ? 'accent' : 'default'}
        disabled={!hasNonWebAuthnWallet}
        onClick={() => setExpanded((prev) => !prev)}
      >
        {expanded ? 'Hide tokens' : 'Show tokens'}
      </Button>
    )
  }, [hasNonWebAuthnWallet, active, expanded])

  return (
    <Step
      active={active}
      completed={completed}
      actions={actions}
      number={stepNumber}
      title="Add tokens to wallet."
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex flex-wrap gap-2 mt-2">
              {TOKENS.map((token) => (
                <AddTokenButton
                  key={token.address}
                  token={token}
                  disabled={!hasNonWebAuthnWallet}
                  onSuccess={() =>
                    setAddedTokens((prev) => new Set([...prev, token.address]))
                  }
                  isAdded={addedTokens.has(token.address)}
                />
              ))}
            </div>
          </div>
        </div>
      )}
    </Step>
  )
}
