import * as React from 'react'
import { type Address, isAddress } from 'viem'
import { useChainId, useConfig, useConnection } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { Button, ExplorerLink, Step, StringFormatter } from '../../Demo'
import { alphaUsd, betaUsd, thetaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

type FeeTokenOption =
  | {
      value: 'alpha' | 'beta' | 'theta'
      label: string
      address: Address
    }
  | { value: 'other' | 'none'; label: string }

const FEE_TOKEN_OPTIONS = [
  { value: 'none', label: '-- Select a token --' },
  { value: 'alpha', label: 'AlphaUSD', address: alphaUsd },
  { value: 'beta', label: 'BetaUSD', address: betaUsd },
  { value: 'theta', label: 'ThetaUSD', address: thetaUsd },
  { value: 'other', label: 'Other (custom)' },
] as const satisfies readonly FeeTokenOption[]

const DEFAULT_FEE_TOKEN_OPTION = FEE_TOKEN_OPTIONS[0]

export function SetFeeToken(props: DemoStepProps) {
  const { stepNumber = 1 } = props
  const { address, connector } = useConnection()
  const hasNonWebAuthnWallet = Boolean(address && connector?.id !== 'webAuthn')
  const chainId = useChainId()
  const config = useConfig()

  const [selectedFeeToken, setSelectedFeeToken] =
    React.useState<FeeTokenOption['value']>('none')
  const [customFeeToken, setCustomFeeToken] = React.useState('')
  const [txHash, setTxHash] = React.useState<string | undefined>(undefined)

  const { data: balance } = Hooks.token.useGetBalance({
    account: address,
    token: alphaUsd,
  })

  const userToken = Hooks.fee.useUserToken({
    account: address,
    query: {
      enabled: Boolean(address),
    },
  })
  const setUserToken = Hooks.fee.useSetUserTokenSync()

  const selectedOption = React.useMemo<FeeTokenOption>(() => {
    const option = FEE_TOKEN_OPTIONS.find(
      (candidate) => candidate.value === selectedFeeToken,
    )
    return option ?? DEFAULT_FEE_TOKEN_OPTION
  }, [selectedFeeToken])

  const resolvedFeeToken =
    selectedOption.value === 'other' 
      ? customFeeToken 
      : selectedOption.value === 'none'
        ? undefined
        : 'address' in selectedOption
          ? selectedOption.address
          : undefined
  const isFeeTokenValid =
    selectedOption.value === 'none' ||
    selectedOption.value !== 'other' || 
    isAddress(customFeeToken)
  const defaultChainId = chainId ?? config?.chains?.[0]?.id

  const hasBalance = Boolean(balance && balance > 0n)
  const userTokenAddress = userToken.data?.address
  const hasUserToken = Boolean(userTokenAddress && userTokenAddress !== '0x0000000000000000000000000000000000000000')

  const canSubmit = Boolean(
    hasNonWebAuthnWallet &&
      hasBalance &&
      resolvedFeeToken &&
      isFeeTokenValid &&
      !setUserToken.isPending,
  )

  const currentFeeTokenLabel = React.useMemo(() => {
    const userTokenAddress = userToken.data?.address ?? undefined
    if (!userTokenAddress) return undefined
    const match = FEE_TOKEN_OPTIONS.find(
      (option) =>
        'address' in option &&
        option.address.toLowerCase() === userTokenAddress.toLowerCase(),
    )
    return match && match.value !== 'other'
      ? match.label
      : StringFormatter.truncate(userTokenAddress, {
          start: 6,
          end: 4,
        })
  }, [userToken.data?.address])

  const handleSetFeeToken = React.useCallback(() => {
    if (!resolvedFeeToken || !isFeeTokenValid || !address) return
    if (!defaultChainId) return

    setTxHash(undefined)
    setUserToken.mutate(
      {
        token: resolvedFeeToken as Address,
        chainId: defaultChainId,
        account: address,
      },
      {
        onSuccess: (result) => {
          setTxHash(result?.receipt.transactionHash)
          userToken.refetch()
        },
        onSettled: (_data, error) => {
          if (error) setTxHash(undefined)
        },
      },
    )
  }, [address, isFeeTokenValid, resolvedFeeToken, setUserToken, defaultChainId])

  // Sync selected option with current user token
  React.useEffect(() => {
    const userTokenAddress = userToken.data?.address ?? undefined
    if (!userTokenAddress || userTokenAddress === '0x0000000000000000000000000000000000000000') {
      setSelectedFeeToken('none')
      setCustomFeeToken('')
      return
    }
    const match = FEE_TOKEN_OPTIONS.find(
      (option) =>
        'address' in option &&
        option.address.toLowerCase() === userTokenAddress.toLowerCase(),
    )
    if (match && match.value !== 'other') {
      setSelectedFeeToken(match.value)
      setCustomFeeToken('')
    } else {
      setSelectedFeeToken('other')
      setCustomFeeToken(userTokenAddress)
    }
  }, [userToken.data?.address])

  const active = hasNonWebAuthnWallet && hasBalance
  const completed = hasNonWebAuthnWallet && hasBalance && hasUserToken

  const actions = React.useMemo(() => {
    return (
      <div className="flex gap-2 items-center">
        <select
          className="h-[32px] border border-gray4 px-3 rounded-full text-[14px] font-medium -tracking-[2%] bg-white dark:bg-transparent text-black dark:text-white min-w-0 flex-shrink-0"
          value={selectedFeeToken}
          onChange={(event) => {
            const value = event.target.value as FeeTokenOption['value']
            setSelectedFeeToken(value)
            if (value !== 'other') setCustomFeeToken('')
          }}
          disabled={!hasBalance || setUserToken.isPending}
        >
          {FEE_TOKEN_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <Button
          variant={active && !hasUserToken ? 'accent' : 'default'}
          onClick={handleSetFeeToken}
          disabled={!canSubmit || selectedFeeToken === 'none'}
        >
          {setUserToken.isPending 
            ? 'Setting...' 
            : hasUserToken 
              ? 'Change fee token' 
              : 'Set fee token'}
        </Button>
      </div>
    )
  }, [
    selectedFeeToken,
    hasBalance,
    setUserToken.isPending,
    active,
    handleSetFeeToken,
    canSubmit,
  ])

  return (
    <Step
      active={active}
      completed={completed}
      actions={actions}
      error={setUserToken.error}
      number={stepNumber}
      title={hasUserToken ? "Change your fee token." : "Set your fee token."}
    >
      {(selectedOption.value === 'other' || currentFeeTokenLabel || txHash) && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            {selectedOption.value === 'other' && (
              <div className="flex flex-col mt-2">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="customFeeToken"
                >
                  Custom fee token address
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-full text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  autoCapitalize="none"
                  autoComplete="off"
                  autoCorrect="off"
                  spellCheck={false}
                  name="customFeeToken"
                  placeholder="0x..."
                  value={customFeeToken}
                  onChange={(event) => setCustomFeeToken(event.target.value)}
                  disabled={setUserToken.isPending}
                />
              </div>
            )}
            {currentFeeTokenLabel && (
              <div className="text-[13px] text-gray9 mt-2">
                Current fee token:{' '}
                <a 
                  href={`https://explore.tempo.xyz/address/${userToken.data?.address}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-black dark:text-white hover:underline hover:text-accent transition-colors"
                >
                  {currentFeeTokenLabel}
                </a>
              </div>
            )}
            {txHash && <ExplorerLink hash={txHash} />}
          </div>
        </div>
      )}
    </Step>
  )
}
