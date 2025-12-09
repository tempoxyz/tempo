import { useQuery } from '@tanstack/react-query'
import { Hex } from 'ox'
import * as React from 'react'
import { Abis } from 'tempo.ts/viem'
import { Actions, Hooks } from 'tempo.ts/wagmi'
import {
  type Address,
  formatUnits,
  type Hex as HexType,
  isAddress,
  parseEventLogs,
} from 'viem'
import { useAccount, useChainId, useConfig } from 'wagmi'
import LucideDollarSign from '~icons/lucide/dollar-sign'

import { Container } from './Container'
import { Button, ExplorerLink, StringFormatter } from './guides/Demo'
import { alphaUsd, betaUsd, pathUsd, thetaUsd } from './guides/tokens'

type FeeTokenOption =
  | {
      value: 'alpha' | 'beta' | 'theta' | 'path'
      label: string
      address: Address
    }
  | { value: 'other'; label: string }

const FEE_TOKEN_OPTIONS = [
  { value: 'alpha', label: 'AlphaUSD', address: alphaUsd },
  { value: 'beta', label: 'BetaUSD', address: betaUsd },
  { value: 'theta', label: 'ThetaUSD', address: thetaUsd },
  { value: 'path', label: 'PathUSD', address: pathUsd },
  { value: 'other', label: 'Other (custom)' },
] as const satisfies readonly FeeTokenOption[]

const DEFAULT_FEE_TOKEN_OPTION = FEE_TOKEN_OPTIONS[0]

export function Faucet() {
  const { address, isConnected } = useAccount()
  const chainId = useChainId()
  const config = useConfig()

  const [lastAddress, setLastAddress] = React.useState<Address | undefined>(
    undefined,
  )
  const [lastTxHashes, setLastTxHashes] = React.useState<HexType[] | undefined>(
    undefined,
  )

  const [selectedFeeToken, setSelectedFeeToken] =
    React.useState<FeeTokenOption['value']>('path')
  const [customFeeToken, setCustomFeeToken] = React.useState('')
  const [feeStatus, setFeeStatus] = React.useState<string | undefined>(
    undefined,
  )
  const [feeTxHash, setFeeTxHash] = React.useState<string | undefined>(
    undefined,
  )

  const userToken = Hooks.fee.useUserToken({
    account: address,
    query: {
      enabled: Boolean(address),
    },
  })
  const setUserToken = Hooks.fee.useSetUserTokenSync()

  const fund = Hooks.faucet.useFundSync()
  const selectedOption = React.useMemo<FeeTokenOption>(() => {
    const option = FEE_TOKEN_OPTIONS.find(
      (candidate) => candidate.value === selectedFeeToken,
    )
    return option ?? DEFAULT_FEE_TOKEN_OPTION
  }, [selectedFeeToken])
  const resolvedFeeToken =
    selectedOption.value === 'other' ? customFeeToken : selectedOption.address
  const isFeeTokenValid =
    selectedOption.value !== 'other' || isAddress(customFeeToken)
  const defaultChainId = chainId ?? config?.chains?.[0]?.id
  const canSubmitFeeToken = Boolean(
    isConnected &&
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
  const receivedTokens = useQuery({
    enabled: Boolean(fund.data),
    queryKey: ['receivedTokens', fund.data] as const,
    async queryFn({ queryKey }) {
      const [, receipts] = queryKey
      if (!receipts) throw new Error('receipts not found')
      const events = receipts.flatMap((receipt) =>
        parseEventLogs({
          abi: Abis.tip20,
          eventName: 'Transfer',
          logs: receipt.logs,
          args: {
            to: lastAddress,
          },
        }),
      )
      return await Promise.all(
        events.map(async (event) => {
          const metadata = await Actions.token.getMetadata(config, {
            token: event.address,
          })
          return {
            amount: formatUnits(event.args.amount, metadata.decimals),
            name: metadata.name,
          }
        }),
      )
    },
  })

  const handleSetFeeToken = React.useCallback(
    (event?: React.FormEvent<HTMLFormElement>) => {
      event?.preventDefault()
      if (!resolvedFeeToken || !isFeeTokenValid || !isConnected) return
      if (!defaultChainId) {
        setFeeStatus('No chain configured; please reconnect your wallet.')
        return
      }

      setFeeStatus(undefined)
      setUserToken.mutate(
        {
          token: resolvedFeeToken as Address,
          chainId: defaultChainId,
          account: address,
        },
        {
          onSuccess: (result) => {
            setFeeTxHash(result?.receipt.transactionHash)
            const label =
              selectedOption.value === 'other'
                ? StringFormatter.truncate(resolvedFeeToken, {
                    start: 6,
                    end: 4,
                  })
                : selectedOption.label
            setFeeStatus(`Fee token set to ${label}.`)
          },
          onError: (error) =>
            setFeeStatus(
              'shortMessage' in error
                ? error.shortMessage
                : (error as Error).message,
            ),
          onSettled: (_data, error) => {
            if (error) setFeeTxHash(undefined)
          },
        },
      )
    },
    [
      isConnected,
      isFeeTokenValid,
      resolvedFeeToken,
      selectedOption,
      setUserToken,
      defaultChainId,
      address,
    ],
  )

  React.useEffect(() => {
    const userTokenAddress = userToken.data?.address ?? undefined
    if (!userTokenAddress) return
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

  return (
    <Container>
      <div className="flex flex-col gap-3">
        <div className="flex flex-col gap-3 border border-gray4 rounded-[12px] p-3">
          <header className="flex items-center justify-between">
            <div className="flex flex-col gap-2">
              <div className="flex gap-3 text-[16px] dark:text-white font-normal text-black -tracking-[1%]">
                <div className="text-[13px] dark:text-white text-black size-7 rounded-full text-center flex items-center justify-center tabular-nums opacity-40 group-data-[completed=true]:opacity-100 bg-gray4">
                  <LucideDollarSign className="text-gray12" />
                </div>
                Fund address
              </div>
              <div className="text-[14px] text-gray9 -tracking-[1%] leading-normal">
                Enter an address below to receive testnet tokens. This action is{' '}
                <span className="dark:text-white text-black">free</span>.
              </div>
            </div>
          </header>

          <form
            onSubmit={(event) => {
              event.preventDefault()
              const formData = new FormData(event.target as HTMLFormElement)
              const address = formData.get('address')
              Hex.assert(address)
              fund.mutate(
                { account: address },
                {
                  onSuccess: (receipts) => {
                    setLastTxHashes(receipts.map((r) => r.transactionHash))
                  },
                },
              )
              setLastAddress(address)
            }}
          >
            <div className="flex gap-2">
              <input
                autoCapitalize="none"
                autoComplete="off"
                autoCorrect="off"
                className="w-full h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-medium -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                defaultValue={address}
                name="address"
                required
                spellCheck={false}
                placeholder="0x1A60E1922C498c6fD690dB24543fb6Cf0e15F2E7"
              />
              <Button
                variant="accent"
                type="submit"
                disabled={fund.isPending || receivedTokens.isFetching}
              >
                <div className="px-2!">
                  {fund.isPending || receivedTokens.isFetching
                    ? 'Funding...'
                    : 'Fund'}
                </div>
              </Button>
            </div>
          </form>

          {fund.isSuccess && lastAddress && receivedTokens.data && (
            <div className="flex flex-col text-[13px] text-gray9 gap-1">
              <div>
                Address{' '}
                <a
                  href={`https://explore.tempo.xyz/address/${lastAddress}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="dark:text-white text-black hover:underline"
                >
                  {StringFormatter.truncate(lastAddress, {
                    start: 6,
                    end: 4,
                  })}
                </a>{' '}
                successfully funded with:
              </div>
              <div className="flex flex-col gap-2">
                {receivedTokens.data?.map((token, index) => (
                  <div className="leading-none" key={token.name}>
                    →{' '}
                    {lastTxHashes?.[index] ? (
                      <a
                        href={`https://explore.tempo.xyz/tx/${lastTxHashes[index]}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:underline"
                      >
                        {new Intl.NumberFormat().format(Number(token.amount))}{' '}
                        <span className="dark:text-white text-black">
                          {token.name}
                        </span>
                      </a>
                    ) : (
                      <>
                        {new Intl.NumberFormat().format(Number(token.amount))}{' '}
                        <span className="dark:text-white text-black">
                          {token.name}
                        </span>
                      </>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {fund.error && (
            <div className="bg-destructiveTint text-destructive rounded py-2 px-3 text-[14px] -tracking-[2%] leading-normal font-normal">
              {'shortMessage' in fund.error
                ? fund.error.shortMessage
                : (fund.error as Error).message}
            </div>
          )}
        </div>

        <form
          onSubmit={handleSetFeeToken}
          className="flex flex-col gap-3 border border-gray4 rounded-[12px] p-3"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex flex-col gap-1">
              <div className="text-[14px] font-medium text-black dark:text-white">
                Fee token for EVM txs
              </div>
              <div className="text-[13px] text-gray9 -tracking-[1%] leading-normal">
                EVM transactions use your chosen stablecoin for fees; this
                faucet action stays free.
              </div>
            </div>
            {address && (
              <div className="text-[12px] text-gray9 text-right leading-snug">
                Current
                <div className="font-medium text-black dark:text-white">
                  {currentFeeTokenLabel ?? '—'}
                </div>
              </div>
            )}
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <select
              className="w-full h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-medium -tracking-[2%] bg-white dark:bg-transparent text-black dark:text-white"
              value={selectedFeeToken}
              onChange={(event) => {
                const value = event.target.value as FeeTokenOption['value']
                setSelectedFeeToken(value)
                if (value !== 'other') setCustomFeeToken('')
              }}
              disabled={setUserToken.isPending}
            >
              {FEE_TOKEN_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>

            {selectedOption.value === 'other' && (
              <input
                className="w-full h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-medium -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                autoCapitalize="none"
                autoComplete="off"
                autoCorrect="off"
                spellCheck={false}
                placeholder="0x... custom fee token"
                value={customFeeToken}
                onChange={(event) => setCustomFeeToken(event.target.value)}
                disabled={setUserToken.isPending}
              />
            )}
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="accent"
              type="submit"
              disabled={!canSubmitFeeToken}
            >
              {!isConnected
                ? 'Connect your wallet above'
                : setUserToken.isPending
                  ? 'Setting...'
                  : 'Set fee token'}
            </Button>
            <div className="text-[12px] text-gray9 leading-normal">
              {feeStatus ??
                (isConnected
                  ? 'Wallet will prompt to confirm.'
                  : 'Connect your wallet above to set your fee token.')}
            </div>
          </div>
          {feeTxHash && <ExplorerLink hash={feeTxHash} />}
        </form>
      </div>
    </Container>
  )
}
