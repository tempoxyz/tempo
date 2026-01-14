import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { type Address, pad, parseUnits, stringToHex } from 'viem'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function MintToken(props: DemoStepProps & { recipient?: Address }) {
  const { stepNumber, recipient, last = false } = props
  const { address } = useConnection()
  const { getData, setData } = useDemoContext()
  const queryClient = useQueryClient()

  const [memo, setMemo] = React.useState<string>('')
  const [expanded, setExpanded] = React.useState(false)

  // Get the address of the token created in a previous step
  const tokenAddress = getData('tokenAddress')

  const { data: metadata } = Hooks.token.useGetMetadata({
    token: tokenAddress,
  })
  const { data: hasRole } = Hooks.token.useHasRole({
    account: address,
    token: tokenAddress,
    role: 'issuer',
  })
  const { data: balance } = Hooks.token.useGetBalance({
    account: address,
    token: tokenAddress,
  })

  const mint = Hooks.token.useMintSync({
    mutation: {
      onSettled(data) {
        queryClient.refetchQueries({ queryKey: ['getBalance'] })
        setData('transferId', data?.receipt.transactionHash || 'mint')
      },
    },
  })
  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      mint.reset()
    },
  })

  const handleMint = async () => {
    if (!tokenAddress || !address || !metadata) return

    await mint.mutate({
      amount: parseUnits('100', metadata.decimals),
      to: recipient || address,
      token: tokenAddress,
      memo: memo ? pad(stringToHex(memo), { size: 32 }) : undefined,
      feeToken: alphaUsd,
    })
  }

  const hasSufficientBalance =
    balance && metadata && balance >= parseUnits('90', metadata.decimals)

  return (
    <Step
      active={Boolean(
        !!tokenAddress &&
          !!hasRole &&
          !hasSufficientBalance &&
          (last ? true : !mint.isSuccess),
      )}
      completed={mint.isSuccess || Boolean(hasSufficientBalance)}
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
              !!tokenAddress && !!hasRole && !hasSufficientBalance
                ? mint.isSuccess
                  ? 'default'
                  : 'accent'
                : 'default'
            }
            disabled={Boolean(
              !tokenAddress || !hasRole || hasSufficientBalance,
            )}
            onClick={() => setExpanded(true)}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Enter details
          </Button>
        )
      }
      number={stepNumber}
      title={`Mint 100 ${metadata ? metadata.name : 'tokens'} to ${recipient ? 'recipient' : 'yourself'}.`}
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-2">
              <div className="flex flex-col flex-2">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="recipient"
                >
                  Recipient address
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  data-1p-ignore
                  type="text"
                  name="recipient"
                  value={recipient || address}
                  disabled={true}
                  onChange={(_e) => {}}
                  placeholder="0x..."
                />
              </div>
              <div className="flex flex-col flex-1">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="memo"
                >
                  Memo (optional)
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  data-1p-ignore
                  type="text"
                  name="memo"
                  value={memo}
                  onChange={(e) => setMemo(e.target.value)}
                  placeholder="INV-12345"
                />
              </div>
              <Button
                variant={address ? 'accent' : 'default'}
                disabled={!address}
                onClick={handleMint}
                type="button"
                className="text-[14px] -tracking-[2%] font-normal"
              >
                {mint.isPending ? 'Minting...' : 'Mint'}
              </Button>
            </div>
            {mint.isSuccess && mint.data && (
              <ExplorerLink hash={mint.data.receipt.transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
