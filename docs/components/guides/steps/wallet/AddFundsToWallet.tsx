import { useMutation, useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import type { Chain, Client, Transport } from 'viem'
import { parseUnits } from 'viem'
import { mnemonicToAccount } from 'viem/accounts'
import { Actions } from 'viem/tempo'
import { useBlockNumber, useClient, useConnection } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function AddFundsToWallet(props: DemoStepProps) {
  const { stepNumber = 2, last = false } = props
  const { address, connector } = useConnection()
  const hasNonWebAuthnWallet = Boolean(address && connector?.id !== 'webAuthn')
  const queryClient = useQueryClient()
  const [txHash, setTxHash] = React.useState<string | undefined>(undefined)

  const { data: balance, refetch: balanceRefetch } = Hooks.token.useGetBalance({
    account: address,
    token: alphaUsd,
    query: {
      enabled: hasNonWebAuthnWallet,
    },
  })
  const { data: blockNumber } = useBlockNumber({
    query: {
      enabled: Boolean(hasNonWebAuthnWallet && (!balance || balance < 0)),
      refetchInterval: 1_500,
    },
  })
  React.useEffect(() => {
    balanceRefetch()
  }, [blockNumber])
  const client = useClient()
  const fundAccount = useMutation({
    async mutationFn() {
      if (!address) throw new Error('account.address not found')
      if (!client) throw new Error('client not found')

      if (import.meta.env.VITE_ENVIRONMENT !== 'local') {
        const receipts = await Actions.faucet.fundSync(
          client as unknown as Client<Transport, Chain>,
          { account: address },
        ) as any
        // fundSync returns an array of receipts
        return receipts?.[0]?.transactionHash
      } else {
        const result = await Actions.token.transferSync(
          client as unknown as Client<Transport, Chain>,
          {
            account: mnemonicToAccount(
              'test test test test test test test test test test test junk',
            ),
            amount: parseUnits('10000', 6),
            to: address,
            token: alphaUsd,
          },
        ) as any
        return result?.receipt?.transactionHash
      }
    },
    onSuccess: (hash) => {
      if (hash) {
        setTxHash(hash)
      }
      queryClient.invalidateQueries({ queryKey: ['getBalance'] })
    },
  })

  const active = React.useMemo(() => {
    // If this is the last step, simply has to have a non-webauthn wallet
    if (last) return hasNonWebAuthnWallet

    // If this is an intermediate step, also needs to not have balance yet
    return hasNonWebAuthnWallet && !balance
  }, [hasNonWebAuthnWallet, balance, last])

  const actions = React.useMemo(() => {
    if (balance && balance > 0n)
      return (
        <div className="flex gap-2 items-center flex-wrap">
          {txHash && <ExplorerLink hash={txHash} />}
          <Button
            disabled={!hasNonWebAuthnWallet || fundAccount.isPending}
            variant="default"
            className="text-[14px] -tracking-[2%] font-normal"
            onClick={() => {
              setTxHash(undefined)
              fundAccount.mutate()
            }}
            type="button"
          >
            {fundAccount.isPending ? 'Adding funds' : 'Add more funds'}
          </Button>
        </div>
      )
    return (
      <Button
        disabled={!hasNonWebAuthnWallet || fundAccount.isPending}
        variant={hasNonWebAuthnWallet ? 'accent' : 'default'}
        className="text-[14px] -tracking-[2%] font-normal"
        type="button"
        onClick={() => {
          setTxHash(undefined)
          fundAccount.mutate()
        }}
      >
        {fundAccount.isPending ? 'Adding funds' : 'Add funds'}
      </Button>
    )
  }, [hasNonWebAuthnWallet, balance, fundAccount.isPending, txHash])

  return (
    <Step
      active={active}
      completed={Boolean(hasNonWebAuthnWallet && balance && balance > 0n)}
      actions={actions}
      error={fundAccount.error}
      number={stepNumber}
      title="Add testnet funds to your wallet."
    />
  )
}