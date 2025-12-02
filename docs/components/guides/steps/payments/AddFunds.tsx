import { useMutation, useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import type { Chain } from 'tempo.ts/viem'
import { Actions } from 'tempo.ts/viem'
import { Hooks } from 'tempo.ts/wagmi'
import type { Client, Transport } from 'viem'
import { parseUnits } from 'viem'
import { mnemonicToAccount } from 'viem/accounts'
import { useAccount, useBlockNumber, useClient } from 'wagmi'
import { Button, Login, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function AddFunds(props: DemoStepProps) {
  const { stepNumber = 2, last = false } = props
  const { address } = useAccount()
  const queryClient = useQueryClient()
  const { data: balance, refetch: balanceRefetch } = Hooks.token.useGetBalance({
    account: address,
    token: alphaUsd,
  })
  const { data: blockNumber } = useBlockNumber({
    query: {
      enabled: Boolean(address && (!balance || balance < 0)),
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

      if (import.meta.env.VITE_LOCAL !== 'true')
        await Actions.faucet.fundSync(
          client as unknown as Client<Transport, Chain.Chain<null>>,
          { account: address },
        )
      else {
        await Actions.token.transferSync(
          client as unknown as Client<Transport, Chain.Chain<null>>,
          {
            account: mnemonicToAccount(
              'test test test test test test test test test test test junk',
            ),
            amount: parseUnits('10000', 6),
            to: address,
            token: alphaUsd,
          },
        )
      }
      await new Promise((resolve) => setTimeout(resolve, 400))
      queryClient.refetchQueries({ queryKey: ['getBalance'] })
    },
  })

  const showLogin = stepNumber === 1 && !address

  const active = React.useMemo(() => {
    // If we need to show the login button, we are active.
    if (showLogin) return true

    // If this is the last step, simply has to be logged in
    if (last) return !!address

    // If this is an intermediate step, also needs to not have succeeded
    return Boolean(address && !balance)
  }, [address, balance, last])

  const actions = React.useMemo(() => {
    if (showLogin) return <Login />
    if (balance && balance > 0n)
      return (
        <Button
          disabled={fundAccount.isPending}
          variant="default"
          className="text-[14px] -tracking-[2%] font-normal"
          onClick={() => fundAccount.mutate()}
          type="button"
        >
          {fundAccount.isPending ? 'Adding funds' : 'Add more funds'}
        </Button>
      )
    return (
      <Button
        disabled={!address || fundAccount.isPending}
        variant={address ? 'accent' : 'default'}
        className="text-[14px] -tracking-[2%] font-normal"
        type="button"
        onClick={() => fundAccount.mutate()}
      >
        {fundAccount.isPending ? 'Adding funds' : 'Add funds'}
      </Button>
    )
  }, [stepNumber, address, balance, fundAccount.isPending])

  return (
    <Step
      active={active}
      completed={Boolean(address && balance && balance > 0n)}
      actions={actions}
      error={fundAccount.error}
      number={stepNumber}
      title="Add testnet funds to your account."
    />
  )
}
