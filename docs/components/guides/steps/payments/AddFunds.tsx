import { useMutation, useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import type { Chain } from 'tempo.ts/viem'
import { Actions } from 'tempo.ts/viem'
import { Hooks } from 'tempo.ts/wagmi'
import type { Address, Client, Transport } from 'viem'
import { isAddress, parseUnits } from 'viem'
import { mnemonicToAccount } from 'viem/accounts'
import { useBlockNumber, useClient, useConnection } from 'wagmi'
import { Button, ExplorerLink, Login, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function AddFunds(props: DemoStepProps & { fundOthers?: boolean }) {
  const { stepNumber = 2, last = false, fundOthers = false } = props
  const { address } = useConnection()
  const queryClient = useQueryClient()
  const [fundAddress, setFundAddress] = React.useState<string | undefined>(
    undefined,
  )

  // Initialize fundAddress with connected wallet address (only once)
  React.useEffect(() => {
    if (address && fundAddress === undefined) {
      setFundAddress(address)
    }
  }, [address, fundAddress])

  const targetAddress = fundOthers && fundAddress ? fundAddress : address
  const isValidTarget = targetAddress && isAddress(targetAddress)

  const { data: balance, refetch: balanceRefetch } = Hooks.token.useGetBalance({
    account: targetAddress as Address | undefined,
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
      if (!isValidTarget) throw new Error('valid target address not found')
      if (!client) throw new Error('client not found')

      let receipts = null
      if (import.meta.env.VITE_LOCAL !== 'true')
        receipts = await Actions.faucet.fundSync(
          client as unknown as Client<Transport, Chain.Chain<null>>,
          { account: targetAddress as Address },
        )
      else {
        const result = await Actions.token.transferSync(
          client as unknown as Client<Transport, Chain.Chain<null>>,
          {
            account: mnemonicToAccount(
              'test test test test test test test test test test test junk',
            ),
            amount: parseUnits('10000', 6),
            to: targetAddress as Address,
            token: alphaUsd,
          },
        )
        receipts = [result.receipt]
      }
      await new Promise((resolve) => setTimeout(resolve, 400))
      queryClient.refetchQueries({ queryKey: ['getBalance'] })
      return receipts
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
          disabled={!isValidTarget || fundAccount.isPending}
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
        disabled={!isValidTarget || fundAccount.isPending}
        variant={isValidTarget ? 'accent' : 'default'}
        className="text-[14px] -tracking-[2%] font-normal"
        type="button"
        onClick={() => fundAccount.mutate()}
      >
        {fundAccount.isPending ? 'Adding funds' : 'Add funds'}
      </Button>
    )
  }, [stepNumber, isValidTarget, balance, fundAccount.isPending])

  return (
    <Step
      active={active}
      completed={Boolean(isValidTarget && balance && balance > 0n)}
      actions={actions}
      error={fundAccount.error}
      number={stepNumber}
      title={
        fundOthers
          ? 'Add testnet funds to an address.'
          : 'Add testnet funds to your account.'
      }
    >
      {fundOthers && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex flex-col mt-2">
              <label
                className="text-[11px] -tracking-[1%] text-gray9"
                htmlFor="fundAddress"
              >
                Address to fund
              </label>
              <input
                className="h-[34px] border border-gray4 px-3.25 rounded-full text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                autoCapitalize="none"
                autoComplete="off"
                autoCorrect="off"
                spellCheck={false}
                name="fundAddress"
                placeholder="0x..."
                value={fundAddress ?? ''}
                onChange={(event) => setFundAddress(event.target.value)}
                disabled={fundAccount.isPending}
              />
            </div>
            {fundAccount.data?.[0]?.transactionHash && (
              <ExplorerLink hash={fundAccount.data[0].transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
