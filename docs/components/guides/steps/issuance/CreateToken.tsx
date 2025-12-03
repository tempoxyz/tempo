import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { useAccount, useAccountEffect } from 'wagmi'
import { cx } from '../../../../cva.config'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Login, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function CreateToken(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useAccount()
  const { setData } = useDemoContext()
  const { data: balance, refetch: balanceRefetch } = Hooks.token.useGetBalance({
    account: address,
    token: alphaUsd,
  })
  const create = Hooks.token.useCreateSync({
    mutation: {
      onSettled(data) {
        balanceRefetch()
        if (data) {
          setData('tokenAddress', data.token)
          setData('tokenReceipt', data.receipt)
        }
      },
    },
  })
  useAccountEffect({
    onDisconnect() {
      create.reset()
    },
  })

  const showLogin = stepNumber === 1 && !address

  const active = React.useMemo(() => {
    // If we need to show the login button, we are active.
    if (showLogin) return true

    // If this is the last step has to be logged in and funded.
    const activeWithBalance = Boolean(address && balance && balance > 0n)
    if (last) return activeWithBalance

    // If this is an intermediate step, also needs to not have succeeded
    return activeWithBalance && !create.isSuccess
  }, [stepNumber, address, balance, create.isSuccess, last])

  return (
    <Step
      active={active}
      completed={create.isSuccess}
      number={stepNumber}
      actions={showLogin && <Login />}
      title="Create & deploy a token to testnet."
    >
      {(active || create.isSuccess) && (
        <div className="flex ml-6 flex-col gap-3 py-4">
          <div className="ps-5 border-gray4 border-s-2">
            <form
              onSubmit={(event) => {
                event.preventDefault()
                const formData = new FormData(event.target as HTMLFormElement)
                const name = formData.get('name') as string
                const symbol = formData.get('symbol') as string
                create.mutate({
                  name,
                  symbol,
                  currency: 'USD',
                  feeToken: alphaUsd,
                })
              }}
              className="flex gap-2 flex-col md:items-end md:flex-row -mt-2.5"
            >
              <div className="flex flex-col flex-1">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="name"
                >
                  Token name
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-lg text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  data-1p-ignore
                  type="text"
                  name="name"
                  required
                  spellCheck={false}
                  placeholder="demoUSD"
                />
              </div>
              <div className="flex flex-col flex-1">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="symbol"
                >
                  Token symbol
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-lg text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  data-1p-ignore
                  type="text"
                  name="symbol"
                  required
                  spellCheck={false}
                  placeholder="DEMO"
                />
              </div>
              <Button
                variant="accent"
                type="submit"
                disabled={create.isPending}
              >
                {create.isPending ? 'Deploying...' : 'Deploy'}
              </Button>
            </form>
          </div>

          {create.data && (
            <div className="relative">
              <div
                className={cx(
                  'bg-gray2 rounded-[10px] p-4 text-center text-gray9 font-normal text-[13px] -tracking-[2%] leading-snug flex flex-col items-center',
                )}
              >
                <div>
                  Token{' '}
                  <span className="text-primary font-medium">
                    {' '}
                    {create.data.name} ({create.data.symbol}){' '}
                  </span>{' '}
                  successfully created and deployed to Tempo!
                </div>
                <ExplorerLink
                  hash={create.data?.receipt.transactionHash ?? ''}
                />
              </div>
            </div>
          )}
        </div>
      )}
    </Step>
  )
}
