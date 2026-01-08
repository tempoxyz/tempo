import * as React from 'react'
import { parseUnits } from 'viem'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function SetSupplyCap(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const { getData } = useDemoContext()
  const [expanded, setExpanded] = React.useState(false)

  // Get the address of the token created in a previous step
  const tokenAddress = getData('tokenAddress')

  const { data: metadata, refetch: refetchMetadata } =
    Hooks.token.useGetMetadata({
      token: tokenAddress,
    })

  const setSupplyCap = Hooks.token.useSetSupplyCapSync({
    mutation: {
      onSettled() {
        refetchMetadata()
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      setSupplyCap.reset()
    },
  })

  const handleSetSupplyCap = () => {
    if (!tokenAddress) return

    setSupplyCap.mutate({
      token: tokenAddress,
      supplyCap: parseUnits('1000', metadata?.decimals || 6),
      feeToken: alphaUsd,
    })
  }

  const active = Boolean(tokenAddress && address)
  const hasSupplyCap = Boolean(
    metadata?.supplyCap &&
      metadata.supplyCap <= parseUnits('1000', metadata.decimals || 6),
  )

  return (
    <Step
      active={active && (last ? true : !setSupplyCap.isSuccess)}
      completed={setSupplyCap.isSuccess || hasSupplyCap}
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
              active
                ? setSupplyCap.isSuccess
                  ? 'default'
                  : 'accent'
                : 'default'
            }
            disabled={!active}
            onClick={() => setExpanded(true)}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Enter details
          </Button>
        )
      }
      number={stepNumber}
      title={`Set supply cap to 1,000 ${metadata ? metadata.name : 'tokens'}.`}
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-2 flex-col md:items-end md:flex-row pe-8 mt-2">
              <div className="flex flex-col flex-1">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="supplyCap"
                >
                  Supply cap amount
                </label>
                <input
                  className="h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white"
                  data-1p-ignore
                  type="text"
                  name="supplyCap"
                  value="1,000"
                  disabled={true}
                  onChange={() => {}}
                />
              </div>
              <Button
                variant={active ? 'accent' : 'default'}
                disabled={!active}
                onClick={handleSetSupplyCap}
                type="button"
                className="text-[14px] -tracking-[2%] font-normal"
              >
                {setSupplyCap.isPending ? 'Setting...' : 'Set Cap'}
              </Button>
            </div>
            {setSupplyCap.isSuccess && setSupplyCap.data && (
              <ExplorerLink hash={setSupplyCap.data.receipt.transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
