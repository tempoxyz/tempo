import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { useDemoContext } from '../../../DemoContext'
import { Button, ExplorerLink, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function PauseUnpauseTransfers(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const { getData } = useDemoContext()

  // Get the address of the token created in a previous step
  const tokenAddress = getData('tokenAddress')

  const { data: metadata, refetch: refetchMetadata } =
    Hooks.token.useGetMetadata({
      token: tokenAddress,
    })

  // Check for pause and unpause roles
  const { data: hasPauseRole } = Hooks.token.useHasRole({
    account: address,
    token: tokenAddress,
    role: 'pause',
  })

  const { data: hasUnpauseRole } = Hooks.token.useHasRole({
    account: address,
    token: tokenAddress,
    role: 'unpause',
  })

  const pause = Hooks.token.usePauseSync({
    mutation: {
      onSettled() {
        refetchMetadata()
      },
    },
  })

  const unpause = Hooks.token.useUnpauseSync({
    mutation: {
      onSettled() {
        refetchMetadata()
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      pause.reset()
      unpause.reset()
    },
  })

  const paused = metadata?.paused || false

  const handleToggle = () => {
    if (!tokenAddress) return

    if (paused) {
      unpause.mutate({ token: tokenAddress, feeToken: alphaUsd })
    } else {
      pause.mutate({ token: tokenAddress, feeToken: alphaUsd })
    }
  }

  const canToggle = paused ? hasUnpauseRole : hasPauseRole
  const isProcessing = pause.isPending || unpause.isPending
  const active = Boolean(tokenAddress && canToggle)

  return (
    <Step
      active={active && (last ? true : !pause.isSuccess && !unpause.isSuccess)}
      completed={pause.isSuccess || unpause.isSuccess}
      actions={
        <Button
          variant={active ? 'accent' : 'default'}
          disabled={!active || isProcessing}
          onClick={handleToggle}
          type="button"
          className="text-[14px] -tracking-[2%] font-normal"
        >
          {isProcessing ? 'Processing...' : paused ? 'Unpause' : 'Pause'}
        </Button>
      }
      number={stepNumber}
      title={`${paused ? 'Unpause' : 'Pause'} transfers for ${metadata ? metadata.name : 'token'}.`}
    >
      {(pause.isSuccess || unpause.isSuccess) &&
        (pause.data || unpause.data) && (
          <div className="flex mx-6 flex-col gap-3 pb-4">
            <div className="ps-5 border-gray4 border-s-2">
              <ExplorerLink
                hash={
                  pause.data?.receipt.transactionHash ??
                  unpause.data?.receipt.transactionHash ??
                  ''
                }
              />
            </div>
          </div>
        )}
    </Step>
  )
}
