import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { Actions, Hooks } from 'wagmi/tempo'
import { parseUnits } from 'viem'
import {
  useConfig,
  useConnection,
  useConnectionEffect,
  useTransaction,
} from 'wagmi'
import {
  Button,
  ExplorerLink,
  FAKE_RECIPIENT,
  FAKE_RECIPIENT_2,
  Step,
} from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

type TransferState = {
  status: 'idle' | 'pending' | 'success' | 'error'
  hash?: string
  error?: string
}

function TransferResult({
  label,
  state,
}: {
  label: string
  state: TransferState
}) {
  const { data: transaction } = useTransaction({
    hash: state.hash as `0x${string}` | undefined,
    query: {
      enabled: state.status === 'success' && !!state.hash,
    },
  })

  if (state.status === 'idle') return null

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2">
        <span className="text-[13px] text-gray9 mt-1">{label}:</span>
        {state.status === 'pending' && (
          <span className="text-[13px] text-gray9 mt-1">Sending...</span>
        )}
        {state.status === 'error' && (
          <span className="text-[13px] text-red-500 mt-1">
            Transfer failed, please try again
          </span>
        )}
        {state.status === 'success' && state.hash && (
          <ExplorerLink hash={state.hash} />
        )}
      </div>

      {state.status === 'success' && (
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-gray9 pl-2">
          {transaction ? (
            <>
              <span>Nonce Key: {transaction.nonceKey}</span>
              <span>Nonce: {transaction.nonce}</span>
            </>
          ) : (
            <span className="animate-pulse">Confirming on chain...</span>
          )}
        </div>
      )}
    </div>
  )
}

export function SendParallelPayments(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const config = useConfig()
  const queryClient = useQueryClient()
  const [expanded, setExpanded] = React.useState(false)

  const [transfer1, setTransfer1] = React.useState<TransferState>({
    status: 'idle',
  })
  const [transfer2, setTransfer2] = React.useState<TransferState>({
    status: 'idle',
  })

  const { data: balance, refetch: balanceRefetch } = Hooks.token.useGetBalance({
    account: address,
    token: alphaUsd,
  })

  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      setTransfer1({ status: 'idle' })
      setTransfer2({ status: 'idle' })
    },
  })

  const sendTransfer = (
    params: Actions.token.transfer.Parameters<typeof config>,
    setTransfer: React.Dispatch<React.SetStateAction<TransferState>>,
  ) => {
    setTransfer({ status: 'pending' })
    Actions.token
      .transfer(config, params)
      .then((hash) => {
        setTransfer({ status: 'success', hash })
        queryClient.refetchQueries({ queryKey: ['getBalance'] })
        balanceRefetch()
      })
      .catch((error) => {
        setTransfer({ status: 'error', error: error.message || 'Failed' })
      })
  }

  const handleSendParallel = async () => {
    if (!address) return

    const [nonce1, nonce2] = await Promise.all([
      Actions.nonce.getNonce(config, { account: address, nonceKey: 1n }),
      Actions.nonce.getNonce(config, { account: address, nonceKey: 2n }),
    ])

    // Send both transfers without blocking
    sendTransfer(
      {
        amount: parseUnits('50', 6),
        to: FAKE_RECIPIENT,
        token: alphaUsd,
        nonceKey: 1n,
        nonce: Number(nonce1),
      },
      setTransfer1,
    )

    sendTransfer(
      {
        amount: parseUnits('50', 6),
        to: FAKE_RECIPIENT_2,
        token: alphaUsd,
        nonceKey: 2n,
        nonce: Number(nonce2),
      },
      setTransfer2,
    )
  }

  const bothSucceeded =
    transfer1.status === 'success' && transfer2.status === 'success'
  const isSending =
    transfer1.status === 'pending' || transfer2.status === 'pending'
  const hasStarted = transfer1.status !== 'idle' || transfer2.status !== 'idle'

  return (
    <Step
      active={
        Boolean(address && balance && balance >= parseUnits('100', 6)) &&
        (last ? true : !bothSucceeded)
      }
      completed={bothSucceeded}
      actions={
        expanded ? (
          <Button
            variant="default"
            onClick={() => setExpanded(false)}
            className="text-[14px] -tracking-[2%] font-normal"
            type="button"
          >
            Cancel
          </Button>
        ) : (
          <Button
            variant={
              address && balance && balance >= parseUnits('100', 6)
                ? bothSucceeded
                  ? 'default'
                  : 'accent'
                : 'default'
            }
            disabled={!(address && balance && balance >= parseUnits('100', 6))}
            onClick={() => setExpanded(true)}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Enter details
          </Button>
        )
      }
      number={stepNumber}
      title="Send 50 AlphaUSD to two recipients in parallel."
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-3 mt-2">
              <div className="flex flex-col gap-2 flex-1">
                <div className="flex flex-col">
                  <label
                    className="text-[11px] -tracking-[1%] text-gray9"
                    htmlFor="recipient1"
                  >
                    Recipient 1
                  </label>
                  <input
                    className="h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white disabled:opacity-60 disabled:cursor-not-allowed"
                    data-1p-ignore
                    type="text"
                    name="recipient1"
                    value={FAKE_RECIPIENT}
                    disabled
                    placeholder="0x..."
                  />
                </div>
                <div className="flex flex-col">
                  <label
                    className="text-[11px] -tracking-[1%] text-gray9"
                    htmlFor="recipient2"
                  >
                    Recipient 2
                  </label>
                  <input
                    className="h-[34px] border border-gray4 px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white disabled:opacity-60 disabled:cursor-not-allowed"
                    data-1p-ignore
                    type="text"
                    name="recipient2"
                    value={FAKE_RECIPIENT_2}
                    disabled
                    placeholder="0x..."
                  />
                </div>
              </div>
              <div className="flex items-start">
                <Button
                  variant={
                    address && balance && balance >= parseUnits('100', 6)
                      ? 'accent'
                      : 'default'
                  }
                  disabled={
                    !(address && balance && balance >= parseUnits('100', 6)) ||
                    isSending
                  }
                  onClick={handleSendParallel}
                  type="button"
                  className="text-[14px] -tracking-[2%] font-normal"
                >
                  {isSending ? 'Sending both...' : 'Send both payments'}
                </Button>
              </div>
            </div>
            {hasStarted && (
              <div className="flex flex-col gap-1 mt-2">
                <TransferResult label="Payment 1" state={transfer1} />
                <TransferResult label="Payment 2" state={transfer2} />
              </div>
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
