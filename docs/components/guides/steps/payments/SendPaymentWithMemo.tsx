import * as React from 'react'
import { fromHex, isAddress, pad, parseUnits, stringToHex } from 'viem'
import { Abis } from 'viem/tempo'
import {
  useConnection,
  useConnectionEffect,
  useWatchContractEvent,
} from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { Button, ExplorerLink, FAKE_RECIPIENT, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

interface MemoEvent {
  from: `0x${string}`
  to: `0x${string}`
  value: bigint
  memo: string
}

export function SendPaymentWithMemo(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const [recipient, setRecipient] = React.useState<string>(FAKE_RECIPIENT)
  const [memo, setMemo] = React.useState<string>('CUST-12345')
  const [memoError, setMemoError] = React.useState<string | null>(null)
  const [expanded, setExpanded] = React.useState(false)
  const [memoEvents, setMemoEvents] = React.useState<MemoEvent[]>([])
  const { data: balance, refetch: balanceRefetch } = Hooks.token.useGetBalance({
    account: address,
    token: alphaUsd,
  })
  const sendPayment = Hooks.token.useTransferSync({
    mutation: {
      onSettled() {
        balanceRefetch()
      },
    },
  })
  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      setMemoError(null)
      setMemoEvents([])
      sendPayment.reset()
    },
  })

  useWatchContractEvent({
    address: alphaUsd,
    abi: Abis.tip20,
    eventName: 'TransferWithMemo',
    enabled: sendPayment.isSuccess,
    onLogs: (logs) => {
      for (const log of logs) {
        if (log.args.from === address) {
          const memoStr = fromHex(
            log.args.memo as `0x${string}`,
            'string',
          ).replace(/\0/g, '')
          setMemoEvents((prev) => [
            ...prev,
            {
              from: log.args.from as `0x${string}`,
              to: log.args.to as `0x${string}`,
              value: log.args.amount as bigint,
              memo: memoStr,
            },
          ])
        }
      }
    },
  })

  const isValidRecipient = recipient && isAddress(recipient)

  const validateMemo = (value: string): string | null => {
    if (!value.trim()) {
      return 'Memo is required for reconciliation'
    }
    const byteLength = new TextEncoder().encode(value).length
    if (byteLength > 32) {
      return `${byteLength - 32} characters too long`
    }
    return null
  }

  const handleMemoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setMemo(value)
    setMemoError(validateMemo(value))
  }

  const handleTransfer = () => {
    const error = validateMemo(memo)
    if (!isValidRecipient || error) {
      setMemoError(error)
      return
    }
    sendPayment.mutate({
      amount: parseUnits('100', 6),
      to: recipient as `0x${string}`,
      token: alphaUsd,
      memo: pad(stringToHex(memo), { size: 32 }),
    })
  }

  return (
    <Step
      active={
        Boolean(address && balance && balance > 0n) &&
        (last ? true : !sendPayment.isSuccess)
      }
      completed={sendPayment.isSuccess}
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
              address && balance && balance > 0n
                ? sendPayment.isSuccess
                  ? 'default'
                  : 'accent'
                : 'default'
            }
            disabled={!(address && balance && balance > 0n)}
            onClick={() => setExpanded(true)}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Enter details
          </Button>
        )
      }
      number={stepNumber}
      title="Send a payment with a memo for reconciliation."
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="flex gap-2 flex-col pe-8 mt-2">
              <div className="flex flex-col">
                <label
                  className="text-[11px] -tracking-[1%] text-gray9"
                  htmlFor="memo"
                >
                  Memo (e.g., customer ID, invoice number)
                </label>
                <input
                  className={`h-[34px] border px-3.25 rounded-[50px] text-[14px] font-normal -tracking-[2%] placeholder-gray9 text-black dark:text-white ${memoError ? 'border-red-500' : 'border-gray4'}`}
                  data-1p-ignore
                  type="text"
                  name="memo"
                  value={memo}
                  onChange={handleMemoChange}
                  placeholder="CUST-12345"
                />
                {memoError && (
                  <span className="text-[11px] text-red-500 mt-1">
                    {memoError}
                  </span>
                )}
              </div>
              <div className="flex flex-col md:flex-row gap-2 md:items-end">
                <div className="flex flex-col flex-1">
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
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                    placeholder="0x..."
                  />
                </div>
                <Button
                  variant={
                    address &&
                    balance &&
                    balance > 0n &&
                    isValidRecipient &&
                    !memoError &&
                    memo.trim()
                      ? 'accent'
                      : 'default'
                  }
                  disabled={
                    !(
                      address &&
                      balance &&
                      balance > 0n &&
                      isValidRecipient &&
                      memo.trim()
                    ) || !!memoError
                  }
                  onClick={handleTransfer}
                  type="button"
                  className="text-[14px] -tracking-[2%] font-normal"
                >
                  {sendPayment.isPending ? 'Sending...' : 'Send with Memo'}
                </Button>
              </div>
            </div>
            {sendPayment.isSuccess && sendPayment.data && (
              <div className="mt-2">
                <ExplorerLink hash={sendPayment.data.receipt.transactionHash} />
                {memoEvents.length > 0 && (
                  <div className="mt-3 p-2 bg-gray2 rounded-lg">
                    <p className="text-[11px] text-gray9 mb-1">
                      TransferWithMemo event detected:
                    </p>
                    {memoEvents.map((event) => (
                      <div
                        key={`${event.from}-${event.to}-${event.memo}`}
                        className="text-[11px] font-mono text-gray11"
                      >
                        <span className="text-gray9">memo:</span> "{event.memo}"
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
