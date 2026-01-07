import * as React from 'react'
import { isAddress, pad, parseUnits, stringToHex } from 'viem'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { Button, ExplorerLink, FAKE_RECIPIENT, Step } from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function SendPaymentWithMemo(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const [recipient, setRecipient] = React.useState<string>(FAKE_RECIPIENT)
  const [memo, setMemo] = React.useState<string>('CUST-12345')
  const [memoError, setMemoError] = React.useState<string | null>(null)
  const [expanded, setExpanded] = React.useState(false)
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
      sendPayment.reset()
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
                <p className="text-[11px] text-gray9 mt-1">
                  Memo "{memo}" attached to transaction
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
