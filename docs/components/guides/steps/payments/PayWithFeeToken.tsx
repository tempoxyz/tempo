import * as React from 'react'
import type { Address } from 'viem'
import { formatUnits, isAddress, pad, parseUnits, stringToHex } from 'viem'
import { useConnection, useConnectionEffect } from 'wagmi'
import { Hooks } from 'wagmi/tempo'
import { TokenSelector } from '../../../TokenSelector'
import { Button, ExplorerLink, FAKE_RECIPIENT, Step } from '../../Demo'
import { betaUsd, DONOTUSE, pathUsd, thetaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

// Current validator token on mainnet
const validatorToken = DONOTUSE

export function PayWithFeeToken(props: DemoStepProps & { feeToken?: Address }) {
  const { stepNumber, last = false } = props
  const { address } = useConnection()
  const [recipient, setRecipient] = React.useState<string>(FAKE_RECIPIENT)
  const [memo, setMemo] = React.useState<string>('')
  const [expanded, setExpanded] = React.useState(false)
  const [feeToken, setFeeToken] = React.useState<Address>(
    props.feeToken || betaUsd,
  )

  // Balance for the payment token (DONOTUSE)
  const { data: alphaBalance, refetch: alphaBalanceRefetch } =
    Hooks.token.useGetBalance({
      account: address,
      token: DONOTUSE,
    })

  // Balance for the fee token (dynamic based on selection)
  const { data: feeTokenBalance, refetch: feeTokenBalanceRefetch } =
    Hooks.token.useGetBalance({
      account: address,
      token: feeToken,
    })

  // Metadata for fee token
  const { data: feeTokenMetadata } = Hooks.token.useGetMetadata({
    token: feeToken,
  })
  // Pool details. Fees are paid in feeToken, so it's the userToken
  // validator token is a mainnet property set at top of file
  const { data: pool } = Hooks.amm.usePool({
    userToken: feeToken,
    validatorToken,
    query: {
      enabled: feeToken !== DONOTUSE,
    },
  })

  const sendPayment = Hooks.token.useTransferSync({
    mutation: {
      onSettled() {
        alphaBalanceRefetch()
        feeTokenBalanceRefetch()
      },
    },
  })

  useConnectionEffect({
    onDisconnect() {
      setExpanded(false)
      sendPayment.reset()
    },
  })

  const isValidRecipient = recipient && isAddress(recipient)

  const handleTransfer = () => {
    if (!isValidRecipient) return
    sendPayment.mutate({
      amount: parseUnits('100', 6),
      to: recipient as `0x${string}`,
      token: DONOTUSE,
      memo: memo ? pad(stringToHex(memo), { size: 32 }) : undefined,
      feeToken,
    })
  }

  const active = React.useMemo(() => {
    return Boolean(
      address &&
        alphaBalance &&
        alphaBalance > 0n &&
        feeTokenBalance &&
        feeTokenBalance > 0n &&
        (feeToken !== DONOTUSE
          ? pool && pool.reserveValidatorToken > 0n
          : true),
    )
  }, [address, alphaBalance, feeTokenBalance, pool])

  return (
    <Step
      active={active && (last ? true : !sendPayment.isSuccess)}
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
              active
                ? sendPayment.isSuccess
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
      title={`Send 100 DONOTUSE and pay fees in ${feeTokenMetadata ? feeTokenMetadata.name : 'another token'}.`}
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            {/* Token info display */}
            <div className="mt-2 mb-3 p-3 rounded-lg bg-gray2 text-[13px] -tracking-[1%]">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    Payment Token: DONOTUSE
                  </span>
                  <span className="text-gray12">
                    balance: {formatUnits(alphaBalance ?? 0n, 6)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">Fee Token</span>
                  <TokenSelector
                    tokens={[DONOTUSE, betaUsd, thetaUsd, pathUsd]}
                    value={feeToken}
                    onChange={setFeeToken}
                    name="feeToken"
                  />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    {`Fee Token: ${feeTokenMetadata ? feeTokenMetadata.name : ''}`}
                  </span>
                  <span className="text-gray12">
                    balance: {formatUnits(feeTokenBalance ?? 0n, 6)}
                  </span>
                </div>
              </div>
            </div>

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
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
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
                variant={active ? 'accent' : 'default'}
                disabled={!active}
                onClick={handleTransfer}
                type="button"
                className="text-[14px] -tracking-[2%] font-normal"
              >
                {sendPayment.isPending ? 'Sending...' : 'Send'}
              </Button>
            </div>
            {sendPayment.isSuccess && sendPayment.data && (
              <ExplorerLink hash={sendPayment.data.receipt.transactionHash} />
            )}
          </div>
        </div>
      )}
    </Step>
  )
}
