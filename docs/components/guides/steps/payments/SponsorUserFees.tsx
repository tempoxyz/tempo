import * as React from 'react'
import { Hooks } from 'tempo.ts/wagmi'
import { formatUnits, isAddress, pad, parseUnits, stringToHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { useAccount, useAccountEffect, useBlockNumber } from 'wagmi'
import { useDemoContext } from '../../../DemoContext'
import {
  Button,
  ExplorerAccountLink,
  ExplorerLink,
  FAKE_RECIPIENT,
  Step,
} from '../../Demo'
import { alphaUsd } from '../../tokens'
import type { DemoStepProps } from '../types'

export function CreateSponsorAccount(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { setData, getData } = useDemoContext()

  const sponsorAccount = getData('sponsorAccount')

  const handleCreate = () => {
    const privateKey = `0x${Array.from({ length: 64 }, () =>
      Math.floor(Math.random() * 16).toString(16),
    ).join('')}` as `0x${string}`
    const account = privateKeyToAccount(privateKey)
    setData('sponsorAccount', account)
  }

  return (
    <Step
      active={last ? true : !sponsorAccount}
      completed={!!sponsorAccount}
      actions={
        sponsorAccount ? (
          <Button
            variant="default"
            static
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Created
          </Button>
        ) : (
          <Button
            variant="accent"
            onClick={handleCreate}
            type="button"
            className="text-[14px] -tracking-[2%] font-normal"
          >
            Create Sponsor Account
          </Button>
        )
      }
      number={stepNumber}
      title="Create a sponsor account to pay fees for your users."
    >
      {sponsorAccount && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="mt-2 p-3 rounded-lg bg-gray2 text-[13px] -tracking-[1%]">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    Your Sponsor Account
                  </span>
                  <ExplorerAccountLink address={sponsorAccount.address} />
                </div>
                <div className="text-gray9 text-[12px] mt-1">
                  You control this account and will use it to sponsor
                  transaction fees for your users.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </Step>
  )
}

export function FundSponsorAccount(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { getData } = useDemoContext()
  const { mutate, isPending } = Hooks.faucet.useFundSync()

  const sponsorAccount = getData('sponsorAccount')

  const { data: sponsorBalance, refetch: sponsorBalanceRefetch } =
    Hooks.token.useGetBalance({
      account: sponsorAccount?.address,
      token: alphaUsd,
      query: {
        enabled: !!sponsorAccount,
      },
    })

  const { data: blockNumber } = useBlockNumber({
    query: {
      enabled: Boolean(
        sponsorAccount && (!sponsorBalance || sponsorBalance < 0),
      ),
      refetchInterval: 1_500,
    },
  })

  React.useEffect(() => {
    sponsorBalanceRefetch()
  }, [blockNumber])

  return (
    <Step
      active={
        !!sponsorAccount &&
        (last ? true : !sponsorBalance || sponsorBalance === 0n)
      }
      completed={Boolean(
        sponsorAccount && sponsorBalance && sponsorBalance > 0n,
      )}
      actions={
        <Button
          disabled={isPending}
          variant="default"
          className="text-[14px] -tracking-[2%] font-normal"
          onClick={() =>
            mutate({ account: sponsorAccount?.address as `0x${string}` })
          }
          type="button"
        >
          {isPending
            ? 'Adding funds'
            : sponsorBalance && sponsorBalance > 0n
              ? 'Add more funds'
              : 'Add funds'}
        </Button>
      }
      number={stepNumber}
      title="Fund your sponsor account with AlphaUSD."
    />
  )
}

export function SendSponsoredPayment(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useAccount()
  const { getData } = useDemoContext()
  const [recipient, setRecipient] = React.useState<string>(FAKE_RECIPIENT)
  const [memo, setMemo] = React.useState<string>('')
  const [expanded, setExpanded] = React.useState(false)

  const sponsorAccount = getData('sponsorAccount')

  const { data: userBalance, refetch: userBalanceRefetch } =
    Hooks.token.useGetBalance({
      account: address,
      token: alphaUsd,
    })

  const { data: sponsorBalance, refetch: sponsorBalanceRefetch } =
    Hooks.token.useGetBalance({
      account: sponsorAccount?.address,
      token: alphaUsd,
      query: {
        enabled: !!sponsorAccount,
      },
    })

  const sendPayment = Hooks.token.useTransferSync({
    mutation: {
      onSettled() {
        userBalanceRefetch()
        sponsorBalanceRefetch()
      },
    },
  })

  useAccountEffect({
    onDisconnect() {
      setExpanded(false)
      sendPayment.reset()
    },
  })

  const isValidRecipient = recipient && isAddress(recipient)

  const handleTransfer = () => {
    if (!isValidRecipient || !sponsorAccount) return

    sendPayment.mutate({
      amount: parseUnits('100', 6),
      to: recipient as `0x${string}`,
      token: alphaUsd,
      memo: memo ? pad(stringToHex(memo), { size: 32 }) : undefined,
      feePayer: sponsorAccount,
    })
  }

  const active = React.useMemo(() => {
    return Boolean(
      address &&
        userBalance &&
        userBalance > 0n &&
        sponsorAccount &&
        sponsorBalance &&
        sponsorBalance > 0n,
    )
  }, [address, userBalance, sponsorAccount, sponsorBalance])

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
      title="Send payment with fees sponsored by your account."
    >
      {expanded && sponsorAccount && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            {/* Sponsor info display */}
            <div className="mt-2 mb-3 p-3 rounded-lg bg-gray2 text-[13px] -tracking-[1%]">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    Connected Account AlphaUSD Balance:
                  </span>
                  <span className="text-gray12">
                    {formatUnits(userBalance ?? 0n, 6)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    Sponsor Account AlphaUSD Balance:
                  </span>
                  <span className="text-gray12">
                    {formatUnits(sponsorBalance ?? 0n, 6)}
                  </span>
                </div>
              </div>
              <div className="text-gray9 text-[12px] mt-2 pt-2 border-t border-gray4">
                The sponsor account pays the transaction fees.
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
                variant={active && isValidRecipient ? 'accent' : 'default'}
                disabled={!(active && isValidRecipient)}
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

export function SendRelayerSponsoredPayment(props: DemoStepProps) {
  const { stepNumber, last = false } = props
  const { address } = useAccount()
  const [recipient, setRecipient] = React.useState<string>(FAKE_RECIPIENT)
  const [memo, setMemo] = React.useState<string>('')
  const [expanded, setExpanded] = React.useState(false)

  const { data: userBalance, refetch: userBalanceRefetch } =
    Hooks.token.useGetBalance({
      account: address,
      token: alphaUsd,
    })

  const sendPayment = Hooks.token.useTransferSync({
    mutation: {
      onSettled() {
        userBalanceRefetch()
      },
    },
  })

  useAccountEffect({
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
      token: alphaUsd,
      memo: memo ? pad(stringToHex(memo), { size: 32 }) : undefined,
      feePayer: true,
    })
  }

  const active = React.useMemo(() => {
    return Boolean(address && userBalance && userBalance > 0n)
  }, [address, userBalance])

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
      title="Send 100 AlphaUSD with fees sponsored by the testnet fee payer."
    >
      {expanded && (
        <div className="flex mx-6 flex-col gap-3 pb-4">
          <div className="ps-5 border-gray4 border-s-2">
            <div className="mt-2 mb-3 p-3 rounded-lg bg-gray2 text-[13px] -tracking-[1%]">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-gray10 font-medium">
                    Payment Token: AlphaUSD
                  </span>
                  <span className="text-gray12">
                    balance: {formatUnits(userBalance ?? 0n, 6)}
                  </span>
                </div>
              </div>
              <div className="text-gray9 text-[12px] mt-2 pt-2 border-t border-gray4">
                  The testnet fee payer at https://sponsor.testnet.tempo.xyz will pay the transaction fees.
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
                variant={active && isValidRecipient ? 'accent' : 'default'}
                disabled={!(active && isValidRecipient)}
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
