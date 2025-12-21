import { useQueryClient } from '@tanstack/react-query'
import type { VariantProps } from 'cva'
import * as React from 'react'
import { tempo } from 'tempo.ts/chains'
import { Hooks } from 'tempo.ts/wagmi'
import type { Address, BaseError } from 'viem'
import { formatUnits } from 'viem'
import {
  useAccount,
  useConnect,
  useConnections,
  useConnectors,
  useDisconnect,
} from 'wagmi'
import LucideCheck from '~icons/lucide/check'
import LucideCopy from '~icons/lucide/copy'
import LucideExternalLink from '~icons/lucide/external-link'
import LucidePictureInPicture2 from '~icons/lucide/picture-in-picture-2'
import LucideRotateCcw from '~icons/lucide/rotate-ccw'
import LucideWalletCards from '~icons/lucide/wallet-cards'
import { cva, cx } from '../../cva.config'
import { Container as ParentContainer } from '../Container'
import { alphaUsd } from './tokens'

export const FAKE_RECIPIENT = '0xbeefcafe54750903ac1c8909323af7beb21ea2cb'
export const FAKE_RECIPIENT_2 = '0xdeadbeef54750903ac1c8909323af7beb21ea2cb'

export function useWebAuthnConnector() {
  const connectors = useConnectors()
  return React.useMemo(
    // biome-ignore lint/style/noNonNullAssertion: webAuthn connector always defined in wagmi.config.ts
    () => connectors.find((connector) => connector.id === 'webAuthn')!,
    [connectors],
  )
}

function getExplorerHost() {
  const { VITE_ENVIRONMENT, VITE_EXPLORER_OVERRIDE } = import.meta.env

  if (VITE_ENVIRONMENT !== 'testnet' && VITE_EXPLORER_OVERRIDE !== undefined) {
    return VITE_EXPLORER_OVERRIDE
  }

  return tempo({}).blockExplorers.default.url
}

export function ExplorerLink({ hash }: { hash: string }) {
  return (
    <div className="mt-1">
      <a
        href={`${getExplorerHost()}/tx/${hash}`}
        target="_blank"
        rel="noreferrer"
        className="text-accent text-[13px] -tracking-[1%] flex items-center gap-1 hover:underline"
      >
        View receipt
        <LucideExternalLink className="size-3" />
      </a>
    </div>
  )
}

export function ExplorerAccountLink({ address }: { address: string }) {
  return (
    <div className="mt-1">
      <a
        href={`${getExplorerHost()}/account/${address}`}
        target="_blank"
        rel="noreferrer"
        className="text-accent text-[13px] -tracking-[1%] flex items-center gap-1 hover:underline"
      >
        View account
        <LucideExternalLink className="size-3" />
      </a>
    </div>
  )
}

export function Container(
  props: React.PropsWithChildren<
    {
      name: string
      showBadge?: boolean | undefined
    } & (
      | {
          footerVariant: undefined
        }
      | {
          footerVariant: 'balances'
          tokens: Address[]
          balanceSource?: 'webAuthn' | 'wallet' | undefined
        }
      | {
          footerVariant: 'source'
          src: string
        }
    )
  >,
) {
  const { children, name, showBadge = true } = props
  const { address } = useAccount()
  const connections = useConnections()
  const disconnect = useDisconnect()
  const restart = React.useCallback(() => {
    disconnect.disconnect()
  }, [disconnect.disconnect])

  const balanceAddress = React.useMemo(() => {
    if (props.footerVariant !== 'balances') return address

    const source = props.balanceSource
    if (!source) return address

    if (source === 'webAuthn') {
      const webAuthnConnection = connections.find(
        (c) => c.connector.id === 'webAuthn',
      )
      return webAuthnConnection?.accounts[0]
    }

    if (source === 'wallet') {
      const walletConnection = connections.find(
        (c) => c.connector.id !== 'webAuthn',
      )
      return walletConnection?.accounts[0]
    }

    return address
  }, [props, address, connections])

  const footerElement = React.useMemo(() => {
    if (props.footerVariant === 'balances')
      return (
        <Container.BalancesFooter
          address={balanceAddress}
          tokens={props.tokens || [alphaUsd]}
        />
      )
    if (props.footerVariant === 'source')
      return <Container.SourceFooter src={props.src} />
    return null
  }, [props, balanceAddress])

  return (
    <ParentContainer
      headerLeft={
        <div className="flex gap-1.5 items-center">
          <h4 className="text-gray12 text-[14px] font-normal leading-none -tracking-[1%]">
            {name}
          </h4>
          {showBadge && (
            <span className="text-[9px] font-medium bg-accentTint text-accent h-[19px] flex items-center text-center justify-center rounded-[30px] px-1.5 tracking-[2%] uppercase leading-none">
              demo
            </span>
          )}
        </div>
      }
      headerRight={
        <div>
          {address && (
            <button
              type="button"
              onClick={restart}
              className="flex items-center text-gray9 leading-none gap-1 text-[12.5px] tracking-[-1%]"
            >
              <LucideRotateCcw className="text-gray9 size-3 mt-px" />
              Restart
            </button>
          )}
        </div>
      }
      footer={footerElement}
    >
      <div className="space-y-4">{children}</div>
    </ParentContainer>
  )
}

export namespace Container {
  function BalancesFooterItem(props: { address: Address; token: Address }) {
    const queryClient = useQueryClient()
    const { address, token } = props
    const {
      data: balance,
      isPending: balanceIsPending,
      queryKey: balancesKey,
    } = Hooks.token.useGetBalance({
      account: address,
      token,
    })
    const { data: metadata, isPending: metadataIsPending } =
      Hooks.token.useGetMetadata({
        token,
      })

    Hooks.token.useWatchTransfer({
      token,
      args: {
        to: address,
      },
      onTransfer: () => {
        queryClient.invalidateQueries({ queryKey: balancesKey })
      },
      enabled: !!address,
    })

    Hooks.token.useWatchTransfer({
      token,
      args: {
        from: address,
      },
      onTransfer: () => {
        queryClient.invalidateQueries({ queryKey: balancesKey })
      },
      enabled: !!address,
    })

    const isPending = balanceIsPending || metadataIsPending
    const isUndefined = balance === undefined || metadata === undefined

    return (
      <div>
        {isPending || isUndefined ? (
          <span />
        ) : (
          <span className="flex gap-1">
            <span className="text-gray10">
              {formatUnits(balance ?? 0n, metadata.decimals)}
            </span>
            {metadata.symbol}
          </span>
        )}
      </div>
    )
  }

  export function BalancesFooter(props: {
    address?: string | undefined
    tokens: Address[]
  }) {
    const { address, tokens } = props
    return (
      <div className="gap-2 h-full py-2 flex items-center leading-none">
        <span className="text-gray10">Balances</span>
        <div className="self-stretch min-h-5 w-px bg-gray4" />
        <div className="flex flex-col gap-2">
          {address ? (
            tokens.map((token) => (
              <BalancesFooterItem
                key={token}
                address={address as Address}
                token={token}
              />
            ))
          ) : (
            <span className="text-gray9">No account detected</span>
          )}
        </div>
      </div>
    )
  }

  export function SourceFooter(props: { src: string }) {
    const { src } = props
    const [isCopied, copy] = useCopyToClipboard()
    return (
      <div className="flex justify-between w-full">
        {/** biome-ignore lint/a11y/noStaticElementInteractions: _ */}
        {/** biome-ignore lint/a11y/useKeyWithClickEvents: _ */}
        <div
          className="text-primary flex cursor-pointer items-center gap-[6px] font-mono text-[12px] tracking-tight max-sm:hidden"
          onClick={() => copy(`pnpx gitpick ${src}`)}
          title="Copy to clipboard"
        >
          <div>
            <span className="text-gray10">pnpx gitpick</span> {src}
          </div>
          {isCopied ? (
            <LucideCheck className="text-gray10 size-3" />
          ) : (
            <LucideCopy className="text-gray10 size-3" />
          )}
        </div>
        <div className="text-accent text-[12px] tracking-tight">
          <a
            className="flex items-center gap-1"
            href={`https://github.com/${src}`}
            rel="noreferrer"
            target="_blank"
          >
            Source <LucideExternalLink className="size-[12px]" />
          </a>
        </div>
      </div>
    )
  }
}

export function Step(
  props: React.PropsWithChildren<{
    actions?: React.ReactNode | undefined
    active: boolean
    completed: boolean
    error?: BaseError | Error | null | undefined
    number: number
    title: React.ReactNode
  }>,
) {
  const { actions, active, children, completed, error, number, title } = props
  return (
    <div data-active={active} data-completed={completed} className="group">
      <header className="flex max-sm:flex-col max-sm:items-start max-sm:justify-start items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div
            className={cx(
              'text-[13px] dark:text-white text-black size-7 rounded-full text-center flex items-center justify-center tabular-nums opacity-40 group-data-[completed=true]:opacity-100',
              completed ? 'bg-green3' : 'bg-gray4',
            )}
          >
            {completed ? <LucideCheck className="text-green9" /> : number}
          </div>
          <div className="text-[14px] dark:text-white text-black -tracking-[1%] group-data-[active=false]:opacity-40">
            {title}
          </div>
        </div>
        <div className="opacity-40 group-data-[active=true]:opacity-100 group-data-[completed=true]:opacity-100">
          {actions}
        </div>
      </header>
      {children}
      {error && (
        <>
          <div className="h-2" />
          <div className="bg-destructiveTint text-destructive rounded py-2 px-3 text-[14px] -tracking-[2%] leading-normal font-normal">
            {'shortMessage' in error ? error.shortMessage : error.message}
          </div>
        </>
      )}
    </div>
  )
}

export namespace StringFormatter {
  export function truncate(
    str: string,
    {
      start = 8,
      end = 6,
      separator = '\u2026',
    }: {
      start?: number | undefined
      end?: number | undefined
      separator?: string | undefined
    } = {},
  ) {
    if (str.length <= start + end) return str
    return `${str.slice(0, start)}${separator}${str.slice(-end)}`
  }
}

export function Login() {
  const connect = useConnect()
  const connector = useWebAuthnConnector()

  return (
    <div>
      {connect.isPending ? (
        <Button disabled variant="default">
          <LucidePictureInPicture2 className="mt-px" />
          Check prompt
        </Button>
      ) : (
        <div className="flex gap-1">
          <Button
            variant="accent"
            className="text-[14px] -tracking-[2%] font-normal"
            onClick={() => connect.connect({ connector })}
            type="button"
          >
            Sign in
          </Button>
          <Button
            variant="default"
            className="text-[14px] -tracking-[2%] font-normal"
            onClick={() =>
              connect.connect({
                connector,
                capabilities: {
                  label: 'Tempo Docs',
                  type: 'sign-up',
                },
              })
            }
            type="button"
          >
            Sign up
          </Button>
        </div>
      )}
    </div>
  )
}

export function Logout() {
  const { address, connector } = useAccount()
  const disconnect = useDisconnect()
  const [copied, copyToClipboard] = useCopyToClipboard()
  if (!address) return null
  return (
    <div className="flex items-center gap-1">
      <Button onClick={() => copyToClipboard(address)} variant="default">
        {copied ? (
          <LucideCheck className="text-gray9 mt-px" />
        ) : (
          <LucideWalletCards className="text-gray9 mt-px" />
        )}
        {StringFormatter.truncate(address, {
          start: 6,
          end: 4,
          separator: '⋅⋅⋅',
        })}
      </Button>
      <Button
        variant="destructive"
        className="text-[14px] -tracking-[2%] font-normal"
        onClick={() => disconnect.disconnect({ connector })}
        type="button"
      >
        Sign out
      </Button>
    </div>
  )
}

export function Button(
  props: Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, 'disabled'> &
    VariantProps<typeof buttonClassName> & {
      render?: React.ReactElement
    },
) {
  const {
    className,
    disabled,
    render,
    size,
    static: static_,
    variant,
    ...rest
  } = props
  const Element = render
    ? (p: typeof props) => React.cloneElement(render, p)
    : 'button'
  return (
    <Element
      className={buttonClassName({
        className,
        disabled,
        size,
        static: static_,
        variant,
      })}
      {...rest}
    />
  )
}

const buttonClassName = cva({
  base: 'relative inline-flex gap-2 items-center justify-center whitespace-nowrap rounded-md font-normal transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50',
  defaultVariants: {
    size: 'default',
    variant: 'default',
  },
  variants: {
    disabled: {
      true: 'pointer-events-none opacity-50',
    },
    size: {
      default: 'text-[14px] -tracking-[2%] h-[32px] px-[14px]',
    },
    static: {
      true: 'pointer-events-none',
    },
    variant: {
      accent:
        'bg-(--vocs-color_inverted) text-(--vocs-color_background) border dark:border-dashed',
      default:
        'text-(--vocs-color_inverted) bg-(--vocs-color_background) border border-dashed',
      destructive:
        'bg-(--vocs-color_backgroundRedTint2) text-(--vocs-color_textRed) border border-dashed',
    },
  },
})

export function useCopyToClipboard(props?: useCopyToClipboard.Props) {
  const { timeout = 1_500 } = props ?? {}

  const [isCopied, setIsCopied] = React.useState(false)

  const timer = React.useRef<ReturnType<typeof setTimeout> | null>(null)

  const copyToClipboard: useCopyToClipboard.CopyFn = React.useCallback(
    async (text) => {
      if (!navigator?.clipboard) {
        console.warn('Clipboard API not supported')
        return false
      }

      if (timer.current) clearTimeout(timer.current)

      try {
        await navigator.clipboard.writeText(text)
        setIsCopied(true)
        timer.current = setTimeout(() => setIsCopied(false), timeout)
        return true
      } catch (error) {
        console.error('Failed to copy text: ', error)
        return false
      }
    },
    [timeout],
  )

  return [isCopied, copyToClipboard] as const
}

export declare namespace useCopyToClipboard {
  type CopyFn = (text: string) => Promise<boolean>
  type Props = {
    timeout?: number
  }
}
