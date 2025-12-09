import * as React from 'react'
import {
  useAccount,
  useChains,
  useConnect,
  useConnection,
  useConnections,
  useConnectors,
  useDisconnect,
  useSwitchChain,
} from 'wagmi'
import LucideCheck from '~icons/lucide/check'
import LucideWalletCards from '~icons/lucide/wallet-cards'
import { filterSupportedInjectedConnectors } from '../../../lib/wallets'
import { Button, Step, StringFormatter, useCopyToClipboard } from '../../Demo'
import type { DemoStepProps } from '../types'

export function ConnectWallet(props: DemoStepProps) {
  const { stepNumber = 1 } = props
  const { chain, connector } = useConnection()
  const { status } = useAccount()
  const connections = useConnections()
  const connect = useConnect()
  const disconnect = useDisconnect()
  const connectors = useConnectors()
  const injectedConnectors = React.useMemo(
    () => filterSupportedInjectedConnectors(connectors),
    [connectors],
  )
  const switchChain = useSwitchChain()
  const chains = useChains()
  const isSupported = chains.some((c) => c.id === chain?.id)
  const [copied, copyToClipboard] = useCopyToClipboard()

  const walletConnection = connections.find(
    (c) => c.connector.id !== 'webAuthn',
  )
  const walletAddress = walletConnection?.accounts[0]
  const walletConnector = walletConnection?.connector
  const hasNonWebAuthnWallet = Boolean(walletAddress)
  const isReconnecting = status === 'reconnecting' || status === 'connecting'
  const active = !hasNonWebAuthnWallet || !isSupported
  const completed = hasNonWebAuthnWallet && isSupported

  const actions = React.useMemo(() => {
    if (!injectedConnectors.length) {
      return (
        <div className="text-[14px] -tracking-[2%] flex items-center">
          No browser wallets found.
        </div>
      )
    }

    if (!hasNonWebAuthnWallet) {
      // Show reconnecting state
      if (isReconnecting) {
        return (
          <div className="text-[14px] -tracking-[2%] flex items-center">
            Reconnecting...
          </div>
        )
      }

      // Filter out generic "Injected" if there are specific wallet connectors
      const displayConnectors = injectedConnectors.filter(conn => {
        // If there are multiple connectors and one is just "Injected", hide it
        if (injectedConnectors.length > 1 && conn.name === 'Injected') {
          return false
        }
        return true
      })

      return (
        <div className="flex gap-2 flex-wrap">
          {displayConnectors.map((conn) => (
            <Button
              variant="default"
              className="flex gap-1.5 items-center"
              key={conn.id}
              onClick={() => connect.connect({ connector: conn })}
            >
              {conn.icon ? (
                <img className="size-5" src={conn.icon} alt={conn.name} />
              ) : (
                <div />
              )}
              {conn.name}
            </Button>
          ))}
        </div>
      )
    }

    return (
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-1">
          <Button
            onClick={() => walletAddress && copyToClipboard(walletAddress)}
            variant="default"
          >
            {copied ? (
              <LucideCheck className="text-gray9 mt-px" />
            ) : (
              <LucideWalletCards className="text-gray9 mt-px" />
            )}
            {walletAddress &&
              StringFormatter.truncate(walletAddress, {
                start: 6,
                end: 4,
                separator: '⋅⋅⋅',
              })}
          </Button>
          <Button
            variant="destructive"
            className="text-[14px] -tracking-[2%] font-normal"
            onClick={() => disconnect.disconnect({ connector: walletConnector })}
            type="button"
          >
            Disconnect
          </Button>
        </div>
        {!isSupported && (
          <Button
            className="w-fit"
            variant="accent"
            onClick={() =>
              switchChain.switchChain({
                chainId: chains[0].id,
                addEthereumChainParameter: {
                  nativeCurrency: {
                    name: 'USD',
                    decimals: 18,
                    symbol: 'USD',
                  },
                  blockExplorerUrls: ['https://explore.tempo.xyz'],
                },
              })
            }
          >
            Add Tempo to {connector?.name ?? 'Wallet'}
          </Button>
        )}
        {switchChain.isSuccess && (
          <div className="text-[14px] -tracking-[2%] font-normal flex items-center">
            Added Tempo to {connector?.name ?? 'Wallet'}!
          </div>
        )}
      </div>
    )
  }, [
    injectedConnectors,
    hasNonWebAuthnWallet,
    walletAddress,
    walletConnector,
    copied,
    copyToClipboard,
    disconnect,
    connector,
    connect,
    isSupported,
    switchChain,
    chains,
  ])

  const stackConnectors = injectedConnectors.length > 2

  return (
    <Step
      active={active}
      completed={completed}
      number={stepNumber}
      title="Connect your browser wallet."
      actions={!stackConnectors && actions}
    >
      {stackConnectors && actions}
    </Step>
  )
}
