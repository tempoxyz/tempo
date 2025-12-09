import * as React from 'react'
import {
  useAccount,
  useChains,
  useConnect,
  useConnectors,
  useSwitchChain,
} from 'wagmi'
import { Button, Logout, Step } from '../../Demo'
import type { DemoStepProps } from '../types'

export function ConnectWallet(props: DemoStepProps) {
  const { stepNumber = 1 } = props
  const { address, chain, connector } = useAccount()
  const connect = useConnect()
  const connectors = useConnectors()
  const injectedConnectors = React.useMemo(
    () => connectors.filter((connector) => connector.id !== 'webAuthn'),
    [connectors],
  )
  const switchChain = useSwitchChain()
  const chains = useChains()
  const isSupported = chains.some((c) => c.id === chain?.id)

  const active = !address || !isSupported
  const completed = Boolean(address && isSupported)

  const actions = React.useMemo(() => {
    if (!injectedConnectors.length) {
      return (
        <div className="text-[14px] -tracking-[2%] flex items-center">
          No browser wallets found.
        </div>
      )
    }

    if (!address || connector?.id === 'webAuthn') {
      return (
        <div className="flex gap-2">
          {injectedConnectors.map((conn) => (
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
        <Logout />
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
    address,
    connector,
    connect,
    isSupported,
    switchChain,
    chains,
  ])

  return (
    <Step
      active={active}
      completed={completed}
      actions={actions}
      number={stepNumber}
      title="Connect your browser wallet."
    />
  )
}
