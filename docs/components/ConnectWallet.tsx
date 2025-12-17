import * as React from 'react'
import {
  useChains,
  useConnect,
  useConnection,
  useConnectors,
  useSwitchChain,
} from 'wagmi'
import { Button, Logout } from './guides/Demo'
import { filterSupportedInjectedConnectors } from './lib/wallets'

export function ConnectWallet({
  showAddChain = true,
}: {
  showAddChain?: boolean
}) {
  const { address, chain, connector } = useConnection()
  const connect = useConnect()
  const connectors = useConnectors()
  const injectedConnectors = React.useMemo(
    () => filterSupportedInjectedConnectors(connectors),
    [connectors],
  )
  const switchChain = useSwitchChain()
  const chains = useChains()
  const isSupported = chains.some((c) => c.id === chain?.id)
  if (!injectedConnectors.length)
    return (
      <div className="text-[14px] -tracking-[2%] flex items-center">
        No browser wallets found.
      </div>
    )
  if (!address || connector?.id === 'webAuthn')
    return (
      <div className="flex gap-2">
        {injectedConnectors.map((connector) => (
          <Button
            variant="default"
            className="flex gap-1.5 items-center"
            key={connector.id}
            onClick={() => connect.connect({ connector })}
          >
            {connector.icon ? (
              <img
                className="size-5"
                src={connector.icon}
                alt={connector.name}
              />
            ) : (
              <div />
            )}
            {connector.name}
          </Button>
        ))}
      </div>
    )
  return (
    <div className="flex flex-col gap-2">
      <Logout />
      {showAddChain && !isSupported && (
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
}
