import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Json } from 'ox'
import React from 'react'
import { Toaster } from 'sonner'
import { WagmiProvider } from 'wagmi'
import { DemoContextProvider } from './components/DemoContext'
import * as WagmiConfig from './wagmi.config'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryKeyHashFn: Json.stringify,
    },
  },
})

export default function Layout(
  props: React.PropsWithChildren<{
    path: string
    frontmatter?: { mipd?: boolean }
  }>,
) {
  const config = React.useMemo(
    () =>
      WagmiConfig.getConfig({
        multiInjectedProviderDiscovery: Boolean(props.frontmatter?.mipd),
      }),
    [props.frontmatter?.mipd],
  )

  return (
    <>
      <WagmiProvider config={config}>
        <QueryClientProvider client={queryClient}>
          <DemoContextProvider>{props.children}</DemoContextProvider>
        </QueryClientProvider>
      </WagmiProvider>

      <Toaster
        className="z-[42069] select-none"
        expand={false}
        position="bottom-right"
        swipeDirections={['right', 'left', 'top', 'bottom']}
        theme="light"
        toastOptions={{
          style: {
            borderRadius: '1.5rem',
          },
        }}
      />
    </>
  )
}
