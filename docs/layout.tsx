import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Analytics } from '@vercel/analytics/react'
import { SpeedInsights } from '@vercel/speed-insights/react'
import { NuqsAdapter } from 'nuqs/adapters/react-router/v7'
import { Json } from 'ox'
import type React from 'react'
import { Toaster } from 'sonner'
import { WagmiProvider } from 'wagmi'
import { PostHogProvider } from 'posthog-js/react'
import { DemoContextProvider } from './components/DemoContext'
import { PageViewTracker } from './components/PageViewTracker'
import { PostHogSiteIdentifier } from './components/PostHogSiteIdentifier'
import * as WagmiConfig from './wagmi.config'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryKeyHashFn: Json.stringify,
    },
  },
})

const config = WagmiConfig.getConfig()
const mipdConfig = WagmiConfig.getConfig({
  multiInjectedProviderDiscovery: true,
})

export default function Layout(
  props: React.PropsWithChildren<{ path: string; frontmatter?: { mipd?: boolean } }>,
) {
  return (
    <>
      <PostHogProvider
        apiKey={import.meta.env.VITE_PUBLIC_POSTHOG_KEY}
        options={{
          api_host: import.meta.env.VITE_PUBLIC_POSTHOG_HOST,
          defaults: '2025-05-24',
          capture_exceptions: true, // This enables capturing exceptions using Error Tracking
          debug: import.meta.env.MODE === 'development',
        }}
      >
        <WagmiProvider config={props.frontmatter?.mipd ? mipdConfig : config}>
          <QueryClientProvider client={queryClient}>
            <NuqsAdapter>
              <PostHogSiteIdentifier />
              <PageViewTracker />
              <DemoContextProvider>{props.children}</DemoContextProvider>
            </NuqsAdapter>
          </QueryClientProvider>
        </WagmiProvider>
      </PostHogProvider>

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
      <SpeedInsights />
      <Analytics />
    </>
  )
}