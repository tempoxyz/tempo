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
  const posthogKey = import.meta.env.VITE_PUBLIC_POSTHOG_KEY
  const posthogHost = import.meta.env.VITE_PUBLIC_POSTHOG_HOST

  const appContent = (
    <WagmiProvider config={props.frontmatter?.mipd ? mipdConfig : config}>
      <QueryClientProvider client={queryClient}>
        <NuqsAdapter>
          {posthogKey && posthogHost && <PostHogSiteIdentifier />}
          {posthogKey && posthogHost && <PageViewTracker />}
          <DemoContextProvider>{props.children}</DemoContextProvider>
        </NuqsAdapter>
      </QueryClientProvider>
    </WagmiProvider>
  )

  return (
    <>
      {posthogKey && posthogHost ? (
        <PostHogProvider
          apiKey={posthogKey}
          options={{
            api_host: posthogHost,
            defaults: '2025-05-24',
            capture_exceptions: true, // This enables capturing exceptions using Error Tracking
            debug: import.meta.env.MODE === 'development',
          }}
        >
          {appContent}
        </PostHogProvider>
      ) : (
        appContent
      )}

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