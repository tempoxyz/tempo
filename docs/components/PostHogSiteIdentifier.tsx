import { usePostHog } from 'posthog-js/react'
import { useEffect } from 'react'

/**
 * Component to set site identifier for PostHog
 * This distinguishes docs from web in the same PostHog project
 */
export function PostHogSiteIdentifier() {
  const posthog = usePostHog()

  useEffect(() => {
    if (posthog) {
      // Set site property as a super property so it's included in all events
      posthog.register({
        site: 'docs',
      })
    }
  }, [posthog])

  return null
}
