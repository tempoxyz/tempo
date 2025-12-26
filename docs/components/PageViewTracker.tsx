import { useEffect } from 'react'
import { useLocation } from 'react-router'
import { usePostHogTracking } from '../lib/posthog'

/**
 * Component to track page views automatically
 * Should be placed inside the PostHogProvider
 */
export function PageViewTracker() {
  const location = useLocation()
  const { trackPageView } = usePostHogTracking()

  useEffect(() => {
    // Track page view on mount and when location changes
    trackPageView(location.pathname + location.search, document.title)
  }, [location.pathname, location.search, trackPageView])

  return null
}
