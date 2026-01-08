import { usePostHog } from 'posthog-js/react'

/**
 * PostHog event names
 * Following naming convention: UPPERCASE_WITH_UNDERSCORE
 */
export const POSTHOG_EVENTS = {
  // Page views
  PAGE_VIEW: 'docs_page_view',

  // Link clicks
  INTERNAL_LINK_CLICK: 'docs_internal_link_click',
  EXTERNAL_LINK_CLICK: 'docs_external_link_click',
  NAVIGATION_LINK_CLICK: 'docs_navigation_link_click',

  // Button clicks
  BUTTON_CLICK: 'docs_button_click',
  CTA_CLICK: 'docs_cta_click',

  // Copy actions
  COPY_CODE: 'docs_copy_code',
  COPY_COMMAND: 'docs_copy_command',

  // Demo interactions
  DEMO_START: 'docs_demo_start',
  DEMO_STEP_COMPLETE: 'docs_demo_step_complete',
  DEMO_SOURCE_CLICK: 'docs_demo_source_click',

  // Search
  SEARCH_QUERY: 'docs_search_query',
  SEARCH_RESULT_CLICK: 'docs_search_result_click',

  // Code interactions
  CODE_EXAMPLE_VIEW: 'docs_code_example_view',
  CODE_EXAMPLE_COPY: 'docs_code_example_copy',
} as const

/**
 * PostHog event property names
 * Following naming convention: UPPERCASE_WITH_UNDERSCORE
 */
export const POSTHOG_PROPERTIES = {
  // Site identification
  SITE: 'site',

  // Common properties
  PAGE_PATH: 'page_path',
  PAGE_TITLE: 'page_title',
  LINK_URL: 'link_url',
  LINK_TEXT: 'link_text',
  BUTTON_TEXT: 'button_text',
  BUTTON_VARIANT: 'button_variant',
  EXTERNAL_DOMAIN: 'external_domain',

  // Code-related properties
  CODE_LANGUAGE: 'code_language',
  CODE_SNIPPET: 'code_snippet',
  COMMAND_TEXT: 'command_text',

  // Demo properties
  DEMO_NAME: 'demo_name',
  DEMO_STEP: 'demo_step',
  DEMO_STEP_NAME: 'demo_step_name',

  // Search properties
  SEARCH_QUERY: 'search_query',
  SEARCH_RESULT_TITLE: 'search_result_title',
  SEARCH_RESULT_URL: 'search_result_url',
} as const

/**
 * Hook to access PostHog instance
 */
export function usePostHogTracking() {
  const posthog = usePostHog()

  return {
    posthog,
    /**
     * Track a page view
     */
    trackPageView: (path: string, title?: string) => {
      posthog?.capture(POSTHOG_EVENTS.PAGE_VIEW, {
        [POSTHOG_PROPERTIES.PAGE_PATH]: path,
        [POSTHOG_PROPERTIES.PAGE_TITLE]: title || document.title,
      })
    },

    /**
     * Track an internal link click
     */
    trackInternalLinkClick: (url: string, linkText?: string) => {
      posthog?.capture(POSTHOG_EVENTS.INTERNAL_LINK_CLICK, {
        [POSTHOG_PROPERTIES.LINK_URL]: url,
        [POSTHOG_PROPERTIES.LINK_TEXT]: linkText,
        [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
      })
    },

    /**
     * Track an external link click
     */
    trackExternalLinkClick: (url: string, linkText?: string) => {
      try {
        const domain = new URL(url).hostname
        posthog?.capture(POSTHOG_EVENTS.EXTERNAL_LINK_CLICK, {
          [POSTHOG_PROPERTIES.LINK_URL]: url,
          [POSTHOG_PROPERTIES.LINK_TEXT]: linkText,
          [POSTHOG_PROPERTIES.EXTERNAL_DOMAIN]: domain,
          [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
        })
      } catch {
        // Invalid URL, skip tracking
      }
    },

    /**
     * Track a button click
     */
    trackButtonClick: (
      buttonText: string,
      variant?: string,
      additionalProps?: Record<string, unknown>,
    ) => {
      posthog?.capture(POSTHOG_EVENTS.BUTTON_CLICK, {
        [POSTHOG_PROPERTIES.BUTTON_TEXT]: buttonText,
        [POSTHOG_PROPERTIES.BUTTON_VARIANT]: variant,
        [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
        ...additionalProps,
      })
    },

    /**
     * Track a CTA click
     */
    trackCTAClick: (ctaText: string, destination?: string) => {
      posthog?.capture(POSTHOG_EVENTS.CTA_CLICK, {
        [POSTHOG_PROPERTIES.BUTTON_TEXT]: ctaText,
        [POSTHOG_PROPERTIES.LINK_URL]: destination,
        [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
      })
    },

    /**
     * Track a copy action
     */
    trackCopy: (
      type: 'code' | 'command',
      content: string,
      language?: string,
    ) => {
      const eventName =
        type === 'code' ? POSTHOG_EVENTS.COPY_CODE : POSTHOG_EVENTS.COPY_COMMAND

      posthog?.capture(eventName, {
        [POSTHOG_PROPERTIES.CODE_LANGUAGE]: language,
        [POSTHOG_PROPERTIES.COMMAND_TEXT]:
          type === 'command' ? content : undefined,
        [POSTHOG_PROPERTIES.CODE_SNIPPET]:
          type === 'code' ? content.substring(0, 100) : undefined, // Limit length
        [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
      })
    },

    /**
     * Track a demo interaction
     */
    trackDemo: (
      action: 'start' | 'step_complete' | 'source_click',
      demoName?: string,
      step?: number,
      stepName?: string,
      sourceUrl?: string,
    ) => {
      const eventNameMap = {
        start: POSTHOG_EVENTS.DEMO_START,
        step_complete: POSTHOG_EVENTS.DEMO_STEP_COMPLETE,
        source_click: POSTHOG_EVENTS.DEMO_SOURCE_CLICK,
      }

      posthog?.capture(eventNameMap[action], {
        [POSTHOG_PROPERTIES.DEMO_NAME]: demoName,
        [POSTHOG_PROPERTIES.DEMO_STEP]: step,
        [POSTHOG_PROPERTIES.DEMO_STEP_NAME]: stepName,
        [POSTHOG_PROPERTIES.LINK_URL]: sourceUrl,
        [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
      })
    },

    /**
     * Track a search query
     */
    trackSearch: (query: string, resultTitle?: string, resultUrl?: string) => {
      if (resultTitle || resultUrl) {
        posthog?.capture(POSTHOG_EVENTS.SEARCH_RESULT_CLICK, {
          [POSTHOG_PROPERTIES.SEARCH_QUERY]: query,
          [POSTHOG_PROPERTIES.SEARCH_RESULT_TITLE]: resultTitle,
          [POSTHOG_PROPERTIES.SEARCH_RESULT_URL]: resultUrl,
          [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
        })
      } else {
        posthog?.capture(POSTHOG_EVENTS.SEARCH_QUERY, {
          [POSTHOG_PROPERTIES.SEARCH_QUERY]: query,
          [POSTHOG_PROPERTIES.PAGE_PATH]: window.location.pathname,
        })
      }
    },
  }
}
