/**
 * Vercel Routing Middleware for tracking AI crawlers.
 *
 * AI crawlers (GPTBot, ClaudeBot, etc.) don't execute JavaScript,
 * so they're invisible to PostHog's client-side tracking.
 * This middleware runs server-side on every request to capture them.
 */

const AI_CRAWLERS = [
  'GPTBot',
  'OAI-SearchBot',
  'ChatGPT-User',
  'anthropic-ai',
  'ClaudeBot',
  'claude-web',
  'PerplexityBot',
  'Perplexity-User',
  'Google-Extended',
  'Googlebot',
  'Bingbot',
  'Amazonbot',
  'Applebot',
  'Applebot-Extended',
  'FacebookBot',
  'meta-externalagent',
  'LinkedInBot',
  'Bytespider',
  'DuckAssistBot',
  'cohere-ai',
  'AI2Bot',
  'CCBot',
  'Diffbot',
  'omgili',
  'Timpibot',
  'YouBot',
  'MistralAI-User',
  'GoogleAgent-Mariner',
]

export const config = {
  // Run on all paths except static assets
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|gif|svg|ico|webp)$).*)',
  ],
}

export default async function middleware(request: Request) {
  const ua = request.headers.get('user-agent') || ''
  const matchedCrawler = AI_CRAWLERS.find((crawler) => ua.includes(crawler))

  // Only track if it's a crawler (to avoid double-counting with client-side PostHog)
  if (matchedCrawler) {
    const url = new URL(request.url)
    const posthogKey = process.env['VITE_PUBLIC_POSTHOG_KEY']
    const posthogHost =
      process.env['VITE_PUBLIC_POSTHOG_HOST'] || 'https://us.i.posthog.com'

    if (posthogKey) {
      const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()

      const event = {
        api_key: posthogKey,
        event: 'crawler_pageview',
        distinct_id: `crawler_${matchedCrawler}`,
        properties: {
          crawler_name: matchedCrawler,
          user_agent: ua,
          path: url.pathname,
          $current_url: request.url,
          $ip: ip,
        },
      }

      // Fire-and-forget to PostHog (don't await to avoid latency)
      fetch(`${posthogHost}/capture/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
      }).catch(() => {
        // Silently ignore errors
      })
    }
  }

  // Continue to the actual page
  return undefined
}
