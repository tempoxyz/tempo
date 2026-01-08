const outDirectory = 'dist'
const hostname = 'https://docs.tempo.xyz'

const excludeRoutes = ['_template', 'google']

type ChangeFreq =
  | 'always'
  | 'hourly'
  | 'daily'
  | 'weekly'
  | 'monthly'
  | 'yearly'
  | 'never'

// Sitemap changefreq values per spec: always, hourly, daily, weekly, monthly, yearly, never
const FREQ_THRESHOLDS = {
  daily: 1,
  weekly: 7,
  monthly: 30,
  yearly: 365,
} as const

import { existsSync } from 'node:fs'

// Only run if dist directory exists (i.e., after vocs build)
if (existsSync(outDirectory)) {
  main()
    .catch((error) => console.error(error))
    .finally(() => process.exit(0))
} else {
  console.log('Skipping sitemap generation: dist directory not found')
  process.exit(0)
}

// Map route to source file path pattern
function routeToSourceFile(route: string): string {
  if (route === '/') return 'pages/index'
  return `pages${route}`
}

// Get last modified date and calculate changefreq from git history
async function getGitInfo(route: string): Promise<{
  lastmod: string
  changefreq: ChangeFreq
}> {
  const sourcePath = routeToSourceFile(route)
  const now = Date.now()

  // Try each file pattern separately since git doesn't handle missing files well
  const patterns = [
    `${sourcePath}.mdx`,
    `${sourcePath}/index.mdx`,
    `${sourcePath}.md`,
    `${sourcePath}/index.md`,
  ]

  let allDates: number[] = []
  let lastCommitIso: string | null = null

  for (const pattern of patterns) {
    try {
      // Get ISO 8601 timestamps for W3C Datetime format (high fidelity for crawlers)
      const proc = Bun.spawn(
        [
          'git',
          'log',
          '--format=%aI', // ISO 8601 strict format
          '--follow',
          '--',
          pattern,
        ],
        { cwd: process.cwd(), stdout: 'pipe', stderr: 'pipe' },
      )

      const output = await new Response(proc.stdout).text()
      const timestamps = output.trim().split('\n').filter(Boolean)

      const firstTimestamp = timestamps[0]
      if (firstTimestamp) {
        // First line is most recent commit
        lastCommitIso = firstTimestamp
        allDates = timestamps.map((ts) => new Date(ts).getTime())
        break // Use first matching pattern
      }
    } catch {
      // Continue to next pattern
    }
  }

  if (allDates.length === 0 || !lastCommitIso) {
    return {
      lastmod: new Date().toISOString(),
      changefreq: 'monthly' as const,
    }
  }

  // Use full ISO 8601 timestamp for lastmod (W3C Datetime format)
  const lastmod = lastCommitIso

  // Calculate changefreq based on commit history
  let changefreq: ChangeFreq = 'yearly'

  if (allDates.length >= 2) {
    allDates.sort((a, b) => b - a)
    const mostRecent = allDates[0] ?? now

    // Average interval between commits
    let totalInterval = 0
    for (let i = 0; i < allDates.length - 1; i++) {
      const current = allDates[i] ?? 0
      const next = allDates[i + 1] ?? 0
      totalInterval += current - next
    }
    const avgIntervalDays =
      totalInterval / (allDates.length - 1) / (1000 * 60 * 60 * 24)

    // Days since last update
    const daysSinceLastUpdate = (now - mostRecent) / (1000 * 60 * 60 * 24)

    // Use the more conservative estimate
    const effectiveInterval = Math.max(avgIntervalDays, daysSinceLastUpdate)

    if (effectiveInterval <= FREQ_THRESHOLDS.daily) changefreq = 'daily'
    else if (effectiveInterval <= FREQ_THRESHOLDS.weekly) changefreq = 'weekly'
    else if (effectiveInterval <= FREQ_THRESHOLDS.monthly)
      changefreq = 'monthly'
    else changefreq = 'yearly'
  } else {
    // Single commit - base on recency
    const mostRecent = allDates[0] ?? now
    const daysSinceLastUpdate = (now - mostRecent) / (1000 * 60 * 60 * 24)

    if (daysSinceLastUpdate <= FREQ_THRESHOLDS.weekly) changefreq = 'weekly'
    else if (daysSinceLastUpdate <= FREQ_THRESHOLDS.monthly)
      changefreq = 'monthly'
    else changefreq = 'yearly'
  }

  return { lastmod, changefreq }
}

async function main() {
  const glob = new Bun.Glob('**/*.html')
  const files = Array.from(glob.scanSync(outDirectory))

  const routes = files
    .map((file) =>
      `/${file}`.replace(/\/index\.html$/, '').replace(/\.html$/, ''),
    )
    .map((route) => (route === '' ? '/' : route))
    .filter(
      (route) => !excludeRoutes.some((exclude) => route.includes(exclude)),
    )
    .sort()

  console.log(`Analyzing git history for ${routes.length} pages...`)

  // Get git info for each route in parallel
  const routeInfo = await Promise.all(
    routes.map(async (route) => ({
      route,
      ...(await getGitInfo(route)),
    })),
  )

  // Log frequency distribution
  const freqCounts: Record<string, number> = {}
  for (const { changefreq } of routeInfo) {
    freqCounts[changefreq] = (freqCounts[changefreq] || 0) + 1
  }
  console.log('Frequency distribution:', freqCounts)

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${routeInfo
  .map(
    ({ route, lastmod, changefreq }) => `  <url>
    <loc>${hostname}${route}</loc>
    <lastmod>${lastmod}</lastmod>
    <changefreq>${changefreq}</changefreq>
  </url>`,
  )
  .join('\n')}
</urlset>`

  const IS_PRODUCTION = process.env.NODE_ENV === 'production'

  const sitemapSuccess = await Bun.write(`${outDirectory}/sitemap.xml`, sitemap)
  if (sitemapSuccess)
    console.log(`✓ Generated sitemap.xml with ${routes.length} URLs`)
  else console.error('Failed to generate sitemap.xml')

  // only allow all routes in production

  const allow = IS_PRODUCTION ? '' : '/'

  const robots = /* txt */ `User-agent: *
Disallow: ${allow}

Sitemap: ${hostname}/sitemap.xml`
  const robotsSuccess = await Bun.write(`${outDirectory}/robots.txt`, robots)
  if (robotsSuccess) console.log(`✓ Generated robots.txt`)
  else console.error('Failed to generate robots.txt')
}
