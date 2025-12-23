import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { IndexHtmlTransformContext, Plugin } from 'vite'

const baseUrl = process.env['VITE_BASE_URL'] ||
  (process.env['VERCEL_URL'] ? `https://${process.env['VERCEL_URL']}` : undefined) ||
  (process.env['NODE_ENV'] !== 'production' ? 'http://localhost:5173' : 'https://docs.tempo.xyz')

/**
 * Finds the MDX file for a given path
 * Handles various path formats that Vocs might use
 */
function findMdxFile(path: string, pagesDir: string): string | null {
  // Remove query params and hash
  const withoutQuery = path.split('?')[0] ?? path
  let cleanPath = withoutQuery.split('#')[0] ?? withoutQuery
  
  // Normalize /index.html to / for root path
  if (cleanPath === '/index.html' || cleanPath === 'index.html') {
    cleanPath = '/'
  }
  
  // Normalize path - remove leading/trailing slashes
  const normalizedPath = cleanPath.replace(/^\//, '').replace(/\/$/, '')
  
  // Handle root path
  if (normalizedPath === '') {
    const indexPath = join(pagesDir, 'index.mdx')
    if (existsSync(indexPath)) {
      return indexPath
    }
    return null
  }
  
  // Try multiple path variations
  const attempts = [
    // Direct file path: /learn -> pages/learn.mdx
    join(pagesDir, `${normalizedPath}.mdx`),
    // Directory index: /learn -> pages/learn/index.mdx
    join(pagesDir, normalizedPath, 'index.mdx'),
    // With trailing slash removed: /learn/ -> pages/learn/index.mdx
    normalizedPath.endsWith('/') 
      ? join(pagesDir, normalizedPath.slice(0, -1), 'index.mdx')
      : null,
  ].filter(Boolean) as string[]
  
  for (const attempt of attempts) {
    if (existsSync(attempt)) {
      return attempt
    }
  }
  
  return null
}

/**
 * Vite plugin to inject OG image meta tags into HTML
 */
export function ogImagePlugin(): Plugin {
  return {
    name: 'vite-plugin-og-image',
    enforce: 'post', // Run after Vocs processes files
    transformIndexHtml(html: string, ctx: IndexHtmlTransformContext) {
      // Debug: log that plugin is running
      const isDev = process.env['NODE_ENV'] !== 'production'
      if (isDev) {
        console.log('[OG Plugin] transformIndexHtml called')
        console.log('[OG Plugin] Context keys:', Object.keys(ctx))
      }

      // Get the actual route path - check originalUrl first, then path
      // Vocs uses /index.html for the root, but originalUrl has the real path
      let path = 'originalUrl' in ctx && ctx.originalUrl 
        ? new URL(ctx.originalUrl, 'http://localhost').pathname
        : ('path' in ctx ? ctx.path : undefined)
      
      // Normalize /index.html to / for root path
      if (path === '/index.html' || path === 'index.html') {
        path = '/'
      }
      
      if (isDev) {
        console.log('[OG Plugin] Path from context:', path)
        if ('originalUrl' in ctx) {
          console.log('[OG Plugin] Original URL:', ctx.originalUrl)
        }
      }
      
      if (!path || path.startsWith('/api/')) {
        if (isDev) {
          console.log('[OG Plugin] Skipping - no path or API route')
        }
        return html
      }

      const pagesDir = join(process.cwd(), 'pages')
      const mdxPath = findMdxFile(path, pagesDir)

      if (!mdxPath) {
        // No MDX file found for this path, skip
        // This is expected for some routes (like 404 pages)
        if (process.env['NODE_ENV'] !== 'production') {
          console.log(`[OG Plugin] No MDX file found for path: ${path}`)
        }
        return html
      }

      if (isDev) {
        console.log(`[OG Plugin] Processing path: ${path} -> ${mdxPath}`)
        console.log(`[OG Plugin] HTML length: ${html.length}`)
        console.log(`[OG Plugin] HTML contains </head>: ${html.includes('</head>')}`)
      }

      try {
        const content = readFileSync(mdxPath, 'utf-8')
        
        // Extract frontmatter - handle various formats
        const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n/)
        if (!frontmatterMatch) {
          if (isDev) {
            console.log(`[OG Plugin] No frontmatter found in ${mdxPath}`)
            console.log(`[OG Plugin] File content preview: ${content.substring(0, 200)}`)
          }
          return html
        }

        const frontmatter = frontmatterMatch[1]
        if (!frontmatter || frontmatter.trim() === '') {
          if (process.env['NODE_ENV'] !== 'production') {
            console.log(`[OG Plugin] Empty frontmatter in ${mdxPath}`)
          }
          return html
        }
        
        // Extract title - handle multi-line titles and various quote styles
        // Match title: "value" or title: 'value' or title: value (with optional quotes)
        const titleMatch = frontmatter.match(/title:\s*(.+?)(?=\n\w+:|---|$)/s)
        const descMatch = frontmatter.match(/description:\s*(.+?)(?=\n\w+:|---|$)/s)

        let title = titleMatch?.[1]
          ? titleMatch[1].trim().replace(/^["']|["']$/g, '').trim()
          : 'Documentation ⋅ Tempo'
        
        // Ensure title has "• Tempo" branding
        const tempoSuffix = ' • Tempo'
        if (!title.endsWith(tempoSuffix) && !title.endsWith(' • Tempo') && !title.endsWith(' · Tempo')) {
          title = `${title}${tempoSuffix}`
        }
        
        let description = descMatch?.[1]
          ? descMatch[1].trim().replace(/^["']|["']$/g, '').trim()
          : 'Documentation for Tempo testnet and protocol specifications'

        if (process.env['NODE_ENV'] !== 'production') {
          console.log(`[OG Plugin] Extracted - Title: ${title}, Description: ${description.substring(0, 50)}...`)
        }

        // Construct OG image URL using local API route
        const logoUrl = `${baseUrl}/lockup-light.svg`
        const ogImageUrl = `${baseUrl}/api/og?logo=${encodeURIComponent(logoUrl)}&title=${encodeURIComponent(title)}&description=${encodeURIComponent(description)}`
        
        if (process.env['NODE_ENV'] !== 'production') {
          console.log(`[OG Plugin] Generated OG image URL: ${ogImageUrl.substring(0, 100)}...`)
        }

        // Escape HTML entities
        const escapedTitle = title.replace(/"/g, '&quot;').replace(/&/g, '&amp;')
        const escapedDescription = description.replace(/"/g, '&quot;').replace(/&/g, '&amp;')

        // Inject OG meta tags before closing </head>
        // Check if og:image already exists to avoid duplicates
        const hasOgImage = html.includes('property="og:image"') || html.includes('property=\'og:image\'')
        
        if (hasOgImage) {
          // Replace existing OG tags - handle both single and double quotes
          const ogImageRegex = /<meta\s+property=["']og:image["'][^>]*>/gi
          const ogImageWidthRegex = /<meta\s+property=["']og:image:width["'][^>]*>/gi
          const ogImageHeightRegex = /<meta\s+property=["']og:image:height["'][^>]*>/gi
          const ogTitleRegex = /<meta\s+property=["']og:title["'][^>]*>/gi
          const ogDescRegex = /<meta\s+property=["']og:description["'][^>]*>/gi
          
          html = html.replace(ogImageRegex, `<meta property="og:image" content="${ogImageUrl}" />`)
          html = html.replace(ogImageWidthRegex, '<meta property="og:image:width" content="1200" />')
          html = html.replace(ogImageHeightRegex, '<meta property="og:image:height" content="630" />')
          html = html.replace(ogTitleRegex, `<meta property="og:title" content="${escapedTitle}" />`)
          html = html.replace(ogDescRegex, `<meta property="og:description" content="${escapedDescription}" />`)
          
          if (process.env['NODE_ENV'] !== 'production') {
            console.log(`[OG Plugin] Replaced existing OG tags for ${path}`)
          }
        } else {
          // Add new OG tags before </head>
          const ogTags = `\n    <meta property="og:image" content="${ogImageUrl}" />\n    <meta property="og:image:width" content="1200" />\n    <meta property="og:image:height" content="630" />\n    <meta property="og:title" content="${escapedTitle}" />\n    <meta property="og:description" content="${escapedDescription}" />`
          
          // Try to insert before </head>, fallback to before </body> if </head> not found
          if (html.includes('</head>')) {
            html = html.replace('</head>', `${ogTags}\n  </head>`)
          } else if (html.includes('</body>')) {
            html = html.replace('</body>', `${ogTags}\n  </body>`)
          } else {
            // Last resort: append to end
            html = html + ogTags
          }
          
          if (process.env['NODE_ENV'] !== 'production') {
            console.log(`[OG Plugin] Added new OG tags for ${path}`)
          }
        }

        return html
      } catch (error) {
        console.warn(`Failed to inject OG image for ${path}:`, error)
        return html
      }
    },
  }
}
