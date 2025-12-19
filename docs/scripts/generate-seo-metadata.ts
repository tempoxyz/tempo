import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs'
import { join, relative } from 'node:path'

/**
 * Truncates description to exactly 160 characters max, ensuring it ends with a period
 * and doesn't cut off mid-word or mid-sentence. Prefers the first complete sentence.
 */
export function truncateDescription(description: string, maxLength: number = 160): string {
  let result = description.trim()
  
  // First, try to find the first complete sentence (ending with period) that fits within maxLength
  // This is preferred over using the last period, as it gives cleaner, more complete descriptions
  const firstPeriod = result.indexOf('.')
  if (firstPeriod > 0 && firstPeriod < maxLength) {
    // Check if this is a complete sentence (not just a decimal point or abbreviation)
    // A complete sentence should have at least 10 characters before the period
    if (firstPeriod > 10) {
      const firstSentence = result.substring(0, firstPeriod + 1).trim()
      // If there's text after the first sentence, prefer using just the first sentence
      // This ensures we don't include incomplete second sentences
      const textAfterFirstPeriod = result.substring(firstPeriod + 1).trim()
      if (textAfterFirstPeriod.length > 0) {
        // Use the first sentence if it's a reasonable length
        if (firstSentence.length <= maxLength) {
          return firstSentence
        }
      } else {
        // No text after first period, so first sentence is the whole description
        if (firstSentence.length <= maxLength) {
          return firstSentence
        }
      }
    }
  }
  
  // If first sentence doesn't work, fall back to last period within maxLength
  const truncated = result.substring(0, maxLength)
  const lastPeriod = truncated.lastIndexOf('.')
  
  // If we found a period that's not at the very start, use that sentence
  if (lastPeriod > 10) {
    result = result.substring(0, lastPeriod + 1).trim()
    // Result should now end with period and be within or close to maxLength
    if (result.endsWith('.') && result.length <= maxLength) {
      return result
    }
  }
  
  // If no period found within maxLength, we need to truncate at word boundary
  // First check if the full description is over the limit
  if (result.length > maxLength) {
    // Try to cut at word boundary - look for the last space before maxLength
    // We want to find a space that's reasonably close to maxLength (within 20 chars)
    let bestSpace = -1
    for (let i = Math.min(maxLength, result.length - 1); i >= Math.max(10, maxLength - 20); i--) {
      if (result[i] === ' ') {
        bestSpace = i
        break
      }
    }
    
    if (bestSpace > 10) {
      // Found a good word boundary
      result = result.substring(0, bestSpace).trim()
    } else {
      // No good word boundary found - this shouldn't happen often, but if it does,
      // try to find ANY space before maxLength
      const lastSpace = truncated.lastIndexOf(' ')
      if (lastSpace > 10) {
        result = result.substring(0, lastSpace).trim()
      } else {
        // Last resort: if we really can't find a space, truncate at maxLength
        // but this should be very rare
        result = truncated.trim()
      }
    }
  }
  
  // If we still don't have a period, ensure it ends with one
  // (This handles cases where there's no period in the description at all)
  if (!result.endsWith('.')) {
    // If adding period would exceed limit, remove last character(s) to make room
    if (result.length >= maxLength) {
      // Try to remove enough characters to fit the period, cutting at word boundary if possible
      const targetLength = maxLength - 1
      if (targetLength > 0) {
        const lastSpace = result.substring(0, targetLength).lastIndexOf(' ')
        if (lastSpace > targetLength - 20 && lastSpace > 10) {
          result = result.substring(0, lastSpace).trim()
        } else {
          result = result.substring(0, targetLength).trim()
        }
      }
    }
    // Add period
    result = `${result}.`
  }
  
  // Final safety check - ensure we don't exceed maxLength
  if (result.length > maxLength) {
    // Last resort: hard truncate, but try to end at word boundary
    const truncated = result.substring(0, maxLength)
    const lastSpace = truncated.lastIndexOf(' ')
    if (lastSpace > maxLength - 20 && lastSpace > 10) {
      result = result.substring(0, lastSpace).trim()
      if (!result.endsWith('.')) {
        result = `${result}.`
      }
    } else {
      result = truncated.trim()
      // Try to end with period if possible
      if (!result.endsWith('.') && result.length < maxLength) {
        result = `${result}.`
      }
    }
  }
  
  return result
}

/**
 * Appends "• Tempo" to title if not already present
 */
export function appendTempoBranding(title: string): string {
  const tempoSuffix = ' • Tempo'
  // Check if title already ends with "• Tempo" (with or without the bullet point character)
  if (title.endsWith(tempoSuffix) || title.endsWith(' • Tempo') || title.endsWith(' · Tempo')) {
    return title
  }
  return `${title}${tempoSuffix}`
}

/**
 * Extracts title from H1 heading or generates from filename
 */
export function extractTitle(content: string, filePath: string): string {
  // Try to find H1 heading
  const h1Match = content.match(/^#\s+(.+)$/m)
  if (h1Match && h1Match[1]) {
    let title = h1Match[1].trim()
    // Remove markdown formatting (backticks, bold, etc.)
    title = title.replace(/`([^`]+)`/g, '$1')
    title = title.replace(/\*\*([^*]+)\*\*/g, '$1')
    title = title.replace(/\*([^*]+)\*/g, '$1')
    // Remove brackets like [Documentation, integration guides, and protocol specifications]
    title = title.replace(/\s*\[.*?\]/g, '')
    // Capitalize first letter
    if (title.length > 0) {
      title = title.charAt(0).toUpperCase() + title.slice(1)
    }
    return appendTempoBranding(title)
  }

  // Fallback: generate from filename
  const fileName = filePath.split('/').pop()?.replace(/\.mdx?$/, '') || ''
  const title = fileName
    .split(/[-_]/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
  return appendTempoBranding(title)
}

/**
 * Extracts description from first paragraph or intro text
 * Also checks for subtitle in H1 square brackets (Vocs format)
 */
export function extractDescription(content: string): string {
  // First, check for subtitle in H1 heading (Vocs format: # Title [Subtitle])
  const h1Match = content.match(/^#\s+.+\[(.+?)\]/m)
  if (h1Match && h1Match[1]) {
    let subtitle = h1Match[1].trim()
    // Clean up markdown formatting
    subtitle = subtitle
      .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // Remove links, keep text
      .replace(/`([^`]+)`/g, '$1') // Remove code backticks
      .replace(/\*\*([^*]+)\*\*/g, '$1') // Remove bold
      .replace(/\*([^*]+)\*/g, '$1') // Remove italic
    // Use subtitle if it's a reasonable length
    if (subtitle.length > 10 && subtitle.length <= 160) {
      // Ensure it ends with period
      if (!subtitle.endsWith('.')) {
        subtitle = `${subtitle}.`
      }
      return truncateDescription(subtitle)
    }
  }
  
  // Remove frontmatter if present
  let body = content.replace(/^---\n[\s\S]*?\n---\n/, '')
  
  // Remove imports
  body = body.replace(/^import\s+.*?from\s+['"].*?['"];?\n/gm, '')
  
  // Remove H1 heading
  body = body.replace(/^#\s+.+$/m, '')
  
  // Find first paragraph (non-empty line after H1, skipping code blocks)
  const lines = body.split('\n')
  let inCodeBlock = false
  let paragraphLines: string[] = []
  
  for (const line of lines) {
    // Track code block state
    if (line.trim().startsWith('```')) {
      inCodeBlock = !inCodeBlock
      continue
    }
    
    if (inCodeBlock) continue
    
    // Skip empty lines, headings, and other markdown elements
    const trimmed = line.trim()
    if (
      trimmed === '' ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('import ') ||
      trimmed.startsWith(':::') ||
      trimmed.startsWith('<')
    ) {
      if (paragraphLines.length > 0) break
      continue
    }
    
    paragraphLines.push(line.trim())
    
    // Stop after first complete sentence (ending with period)
    // This ensures we get a clean, complete sentence for the description
    const text = paragraphLines.join(' ')
    const firstPeriod = text.indexOf('.')
    if (firstPeriod > 0) {
      // We found a complete sentence, use it
      break
    }
    
    // Also stop if we've collected enough text (safety limit)
    if (text.length > 200) {
      break
    }
  }
  
  let description = paragraphLines.join(' ').trim()
  
  // Clean up markdown formatting
  description = description
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // Remove links, keep text
    .replace(/`([^`]+)`/g, '$1') // Remove code backticks
    .replace(/\*\*([^*]+)\*\*/g, '$1') // Remove bold
    .replace(/\*([^*]+)\*/g, '$1') // Remove italic
    .replace(/\n+/g, ' ') // Replace newlines with spaces
    .replace(/\s+/g, ' ') // Normalize whitespace
  
  // Extract only the first complete sentence (ending with period)
  // This ensures we get a clean, complete sentence for the description
  const firstPeriod = description.indexOf('.')
  if (firstPeriod > 0 && firstPeriod > 10) {
    description = description.substring(0, firstPeriod + 1).trim()
  }
  
  // Truncate to max 160 characters (this will handle edge cases)
  description = truncateDescription(description)
  
  return description || 'Documentation for Tempo testnet and protocol specifications'
}

/**
 * Generates frontmatter YAML
 */
export function generateFrontmatter(title: string, description: string, existingFrontmatter?: string): string {
  const frontmatter: Record<string, string | boolean> = {}
  
  // Parse existing frontmatter if present
  if (existingFrontmatter) {
    const lines = existingFrontmatter.split('\n')
    for (const line of lines) {
      const match = line.match(/^(\w+):\s*(.+)$/)
      if (match && match[1] && match[2]) {
        const key = match[1]
        let value: string | boolean = match[2].trim()
        if (value === 'true') value = true
        if (value === 'false') value = false
        frontmatter[key] = value
      }
    }
  }
  
  // Add or update title and description
  // Ensure title has "• Tempo" branding
  frontmatter['title'] = appendTempoBranding(title)
  frontmatter['description'] = description
  
  // Build YAML string
  const yamlLines = Object.entries(frontmatter).map(([key, value]) => {
    if (typeof value === 'boolean') {
      return `${key}: ${value}`
    }
    return `${key}: ${JSON.stringify(value)}`
  })
  
  return `---\n${yamlLines.join('\n')}\n---\n\n`
}

/**
 * Processes a single MDX file
 */
function processFile(
  filePath: string,
  dryRun: boolean = false,
): { updated: boolean; title: string; description: string } {
  const content = readFileSync(filePath, 'utf-8')

  // Check if frontmatter already exists
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---\n/)
  const hasTitle = frontmatterMatch?.[1]?.includes('title:')
  const hasDescription = frontmatterMatch?.[1]?.includes('description:')

  // Extract metadata - always extract to ensure consistency
  const title = extractTitle(content, filePath)
  
  // Get description - always process to ensure it ends with period and is properly formatted
  let description = ''
  if (frontmatterMatch && hasDescription && frontmatterMatch[1]) {
    const frontmatter = frontmatterMatch[1]
    // Match description that may span multiple lines or be on a single line
    // Look for description: followed by content (handling quoted strings and multi-line)
    // Stop at next key, end of frontmatter (---), or end of string
    const descMatch = frontmatter.match(/description:\s*(.+?)(?=\n\w+:|---|$)/s)
    if (descMatch && descMatch[1]) {
      let rawDesc = descMatch[1].trim()
      // Remove quotes if present
      if ((rawDesc.startsWith('"') && rawDesc.endsWith('"')) || 
          (rawDesc.startsWith("'") && rawDesc.endsWith("'"))) {
        rawDesc = rawDesc.slice(1, -1)
      }
      description = rawDesc.trim()
    }
  }
  
  // If no description in frontmatter, extract from content
  if (!description) {
    description = extractDescription(content)
  } else {
    // Check if existing description is malformed (ends mid-word, no period, etc.)
    const endsWithPeriod = description.endsWith('.')
    const endsWithSpace = description.endsWith(' ')
    const lastChar = description.trim().slice(-1)
    const isAlphanumeric = /[a-zA-Z0-9]/.test(lastChar)
    const isMalformed = !endsWithPeriod && isAlphanumeric && !endsWithSpace
    
    // Check if existing description is incomplete (has text after first sentence)
    // If so, extract a fresh description from content instead
    const firstPeriod = description.indexOf('.')
    const textAfterFirstPeriod = firstPeriod > 10 ? 
      description.substring(firstPeriod + 1).trim() : ''
    
    // If description is malformed or has significant text after the first period,
    // extract a fresh one from content
    if (isMalformed || textAfterFirstPeriod.length > 3) {
      description = extractDescription(content)
    } else {
      // Always apply truncation to ensure it ends with period and is within limit
      description = truncateDescription(description)
    }
  }
  
  // Check if we actually need to update (only skip if both exist AND are already correct)
  let needsUpdate = true
  if (hasTitle && hasDescription && !dryRun && frontmatterMatch?.[1]) {
    // Check if title and description match what we would generate
    const existingTitleMatch = frontmatterMatch[1].match(/title:\s*(.+?)(?=\n\w+:|$)/s)
    let existingTitle = existingTitleMatch?.[1]?.trim() || ''
    // Remove quotes from existing title for comparison
    if ((existingTitle.startsWith('"') && existingTitle.endsWith('"')) || 
        (existingTitle.startsWith("'") && existingTitle.endsWith("'"))) {
      existingTitle = existingTitle.slice(1, -1).trim()
    }
    
    // Check if existing title has " • Tempo" branding
    const tempoSuffix = ' • Tempo'
    const hasBranding = existingTitle.endsWith(tempoSuffix) || existingTitle.endsWith(' • Tempo') || existingTitle.endsWith(' · Tempo')
    
    // Normalize existing title to ensure it has " • Tempo" branding for comparison
    const normalizedExistingTitle = appendTempoBranding(existingTitle)
    
    const existingDescMatch = frontmatterMatch[1].match(/description:\s*(.+?)(?=\n\w+:|---|$)/s)
    let existingDesc = existingDescMatch?.[1]?.trim() || ''
    // Remove quotes from existing description for comparison
    if ((existingDesc.startsWith('"') && existingDesc.endsWith('"')) || 
        (existingDesc.startsWith("'") && existingDesc.endsWith("'"))) {
      existingDesc = existingDesc.slice(1, -1).trim()
    }
    // Check if existing description is malformed (ends mid-word, no period, etc.)
    const endsWithPeriod = existingDesc.endsWith('.')
    const endsWithSpace = existingDesc.endsWith(' ')
    const lastChar = existingDesc.trim().slice(-1)
    const isAlphanumeric = /[a-zA-Z0-9]/.test(lastChar)
    const isMalformed = !endsWithPeriod && isAlphanumeric && !endsWithSpace
    
    // Check if existing description is properly truncated (ends at first sentence)
    // A properly truncated description should end at the first period
    // We check this by seeing if truncateDescription would change the description
    const normalizedExistingDesc = truncateDescription(existingDesc)
    const wouldChangeAfterTruncation = normalizedExistingDesc !== existingDesc
    
    // Check if there's significant text after the first period (indicating incomplete truncation)
    const firstPeriod = existingDesc.indexOf('.')
    // Get all text after the first period
    const textAfterFirstPeriod = firstPeriod > 10 ? 
      existingDesc.substring(firstPeriod + 1).trim() : ''
    // If truncateDescription would change it, or there's text after the first period, or it's malformed, it's not properly truncated
    const isProperlyTruncated = !isMalformed &&
                                !wouldChangeAfterTruncation && 
                                firstPeriod > 10 && 
                                (textAfterFirstPeriod === '' || textAfterFirstPeriod.length <= 3)
    
    // Check if the actual existing description matches what we would generate
    // (compare the actual file content, not normalized versions)
    const actualDescMatches = existingDesc === description
    
    // Always update if description is not properly truncated (has incomplete text after last period)
    // Only skip if ALL of these are true:
    // 1. Title matches (after normalization) AND
    // 2. Title already has branding AND
    // 3. Actual description in file matches what we would generate (exact match) AND
    // 4. Description ends with period AND
    // 5. Description is properly truncated at a sentence boundary
    if (!isProperlyTruncated) {
      // Force update if not properly truncated
      needsUpdate = true
    } else if (normalizedExistingTitle === title && hasBranding && 
               actualDescMatches && description.endsWith('.') &&
               isProperlyTruncated) {
      needsUpdate = false
    }
    // Otherwise, needsUpdate stays true (which is the default)
  }

  if (dryRun) {
    return { updated: needsUpdate, title, description }
  }

  // Only write if we need to update
  if (!needsUpdate) {
    return { updated: false, title, description }
  }

  // Generate new content
  let newContent = content

  if (frontmatterMatch) {
    // Update existing frontmatter
    const existingFrontmatter = frontmatterMatch[1]
    const newFrontmatter = generateFrontmatter(title, description, existingFrontmatter)
    newContent = content.replace(/^---\n[\s\S]*?\n---\n/, newFrontmatter)
  } else {
    // Add new frontmatter
    const newFrontmatter = generateFrontmatter(title, description)
    newContent = newFrontmatter + content
  }

  writeFileSync(filePath, newContent, 'utf-8')
  return { updated: true, title, description }
}

/**
 * Recursively find all MDX/MD files in a directory
 */
function findMarkdownFiles(dir: string, baseDir: string = dir): string[] {
  const files: string[] = []
  
  if (!existsSync(dir)) {
    return files
  }
  
  const entries = readdirSync(dir, { withFileTypes: true })
  
  for (const entry of entries) {
    const fullPath = join(dir, entry.name)
    
    if (entry.isDirectory()) {
      files.push(...findMarkdownFiles(fullPath, baseDir))
    } else if (entry.isFile() && /\.(mdx|md)$/.test(entry.name)) {
      files.push(relative(baseDir, fullPath))
    }
  }
  
  return files
}

/**
 * Main function to process all MDX files
 */
export function generateSEOMetadata(dryRun: boolean = false) {
  const pagesDir = join(process.cwd(), 'pages')

  if (!existsSync(pagesDir)) {
    console.error(`Pages directory not found: ${pagesDir}`)
    return
  }

  const files = findMarkdownFiles(pagesDir, pagesDir)

  console.log(`Found ${files.length} markdown files`)

  const results: Array<{ file: string; updated: boolean; title: string; description: string }> = []

  for (const file of files) {
    const filePath = join(pagesDir, file)
    const result = processFile(filePath, dryRun)
    results.push({ file, ...result })

    if (result.updated) {
      console.log(`✓ ${file}`)
      console.log(`  Title: ${result.title}`)
      console.log(`  Description: ${result.description.substring(0, 80)}...`)
    }
  }

  const updatedCount = results.filter((r) => r.updated).length
  console.log(`\n${updatedCount} files ${dryRun ? 'would be' : 'were'} updated`)

  return results
}

// Run if called directly
import { fileURLToPath } from 'node:url'
const __filename = fileURLToPath(import.meta.url)
if (process.argv[1] === __filename || process.argv[1]?.includes('generate-seo-metadata.ts')) {
  const dryRun = process.argv.includes('--dry-run')
  generateSEOMetadata(dryRun)
}

