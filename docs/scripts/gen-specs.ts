import * as child_process from 'node:child_process'
import * as fs from 'node:fs'
import * as path from 'node:path'
import type { SidebarItem } from 'vocs'

const specsDir = path.join(process.cwd(), 'specs')
const files = fs
  .readdirSync(specsDir)
  .filter((file) => file.endsWith('.md'))
  .sort()

const items: SidebarItem[] = []

for (const file of files) {
  const content = fs.readFileSync(path.join(specsDir, file), 'utf-8')
  const lines = content.split('\n')

  // Find the first heading (# or ##)
  let heading = ''
  for (const line of lines) {
    const match = line.match(/^#{1,2}\s+(.+)$/)
    if (!match?.[1]) continue
    heading = match[1].trim()
    break
  }
  if (!heading) continue

  const filename = file.replace('.md', '')
  items.push({
    text: heading,
    link: `/protocol/specs/${filename}`,
  })
}

const configPath = path.join(process.cwd(), 'vocs.config.tsx')
let config = fs.readFileSync(configPath, 'utf-8')

const context = items
  .map((item) => `{ text: '${item.text}', link: '${item.link}' }`)
  .join(',')

config = config.replace(
  /(\s+{\s+text: 'Specs',\s+items: )\[[\s\S]*?\],/,
  `$1[${context}],`,
)

fs.writeFileSync(configPath, config, 'utf-8')

child_process.spawnSync('bun', ['run', 'check'])

console.log(`✓ Generated ${items.length} spec items in \`vocs.config.tsx\``)
