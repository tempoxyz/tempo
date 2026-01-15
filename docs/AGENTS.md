# AGENTS.md - Tempo Documentation

## Commands
- `bun run dev` - Start development server
- `bun run build` - Production build with search index
- `bun run check` - Lint and format with Biome (auto-fix)
- `bun run check:types` - TypeScript type checking

## Architecture
Tempo docs site built with [Vocs](https://vocs.dev). Key directories:
- `pages/` - MDX content (structure below)
- `components/` - React components; `components/guides/` for interactive demos
- `snippets/` - Reusable MDX fragments (import into pages to avoid duplication)
- `specs/` - Auto-generated protocol specs (`bun run gen:specs`)

## Content Structure
| Directory | Purpose | Audience |
|-----------|---------|----------|
| `pages/quickstart/` | Network setup, faucet, EVM differences, connection details | New developers onboarding |
| `pages/guide/` | How-to guides with interactive demos (accounts, payments, issuance, exchange) | Developers building apps |
| `pages/sdk/` | SDK references | Developers using SDKs |
| `pages/protocol/` | Protocol specs (TIP-20 tokens, fees, transactions, exchange, blockspace) | Protocol-level understanding |
| `pages/learn/` | Conceptual content about Tempo and stablecoin use cases | Non-technical/evaluators |

Sidebar is defined in `vocs.config.tsx`. New pages must be added there to appear in navigation.

## SDK References
- TypeScript SDK docs: `pages/sdk/typescript/` (server/, prool/); Wagmi/Viem docs are external
- SDK sources:
  - [viem/tempo](https://viem.sh/tempo) - Viem actions
  - [wagmi/tempo](https://wagmi.sh/tempo) - Wagmi hooks, connectors, actions
  - [tempo.ts](https://github.com/tempoxyz/tempo-ts) - Server utilities, prool
  - [tempo-go](https://github.com/tempoxyz/tempo-go) - Go SDK
  - [tempo-alloy](https://github.com/tempoxyz/tempo/tree/main/crates/tempo-alloy) - Rust/Alloy crate (in monorepo)
  - [tempo-std](https://github.com/tempoxyz/tempo-std) - Foundry standard library

## Interactive Demos
Use `Demo.Container` + `Step.*` components for interactive guides:
```tsx
import * as Demo from '../../../components/guides/Demo.tsx'
import * as Step from '../../../components/guides/steps'
<Demo.Container name="Demo Name" footerVariant="source" src="tempoxyz/tempo-ts/...">
  <Step.Connect stepNumber={1} />
  <Step.AddFunds stepNumber={2} />
  <Step.YourStep stepNumber={3} last />
</Demo.Container>
```
Steps are in `components/guides/steps/`. Use `DemoContext` for cross-step state.

## Snippets
Reusable MDX in `snippets/`. Import and use directly:
```tsx
import TempoTxProperties from '../../../snippets/tempo-tx-properties.mdx'
<TempoTxProperties />
```

## Code Style
- Biome: single quotes, no semicolons, 2-space indent
- Strict TypeScript (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`)
- CVA for component variants; auto-import for `components/` and Lucide icons

## Documentation Style
Follow `style-guide.md`: active voice, present tense, sentence case headings, no Latin abbreviations, Oxford comma. Use `code font` for API objects.

## Adding a New Guide
1. Copy `pages/guide/_template.mdx` as a starting point
2. Update placeholder content with your guide's title, description, steps, and examples
3. Follow the template structure: intro + demo, steps section with code examples, recipes, best practices, learning resources
4. For multi-step guides, use `Step.*` components and code-group for showing side-by-side examples
5. Run `bun run dev` to verify, then `bun run check` before committing

## Adding a New Page
1. Create `.mdx` file in appropriate `pages/` subdirectory (match URL path to file path)
2. **Add SEO frontmatter** at the top of the file (required):
   ```yaml
   ---
   title: Page Title Here
   description: A concise 150-160 character description for search engines and social sharing.
   ---
   ```
   - **title**: Concise, descriptive page title (used in `<title>` and OG tags)
   - **description**: 150-160 characters, active voice, describes what the page covers
3. Add entry to sidebar in `vocs.config.tsx`
4. Run `bun run dev` to verify, then `bun run check` before committing

## SEO Configuration
- **Dynamic OG images**: Generated via `/api/og.tsx` using title and description from frontmatter
- **Config**: `vocs.config.tsx` sets `baseUrl`, `ogImageUrl` (with `%title` and `%description` template variables), and `titleTemplate`
- All pages automatically get proper `<title>`, `<meta description>`, Open Graph, and Twitter Card tags from frontmatter

## Generated Content (Do Not Edit)
- `specs/` - Regenerate with `bun run gen:specs`; do not hand-edit
- Files with "generated" headers - Edit the source/generator instead

## Icons
Use `~icons/lucide/<name>` imports (via unplugin-icons):
```tsx
import LucideCheck from '~icons/lucide/check'
```

## Key Patterns
- Find a page: search route in `vocs.config.tsx` → open corresponding `pages/` file
- Add demo step: create component in `components/guides/steps/`, export from `index.ts`
- Prefer copying existing patterns over inventing new structures
