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
| `pages/sdk/` | SDK references (typescript/wagmi, server, prool; also go, rust, foundry) | Developers using SDKs |
| `pages/protocol/` | Protocol specs (TIP-20 tokens, fees, transactions, exchange, blockspace) | Protocol-level understanding |
| `pages/learn/` | Conceptual content about Tempo and stablecoin use cases | Non-technical/evaluators |

Sidebar is defined in `vocs.config.tsx`. New pages must be added there to appear in navigation.

## SDK References
- TypeScript SDK docs: `pages/sdk/typescript/` (wagmi/, server/, prool/)
- SDK source: [tempo.ts](https://github.com/tempoxyz/tempo-ts) package

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
import WriteParameters from '../../../snippets/write-parameters.mdx'
<WriteParameters wagmi />
```

## Code Style
- Biome: single quotes, no semicolons, 2-space indent
- Strict TypeScript (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`)
- CVA for component variants; auto-import for `components/` and Lucide icons

## Documentation Style
Follow `style-guide.md`: active voice, present tense, sentence case headings, no Latin abbreviations, Oxford comma. Use `code font` for API objects.

## Adding a New Page
1. Create `.mdx` file in appropriate `pages/` subdirectory (match URL path to file path)
2. Add entry to sidebar in `vocs.config.tsx`
3. Run `bun run dev` to verify, then `bun run check` before committing

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
