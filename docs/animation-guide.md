# Animated Diagram System

A generalizable React component system for creating animated, theme-aware, zoomable SVG diagrams with sequential flow animations. Designed for Figma-exported SVGs with minimal markup requirements.

## Features

- ✨ **Sequential animation**: Flow indicators appear one at a time
- 🎨 **Theme-aware**: Automatically adapts to light/dark mode using `@porto/ui` colors
- 🔍 **Zoomable**: Click to zoom with lightbox overlay
- 🔄 **Replay control**: Restart animation at any time
- ⌨️ **Keyboard accessible**: ESC to close, Enter/Space to zoom
- 📱 **Responsive**: Works on all screen sizes
- 🎯 **Figma-friendly**: Works with raw Figma SVG exports

## Quick Start (Figma Workflow)

### 1. Export SVG from Figma

1. Design your diagram in Figma with static entities (boxes, icons) and flow indicators (arrows, numbers)
2. Use `@porto/ui` colors from your design system
3. Export as SVG: Right-click → "Copy/Paste as" → "Copy as SVG"
4. Save to `docs/public/learn/your-diagram.svg`

**No special attributes needed!** The system works with raw Figma exports.

### 2. Inspect the SVG Structure

Open the SVG file and identify the elements:

**Static entities** (should be visible from start):
- Look for `<g clip-path="url(#clipX)">` groups - these are usually entity boxes
- Note their clip-path identifiers (e.g., `clip0`, `clip1`, `clip2`)

**Flow indicators** (animate in sequence):
- Arrows: `<path>` elements with specific `d` attributes
- Numbers: `<circle>` or `<rect>` elements near arrows
- Text: `<text>` elements with descriptions
- Look for common attributes like `fill`, `stroke`, position attributes

### 3. Create Your Component

```tsx
import { AnimatedDiagram } from './AnimatedDiagram'

export function YourDiagram() {
  // Static entities - identify by clip-path groups
  const staticElements = [
    'g[clip-path*="clip0"]',  // First entity box
    'g[clip-path*="clip1"]',  // Second entity box
    'g[clip-path*="clip2"]',  // Third entity box
    // Add more as needed
  ]

  // Flow steps - identify by unique attributes
  const steps = [
    {
      id: 'step1',
      elements: [
        'path[d*="unique-path-data"]',      // Arrow path
        'rect[x="100"][y="200"]',           // Number badge
        'text[fill="#0090FF"]',             // Description text
      ],
      duration: 2500,
    },
    // Add more steps
  ]

  return (
    <AnimatedDiagram
      src="/learn/your-diagram.svg"
      alt="Your diagram description"
      steps={steps}
      staticElements={staticElements}
      autoPlay={false}  // User clicks replay to start
    />
  )
}
```

### 4. Embed in Your Page

```mdx
import { YourDiagram } from "../../components/YourDiagram.tsx"

## Your Section

Here's how the process works:

<YourDiagram />
```

## Finding Element Selectors

Since Figma SVGs don't have custom `data-` attributes, use CSS attribute selectors:

### By Position/Size
```tsx
'rect[x="96"][y="86"]'           // Specific rectangle
'rect[width="250"][height="201"]' // By dimensions
```

### By Style
```tsx
'path[stroke="#0090FF"]'         // Blue paths (flow arrows)
'rect[fill="#E3F3E8"]'           // Green backgrounds
'text[fill="#E5484D"]'           // Red text
```

### By Content (partial match)
```tsx
'path[d*="M 100,100"]'           // Path starting at specific point
'g[clip-path*="clip0"]'          // Groups with clip-path containing "clip0"
```

### By Structure
```tsx
'svg > g:nth-child(3)'           // Third group in SVG
'g[clip-path] path'              // All paths inside clip-path groups
```

## Real Example: Stablecoin Diagram

Here's the actual implementation from `StablecoinMintBurnDiagram.tsx`:

```tsx
export function StablecoinMintBurnDiagram() {
  // The 4 entity boxes (Company, Reserves, Stablecoin, Smart Contract)
  const staticElements = [
    'g[clip-path*="clip0"]',
    'g[clip-path*="clip1"]',
    'g[clip-path*="clip2"]',
    'g[clip-path*="clip3"]',
  ]

  const steps = [
    {
      id: 'mint-flow',
      elements: [
        'path[d*="676.237 249.237"]',  // Green arrow path
        'rect[x="476.5"][y="221.5"]',  // Number circle
        'text[fill="#30A46C"]',        // Green mint text
      ],
      duration: 2500,
    },
    {
      id: 'burn-flow',
      elements: [
        'rect[fill="#FCD8DA"]',  // Red background
        'path[stroke="#E5484D"]', // Red flame icon
        'text[fill="#E5484D"]',  // "burn" text
      ],
      duration: 2500,
    },
    {
      id: 'issue-flow',
      elements: [
        'rect[fill="#E3F3E8"]',  // Green background
        'path[stroke="#30A46C"]', // Green flame
        'text[fill="#30A46C"]',  // "mint" text
      ],
      duration: 3000,
    },
  ]

  return (
    <AnimatedDiagram
      src="/learn/example.svg"
      alt="Stablecoin mint and burn flow diagram"
      steps={steps}
      staticElements={staticElements}
      autoPlay={false}
    />
  )
}
```

## Workflow Tips

### 1. Preview in Browser DevTools

After embedding your component:

1. Run `just docs-dev` to start the dev server
2. Navigate to your page
3. Right-click the SVG → "Inspect Element"
4. Find the elements you want to animate
5. Copy their attribute selectors

### 2. Visual Flow Order

When arrows aren't numbered, infer the order:
- **Left to right**: Typical flow direction
- **Top to bottom**: Secondary flow
- **Circular**: Start at entry point, follow clockwise
- **Parallel flows**: Animate simultaneously by including in same step

### 3. Grouping Elements

If multiple elements should animate together:

```tsx
{
  id: 'complex-step',
  elements: [
    'path[stroke="#0090FF"]',      // Main arrow
    'path[stroke="#0090FF"][d*="arrowhead"]', // Arrow head
    'circle[fill="#0090FF"]',      // Number badge
    'text[fill="#0090FF"]',        // Description
    'rect[fill*="0090FF"]',        // Background highlight
  ],
  duration: 3000,  // Longer for complex steps
}
```

### 4. Testing Selectors

Add console logging to verify selectors match:

```tsx
useEffect(() => {
  if (!containerRef.current) return
  const svg = containerRef.current.querySelector('svg')
  
  steps.forEach(step => {
    step.elements.forEach(selector => {
      const matches = svg?.querySelectorAll(selector)
      console.log(`${selector}: ${matches?.length || 0} matches`)
    })
  })
}, [svgContent])
```

## Theme-Aware SVGs

Replace hardcoded Figma colors with `@porto/ui` CSS variables **before** exporting:

### Color Mapping

| Figma/Hardcoded | Porto UI Variable | Usage |
|----------------|-------------------|-------|
| `#202020` | `var(--color-gray12)` | Dark text, primary |
| `#FCFCFC` | `var(--color-gray1)` | Light backgrounds |
| `#F0F0F0` | `var(--color-gray2)` | Canvas, subtle bg |
| `#E8E8E8` | `var(--color-gray4)` | Borders, dividers |
| `#8D8D8D` | `var(--color-gray8)` | Muted text |
| `#008FF5`, `#0090FF` | `var(--color-blue9)` | Primary actions |
| `#0588F0` | `var(--color-blue10)` | Primary hover |
| `#E2A336` | `var(--color-amber9)` | Warnings |
| `#E5484D` | `var(--color-red9)` | Errors, burns |
| `#30A46C` | `var(--color-green9)` | Success, mints |
| `#FCD8DA` | `var(--color-red3)` | Error backgrounds |
| `#E3F3E8` | `var(--color-green3)` | Success backgrounds |

### Find and Replace in SVG

```bash
# Example: Replace blue colors
sed -i '' 's/#008FF5/var(--color-blue9)/g' your-diagram.svg
sed -i '' 's/#0588F0/var(--color-blue10)/g' your-diagram.svg
```

Or use your editor's find/replace (recommended for visibility).

## Component API

### `AnimatedDiagram` Props

```tsx
interface AnimatedDiagramProps {
  /** Path to SVG file in public directory */
  src: string
  
  /** Accessibility description */
  alt: string
  
  /** Animation steps in order */
  steps: Step[]
  
  /** Start animation on mount (default: true) */
  autoPlay?: boolean
  
  /** Selectors for always-visible elements (default: []) */
  staticElements?: string[]
}

interface Step {
  /** Unique identifier for this step */
  id: string
  
  /** CSS selectors for elements to animate in this step */
  elements: string[]
  
  /** Milliseconds to display before next step */
  duration: number
}
```

### Controls

- **Replay button**: Restarts animation (always visible)
- **Zoom/expand**: Opens lightbox with larger view
- **Close (X)**: Closes lightbox
- **ESC key**: Closes lightbox
- **Click outside**: Closes lightbox

## Animation Behavior

1. **Mount**: Static elements visible at full opacity
2. **Step N**: Flow elements fade in (0 → 1 opacity, 600ms)
3. **Step N+1**: Previous elements dim (1 → 0.35 opacity), new elements appear
4. **Complete**: All steps visible, most recent at full opacity
5. **Replay**: Reset to initial state, restart sequence

## Advanced Patterns

### Conditional Steps

Skip steps based on diagram variant:

```tsx
const steps = [
  baseStep,
  ...(includeOptionalFlow ? [optionalStep] : []),
  finalStep,
]
```

### Variable Duration

Adjust based on complexity:

```tsx
const steps = flows.map((flow, i) => ({
  id: flow.id,
  elements: flow.selectors,
  duration: flow.elements.length * 1000, // More elements = longer
}))
```

### Bidirectional Flows

Show both directions:

```tsx
const steps = [
  { id: 'forward', elements: ['path[id*="forward"]'], duration: 2500 },
  { id: 'backward', elements: ['path[id*="backward"]'], duration: 2500 },
]
```

## Troubleshooting

### Elements not animating

1. **Check selector matches**: Use DevTools to verify `document.querySelectorAll(selector)` returns elements
2. **Escape special characters**: `circle[r="10"]` not `circle[r=10]`
3. **Use partial matches**: `[d*="substring"]` instead of exact `d="..."` for long paths

### Static entities animating

1. **Add to staticElements**: Include their selectors
2. **Check selector specificity**: More specific selectors override less specific
3. **Verify no conflicts**: An element shouldn't be in both static and step arrays

### Theme not working

1. **Update SVG**: Replace hardcoded colors with CSS variables
2. **Check variable names**: Must match Porto UI exactly (e.g., `--color-blue9` not `--blue9`)
3. **Test in both modes**: Toggle theme in browser

### Zoom not working

1. **Check imports**: Ensure component is properly imported
2. **Verify click handler**: Button should be outside disabled areas
3. **Z-index conflicts**: Lightbox needs high z-index (default: 50)

### Animation too fast/slow

Adjust `duration` per step:
- Simple arrow: **2000-2500ms**
- Multiple elements: **2500-3000ms**
- Complex step: **3000-3500ms**
- Final step: **3500-4000ms** (pause longer)

## Migration from Static Images

Replace existing `<ZoomableImage>` with animated diagram:

```diff
- import { ZoomableImage } from "../../components/ZoomableImage.tsx"
+ import { YourDiagram } from "../../components/YourDiagram.tsx"

- <ZoomableImage src="/learn/diagram.svg" alt="Diagram" />
+ <YourDiagram />
```

## Best Practices

### Design in Figma

1. **Consistent spacing**: Use 8px grid
2. **Clear visual hierarchy**: Entities prominent, flows secondary
3. **Readable text**: Minimum 14px font size
4. **Accessible colors**: Check contrast ratios
5. **Logical grouping**: Related elements in same frame

### Animation Timing

1. **Not too fast**: Give users time to read (2-3 seconds per step)
2. **Not too slow**: Keep engagement (avoid >4 seconds)
3. **Consistent pace**: Similar duration for similar complexity
4. **Final pause**: Last step slightly longer

### Selectors

1. **Stable attributes**: Prefer `fill`, `stroke` over `d` (path data changes with edits)
2. **Readable**: Use semantic selectors when possible
3. **Comments**: Document why specific selectors were chosen
4. **Fallbacks**: Include multiple selectors per element if needed

### Accessibility

1. **Descriptive alt text**: Explain diagram purpose
2. **Color contrast**: Ensure WCAG AA compliance
3. **Keyboard support**: All interactions keyboard-accessible
4. **Screen readers**: Consider adding ARIA labels

## Examples in the Codebase

- **StablecoinMintBurnDiagram**: Mint and burn process with 3 sequential flows
- **AnimatedDiagram**: Base component (reusable for any SVG)

## Get Started

1. Export SVG from Figma → Save to `/docs/public/learn/`
2. Create component file → `/docs/components/YourDiagram.tsx`
3. Inspect SVG → Identify static elements and flow steps
4. Configure animation → Map selectors to steps
5. Embed in page → Import and use in `.mdx`
6. Test & iterate → Adjust selectors and timing

That's it! No markup needed in the SVG itself.
