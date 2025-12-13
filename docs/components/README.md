# Animated Diagram Components

This directory contains the animated diagram system for creating interactive, animated SVG diagrams from Figma exports.

## Quick Reference

### Files

- **`AnimatedDiagram.tsx`** - Core reusable component for any animated SVG
- **`StablecoinMintBurnDiagram.tsx`** - Example implementation for stablecoin flows
- **`ANIMATED_DIAGRAM_GUIDE.md`** - Complete guide with examples and best practices

### Usage

1. Export SVG from Figma → Save to `/docs/public/learn/your-diagram.svg`
2. Create component → `/docs/components/YourDiagram.tsx`
3. Configure animation → Map CSS selectors to animation steps
4. Embed in page → Import in `.mdx` file

### Example

```tsx
import { AnimatedDiagram } from './AnimatedDiagram'

export function YourDiagram() {
  return (
    <AnimatedDiagram
      src="/learn/your-diagram.svg"
      alt="Your diagram description"
      steps={[
        { id: 'step1', elements: ['path[stroke="#0090FF"]'], duration: 2500 },
        { id: 'step2', elements: ['rect[fill="#30A46C"]'], duration: 2500 },
      ]}
      staticElements={['g[clip-path*="clip0"]', 'g[clip-path*="clip1"]']}
      autoPlay={false}
    />
  )
}
```

See `ANIMATED_DIAGRAM_GUIDE.md` for complete documentation.

