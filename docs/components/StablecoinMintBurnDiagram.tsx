import { AnimatedDiagram } from './AnimatedDiagram'

/**
 * Animated stablecoin mint and burn flow diagram exported from Figma.
 *
 * The SVG has 4 main entities and numbered flow steps.
 *
 * ## Easy Customization Guide
 *
 * ### Adding New Steps
 * 1. In Figma, give your element an ID (e.g., "2.5a-draw" for a step between 2 and 3)
 * 2. Add a step object below with:
 *    - `elements: ['#2.5a-draw']` (use ID as-is, dots/special chars work!)
 *    - `duration: 1200` (milliseconds - adjust for pacing)
 *    - `focus: { x: 862, y: 365 }` (SVG coordinates - center of element)
 *
 * ### Timing Steps
 * - Quick transitions: 1000-1500ms
 * - Normal steps: 2000-2500ms
 * - Complex steps: 2500-3000ms
 *
 * ### Focus Points (Camera Position)
 * Find x,y coordinates by inspecting SVG element positions:
 * - Open example.svg, find your element's x/y or path coordinates
 * - Use midpoint of the element for best framing
 * - SVG canvas: 1710x946
 *
 * ### Path Animations
 * For moving elements along paths, create SEPARATE trajectory paths in Figma:
 * - Don't use arrow paths directly (includes arrowhead geometry)
 * - Create a simple line path that follows the desired trajectory
 * - Give it an ID like "path_4a-trajectory"
 * - Use in pathAnimations: `path: '#path_4a-trajectory'`
 */
export function StablecoinMintBurnDiagram() {
  // Static entities - these should always be visible
  const staticElements = [
    '#company', // Company entity (left)
    '#reserves', // Reserves entity (right)
    '#issuer', // Stablecoin issuer entity (middle)
    '#contract', // Smart Contract entity (bottom)
  ]

  // Flow steps - animate each numbered flow in sequence
  // Focus points define where the camera should zoom/pan to for each step
  const steps = [
    {
      id: 'step-1a',
      // Step 1A: Company sends USD to issuer
      elements: ['#1a'],
      duration: 2500,
      focus: { x: 500, y: 280 }, // Center on Company → Issuer arrow
    },
    {
      id: 'step-2a',
      // Step 2A: Issuer deposits USD in reserves
      elements: ['#2a'],
      duration: 2500,
      focus: { x: 1050, y: 300 }, // Center on Issuer → Reserves arrow
    },
    {
      id: 'step-2.5a',
      // Step 2.5A: Draw connection from Issuer to Contract (short transition)
      elements: ['#2.5a-draw'], // Yellow dashed line from issuer to contract
      duration: 1500, // Match the drawStroke duration for progress bar sync
      focus: { x: 862, y: 365 }, // Center on the vertical line between issuer and contract
      pathAnimations: [
        {
          element: '#2.5a-draw',
          drawStroke: true, // Animate the line drawing from top to bottom
          duration: 1500, // Same as step duration
        },
      ],
    },
    {
      id: 'step-3a',
      // Step 3A: Issuer mints stablecoins
      // The move-1a coin animates along path-1a, ending at (461, 695) - same as move-1b start
      elements: ['#3a', '#move-1a', '#2.5a-draw'], // Keep yellow line visible
      duration: 2500,
      focus: { x: 700, y: 550 }, // Center on minting area
      pathAnimations: [
        {
          element: '#move-1a',
          path: '#path-1a',
          duration: 2000,
          snapToElement: '#move-1b', // Snap to move-1b's exact position after path completes
          hideOnNextStep: true, // Hide instantly when step 4a starts (move-1b will be on top)
        },
      ],
    },
    {
      id: 'step-4a',
      // Step 4A: Issuer sends stablecoins to company
      // move-1b appears exactly where move-1a was (461, 695) - seamless handoff
      // move-1a is hidden instantly as move-1b appears on top
      elements: ['#4a', '#move-1b', '#2.5a-draw'],
      instantElements: ['#move-1b'], // Appear instantly (no fade) for seamless handoff from move-1a
      duration: 3000,
      focus: { x: 400, y: 520 }, // Lower focus to show the description text
      pathAnimations: [
        {
          element: '#move-1b',
          path: '#path-1b',
          duration: 2500,
        },
      ],
    },
  ]

  return (
    <AnimatedDiagram
      src="/learn/example.svg"
      alt="Stablecoin mint and burn flow diagram showing how users deposit funds, stablecoins are minted and burned, and how reserves are managed through smart contracts"
      steps={steps}
      staticElements={staticElements}
      autoPlay={true}
    />
  )
}
