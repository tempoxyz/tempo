import { useEffect, useMemo, useRef, useState } from 'react'

interface PathAnimation {
  /** Selector for the element to move */
  element: string
  /** Selector for the path to follow (optional - use if following SVG path) */
  path?: string
  /** Explicit end position {x, y} (optional - use for direct movement) */
  endPosition?: { x: number; y: number }
  /** Duration of the path animation in ms (defaults to step duration) */
  duration?: number
  /** If true, hide this element instantly when the next step starts */
  hideOnNextStep?: boolean
  /** If true, animate stroke drawing from start to end (for lines/paths) */
  drawStroke?: boolean
  /** If true, fade out element after path animation completes */
  fadeOutAfterPath?: boolean
  /** Selector for element to snap to after path animation (ensures perfect alignment) */
  snapToElement?: string
}

interface Step {
  id: string
  /**
   * CSS selectors or element indices for this step's flow indicators.
   * Since SVGs come from Figma, use clip-path groups or nth-child selectors:
   * - 'g[clip-path*="clip5"]' - Selects group with clip-path url(#clip5)
   * - 'g:nth-child(6)' - Selects 6th group element
   * - Multiple selectors will all animate together
   */
  elements: string[]
  /**
   * Elements that should appear instantly (no fade transition).
   * Useful for seamless handoffs between animated elements.
   */
  instantElements?: string[]
  duration: number // ms to display before next step
  /**
   * Optional path animations - elements that move along a path during this step
   */
  pathAnimations?: PathAnimation[]
  /**
   * Optional focus point for camera zoom/pan (SVG coordinates)
   * If provided, the diagram will zoom and pan to center on this point
   */
  focus?: { x: number; y: number }
}

interface AnimatedDiagramProps {
  src: string
  alt: string
  steps: Step[]
  autoPlay?: boolean
  /**
   * CSS selectors for static entities (visible from start).
   * For Figma exports, typically the first few clip-path groups are entities.
   * Leave empty to auto-detect: first 4 groups are usually static.
   */
  staticElements?: string[]
  /**
   * Optional title to display above the diagram
   */
  title?: string
}

// Camera constants
const SVG_WIDTH = 1710
const SVG_HEIGHT = 946
const ZOOM_SCALE = 1.25 // 125% zoom (desktop)
const MOBILE_ZOOM_SCALE = 2.4 // 220% zoom (mobile) - balanced to show detail while keeping text readable

// Calculate clamped pan values to never show empty space
function calculatePan(focusX: number, focusY: number, scale: number, isMobileView = false) {
  if (scale === 1) {
    return { x: 0, y: 0 }
  }
  
  // Calculate the visible area in SVG coordinates
  const visibleWidth = SVG_WIDTH / scale
  const visibleHeight = SVG_HEIGHT / scale
  
  // The overflow (extra content beyond viewport) divided by 2 gives max pan distance
  const overflowX = (SVG_WIDTH - visibleWidth) / 2
  const overflowY = (SVG_HEIGHT - visibleHeight) / 2
  
  // Calculate desired pan to center the focus point
  const centerX = SVG_WIDTH / 2
  const centerY = SVG_HEIGHT / 2
  
  // How much we want to shift to center the focus
  let panX = (focusX - centerX)
  let panY = (focusY - centerY)
  
  // Be more conservative on mobile to prevent showing background
  const safetyFactor = isMobileView ? 0.50 : 0.60
  const safeOverflowX = overflowX * safetyFactor
  const safeOverflowY = overflowY * safetyFactor
  
  panX = Math.max(-safeOverflowX, Math.min(safeOverflowX, panX))
  panY = Math.max(-safeOverflowY, Math.min(safeOverflowY, panY))
  
  return { x: panX, y: panY }
}

export function AnimatedDiagram(props: AnimatedDiagramProps) {
  const { src, alt, steps, autoPlay = true, staticElements = [], title } = props
  const [isZoomed, setIsZoomed] = useState(false)
  const [lightboxTab, setLightboxTab] = useState<'static' | 'animated'>('static')
  const prevLightboxTabRef = useRef<'static' | 'animated'>('static')
  const [currentStep, setCurrentStep] = useState(-1) // Start at -1, will animate to 0
  const [isPlaying, setIsPlaying] = useState(false)
  const [svgContent, setSvgContent] = useState<string>('')
  const [cleanSvgContent, setCleanSvgContent] = useState<string>('') // Unmodified SVG for static view
  const [showAllSteps, setShowAllSteps] = useState(false)
  const [isInitialized, setIsInitialized] = useState(false)
  const [aspectRatio, setAspectRatio] = useState<number>(1710 / 946) // Default to SVG dimensions
  const [isInView, setIsInView] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [totalProgress, setTotalProgress] = useState(0) // 0-100, cumulative progress across all steps
  const [isDarkMode, setIsDarkMode] = useState(false) // Theme detection for smart invert
  const [hasStarted, setHasStarted] = useState(false) // Track if animation has ever started
  
  // Camera state - scale and pan
  const [camera, setCamera] = useState({ scale: 1, x: 0, y: 0 })
  const [isMobile, setIsMobile] = useState(false)
  const [isDragging, setIsDragging] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  const [userZoom, setUserZoom] = useState<number | null>(null) // User-controlled zoom (null = auto)
  
  const containerRef = useRef<HTMLDivElement>(null)
  const svgWrapperRef = useRef<HTMLDivElement>(null)
  const zoomedContainerRef = useRef<HTMLDivElement>(null)
  const wrapperRef = useRef<HTMLDivElement>(null)
  const timeoutRef = useRef<NodeJS.Timeout | undefined>(undefined)
  const finalTimeoutRef = useRef<NodeJS.Timeout | undefined>(undefined)
  const initializedRef = useRef(false)
  const isReplayingRef = useRef(false)
  const hasStartedRef = useRef(false) // Track if animation has started (for in-view trigger)
  const pathAnimationFrameRef = useRef<number | undefined>(undefined)
  const lastTapRef = useRef<number>(0)
  const pathAnimationStartPositions = useRef<Map<string, { x: number; y: number }>>(new Map())
  const pathAnimationFinalTransforms = useRef<Map<string, string>>(new Map())
  const stepStartTimeRef = useRef<number>(0)
  const stepElapsedRef = useRef<number>(0) // Track elapsed time when paused
  const animationStartTimeRef = useRef<number>(0) // When the entire animation started
  const progressAnimationFrameRef = useRef<number | undefined>(undefined)
  const progressPauseTimeRef = useRef<number>(0) // When progress was paused
  const progressPausedDurationRef = useRef<number>(0) // Total time spent paused

  // Helper function to select elements that handles ID selectors with special characters
  const selectElements = (svgElement: SVGSVGElement, selector: string): Element[] => {
    if (selector.startsWith('#')) {
      // Extract the ID (everything after #)
      const id = selector.slice(1)
      // Use attribute selector to handle IDs with dots, colons, etc.
      const element = svgElement.querySelector(`[id="${id}"]`)
      return element ? [element] : []
    }
    return Array.from(svgElement.querySelectorAll(selector))
  }

  // Animate stroke drawing for a path
  const animateStrokeDrawing = (
    svgElement: SVGSVGElement,
    elementSelector: string,
    duration: number,
    onComplete?: () => void
  ) => {
    const elements = selectElements(svgElement, elementSelector)
    
    if (elements.length === 0) {
      onComplete?.()
      return
    }
    
    const element = elements[0] as SVGPathElement
    if (!element.getTotalLength) {
      onComplete?.()
      return
    }
    
    const length = element.getTotalLength()
    
    // Set up for drawing animation
    element.style.strokeDasharray = `${length}`
    element.style.strokeDashoffset = `${length}`
    element.style.opacity = '1'
    
    const startTime = performance.now()
    
    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime
      const progress = Math.min(elapsed / duration, 1)
      
      // Ease-in-out
      const eased = progress < 0.5
        ? 2 * progress * progress
        : 1 - Math.pow(-2 * progress + 2, 2) / 2
      
      // Animate from full offset (hidden) to 0 (fully drawn)
      const offset = length * (1 - eased)
      element.style.strokeDashoffset = `${offset}`
      
      if (progress < 1) {
        pathAnimationFrameRef.current = requestAnimationFrame(animate)
      } else {
        onComplete?.()
      }
    }
    
    pathAnimationFrameRef.current = requestAnimationFrame(animate)
  }

  // Animate an element along a path or to a position
  const animateElement = (
    svgElement: SVGSVGElement,
    elementSelector: string,
    pathSelector: string | undefined,
    endPosition: { x: number; y: number } | undefined,
    duration: number,
    onComplete?: () => void
  ) => {
    const elements = selectElements(svgElement, elementSelector)
    
    if (elements.length === 0) {
      onComplete?.()
      return
    }
    
    const element = elements[0] as SVGGraphicsElement
    const bbox = element.getBBox()
    const elementCenterX = bbox.x + bbox.width / 2
    const elementCenterY = bbox.y + bbox.height / 2
    
    // Store the original position if not already stored
    const posKey = elementSelector
    if (!pathAnimationStartPositions.current.has(posKey)) {
      pathAnimationStartPositions.current.set(posKey, { x: elementCenterX, y: elementCenterY })
    }
    const originalPos = pathAnimationStartPositions.current.get(posKey)!
    
    let getPointAtProgress: (progress: number) => { x: number; y: number }
    
    if (pathSelector) {
      // Follow a path directly using getPointAtLength
      const pathElements = selectElements(svgElement, pathSelector)
      if (pathElements.length === 0) {
        onComplete?.()
        return
      }
      
      const pathElement = pathElements[0] as SVGPathElement
      if (!pathElement.getTotalLength) {
        onComplete?.()
        return
      }
      
      const totalLength = pathElement.getTotalLength()
      
      // Simple: just follow the path from start to end
      getPointAtProgress = (progress: number) => {
        const pt = pathElement.getPointAtLength(progress * totalLength)
        return { x: pt.x, y: pt.y }
      }
    } else if (endPosition) {
      // Move to explicit end position
      getPointAtProgress = (progress: number) => {
        return {
          x: originalPos.x + (endPosition.x - originalPos.x) * progress,
          y: originalPos.y + (endPosition.y - originalPos.y) * progress,
        }
      }
    } else {
      onComplete?.()
      return
    }
    
    const startTime = performance.now()
    
    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime
      const progress = Math.min(elapsed / duration, 1)
      
      // Ease-in-out function
      const eased = progress < 0.5
        ? 2 * progress * progress
        : 1 - Math.pow(-2 * progress + 2, 2) / 2
      
      // Get position at this progress
      const pos = getPointAtProgress(eased)
      
      // Calculate translation from original position
      const translateX = pos.x - originalPos.x
      const translateY = pos.y - originalPos.y
      
      // Apply transform
      const transformValue = `translate(${translateX}px, ${translateY}px)`
      element.style.transform = transformValue
      
      if (progress < 1) {
        pathAnimationFrameRef.current = requestAnimationFrame(animate)
      } else {
        // Store the final transform for later restoration
        pathAnimationFinalTransforms.current.set(elementSelector, transformValue)
        onComplete?.()
      }
    }
    
    pathAnimationFrameRef.current = requestAnimationFrame(animate)
  }

  // Reset path animation for an element
  const resetPathAnimation = (svgElement: SVGSVGElement, elementSelector: string) => {
    const elements = selectElements(svgElement, elementSelector)
    if (elements.length > 0) {
      const element = elements[0] as SVGGraphicsElement
      element.style.transform = ''
    }
    pathAnimationStartPositions.current.delete(elementSelector)
  }

  // Load SVG content and inject font styles
  useEffect(() => {
    // Build CSS selectors for step elements to hide by default
    const stepSelectorsCSS = steps
      .flatMap((step) =>
        step.elements.map((selector) => {
          if (selector.startsWith('#')) {
            const id = selector.slice(1).replace(/\\(.)/g, '$1')
            return `[id="${id}"]`
          }
          return selector
        })
      )
      .join(', ')

    fetch(src)
      .then((res) => res.text())
      .then((text) => {
        // Parse viewBox to set aspect ratio
        const viewBoxMatch = text.match(/viewBox=["']([^"']+)["']/)
        if (viewBoxMatch?.[1]) {
          const parts = viewBoxMatch[1].split(/\s+/).map(Number)
          const w = parts[2]
          const h = parts[3]
          if (w && h && !Number.isNaN(w) && !Number.isNaN(h)) {
            setAspectRatio(w / h)
          }
        }
        
        // Inject font styles AND default hidden state for step elements
        // No color replacements needed - we use CSS filter for dark mode
        const styles = `<style>
          @import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&amp;family=Geist+Mono:wght@400;500;600;700&amp;display=swap');
          text[font-family="Geist"] { font-family: 'Geist', -apple-system, BlinkMacSystemFont, sans-serif !important; }
          text[font-family="Geist Mono"] { font-family: 'Geist Mono', 'Monaco', 'Courier New', monospace !important; }
          ${stepSelectorsCSS} { opacity: 0; }
        </style>`
        
        // Save clean version for static lightbox (without hidden state styles)
        const cleanStyles = `<style>
          @import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&amp;family=Geist+Mono:wght@400;500;600;700&amp;display=swap');
          text[font-family="Geist"] { font-family: 'Geist', -apple-system, BlinkMacSystemFont, sans-serif !important; }
          text[font-family="Geist Mono"] { font-family: 'Geist Mono', 'Monaco', 'Courier New', monospace !important; }
        </style>`
        const cleanText = text.replace(/<svg([^>]*)>/, `<svg$1>${cleanStyles}`)
        setCleanSvgContent(cleanText)
        
        // Insert the style tag (with hidden state) after the opening <svg> tag
        const modifiedText = text.replace(/<svg([^>]*)>/, `<svg$1>${styles}`)
        setSvgContent(modifiedText)
      })
      .catch((err) => console.error('Failed to load SVG:', err))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [src])

  // IntersectionObserver to start animation when approaching middle of viewport
  useEffect(() => {
    const element = wrapperRef.current
    if (!element || isInView) return // Already triggered
    
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setIsInView(true)
            observer.disconnect() // Only need to trigger once
          }
        })
      },
      { 
        threshold: 0.1,
        rootMargin: '-25% 0px -25% 0px' // Trigger when element enters middle 50% of viewport
      }
    )
    
    observer.observe(element)
    
    return () => observer.disconnect()
  }, [isInView])

  // Auto-play when switching to animated tab in lightbox
  useEffect(() => {
    if (isZoomed && lightboxTab === 'animated' && prevLightboxTabRef.current === 'static') {
      // Switched to animated tab - restart animation
      setIsPaused(false)
      if (!isPlaying) {
        handleReplay()
      }
    }
    prevLightboxTabRef.current = lightboxTab
  }, [lightboxTab, isZoomed])

  // Calculate total animation duration
  const totalDuration = useMemo(() => {
    const baseDuration = steps.reduce((acc, step) => acc + step.duration + 1500, 0)
    return baseDuration + 1750 // Add final pause
  }, [steps])

  // Continuous progress bar animation
  useEffect(() => {
    if (!isPlaying || currentStep < 0) {
      if (progressAnimationFrameRef.current) {
        cancelAnimationFrame(progressAnimationFrameRef.current)
      }
      return
    }
    
    // Handle pause - record when we paused
    if (isPaused) {
      if (progressAnimationFrameRef.current) {
        cancelAnimationFrame(progressAnimationFrameRef.current)
      }
      if (!progressPauseTimeRef.current) {
        progressPauseTimeRef.current = Date.now()
      }
      return
    }
    
    // Handle resume - add pause duration to total
    if (progressPauseTimeRef.current) {
      progressPausedDurationRef.current += Date.now() - progressPauseTimeRef.current
      progressPauseTimeRef.current = 0
    }

    if (currentStep === 0 && !animationStartTimeRef.current) {
      animationStartTimeRef.current = Date.now()
    }

    const animateProgress = () => {
      const now = Date.now()
      // Subtract total paused duration from elapsed time
      const elapsed = now - animationStartTimeRef.current - progressPausedDurationRef.current
      const progress = Math.min((elapsed / totalDuration) * 100, 100)
      setTotalProgress(progress)

      if (progress < 100) {
        progressAnimationFrameRef.current = requestAnimationFrame(animateProgress)
      } else {
        setTotalProgress(100)
      }
    }

    progressAnimationFrameRef.current = requestAnimationFrame(animateProgress)

    return () => {
      if (progressAnimationFrameRef.current) {
        cancelAnimationFrame(progressAnimationFrameRef.current)
      }
    }
  }, [isPlaying, currentStep, isPaused, totalDuration])

  // Animation timer logic with pause support
  useEffect(() => {
    if (!isPlaying || currentStep < 0 || isPaused) return

    // Get the current step duration (add extra reading time)
    const baseDuration = steps[currentStep]?.duration || 2000
    const stepDuration = baseDuration + 1500 // Add 1.5s extra reading time per step
    const remainingTime = stepDuration - stepElapsedRef.current
    
    // Track when this step started
    stepStartTimeRef.current = Date.now()

    if (currentStep >= steps.length - 1) {
      // On last step, wait for its duration, then show all steps
      timeoutRef.current = setTimeout(() => {
        finalTimeoutRef.current = setTimeout(() => {
          setShowAllSteps(true)
          setIsPlaying(false)
        }, 1750) // 1.75s delay after last step finishes
      }, remainingTime)
      return
    }

    // Normal step: wait for duration then advance
    timeoutRef.current = setTimeout(() => {
      stepElapsedRef.current = 0 // Reset for next step
      setCurrentStep((prev) => prev + 1)
    }, remainingTime)

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
      if (finalTimeoutRef.current) clearTimeout(finalTimeoutRef.current)
    }
  }, [currentStep, isPlaying, isPaused, steps])
  
  // Handle pause - track elapsed time
  useEffect(() => {
    if (isPaused && isPlaying && currentStep >= 0) {
      // Store how much time has elapsed when pausing
      stepElapsedRef.current += Date.now() - stepStartTimeRef.current
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
    }
  }, [isPaused, isPlaying, currentStep])

  // Apply step visibility - takes explicit parameters to avoid closure issues
  const applyStepVisibility = (container: HTMLElement, stepIndex: number, showAll: boolean) => {
    const svgElement = container.querySelector('svg')
    if (!svgElement) return

    // If showAll is true, show all steps at full opacity
    // BUT preserve hideOnNextStep elements as hidden and restore final transforms
    if (showAll) {
      steps.forEach((step) => {
        step.elements.forEach((selector) => {
          const elements = selectElements(svgElement, selector)
          elements.forEach((el) => {
            const htmlEl = el as HTMLElement
            if (!htmlEl.style.transition) {
              htmlEl.style.transition = 'opacity 0.6s ease-in-out'
            }
            htmlEl.style.opacity = '1'
          })
        })
        
        // Handle path animations
        step.pathAnimations?.forEach((pathAnim) => {
          const elements = selectElements(svgElement, pathAnim.element)
          elements.forEach((el) => {
            const htmlEl = el as HTMLElement
            
            if (pathAnim.hideOnNextStep) {
              // Keep elements with hideOnNextStep hidden
              htmlEl.style.opacity = '0'
            } else {
              // Restore final transform position
              const finalTransform = pathAnimationFinalTransforms.current.get(pathAnim.element)
              if (finalTransform) {
                htmlEl.style.transform = finalTransform
              }
            }
          })
        })
      })
      return
    }

    // First, handle hideOnNextStep from PREVIOUS step (hide instantly, same frame)
    if (stepIndex > 0) {
      const prevStep = steps[stepIndex - 1]
      prevStep?.pathAnimations?.forEach((pathAnim) => {
        if (pathAnim.hideOnNextStep) {
          const elements = selectElements(svgElement, pathAnim.element)
          elements.forEach((el) => {
            const htmlEl = el as HTMLElement
            htmlEl.style.transition = 'none'
            htmlEl.style.opacity = '0'
          })
        }
      })
    }
    
    // For each step, set appropriate opacity based on stepIndex
    steps.forEach((step, index) => {
      const targetOpacity = index < stepIndex ? '0.35' : index === stepIndex ? '1' : '0'
      const isCurrentStep = index === stepIndex
      
      step.elements.forEach((selector) => {
        const elements = selectElements(svgElement, selector)
        const isInstant = isCurrentStep && step.instantElements?.includes(selector)
        
        elements.forEach((el) => {
          const htmlEl = el as HTMLElement
          
          if (isInstant) {
            // Instant appearance - no transition (same frame as hideOnNextStep)
            htmlEl.style.transition = 'none'
            htmlEl.style.opacity = targetOpacity
          } else {
            // Normal fade transition
            if (!htmlEl.style.transition) {
              htmlEl.style.transition = 'opacity 0.6s ease-in-out'
            }
            htmlEl.style.opacity = targetOpacity
          }
        })
      })
    })
    
    // Re-enable transitions after the instant changes are applied
    requestAnimationFrame(() => {
      steps.forEach((step) => {
        step.instantElements?.forEach((selector) => {
          const elements = selectElements(svgElement, selector)
          elements.forEach((el) => {
            const htmlEl = el as HTMLElement
            htmlEl.style.transition = 'opacity 0.6s ease-in-out'
          })
        })
      })
    })
  }

  // Initialize SVG on first load
  useEffect(() => {
    if (!containerRef.current || !svgContent || initializedRef.current) return
    
    const svgElement = containerRef.current.querySelector('svg')
    if (!svgElement) return
    
    // Step 1: Set all elements to opacity 0 WITHOUT transition (instant hide)
    staticElements.forEach((selector) => {
      const elements = selectElements(svgElement, selector)
      elements.forEach((el) => {
        const htmlEl = el as HTMLElement
        htmlEl.style.transition = 'none'
        htmlEl.style.opacity = '1'
      })
    })
    
    steps.forEach((step) => {
      step.elements.forEach((selector) => {
        const elements = selectElements(svgElement, selector)
        elements.forEach((el) => {
          const htmlEl = el as HTMLElement
          htmlEl.style.transition = 'none'
          htmlEl.style.opacity = '0'
        })
      })
    })
    
    // Force a reflow to apply the instant opacity changes
    void svgElement.getBoundingClientRect()
    
    // Step 2: Now add transitions to all flow elements
    requestAnimationFrame(() => {
      steps.forEach((step) => {
        step.elements.forEach((selector) => {
          const elements = selectElements(svgElement, selector)
          elements.forEach((el) => {
            const htmlEl = el as HTMLElement
            htmlEl.style.transition = 'opacity 0.6s ease-in-out'
          })
        })
      })
      
      // Force another reflow
      void svgElement.getBoundingClientRect()
      
      // Step 3: Mark as initialized and show container
      requestAnimationFrame(() => {
        initializedRef.current = true
        setIsInitialized(true)
        // Animation will start when isInView becomes true (see separate effect)
      })
    })
  }, [svgContent, steps, staticElements])
  
  // Start animation when in view (after initialization)
  useEffect(() => {
    if (!isInView || !initializedRef.current || hasStartedRef.current || !autoPlay) return
    
    hasStartedRef.current = true
    
    // Start zooming in during the delay
    setTimeout(() => {
      const focus = steps[0]?.focus || { x: SVG_WIDTH / 2, y: SVG_HEIGHT / 2 }
      const zoomScale = isMobile ? MOBILE_ZOOM_SCALE : ZOOM_SCALE
      const pan = calculatePan(focus.x, focus.y, zoomScale, isMobile)
      setCamera({ scale: zoomScale, x: pan.x, y: pan.y })
    }, 300) // Start zoom early
    
    setTimeout(() => {
      stepElapsedRef.current = 0
      setCurrentStep(0)
      setIsPlaying(true)
      setHasStarted(true)
      setIsPaused(false) // Ensure it's not paused on mobile
    }, 2500) // 2.5s delay before starting animation
  }, [isInView, autoPlay, steps, isMobile])

  // Apply step visibility when currentStep or showAllSteps changes
  useEffect(() => {
    if (!containerRef.current || !svgContent || !initializedRef.current || isReplayingRef.current) return
    if (currentStep < 0 && !showAllSteps) return
    applyStepVisibility(containerRef.current, currentStep, showAllSteps)
  }, [currentStep, showAllSteps, svgContent])

  // Update camera pan when step changes (zoom stays constant until showAllSteps)
  useEffect(() => {
    if (!initializedRef.current) return
    
    // Zoom back to 100% when showing all steps
    if (showAllSteps) {
      setCamera({ scale: 1, x: 0, y: 0 })
      return
    }
    
    // Pan to new step's focus point (only for steps 1+, step 0 handled by init)
    if (currentStep > 0 && steps[currentStep]?.focus) {
      const focus = steps[currentStep].focus!
      const zoomScale = isMobile ? MOBILE_ZOOM_SCALE : ZOOM_SCALE
      const pan = calculatePan(focus.x, focus.y, zoomScale, isMobile)
      // Keep scale constant, only update pan
      setCamera(prev => ({ scale: prev.scale, x: pan.x, y: pan.y }))
    }
  }, [currentStep, showAllSteps, steps, isMobile])


  // Handle path animations when step changes
  useEffect(() => {
    if (!containerRef.current || !svgContent || !initializedRef.current || isReplayingRef.current) return
    if (currentStep < 0) return
    
    const svgElement = containerRef.current.querySelector('svg')
    if (!svgElement) return
    
    // Note: hideOnNextStep is now handled in applyStepVisibility for synchronization
    
    const step = steps[currentStep]
    if (!step?.pathAnimations || step.pathAnimations.length === 0) return
    
    // Trigger path animations for this step
    step.pathAnimations.forEach((pathAnim) => {
      const animDuration = pathAnim.duration || step.duration
      
      if (pathAnim.drawStroke) {
        // Animate stroke drawing
        animateStrokeDrawing(svgElement, pathAnim.element, animDuration)
      } else {
        // Animate position/movement
        const onComplete = () => {
          const elements = selectElements(svgElement, pathAnim.element)
          
          // Snap to target element position if specified (ensures perfect alignment)
          if (pathAnim.snapToElement) {
            const targetElements = selectElements(svgElement, pathAnim.snapToElement)
            if (targetElements.length > 0) {
              const targetEl = targetElements[0] as SVGGraphicsElement
              const targetBBox = targetEl.getBBox()
              const targetCenterX = targetBBox.x + targetBBox.width / 2
              const targetCenterY = targetBBox.y + targetBBox.height / 2
              
              // Get original position of animated element
              const originalPos = pathAnimationStartPositions.current.get(pathAnim.element)
              if (originalPos) {
                const translateX = targetCenterX - originalPos.x
                const translateY = targetCenterY - originalPos.y
                
                elements.forEach((el) => {
                  const htmlEl = el as HTMLElement
                  htmlEl.style.transform = `translate(${translateX}px, ${translateY}px)`
                })
              }
            }
          }
          
          // Fade out after path animation completes
          if (pathAnim.fadeOutAfterPath) {
            elements.forEach((el) => {
              const htmlEl = el as HTMLElement
              htmlEl.style.transition = 'opacity 0.5s ease-out'
              htmlEl.style.opacity = '0'
            })
          }
        }
        
        animateElement(svgElement, pathAnim.element, pathAnim.path, pathAnim.endPosition, animDuration, onComplete)
      }
    })
    
    return () => {
      // Cancel any running path animation
      if (pathAnimationFrameRef.current) {
        cancelAnimationFrame(pathAnimationFrameRef.current)
      }
    }
  }, [currentStep, svgContent, steps])

  // Apply step visibility to zoomed container
  useEffect(() => {
    if (!zoomedContainerRef.current || !svgContent || !isZoomed) return
    
    const svgElement = zoomedContainerRef.current.querySelector('svg')
    if (!svgElement) return
    
    // Set up zoomed container with current state
    staticElements.forEach((selector) => {
      const elements = selectElements(svgElement, selector)
      elements.forEach((el) => {
        const htmlEl = el as HTMLElement
        htmlEl.style.transition = 'opacity 0.6s ease-in-out'
        htmlEl.style.opacity = '1'
      })
    })
    
    steps.forEach((step) => {
      step.elements.forEach((selector) => {
        const elements = selectElements(svgElement, selector)
        elements.forEach((el) => {
          const htmlEl = el as HTMLElement
          htmlEl.style.transition = 'opacity 0.6s ease-in-out'
        })
      })
    })
    
    applyStepVisibility(zoomedContainerRef.current, currentStep, showAllSteps)
  }, [currentStep, svgContent, steps, staticElements, isZoomed, showAllSteps])

  const handleSkip = () => {
    // Clear any pending timeouts and animations
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    if (finalTimeoutRef.current) clearTimeout(finalTimeoutRef.current)
    if (pathAnimationFrameRef.current) cancelAnimationFrame(pathAnimationFrameRef.current)
    if (progressAnimationFrameRef.current) cancelAnimationFrame(progressAnimationFrameRef.current)
    
    // Jump to final state
    setIsPlaying(false)
    setShowAllSteps(true)
    setCurrentStep(steps.length - 1)
    setTotalProgress(100)
    
    // Lock progress at 100% by updating ref
    animationStartTimeRef.current = 0
    progressPauseTimeRef.current = 0
    progressPausedDurationRef.current = 0
    
    setCamera({ scale: 1, x: 0, y: 0 })
    setUserZoom(1)
    
    // Reset camera to default (unzoomed)
    setCamera({ scale: 1, x: 0, y: 0 })
  }

  // Start animation manually (when autoPlay didn't trigger)
  const handlePlay = () => {
    if (hasStarted || isPlaying) return
    
    hasStartedRef.current = true
    setHasStarted(true)
    
    // Start zooming in during the delay
    setTimeout(() => {
      const focus = steps[0]?.focus || { x: SVG_WIDTH / 2, y: SVG_HEIGHT / 2 }
      const zoomScale = isMobile ? MOBILE_ZOOM_SCALE : ZOOM_SCALE
      const pan = calculatePan(focus.x, focus.y, zoomScale, isMobile)
      setCamera({ scale: zoomScale, x: pan.x, y: pan.y })
    }, 300)
    
    setTimeout(() => {
      stepElapsedRef.current = 0
      setCurrentStep(0)
      setIsPlaying(true)
    }, 2500)
  }

  // Interactive pan and zoom handlers (when animation is complete)
  const handleMouseDown = (e: React.MouseEvent) => {
    if (!showAllSteps) return
    setIsDragging(true)
    setDragStart({ x: e.clientX, y: e.clientY })
  }

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging || !showAllSteps) return
    
    const deltaX = e.clientX - dragStart.x
    const deltaY = e.clientY - dragStart.y
    
    setCamera(prev => {
      const zoom = userZoom || 1
      const maxPan = 300
      return {
        scale: prev.scale,
        x: Math.max(-maxPan, Math.min(maxPan, prev.x - deltaX / zoom)),
        y: Math.max(-maxPan, Math.min(maxPan, prev.y - deltaY / zoom))
      }
    })
    setDragStart({ x: e.clientX, y: e.clientY })
  }

  const handleMouseUp = () => {
    setIsDragging(false)
  }

  const handleDoubleClick = (e: React.MouseEvent) => {
    if (!showAllSteps) return
    e.stopPropagation()
    
    // Toggle between 100% and 200%
    const newZoom = userZoom === 2 ? 1 : 2
    setUserZoom(newZoom)
    setCamera(prev => ({ ...prev, scale: newZoom }))
  }

  const handleTouchStart = (e: React.TouchEvent) => {
    if (!showAllSteps) return
    
    // Check for double-tap
    const now = Date.now()
    if (now - lastTapRef.current < 300) {
      // Double tap detected - toggle zoom
      const newZoom = userZoom === 2 ? 1 : 2
      setUserZoom(newZoom)
      setCamera(prev => ({ ...prev, scale: newZoom }))
      lastTapRef.current = 0
      return
    }
    lastTapRef.current = now
    
    if (e.touches.length === 1) {
      setIsDragging(true)
      setDragStart({ 
        x: e.touches[0]?.clientX || 0, 
        y: e.touches[0]?.clientY || 0 
      })
    }
  }

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!isDragging || !showAllSteps || e.touches.length !== 1) return
    
    const touch = e.touches[0]
    if (!touch) return
    
    const deltaX = touch.clientX - dragStart.x
    const deltaY = touch.clientY - dragStart.y
    
    setCamera(prev => {
      const zoom = userZoom || 1
      const maxPan = 300
      return {
        scale: prev.scale,
        x: Math.max(-maxPan, Math.min(maxPan, prev.x - deltaX / zoom)),
        y: Math.max(-maxPan, Math.min(maxPan, prev.y - deltaY / zoom))
      }
    })
    setDragStart({ x: touch.clientX, y: touch.clientY })
  }

  const handleTouchEnd = () => {
    setIsDragging(false)
  }

  const handleReplay = () => {
    // Clear any pending timeouts and animations
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    if (finalTimeoutRef.current) clearTimeout(finalTimeoutRef.current)
    if (pathAnimationFrameRef.current) cancelAnimationFrame(pathAnimationFrameRef.current)
    if (progressAnimationFrameRef.current) cancelAnimationFrame(progressAnimationFrameRef.current)
    
    // Set replay flag to prevent useEffect interference
    isReplayingRef.current = true
    
    // Stop playing and reset state
    setIsPlaying(false)
    setShowAllSteps(false)
    setCurrentStep(-1)
    setTotalProgress(0)
    stepElapsedRef.current = 0
    animationStartTimeRef.current = 0
    progressPauseTimeRef.current = 0
    progressPausedDurationRef.current = 0
    setUserZoom(null) // Reset user zoom
    
    // Reset camera to default
    setCamera({ scale: 1, x: 0, y: 0 })
    
    // Use RAF to ensure React has processed the state updates
    requestAnimationFrame(() => {
      if (!containerRef.current) return
      
      const svgElement = containerRef.current.querySelector('svg')
      if (!svgElement) return
      
      // Hide all flow elements instantly (no transition) and reset path animations
      steps.forEach((step) => {
        step.elements.forEach((selector) => {
          const elements = selectElements(svgElement, selector)
          elements.forEach((el) => {
            const htmlEl = el as HTMLElement
            htmlEl.style.transition = 'none'
            htmlEl.style.opacity = '0'
          })
        })
        
        // Reset any path animation transforms
        step.pathAnimations?.forEach((pathAnim) => {
          resetPathAnimation(svgElement, pathAnim.element)
        })
      })
      
      // Clear stored positions and transforms
      pathAnimationStartPositions.current.clear()
      pathAnimationFinalTransforms.current.clear()
      
      // Force a reflow
      void svgElement.getBoundingClientRect()
      
      // Re-enable transitions
      requestAnimationFrame(() => {
        steps.forEach((step) => {
          step.elements.forEach((selector) => {
            const elements = selectElements(svgElement, selector)
            elements.forEach((el) => {
              const htmlEl = el as HTMLElement
              htmlEl.style.transition = 'opacity 0.6s ease-in-out'
            })
          })
        })
        
        // Force another reflow
        void svgElement.getBoundingClientRect()
        
        // Start zooming in during the delay
        setTimeout(() => {
          const focus = steps[0]?.focus || { x: SVG_WIDTH / 2, y: SVG_HEIGHT / 2 }
          const pan = calculatePan(focus.x, focus.y, ZOOM_SCALE)
          setCamera({ scale: ZOOM_SCALE, x: pan.x, y: pan.y })
        }, 300) // Start zoom early
        
        // Start playing from step 0 (with delay)
        setTimeout(() => {
          isReplayingRef.current = false
          setCurrentStep(0)
          setIsPlaying(true)
          setHasStarted(true)
        }, 2500) // 2.5s delay before starting animation
      })
    })
  }

  const handleDownload = () => {
    if (!svgContent) return
    const blob = new Blob([svgContent], { type: 'image/svg+xml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = alt.replace(/[^a-z0-9]/gi, '-').toLowerCase() + '.svg'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleOpen = () => {
    setIsZoomed(true)
    setLightboxTab('static')
  }
  const handleClose = () => {
    setIsZoomed(false)
    setLightboxTab('static')
  }

  // Keyboard handling for lightbox
  useEffect(() => {
    if (!isZoomed) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') handleClose()
    }

    document.addEventListener('keydown', handleKeyDown)
    document.body.style.overflow = 'hidden'

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = ''
    }
  }, [isZoomed])

  // Memoize SVG content element to prevent re-creation on camera state changes
  // Dark mode filter is applied via className based on isDarkMode state
  const svgContentElement = useMemo(
    () => (
      <div
        // biome-ignore lint/security/noDangerouslySetInnerHtml: SVG content is loaded from static assets
        dangerouslySetInnerHTML={{ __html: svgContent }}
        style={{
          width: '100%',
          height: isMobile ? '100%' : 'auto',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
        }}
        className={`${
          isMobile 
            ? '[&>svg]:!w-auto [&>svg]:!h-full [&>svg]:max-h-full [&>svg]:min-h-full' 
            : '[&>svg]:max-w-full [&>svg]:h-auto'
        } [&>svg]:rounded-lg [&>svg]:transition-[filter] [&>svg]:duration-200 ${
          isDarkMode ? '[&>svg]:[filter:invert(0.88)_hue-rotate(180deg)]' : ''
        }`}
      />
    ),
    [svgContent, isDarkMode, isMobile]
  )
  
  // Detect dark mode from Vocs (uses .dark class on html element)
  useEffect(() => {
    const checkDarkMode = () => {
      setIsDarkMode(document.documentElement.classList.contains('dark'))
    }
    
    // Initial check
    checkDarkMode()
    
    // Watch for class changes on <html> (Vocs theme toggle)
    const observer = new MutationObserver(checkDarkMode)
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    })
    
    return () => {
      observer.disconnect()
    }
  }, [])

  // Detect mobile viewport
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768)
    }
    
    checkMobile()
    window.addEventListener('resize', checkMobile)
    
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  // Pause icon
  const PauseIcon = () => (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
    >
      <rect x="6" y="4" width="4" height="16" rx="1" />
      <rect x="14" y="4" width="4" height="16" rx="1" />
    </svg>
  )

  // Determine if we should render the animation in the main view or lightbox
  const showAnimationInMain = !isZoomed || (isZoomed && lightboxTab === 'static')

  return (
    <>
      {/* Title */}
      {title && (
        <h2 id={title.toLowerCase().replace(/\s+/g, '-')} className="vocs_H2 mb-6 font-medium">{title}</h2>
      )}
      
      {/* Main inline component */}
      <div 
        ref={wrapperRef}
        className={`${isMobile ? 'rounded-none border-x-0 border-y -mx-6' : 'rounded-xl border'} border-gray4 bg-[var(--vocs-color_codeBlockBackground)] overflow-hidden relative`}
        style={{ 
          visibility: isZoomed && lightboxTab === 'animated' ? 'hidden' : 'visible',
          pointerEvents: isZoomed ? 'none' : 'auto'
        }}
      >
        {showAnimationInMain && (
          /* Diagram with camera wrapper */
          <div 
            className="relative overflow-hidden flex items-center justify-center"
            onMouseEnter={() => !isZoomed && !isMobile && setIsPaused(true)}
            onMouseLeave={() => !isZoomed && !isMobile && setIsPaused(false)}
            style={{ 
              aspectRatio: isMobile ? undefined : `${aspectRatio}`,
              height: isMobile ? '65vh' : 'auto',
              padding: isMobile ? '8px' : '16px'
            }}
          >
            {/* Loading shimmer */}
            {!isInitialized && (
              <div className="absolute inset-0 bg-gradient-to-r from-gray3 via-gray4 to-gray3 animate-pulse" />
            )}
            
            <div
              ref={containerRef}
              className={`select-none ${isMobile ? 'w-full h-full flex items-center justify-center' : 'cursor-zoom-in w-full h-full flex items-center justify-center'}`}
              onClick={isMobile && !showAllSteps ? () => setIsPaused(!isPaused) : (!isMobile && !showAllSteps ? handleOpen : undefined)}
              onTouchStart={isMobile && showAllSteps ? handleTouchStart : (isMobile && !showAllSteps ? () => setIsPaused(!isPaused) : undefined)}
              onTouchMove={isMobile && showAllSteps ? handleTouchMove : undefined}
              onTouchEnd={isMobile && showAllSteps ? handleTouchEnd : undefined}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  if (isMobile && !showAllSteps) {
                    setIsPaused(!isPaused)
                  } else if (!isMobile) {
                    handleOpen()
                  }
                }
              }}
              role="button"
              tabIndex={0}
              aria-label={
                isMobile 
                  ? (showAllSteps ? 'Double-tap to zoom, drag to pan' : (isPaused ? 'Tap to play' : 'Tap to pause'))
                  : `Click to zoom ${alt}`
              }
              style={{
                maxWidth: '100%',
                opacity: isInitialized ? 1 : 0,
                transition: 'opacity 0.6s ease-in-out',
              }}
            >
              {/* Camera wrapper - applies zoom and pan */}
              <div
                ref={svgWrapperRef}
                style={{
                  width: '100%',
                  height: isMobile ? '100%' : 'auto',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  transform: `translate(${-camera.x}px, ${-camera.y}px) scale(${camera.scale})`,
                  transformOrigin: 'center center',
                  transition: 'transform 1.2s cubic-bezier(0.4, 0, 0.2, 1)',
                }}
              >
                {svgContentElement}
              </div>
            </div>
            
            {/* Pause indicator */}
            {isPaused && isPlaying && (
              <div className="absolute top-3 right-3 flex items-center gap-1.5 px-2 py-1 rounded-md bg-black/60 text-white/90 text-xs font-medium backdrop-blur-sm">
                <PauseIcon />
                <span>Paused</span>
              </div>
            )}
          </div>
        )}

        {/* Gradient fade for mobile buttons */}
        {isMobile && (
          <div className="absolute bottom-0 left-0 right-0 h-32 pointer-events-none bg-gradient-to-t from-[var(--vocs-color_codeBlockBackground)] via-[var(--vocs-color_codeBlockBackground)] to-transparent" 
            style={{ 
              backgroundImage: 'linear-gradient(to top, var(--vocs-color_codeBlockBackground) 0%, var(--vocs-color_codeBlockBackground) 20%, transparent 80%)'
            }}
          />
        )}

        {/* Progress bar at bottom edge - mobile only */}
        {isMobile && (
          <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-gray4 z-10">
            <div 
              className="h-full bg-accent transition-none"
              style={{ 
                width: `${totalProgress}%`,
              }}
            />
          </div>
        )}

        {/* Bottom controls with integrated progress bars */}
        <div className={`flex items-center gap-4 px-4 relative z-10 ${isMobile ? 'justify-around pb-6' : 'justify-between py-3'}`}>
          {/* Download button - bottom left */}
          <button
            type="button"
            onClick={handleDownload}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray6 bg-gray2 hover:bg-gray3 text-gray11 hover:text-gray12 transition-colors text-sm ${isMobile ? 'flex-1 justify-center' : ''}`}
            aria-label="Download diagram"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            <span>Download</span>
          </button>

          {/* Progress bars - center, elongated horizontal bars (desktop only) */}
          {!isMobile && (
            <div className="flex items-center justify-center gap-1.5 px-3 py-1.5 flex-1 max-w-[100px] mx-auto">
            {steps.filter(step => !step.id.includes('.')).map((_, index) => {
              // Calculate what % of this step is complete
              const stepStartPercent = (index / steps.length) * 100
              const stepEndPercent = ((index + 1) / steps.length) * 100
              const stepWidth = stepEndPercent - stepStartPercent
              
              let fillPercent = 0
              if (totalProgress >= stepEndPercent) {
                fillPercent = 100 // Fully filled
              } else if (totalProgress > stepStartPercent) {
                // Partially filled
                fillPercent = ((totalProgress - stepStartPercent) / stepWidth) * 100
              }
              
              return (
                <div
                  key={`step-${
                    // biome-ignore lint/suspicious/noArrayIndexKey: stable list
                    index
                  }`}
                  className="relative h-1 flex-1 bg-gray6 rounded-full overflow-hidden"
                >
                  <div
                    className="absolute inset-y-0 left-0 bg-accent rounded-full transition-none"
                    style={{ 
                      width: `${fillPercent}%`,
                    }}
                  />
                </div>
              )
            })}
            </div>
          )}

          {/* Skip button */}
          <button
            type="button"
            onClick={handleSkip}
            disabled={showAllSteps}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray6 bg-gray2 hover:bg-gray3 text-gray11 hover:text-gray12 transition-colors text-sm disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-gray2 ${isMobile ? 'flex-1 justify-center' : ''}`}
            aria-label="Skip to end"
          >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <polygon points="5 4 15 12 5 20 5 4" />
                <line x1="19" y1="5" x2="19" y2="19" />
              </svg>
              <span>Skip</span>
          </button>
            
          {/* Replay/Play button */}
          <button
            type="button"
            onClick={hasStarted ? handleReplay : handlePlay}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors text-sm ${
              hasStarted 
                ? 'border-gray6 bg-gray2 hover:bg-gray3 text-gray11 hover:text-gray12' 
                : 'border-accent bg-accent hover:bg-accentHover text-white'
            } ${isMobile ? 'flex-1 justify-center' : ''}`}
            aria-label={hasStarted ? "Replay animation" : "Play animation"}
          >
              {hasStarted ? (
                <>
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
                    <path d="M21 3v5h-5" />
                    <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
                    <path d="M3 21v-5h5" />
                  </svg>
                  <span>Replay</span>
                </>
              ) : (
                <>
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <polygon points="5 3 19 12 5 21 5 3" />
                  </svg>
                  <span>Play</span>
                </>
              )}
          </button>
        </div>
      </div>

      {/* Lightbox */}
      {isZoomed && (
        /* biome-ignore lint/a11y/useKeyWithClickEvents: keyboard close handled via Escape in useEffect */
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85"
          onClick={handleClose}
          role="dialog"
          aria-modal="true"
          style={{ marginBottom: 0 }}
        >
          {/* Floating close button */}
          <button
            type="button"
            className="fixed top-8 right-8 flex items-center justify-center w-12 h-12 rounded-full bg-gray2/90 backdrop-blur-sm text-gray12 hover:bg-gray3 transition-colors border border-gray6 shadow-lg z-50"
            onClick={handleClose}
            aria-label="Close lightbox"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>

          {/* Lightbox content with tabs */}
          {/* biome-ignore lint/a11y/useKeyWithClickEvents: only prevents propagation, not interactive */}
          {/* biome-ignore lint/a11y/noStaticElementInteractions: only prevents propagation, not interactive */}
          <div 
            className="w-full md:w-[80vw] h-[96vh] md:h-auto md:max-h-[90vh] bg-[var(--vocs-color_codeBlockBackground)] md:rounded-2xl border-0 md:border md:border-gray4 overflow-hidden flex flex-col my-auto"
            onClick={(e) => e.stopPropagation()}
            style={{ marginBottom: 0 }}
          >
            {/* Full-width tabs across the top */}
            <div className="flex border-b border-gray6">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  setLightboxTab('static')
                }}
                className={`flex-1 px-6 py-3 text-sm font-semibold transition-colors relative ${
                  lightboxTab === 'static'
                    ? 'text-gray12 bg-gray2'
                    : 'text-gray11 hover:text-gray12 bg-[var(--vocs-color_codeBlockBackground)] hover:bg-gray2'
                }`}
              >
                Static
                {lightboxTab === 'static' && (
                  <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-accent" />
                )}
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  setLightboxTab('animated')
                }}
                className={`flex-1 px-6 py-3 text-sm font-semibold transition-colors relative ${
                  lightboxTab === 'animated'
                    ? 'text-gray12 bg-gray2'
                    : 'text-gray11 hover:text-gray12 bg-[var(--vocs-color_codeBlockBackground)] hover:bg-gray2'
                }`}
              >
                Animated
                {lightboxTab === 'animated' && (
                  <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-accent" />
                )}
              </button>
            </div>

            {/* Tab content */}
            <div className="flex-1 overflow-hidden p-4 flex flex-col">
              {lightboxTab === 'static' ? (
                /* Static tab - show clean SVG with all elements visible */
                <div
                  // biome-ignore lint/security/noDangerouslySetInnerHtml: SVG content is loaded from static assets
                  dangerouslySetInnerHTML={{ __html: cleanSvgContent }}
                  className={`w-full select-none [&_*]:!opacity-100 ${
                    isDarkMode ? '[&>svg]:[filter:invert(0.88)_hue-rotate(180deg)]' : ''
                  } [&>svg]:w-full [&>svg]:h-auto [&>svg]:max-w-full [&>svg]:rounded-lg`}
                />
              ) : (
                /* Animated tab - render the live animation here (unmounted from background) */
                <div className="relative flex-1 flex flex-col">
                  <div 
                    className="relative overflow-hidden flex-1 mb-4"
                  >
                    <div
                      ref={containerRef}
                      className="w-full h-full flex items-center justify-center"
                      style={{
                        maxWidth: '100%',
                        opacity: isInitialized ? 1 : 0,
                      }}
                      onMouseEnter={undefined}
                      onMouseLeave={undefined}
                    >
                      {/* Camera transform applies zoom and pan */}
                      <div
                        ref={svgWrapperRef}
                        className={isDarkMode ? '[&>svg]:[filter:invert(0.88)_hue-rotate(180deg)]' : ''}
                        style={{
                          width: '100%',
                          height: '100%',
                          display: 'flex',
                          justifyContent: 'center',
                          alignItems: 'center',
                          transform: `translate(${-camera.x}px, ${-camera.y}px) scale(${camera.scale})`,
                          transformOrigin: 'center center',
                          transition: 'transform 1.2s cubic-bezier(0.4, 0, 0.2, 1)',
                        }}
                      >
                        {svgContentElement}
                      </div>
                    </div>
                    
                    {/* Pause indicator */}
                    {isPaused && isPlaying && (
                      <div className="absolute top-3 right-3 flex items-center gap-1.5 px-2 py-1 rounded-md bg-black/60 text-white/90 text-xs font-medium backdrop-blur-sm">
                        <PauseIcon />
                        <span>Paused</span>
                      </div>
                    )}

                  </div>

                  {/* Bottom controls with integrated progress bars */}
                  <div className="flex items-center justify-between gap-4 px-2 py-2">
                    {/* Download button - bottom left */}
                    <button
                      type="button"
                      onClick={handleDownload}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray6 bg-gray2 hover:bg-gray3 text-gray11 hover:text-gray12 transition-colors text-sm"
                      aria-label="Download diagram"
                    >
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        aria-hidden="true"
                      >
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                        <polyline points="7 10 12 15 17 10" />
                        <line x1="12" y1="15" x2="12" y2="3" />
                      </svg>
                      <span className="hidden md:inline">Download</span>
                    </button>

                    {/* Progress bars - center */}
                    <div className="flex items-center justify-center gap-1.5 px-3 py-1.5 flex-1 max-w-[100px] mx-auto">
                      {steps.filter(step => !step.id.includes('.')).map((_, index) => {
                        const stepStartPercent = (index / steps.length) * 100
                        const stepEndPercent = ((index + 1) / steps.length) * 100
                        const stepWidth = stepEndPercent - stepStartPercent
                        
                        let fillPercent = 0
                        if (totalProgress >= stepEndPercent) {
                          fillPercent = 100
                        } else if (totalProgress > stepStartPercent) {
                          fillPercent = ((totalProgress - stepStartPercent) / stepWidth) * 100
                        }
                        
                        return (
                          <div
                            key={`lightbox-step-${index}`}
                            className="relative h-1 flex-1 bg-gray6 rounded-full overflow-hidden"
                          >
                            <div
                              className="absolute inset-y-0 left-0 bg-accent rounded-full transition-none"
                              style={{ 
                                width: `${fillPercent}%`,
                              }}
                            />
                          </div>
                        )
                      })}
                    </div>

                    {/* Play/Pause, Skip and Replay buttons - bottom right */}
                    <div className="flex items-center gap-2">
                      {/* Play/Pause button - only show during animation */}
                      {!showAllSteps && (
                        <button
                          type="button"
                          onClick={() => setIsPaused(!isPaused)}
                          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray6 bg-gray2 hover:bg-gray3 text-gray11 hover:text-gray12 transition-colors text-sm"
                          aria-label={isPaused ? "Play animation" : "Pause animation"}
                        >
                          {isPaused ? (
                          <>
                            <svg
                              xmlns="http://www.w3.org/2000/svg"
                              width="16"
                              height="16"
                              viewBox="0 0 24 24"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="2"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              aria-hidden="true"
                            >
                              <polygon points="5 3 19 12 5 21 5 3" />
                            </svg>
                            <span className="hidden md:inline">Play</span>
                          </>
                        ) : (
                          <>
                            <svg
                              xmlns="http://www.w3.org/2000/svg"
                              width="16"
                              height="16"
                              viewBox="0 0 24 24"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="2"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              aria-hidden="true"
                            >
                              <rect x="6" y="4" width="4" height="16" />
                              <rect x="14" y="4" width="4" height="16" />
                            </svg>
                            <span className="hidden md:inline">Pause</span>
                          </>
                          )}
                        </button>
                      )}
                      
                      <button
                        type="button"
                        onClick={handleSkip}
                        disabled={showAllSteps}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray6 bg-gray2 hover:bg-gray3 text-gray11 hover:text-gray12 transition-colors text-sm disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-gray2"
                        aria-label="Skip to end"
                      >
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          width="16"
                          height="16"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          aria-hidden="true"
                        >
                          <polygon points="5 4 15 12 5 20 5 4" />
                          <line x1="19" y1="5" x2="19" y2="19" />
                        </svg>
                        <span className="hidden md:inline">Skip</span>
                      </button>
                      
                      <button
                        type="button"
                        onClick={handleReplay}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray6 bg-gray2 hover:bg-gray3 text-gray11 hover:text-gray12 transition-colors text-sm"
                        aria-label="Replay animation"
                      >
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          width="16"
                          height="16"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          aria-hidden="true"
                        >
                          <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
                          <path d="M21 3v5h-5" />
                          <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
                          <path d="M3 21v-5h5" />
                        </svg>
                        <span className="hidden md:inline">Replay</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  )
}
