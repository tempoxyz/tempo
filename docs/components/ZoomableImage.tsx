import { useState, useEffect } from 'react'
import { cx } from '../cva.config'

export function ZoomableImage(props: {
  src: string
  alt: string
}) {
  const { src, alt } = props
  const [isZoomed, setIsZoomed] = useState(false)

  const handleOpen = () => setIsZoomed(true)
  const handleClose = () => setIsZoomed(false)

  useEffect(() => {
    if (!isZoomed) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        handleClose()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    document.body.style.overflow = 'hidden'

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = ''
    }
  }, [isZoomed])

  return (
    <>
      <img
        src={src}
        alt={alt}
        className="cursor-zoom-in rounded-lg transition-opacity hover:opacity-80"
        onClick={handleOpen}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            handleOpen()
          }
        }}
        tabIndex={0}
        role="button"
        aria-label={`Click to zoom ${alt}`}
      />

      {isZoomed && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-8"
          onClick={handleClose}
          role="dialog"
          aria-modal="true"
        >
          <div
            className="relative w-[90vw] h-[90vh] bg-gray1 rounded-lg shadow-2xl border border-gray4 p-8 flex items-center justify-center"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="absolute top-4 right-4 flex items-center justify-center w-10 h-10 rounded-full bg-gray3 text-gray12 hover:bg-gray4 transition-colors border border-gray6 z-10"
              onClick={handleClose}
              aria-label="Close zoomed image"
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
              >
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>

            <img
              src={src}
              alt={alt}
              className="max-w-full max-h-full object-contain rounded cursor-zoom-out"
              onClick={handleClose}
            />
          </div>
        </div>
      )}
    </>
  )
}
