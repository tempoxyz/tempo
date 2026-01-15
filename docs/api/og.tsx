import { ImageResponse } from '@vercel/og'

export const config = {
  runtime: 'edge',
}

export default async function handler(req: Request) {
  const { searchParams } = new URL(req.url)
  const title = searchParams.get('title') || 'Tempo Docs'
  const description =
    searchParams.get('description') ||
    'Documentation for Tempo testnet and protocol specifications'

  return new ImageResponse(
    <div
      style={{
        height: '100%',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-start',
        justifyContent: 'flex-end',
        backgroundColor: '#0a0a0a',
        padding: '60px 80px',
        fontFamily: 'Inter, system-ui, sans-serif',
      }}
    >
      {/* Tempo logo/brand mark */}
      <div
        style={{
          position: 'absolute',
          top: '60px',
          left: '80px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <svg
          width="40"
          height="40"
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          role="img"
          aria-label="Tempo logo"
        >
          <circle cx="16" cy="16" r="16" fill="#ffffff" />
          <path
            d="M10 16L14 12L18 16L22 12"
            stroke="#0a0a0a"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M10 20L14 16L18 20L22 16"
            stroke="#0a0a0a"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
        <span
          style={{
            fontSize: '24px',
            fontWeight: 600,
            color: '#ffffff',
            letterSpacing: '-0.02em',
          }}
        >
          Tempo Docs
        </span>
      </div>

      {/* Title */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
          maxWidth: '900px',
        }}
      >
        <h1
          style={{
            fontSize: title.length > 40 ? '48px' : '64px',
            fontWeight: 700,
            color: '#ffffff',
            lineHeight: 1.1,
            margin: 0,
            letterSpacing: '-0.03em',
          }}
        >
          {title}
        </h1>
        {description && (
          <p
            style={{
              fontSize: '24px',
              color: '#a1a1aa',
              lineHeight: 1.4,
              margin: 0,
              maxWidth: '800px',
            }}
          >
            {description.length > 120
              ? `${description.slice(0, 120)}...`
              : description}
          </p>
        )}
      </div>

      {/* URL footer */}
      <div
        style={{
          position: 'absolute',
          bottom: '60px',
          right: '80px',
          fontSize: '20px',
          color: '#52525b',
        }}
      >
        docs.tempo.xyz
      </div>
    </div>,
    {
      width: 1200,
      height: 630,
    },
  )
}
