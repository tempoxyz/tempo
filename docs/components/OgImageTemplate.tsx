interface OgImageTemplateProps {
  title: string
  description: string
  logoUrl?: string
  backgroundUrl?: string
}

/**
 * Custom OG image template component for documentation
 * Renders a polished design with title, description, and optional logo
 */
export function OgImageTemplate({
  title,
  description,
  logoUrl,
  backgroundUrl,
}: OgImageTemplateProps) {
  // Truncate text to fit within image bounds
  const truncatedTitle =
    title.length > 60 ? `${title.slice(0, 57)}...` : title
  const truncatedDescription =
    description.length > 120 ? `${description.slice(0, 117)}...` : description

  return (
    <div
      style={{
        height: '100%',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        backgroundColor: '#ffffff',
        ...(backgroundUrl
          ? {
              backgroundImage: `url(${backgroundUrl})`,
              backgroundSize: 'cover',
              backgroundPosition: 'center',
            }
          : {
              backgroundImage:
                'linear-gradient(135deg, #ffffff 0%, #f8f9fa 50%, #f1f3f5 100%)',
            }),
        fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
      }}
    >
      {/* Background overlay for readability when using custom background */}
      {backgroundUrl && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(255, 255, 255, 0.85)',
          }}
        />
      )}

      {/* Background pattern overlay for visual interest (only if no custom background) */}
      {!backgroundUrl && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            opacity: 0.03,
            backgroundImage:
              'radial-gradient(circle at 2px 2px, #000000 1px, transparent 0)',
            backgroundSize: '40px 40px',
          }}
        />
      )}

      {/* Main content container */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'flex-start',
          justifyContent: 'center',
          padding: '80px 100px',
          height: '100%',
          width: '100%',
          position: 'relative',
          zIndex: 1,
        }}
      >
        {/* Logo section */}
        {logoUrl && (
          <div
            style={{
              display: 'flex',
              marginBottom: '48px',
            }}
          >
            <img
              src={logoUrl}
              alt="Tempo"
              width="180"
              height="42"
              style={{
                objectFit: 'contain',
              }}
            />
          </div>
        )}

        {/* Title section */}
        <div
          style={{
            display: 'flex',
            fontSize: '72px',
            fontWeight: '700',
            lineHeight: '1.1',
            color: '#000000',
            marginBottom: '32px',
            maxWidth: '1000px',
            letterSpacing: '-0.02em',
            fontFamily: 'Inter, system-ui, sans-serif',
          }}
        >
          {truncatedTitle}
        </div>

        {/* Description section */}
        <div
          style={{
            display: 'flex',
            fontSize: '36px',
            fontWeight: '400',
            lineHeight: '1.5',
            color: '#4b5563',
            maxWidth: '1000px',
            letterSpacing: '-0.01em',
            fontFamily: 'Inter, system-ui, sans-serif',
          }}
        >
          {truncatedDescription}
        </div>

        {/* Decorative accent line */}
        <div
          style={{
            position: 'absolute',
            bottom: '80px',
            left: '100px',
            width: '120px',
            height: '4px',
            backgroundColor: '#3b82f6',
            borderRadius: '2px',
          }}
        />
      </div>
    </div>
  )
}




