export function Container(
  props: React.PropsWithChildren<{
    headerLeft?: React.ReactNode
    headerRight?: React.ReactNode
    footer?: React.ReactNode
  }>,
) {
  const { children, headerLeft, headerRight, footer } = props

  // Note: styling of this container mimics Vocs styles.
  return (
    <div className="border-gray4 border rounded divide-gray4 divide-y">
      {(headerLeft || headerRight) && (
        <header className="px-4 h-[44px] flex items-center justify-between">
          {headerLeft}
          {headerRight}
        </header>
      )}
      <div className="p-4">{children}</div>
      {footer && (
        <footer className="px-2.5 min-h-8 text-[13px] text-gray10 items-center flex">
          {footer}
        </footer>
      )}
    </div>
  )
}
