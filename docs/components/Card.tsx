import { useState } from 'react'
import { Link as RouterLink } from 'react-router'
import type LucideArrowLeftRight from '~icons/lucide/arrow-left-right'
import LucideExternalLink from '~icons/lucide/external-link'
import { cx } from '../cva.config'

export function Link(props: {
  description: string
  href: string
  icon: typeof LucideArrowLeftRight
  title: string
  sampleHref?: string
}) {
  const { description, href, icon: Icon, title, sampleHref } = props
  const [sampleHovering, setSampleHovering] = useState(false)

  return (
    <RouterLink
      className={cx(
        'relative border border-gray4 rounded-lg p-4 flex flex-col gap-4 min-h-33.75',
        {
          'hover:border-accentHover': !sampleHovering,
        },
      )}
      to={href}
    >
      {sampleHref && (
        <a
          className="absolute flex align-center items-center gap-1 top-3 right-3 text-[11px] border border-gray4 rounded px-2 py-0.5 leading-5 hover:bg-gray2"
          href={sampleHref}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          onMouseEnter={() => setSampleHovering(true)}
          onMouseLeave={() => setSampleHovering(false)}
        >
          Sample Project
          <LucideExternalLink className="text-gray10 size-3" />
        </a>
      )}
      <Icon className="text-accent size-4.5" />
      <div className="flex flex-col gap-1">
        <div className="leading-normal text-gray12 font-[510] text-[14px]">
          {title}
        </div>
        <div className="leading-normal text-gray11 text-[14px]">
          {description}
        </div>
      </div>
    </RouterLink>
  )
}

export function Container(props: React.PropsWithChildren) {
  const { children } = props
  return <div className="grid md:grid-cols-2 gap-3">{children}</div>
}

export function Notice(props: React.PropsWithChildren<{
  title?: string,
  icon?: typeof LucideArrowLeftRight,
  inline?: boolean,
}>) {
  const { children, icon: Icon, title, inline } = props
  return (
    <div
      className={cx(
        'relative border border-gray4 rounded-lg p-4 flex gap-4 flex-col',
        {
          'md:flex-row md:items-center': inline,
        }
      )}
    >
      {(Icon || title) && (
        <div className="flex items-center gap-3">
          {Icon && <Icon className="text-accent size-4.5" />}
          {title && (
            <div className="leading-normal text-gray12 font-[510] text-[14px]">
              {title}
            </div>
          )}
        </div>
      )}
      <div className="leading-normal text-gray11 text-[14px] [&_a]:underline [&_a]:text-accent hover:[&_a]:text-accentHover">
        {children}
      </div>
    </div>
  )
}
