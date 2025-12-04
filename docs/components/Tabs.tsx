import { Tabs as base_Tabs } from '@base-ui-components/react/tabs'
import { useQueryState } from 'nuqs'
import * as React from 'react'

export function Tabs(props: base_Tabs.Root.Props) {
  const { children } = props

  const tabs = React.useMemo(() => {
    const values = React.Children.map(children, (child) => {
      if (React.isValidElement(child))
        return (child.props as { value: string }).value
      return null
    })
    if (!values) return []
    return values.filter(Boolean) as string[]
  }, [children])

  const [tab, setTab] = useQueryState('tab', {
    // biome-ignore lint/style/noNonNullAssertion: _
    defaultValue: tabs[0]!,
  })

  return (
    <base_Tabs.Root
      onValueChange={(value) => setTab(value)}
      value={tab}
      {...props}
    >
      <base_Tabs.List className="border-b border-gray4 flex">
        {tabs.map((tab) => (
          <base_Tabs.Tab
            className="h-[40px] text-[15px] -mb-px font-[350] flex items-center px-2 border-b border-transparent aria-selected:border-active aria-selected:text-active"
            key={tab}
            value={tab}
          >
            {tab}
          </base_Tabs.Tab>
        ))}
      </base_Tabs.List>
      {children}
    </base_Tabs.Root>
  )
}

export namespace Tabs {
  export function Tab(props: base_Tabs.Panel.Props) {
    return <base_Tabs.Panel {...props} />
  }
}
