import type { ReactNode } from 'react'
import { Menu } from '@base-ui/react/menu'
import { MoreHorizontal } from 'lucide-react'
import { cn } from '@/lib/utils'
import { buttonVariants } from '@/components/ui/button'

export interface Action {
  label: string
  onSelect: () => void
  icon?: ReactNode
  /** Destructive actions render last, in red, after a separator. */
  destructive?: boolean
  disabled?: boolean
}

const item = 'flex w-full cursor-default items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none select-none data-highlighted:bg-muted data-disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0'

/** RowActions is the "⋯" menu at the end of a table row. `label` names the
 * row for screen readers ("Actions for Storefront"). */
export function RowActions({ label, actions }: { label: string; actions: Action[] }) {
  const visible = actions.filter(Boolean)
  if (!visible.length) return null
  const safe = visible.filter(a => !a.destructive)
  const danger = visible.filter(a => a.destructive)
  return <Menu.Root>
    <Menu.Trigger aria-label={label} className={cn(buttonVariants({ variant: 'ghost', size: 'icon-sm' }))} onClick={e => e.stopPropagation()}>
      <MoreHorizontal />
    </Menu.Trigger>
    <Menu.Portal>
      <Menu.Positioner className="z-50 outline-none" sideOffset={4} align="end">
        <Menu.Popup className="min-w-44 origin-[var(--transform-origin)] rounded-lg border bg-popover p-1 text-popover-foreground shadow-md outline-none transition-[scale,opacity] duration-100 data-ending-style:scale-95 data-ending-style:opacity-0 data-starting-style:scale-95 data-starting-style:opacity-0">
          {safe.map(a => <Menu.Item key={a.label} className={item} disabled={a.disabled} onClick={a.onSelect}>{a.icon}{a.label}</Menu.Item>)}
          {safe.length > 0 && danger.length > 0 && <Menu.Separator className="-mx-1 my-1 h-px bg-border" />}
          {danger.map(a => <Menu.Item key={a.label} className={cn(item, 'text-destructive data-highlighted:bg-destructive/10')} disabled={a.disabled} onClick={a.onSelect}>{a.icon}{a.label}</Menu.Item>)}
        </Menu.Popup>
      </Menu.Positioner>
    </Menu.Portal>
  </Menu.Root>
}
