import type { InputHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

type SwitchProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'onChange'> & {
  onCheckedChange?: (checked: boolean) => void
}

/** Switch is a native checkbox with switch semantics and styling, so it
 * submits with forms and is labelled like any input. */
export function Switch({ className, onCheckedChange, ...props }: SwitchProps) {
  return <span className={cn('relative inline-flex h-5 w-9 shrink-0', className)}>
    <input type="checkbox" role="switch" data-slot="switch" className="peer absolute inset-0 z-10 m-0 cursor-pointer appearance-none rounded-full opacity-0 disabled:cursor-not-allowed" onChange={e => onCheckedChange?.(e.target.checked)} {...props} />
    {/* dark: overrides peer-checked:, so "on" is repeated under dark: too. */}
    <span aria-hidden className="pointer-events-none absolute inset-0 rounded-full bg-input transition-colors peer-checked:bg-primary peer-focus-visible:ring-3 peer-focus-visible:ring-ring/50 peer-disabled:opacity-50 dark:bg-muted-foreground/25 dark:peer-checked:bg-primary" />
    <span aria-hidden className="pointer-events-none absolute top-0.5 left-0.5 size-4 rounded-full bg-background shadow-sm transition-transform peer-checked:translate-x-4 peer-disabled:opacity-70 dark:bg-foreground/80 dark:peer-checked:bg-primary-foreground" />
  </span>
}
