import { cn } from '@/lib/utils'

/** PageHeader: title and description on the left, actions on the right. The
 * description wraps within its column (capped for readability) so actions
 * stay beside the title from `sm` up and stack below it on phones. */
export function PageHeader({ title, description, actions, className }: { title: string; description?: string; actions?: React.ReactNode; className?: string }) {
  return <div className={cn('flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6', className)}>
    <div className="min-w-0 flex-1"><h1 className="font-mono text-2xl font-bold tracking-tight">{title}</h1>{description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>}</div>
    {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
  </div>
}
