import { cn } from '@/lib/utils'

export function PageHeader({ title, description, actions, className }: { title: string; description?: string; actions?: React.ReactNode; className?: string }) {
  return <div className={cn('flex flex-wrap items-start justify-between gap-4', className)}>
    <div><h1 className="font-mono text-2xl font-bold tracking-tight">{title}</h1>{description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}</div>
    {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
  </div>
}
