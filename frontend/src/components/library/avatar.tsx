import { useState } from 'react'
import { cn } from '@/lib/utils'

/** initials of a name (or email): up to two letters. */
export function initials(name?: string | null) {
  const words = (name ?? '').replace(/@.*/, '').split(/[\s._-]+/).filter(Boolean)
  return (words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2)).toUpperCase()
}

/** Avatar shows a user's picture (an https URL), falling back to their
 * initials when there is none or it fails to load. */
export function Avatar({ src, name, className }: { src?: string | null; name?: string | null; className?: string }) {
  const [failed, setFailed] = useState<string | null>(null)
  const base = cn('inline-flex size-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-muted text-xs font-medium text-muted-foreground', className)
  if (src && src.startsWith('https://') && failed !== src) {
    return <img src={src} alt="" referrerPolicy="no-referrer" loading="lazy" className={cn(base, 'object-cover')} onError={() => setFailed(src)} />
  }
  return <span aria-hidden className={base}>{initials(name)}</span>
}
