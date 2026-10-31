// Permission descriptions (D40): how people read a resource's permissions.
// The permission's name stays the identifier and the last fallback.
import { useEffect, useMemo, useState } from 'react'
import { api } from '@/lib/api'
import { language } from '@/lib/i18n'

/** One stored text of a permission; locale '' is the default text. */
export interface PermissionDescription { permission: string; locale: string; display_name: string; description: string }

/** A permission as the reader sees it; display_name is the name itself when nothing describes it. */
export interface PermissionText { name: string; display_name: string; description: string; described: boolean }

/** Limits the server enforces (authorization.MaxDisplayName / MaxDescription). */
export const MAX_DISPLAY_NAME = 80
export const MAX_DESCRIPTION = 300

/** describe resolves one permission: exact locale › base language ('es-PE' → 'es') › default '' › the raw name. */
export function describe(items: readonly PermissionDescription[] | undefined, permission: string, locale: string = language()): PermissionText {
  const tag = locale.toLowerCase()
  const chain = [tag, tag.split('-')[0], '']
  for (const l of chain) {
    const hit = items?.find(d => d.permission === permission && d.locale.toLowerCase() === l && (d.display_name || d.description))
    if (hit) return { name: permission, display_name: hit.display_name || permission, description: hit.description, described: true }
  }
  return { name: permission, display_name: permission, description: '', described: false }
}

/** usePermissionText loads the descriptions of the given resources (once each) and returns a resolver; until they arrive, and for failures, it answers with raw names. */
export function usePermissionText(base: string, resourceIds: readonly (string | undefined)[]): (resourceId: string | undefined, permission: string) => PermissionText {
  const [loaded, setLoaded] = useState<Record<string, PermissionDescription[]>>({})
  const wanted = useMemo(() => [...new Set(resourceIds.filter((id): id is string => !!id))].sort(), [resourceIds])
  const key = `${base}|${wanted.join(',')}`
  useEffect(() => {
    let live = true
    for (const id of wanted) {
      api.get<{ items: PermissionDescription[] | null }>(`${base}/resources/${id}/permission-descriptions`)
        .then(r => { if (live) setLoaded(m => ({ ...m, [`${base}|${id}`]: r.items ?? [] })) })
        .catch(() => undefined)
    }
    return () => { live = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  return (resourceId, permission) => describe(resourceId ? loaded[`${base}|${resourceId}`] : undefined, permission)
}
