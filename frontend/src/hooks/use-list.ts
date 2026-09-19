import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
export function useList<T>(path: string | null) {
  const [version, setVersion] = useState(0)
  const [state, setState] = useState<{ path: string | null; data: T[]; total: number; loading: boolean; error: string }>({ path: null, data: [], total: 0, loading: true, error: '' })
  useEffect(() => {
    const controller = new AbortController()
    if (!path) return () => controller.abort()
    setState({ path, data: [], total: 0, loading: true, error: '' })
    api.list<T>(path, controller.signal)
      .then(result => { if (!controller.signal.aborted) setState({ path, data: result.data, total: result.total, loading: false, error: '' }) })
      .catch(e => { if (!controller.signal.aborted) setState({ path, data: [], total: 0, loading: false, error: message(e) }) })
    return () => controller.abort()
  }, [path, version])
  const current = state.path === path ? state : { data: [], total: 0, loading: !!path, error: '' }
  return { ...current, reload: () => setVersion(v => v + 1) }
}
