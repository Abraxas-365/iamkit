import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'

const PAGE_SIZE = 50
const DEBOUNCE_MS = 300

export interface PaginatedState<T> {
  data: T[]
  total: number
  loading: boolean
  error: string
  /** Current search string (debounced value that was actually sent). */
  search: string
  /** Current offset. */
  offset: number
  /** Page size. */
  limit: number
  /** True when there is a previous page. */
  hasPrev: boolean
  /** True when there is a next page. */
  hasNext: boolean
  /** 1-based index of first visible item (0 when empty). */
  from: number
  /** 1-based index of last visible item. */
  to: number
  /** Set the search string (debounced automatically). */
  setSearch: (value: string) => void
  /** The raw (un-debounced) search string for binding to the input. */
  rawSearch: string
  /** Go to next page. */
  nextPage: () => void
  /** Go to previous page. */
  prevPage: () => void
  /** Reload current page. */
  reload: () => void
}

/**
 * Server-side paginated list hook.
 *
 * Sends `?search=&limit=&offset=` to the given path.
 * Debounces the search input and resets offset on search change.
 *
 * @param basePath  API path without query params, e.g. `/environments/xxx/users`.
 *                  Pass `null` to disable fetching.
 * @param options   Optional overrides.
 */
export function usePaginatedList<T>(
  basePath: string | null,
  options?: { limit?: number; extraParams?: Record<string, string> },
): PaginatedState<T> {
  const limit = options?.limit ?? PAGE_SIZE
  const extraParams = options?.extraParams

  const [rawSearch, setRawSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [version, setVersion] = useState(0)
  const [state, setState] = useState<{
    path: string | null
    data: T[]
    total: number
    loading: boolean
    error: string
  }>({ path: null, data: [], total: 0, loading: true, error: '' })

  // Debounce search input
  useEffect(() => {
    const id = setTimeout(() => {
      setDebouncedSearch(rawSearch)
      setOffset(0) // reset to first page on new search
    }, DEBOUNCE_MS)
    return () => clearTimeout(id)
  }, [rawSearch])

  // Build full path with query params
  const fullPath = useMemo(() => {
    if (!basePath) return null
    const params = new URLSearchParams()
    if (debouncedSearch) params.set('search', debouncedSearch)
    params.set('limit', String(limit))
    params.set('offset', String(offset))
    if (extraParams) {
      for (const [k, v] of Object.entries(extraParams)) {
        if (v) params.set(k, v)
      }
    }
    return `${basePath}?${params.toString()}`
  }, [basePath, debouncedSearch, limit, offset, extraParams])

  // Stable reference for extraParams to avoid infinite loops
  const extraParamsRef = useRef(extraParams)
  useEffect(() => {
    const prev = extraParamsRef.current
    const next = extraParams
    const changed = JSON.stringify(prev) !== JSON.stringify(next)
    extraParamsRef.current = next
    if (changed) setOffset(0)
  }, [extraParams])

  // Fetch
  useEffect(() => {
    const controller = new AbortController()
    if (!fullPath) {
      setState({ path: null, data: [], total: 0, loading: false, error: '' })
      return () => controller.abort()
    }
    setState(s => ({ ...s, path: fullPath, loading: true, error: '' }))
    api.list<T>(fullPath, controller.signal)
      .then(result => {
        if (!controller.signal.aborted) {
          setState({ path: fullPath, data: result.data, total: result.total, loading: false, error: '' })
        }
      })
      .catch(e => {
        if (!controller.signal.aborted) {
          setState({ path: fullPath, data: [], total: 0, loading: false, error: message(e) })
        }
      })
    return () => controller.abort()
  }, [fullPath, version])

  const current = state.path === fullPath ? state : { data: [] as T[], total: 0, loading: !!fullPath, error: '' }

  const from = current.total === 0 ? 0 : offset + 1
  const to = Math.min(offset + limit, current.total)

  const setSearch = useCallback((value: string) => {
    setRawSearch(value)
  }, [])

  const nextPage = useCallback(() => {
    setOffset(o => o + limit)
  }, [limit])

  const prevPage = useCallback(() => {
    setOffset(o => Math.max(0, o - limit))
  }, [limit])

  const reload = useCallback(() => {
    setVersion(v => v + 1)
  }, [])

  return {
    data: current.data,
    total: current.total,
    loading: current.loading,
    error: current.error,
    search: debouncedSearch,
    offset,
    limit,
    hasPrev: offset > 0,
    hasNext: offset + limit < current.total,
    from,
    to,
    setSearch,
    rawSearch,
    nextPage,
    prevPage,
    reload,
  }
}
