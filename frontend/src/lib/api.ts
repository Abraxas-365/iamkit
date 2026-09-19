export class ApiError extends Error {
  constructor(public status: number, message: string, public code?: string) { super(message) }
}
export interface ListResult<T> { data: T[]; total: number }
export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/management/v1${path}`, {
    ...init, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-IAMKit-Console': '1', ...init.headers },
  })
  if (!response.ok) {
    if (response.status === 401 && path !== '/login') window.dispatchEvent(new Event('session-expired'))
    const body = await response.json().catch(() => null)
    throw new ApiError(response.status, body?.error?.message || response.statusText, body?.error?.code)
  }
  if (response.status === 204 || response.headers.get('content-length') === '0') return undefined as T
  if (!response.headers.get('content-type')?.includes('application/json')) return undefined as T
  const text = await response.text()
  return text ? JSON.parse(text) as T : undefined as T
}
export async function requestList<T>(path: string, signal?: AbortSignal): Promise<ListResult<T>> {
  const response = await fetch(`/management/v1${path}`, {
    signal, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-IAMKit-Console': '1' },
  })
  if (!response.ok) {
    if (response.status === 401 && path !== '/login') window.dispatchEvent(new Event('session-expired'))
    const body = await response.json().catch(() => null)
    throw new ApiError(response.status, body?.error?.message || response.statusText, body?.error?.code)
  }
  const text = await response.text()
  if (!text) return { data: [], total: 0 }
  const json = JSON.parse(text)
  // Support both new envelope { items, page } and legacy raw arrays
  if (Array.isArray(json)) {
    return { data: json as T[], total: json.length }
  }
  return { data: (json.items ?? []) as T[], total: json.page?.total ?? 0 }
}
export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  list: <T>(path: string, signal?: AbortSignal) => requestList<T>(path, signal),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
  put: <T>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) => request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }),
  delete: (path: string) => request<void>(path, { method: 'DELETE' }),
}
