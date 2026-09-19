import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from './api'
const fetchMock = vi.fn()
const dispatchEvent = vi.fn()
beforeEach(() => { vi.stubGlobal('fetch', fetchMock); vi.stubGlobal('window', { dispatchEvent }) })
afterEach(() => { vi.unstubAllGlobals(); vi.resetAllMocks() })
describe('management API client', () => {
  it('sends same-origin cookies and the console CSRF header, never a bearer token', async () => {
    fetchMock.mockResolvedValue(Response.json({ role: 'owner' }))
    expect(await api.get('/me')).toEqual({ role: 'owner' })
    expect(fetchMock).toHaveBeenCalledWith('/management/v1/me', expect.objectContaining({ credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-IAMKit-Console': '1' } }))
  })
  it('handles no-content and Fiber plain-text creation responses', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }))
    expect(await api.delete('/sessions/current')).toBeUndefined()
    fetchMock.mockResolvedValueOnce(new Response('Created', { status: 201, headers: { 'Content-Type': 'text/plain' } }))
    expect(await api.post('/environments/env/memberships', {})).toBeUndefined()
  })
  it('preserves the structured error envelope', async () => {
    fetchMock.mockResolvedValue(Response.json({ error: { message: 'insufficient permissions', code: 'DENIED' } }, { status: 403 }))
    await expect(api.get('/projects')).rejects.toMatchObject({ status: 403, code: 'DENIED', message: 'insufficient permissions' })
  })
  it('expires the console session on 401 but not on a failed login', async () => {
    fetchMock.mockResolvedValue(Response.json({ error: { message: 'invalid credentials' } }, { status: 401 }))
    await expect(api.post('/login', {})).rejects.toBeInstanceOf(ApiError)
    expect(dispatchEvent).not.toHaveBeenCalled()
    await expect(api.get('/me')).rejects.toBeInstanceOf(ApiError)
    expect(dispatchEvent).toHaveBeenCalledWith(expect.objectContaining({ type: 'session-expired' }))
  })
  it('passes cancellation to fetch', async () => {
    const controller = new AbortController()
    fetchMock.mockResolvedValue(Response.json(null))
    expect(await api.get('/projects', controller.signal)).toBeNull()
    expect(fetchMock).toHaveBeenCalledWith('/management/v1/projects', expect.objectContaining({ signal: controller.signal }))
  })
})
