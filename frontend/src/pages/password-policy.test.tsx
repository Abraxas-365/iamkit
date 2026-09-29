// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const defaults = { min_length: 12, require_upper: false, require_lower: false, require_digit: false, require_symbol: false, max_age_days: 0, lockout_threshold: 0, lockout_minutes: 15, breach_check: false, custom: false }
let policy: Record<string, unknown>
let user: Record<string, unknown>
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'

beforeEach(() => {
  policy = { ...defaults }
  user = { id: 'u1', name: 'Alice', email: 'alice@example.com', active: true, failed_logins: 5, locked_until: '2099-01-01T00:00:00Z' }
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    if (path === `${env}/password-policy` && method === 'PUT') {
      const body = JSON.parse(String(init.body))
      if (body.min_length < 8) return Response.json({ error: { code: 'VALIDATION', message: 'min_length must be 8-72' } }, { status: 400 })
      policy = { ...body, custom: true, updated_at: '2026-09-01T00:00:00Z' }
      return Response.json(policy)
    }
    if (path === `${env}/password-policy` && method === 'DELETE') { policy = { ...defaults }; return new Response(null, { status: 204 }) }
    if (path === `${env}/users/u1/unlock`) { user = { ...user, failed_logins: 0, locked_until: null }; return new Response(null, { status: 204 }) }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/password-policy` ? policy :
            path === `${env}/users/u1` ? user :
              path === `${env}/users/u1/factors` ? { factors: [], recovery_codes_remaining: 0 } :
                path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('saves a stricter policy and restores the default', async () => {
  const u = userEvent.setup()
  open('password-policy')
  const length = await screen.findByLabelText('Minimum length')
  expect(screen.getByText(/The default policy/)).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Save policy' }) as HTMLButtonElement).disabled).toBe(true)
  await u.clear(length); await u.type(length, '16')
  await u.click(screen.getByLabelText('Require a digit'))
  await u.click(screen.getByLabelText('Reject breached passwords'))
  const threshold = screen.getByLabelText('Lock after wrong passwords')
  await u.clear(threshold); await u.type(threshold, '5')
  await u.click(screen.getByRole('button', { name: 'Save policy' }))
  const { custom: _custom, ...unchanged } = defaults
  await waitFor(() => expect(calls).toEqual([{ method: 'PUT', path: `${env}/password-policy`, body: { ...unchanged, min_length: 16, require_digit: true, breach_check: true, lockout_threshold: 5 } }]))
  expect(await screen.findByText(/Custom policy/)).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Restore default' }))
  await u.click(await screen.findByRole('button', { name: 'Restore default' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'DELETE', path: `${env}/password-policy`, body: undefined }))
  expect(await screen.findByText(/The default policy/)).toBeTruthy()
})

it('shows server validation errors', async () => {
  const u = userEvent.setup()
  open('password-policy')
  const length = await screen.findByLabelText('Minimum length')
  await u.clear(length); await u.type(length, '7')
  // The browser would block min=8; submit the form directly like a stale client.
  length.closest('form')!.noValidate = true
  await u.click(screen.getByRole('button', { name: 'Save policy' }))
  expect(await screen.findByText('min_length must be 8-72')).toBeTruthy()
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open('password-policy')
  expect(((await screen.findByLabelText('Minimum length')) as HTMLInputElement).disabled).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save policy' })).toBeNull()
})

it('unlocks a locked user', async () => {
  const u = userEvent.setup()
  open('users/u1')
  expect(await screen.findByText('Locked after 5 wrong passwords')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: /Unlock/ }))
  await u.click(await screen.findByRole('button', { name: 'Unlock' }))
  await waitFor(() => expect(calls).toContainEqual({ method: 'POST', path: `${env}/users/u1/unlock`, body: undefined }))
  await waitFor(() => expect(screen.queryByText('Locked after 5 wrong passwords')).toBeNull())
})
