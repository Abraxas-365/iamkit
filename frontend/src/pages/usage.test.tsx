// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
let limits: { deployment: Record<string, number>; environment: Record<string, number>; effective: Record<string, number>; updated_at?: string }
let calls: { method: string; path: string; query: string; body?: Record<string, unknown> }[]
let role = 'owner'

const day = (d: string, logins: number) => ({ day: d, metrics: { logins, users_created: 0, tokens: logins * 2, emails: 0, sms: 0, action_calls: 0, api_requests: 0 } })

beforeEach(() => {
  limits = { deployment: { users_max: 100 }, environment: {}, effective: { users_max: 100 } }
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [full, query = ''] = url.split('?')
    const path = full.replace('/management/v1', '')
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ method, path, query, body })
    if (path === `${env}/limits` && method === 'PUT') {
      const own = Object.fromEntries(Object.entries(body as Record<string, number | null>).filter(([, v]) => v !== null)) as Record<string, number>
      limits = { ...limits, environment: own, effective: { users_max: Math.min(100, own.users_max ?? 100), ...(own.sms_per_day !== undefined ? { sms_per_day: own.sms_per_day } : {}) }, updated_at: new Date().toISOString() }
      return Response.json(limits)
    }
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/limits` ? limits :
            path === `${env}/usage` ? { days: [day('2026-09-30', 3), day('2026-10-01', 5)], totals: { logins: 8, users_created: 0, tokens: 16, emails: 0, sms: 0, action_calls: 0, api_requests: 0 }, now: [{ name: 'users_max', count: 42, max: limits.effective.users_max ?? null }, { name: 'organizations_max', count: 3, max: null }, { name: 'applications_max', count: 1, max: null }] } :
              path.startsWith(env) ? { items: [], page: { total: 0, limit: 200, offset: 0 } } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/usage']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('shows usage and tightens limits', async () => {
  const u = userEvent.setup()
  open()
  expect(await screen.findByText('42 of 100')).toBeTruthy()
  expect(screen.getByRole('progressbar', { name: 'Users' }).getAttribute('aria-valuenow')).toBe('42')
  expect(screen.getByText('2026-10-01')).toBeTruthy()
  expect(calls.some(c => c.path === `${env}/usage` && c.query === 'days=30')).toBe(true)

  await u.click(screen.getByRole('button', { name: '7 days' }))
  await waitFor(() => expect(calls.some(c => c.path === `${env}/usage` && c.query === 'days=7')).toBe(true))

  const users = await screen.findByRole('spinbutton', { name: 'Users' }) as HTMLInputElement
  expect(users.placeholder).toBe('Unlimited')
  await u.type(users, '50')
  await u.type(screen.getByRole('spinbutton', { name: 'SMS per day' }), '10')
  await u.click(screen.getByRole('button', { name: 'Save limits' }))
  await waitFor(() => expect(calls.find(c => c.method === 'PUT')?.body).toEqual({
    users_max: 50, organizations_max: null, applications_max: null, requests_per_minute: null, emails_per_day: null, sms_per_day: 10, action_calls_per_minute: null,
  }))
  expect(await screen.findByText('Server: 100 · in effect: 50')).toBeTruthy()
})

it('is read-only for non-owners', async () => {
  role = 'admin'
  open()
  const users = await screen.findByRole('spinbutton', { name: 'Users' }) as HTMLInputElement
  expect(users.disabled).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save limits' })).toBeNull()
  expect(screen.getByText('Only workspace owners change limits.')).toBeTruthy()
})
