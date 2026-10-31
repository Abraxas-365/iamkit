// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const DAY = 86400
let retention: Record<string, unknown>
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'

beforeEach(() => {
  retention = { security_retention_seconds: null, default_retention_seconds: 7 * DAY, ceilings: { security: 365 * DAY, default: 90 * DAY }, effective: { security: 365 * DAY, default: 7 * DAY } }
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.split('?')[0].replace('/management/v1', '')
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ method, path, body })
    if (path === `${env}/event-retention` && method === 'PUT') {
      const security = body.security_retention_seconds as number | null
      retention = { ...retention, ...body, effective: { security: Math.min(365 * DAY, security ?? 365 * DAY), default: 7 * DAY } }
      return Response.json(retention)
    }
    return Response.json(path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/event-retention` ? retention : [])
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/event-retention']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('shows the ceilings and shortens security retention', async () => {
  const u = userEvent.setup()
  open()
  const security = await screen.findByRole('spinbutton', { name: 'Security events' }) as HTMLInputElement
  expect(security.placeholder).toBe('365 days')
  expect((screen.getByRole('spinbutton', { name: 'Other events' }) as HTMLInputElement).value).toBe('7')
  await u.type(security, '30')
  await u.click(screen.getByRole('button', { name: 'Save retention' }))
  await waitFor(() => expect(calls.find(c => c.method === 'PUT')?.body).toEqual({ security_retention_seconds: 30 * DAY, default_retention_seconds: 7 * DAY }))
})

it('is read-only for people who are not owners', async () => {
  role = 'admin'
  open()
  const security = await screen.findByRole('spinbutton', { name: 'Security events' }) as HTMLInputElement
  expect(security.disabled).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save retention' })).toBeNull()
  expect(screen.getByText('Only workspace owners change event retention.')).toBeTruthy()
})
