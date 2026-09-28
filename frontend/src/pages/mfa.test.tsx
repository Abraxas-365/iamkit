// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
let factors = { factors: [{ id: 'f1', kind: 'totp', confirmed_at: '2026-01-01T00:00:00Z', last_used_at: null, created_at: '2026-01-01T00:00:00Z' }], recovery_codes_remaining: 8 }
let role = 'owner'
let orgFails = false

beforeEach(() => {
  role = 'owner'
  orgFails = false
  factors = { factors: [{ id: 'f1', kind: 'totp', confirmed_at: '2026-01-01T00:00:00Z', last_used_at: null, created_at: '2026-01-01T00:00:00Z' }], recovery_codes_remaining: 8 }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'DELETE' && path === `${env}/users/u1/factors`) {
      factors = { factors: [], recovery_codes_remaining: 0 }
      return new Response(null, { status: 204 })
    }
    if (init.method && init.method !== 'GET') return new Response(null, { status: 204 })
    if (orgFails && path === `${env}/organizations/org1`) return Response.json({ error: { message: 'unavailable' } }, { status: 500 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/users` ? page([{ id: 'u1', name: 'Alice', email: 'alice@example.com', active: true }]) :
            path === `${env}/users/u1/factors` ? factors :
              path === `${env}/organizations` ? page([{ id: 'org1', name: 'Acme' }]) :
                path === `${env}/organizations/org1` ? { id: 'org1', name: 'Acme', active: true, mfa_required: true, mfa_for_federated: false } :
                  path === `${env}/users/u1` ? { id: 'u1', name: 'Alice', email: 'alice@example.com', active: true } :
                    path.startsWith(env) && !path.endsWith('/factors') ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(kind: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${kind}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('shows a user\'s second factors and resets them', async () => {
  open('users')
  await userEvent.click(await screen.findByRole('link', { name: 'Alice' }))
  await screen.findByText('Authenticator app (TOTP)')
  expect(screen.getByText('8')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Reset factors' }))
  await userEvent.click(screen.getByRole('button', { name: 'Reset' }))
  await waitFor(() => expect(calls('DELETE').some(c => c.url.endsWith('/users/u1/factors'))).toBe(true))
  await screen.findByText('No second factor enrolled.')
})

it('edits an organization\'s MFA policy from its overview', async () => {
  open('organizations/org1')
  const required = await screen.findByRole('switch', { name: 'Require a second factor' }) as HTMLInputElement
  expect(required.checked).toBe(true)
  // Each switch saves on its own and only sends the field it changes.
  await userEvent.click(screen.getByRole('switch', { name: 'Also require it for SSO sign-ins' }))
  await waitFor(() => expect(calls('PATCH')).toEqual([{ url: `/management/v1${env}/organizations/org1`, body: { mfa_for_federated: true } }]))
})

it('lets viewers see factors but not reset them', async () => {
  role = 'viewer'
  open('users/u1')
  await screen.findByText('Authenticator app (TOTP)')
  expect(screen.queryByRole('button', { name: 'Reset factors' })).toBeNull()
  expect((screen.getAllByRole('button').find(b => b.textContent?.includes('Suspend')))).toBeUndefined()
})

it('shows an error instead of a lossy form when the organization cannot be loaded', async () => {
  orgFails = true
  open('organizations/org1')
  await screen.findByText('unavailable')
  expect(screen.queryByRole('switch', { name: 'Require a second factor' })).toBeNull()
  expect(calls('PATCH')).toHaveLength(0)
})
