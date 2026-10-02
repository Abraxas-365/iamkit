// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import OrgAdminPortal from './portal'

const fetchMock = vi.fn()
const assign = vi.fn()
let enabled = true
let calls: { url: string; method: string; body?: unknown; auth?: string }[] = []

function jwt(claims: Record<string, unknown>) {
  const part = (v: unknown) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(v)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${part({ alg: 'none' })}.${part(claims)}.sig`
}
function signedIn(permissions: string[]) {
  sessionStorage.setItem('iamkit-org-admin:env1', JSON.stringify({ access_token: jwt({ organization_id: 'org1', permissions, email: 'alice@acme.test' }), refresh_token: 'rt', expires_at: Date.now() + 60_000 }))
}
const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })

beforeEach(() => {
  enabled = true
  calls = []
  sessionStorage.clear()
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('location', { ...window.location, assign })
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET'
    calls.push({ url, method, body: init.body ? JSON.parse(String(init.body)) : undefined, auth: (init.headers as Record<string, string> | undefined)?.Authorization })
    if (url === '/identity/v1/org-admin/env1') return enabled ? Response.json({ client_id: 'client1', environment_id: 'env1', url: 'https://iam.example/org-admin/env1' }) : Response.json({ error: { message: 'not found' } }, { status: 404 })
    const path = url.replace('/api/v1/environments/env1/organizations/org1/admin', '').split('?')[0]
    if (method === 'PATCH' || method === 'DELETE') return new Response(null, { status: 204 })
    if (path === '') return Response.json({ id: 'org1', name: 'Acme', mfa_required: false, mfa_for_federated: false, allow_password: true, allow_email_code: true, allow_social: true, allow_passkey: true })
    if (path === '/members') return Response.json(page([{ user_id: 'u1', user_name: 'Bob', user_email: 'bob@acme.test', active: true, sso_bypass: false }]))
    if (path === '/events') return Response.json(page([
      { id: '2', actor_id: 'u9', actor_kind: 'user', actor_label: 'alice@acme.test', action: 'user.deactivated', target_id: 'u2', created_at: '2026-09-29T10:00:00Z' },
      { id: '1', actor_id: 'op-0000-uuid', actor_kind: 'operator', actor_label: '', action: 'POST', target_id: '/management/v1/environments/env1/organizations/org1/domains', created_at: '2026-09-29T09:00:00Z' },
    ]))
    return Response.json(page([]))
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

function open(path: string) {
  const router = createMemoryRouter([{ path: '/org-admin/*', element: <OrgAdminPortal /> }], { initialEntries: [path] })
  render(<RouterProvider router={router} />)
  return router
}

it('asks to sign in and forwards the organization hint to the hosted login', async () => {
  const user = userEvent.setup()
  open('/org-admin/env1?organization_id=org1')
  await user.click(await screen.findByRole('button', { name: 'Sign in' }))
  await waitFor(() => expect(assign).toHaveBeenCalled())
  const q = new URL(assign.mock.calls[0][0], 'https://iam.example').searchParams
  expect(q.get('client_id')).toBe('client1')
  expect(q.get('organization_id')).toBe('org1')
})

it('explains when the portal is off', async () => {
  enabled = false
  open('/org-admin/env1')
  expect(await screen.findByText(/not available for this environment/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Sign in' })).toBeNull()
})

it('shows only the pages the token allows and calls /admin with the bearer token', async () => {
  signedIn(['iam:org:read', 'iam:org:members:read'])
  open('/org-admin/env1')
  const nav = await screen.findByRole('navigation', { name: 'Organization administration' })
  expect(within(nav).getByRole('link', { name: 'Members' })).toBeTruthy()
  expect(within(nav).queryByRole('link', { name: 'Roles' })).toBeNull()
  expect(within(nav).queryByRole('link', { name: 'Activity' })).toBeNull()
  expect(await screen.findByRole('heading', { name: 'Acme' })).toBeTruthy()
  // Read-only: no settings writes without iam:org:settings:write.
  expect(screen.queryByRole('button', { name: 'Save settings' })).toBeNull()
  const admin = calls.find(c => c.url.startsWith('/api/v1/'))!
  expect(admin.url).toBe('/api/v1/environments/env1/organizations/org1/admin')
  expect(admin.auth).toMatch(/^Bearer /)
})

it('removes a member when allowed', async () => {
  const user = userEvent.setup()
  signedIn(['iam:org:read', 'iam:org:members:read', 'iam:org:members:write'])
  open('/org-admin/env1/members')
  await user.click(await screen.findByRole('button', { name: 'Actions for bob@acme.test' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Remove from organization' }))
  await user.click(await screen.findByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.url.endsWith('/admin/members/u1'))).toBe(true))
})

it('turns away a member without administration roles', async () => {
  signedIn([])
  open('/org-admin/env1')
  expect(await screen.findByText(/does not administer this organization/)).toBeTruthy()
  expect(calls.some(c => c.url.startsWith('/api/v1/'))).toBe(false)
})

it('shows platform operators by kind in the activity, never by ID', async () => {
  signedIn(['iam:org:read', 'iam:org:audit:read'])
  open('/org-admin/env1/activity')
  expect(await screen.findByText('alice@acme.test')).toBeTruthy()
  expect(screen.getByText('Platform administrator')).toBeTruthy()
  expect(screen.queryByText('op-0000-uuid')).toBeNull()
})
