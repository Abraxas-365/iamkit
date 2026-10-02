// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { describeAction } from './activity'

const fetchMock = vi.fn()
const env = '/environments/env1'
let user: Record<string, unknown>
let patches: unknown[]

beforeEach(() => {
  user = { id: 'u1', name: 'Alice', email: 'alice@example.com', active: true, state: 'active', home_organization_id: null }
  patches = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (method === 'PATCH' && path === `${env}/users/u1`) {
      const body = JSON.parse(String(init.body))
      patches.push(body)
      user = { ...user, home_organization_id: body.home_organization_id || null }
      return new Response(null, { status: 204 })
    }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/users/u1` ? user :
            path === `${env}/users/u1/factors` ? { factors: [], recovery_codes_remaining: 0 } :
              path === `${env}/organizations` ? page([{ id: 'o1', name: 'Acme', active: true }]) :
                path === `${env}/roles` ? page([
                  { id: 'r1', name: 'Organization owner', resource_id: 'iam', resource_name: 'IAMKit', permissions: ['iam:org:read'], system_role: 'org_owner' },
                  { id: 'r2', name: 'Reader', resource_id: 'res', resource_name: 'Invoices', permissions: ['invoices:read'] },
                ]) :
                  path === `${env}/audit-events` ? page([
                    { id: '2', actor_id: 'u9', actor_label: 'owner@acme.io', actor_kind: 'user', action: 'user.deactivated', target_id: '/api/v1/environments/env1/organizations/o1/admin/users/u2/deactivate', created_at: '2026-09-29T10:00:00Z' },
                    { id: '1', actor_id: 'op1', actor_label: 'ops@vendor.io', actor_kind: 'operator', action: 'POST', target_id: '/management/v1/environments/env1/users', created_at: '2026-09-29T09:00:00Z' },
                  ]) :
                    path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('marks built-in roles and offers no edit or delete for them', async () => {
  const u = userEvent.setup()
  open('roles')
  expect(await screen.findByText('Built-in')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Actions for Organization owner' })).toBeNull()
  await u.click(screen.getByRole('button', { name: /Actions for Reader/ }))
  expect(await screen.findByRole('menuitem', { name: 'Delete role' })).toBeTruthy()
})

it('sets and clears the home organization of a user', async () => {
  const u = userEvent.setup()
  open('users/u1')
  await screen.findByText('Acme')
  await u.click(screen.getByRole('button', { name: 'Actions for Acme' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Make home organization' }))
  await waitFor(() => expect(patches).toEqual([{ home_organization_id: 'o1' }]))
  expect(await screen.findByText('Home')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Actions for Acme' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Clear home organization' }))
  await waitFor(() => expect(patches.at(-1)).toEqual({ home_organization_id: '' }))
})

it('labels audit events made by end users', async () => {
  open('audit-events')
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Change log' }))
  const row = (await screen.findByText('owner@acme.io')).closest('tr') as HTMLElement
  expect(within(row).getByText('End user')).toBeTruthy()
  const operator = screen.getByText('ops@vendor.io').closest('tr') as HTMLElement
  expect(within(operator).queryByText('End user')).toBeNull()
})

it('describes organization administration paths', () => {
  const admin = '/api/v1/environments/env1/organizations/83c2749c-cc53-4163-8008-8754b79943a7/admin'
  expect(describeAction('POST', `${admin}/role-assignments`)).toBe('Created role assignment')
  expect(describeAction('PATCH', admin)).toBe('Updated organization')
})
