// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { connectionPatch } from './federation-detail'

const fetchMock = vi.fn()
const env = '/environments/env1'
const conn = { id: 'c1', organization_id: 'org1', name: 'Acme Entra', issuer: 'https://login.example', client_id: 'acme', secret_env: '', secret_source: 'sealed' as const, active: true, linked: 2, jit_provisioning: true, jit_group_id: null, enforcement: 'enforced' as const, created_at: '2026-01-01T00:00:00Z' }
const members = [
  { user_id: 'u1', user_name: 'Alice', user_email: 'alice@acme.com', active: true, manager_id: null, manager_name: null, sso_bypass: true },
  { user_id: 'u2', user_name: 'Bob', user_email: 'bob@acme.com', active: true, manager_id: null, manager_name: null, sso_bypass: false },
]

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method && init.method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/organizations/org1` ? { id: 'org1', name: 'Acme' } :
            path === `${env}/organizations/org1/members` ? page(members) :
              path === `${env}/organizations/org1/domains` ? page([{ id: 'd1', domain: 'acme.com', verified: true }, { id: 'd2', domain: 'pending.example', verified: false }]) :
              path === `${env}/federation-connections/c1` ? conn :
                path === `${env}/federation-connections/c1/identities` ? page([{ connection_id: 'c1', subject: 'sub-1', user_id: 'u2', user_name: 'Bob', user_email: 'bob@acme.com', origin: 'jit', created_at: '2026-01-01T00:00:00Z' }]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('shows organization SSO settings and identity origin', async () => {
  open('/projects/project1/environments/env1/federation/c1')
  await screen.findByText('Acme Entra')
  expect(screen.getByText('Stored encrypted')).toBeTruthy()
  expect(screen.getByText(/Enforced: password login blocked/)).toBeTruthy()
  expect(screen.getByText('On, no default group')).toBeTruthy()
  expect(await screen.findByText('Just-in-time')).toBeTruthy()
})

it('patches only changed connection fields', () => {
  expect(connectionPatch(conn, { name: 'Acme Entra', client_secret: '', jit_provisioning: true, jit_group_id: '', enforcement: 'enforced' })).toEqual({})
  expect(connectionPatch(conn, { name: 'Acme', client_secret: 's', jit_provisioning: true, jit_group_id: 'g1', enforcement: 'optional' })).toEqual({ name: 'Acme', client_secret: 's', jit_group_id: 'g1', enforcement: 'optional' })
  expect(connectionPatch({ ...conn, jit_group_id: 'g1' }, { name: 'Acme Entra', client_secret: '', jit_provisioning: true, jit_group_id: '', enforcement: 'enforced' })).toEqual({ jit_group_id: '' })
  expect(connectionPatch({ ...conn, organization_id: null }, { name: 'Acme Entra', client_secret: '' })).toEqual({})
  expect(connectionPatch(conn, { name: 'Acme Entra', client_secret: '', jit_provisioning: true, jit_group_id: '', enforcement: 'enforced', link_email: true })).toEqual({ link_email: true })
})

it('offers Google Workspace for organization SSO, limited to verified domains', async () => {
  open('/projects/project1/environments/env1/organizations/org1/connections')
  await userEvent.click(await screen.findByRole('button', { name: 'Add SSO connection' }))
  const dialog = await screen.findByRole('dialog', { name: 'Add SSO for Acme' })
  const options = [...dialog.querySelectorAll('button[aria-pressed]')].map(b => b.textContent)
  expect(options).toEqual(['Microsoft Entra ID', 'Google Workspace', 'GitLab self-managed', 'Other (OIDC)', 'SAML 2.0', 'LDAP / AD'])
  expect(screen.getByText(/GitHub and Apple accounts are personal/)).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Google Workspace' }))
  // Pre-filled with the organization's verified domains only.
  expect(await screen.findByText('acme.com')).toBeTruthy()
  expect(screen.queryByText('pending.example')).toBeNull()
  await userEvent.type(screen.getByLabelText('Client ID'), 'gid')
  await userEvent.type(screen.getByLabelText(/Client secret/), 's')
  await userEvent.click(screen.getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${env}/federation-connections`, body: expect.objectContaining({ provider: 'google', organization_id: 'org1', options: { domains: ['acme.com'] } }) }]))
})

it('toggles the SSO bypass of a member', async () => {
  open('/projects/project1/environments/env1/organizations/org1/members')
  await screen.findByText('Alice')
  expect(screen.getByText('SSO bypass')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Bob' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Allow password sign-in (SSO bypass)' }))
  expect(screen.getByRole('dialog', { name: 'Grant SSO bypass for Bob?' })).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Grant bypass' }))
  await waitFor(() => expect(calls('PATCH')).toEqual([{ url: `/management/v1${env}/organizations/org1/members/u2`, body: { sso_bypass: true } }]))
})
