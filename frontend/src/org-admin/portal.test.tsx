// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import OrgAdminPortal from './portal'

const fetchMock = vi.fn()
const assign = vi.fn()
let enabled = true
let keysEnabled = true
let calls: { url: string; method: string; body?: unknown; auth?: string }[] = []

function jwt(claims: Record<string, unknown>) {
  const part = (v: unknown) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(v)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${part({ alg: 'none' })}.${part(claims)}.sig`
}
function signedIn(permissions: string[]) {
  sessionStorage.setItem('iamkit-org-admin:env1', JSON.stringify({ access_token: jwt({ organization_id: 'org1', permissions }), refresh_token: 'rt', expires_at: Date.now() + 60_000 }))
}
const apiKey = (over: Record<string, unknown>) => ({
  id: 'k1', owner: { type: 'organization' }, organization_id: 'org1', organization_name: 'Acme', resource_id: 'r1', resource_name: 'Billing API', name: 'ERP sync', permissions: ['billing:read'],
  obfuscated_value: 'ik_key_…wxyz', expires_at: '2999-01-01T00:00:00Z', expires: true, last_used_at: null, revoked_at: null, created_by: { kind: 'machine', id: 'abc' }, created_at: '2026-09-29T00:00:00Z', state: 'active', ...over,
})
const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })

beforeEach(() => {
  enabled = true
  keysEnabled = true
  calls = []
  sessionStorage.clear()
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('location', { ...window.location, assign })
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET'
    calls.push({ url, method, body: init.body ? JSON.parse(String(init.body)) : undefined, auth: (init.headers as Record<string, string> | undefined)?.Authorization })
    if (url === '/identity/v1/org-admin/env1') return enabled ? Response.json({ client_id: 'client1', environment_id: 'env1', url: 'https://iam.example/org-admin/env1' }) : Response.json({ error: { message: 'not found' } }, { status: 404 })
    if (url === '/oauth/userinfo') return Response.json({ sub: 'u9', email: 'owner@acme.test', name: 'Olivia Owner' })
    const path = url.replace('/api/v1/environments/env1/organizations/org1/admin', '').split('?')[0]
    if (method === 'POST' && path === '/directories') return Response.json({ id: 'c2', secret: 'ik_scim_topsecret', expires_at: '2027-01-01T00:00:00Z', connection_id: 'k1', scim_url: 'https://iam.example/scim/v2' }, { status: 201 })
    if (method === 'POST' && path === '/api-keys') return Response.json({ ...apiKey({ id: 'k9', name: JSON.parse(String(init.body)).name }), value: 'ik_key_org_secret' }, { status: 201 })
    if (method === 'GET' && path === '/api-keys/options') return Response.json({ enabled: keysEnabled, max_ttl_days: 100, resources: [{ id: 'r1', name: 'Billing API', audience: 'https://billing', permissions: ['billing:read', 'billing:write'] }] })
    if (method === 'GET' && path === '/api-keys') {
      const owner = new URLSearchParams(url.split('?')[1]).get('owner_type')
      return Response.json(page(owner === 'user'
        ? [apiKey({ id: 'k2', name: 'laptop', owner: { type: 'user', user_id: 'u1' }, user_name: 'Alice Member', created_by: { kind: 'user', id: 'u1' } })]
        : [apiKey({})]))
    }
    if (method === 'POST' && path === '/log-streams') return Response.json({ id: 'ls2' }, { status: 201 })
    if (method === 'POST' && path === '/connections') return Response.json({ id: 'draft1' }, { status: 201 })
    if (method === 'POST' && path === '/connections/draft1/enable') return new Response(null, { status: 204 })
    if (method === 'GET' && path === '/connections/draft1') return Response.json({ id: 'draft1', draft: true, saml: { entity_id: 'https://iam.example/sp/env1/draft1', acs_url: 'https://iam.example/acs/env1/draft1', metadata_url: 'https://iam.example/sp/env1/draft1/metadata' } })
    if (method === 'PATCH' || method === 'DELETE') return new Response(null, { status: 204 })
    if (path === '/directories') return Response.json({ ...page([{ id: 'c1', name: 'Okta', connection_id: 'k1', expires_at: '2099-01-01T00:00:00Z', revoked_at: null, adopt_existing_members: false, adopt_scope: 'any', map_phone: false }]), scim_url: 'https://iam.example/scim/v2' })
    if (path === '') return Response.json({ id: 'org1', name: 'Acme', mfa_required: false, mfa_for_federated: false, allow_password: true, allow_email_code: true, allow_social: true, allow_passkey: true })
    if (path === '/members') return Response.json(page([{ user_id: 'u1', user_name: 'Bob', user_email: 'bob@acme.test', active: true, sso_bypass: false }]))
    if (path === '/audit-logs/export') return new Response('{"id":"e1"}\n', { status: 200 })
    if (path === '/audit-logs') return Response.json({ items: [{ seq: 2, id: 'e2', action: 'invoice.created', version: 1, occurred_at: '2026-09-29T10:00:00Z', created_at: '2026-09-29T10:00:00Z', actor: { type: 'user', id: 'u1', name: 'Alice' }, targets: [{ type: 'invoice', id: 'i1' }] }], next: 0 })
    if (path === '/log-streams') return Response.json({ items: [{ id: 'ls1', name: 'Org SIEM', destination: 'https', config: { url: 'https://logs.example/in' }, sources: ['audit_logs'], secret_set: true, active: true, pending: 0, created_at: '2026-09-29T10:00:00Z', updated_at: '2026-09-29T10:00:00Z' }] })
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

it('shows who is signed in from UserInfo, since the tokens carry no email', async () => {
  signedIn(['iam:org:read'])
  open('/org-admin/env1')
  expect(await within(await screen.findByRole('banner')).findByText('owner@acme.test')).toBeTruthy()
  expect(calls.find(c => c.url === '/oauth/userinfo')?.auth).toMatch(/^Bearer /)
})

it('shows platform operators by kind in the activity, never by ID', async () => {
  signedIn(['iam:org:read', 'iam:org:audit:read'])
  open('/org-admin/env1/activity')
  expect(await screen.findByText('alice@acme.test')).toBeTruthy()
  expect(screen.getByText('Platform administrator')).toBeTruthy()
  expect(screen.queryByText('op-0000-uuid')).toBeNull()
})

it('lists directory tokens with the SCIM URL, and creates and revokes them with iam:org:sso:write', async () => {
  const user = userEvent.setup()
  signedIn(['iam:org:read', 'iam:org:sso:write'])
  open('/org-admin/env1/directory')
  expect(await screen.findByText('Okta')).toBeTruthy()
  expect(screen.getByText('https://iam.example/scim/v2')).toBeTruthy()

  await user.click(screen.getByRole('button', { name: 'Add token' }))
  await user.type(await screen.findByLabelText('Name'), 'Entra')
  await user.click(screen.getByRole('button', { name: 'Issue token' }))
  // The secret is shown once, with the SCIM URL.
  expect(await screen.findByText('ik_scim_topsecret')).toBeTruthy()
  const post = calls.find(c => c.method === 'POST' && c.url.endsWith('/admin/directories'))!
  expect(post.body).toMatchObject({ name: 'Entra', expires_in: '8760h', adopt_existing_members: false, map_phone: false })
  await user.click(screen.getByRole('button', { name: 'I have saved the token' }))
  expect(screen.queryByText('ik_scim_topsecret')).toBeNull()

  await user.click(await screen.findByRole('button', { name: 'Actions for Okta' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Revoke token' }))
  await user.click(await screen.findByRole('button', { name: 'Revoke token' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.url.endsWith('/admin/directories/c1'))).toBe(true))
})

it('hides directory writes without iam:org:sso:write', async () => {
  signedIn(['iam:org:read'])
  open('/org-admin/env1/directory')
  expect(await screen.findByText('Okta')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Add token' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for Okta' })).toBeNull()
})

it('shows the Setup links page only to accounts holding every organization permission', async () => {
  const all = ['iam:org:read', 'iam:org:settings:write', 'iam:org:members:read', 'iam:org:members:write', 'iam:org:users:write', 'iam:org:roles:read', 'iam:org:roles:assign', 'iam:org:invitations:write', 'iam:org:domains:write', 'iam:org:sso:write', 'iam:org:audit:read', 'iam:org:resources:read', 'iam:org:resources:write', 'iam:org:log-streams:write', 'iam:org:api-keys:read', 'iam:org:api-keys:write']
  signedIn(all)
  open('/org-admin/env1/setup-links')
  expect(await screen.findByRole('button', { name: 'Create setup link' })).toBeTruthy()
  expect(within(screen.getByRole('navigation', { name: 'Organization administration' })).getByRole('link', { name: 'Setup links' })).toBeTruthy()
  cleanup()
  signedIn(['iam:org:read', 'iam:org:sso:write'])
  open('/org-admin/env1')
  const nav = await screen.findByRole('navigation', { name: 'Organization administration' })
  expect(within(nav).queryByRole('link', { name: 'Setup links' })).toBeNull()
})

it('lists audit logs and exports them with the bearer token to those holding iam:org:audit:read', async () => {
  const user = userEvent.setup()
  const url = vi.fn(() => 'blob:x')
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: url, revokeObjectURL: vi.fn() }))
  signedIn(['iam:org:read', 'iam:org:audit:read'])
  open('/org-admin/env1/audit-logs')
  expect(await screen.findByText('invoice.created')).toBeTruthy()
  expect(screen.queryByLabelText('Organization')).toBeNull()
  await user.click(screen.getByRole('button', { name: /Export CSV/ }))
  await waitFor(() => expect(calls.some(c => c.url.includes('/admin/audit-logs/export?') && c.url.includes('format=csv') && c.auth?.startsWith('Bearer '))).toBe(true))
  const nav = within(screen.getByRole('navigation', { name: 'Organization administration' }))
  expect(nav.getByRole('link', { name: 'Audit logs' })).toBeTruthy()
  expect(nav.getByRole('link', { name: 'Log streams' })).toBeTruthy()
})

it('hides Audit logs without iam:org:audit:read, and lets log-stream writers manage streams only', async () => {
  signedIn(['iam:org:read', 'iam:org:log-streams:write'])
  open('/org-admin/env1')
  const nav = within(await screen.findByRole('navigation', { name: 'Organization administration' }))
  expect(nav.queryByRole('link', { name: 'Audit logs' })).toBeNull()
  expect(nav.getByRole('link', { name: 'Log streams' })).toBeTruthy()
  cleanup()
  signedIn(['iam:org:read', 'iam:org:audit:read'])
  const user = userEvent.setup()
  open('/org-admin/env1/log-streams')
  expect(await screen.findByText('Org SIEM')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Add log stream' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for Org SIEM' })).not.toBeNull()
  await user.click(screen.getByRole('button', { name: 'Actions for Org SIEM' }))
  expect(screen.queryByRole('menuitem', { name: 'Delete' })).toBeNull()
})

it('creates organization log streams without a sources choice', async () => {
  const user = userEvent.setup()
  signedIn(['iam:org:read', 'iam:org:log-streams:write'])
  open('/org-admin/env1/log-streams')
  await screen.findByText('Org SIEM')
  await user.click(screen.getAllByRole('button', { name: 'Add log stream' })[0])
  expect(screen.queryByText('Sources')).toBeNull()
  await user.type(screen.getByLabelText('Name'), 'Mine')
  await user.type(screen.getByLabelText('API key'), 'dd-key')
  await user.click(screen.getByRole('button', { name: 'Create log stream' }))
  await waitFor(() => expect(calls.find(c => c.method === 'POST' && c.url.endsWith('/admin/log-streams'))?.body).toEqual({ name: 'Mine', destination: 'datadog', config: { site: 'datadoghq.com' }, secret: 'dd-key' }))
})

it('lists organization keys and members\' keys in two tabs and revokes with the bearer token', async () => {
  const user = userEvent.setup()
  signedIn(['iam:org:read', 'iam:org:api-keys:read', 'iam:org:api-keys:write'])
  open('/org-admin/env1/api-keys')
  expect(await screen.findByText('ERP sync')).toBeTruthy()
  expect(within(screen.getByRole('navigation', { name: 'Organization administration' })).getByRole('link', { name: 'API keys' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'Organization keys' }).getAttribute('aria-selected')).toBe('true')
  expect(screen.getByText('Machine user')).toBeTruthy()
  await user.click(screen.getByRole('tab', { name: 'Members\' keys' }))
  expect(await screen.findByText('laptop')).toBeTruthy()
  expect(screen.getByText('Alice Member')).toBeTruthy()
  expect(screen.queryByText('ERP sync')).toBeNull()
  expect(calls.some(c => c.url.includes('/admin/api-keys?') && c.url.includes('owner_type=user'))).toBe(true)
  await user.click(screen.getByRole('button', { name: 'Actions for laptop' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Revoke' }))
  await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Revoke' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.url.endsWith('/admin/api-keys/k2') && c.auth?.startsWith('Bearer '))).toBe(true))
})

it('creates an organization key within the offered resources and lifetimes, showing the value once', async () => {
  const user = userEvent.setup()
  signedIn(['iam:org:read', 'iam:org:api-keys:read', 'iam:org:api-keys:write'])
  open('/org-admin/env1/api-keys')
  await screen.findByText('ERP sync')
  await waitFor(() => expect(screen.getAllByRole('button', { name: /Create API key/ })[0].hasAttribute('disabled')).toBe(false))
  await user.click(screen.getAllByRole('button', { name: /Create API key/ })[0])
  const dialog = await screen.findByRole('dialog')
  await user.type(within(dialog).getByLabelText('Name'), 'Billing export')
  await user.selectOptions(within(dialog).getByLabelText('Resource'), 'r1')
  await user.click(within(dialog).getByLabelText('billing:read'))
  // The environment caps lifetimes at 100 days: 30 and 90 days fit, 1 year and never do not.
  const expiry = within(dialog).getByLabelText<HTMLSelectElement>('Expires in')
  expect([...expiry.options].map(o => o.text)).toEqual(['30 days', '90 days', '100 days'])
  expect(expiry.value).toBe('2160h')
  await user.click(within(dialog).getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(calls.find(c => c.method === 'POST' && c.url.endsWith('/admin/api-keys'))?.body).toEqual({ resource_id: 'r1', name: 'Billing export', permissions: ['billing:read'], expires_in: '2160h' }))
  const secret = await screen.findByRole('dialog', { name: 'API key created' })
  expect(within(secret).getByText('ik_key_org_secret')).toBeTruthy()
  expect(within(secret).getByText(/shown only once/)).toBeTruthy()
  await user.click(within(secret).getByRole('button', { name: 'I have saved the key' }))
  expect(screen.queryByText('ik_key_org_secret')).toBeNull()
})

it('tells admins that the operator must enable organization keys and disables creating them', async () => {
  keysEnabled = false
  signedIn(['iam:org:read', 'iam:org:api-keys:read', 'iam:org:api-keys:write'])
  open('/org-admin/env1/api-keys')
  expect(await screen.findByText(/The operator of this environment must enable organization keys/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: /Create API key/ })).toBeNull()
  expect(screen.getByText('ERP sync')).toBeTruthy()
})

it('shows API keys read-only to accounts without the write permission and hides the page without read', async () => {
  signedIn(['iam:org:read', 'iam:org:api-keys:read'])
  open('/org-admin/env1/api-keys')
  expect(await screen.findByText('ERP sync')).toBeTruthy()
  expect(screen.queryByRole('button', { name: /Create API key/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for ERP sync' })).toBeNull()
  expect(calls.some(c => c.url.endsWith('/api-keys/options'))).toBe(false)
  cleanup()
  signedIn(['iam:org:read'])
  open('/org-admin/env1')
  const nav = await screen.findByRole('navigation', { name: 'Organization administration' })
  expect(within(nav).queryByRole('link', { name: 'API keys' })).toBeNull()
})

it('walks an organization administrator through the guided SSO setup and keeps Advanced', async () => {
  const user = userEvent.setup()
  signedIn(['iam:org:read', 'iam:org:sso:write'])
  open('/org-admin/env1/sso')
  expect(await screen.findByRole('button', { name: 'Advanced' })).toBeTruthy()

  await user.click(screen.getByRole('button', { name: 'Add SSO' }))
  await user.click(within(await screen.findByRole('group', { name: 'SAML 2.0' })).getByRole('button', { name: 'Okta' }))
  await user.click(screen.getByRole('button', { name: 'Continue' }))
  // The draft is created through the portal's own /admin route, then its values are read back.
  expect(await screen.findByText('https://iam.example/acs/env1/draft1')).toBeTruthy()
  const create = calls.find(c => c.method === 'POST' && c.url.endsWith('/admin/connections'))!
  expect(create.body).toEqual({ provider: 'saml', name: 'Okta', organization_id: 'org1', draft: true, options: {} })
  expect(create.auth).toMatch(/^Bearer /)

  await user.click(screen.getByRole('button', { name: 'I have done this' }))
  await user.type(screen.getByLabelText('Identity provider metadata URL'), 'https://acme.okta.example/metadata')
  await user.click(screen.getByRole('button', { name: 'Save metadata' }))
  await waitFor(() => expect(calls.some(c => c.method === 'PATCH' && c.url.endsWith('/admin/connections/draft1') && JSON.stringify(c.body) === JSON.stringify({ options: { metadata_url: 'https://acme.okta.example/metadata' } }))).toBe(true))

  await user.click(await screen.findByRole('button', { name: 'Enable connection' }))
  await waitFor(() => expect(calls.some(c => c.method === 'POST' && c.url.endsWith('/admin/connections/draft1/enable'))).toBe(true))
}, 20_000)
