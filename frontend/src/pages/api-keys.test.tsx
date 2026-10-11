// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
let calls: { method: string; path: string; search: string; body?: Record<string, unknown> }[]
let keys: Record<string, unknown>[]
let policy: Record<string, unknown>
let resource: Record<string, unknown>
let role = 'owner'

const key = (over: Record<string, unknown>) => ({
  id: 'k1', owner: { type: 'organization' }, organization_id: 'o1', organization_name: 'Acme', resource_id: 'r1', resource_name: 'Billing API', name: 'ERP sync',
  permissions: ['billing:read', 'billing:write', 'billing:admin'], obfuscated_value: 'ik_key_…wxyz', expires_at: '2999-01-01T00:00:00Z', expires: true, last_used_at: null, revoked_at: null,
  created_by: { kind: 'user', id: 'u-0000-1111' }, created_at: '2026-09-29T00:00:00Z', state: 'active', ...over,
})

beforeEach(() => {
  calls = []
  role = 'owner'
  keys = [
    key({}),
    key({ id: 'k2', name: 'laptop', owner: { type: 'user', user_id: 'u1' }, user_name: 'Alice', permissions: ['billing:read'], expires: false, state: 'revoked', created_by: { kind: 'user', id: 'u1' } }),
    key({ id: 'k3', name: 'etl', owner: { type: 'machine', user_id: 'm1' }, user_name: 'etl-bot', permissions: null, application_id: 'a1', application_name: 'Billing', created_by: { kind: 'operator', id: 'op1' } }),
  ]
  policy = { user_keys: true, organization_keys: false, max_ttl_days: null, max_per_user: 10, max_per_organization: 50, updated_at: '2026-09-01T00:00:00Z' }
  resource = { id: 'r1', name: 'Billing API', prefix: 'billing', audience: 'https://billing', permissions: ['billing:read', 'billing:write'], owner_organization_id: null, require_grant: false, api_key_permissions: { user: ['billing:read'], organization: [] } }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path, search = ''] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    if (method !== 'GET') calls.push({ method, path, search, body })
    else calls.push({ method, path, search })
    if (method === 'POST' && path === `${env}/api-keys`) return Response.json({ ...key({ id: 'k9', name: body.name }), value: 'ik_key_the_whole_secret' }, { status: 201 })
    if (method === 'DELETE' && path === `${env}/api-keys/k1`) { keys = keys.map(k => k.id === 'k1' ? { ...k, state: 'revoked' } : k); return new Response(null, { status: 204 }) }
    if (method === 'PUT' && path === `${env}/api-key-policy`) { policy = { ...body, updated_at: '2026-09-02T00:00:00Z' }; return Response.json(policy) }
    if (method === 'PUT' && path === `${env}/resources/r1/api-key-permissions`) { resource = { ...resource, api_key_permissions: body }; return new Response(null, { status: 204 }) }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/api-keys` ? page(keys) :
            path === `${env}/api-key-policy` ? policy :
              path === `${env}/resources` ? page([{ ...resource, api_key_permissions: { user: [], organization: ['billing:read', 'billing:write'] } }, { id: 'r2', name: 'Plain API', permissions: ['x'], api_key_permissions: { user: [], organization: [] } }]) :
                path === `${env}/resources/r1` ? resource :
                  path === `${env}/organizations` ? page([{ id: 'o1', name: 'Acme' }]) :
                    path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('lists keys with their owner, permissions, expiry and state, and filters by owner type', async () => {
  const u = userEvent.setup()
  open('api-keys')
  expect(await screen.findByText('ERP sync')).toBeTruthy()
  expect(screen.getAllByText('ik_key_…wxyz').length).toBe(3)
  const machine = screen.getByText('etl').closest('tr')!
  expect(within(machine).getByText('All of the machine user\'s permissions')).toBeTruthy()
  expect(within(machine).getByText('etl-bot')).toBeTruthy()
  expect(within(machine).getByText('Operator')).toBeTruthy()
  const human = screen.getByText('laptop').closest('tr')!
  expect(within(human).getByText('Never')).toBeTruthy()
  expect(within(human).getByText('Revoked')).toBeTruthy()
  expect(within(human).getByText('Alice')).toBeTruthy()
  const org = screen.getByText('ERP sync').closest('tr')!
  expect(within(org).getByText('+1 more')).toBeTruthy()
  await u.selectOptions(screen.getByLabelText('Owner type'), 'machine')
  await waitFor(() => expect(calls.some(c => c.path === `${env}/api-keys` && new URLSearchParams(c.search).get('owner_type') === 'machine')).toBe(true))
  await u.selectOptions(screen.getByLabelText('State'), 'revoked')
  await waitFor(() => expect(calls.some(c => c.path === `${env}/api-keys` && c.search.includes('state=revoked') && c.search.includes('owner_type=machine'))).toBe(true))
})

it('revokes an active key after confirming', async () => {
  const u = userEvent.setup()
  open('api-keys')
  await screen.findByText('ERP sync')
  expect(screen.queryByRole('button', { name: 'Actions for laptop' })).toBeNull()
  await u.click(screen.getByRole('button', { name: 'Actions for ERP sync' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Revoke' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('Revoke ERP sync?')).toBeTruthy()
  await u.click(within(dialog).getByRole('button', { name: 'Revoke' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.path === `${env}/api-keys/k1`)).toBe(true))
})

it('creates an organization key limited to the resource allowlist and shows the value once', async () => {
  const u = userEvent.setup()
  open('api-keys')
  await screen.findByText('ERP sync')
  await u.click(screen.getAllByRole('button', { name: /Create organization key/ })[0])
  const dialog = await screen.findByRole('dialog')
  expect(await within(dialog).findByText(/Organization keys are turned off/)).toBeTruthy()
  await u.type(within(dialog).getByLabelText('Name'), 'Reports')
  const box = within(dialog).getByLabelText('Organization')
  await waitFor(() => expect((box as HTMLInputElement).disabled).toBe(false))
  await u.click(box)
  fireEvent.mouseDown(await screen.findByText('Acme', { selector: 'li > span' }))
  const resourceSelect = within(dialog).getByLabelText('Resource')
  await waitFor(() => expect(within(resourceSelect).getByRole('option', { name: 'Billing API' })).toBeTruthy())
  // Resources whose allowlist for organization keys is empty are not offered.
  expect(within(resourceSelect).queryByRole('option', { name: 'Plain API' })).toBeNull()
  await u.selectOptions(resourceSelect, 'r1')
  await u.click(within(dialog).getByLabelText('billing:write'))
  const expiry = within(dialog).getByLabelText<HTMLSelectElement>('Expires in')
  expect(expiry.value).toBe('2160h')
  expect([...expiry.options].map(o => o.text)).toEqual(['30 days', '90 days', '1 year', 'Never'])
  await u.selectOptions(expiry, 'never')
  await u.click(within(dialog).getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(calls).toContainEqual(expect.objectContaining({ method: 'POST', path: `${env}/api-keys`, body: { organization_id: 'o1', resource_id: 'r1', name: 'Reports', permissions: ['billing:write'], expires_in: 'never' } })))
  const secret = await screen.findByRole('dialog', { name: 'API key created' })
  expect(within(secret).getByText('ik_key_the_whole_secret')).toBeTruthy()
  expect(within(secret).getByText(/shown only once/)).toBeTruthy()
  await u.click(within(secret).getByRole('button', { name: 'I have saved the key' }))
  expect(screen.queryByText('ik_key_the_whole_secret')).toBeNull()
})

it('hides write actions from viewers', async () => {
  role = 'viewer'
  open('api-keys')
  await screen.findByText('ERP sync')
  expect(screen.queryByRole('button', { name: /Create organization key/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for ERP sync' })).toBeNull()
})

it('edits the API key policy: toggles, a lifetime cap and limits', async () => {
  const u = userEvent.setup()
  open('api-key-policy')
  const orgKeys = await screen.findByRole('switch', { name: /Organization keys/ })
  expect((screen.getByRole('switch', { name: /User keys/ }) as HTMLInputElement).checked).toBe(true)
  expect((orgKeys as HTMLInputElement).checked).toBe(false)
  expect(screen.getByRole('button', { name: 'Save policy' }).hasAttribute('disabled')).toBe(true)
  await u.click(orgKeys)
  await u.click(screen.getByRole('switch', { name: /Limit the lifetime/ }))
  const days = screen.getByLabelText('Maximum lifetime (days)')
  await u.clear(days)
  await u.type(days, '120')
  const perUser = screen.getByLabelText('Keys per user')
  await u.clear(perUser)
  await u.type(perUser, '5')
  await u.click(screen.getByRole('button', { name: 'Save policy' }))
  await waitFor(() => expect(calls).toContainEqual(expect.objectContaining({ method: 'PUT', path: `${env}/api-key-policy`, body: { user_keys: true, organization_keys: true, max_ttl_days: 120, max_per_user: 5, max_per_organization: 50 } })))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Save policy' }).hasAttribute('disabled')).toBe(true))
  expect((screen.getByLabelText('Keys per user') as HTMLInputElement).value).toBe('5')
})

it('sends a null lifetime when the cap is off', async () => {
  policy = { ...policy, max_ttl_days: 30 }
  const u = userEvent.setup()
  open('api-key-policy')
  expect((await screen.findByLabelText<HTMLInputElement>('Maximum lifetime (days)')).value).toBe('30')
  await u.click(screen.getByRole('switch', { name: /Limit the lifetime/ }))
  expect(screen.queryByLabelText('Maximum lifetime (days)')).toBeNull()
  await u.click(screen.getByRole('button', { name: 'Save policy' }))
  await waitFor(() => expect(calls.find(c => c.method === 'PUT')?.body).toMatchObject({ max_ttl_days: null }))
})

it('saves the allowlist of a resource per kind of key and hints that organization keys are off', async () => {
  const u = userEvent.setup()
  open('resources/r1')
  expect(await screen.findByText(/Organization keys are turned off in the environment/)).toBeTruthy()
  const user = screen.getByLabelText('User keys: billing:read') as HTMLInputElement
  expect(user.checked).toBe(true)
  expect((screen.getByLabelText('Organization keys: billing:read') as HTMLInputElement).checked).toBe(false)
  const save = screen.getByRole('button', { name: 'Save API key permissions' })
  expect(save.hasAttribute('disabled')).toBe(true)
  await u.click(screen.getByLabelText('Organization keys: billing:write'))
  await u.click(screen.getByLabelText('User keys: billing:write'))
  await u.click(user)
  await u.click(save)
  await waitFor(() => expect(calls).toContainEqual(expect.objectContaining({ method: 'PUT', path: `${env}/resources/r1/api-key-permissions`, body: { user: ['billing:write'], organization: ['billing:write'] } })))
})

it('explains why the IAM resource has no key permissions', async () => {
  resource = { ...resource, id: 'r1', name: 'IAMKit', audience: 'iam', prefix: 'iam', permissions: ['iam:users:read'], api_key_permissions: { user: [], organization: [] } }
  open('resources/r1')
  expect(await screen.findByText(/IAMKit's own API is called with a service account or a machine user/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Save API key permissions' })).toBeNull()
})
