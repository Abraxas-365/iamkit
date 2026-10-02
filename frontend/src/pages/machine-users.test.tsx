// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const machine = { id: 'm1', kind: 'machine', name: 'billing-sync', email: '', active: true, state: 'active', last_signed_in_at: null }
let calls: { method: string; path: string; body: unknown }[]
let kinds: string[]
let tokens: Record<string, unknown>[]
let keys: Record<string, unknown>[]
let effective: Record<string, unknown>[]

beforeEach(() => {
  calls = []
  kinds = []
  tokens = [{ id: 't1', name: 'nightly', organization_id: 'o1', organization_name: 'Acme', application_id: 'a1', application_name: 'Billing', resource_id: 'r1', resource_name: 'Billing API', expires_at: '2999-01-01T00:00:00Z', last_used_at: null, revoked_at: null, created_at: '2026-09-29T00:00:00Z' }]
  keys = [{ id: 'k1', user_id: 'm1', public_key: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', use: 'sig' }, expires_at: '2999-01-01T00:00:00Z', last_used_at: null, created_at: '2026-09-29T00:00:00Z' }]
  effective = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path, search = ''] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (method === 'POST' && path === `${env}/users`) return Response.json({ id: 'm1' }, { status: 201 })
    if (method === 'DELETE' && path === `${env}/users/m1/access-tokens/t1`) { tokens = [{ ...tokens[0], revoked_at: '2026-09-29T00:00:00Z' }]; return new Response(null, { status: 204 }) }
    if (method === 'POST' && path === `${env}/users/m1/keys`) {
      const body = JSON.parse(String(init.body))
      const key = { id: 'k2', user_id: 'm1', public_key: body.public_key ?? { kty: 'RSA', n: 'A'.repeat(342), e: 'AQAB' }, expires_at: '2999-01-01T00:00:00Z', last_used_at: null, created_at: '2026-09-29T00:00:00Z' }
      keys = [...keys, key]
      return Response.json(body.public_key ? key : { ...key, private_key: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n' }, { status: 201 })
    }
    if (method === 'DELETE' && path === `${env}/users/m1/keys/k1`) { keys = keys.filter(k => k.id !== 'k1'); return new Response(null, { status: 204 }) }
    if (method !== 'GET') return new Response(null, { status: 204 })
    if (path === `${env}/users`) {
      const kind = new URLSearchParams(search).get('kind') ?? ''
      kinds.push(kind)
      return Response.json(page([machine]))
    }
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/users/m1` ? machine :
            path === `${env}/users/m1/access-tokens` ? page(tokens) :
              path === `${env}/users/m1/keys` ? page(keys) :
              path === `${env}/effective-roles` ? { items: effective } :
              path === `${env}/organizations` ? page([{ id: 'o1', name: 'Acme' }]) :
              path === `${env}/applications` ? page([{ id: 'a1', name: 'Billing' }]) :
              path === `${env}/applications/a1/resources` ? page([{ id: 'r1', name: 'Billing API' }, { id: 'r2', name: 'Reports API' }]) :
              path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('filters users by kind and creates a machine user', async () => {
  const u = userEvent.setup()
  open('users')
  expect(await screen.findByText('billing-sync')).toBeTruthy()
  expect(screen.getByText('Machine')).toBeTruthy()
  await u.selectOptions(screen.getByLabelText('Filter by kind'), 'machine')
  await waitFor(() => expect(kinds.at(-1)).toBe('machine'))
  await u.click(screen.getByRole('button', { name: /Create machine user/ }))
  const dialog = await screen.findByRole('dialog')
  await u.type(within(dialog).getByLabelText('Name'), 'ci-bot')
  await u.click(within(dialog).getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(calls).toContainEqual({ method: 'POST', path: `${env}/users`, body: { kind: 'machine', name: 'ci-bot' } }))
})

it('shows a machine user with its tokens instead of second factors and revokes one', async () => {
  const u = userEvent.setup()
  open('users/m1')
  expect(await screen.findByText('Machine user')).toBeTruthy()
  expect(await screen.findByText('nightly')).toBeTruthy()
  expect(screen.getByText('Billing API', { exact: false })).toBeTruthy()
  expect(screen.queryByText('Second factors')).toBeNull()
  await u.click(screen.getByRole('button', { name: 'Actions for nightly' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Revoke' }))
  const dialog = await screen.findByRole('dialog')
  await u.click(within(dialog).getByRole('button', { name: 'Revoke' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.path === `${env}/users/m1/access-tokens/t1`)).toBe(true))
  expect(await screen.findByText('Revoked')).toBeTruthy()
})

it('warns in the token dialog when the machine user holds no role on the resource', async () => {
  effective = [{ organization_id: 'o1', role_id: 'role1', role_name: 'Reader', resource_id: 'r1', resource_name: 'Billing API', source: 'direct' }]
  const u = userEvent.setup()
  open('users/m1')
  expect(await screen.findByText('nightly')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: /Create token/ }))
  const dialog = await screen.findByRole('dialog')
  const pick = async (label: string, option: string) => {
    const box = within(dialog).getByLabelText(label)
    await waitFor(() => expect((box as HTMLInputElement).disabled).toBe(false))
    await u.click(box)
    fireEvent.mouseDown(await screen.findByText(option, { selector: 'li > span' }))
  }
  await pick('Organization', 'Acme')
  await pick('Application', 'Billing')
  await pick('Resource', 'Reports API')
  expect(await within(dialog).findByRole('note', { name: 'No roles on this resource' })).toBeTruthy()
  await pick('Resource', 'Billing API')
  await waitFor(() => expect(within(dialog).queryByRole('note', { name: 'No roles on this resource' })).toBeNull())
})

it('generates a key pair once, uploads a public key and removes a key', async () => {
  const u = userEvent.setup()
  open('users/m1')
  expect(await screen.findByText('EC P-256')).toBeTruthy()

  await u.click(screen.getByRole('button', { name: /Add signing key/ }))
  let dialog = await screen.findByRole('dialog')
  await u.click(within(dialog).getByRole('button', { name: 'Generate' }))
  await waitFor(() => expect(calls).toContainEqual({ method: 'POST', path: `${env}/users/m1/keys`, body: { expires_in: '8760h' } }))
  dialog = await screen.findByRole('dialog', { name: 'Key created' })
  expect(within(dialog).getByText(/BEGIN PRIVATE KEY/)).toBeTruthy()
  expect(within(dialog).getByText('k2')).toBeTruthy()
  await u.click(within(dialog).getByRole('button', { name: 'I have saved the private key' }))
  expect(await screen.findByText('RSA 2048')).toBeTruthy()

  await u.click(screen.getByRole('button', { name: /Add signing key/ }))
  dialog = await screen.findByRole('dialog')
  await u.click(within(dialog).getByLabelText(/Upload a public key/))
  const field = within(dialog).getByLabelText('Public key (JWK)')
  await u.type(field, 'not json')
  await u.click(within(dialog).getByRole('button', { name: 'Upload' }))
  expect(await within(dialog).findByText(/must be a JSON Web Key/)).toBeTruthy()
  await u.clear(field)
  await u.click(field)
  await u.paste('{"kty":"EC","crv":"P-384","x":"a","y":"b"}')
  await u.click(within(dialog).getByRole('button', { name: 'Upload' }))
  await waitFor(() => expect(calls).toContainEqual({ method: 'POST', path: `${env}/users/m1/keys`, body: { expires_in: '8760h', public_key: { kty: 'EC', crv: 'P-384', x: 'a', y: 'b' } } }))
  expect(screen.queryByRole('dialog', { name: 'Key created' })).toBeNull()

  await u.click(screen.getByRole('button', { name: 'Actions for key k1' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Remove' }))
  dialog = await screen.findByRole('dialog')
  await u.click(within(dialog).getByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.path === `${env}/users/m1/keys/k1`)).toBe(true))
  await waitFor(() => expect(screen.queryByText('EC P-256')).toBeNull())
})
