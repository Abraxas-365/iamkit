// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
type Key = { kid: string; state: string; created_at: string; activated_at?: string; retire_after?: string; retired_at?: string }
let keys: Key[]
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'
let createError = false

beforeEach(() => {
  keys = []
  calls = []
  role = 'owner'
  createError = false
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    const now = new Date().toISOString()
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    if (path === `${env}/signing-keys` && method === 'POST') {
      if (createError) return Response.json({ error: { code: 'ENCRYPTION_KEY_REQUIRED', message: 'environment signing keys require IAMKIT_ENCRYPTION_KEY to be configured' } }, { status: 422 })
      const key = { kid: `key${keys.length + 1}`, state: 'next', created_at: now }
      keys.push(key)
      return Response.json(key, { status: 201 })
    }
    const activate = path.match(/signing-keys\/(\w+)\/activate$/)
    if (activate && method === 'POST') {
      keys = keys.map(k => k.kid === activate[1] ? { ...k, state: 'active', activated_at: now } : k.state === 'active' ? { ...k, state: 'retiring', retire_after: new Date(Date.now() + 20 * 60_000).toISOString() } : k)
      return Response.json(keys.find(k => k.kid === activate[1]))
    }
    const retire = path.match(/signing-keys\/(\w+)\/retire$/)
    if (retire && method === 'POST') {
      keys = keys.map(k => k.kid === retire[1] ? { ...k, state: 'retired', retired_at: now } : k)
      return Response.json(keys.find(k => k.kid === retire[1]))
    }
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 200, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/signing-keys` ? page(keys) :
            path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/signing-keys']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('creates, activates and rotates a signing key', async () => {
  const u = userEvent.setup()
  open()
  expect(await screen.findByText('No environment keys')).toBeTruthy()
  expect(screen.getByText(/signed with the deployment key/)).toBeTruthy()

  await u.click(screen.getByRole('button', { name: 'Create key' }))
  const row = (await screen.findByText('key1')).closest('tr')!
  expect(within(row).getByText('Next')).toBeTruthy()
  await u.click(within(row).getByRole('button', { name: 'Actions for key key1' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Activate' }))
  await u.click(await screen.findByRole('button', { name: 'Activate key' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/signing-keys/key1/activate`, body: {} }))
  await waitFor(() => expect(screen.queryByText(/signed with the deployment key/)).toBeNull())

  // Rotate: the replaced key is retiring; retiring it early needs force and
  // typing its kid.
  await u.click(screen.getByRole('button', { name: 'Create key' }))
  await u.click(within((await screen.findByText('key2')).closest('tr')!).getByRole('button', { name: 'Actions for key key2' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Activate' }))
  expect(await screen.findByText(/key key1 starts retiring/)).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Activate key' }))
  const retiring = await screen.findByText('Retiring')
  await u.click(within(retiring.closest('tr')!).getByRole('button', { name: 'Actions for key key1' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Retire now (force)' }))
  const confirm = await screen.findByRole('button', { name: 'Retire now' }) as HTMLButtonElement
  expect(confirm.disabled).toBe(true)
  await u.type(screen.getByRole('textbox'), 'key1')
  await u.click(confirm)
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/signing-keys/key1/retire`, body: { force: true } }))
  expect(await screen.findByText('Retired')).toBeTruthy()
})

it('shows why a key cannot be created', async () => {
  createError = true
  const u = userEvent.setup()
  open()
  await u.click(await screen.findByRole('button', { name: 'Create key' }))
  expect(await screen.findByText(/require IAMKIT_ENCRYPTION_KEY/)).toBeTruthy()
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  keys = [{ kid: 'key1', state: 'active', created_at: new Date().toISOString() }]
  open()
  expect(await screen.findByText('key1')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create key' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for key key1' })).toBeNull()
})
