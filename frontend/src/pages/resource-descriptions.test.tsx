// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
let calls: { method: string; path: string; body?: { items: Record<string, string>[] } }[]
let stored: Record<string, string>[]
let role = 'owner'

const resource = { id: 'r1', name: 'Notes API', prefix: 'notes', audience: 'https://notes', permissions: ['notes:read', 'notes:write'], owner_organization_id: null, require_grant: false, api_key_permissions: { user: [], organization: [] } }

beforeEach(() => {
  calls = []
  role = 'owner'
  stored = [{ permission: 'notes:read', locale: '', display_name: 'Read notes', description: 'See your notes.' }]
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    if (method === 'PUT' && path === `${env}/resources/r1/permission-descriptions`) { stored = JSON.parse(String(init.body)).items; return new Response(null, { status: 204 }) }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/resources/r1/permission-descriptions` ? { items: stored } :
            path === `${env}/login-settings/locales` ? { items: [{ code: 'en', name: 'English' }, { code: 'es', name: 'Español' }] } :
              path === `${env}/resources/r1` ? resource :
                path === `${env}/resources` ? page([resource, { ...resource, id: 'r2', name: 'Bare API', prefix: 'bare', permissions: ['bare:x'] }]) :
                  path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
const puts = () => calls.filter(c => c.method === 'PUT')

it('shows the stored texts and saves the whole set, per language, dropping empty rows', async () => {
  const u = userEvent.setup()
  open('resources/r1')
  const name = await screen.findByLabelText('Display name: notes:read') as HTMLInputElement
  await waitFor(() => expect(name.value).toBe('Read notes'))
  const save = screen.getByRole('button', { name: 'Save descriptions' })
  expect(save.hasAttribute('disabled')).toBe(true)

  await u.type(screen.getByLabelText('Display name: notes:write'), 'Write notes')
  await u.click(screen.getByRole('tab', { name: /^Español/ }))
  // Another language starts empty: the default text is not copied into it.
  expect((screen.getByLabelText('Display name: notes:read') as HTMLInputElement).value).toBe('')
  await u.type(screen.getByLabelText('Display name: notes:read'), 'Leer notas')
  await u.type(screen.getByLabelText('Description: notes:read'), 'Ver tus notas.')
  await u.click(save)
  await waitFor(() => expect(puts()).toHaveLength(1))
  expect(puts()[0].path).toBe(`${env}/resources/r1/permission-descriptions`)
  expect(puts()[0].body?.items).toEqual([
    { permission: 'notes:read', locale: '', display_name: 'Read notes', description: 'See your notes.' },
    { permission: 'notes:read', locale: 'es', display_name: 'Leer notas', description: 'Ver tus notas.' },
    { permission: 'notes:write', locale: '', display_name: 'Write notes', description: '' },
  ])
})

it('clearing a text removes it from the set', async () => {
  const u = userEvent.setup()
  open('resources/r1')
  const name = await screen.findByLabelText('Display name: notes:read') as HTMLInputElement
  await waitFor(() => expect(name.value).toBe('Read notes'))
  await u.clear(name)
  await u.clear(screen.getByLabelText('Description: notes:read'))
  await u.click(screen.getByRole('button', { name: 'Save descriptions' }))
  await waitFor(() => expect(puts()).toHaveLength(1))
  expect(puts()[0].body).toEqual({ items: [] })
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open('resources/r1')
  const name = await screen.findByLabelText('Display name: notes:read') as HTMLInputElement
  await waitFor(() => expect(name.value).toBe('Read notes'))
  expect(name.disabled).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save descriptions' })).toBeNull()
})

it('lists permissions with the display name and the raw name beside it, or the raw name alone', async () => {
  open('resources')
  const row = (await screen.findByText('Notes API')).closest('tr')!
  await waitFor(() => expect(within(row).getByText('Read notes', { exact: false })).toBeTruthy())
  expect(within(row).getByText('notes:read')).toBeTruthy()
  // Undescribed permissions stay raw.
  expect(within(row).getByText('notes:write')).toBeTruthy()
  const bare = screen.getByText('Bare API').closest('tr')!
  expect(within(bare).getByText('bare:x')).toBeTruthy()
})
