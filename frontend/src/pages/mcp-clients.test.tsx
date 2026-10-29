// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
let role = 'owner'
let server: Record<string, unknown>
const resource = { id: 'res1', name: 'Invoices', prefix: 'invoices', audience: 'https://invoices.example', permissions: ['invoices:read'] }
const base = { protected_resource_id: 'pr1', client_uri: '', logo_uri: '', redirect_uris: ['http://localhost/callback'], token_endpoint_auth_method: 'none', jwks_uri: '', metadata_hash: 'hash-1', admission_expires_at: null, admission_source: '', preset: '', preset_name: '', access_requests: 0, metadata_fetched_at: null, last_used_at: null, created_at: '2026-10-01T00:00:00Z' }
const clients = [
  { ...base, id: 'c1', client_id: 'https://evil.example/oauth/client.json', host: 'evil.example', client_name: 'Totally Claude', logo_uri: 'https://cdn.other.example/logo.png', admission: 'pending', access_requests: 2 },
  { ...base, id: 'c2', client_id: 'https://claude.ai/oauth/mcp-oauth-client-metadata', host: 'claude.ai', client_name: 'Claude', logo_uri: 'https://claude.ai/logo.png', admission: 'approved', admission_source: 'preset', preset: 'claude', preset_name: 'Claude' },
  { ...base, id: 'c3', client_id: 'https://blocked.example/c.json', host: 'blocked.example', client_name: 'Nope', admission: 'blocked' },
]
const presets = [
  { key: 'claude', name: 'Claude', mechanism: 'metadata_document', network: 'public', source_ranges: ['160.79.104.0/21'], development_only: false, warnings: [] },
  { key: 'vscode', name: 'VS Code', mechanism: 'metadata_document', network: 'local', development_only: false, warnings: [] },
  { key: 'cursor', name: 'Cursor', mechanism: 'template', network: 'local', redirect_uris: ['cursor://anysphere.cursor-mcp/oauth/callback'], development_only: false, notes: 'Cursor has no metadata document.', warnings: [] },
]
let allowlist: unknown[]

beforeEach(() => {
  role = 'owner'
  server = { id: 'pr1', resource_id: 'res1', uri: 'https://mcp.example/mcp', name: 'Invoices MCP', default_scopes: [], idle_ttl_seconds: 604800, max_ttl_seconds: 2592000, active: true, created_at: '2026-01-01T00:00:00Z', allow_client_metadata: true, client_admission: 'allowlist' }
  allowlist = [{ id: 'a1', environment_id: 'env1', protected_resource_id: null, origin: 'https://claude.ai', path_prefix: '/oauth/', preset: 'claude', created_at: '2026-10-01T00:00:00Z' }]
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path, query = ''] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (method === 'POST' && path === `${env}/protected-resources/pr1/client-templates`) return Response.json({ preset: 'cursor', name: 'Cursor', mechanism: 'template', network: 'local', warnings: [], allowlist_entry: null, client: { client_id: '8c2f0d0e-0000-4000-8000-000000000001', redirect_uris: [], loopback_any_port: false, created: true } }, { status: 201 })
    if (method === 'POST' && path === `${env}/oauth-client-presets`) return Response.json({ preset: 'claude' }, { status: 201 })
    if (method !== 'GET') return method === 'DELETE' ? new Response(null, { status: 204 }) : Response.json({})
    const params = new URLSearchParams(query)
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/resources/res1` ? resource :
            path === `${env}/organizations` ? page([]) :
              path === `${env}/protected-resources` ? page([server]) :
                path === `${env}/protected-resources/pr1/impact` ? { active_sessions: 3, external_clients: 2 } :
                  path === `${env}/protected-resources/pr1/clients/c1/requests` ? { items: [{ user_id: 'u1', email: 'ana@example.com', name: 'Ana', requested_at: '2026-10-02T00:00:00Z' }] } :
                    path === `${env}/protected-resources/pr1/clients` ? page(clients.filter(c => c.admission === params.get('admission'))) :
                      path === `${env}/oauth-client-allowlist` ? page(allowlist) :
                        path === `${env}/oauth-client-presets` ? { items: presets } : page([])
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url).replace('/management/v1', ''), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('lists pending clients by host, marks document names unverified and counts every state', async () => {
  open('/resources/res1')
  await screen.findByText('evil.example')
  const row = screen.getByText('evil.example').closest('tr')!
  expect(within(row).getByText('Unverified')).toBeTruthy()
  expect(within(row).getByText('Totally Claude')).toBeTruthy()
  // A logo from another host is never loaded.
  expect(row.querySelector('img')).toBeNull()
  expect(screen.getByRole('tab', { name: /Pending/ }).textContent).toContain('1')
  await waitFor(() => expect(screen.getByRole('tab', { name: /Approved/ }).textContent).toContain('1'))
  await userEvent.click(screen.getByRole('tab', { name: /Approved/ }))
  await screen.findByText('claude.ai')
  const approved = screen.getByText('claude.ai').closest('tr')!
  expect(within(approved).getByText('Verified: Claude')).toBeTruthy()
  expect(within(approved).queryByText('Unverified')).toBeNull()
  expect(approved.querySelector('img')?.getAttribute('src')).toBe('https://claude.ai/logo.png')
})

it('approves with an expiry date, blocks with confirmation and shows who asked', async () => {
  const u = userEvent.setup()
  open('/resources/res1')
  await screen.findByText('evil.example')
  await u.click(screen.getByRole('button', { name: 'Actions for evil.example' }))
  await u.click(await screen.findByRole('menuitem', { name: /Access requests \(2\)/ }))
  const requests = await screen.findByRole('dialog')
  await within(requests).findByText('ana@example.com')
  await u.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())

  await u.click(screen.getByRole('button', { name: 'Actions for evil.example' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Approve' }))
  const dialog = await screen.findByRole('dialog')
  const date = new Date(Date.now() + 5 * 86400000).toISOString().slice(0, 10)
  await u.type(within(dialog).getByLabelText(/Approval expires/), date)
  await u.click(within(dialog).getByRole('button', { name: 'Approve' }))
  await waitFor(() => expect(calls('POST')[0]?.url).toBe(`${env}/protected-resources/pr1/clients/c1/approve`))
  expect(new Date(calls('POST')[0].body.expires_at).getTime()).toBeGreaterThan(Date.now())
  // The approval carries the hash of the document the dialog showed.
  expect(calls('POST')[0].body.metadata_hash).toBe('hash-1')

  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  await u.click(screen.getByRole('button', { name: 'Actions for evil.example' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Block' }))
  await u.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Block' }))
  await waitFor(() => expect(calls('POST').some(c => c.url.endsWith('/clients/c1/block'))).toBe(true))
})

it('refreshes the list and says so when the document changed before the approval (409)', async () => {
  const u = userEvent.setup()
  open('/resources/res1')
  await screen.findByText('evil.example')
  const before = fetchMock.mock.calls.filter(([url]) => String(url).includes('/clients?admission=pending')).length
  await u.click(screen.getByRole('button', { name: 'Actions for evil.example' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Approve' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('http://localhost/callback')).toBeTruthy()
  fetchMock.mockImplementationOnce(async () => Response.json({ error: { code: 'CLIENT_METADATA_CHANGED', message: 'changed', type: 'CONFLICT' } }, { status: 409 }))
  await u.click(within(dialog).getByRole('button', { name: 'Approve' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  await waitFor(() => expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('/clients?admission=pending')).length).toBeGreaterThan(before))
})

it('unblocks and deletes after a confirmation', async () => {
  const u = userEvent.setup()
  open('/resources/res1')
  await screen.findByText('evil.example')
  await u.click(screen.getByRole('tab', { name: /Blocked/ }))
  await screen.findByText('blocked.example')
  await u.click(screen.getByRole('button', { name: 'Actions for blocked.example' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Unblock' }))
  await waitFor(() => expect(calls('POST').some(c => c.url.endsWith('/clients/c3/unblock'))).toBe(true))
  await u.click(screen.getByRole('button', { name: 'Actions for blocked.example' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Delete' }))
  await u.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete' }))
  await waitFor(() => expect(calls('DELETE')[0]?.url).toBe(`${env}/protected-resources/pr1/clients/c3`))
})

it('switches admission to open only after warning, and toggles metadata clients', async () => {
  const u = userEvent.setup()
  open('/resources/res1')
  const select = await screen.findByLabelText('Client admission')
  await u.selectOptions(select, 'open')
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/admitted without review/)).toBeTruthy()
  expect(calls('PATCH')).toHaveLength(0)
  await u.click(within(dialog).getByRole('button', { name: 'Admit any client' }))
  await waitFor(() => expect(calls('PATCH')[0]).toMatchObject({ url: `${env}/protected-resources/pr1`, body: { client_admission: 'open' } }))
  await u.click(screen.getByRole('switch', { name: 'Allow clients with a metadata document' }))
  await waitFor(() => expect(calls('PATCH')[1]?.body).toEqual({ allow_client_metadata: false }))
})

it('says which clients go with the server when deleting it', async () => {
  const u = userEvent.setup()
  open('/resources/res1')
  await screen.findByText('evil.example')
  await u.click(screen.getByRole('button', { name: 'Delete' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/2 clients with a metadata document are forgotten with it; clients created from templates stay/)).toBeTruthy()
})

it('creates a client from a template and shows the client ID and snippet', async () => {
  const u = userEvent.setup()
  open('/resources/res1')
  await screen.findByText('evil.example')
  await u.click(screen.getByRole('button', { name: 'Create client from template' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('cursor://anysphere.cursor-mcp/oauth/callback')).toBeTruthy()
  await u.click(within(dialog).getByRole('button', { name: 'Create client' }))
  await within(dialog).findByText('8c2f0d0e-0000-4000-8000-000000000001')
  expect(calls('POST')[0]).toMatchObject({ url: `${env}/protected-resources/pr1/client-templates`, body: { preset: 'cursor' } })
  expect(within(dialog).getByText(/"CLIENT_ID": "8c2f0d0e-0000-4000-8000-000000000001"/)).toBeTruthy()
})

it('lists the allowlist and the preset gallery with network badges', async () => {
  const u = userEvent.setup()
  open('/mcp-clients')
  await screen.findByText('/oauth/')
  expect(screen.getByText('Every MCP server')).toBeTruthy()
  const claude = (await screen.findByRole('heading', { name: 'Claude' })).closest('li')!
  expect(within(claude).getByText('Requires public exposure')).toBeTruthy()
  expect(within(claude).getByText('160.79.104.0/21')).toBeTruthy()
  expect(within(claude).getByText('Enabled')).toBeTruthy()
  const vscode = screen.getByRole('heading', { name: 'VS Code' }).closest('li')!
  expect(within(vscode).getByText('Local client')).toBeTruthy()
  await u.click(within(vscode).getByRole('button', { name: 'Enable' }))
  await waitFor(() => expect(calls('POST')[0]).toMatchObject({ url: `${env}/oauth-client-presets`, body: { preset: 'vscode' } }))
  expect(within(screen.getByRole('heading', { name: 'Cursor' }).closest('li')!).getByRole('button', { name: 'Create client from template' })).toBeTruthy()
})

it('adds and removes allowlist entries', async () => {
  const u = userEvent.setup()
  open('/mcp-clients')
  await screen.findByText('/oauth/')
  await u.click(screen.getByRole('button', { name: /Add entry/ }))
  const dialog = await screen.findByRole('dialog')
  await u.type(within(dialog).getByLabelText('Origin'), 'https://tools.example.com')
  await u.click(within(dialog).getByRole('button', { name: 'Add' }))
  await waitFor(() => expect(calls('POST')[0]).toMatchObject({ url: `${env}/oauth-client-allowlist`, body: { origin: 'https://tools.example.com', path_prefix: '/' } }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  await u.click(screen.getByRole('button', { name: 'Actions for https://claude.ai/oauth/' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Remove' }))
  await u.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls('DELETE')[0]?.url).toBe(`${env}/oauth-client-allowlist/a1`))
})

it('hides write controls from viewers', async () => {
  role = 'viewer'
  open('/mcp-clients')
  await screen.findByText('/oauth/')
  expect(screen.queryByRole('button', { name: /Add entry/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Enable' })).toBeNull()
})
